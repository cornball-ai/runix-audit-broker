#include "broker.h"

#include "id.h"
#include "receipt.h"
#include "record.h"
#include "sink.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

/* Reconstruction refuses a segment larger than this as corruption/DoS. The
 * current segment is normally bounded by cfg.rotate_bytes; this is a hard
 * backstop when rotation is disabled. */
#define RAB_MAX_SEGMENT_BYTES (1024ull * 1024ull * 1024ull) /* 1 GiB */

/* Upper bound on any hash table's bucket count (memory backstop). */
#define RAB_MAX_BUCKETS ((size_t) 1 << 20)

/* Bounded re-mint attempts for an effect-receipt token that collides with the
 * intent's binding or an existing receipt verifier (see the mint loop in
 * rab_broker_issue_receipt); exhausting them fails issuance closed. */
#define RAB_RECEIPT_MINT_TRIES 8

/* ---- state ------------------------------------------------------------- */

/* Open intents are held in two hash tables over the SAME nodes: by cid (for
 * reconstruction and existence checks) and by binding (for outcome matching).
 * Both were linked-list scans before; at the 32768-intent cap that made every
 * lookup O(n) and reconstruction O(n^2). The tables share nbkt (a power of two)
 * so a single mask indexes both. */
typedef struct intent {
    char cid[RAB_CID_MAX];
    char binding[RAB_BINDING_MAX];
    rab_actor actor;
    char operation[RAB_META_MAX]; /* retained so a checkpoint stays meaningful */
    char resource[RAB_META_MAX];
    char scope[RAB_SCOPE_MAX];
    int from_checkpoint; /* opened via a broker_checkpoint (rotation carry)? */
    /* effect-receipt state; has_receipt == 0 for an ordinary intent (unchanged).
     * Installed only after the broker_receipt record is durably appended. The
     * verifier is the SHA-256 of the token in hex; the live token is never held. */
    int has_receipt;
    rab_rcpt_state rcpt_state;
    char verifier_hex[RAB_HEX64_MAX];
    uid_t rcpt_actor_uid;
    char rcpt_verb[RAB_META_MAX];
    char rcpt_resource[RAB_META_MAX];
    long long rcpt_plan_schema;
    char rcpt_plan_hash[RAB_HEX64_MAX];
    unsigned long long rcpt_issue_boottime_us;
    unsigned long long rcpt_ttl_us;
    char rcpt_boot_id[RAB_BOOT_ID_MAX];
    struct intent *hcid;  /* chain in the by-cid table */
    struct intent *hbind; /* chain in the by-binding table */
    struct intent *hrcpt; /* chain in the by-verifier table (has_receipt only) */
} intent;

/* Per-uid accounting: a sliding window of recent ops as a FIFO ring of
 * (timestamp, appended-bytes) with a running byte sum and lazy eviction, so the
 * op-count (n) and the in-window byte total (bsum) are both O(1) to read after
 * eviction. The op-count bounds the ring, so a per-uid BYTE quota requires the
 * op-count limit to be on (validated at open). */
typedef struct uid_state {
    uid_t uid;
    unsigned open;              /* current open intents for this uid */
    unsigned long long *ts;     /* ring of op timestamps (us) */
    unsigned long long *bytes;  /* parallel ring of appended sizes */
    unsigned cap, n, head;      /* FIFO: entries at [head, head+n) mod cap */
    unsigned long long bsum;    /* running sum of bytes currently in the ring */
    struct uid_state *hnext;    /* chain in the by-uid table */
} uid_state;

struct rab_broker {
    char *path;
    int fd;
    rab_config cfg;
    rab_clock_fn clock;
    void *clock_ctx;
    char host[256];
    /* open-intent hash tables (share nbkt) */
    intent **bkt_cid;
    intent **bkt_bind;
    intent **bkt_rcpt; /* by receipt verifier; entries only while has_receipt */
    size_t nbkt;
    size_t open_count;
    /* per-uid accounting hash table */
    uid_state **bkt_uid;
    size_t nbkt_uid;
    /* global write-byte quota: a tumbling window (O(1); does not persist across
     * a restart, unlike the per-uid quota — see global_bytes_note). */
    unsigned long long g_win_start;
    unsigned long long g_win_bytes;
    unsigned long long seg_bytes;
    int poisoned; /* a partial append / fsync uncertainty: refuse until restart */
    /* effect-receipt issue time / boot id sources (broker-owned; injectable). */
    rab_boottime_fn boottime;
    rab_bootid_fn bootid;
    void *rcpt_ctx;
    rab_test_fail_mode test_fail; /* test seam: force the next append to fail */
};

void rab_config_defaults(rab_config *cfg) {
    cfg->max_open_per_uid = 2048;
    cfg->max_open_global = 32768;
    cfg->rate_window_sec = 10;
    cfg->rate_max_in_window = 2000;
    cfg->rate_max_bytes_per_uid = 16ull << 20; /* 16 MiB/uid/window */
    cfg->rate_max_bytes_global = 64ull << 20;  /* 64 MiB/window, all uids */
    cfg->rotate_bytes = 64ull << 20;    /* 64 MiB current-segment cap */
    cfg->min_free_bytes = 64ull << 20;  /* refuse appends below 64 MiB free */
    cfg->retain_segments = 16;          /* keep at most 16 archived segments */
    cfg->retain_bytes = 1024ull << 20;  /* and at most 1 GiB total on disk */
    cfg->receipt_ttl_sec = 300;         /* effect-receipt validity: 5 minutes */
}

static unsigned long long real_clock(void *ctx) {
    (void) ctx;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (unsigned long long) ts.tv_sec * 1000000ull +
           (unsigned long long) (ts.tv_nsec / 1000);
}

/* Default receipt issue-time source: CLOCK_BOOTTIME (counts across suspend,
 * resets across reboot), microseconds. Fails closed if the clock is unreadable. */
static int real_boottime(void *ctx, unsigned long long *out) {
    (void) ctx;
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) {
        return -1;
    }
    *out = (unsigned long long) ts.tv_sec * 1000000ull +
           (unsigned long long) (ts.tv_nsec / 1000);
    return 0;
}

/* Default boot-id provider: the host boot id. Fails closed if unreadable. */
static int real_bootid(void *ctx, char *out, size_t cap) {
    (void) ctx;
    return rab_boot_id(out, cap);
}

/* ---- hashing ----------------------------------------------------------- */

static size_t pow2_ceil(size_t x) {
    size_t p = 16;
    while (p < x && p < RAB_MAX_BUCKETS) {
        p <<= 1;
    }
    return p;
}

/* FNV-1a over a NUL-terminated string. Callers mask with (nbkt - 1). */
static size_t hstr(const char *s) {
    unsigned long long h = 1469598103934665603ull;
    for (; *s != '\0'; s++) {
        h ^= (unsigned char) *s;
        h *= 1099511628211ull;
    }
    return (size_t) h;
}

/* Integer mix for uids. Callers mask with (nbkt_uid - 1). */
static size_t huid(uid_t uid) {
    unsigned long long h = (unsigned long long) uid * 11400714819323198485ull;
    return (size_t) (h >> 29);
}

/* ---- per-uid rate/byte accounting -------------------------------------- */

static uid_state *uid_find(rab_broker *b, uid_t uid) {
    for (uid_state *u = b->bkt_uid[huid(uid) & (b->nbkt_uid - 1)]; u != NULL;
         u = u->hnext) {
        if (u->uid == uid) {
            return u;
        }
    }
    return NULL;
}

static uid_state *uid_get(rab_broker *b, uid_t uid) {
    uid_state *u = uid_find(b, uid);
    if (u != NULL) {
        return u;
    }
    u = calloc(1, sizeof *u);
    if (u == NULL) {
        return NULL;
    }
    unsigned cap = b->cfg.rate_max_in_window ? b->cfg.rate_max_in_window : 1;
    u->ts = calloc(cap, sizeof *u->ts);
    u->bytes = calloc(cap, sizeof *u->bytes);
    if (u->ts == NULL || u->bytes == NULL) {
        free(u->ts);
        free(u->bytes);
        free(u);
        return NULL;
    }
    u->uid = uid;
    u->cap = cap;
    size_t h = huid(uid) & (b->nbkt_uid - 1);
    u->hnext = b->bkt_uid[h];
    b->bkt_uid[h] = u;
    return u;
}

/* The in-window threshold: an op counts iff its timestamp is >= now - window
 * (inclusive boundary). */
static unsigned long long win_th(const rab_broker *b, unsigned long long now) {
    unsigned long long window =
        (unsigned long long) b->cfg.rate_window_sec * 1000000ull;
    return (now > window) ? now - window : 0;
}

/* Drop entries older than the window (ts < th) from the FIFO front, keeping the
 * running byte sum in step. */
static void uid_evict(uid_state *u, unsigned long long th) {
    while (u->n > 0 && u->ts[u->head] < th) {
        u->bsum -= u->bytes[u->head];
        u->head = (u->head + 1) % u->cap;
        u->n--;
    }
}

static void uid_push(uid_state *u, unsigned long long t,
                     unsigned long long nbytes) {
    if (u->n == u->cap) {
        /* Overflow guard: cannot happen while the op-count limit holds (a push
         * follows a passed rate check), but a reconstruction over a shrunken
         * cap could. Evict the oldest, keeping the newest cap entries. */
        u->bsum -= u->bytes[u->head];
        u->head = (u->head + 1) % u->cap;
        u->n--;
    }
    unsigned idx = (u->head + u->n) % u->cap;
    u->ts[idx] = t;
    u->bytes[idx] = nbytes;
    u->bsum += nbytes;
    u->n++;
}

/* 1 if a new op is within the per-uid op-count rate, 0 to reject. */
static int rate_allowed(rab_broker *b, uid_t uid, unsigned long long now) {
    if (b->cfg.rate_max_in_window == 0) {
        return 1;
    }
    uid_state *u = uid_get(b, uid);
    if (u == NULL) {
        return 0; /* allocation failure: fail closed */
    }
    uid_evict(u, win_th(b, now));
    return u->n < b->cfg.rate_max_in_window;
}

/* 1 if appending `nbytes` stays within BOTH the per-uid and global write-byte
 * quotas, 0 to reject. Read-only: the counters advance in the note calls after
 * a successful append. */
static int bytes_allowed(rab_broker *b, uid_t uid, unsigned long long now,
                         unsigned long long nbytes) {
    if (b->cfg.rate_max_bytes_per_uid != 0) {
        uid_state *u = uid_get(b, uid);
        if (u == NULL) {
            return 0;
        }
        uid_evict(u, win_th(b, now));
        if (u->bsum + nbytes > b->cfg.rate_max_bytes_per_uid) {
            return 0;
        }
    }
    if (b->cfg.rate_max_bytes_global != 0) {
        unsigned long long window =
            (unsigned long long) b->cfg.rate_window_sec * 1000000ull;
        unsigned long long cur =
            (now - b->g_win_start >= window) ? 0 : b->g_win_bytes;
        if (cur + nbytes > b->cfg.rate_max_bytes_global) {
            return 0;
        }
    }
    return 1;
}

/* Record one accepted op in the per-uid window (op count + bytes). Also used by
 * reconstruction to reseed the ring, which is why it does NOT touch the global
 * tumbling counter (that one does not persist across a restart). */
static void rate_note(rab_broker *b, uid_t uid, unsigned long long t,
                      unsigned long long nbytes) {
    if (b->cfg.rate_max_in_window == 0) {
        return; /* the ring only exists when the op-count limit is on */
    }
    uid_state *u = uid_get(b, uid);
    if (u != NULL) {
        uid_push(u, t, nbytes);
    }
}

/* Advance the global tumbling window. Live path only. */
static void global_bytes_note(rab_broker *b, unsigned long long now,
                              unsigned long long nbytes) {
    if (b->cfg.rate_max_bytes_global == 0) {
        return;
    }
    unsigned long long window =
        (unsigned long long) b->cfg.rate_window_sec * 1000000ull;
    if (b->g_win_start == 0 || now - b->g_win_start >= window) {
        b->g_win_start = now;
        b->g_win_bytes = 0;
    }
    b->g_win_bytes += nbytes;
}

/* ---- open-intent set (two hash tables) --------------------------------- */

static intent *open_find_binding(rab_broker *b, const char *binding) {
    if (binding[0] == '\0') {
        return NULL;
    }
    for (intent *it = b->bkt_bind[hstr(binding) & (b->nbkt - 1)]; it != NULL;
         it = it->hbind) {
        if (strcmp(it->binding, binding) == 0) {
            return it;
        }
    }
    return NULL;
}

static intent *open_find_cid(rab_broker *b, const char *cid) {
    for (intent *it = b->bkt_cid[hstr(cid) & (b->nbkt - 1)]; it != NULL;
         it = it->hcid) {
        if (strcmp(it->cid, cid) == 0) {
            return it;
        }
    }
    return NULL;
}

/* by-verifier index over receipt-bearing intents. The verifier is unique per
 * receipt (the mint-time collision check, plus reconstruction's conflict
 * rejection), so this maps a token's verifier to at most one intent. It is the
 * lookup the wire redeem path uses: the request carries the opaque token, the
 * broker hashes it to a verifier, and finds the receipt here -- no correlation
 * id ever crosses the wire. Entries live only while an intent has a receipt. */
static intent *open_find_verifier(rab_broker *b, const char *vhex) {
    if (vhex[0] == '\0') {
        return NULL;
    }
    for (intent *it = b->bkt_rcpt[hstr(vhex) & (b->nbkt - 1)]; it != NULL;
         it = it->hrcpt) {
        if (it->has_receipt && strcmp(it->verifier_hex, vhex) == 0) {
            return it;
        }
    }
    return NULL;
}

/* Add an intent to the by-verifier index once its receipt is installed (its
 * verifier_hex is set). Called right after a receipt is issued live or
 * reconstructed; never before the durable append that installs the state. */
static void rcpt_index_add(rab_broker *b, intent *it) {
    size_t h = hstr(it->verifier_hex) & (b->nbkt - 1);
    it->hrcpt = b->bkt_rcpt[h];
    b->bkt_rcpt[h] = it;
}

/* Remove an intent from the by-verifier index (when it closes). */
static void rcpt_index_remove(rab_broker *b, intent *it) {
    intent **pp = &b->bkt_rcpt[hstr(it->verifier_hex) & (b->nbkt - 1)];
    while (*pp != NULL) {
        if (*pp == it) {
            *pp = it->hrcpt;
            break;
        }
        pp = &(*pp)->hrcpt;
    }
}

static int open_add(rab_broker *b, const char *cid, const char *binding,
                    const rab_actor *actor, const char *operation,
                    const char *resource, const char *scope) {
    intent *it = calloc(1, sizeof *it);
    if (it == NULL) {
        return -1;
    }
    snprintf(it->cid, sizeof it->cid, "%s", cid);
    snprintf(it->binding, sizeof it->binding, "%s", binding);
    it->actor = *actor;
    snprintf(it->operation, sizeof it->operation, "%s",
             operation ? operation : "");
    snprintf(it->resource, sizeof it->resource, "%s", resource ? resource : "");
    snprintf(it->scope, sizeof it->scope, "%s", scope ? scope : "");
    size_t hc = hstr(cid) & (b->nbkt - 1);
    it->hcid = b->bkt_cid[hc];
    b->bkt_cid[hc] = it;
    size_t hb = hstr(binding) & (b->nbkt - 1);
    it->hbind = b->bkt_bind[hb];
    b->bkt_bind[hb] = it;
    b->open_count++;
    uid_state *u = uid_get(b, actor->uid);
    if (u != NULL) {
        u->open++;
    }
    return 0;
}

static void open_remove(rab_broker *b, intent *target) {
    intent **pp = &b->bkt_cid[hstr(target->cid) & (b->nbkt - 1)];
    while (*pp != NULL) {
        if (*pp == target) {
            *pp = target->hcid;
            break;
        }
        pp = &(*pp)->hcid;
    }
    pp = &b->bkt_bind[hstr(target->binding) & (b->nbkt - 1)];
    while (*pp != NULL) {
        if (*pp == target) {
            *pp = target->hbind;
            break;
        }
        pp = &(*pp)->hbind;
    }
    if (target->has_receipt) {
        rcpt_index_remove(b, target);
    }
    b->open_count--;
    uid_state *u = uid_find(b, target->actor.uid);
    if (u != NULL && u->open > 0) {
        u->open--;
    }
    free(target);
}

/* ---- append + carry-forward rotation ----------------------------------- */

/* True iff the sink filesystem has at least cfg.min_free_bytes free. A
 * near-full disk is a transient refusal (persist_failed), not corruption, so it
 * does not poison the broker. */
static int enough_free_space(rab_broker *b) {
    if (b->cfg.min_free_bytes == 0) {
        return 1;
    }
    struct statvfs vfs;
    if (statvfs(b->path, &vfs) != 0) {
        return 0; /* cannot tell: fail closed */
    }
    unsigned long long freeb =
        (unsigned long long) vfs.f_bavail * (unsigned long long) vfs.f_frsize;
    return freeb >= b->cfg.min_free_bytes;
}

/* Append one record line. On ANY failure the sink may hold a partial line, so
 * the broker is poisoned (refuses further appends until a restart reconstructs
 * and truncates it) rather than risk concatenating the next record onto torn
 * bytes. */
static int append_line(rab_broker *b, const char *line) {
    size_t len = strlen(line);
    if (b->test_fail != RAB_FAIL_NONE) {
        /* Exercise the sink append/sync boundary: RAB_FAIL_PARTIAL leaves a
         * torn partial record on disk (recovered by truncation at restart);
         * RAB_FAIL_SYNC writes a complete record whose fdatasync is treated as
         * failed (durability uncertain). Either way the broker is poisoned. */
        rab_test_fail_mode mode = b->test_fail;
        b->test_fail = RAB_FAIL_NONE;
        if (mode == RAB_FAIL_PARTIAL && len > 1) {
            ssize_t w = write(b->fd, line, len / 2);
            (void) w;
        } else if (mode == RAB_FAIL_SYNC) {
            ssize_t w1 = write(b->fd, line, len);
            ssize_t w2 = write(b->fd, "\n", 1);
            (void) w1;
            (void) w2;
        }
        b->poisoned = 1;
        return -1;
    }
    if (rab_sink_append(b->fd, line, len) != 0) {
        b->poisoned = 1;
        return -1;
    }
    b->seg_bytes += (unsigned long long) len + 1; /* record + newline */
    return 0;
}

/* Carry the per-uid rate+byte window history into the new segment during
 * rotation: for each uid, the (timestamp, bytes) of every op still inside the
 * window. The client audit records that seeded the ring move to an archive that
 * reconstruction never reads, so without this the per-uid rate AND byte limits
 * would reset at the next restart. Bounded by the ring cap. Returns 0, or -1 on
 * a write/alloc failure (rotation is then aborted, leaving the segment valid). */
static int write_rate_carries(rab_broker *b, int fd) {
    if (b->cfg.rate_max_in_window == 0) {
        return 0;
    }
    unsigned long long th = win_th(b, b->clock(b->clock_ctx));
    for (size_t i = 0; i < b->nbkt_uid; i++) {
        for (uid_state *u = b->bkt_uid[i]; u != NULL; u = u->hnext) {
            uid_evict(u, th);
            if (u->n == 0) {
                continue;
            }
            unsigned long long *ct = malloc((size_t) u->n * sizeof *ct);
            unsigned long long *cb = malloc((size_t) u->n * sizeof *cb);
            if (ct == NULL || cb == NULL) {
                free(ct);
                free(cb);
                return -1;
            }
            for (unsigned k = 0; k < u->n; k++) {
                unsigned idx = (u->head + k) % u->cap;
                ct[k] = u->ts[idx];
                cb[k] = u->bytes[idx];
            }
            char *line = rab_build_rate(u->uid, ct, cb, u->n);
            int rc = 0;
            if (line == NULL) {
                rc = -1;
            } else {
                rc = rab_sink_append(fd, line, strlen(line));
                free(line);
            }
            free(ct);
            free(cb);
            if (rc != 0) {
                return -1;
            }
        }
    }
    return 0;
}

/* All-digits decimal parse of an archive suffix (`<sink>.<us>`); rejects e.g.
 * `.pending`. 0 and *out set on success, -1 otherwise. */
static int arch_suffix_value(const char *s, unsigned long long *out) {
    if (s == NULL || s[0] == '\0') {
        return -1;
    }
    for (const char *c = s; *c != '\0'; c++) {
        if (*c < '0' || *c > '9') {
            return -1;
        }
    }
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno == ERANGE || *end != '\0') {
        return -1;
    }
    *out = v;
    return 0;
}

typedef struct {
    char name[256];            /* directory-relative archive file name */
    unsigned long long suffix; /* the .<us> rotation timestamp (sort key) */
    unsigned long long size;
} archive_ent;

static int archive_cmp(const void *pa, const void *pb) {
    const archive_ent *a = pa;
    const archive_ent *b = pb;
    if (a->suffix < b->suffix) {
        return -1;
    }
    return a->suffix > b->suffix ? 1 : 0;
}

/* Retention: keep total on-disk audit bounded by BOTH a segment count and a
 * total byte budget (the active segment counts toward the bytes). Deletes the
 * oldest archives first until within both bounds. This never risks an
 * unresolved intent: carry-forward rotation re-materialises every open intent
 * as a checkpoint in the (retained) active segment, so an archive only ever
 * holds closed records or superseded checkpoints. Best-effort housekeeping;
 * a failure just leaves more on disk. Must run only after the new segment is
 * durably in place (see rotate). */
static void apply_retention(rab_broker *b) {
    if (b->cfg.retain_segments == 0 && b->cfg.retain_bytes == 0) {
        return; /* both unlimited */
    }
    const char *slash = strrchr(b->path, '/');
    char dirbuf[PATH_MAX];
    const char *dir;
    const char *base;
    if (slash == NULL) {
        dir = ".";
        base = b->path;
    } else {
        size_t dl = (size_t) (slash - b->path);
        if (dl >= sizeof dirbuf) {
            return;
        }
        memcpy(dirbuf, b->path, dl);
        dirbuf[dl] = '\0';
        dir = dirbuf[0] != '\0' ? dirbuf : "/";
        base = slash + 1;
    }
    size_t baselen = strlen(base);
    uid_t self = geteuid();
    DIR *d = opendir(dir);
    if (d == NULL) {
        return;
    }
    archive_ent *ents = NULL;
    size_t n = 0, cap = 0;
    unsigned long long total = b->seg_bytes; /* active segment counts */
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, base, baselen) != 0 ||
            e->d_name[baselen] != '.') {
            continue;
        }
        unsigned long long sv;
        if (arch_suffix_value(e->d_name + baselen + 1, &sv) != 0) {
            continue; /* not an archive (e.g. .pending) */
        }
        char full[PATH_MAX];
        if (snprintf(full, sizeof full, "%s/%s", dir, e->d_name) >=
            (int) sizeof full) {
            continue;
        }
        /* lstat, not stat: never follow a symlink. Only a regular file owned by
         * the broker is a candidate; a symlink or a file planted by another uid
         * is skipped, so retention can never delete an unexpected path. (unlink
         * itself never follows a symlink, but we also refuse to count one.) */
        struct stat st;
        if (lstat(full, &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_uid != self) {
            continue;
        }
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 16;
            archive_ent *tmp = realloc(ents, ncap * sizeof *tmp);
            if (tmp == NULL) {
                free(ents);
                closedir(d);
                return;
            }
            ents = tmp;
            cap = ncap;
        }
        snprintf(ents[n].name, sizeof ents[n].name, "%s", e->d_name);
        ents[n].suffix = sv;
        ents[n].size = (unsigned long long) st.st_size;
        total += ents[n].size;
        n++;
    }
    closedir(d);
    if (n == 0) {
        free(ents);
        return;
    }
    qsort(ents, n, sizeof *ents, archive_cmp); /* oldest first */
    size_t archives = n;
    int pruned = 0;
    for (size_t i = 0; i < n; i++) {
        int over_count = b->cfg.retain_segments != 0 &&
                         archives > b->cfg.retain_segments;
        int over_bytes =
            b->cfg.retain_bytes != 0 && total > b->cfg.retain_bytes;
        if (!over_count && !over_bytes) {
            break;
        }
        char full[PATH_MAX];
        if (snprintf(full, sizeof full, "%s/%s", dir, ents[i].name) >=
            (int) sizeof full) {
            continue;
        }
        if (unlink(full) == 0) {
            archives--;
            total -= ents[i].size;
            pruned = 1;
        }
    }
    /* The active segment is never deleted to meet the byte budget: if it alone
     * exceeds retain_bytes (e.g. a large open-intent checkpoint set), retention
     * prunes every archive and the active segment stands. Audit is never
     * destroyed to satisfy a bound. */
    free(ents);
    if (pruned && rab_fsync_parent_dir(b->path) != 0) {
        /* The unlinks are not yet durable. This is not a correctness fault: a
         * crash could resurrect a pruned archive, but a resurrected archive is
         * harmless (reconstruction never reads archives) and is re-pruned at the
         * next rotation. So retention never poisons the broker or fails a
         * request on this — unlike the rotation rename, whose loss would drop an
         * acknowledged write. */
        (void) 0;
    }
}

/* Carry-forward rotation: write every open intent as a checkpoint into a new
 * segment, carry the per-uid rate history, fsync it, hardlink the old segment
 * to an archive name (preserving history), then atomically swap the new segment
 * into place. Ordering guarantees no open intent is lost across a crash: the
 * current path is never absent, and a stray `.pending` from a crash is
 * discarded at startup (the live path is always the authoritative superset).
 * Retention prunes old archives only after the new segment is durable.
 * Best-effort: on any failure the current segment stays valid and rotation
 * retries on the next append. */
static int rotate(rab_broker *b) {
    char pending[PATH_MAX];
    if (snprintf(pending, sizeof pending, "%s.pending", b->path) >=
        (int) sizeof pending) {
        return -1;
    }
    unlink(pending); /* clear any stray from a prior crashed rotation */
    int pfd = rab_sink_open(pending);
    if (pfd < 0) {
        return -1;
    }
    int rc = 0;
    for (size_t i = 0; i < b->nbkt && rc == 0; i++) {
        for (intent *it = b->bkt_cid[i]; it != NULL && rc == 0; it = it->hcid) {
            unsigned long long now = b->clock(b->clock_ctx);
            char *line = rab_build_checkpoint(it->cid, it->binding, &it->actor,
                                              now, it->operation, it->resource,
                                              it->scope);
            if (line == NULL) {
                rc = -1;
                break;
            }
            if (rab_sink_append(pfd, line, strlen(line)) != 0) {
                rc = -1;
            }
            free(line);
            /* Carry the effect receipt as exactly one checkpoint per still-open
             * effect-required intent, written right after its intent checkpoint
             * so reconstruction sees the intent before its receipt. A checkpoint
             * stands alone (it carries the full current state). */
            if (rc == 0 && it->has_receipt) {
                char *rl = rab_build_receipt(
                    it->cid, it->rcpt_state, 1, it->verifier_hex,
                    it->rcpt_actor_uid, it->rcpt_verb, it->rcpt_resource,
                    it->rcpt_plan_schema, it->rcpt_plan_hash,
                    it->rcpt_issue_boottime_us, it->rcpt_ttl_us,
                    it->rcpt_boot_id);
                if (rl == NULL) {
                    rc = -1;
                    break;
                }
                if (rab_sink_append(pfd, rl, strlen(rl)) != 0) {
                    rc = -1;
                }
                free(rl);
            }
        }
    }
    if (rc != 0) {
        close(pfd);
        unlink(pending);
        return -1;
    }
    /* carry the per-uid rate history into the new segment (see note above) */
    if (write_rate_carries(b, pfd) != 0) {
        close(pfd);
        unlink(pending);
        return -1;
    }
    char arch[PATH_MAX];
    unsigned long long ts = b->clock(b->clock_ctx);
    if (snprintf(arch, sizeof arch, "%s.%llu", b->path, ts) >=
        (int) sizeof arch) {
        close(pfd);
        unlink(pending);
        return -1;
    }
    /* Serialize the swap against any appender to the current sink (the broker
     * is single-instance, but take the same lock appends use as defense). */
    if (flock(b->fd, LOCK_EX) != 0) {
        close(pfd);
        unlink(pending);
        return -1;
    }
    /* archive the old segment (hardlink) then fsync the dir, so the new
     * segment + its parent dir are durable before the old one is retired. */
    if (link(b->path, arch) != 0 || rab_fsync_parent_dir(b->path) != 0) {
        flock(b->fd, LOCK_UN);
        close(pfd);
        unlink(pending);
        unlink(arch); /* may not exist; ignore */
        return -1;
    }
    if (rename(pending, b->path) != 0) {
        flock(b->fd, LOCK_UN);
        close(pfd);
        unlink(pending);
        /* arch remains as a harmless duplicate hardlink of the current file */
        return -1;
    }
    /* The rename is committed but not yet durable. If we cannot fsync the
     * parent directory, a crash could roll the rename back and lose an
     * acknowledged write's segment: that is unrecoverable uncertainty, so
     * poison the broker rather than keep serving. */
    if (rab_fsync_parent_dir(b->path) != 0) {
        b->poisoned = 1;
    }
    flock(b->fd, LOCK_UN);
    close(b->fd);
    b->fd = pfd;
    struct stat st;
    b->seg_bytes =
        (fstat(pfd, &st) == 0) ? (unsigned long long) st.st_size : 0;
    /* Prune old archives ONLY now that the new segment is durably in place: the
     * checkpoints that keep every open intent alive are fsync'd and swapped in
     * before any archive can be deleted. Skip when poisoned (durability is
     * uncertain; keep everything). */
    if (!b->poisoned) {
        apply_retention(b);
    }
    return b->poisoned ? -1 : 0;
}

static void maybe_rotate(rab_broker *b) {
    if (b->cfg.rotate_bytes == 0 || b->seg_bytes <= b->cfg.rotate_bytes) {
        return;
    }
    rotate(b); /* housekeeping: failure keeps the (valid) current segment */
}

/* ---- request handlers -------------------------------------------------- */

static int reply(char **resp, char *s) {
    *resp = s;
    return (s != NULL) ? 0 : -1;
}

/* Copy a string domain field from a client record into dst ("" if absent). */
static void rec_str(json_t *record, const char *key, char *dst, size_t cap) {
    json_t *v = json_object_get(record, key);
    if (json_is_string(v)) {
        snprintf(dst, cap, "%s", json_string_value(v));
    } else {
        dst[0] = '\0';
    }
}

static int handle_open(rab_broker *b, const rab_actor *actor,
                       const rab_request *req, char **resp) {
    /* An effect open binds the record's operation (verb) and resource into the
     * receipt, and those bound fields MUST equal the audited values exactly. The
     * intent metadata buffers are RAB_META_MAX, so a longer value would be
     * silently truncated and the receipt would bind a shortened form of the
     * audited fields. Refuse such an effect open up front rather than bind a
     * value that differs from what was audited. */
    if (req->effect_present) {
        json_t *jop = json_object_get(req->record, "operation");
        json_t *jres = json_object_get(req->record, "resource");
        const char *sop = json_is_string(jop) ? json_string_value(jop) : "";
        const char *sres = json_is_string(jres) ? json_string_value(jres) : "";
        if (strlen(sop) >= RAB_META_MAX || strlen(sres) >= RAB_META_MAX) {
            return reply(resp, rab_response_error(
                                   "schema_invalid",
                                   "effect operation/resource too long to bind"));
        }
    }
    unsigned long long now = b->clock(b->clock_ctx);
    if (!rate_allowed(b, actor->uid, now)) {
        return reply(resp,
                     rab_response_error("rate_limited", "per-uid rate exceeded"));
    }
    if (b->open_count >= b->cfg.max_open_global) {
        return reply(resp, rab_response_error("rate_limited",
                                              "global open-intent cap"));
    }
    uid_state *u = uid_get(b, actor->uid);
    if (u == NULL) {
        return reply(resp, rab_response_error("internal", "out of memory"));
    }
    if (u->open >= b->cfg.max_open_per_uid) {
        return reply(resp, rab_response_error("rate_limited",
                                              "per-uid open-intent cap"));
    }
    if (!enough_free_space(b)) {
        return reply(resp, rab_response_error("persist_failed",
                                              "insufficient free space"));
    }
    char cid[RAB_CID_MAX];
    char binding[RAB_BINDING_MAX];
    if (rab_make_correlation_id(cid, sizeof cid) != 0 ||
        rab_make_binding(binding, sizeof binding) != 0) {
        return reply(resp, rab_response_error("internal", "id minting failed"));
    }
    /* retain the open-intent metadata so a later checkpoint stays meaningful */
    char op[RAB_META_MAX];
    char res[RAB_META_MAX];
    char scope[RAB_SCOPE_MAX];
    rec_str(req->record, "operation", op, sizeof op);
    rec_str(req->record, "resource", res, sizeof res);
    rec_str(req->record, "scope", scope, sizeof scope);

    char *line = rab_build_audit(RAB_PHASE_INTENT, cid, binding, actor,
                                 b->host, now, req->record);
    if (line == NULL) {
        return reply(resp, rab_response_error("internal", "record build"));
    }
    unsigned long long nbytes = (unsigned long long) strlen(line) + 1;
    if (!bytes_allowed(b, actor->uid, now, nbytes)) {
        free(line);
        return reply(resp, rab_response_error("rate_limited",
                                              "write-byte quota exceeded"));
    }
    if (append_line(b, line) != 0) {
        free(line);
        return reply(resp,
                     rab_response_error("persist_failed", "sink append failed"));
    }
    free(line);
    if (open_add(b, cid, binding, actor, op, res, scope) != 0) {
        /* the intent is durable (a queryable open op on restart) but this
         * instance cannot cache it; fail closed rather than lie. */
        return reply(resp, rab_response_error("internal", "open-set alloc"));
    }
    rate_note(b, actor->uid, now, nbytes);
    global_bytes_note(b, now, nbytes);
    maybe_rotate(b);
    if (b->poisoned) {
        /* rotation left the segment's durability uncertain: do not hand back a
         * success the caller would act on. */
        return reply(resp, rab_response_error(
                               "persist_failed",
                               "audit durability uncertain after rotation"));
    }
    /* An effect open issues a receipt bound to the just-opened intent and hands
     * it back alongside the binding. Issuance appends the broker_receipt durably
     * (fsync) before this reply. It fails CLOSED: on any issuance failure the
     * intent stays durably open (a reconcilable open-no-effect record), but the
     * client is told issuance failed rather than handed a success carrying no
     * receipt -- which would silently drop the effect authorization. */
    if (req->effect_present) {
        char token[RAB_RECEIPT_MAX];
        int irc = rab_broker_issue_receipt(b, cid,
                                           (long long) req->effect_plan_schema,
                                           req->effect_plan_hash, token,
                                           sizeof token);
        if (irc != 0) {
            explicit_bzero(token, sizeof token);
            return reply(resp, rab_response_error(
                                   "persist_failed",
                                   "effect receipt issuance failed"));
        }
        char *r = rab_response_open_ok(cid, binding, "system", token);
        explicit_bzero(token, sizeof token);
        return reply(resp, r);
    }
    return reply(resp, rab_response_open_ok(cid, binding, "system", NULL));
}

static int handle_outcome(rab_broker *b, const rab_actor *actor,
                          const rab_request *req, char **resp) {
    unsigned long long now = b->clock(b->clock_ctx);
    if (!rate_allowed(b, actor->uid, now)) {
        return reply(resp,
                     rab_response_error("rate_limited", "per-uid rate exceeded"));
    }
    intent *it = open_find_binding(b, req->binding);
    if (it == NULL) {
        return reply(resp,
                     rab_response_error("unknown_intent", "no such open intent"));
    }
    if (!rab_actor_eq(&it->actor, actor)) {
        return reply(resp, rab_response_error(
                               "actor_mismatch",
                               "peer identity does not match the opener"));
    }
    /* Effect-receipt gate: an outcome that ASSERTS an effect was issued
     * (effect_issued: true) on an effect-required intent is valid only once the
     * intent's receipt has been REDEEMED through the root helper. An issued-but-
     * unredeemed (or pending) receipt cannot back an effect claim -- that effect
     * would have happened outside the sanctioned path. A non-effect outcome
     * (abort/noop) is unaffected, and an ordinary intent (which carries no
     * receipt) is entirely unaffected, so this changes nothing for today's
     * clients. Reachable on the wire only once issuance is wired in (a later
     * slice); until then no conforming client can open a receipt-bearing intent. */
    if (it->has_receipt && it->rcpt_state != RAB_RCPT_REDEEMED &&
        json_is_true(json_object_get(req->record, "effect_issued"))) {
        return reply(resp, rab_response_error(
                               "effect_without_receipt",
                               "effect claimed without a redeemed receipt"));
    }
    if (!enough_free_space(b)) {
        return reply(resp, rab_response_error("persist_failed",
                                              "insufficient free space"));
    }
    char *line = rab_build_audit(RAB_PHASE_OUTCOME, it->cid, NULL, actor,
                                 b->host, now, req->record);
    if (line == NULL) {
        return reply(resp, rab_response_error("internal", "record build"));
    }
    unsigned long long nbytes = (unsigned long long) strlen(line) + 1;
    if (!bytes_allowed(b, actor->uid, now, nbytes)) {
        free(line);
        return reply(resp, rab_response_error("rate_limited",
                                              "write-byte quota exceeded"));
    }
    if (append_line(b, line) != 0) {
        free(line);
        return reply(resp,
                     rab_response_error("persist_failed", "sink append failed"));
    }
    free(line);
    open_remove(b, it); /* single-use: the outcome closes the intent */
    rate_note(b, actor->uid, now, nbytes);
    global_bytes_note(b, now, nbytes);
    maybe_rotate(b);
    if (b->poisoned) {
        return reply(resp, rab_response_error(
                               "persist_failed",
                               "audit durability uncertain after rotation"));
    }
    return reply(resp, rab_response_outcome_ok());
}

/* A single non-effect record (preview / no-op). It mints a correlation id but
 * opens no intent and returns no binding, so it can never be paired with a
 * write_outcome. It is rate/byte/free-space/rotation-poison accounted exactly
 * like the effect paths. The phase (preview|noop) and the non-effect record
 * were already constrained by the parser, so this cannot be a generic append. */
static int handle_emit(rab_broker *b, const rab_actor *actor,
                       const rab_request *req, char **resp) {
    unsigned long long now = b->clock(b->clock_ctx);
    if (!rate_allowed(b, actor->uid, now)) {
        return reply(resp,
                     rab_response_error("rate_limited", "per-uid rate exceeded"));
    }
    if (!enough_free_space(b)) {
        return reply(resp, rab_response_error("persist_failed",
                                              "insufficient free space"));
    }
    char cid[RAB_CID_MAX];
    if (rab_make_correlation_id(cid, sizeof cid) != 0) {
        return reply(resp, rab_response_error("internal", "id minting failed"));
    }
    char *line = rab_build_audit(req->phase, cid, NULL /* no binding */, actor,
                                 b->host, now, req->record);
    if (line == NULL) {
        return reply(resp, rab_response_error("internal", "record build"));
    }
    unsigned long long nbytes = (unsigned long long) strlen(line) + 1;
    if (!bytes_allowed(b, actor->uid, now, nbytes)) {
        free(line);
        return reply(resp, rab_response_error("rate_limited",
                                              "write-byte quota exceeded"));
    }
    if (append_line(b, line) != 0) {
        free(line);
        return reply(resp,
                     rab_response_error("persist_failed", "sink append failed"));
    }
    free(line);
    rate_note(b, actor->uid, now, nbytes);
    global_bytes_note(b, now, nbytes);
    maybe_rotate(b);
    if (b->poisoned) {
        return reply(resp, rab_response_error(
                               "persist_failed",
                               "audit durability uncertain after rotation"));
    }
    return reply(resp, rab_response_emit_ok(cid, "system"));
}

/* Capability discovery: a pure function of compile-time support, touching no
 * broker state and appending nothing. It answers "does this broker offer
 * receipts, and under which digest schemas" before a client opens an intent. */
static int handle_capabilities(char **resp) {
    return reply(resp, rab_response_capabilities());
}

/* Defined with the receipt-issuance helpers below; also used here to hex-encode
 * the presented token's verifier for the by-verifier lookup. */
static void hex_encode(const unsigned char *in, size_t n, char *out);

/* redeem_receipt: the root helper's pre-commit redemption. Token-ADDRESSED --
 * the request carries the opaque receipt, never a correlation id. The broker
 * requires the redeeming peer to be uid 0, derives the token's verifier, finds
 * the receipt by that verifier, redeems via the state primitive (which re-checks
 * everything in constant time and appends the redeemed transition durably before
 * this returns), and derives the response correlation id from the matched
 * intent. The rab_redeem_result maps onto the contract's closed-set receipt
 * error codes. */
static int handle_redeem(rab_broker *b, const rab_actor *actor,
                         const rab_request *req, char **resp) {
    if (actor->uid != 0) {
        return reply(resp, rab_response_error(
                               "receipt_unauthorized",
                               "the redeeming peer is not the root helper"));
    }
    /* the token grammar (32 lc hex) was validated by the parser; derive its
     * verifier and look the receipt up by that verifier. */
    unsigned char vraw[RAB_SHA256_LEN];
    char vhex[RAB_SHA256_HEX_MAX];
    if (rab_sha256(req->effect_receipt, strlen(req->effect_receipt), vraw) != 0) {
        return reply(resp, rab_response_error("internal", "digest failure"));
    }
    hex_encode(vraw, RAB_SHA256_LEN, vhex);
    explicit_bzero(vraw, sizeof vraw);
    intent *it = open_find_verifier(b, vhex);
    if (it == NULL) {
        return reply(resp, rab_response_error("receipt_invalid",
                                              "no such effect receipt"));
    }
    /* the correlation id is DERIVED from the matched intent, never client input */
    rab_redeem_result rr = rab_broker_redeem_receipt(
        b, it->cid, req->effect_receipt, actor->uid, req->redeem_principal_uid,
        req->redeem_verb, req->redeem_resource, req->redeem_plan_schema,
        req->redeem_plan_hash);
    switch (rr) {
    case RAB_REDEEM_OK:
        return reply(resp, rab_response_redeem_ok(it->cid));
    case RAB_REDEEM_NOT_REDEEMER:
        return reply(resp, rab_response_error("receipt_unauthorized",
                                              "the redeeming peer is not uid 0"));
    case RAB_REDEEM_PRINCIPAL:
        return reply(resp, rab_response_error(
                               "receipt_actor_mismatch",
                               "principal_uid differs from the bound actor"));
    case RAB_REDEEM_BINDING:
        return reply(resp, rab_response_error(
                               "receipt_mismatch",
                               "verb/resource/plan differ from the bound values"));
    case RAB_REDEEM_EXPIRED:
        return reply(resp, rab_response_error(
                               "receipt_expired", "past its TTL, or the boot id changed"));
    case RAB_REDEEM_ALREADY:
        return reply(resp,
                     rab_response_error("receipt_redeemed", "already redeemed"));
    case RAB_REDEEM_UNKNOWN:
    case RAB_REDEEM_TOKEN:
        return reply(resp, rab_response_error("receipt_invalid",
                                              "no such effect receipt"));
    case RAB_REDEEM_PERSIST:
        return reply(resp, rab_response_error("persist_failed",
                                              "redemption durability failed"));
    }
    return reply(resp, rab_response_error("internal", "unhandled redeem result"));
}

int rab_broker_handle(rab_broker *b, const rab_actor *actor,
                      const rab_request *req, char **resp) {
    *resp = NULL;
    if (b->poisoned) {
        /* a prior partial append / fsync uncertainty: refuse everything until a
         * restart reconstructs and truncates the sink. */
        return reply(resp, rab_response_error(
                               "persist_failed",
                               "sink unusable after a write fault; restart required"));
    }
    switch (req->type) {
    case RAB_REQ_OPEN_INTENT:
        return handle_open(b, actor, req, resp);
    case RAB_REQ_WRITE_OUTCOME:
        return handle_outcome(b, actor, req, resp);
    case RAB_REQ_EMIT:
        return handle_emit(b, actor, req, resp);
    case RAB_REQ_CAPABILITIES:
        return handle_capabilities(resp);
    case RAB_REQ_REDEEM:
        return handle_redeem(b, actor, req, resp);
    }
    return reply(resp, rab_response_error("internal", "unhandled request type"));
}

/* ---- startup reconstruction -------------------------------------------- */

/* Hashed set of closed correlation ids, for detecting double outcomes and the
 * carry-forward of an already-closed intent during reconstruction. A linked
 * list here was the other half of the O(n^2): a lookup per record. */
typedef struct cidnode {
    char cid[RAB_CID_MAX];
    struct cidnode *hnext;
} cidnode;

typedef struct {
    cidnode **bkt;
    size_t nbkt;
} cidset;

static int cidset_init(cidset *s, size_t hint) {
    s->nbkt = pow2_ceil(hint < 1024 ? 1024 : hint);
    s->bkt = calloc(s->nbkt, sizeof *s->bkt);
    return s->bkt != NULL ? 0 : -1;
}

static int cidset_has(const cidset *s, const char *cid) {
    for (cidnode *n = s->bkt[hstr(cid) & (s->nbkt - 1)]; n != NULL;
         n = n->hnext) {
        if (strcmp(n->cid, cid) == 0) {
            return 1;
        }
    }
    return 0;
}

static int cidset_add(cidset *s, const char *cid) {
    size_t h = hstr(cid) & (s->nbkt - 1);
    cidnode *n = calloc(1, sizeof *n);
    if (n == NULL) {
        return -1;
    }
    snprintf(n->cid, sizeof n->cid, "%s", cid);
    n->hnext = s->bkt[h];
    s->bkt[h] = n;
    return 0;
}

static void cidset_free(cidset *s) {
    if (s->bkt == NULL) {
        return;
    }
    for (size_t i = 0; i < s->nbkt; i++) {
        cidnode *n = s->bkt[i];
        while (n != NULL) {
            cidnode *x = n->hnext;
            free(n);
            n = x;
        }
    }
    free(s->bkt);
    s->bkt = NULL;
}

/* Do a receipt record's bound identity fields match an intent's installed
 * receipt? Used to tell an idempotent replay (equal) from a conflicting
 * duplicate (differ). The verifier is part of the identity, so a re-minted
 * receipt for the same cid conflicts. */
static int receipt_bound_eq(const intent *it, const rab_stored *s) {
    return it->rcpt_actor_uid == s->rcpt_actor_uid &&
           it->rcpt_plan_schema == s->rcpt_plan_schema &&
           it->rcpt_issue_boottime_us == s->rcpt_issue_boottime_us &&
           it->rcpt_ttl_us == s->rcpt_ttl_us &&
           strcmp(it->verifier_hex, s->rcpt_verifier) == 0 &&
           strcmp(it->rcpt_verb, s->rcpt_verb) == 0 &&
           strcmp(it->rcpt_resource, s->rcpt_resource) == 0 &&
           strcmp(it->rcpt_plan_hash, s->rcpt_plan_hash) == 0 &&
           strcmp(it->rcpt_boot_id, s->rcpt_boot_id) == 0;
}

/* Apply a reconstructed broker_receipt record to its already-open intent.
 * First record: a `redeemed` TRANSITION with no prior `issued` is corruption
 * (fail closed); a `redeemed` CHECKPOINT stands alone. Second record: the bound
 * identity must match (a conflicting duplicate fails closed) and the state must
 * be identical (idempotent replay) or a valid issued -> redeemed progression. */
static const char *apply_receipt(rab_broker *b, intent *it,
                                 const rab_stored *s) {
    /* the receipt's bound identity must match its parent intent: a receipt whose
     * actor/verb/resource disagrees with the intent it names is corruption. */
    if (s->rcpt_actor_uid != it->actor.uid ||
        strcmp(s->rcpt_verb, it->operation) != 0 ||
        strcmp(s->rcpt_resource, it->resource) != 0) {
        return "receipt bound fields inconsistent with its intent";
    }
    /* a receipt checkpoint only arises from rotation, which also carries the
     * intent as a checkpoint; it can never pair with a raw audit intent. */
    if (s->rcpt_is_checkpoint && !it->from_checkpoint) {
        return "receipt checkpoint beside a non-checkpoint intent";
    }
    if (!it->has_receipt) {
        if (!s->rcpt_is_checkpoint && s->rcpt_state == RAB_RCPT_REDEEMED) {
            return "redeemed receipt transition without a prior issued";
        }
        /* The verifier is globally unique (live issuance's mint-time collision
         * check guarantees it); two DIFFERENT intents carrying the same verifier
         * on disk is corruption or a collision attack. This intent has no receipt
         * yet, so any match is necessarily another intent -> fail startup closed
         * rather than index a duplicate. */
        if (open_find_verifier(b, s->rcpt_verifier) != NULL) {
            return "receipt verifier collides with another intent";
        }
        it->has_receipt = 1;
        it->rcpt_state = s->rcpt_state;
        it->rcpt_actor_uid = s->rcpt_actor_uid;
        it->rcpt_plan_schema = s->rcpt_plan_schema;
        it->rcpt_issue_boottime_us = s->rcpt_issue_boottime_us;
        it->rcpt_ttl_us = s->rcpt_ttl_us;
        snprintf(it->verifier_hex, sizeof it->verifier_hex, "%s",
                 s->rcpt_verifier);
        snprintf(it->rcpt_verb, sizeof it->rcpt_verb, "%s", s->rcpt_verb);
        snprintf(it->rcpt_resource, sizeof it->rcpt_resource, "%s",
                 s->rcpt_resource);
        snprintf(it->rcpt_plan_hash, sizeof it->rcpt_plan_hash, "%s",
                 s->rcpt_plan_hash);
        snprintf(it->rcpt_boot_id, sizeof it->rcpt_boot_id, "%s",
                 s->rcpt_boot_id);
        rcpt_index_add(b, it); /* verifier now set: index for wire redeem lookup */
        return NULL;
    }
    if (!receipt_bound_eq(it, s)) {
        return "conflicting duplicate receipt";
    }
    if (s->rcpt_state == it->rcpt_state) {
        return NULL; /* idempotent replay */
    }
    if (it->rcpt_state == RAB_RCPT_ISSUED && s->rcpt_state == RAB_RCPT_REDEEMED) {
        it->rcpt_state = RAB_RCPT_REDEEMED;
        return NULL;
    }
    return "inconsistent receipt state transition";
}

/* Apply one reconstructed record to the open-set. Returns NULL on success or a
 * static error string on an inconsistency (fail closed). */
static const char *apply_stored(rab_broker *b, const rab_stored *s,
                                cidset *closed) {
    /* An intent (audit) or a carry-forward (broker_checkpoint) opens the cid. */
    int is_intent = (s->type == RAB_REC_AUDIT &&
                     strcmp(s->phase, RAB_PHASE_INTENT) == 0);
    int is_checkpoint = (s->type == RAB_REC_CHECKPOINT);
    if (is_intent || is_checkpoint) {
        if (s->binding[0] == '\0') {
            return "intent/checkpoint record without a binding";
        }
        intent *it = open_find_cid(b, s->correlation_id);
        if (it != NULL) {
            /* an already-open cid: only a checkpoint may repeat it, and only
             * idempotently (identical binding + actor). */
            if (is_intent) {
                return "inconsistent duplicate intent";
            }
            if (strcmp(it->binding, s->binding) != 0 ||
                !rab_actor_eq(&it->actor, &s->actor)) {
                return "inconsistent duplicate checkpoint";
            }
            return NULL; /* idempotent */
        }
        if (cidset_has(closed, s->correlation_id)) {
            return is_intent ? "duplicate intent for a closed operation"
                             : "checkpoint of a closed operation";
        }
        if (open_add(b, s->correlation_id, s->binding, &s->actor, s->operation,
                     s->resource, s->scope) != 0) {
            return "out of memory during reconstruction";
        }
        if (is_checkpoint) {
            /* remember the intent came from a rotation carry, so a receipt
             * checkpoint (which also only comes from rotation) may pair with it. */
            intent *ni = open_find_cid(b, s->correlation_id);
            if (ni != NULL) {
                ni->from_checkpoint = 1;
            }
        }
        return NULL;
    }
    if (s->type == RAB_REC_AUDIT &&
        strcmp(s->phase, RAB_PHASE_OUTCOME) == 0) {
        intent *it = open_find_cid(b, s->correlation_id);
        if (it == NULL) {
            return cidset_has(closed, s->correlation_id)
                       ? "double outcome"
                       : "outcome without a matching intent";
        }
        open_remove(b, it);
        if (cidset_add(closed, s->correlation_id) != 0) {
            return "out of memory during reconstruction";
        }
        return NULL;
    }
    if (s->type == RAB_REC_RECEIPT) {
        /* A receipt associates to an already-reconstructed intent by cid. An
         * orphan receipt (no matching open intent) fails startup closed rather
         * than being ignored: a crash between the intent and receipt appends
         * leaves an intent with NO receipt (safe: no authorization), never a
         * receipt with no intent. */
        intent *it = open_find_cid(b, s->correlation_id);
        if (it == NULL) {
            return cidset_has(closed, s->correlation_id)
                       ? "receipt for a closed operation"
                       : "orphan receipt without a matching intent";
        }
        return apply_receipt(b, it, s);
    }
    /* any other audit phase (e.g. a preview/noop emit) is a standalone closed
     * record: it opens nothing and is not an open/close event. */
    return NULL;
}

/* Read the whole current segment into *buf (malloc'd) / *total. Returns 0 on
 * success (including no file: *buf NULL, *total 0), -1 with *err set on error. */
static int slurp_segment(const char *path, char **buf, size_t *total,
                         const char **err) {
    *buf = NULL;
    *total = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            return 0; /* fresh sink */
        }
        *err = (errno == ELOOP) ? "sink is a symlink"
                                : "cannot read sink for reconstruction";
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        *err = "cannot stat sink for reconstruction";
        return -1;
    }
    if ((unsigned long long) st.st_size > RAB_MAX_SEGMENT_BYTES) {
        close(fd);
        *err = "sink segment exceeds the reconstruction size limit";
        return -1;
    }
    size_t sz = (size_t) st.st_size;
    if (sz == 0) {
        close(fd);
        return 0;
    }
    char *data = malloc(sz);
    if (data == NULL) {
        close(fd);
        *err = "out of memory reading sink";
        return -1;
    }
    size_t got = 0;
    while (got < sz) {
        ssize_t r = read(fd, data + got, sz - got);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(data);
            close(fd);
            *err = "read error during reconstruction";
            return -1;
        }
        if (r == 0) {
            break;
        }
        got += (size_t) r;
    }
    close(fd);
    *buf = data;
    *total = got;
    return 0;
}

/* Physically truncate `path` to `len` bytes and fsync, removing a torn tail so
 * the next append cannot concatenate a valid record onto partial bytes.
 * Returns 0 on success, -1 on failure. */
static int truncate_to(const char *path, off_t len) {
    int fd = open(path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    int rc = 0;
    if (ftruncate(fd, len) != 0 || fsync(fd) != 0) {
        rc = -1;
    }
    close(fd);
    return rc;
}

static int reconstruct(rab_broker *b, const char **err) {
    char *buf = NULL;
    size_t total = 0;
    if (slurp_segment(b->path, &buf, &total, err) != 0) {
        return -1;
    }
    cidset closed;
    /* size the closed set from the segment: ~one record per 128 bytes is a
     * generous over-estimate that keeps chains short without a huge table. */
    if (cidset_init(&closed, total / 128) != 0) {
        free(buf);
        *err = "out of memory sizing reconstruction state";
        return -1;
    }
    int rc = 0;
    int torn = 0;
    size_t keep_bytes = 0;
    char *p = buf;
    char *end = buf + total;
    while (p < end) {
        char *nl = memchr(p, '\n', (size_t) (end - p));
        if (nl == NULL) {
            /* trailing bytes with no newline: a torn final record from a
             * crash mid-append. Discard exactly that partial tail, and record
             * where the last durable record ended so we can truncate it off. */
            torn = 1;
            keep_bytes = (size_t) (p - buf);
            break;
        }
        size_t linelen = (size_t) (nl - p);
        if (linelen > 0) {
            rab_stored s;
            if (rab_parse_stored(p, linelen, &s) != 0) {
                *err = "corrupt audit record during reconstruction";
                rc = -1;
                break;
            }
            if (s.type == RAB_REC_RATE) {
                /* per-uid rate+byte history carried across a rotation: reseed
                 * the ring so both limits survive a restart (the audit records
                 * that seeded them are in an archive we do not read). */
                for (size_t i = 0; i < s.rate_n; i++) {
                    rate_note(b, s.rate_uid, s.rate_times[i], s.rate_bytes[i]);
                }
                rab_stored_free(&s);
            } else {
                const char *e = apply_stored(b, &s, &closed);
                if (e != NULL) {
                    *err = e;
                    rc = -1;
                    rab_stored_free(&s);
                    break;
                }
                /* rate windows rebuild from client ops (audit records), not from
                 * broker-generated checkpoints. The op's appended size is the
                 * stored line plus its newline. */
                if (s.type == RAB_REC_AUDIT) {
                    rate_note(b, s.actor.uid, s.time_us,
                              (unsigned long long) linelen + 1);
                }
                rab_stored_free(&s);
            }
        }
        p = nl + 1;
    }
    free(buf);
    cidset_free(&closed);
    if (rc != 0) {
        return rc;
    }
    /* Repair a torn tail on disk before we ever append: truncate to the last
     * durable newline and fsync. Failing to do so would let the next record
     * join onto the partial bytes and corrupt the sink. */
    if (torn && truncate_to(b->path, (off_t) keep_bytes) != 0) {
        *err = "cannot truncate a torn-tail record during reconstruction";
        return -1;
    }
    return 0;
}

/* ---- lifecycle --------------------------------------------------------- */

rab_broker *rab_broker_open(const char *path, const rab_config *cfg,
                            rab_clock_fn clock, void *ctx, const char **err) {
    *err = NULL;
    rab_broker *b = calloc(1, sizeof *b);
    if (b == NULL) {
        *err = "out of memory";
        return NULL;
    }
    b->path = strdup(path);
    if (b->path == NULL) {
        free(b);
        *err = "out of memory";
        return NULL;
    }
    b->fd = -1;
    b->cfg = *cfg;
    /* A byte budget smaller than a single segment can never be met by pruning
     * archives (the active segment alone would exceed it), so reject the
     * configuration rather than silently running a bound that cannot hold. */
    if (b->cfg.retain_bytes != 0 && b->cfg.rotate_bytes != 0 &&
        b->cfg.retain_bytes < b->cfg.rotate_bytes) {
        *err = "retain_bytes must be >= rotate_bytes";
        free(b->path);
        free(b);
        return NULL;
    }
    /* A per-uid byte quota is enforced through the op ring, whose size is bounded
     * by the op-count limit; without that limit the ring is unbounded, so refuse
     * the combination rather than run an unbounded structure. */
    if (b->cfg.rate_max_bytes_per_uid != 0 && b->cfg.rate_max_in_window == 0) {
        *err = "rate_max_bytes_per_uid requires rate_max_in_window > 0";
        free(b->path);
        free(b);
        return NULL;
    }
    /* The receipt TTL is a fixed, bounded config value: zero (instantly expired)
     * and an out-of-range value are refused rather than run, so issuance never
     * computes a nonsensical or overflowing expiry. */
    if (b->cfg.receipt_ttl_sec == 0 ||
        b->cfg.receipt_ttl_sec > RAB_MAX_RECEIPT_TTL_SEC) {
        *err = "receipt_ttl_sec must be in (0, RAB_MAX_RECEIPT_TTL_SEC]";
        free(b->path);
        free(b);
        return NULL;
    }
    b->clock = clock ? clock : real_clock;
    b->clock_ctx = ctx;
    /* effect-receipt time/boot-id sources default to the real ones; a test may
     * override them via rab_broker_test_set_receipt_time. */
    b->boottime = real_boottime;
    b->bootid = real_bootid;
    b->rcpt_ctx = NULL;
    if (gethostname(b->host, sizeof b->host) != 0) {
        b->host[0] = '\0';
    }
    b->host[sizeof b->host - 1] = '\0';

    /* the open-intent tables (by cid, by binding) and the per-uid table, sized
     * once up front because reconstruction populates them. */
    b->nbkt = pow2_ceil(b->cfg.max_open_global ? b->cfg.max_open_global : 16);
    b->nbkt_uid = 1024;
    b->bkt_cid = calloc(b->nbkt, sizeof *b->bkt_cid);
    b->bkt_bind = calloc(b->nbkt, sizeof *b->bkt_bind);
    b->bkt_rcpt = calloc(b->nbkt, sizeof *b->bkt_rcpt);
    b->bkt_uid = calloc(b->nbkt_uid, sizeof *b->bkt_uid);
    if (b->bkt_cid == NULL || b->bkt_bind == NULL || b->bkt_rcpt == NULL ||
        b->bkt_uid == NULL) {
        *err = "out of memory allocating broker tables";
        rab_broker_close(b);
        return NULL;
    }

    /* discard a stray pending segment from a crashed rotation: the current
     * path is always the authoritative superset. */
    char pending[PATH_MAX];
    if (snprintf(pending, sizeof pending, "%s.pending", path) <
        (int) sizeof pending) {
        unlink(pending);
    }

    if (reconstruct(b, err) != 0) {
        rab_broker_close(b);
        return NULL;
    }

    b->fd = rab_sink_open(path);
    if (b->fd < 0) {
        *err = "cannot open sink for append";
        rab_broker_close(b);
        return NULL;
    }
    struct stat st;
    b->seg_bytes =
        (fstat(b->fd, &st) == 0) ? (unsigned long long) st.st_size : 0;
    return b;
}

void rab_broker_close(rab_broker *b) {
    if (b == NULL) {
        return;
    }
    /* free every open intent by walking the by-cid table (its authoritative
     * membership; the by-bind table indexes the same nodes). */
    if (b->bkt_cid != NULL) {
        for (size_t i = 0; i < b->nbkt; i++) {
            intent *it = b->bkt_cid[i];
            while (it != NULL) {
                intent *n = it->hcid;
                free(it);
                it = n;
            }
        }
    }
    if (b->bkt_uid != NULL) {
        for (size_t i = 0; i < b->nbkt_uid; i++) {
            uid_state *u = b->bkt_uid[i];
            while (u != NULL) {
                uid_state *n = u->hnext;
                free(u->ts);
                free(u->bytes);
                free(u);
                u = n;
            }
        }
    }
    free(b->bkt_cid);
    free(b->bkt_bind);
    free(b->bkt_rcpt);
    free(b->bkt_uid);
    if (b->fd >= 0) {
        close(b->fd);
    }
    free(b->path);
    free(b);
}

size_t rab_broker_open_count(const rab_broker *b) { return b->open_count; }

int rab_broker_has_open(const rab_broker *b, const char *correlation_id) {
    for (intent *it = b->bkt_cid[hstr(correlation_id) & (b->nbkt - 1)];
         it != NULL; it = it->hcid) {
        if (strcmp(it->cid, correlation_id) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ---- effect-receipt issuance ------------------------------------------- */

/* lowercase-hex encode n bytes into out (2n+1 chars incl. NUL). */
static void hex_encode(const unsigned char *in, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = h[in[i] >> 4];
        out[2 * i + 1] = h[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

/* value of one lowercase-hex digit, or -1 if it is not one. */
static int hexval(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

/* Decode exactly 2*n lowercase-hex chars at `in` into out[n]. Returns 0 on
 * success, -1 if any of the 2*n chars is not lowercase hex. Used to turn the
 * stored hex verifier back into a raw digest so the redeem-time comparison can
 * run in constant time on the raw bytes. */
static int hex_decode(const char *in, size_t n, unsigned char *out) {
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(in[2 * i]);
        int lo = hexval(in[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (unsigned char) ((hi << 4) | lo);
    }
    return 0;
}

int rab_broker_issue_receipt(rab_broker *b, const char *correlation_id,
                             long long plan_schema, const char *plan_hash,
                             char *out_token, size_t out_cap) {
    /* Clear the caller's token buffer up front so EVERY failure path (and the
     * success path before the copy) leaves it empty, never stale data. */
    if (out_token != NULL && out_cap > 0) {
        out_token[0] = '\0';
    }
    if (b->poisoned || out_token == NULL || out_cap < RAB_RECEIPT_MAX) {
        return -1;
    }
    /* Only a plan schema this broker advertises may be bound into a receipt; an
     * unadvertised one fails issuance closed (the wire parser already refuses
     * it, but the internal primitive enforces it independently). */
    if (plan_schema != RAB_PLAN_SCHEMA_V1) {
        return -1;
    }
    intent *it = open_find_cid(b, correlation_id);
    if (it == NULL || it->has_receipt) {
        return -1; /* no such open intent, or it already carries a receipt */
    }
    if (!enough_free_space(b)) {
        return -1; /* transient refusal; not a poison */
    }
    /* Broker-owned issue time, boot id, and TTL (never client-supplied). A
     * clock or boot-id failure fails issuance closed. */
    unsigned long long issue_boottime_us = 0;
    char boot_id[RAB_BOOT_ID_MAX];
    if (b->boottime(b->rcpt_ctx, &issue_boottime_us) != 0 ||
        b->bootid(b->rcpt_ctx, boot_id, sizeof boot_id) != 0) {
        return -1;
    }
    /* receipt_ttl_sec is bounded at open (0 < ttl <= RAB_MAX_RECEIPT_TTL_SEC),
     * so this product cannot overflow a 64-bit microsecond counter. */
    unsigned long long ttl_us =
        (unsigned long long) b->cfg.receipt_ttl_sec * 1000000ull;
    char token[RAB_RECEIPT_MAX];
    unsigned char vraw[RAB_SHA256_LEN];
    char vhex[RAB_SHA256_HEX_MAX];
    /* Mint a token whose value differs from this intent's binding and whose
     * verifier is not already indexed by a live receipt. At 128 bits a collision
     * is astronomically unlikely, but it is checked explicitly and re-minted
     * rather than assumed away; exhausting the bounded retries fails closed. */
    int minted = 0;
    for (int attempt = 0; attempt < RAB_RECEIPT_MINT_TRIES; attempt++) {
        if (rab_make_receipt(token, sizeof token) != 0 ||
            rab_sha256(token, strlen(token), vraw) != 0) {
            break; /* CSPRNG or digest failure: fail closed */
        }
        hex_encode(vraw, RAB_SHA256_LEN, vhex);
        if (strcmp(token, it->binding) != 0 &&
            open_find_verifier(b, vhex) == NULL) {
            minted = 1;
            break;
        }
    }
    if (!minted) {
        explicit_bzero(token, sizeof token);
        explicit_bzero(vraw, sizeof vraw);
        return -1;
    }
    /* binds the intent's opener uid, verb (operation) and resource, plus the
     * caller's plan digest and the broker-assigned time/boot id */
    char *line = rab_build_receipt(it->cid, RAB_RCPT_ISSUED, 0, vhex,
                                   it->actor.uid, it->operation, it->resource,
                                   plan_schema, plan_hash, issue_boottime_us,
                                   ttl_us, boot_id);
    int rc = -1;
    if (line != NULL && append_line(b, line) == 0) {
        /* Durable append + fdatasync succeeded: install the in-memory state
         * only now (never before durability). */
        unsigned long long nbytes = (unsigned long long) strlen(line) + 1;
        unsigned long long now = b->clock(b->clock_ctx);
        it->has_receipt = 1;
        it->rcpt_state = RAB_RCPT_ISSUED;
        it->rcpt_actor_uid = it->actor.uid;
        it->rcpt_plan_schema = plan_schema;
        it->rcpt_issue_boottime_us = issue_boottime_us;
        it->rcpt_ttl_us = ttl_us;
        snprintf(it->verifier_hex, sizeof it->verifier_hex, "%s", vhex);
        snprintf(it->rcpt_verb, sizeof it->rcpt_verb, "%s", it->operation);
        snprintf(it->rcpt_resource, sizeof it->rcpt_resource, "%s",
                 it->resource);
        snprintf(it->rcpt_plan_hash, sizeof it->rcpt_plan_hash, "%s", plan_hash);
        snprintf(it->rcpt_boot_id, sizeof it->rcpt_boot_id, "%s", boot_id);
        rcpt_index_add(b, it); /* verifier now set: index for wire redeem lookup */
        /* The receipt append is a durable write: account it under the intent's
         * opener (the bound actor) so per-uid quotas see it and it is carried
         * across a restart, then rotate if the segment outgrew its cap. */
        rate_note(b, it->actor.uid, now, nbytes);
        global_bytes_note(b, now, nbytes);
        maybe_rotate(b);
        if (!b->poisoned) {
            /* hand back the token only now: if rotation left durability
             * uncertain, fail closed and return none. */
            snprintf(out_token, out_cap, "%s", token);
            rc = 0;
        }
    }
    /* line == NULL: invalid effect params (e.g. bad plan_hash) -> no effect.
     * append failure: append_line already poisoned; out_token stays cleared. */
    free(line);
    explicit_bzero(token, sizeof token);
    explicit_bzero(vraw, sizeof vraw);
    return rc;
}

/* ---- effect-receipt redemption ----------------------------------------- */

rab_redeem_result rab_broker_redeem_receipt(rab_broker *b,
                                            const char *correlation_id,
                                            const char *token, uid_t redeemer_uid,
                                            uid_t principal_uid, const char *verb,
                                            const char *resource,
                                            long long plan_schema,
                                            const char *plan_hash) {
    if (b->poisoned) {
        return RAB_REDEEM_PERSIST;
    }
    /* Only the root helper may redeem at all. This is the kernel-verified peer
     * uid in production; a non-root redeemer never authorizes an effect. */
    if (redeemer_uid != 0) {
        return RAB_REDEEM_NOT_REDEEMER;
    }
    if (correlation_id == NULL || token == NULL) {
        return RAB_REDEEM_UNKNOWN;
    }
    intent *it = open_find_cid(b, correlation_id);
    if (it == NULL || !it->has_receipt) {
        return RAB_REDEEM_UNKNOWN;
    }
    /* The pkexec principal must be the intent's bound opener: root acts on behalf
     * of exactly the uid that opened the intent, so the audit stays coherent. */
    if (principal_uid != it->rcpt_actor_uid) {
        return RAB_REDEEM_PRINCIPAL;
    }
    /* Constant-time verifier check: hash the presented token, decode the stored
     * hex verifier back to a raw digest, and CRYPTO_memcmp. The hex is never
     * strcmp'd (that would leak the first-differing position via early exit). */
    {
        unsigned char presented[RAB_SHA256_LEN];
        unsigned char stored[RAB_SHA256_LEN];
        int match = rab_sha256(token, strlen(token), presented) == 0 &&
                    strlen(it->verifier_hex) == RAB_SHA256_LEN * 2 &&
                    hex_decode(it->verifier_hex, RAB_SHA256_LEN, stored) == 0 &&
                    rab_sha256_eq(presented, stored) == 1;
        explicit_bzero(presented, sizeof presented);
        explicit_bzero(stored, sizeof stored);
        if (!match) {
            return RAB_REDEEM_TOKEN;
        }
    }
    /* The presented plan must equal the plan bound at issue. */
    if (verb == NULL || resource == NULL || plan_hash == NULL ||
        plan_schema != it->rcpt_plan_schema ||
        strcmp(verb, it->rcpt_verb) != 0 ||
        strcmp(resource, it->rcpt_resource) != 0 ||
        strcmp(plan_hash, it->rcpt_plan_hash) != 0) {
        return RAB_REDEEM_BINDING;
    }
    /* Single-use: an already-redeemed receipt cannot authorize a second effect.
     * Checked only after identity + token + plan are proven, so the redeemed
     * state is disclosed only to the legitimate holder. */
    if (it->rcpt_state == RAB_RCPT_REDEEMED) {
        return RAB_REDEEM_ALREADY;
    }
    /* Unexpired: the current boot id must equal the issue-time boot id (a reboot
     * resets CLOCK_BOOTTIME, so a receipt from a prior boot is dead) AND the
     * elapsed boot time must be within the TTL. A clock or boot-id read failure
     * cannot establish validity, so it fails closed as expired. */
    {
        unsigned long long now_us = 0;
        char cur_boot[RAB_BOOT_ID_MAX];
        if (b->boottime(b->rcpt_ctx, &now_us) != 0 ||
            b->bootid(b->rcpt_ctx, cur_boot, sizeof cur_boot) != 0) {
            return RAB_REDEEM_EXPIRED;
        }
        if (strcmp(cur_boot, it->rcpt_boot_id) != 0 ||
            now_us < it->rcpt_issue_boottime_us ||
            now_us - it->rcpt_issue_boottime_us > it->rcpt_ttl_us) {
            return RAB_REDEEM_EXPIRED;
        }
    }
    if (!enough_free_space(b)) {
        return RAB_REDEEM_PERSIST; /* transient refusal; not a poison */
    }
    /* Durably append the redeemed TRANSITION (checkpoint=0), carrying the SAME
     * bound identity, verifier, issue time, TTL, and boot id as the issued
     * record, then advance the in-memory state ONLY after the append+fsync
     * succeeds. An append fault poisons the broker and leaves the state issued. */
    char *line = rab_build_receipt(
        it->cid, RAB_RCPT_REDEEMED, 0, it->verifier_hex, it->rcpt_actor_uid,
        it->rcpt_verb, it->rcpt_resource, it->rcpt_plan_schema, it->rcpt_plan_hash,
        it->rcpt_issue_boottime_us, it->rcpt_ttl_us, it->rcpt_boot_id);
    if (line == NULL) {
        return RAB_REDEEM_PERSIST;
    }
    unsigned long long nbytes = (unsigned long long) strlen(line) + 1;
    int arc = append_line(b, line);
    free(line);
    if (arc != 0) {
        return RAB_REDEEM_PERSIST; /* append_line already poisoned */
    }
    it->rcpt_state = RAB_RCPT_REDEEMED;
    /* Account the redeemed append under the bound ORIGINAL actor (not the root
     * redeemer) so the volume is attributed to the principal who initiated the
     * operation and is carried across a restart, then rotate. A post-append
     * rotation poisoning is a failure: the redeemed state is durable, but its
     * durability is uncertain, so do not report success. */
    unsigned long long now = b->clock(b->clock_ctx);
    rate_note(b, it->rcpt_actor_uid, now, nbytes);
    global_bytes_note(b, now, nbytes);
    maybe_rotate(b);
    if (b->poisoned) {
        return RAB_REDEEM_PERSIST;
    }
    return RAB_REDEEM_OK;
}

int rab_broker_receipt_state(const rab_broker *b, const char *correlation_id) {
    for (intent *it = b->bkt_cid[hstr(correlation_id) & (b->nbkt - 1)];
         it != NULL; it = it->hcid) {
        if (strcmp(it->cid, correlation_id) == 0) {
            if (!it->has_receipt) {
                return -1;
            }
            return it->rcpt_state == RAB_RCPT_REDEEMED ? 1 : 0;
        }
    }
    return -1;
}

int rab_broker_poisoned(const rab_broker *b) { return b->poisoned; }

void rab_broker_test_fail_next_append(rab_broker *b, rab_test_fail_mode mode) {
    b->test_fail = mode;
}

void rab_broker_test_set_receipt_time(rab_broker *b, rab_boottime_fn bt,
                                      rab_bootid_fn bid, void *ctx) {
    b->boottime = bt ? bt : real_boottime;
    b->bootid = bid ? bid : real_bootid;
    b->rcpt_ctx = ctx;
}
