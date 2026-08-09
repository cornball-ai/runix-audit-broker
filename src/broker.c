#include "broker.h"

#include "id.h"
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

/* ---- state ------------------------------------------------------------- */

typedef struct intent {
    char cid[RAB_CID_MAX];
    char binding[RAB_BINDING_MAX];
    rab_actor actor;
    char operation[RAB_META_MAX]; /* retained so a checkpoint stays meaningful */
    char resource[RAB_META_MAX];
    char scope[RAB_SCOPE_MAX];
    struct intent *next;
} intent;

typedef struct uid_state {
    uid_t uid;
    unsigned open;              /* current open intents for this uid */
    unsigned long long *ring;   /* recent appended-record times (us) */
    unsigned cap, n, head;      /* ring buffer bookkeeping */
    struct uid_state *next;
} uid_state;

struct rab_broker {
    char *path;
    int fd;
    rab_config cfg;
    rab_clock_fn clock;
    void *clock_ctx;
    char host[256];
    intent *open;
    size_t open_count;
    uid_state *uids;
    unsigned long long seg_bytes;
    int poisoned; /* a partial append / fsync uncertainty: refuse until restart */
};

void rab_config_defaults(rab_config *cfg) {
    cfg->max_open_per_uid = 2048;
    cfg->max_open_global = 32768;
    cfg->rate_window_sec = 10;
    cfg->rate_max_in_window = 2000;
    cfg->rotate_bytes = 64ull << 20;    /* 64 MiB current-segment cap */
    cfg->min_free_bytes = 64ull << 20;  /* refuse appends below 64 MiB free */
    cfg->retain_segments = 16;          /* keep at most 16 archived segments */
    cfg->retain_bytes = 1024ull << 20;  /* and at most 1 GiB total on disk */
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

/* ---- per-uid rate/quota accounting ------------------------------------- */

static uid_state *uid_find(rab_broker *b, uid_t uid) {
    for (uid_state *u = b->uids; u != NULL; u = u->next) {
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
    u->ring = calloc(cap, sizeof *u->ring);
    if (u->ring == NULL) {
        free(u);
        return NULL;
    }
    u->uid = uid;
    u->cap = cap;
    u->next = b->uids;
    b->uids = u;
    return u;
}

static void ring_push(uid_state *u, unsigned long long t) {
    if (u->n < u->cap) {
        u->ring[(u->head + u->n) % u->cap] = t;
        u->n++;
    } else {
        u->ring[u->head] = t;
        u->head = (u->head + 1) % u->cap;
    }
}

static unsigned ring_count_since(const uid_state *u, unsigned long long th) {
    unsigned c = 0;
    for (unsigned i = 0; i < u->n; i++) {
        if (u->ring[(u->head + i) % u->cap] >= th) {
            c++;
        }
    }
    return c;
}

/* 1 if a new op is within the per-uid rate, 0 if it should be rejected. */
static int rate_allowed(rab_broker *b, uid_t uid, unsigned long long now) {
    if (b->cfg.rate_max_in_window == 0) {
        return 1;
    }
    uid_state *u = uid_get(b, uid);
    if (u == NULL) {
        return 0; /* allocation failure: fail closed */
    }
    unsigned long long window =
        (unsigned long long) b->cfg.rate_window_sec * 1000000ull;
    unsigned long long th = (now > window) ? now - window : 0;
    return ring_count_since(u, th) < b->cfg.rate_max_in_window;
}

static void rate_note(rab_broker *b, uid_t uid, unsigned long long t) {
    if (b->cfg.rate_max_in_window == 0) {
        return;
    }
    uid_state *u = uid_get(b, uid);
    if (u != NULL) {
        ring_push(u, t);
    }
}

/* ---- open-intent set --------------------------------------------------- */

static intent *open_find_binding(rab_broker *b, const char *binding) {
    if (binding[0] == '\0') {
        return NULL;
    }
    for (intent *it = b->open; it != NULL; it = it->next) {
        if (strcmp(it->binding, binding) == 0) {
            return it;
        }
    }
    return NULL;
}

static intent *open_find_cid(rab_broker *b, const char *cid) {
    for (intent *it = b->open; it != NULL; it = it->next) {
        if (strcmp(it->cid, cid) == 0) {
            return it;
        }
    }
    return NULL;
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
    snprintf(it->operation, sizeof it->operation, "%s", operation ? operation : "");
    snprintf(it->resource, sizeof it->resource, "%s", resource ? resource : "");
    snprintf(it->scope, sizeof it->scope, "%s", scope ? scope : "");
    it->next = b->open;
    b->open = it;
    b->open_count++;
    uid_state *u = uid_get(b, actor->uid);
    if (u != NULL) {
        u->open++;
    }
    return 0;
}

static void open_remove(rab_broker *b, intent *target) {
    intent **pp = &b->open;
    while (*pp != NULL) {
        if (*pp == target) {
            *pp = target->next;
            b->open_count--;
            uid_state *u = uid_find(b, target->actor.uid);
            if (u != NULL && u->open > 0) {
                u->open--;
            }
            free(target);
            return;
        }
        pp = &(*pp)->next;
    }
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
    if (rab_sink_append(b->fd, line, len) != 0) {
        b->poisoned = 1;
        return -1;
    }
    b->seg_bytes += (unsigned long long) len + 1; /* record + newline */
    return 0;
}

/* Carry the per-uid rate-window history into the new segment during rotation:
 * for each uid, the broker-assigned timestamps still inside the rate window
 * (only those; older ones are already irrelevant). The client audit records
 * that seeded the ring move to an archive that reconstruction never reads, so
 * without this the per-uid rate limit would reset at the next restart. Bounded
 * by the ring cap. Returns 0, or -1 on a write/alloc failure (rotation is then
 * aborted, leaving the current segment valid). */
static int write_rate_carries(rab_broker *b, int fd) {
    if (b->cfg.rate_max_in_window == 0) {
        return 0;
    }
    unsigned long long now = b->clock(b->clock_ctx);
    unsigned long long window =
        (unsigned long long) b->cfg.rate_window_sec * 1000000ull;
    unsigned long long th = (now > window) ? now - window : 0;
    for (uid_state *u = b->uids; u != NULL; u = u->next) {
        if (u->n == 0) {
            continue;
        }
        unsigned long long *tmp = malloc((size_t) u->n * sizeof *tmp);
        if (tmp == NULL) {
            return -1;
        }
        size_t k = 0;
        for (unsigned i = 0; i < u->n; i++) {
            unsigned long long t = u->ring[(u->head + i) % u->cap];
            if (t >= th) { /* only timestamps still inside the rate window */
                tmp[k++] = t;
            }
        }
        int rc = 0;
        if (k > 0) {
            char *line = rab_build_rate(u->uid, tmp, k);
            if (line == NULL) {
                rc = -1;
            } else {
                rc = rab_sink_append(fd, line, strlen(line));
                free(line);
            }
        }
        free(tmp);
        if (rc != 0) {
            return -1;
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
        struct stat st;
        if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
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
    free(ents);
    if (pruned) {
        rab_fsync_parent_dir(b->path); /* make the deletions durable */
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
    for (intent *it = b->open; it != NULL && rc == 0; it = it->next) {
        unsigned long long now = b->clock(b->clock_ctx);
        char *line = rab_build_checkpoint(it->cid, it->binding, &it->actor, now,
                                          it->operation, it->resource,
                                          it->scope);
        if (line == NULL) {
            rc = -1;
            break;
        }
        if (rab_sink_append(pfd, line, strlen(line)) != 0) {
            rc = -1;
        }
        free(line);
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
    rate_note(b, actor->uid, now);
    maybe_rotate(b);
    if (b->poisoned) {
        /* rotation left the segment's durability uncertain: do not hand back a
         * success the caller would act on. */
        return reply(resp, rab_response_error(
                               "persist_failed",
                               "audit durability uncertain after rotation"));
    }
    return reply(resp, rab_response_open_ok(cid, binding, "system"));
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
    if (!enough_free_space(b)) {
        return reply(resp, rab_response_error("persist_failed",
                                              "insufficient free space"));
    }
    char *line = rab_build_audit(RAB_PHASE_OUTCOME, it->cid, NULL, actor,
                                 b->host, now, req->record);
    if (line == NULL) {
        return reply(resp, rab_response_error("internal", "record build"));
    }
    if (append_line(b, line) != 0) {
        free(line);
        return reply(resp,
                     rab_response_error("persist_failed", "sink append failed"));
    }
    free(line);
    open_remove(b, it); /* single-use: the outcome closes the intent */
    rate_note(b, actor->uid, now);
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
 * write_outcome. It is rate/free-space/rotation-poison accounted exactly like
 * the effect paths. The phase (preview|noop) and the non-effect record were
 * already constrained by the parser, so this cannot be a generic append. */
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
    if (append_line(b, line) != 0) {
        free(line);
        return reply(resp,
                     rab_response_error("persist_failed", "sink append failed"));
    }
    free(line);
    rate_note(b, actor->uid, now);
    maybe_rotate(b);
    if (b->poisoned) {
        return reply(resp, rab_response_error(
                               "persist_failed",
                               "audit durability uncertain after rotation"));
    }
    return reply(resp, rab_response_emit_ok(cid, "system"));
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
    }
    return reply(resp, rab_response_error("internal", "unhandled request type"));
}

/* ---- startup reconstruction -------------------------------------------- */

/* temporary set of closed correlation ids, for detecting double outcomes and
 * carry-forward of an already-closed intent during reconstruction. */
typedef struct cidnode {
    char cid[RAB_CID_MAX];
    struct cidnode *next;
} cidnode;

static int cid_in_list(const cidnode *l, const char *cid) {
    for (; l != NULL; l = l->next) {
        if (strcmp(l->cid, cid) == 0) {
            return 1;
        }
    }
    return 0;
}

static int cid_add(cidnode **l, const char *cid) {
    cidnode *n = calloc(1, sizeof *n);
    if (n == NULL) {
        return -1;
    }
    snprintf(n->cid, sizeof n->cid, "%s", cid);
    n->next = *l;
    *l = n;
    return 0;
}

static void cid_free(cidnode *l) {
    while (l != NULL) {
        cidnode *n = l->next;
        free(l);
        l = n;
    }
}

/* Apply one reconstructed record to the open-set. Returns NULL on success or a
 * static error string on an inconsistency (fail closed). */
static const char *apply_stored(rab_broker *b, const rab_stored *s,
                                cidnode **closed) {
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
        if (cid_in_list(*closed, s->correlation_id)) {
            return is_intent ? "duplicate intent for a closed operation"
                             : "checkpoint of a closed operation";
        }
        if (open_add(b, s->correlation_id, s->binding, &s->actor, s->operation,
                     s->resource, s->scope) != 0) {
            return "out of memory during reconstruction";
        }
        return NULL;
    }
    if (s->type == RAB_REC_AUDIT &&
        strcmp(s->phase, RAB_PHASE_OUTCOME) == 0) {
        intent *it = open_find_cid(b, s->correlation_id);
        if (it == NULL) {
            return cid_in_list(*closed, s->correlation_id)
                       ? "double outcome"
                       : "outcome without a matching intent";
        }
        open_remove(b, it);
        if (cid_add(closed, s->correlation_id) != 0) {
            return "out of memory during reconstruction";
        }
        return NULL;
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
    cidnode *closed = NULL;
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
                /* per-uid rate history carried across a rotation: reseed the
                 * ring so the limit survives a restart (the audit records that
                 * seeded it are in an archive we do not read). */
                for (size_t i = 0; i < s.rate_n; i++) {
                    rate_note(b, s.rate_uid, s.rate_times[i]);
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
                 * broker-generated checkpoints. */
                if (s.type == RAB_REC_AUDIT) {
                    rate_note(b, s.actor.uid, s.time_us);
                }
                rab_stored_free(&s);
            }
        }
        p = nl + 1;
    }
    free(buf);
    cid_free(closed);
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
    b->clock = clock ? clock : real_clock;
    b->clock_ctx = ctx;
    if (gethostname(b->host, sizeof b->host) != 0) {
        b->host[0] = '\0';
    }
    b->host[sizeof b->host - 1] = '\0';

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
    intent *it = b->open;
    while (it != NULL) {
        intent *n = it->next;
        free(it);
        it = n;
    }
    uid_state *u = b->uids;
    while (u != NULL) {
        uid_state *n = u->next;
        free(u->ring);
        free(u);
        u = n;
    }
    if (b->fd >= 0) {
        close(b->fd);
    }
    free(b->path);
    free(b);
}

size_t rab_broker_open_count(const rab_broker *b) { return b->open_count; }

int rab_broker_has_open(const rab_broker *b, const char *correlation_id) {
    for (intent *it = b->open; it != NULL; it = it->next) {
        if (strcmp(it->cid, correlation_id) == 0) {
            return 1;
        }
    }
    return 0;
}
