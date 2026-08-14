/* rab-exercise: VM-ONLY, UNINSTALLED apt-mutation lifecycle driver. It stands in
 * for the future unprivileged issuer (pkgops) so the pkgexec activation slice can
 * be accepted end-to-end on a disposable canary guest, and nowhere else. It is
 * never packaged and never runs on a real host.
 *
 * It performs the WHOLE effect lifecycle in ONE long-lived process, because the
 * outcome binding is pinned to the opener's full process identity
 * ({uid,gid,pid,boot_id,proc-starttime}, peer.c:rab_actor_eq) -- a second process
 * writing the outcome would be refused `actor_mismatch`. Run as the unprivileged
 * principal under test (e.g. `aptbot`):
 *
 *   1. connect the broker, VERIFY its peer is uid 0 (refuse an impostor socket);
 *   2. open_intent with an effect{plan_schema,plan_hash}, keep cid/binding/receipt
 *      in memory only, and validate the reply against the EXACT open_ok_effect
 *      schema (closed key set, dup-key rejecting parse, system scope, cid grammar,
 *      hex tokens, receipt != binding);
 *   3. hand the receipt to the exact pkexec'd entrypoint (derived from the verb,
 *      never chosen freely) over a PRIVATE stdin pipe -- never argv, env, stdout,
 *      or disk;
 *   4. validate the helper result against the EXACT result schema, and enforce the
 *      semantic pairings (ok => effect_issued:true + matching cid; no_op =>
 *      effect_issued:false; a pre-redeem refusal reports an empty cid);
 *   5. write ONE outcome from THIS process, carrying the helper's real
 *      effect_issued and an `observed{status,detail}` object;
 *   6. wipe every buffer that held a token; print ONLY non-secret evidence.
 *
 * --replay (apt.update only, stable descriptor): after a first ok/effect_issued:true
 * update but BEFORE the outcome, re-present the SAME in-memory receipt; the second
 * MUST be nonzero, status=no_intent, detail=receipt_redeemed, effect_issued:false.
 *
 *   make exercise                                   # compile+link (the CI gate)
 *   sudo -u aptbot ./rab-exercise /run/runix-audit.sock apt.hold nginx <h> nginx
 *   sudo -u aptbot ./rab-exercise --replay /run/runix-audit.sock apt.update "" <h>
 */
#include "../src/proto.h"

#include <jansson.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RCPT_HEX 32
#define BIND_HEX 32
#define CID_LEN 37
#define PLAN_HEX 64
#define LOCK_TIMEOUT 60
#define MAX_RESULT 65536
#define HELPER_DEADLINE_MS 180000

enum { EX_OK = 0, EX_FAIL = 1, EX_USAGE = 2, EX_OPEN_LEFT = 3 };

static int status_known(const char *s) {
    static const char *const set[] = {
        "ok",       "no_op",         "apt_locked",     "package_not_owned",
        "held",     "protected_package", "no_intent",  "resolve_failed",
        "not_applied", "operation_failed", "dpkg_broken", "internal"};
    for (size_t i = 0; i < sizeof set / sizeof set[0]; i++) {
        if (strcmp(s, set[i]) == 0) {
            return 1;
        }
    }
    return 0;
}
static int status_is_success(const char *s) {
    return strcmp(s, "ok") == 0 || strcmp(s, "no_op") == 0;
}

/* An object with EXACTLY these keys (no missing, no extra) -- a closed schema. */
static int obj_exact_keys(json_t *o, const char *const *keys, size_t n) {
    if (!json_is_object(o) || json_object_size(o) != n) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (json_object_get(o, keys[i]) == NULL) {
            return 0;
        }
    }
    return 1;
}

static int is_hex_lc(const char *s, size_t n) {
    if (s == NULL || strlen(s) != n) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    return 1;
}
static int cid_valid(const char *s) {
    if (s == NULL || strlen(s) != CID_LEN || s[20] != '-') {
        return 0;
    }
    for (int i = 0; i < 20; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
    }
    return is_hex_lc(s + 21, 16);
}

static const char *entrypoint_for(const char *verb) {
    struct Map {
        const char *verb, *path;
    };
    static const struct Map m[] = {
        {"apt.install", "/usr/libexec/pkgexec/runix-apt-install"},
        {"apt.remove", "/usr/libexec/pkgexec/runix-apt-remove"},
        {"apt.purge", "/usr/libexec/pkgexec/runix-apt-purge"},
        {"apt.upgrade", "/usr/libexec/pkgexec/runix-apt-upgrade"},
        {"apt.dist_upgrade", "/usr/libexec/pkgexec/runix-apt-dist-upgrade"},
        {"apt.update", "/usr/libexec/pkgexec/runix-apt-update"},
        {"apt.hold", "/usr/libexec/pkgexec/runix-apt-hold"},
        {"apt.unhold", "/usr/libexec/pkgexec/runix-apt-unhold"},
        {"apt.configure", "/usr/libexec/pkgexec/runix-apt-configure"}};
    for (size_t i = 0; i < sizeof m / sizeof m[0]; i++) {
        if (strcmp(verb, m[i].verb) == 0) {
            return m[i].path;
        }
    }
    return NULL;
}

static int connect_broker(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof addr.sun_path) {
        fprintf(stderr, "socket path too long\n");
        close(fd);
        return -1;
    }
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);
    if (connect(fd, (struct sockaddr *) &addr, sizeof addr) != 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    struct ucred uc;
    socklen_t uclen = sizeof uc;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &uclen) != 0) {
        perror("SO_PEERCRED");
        close(fd);
        return -1;
    }
    if (uc.uid != 0) {
        fprintf(stderr, "refusing: broker peer is uid %u, not 0\n",
                (unsigned) uc.uid);
        close(fd);
        return -1;
    }
    return fd;
}

/* One request frame -> one response frame, parsed dup-key-rejecting as an object.
 * The raw response frame may carry a receipt/binding, so it is wiped before free. */
static json_t *rpc(int fd, const char *body) {
    if (rab_write_frame(fd, body, (uint32_t) strlen(body)) != 0) {
        fprintf(stderr, "frame write failed\n");
        return NULL;
    }
    char *rbody = NULL;
    uint32_t rlen = 0;
    rab_frame_status s = rab_read_frame(fd, &rbody, &rlen);
    if (s != RAB_FRAME_OK || rbody == NULL) {
        fprintf(stderr, "no valid response frame (status %d)\n", (int) s);
        free(rbody);
        return NULL;
    }
    json_error_t err;
    json_t *o = json_loadb(rbody, rlen, JSON_REJECT_DUPLICATES, &err);
    explicit_bzero(rbody, rlen); /* the open reply carried the receipt + binding */
    free(rbody);
    if (o == NULL || !json_is_object(o)) {
        fprintf(stderr, "response is not a valid JSON object\n");
        json_decref(o);
        return NULL;
    }
    return o;
}

static int reply_ok(json_t *o) {
    return json_is_true(json_object_get(o, "ok"));
}
static int reply_persisted(json_t *o) {
    return json_is_true(json_object_get(o, "persisted"));
}
static const char *reply_str(json_t *o, const char *k) {
    json_t *v = json_object_get(o, k);
    return json_is_string(v) ? json_string_value(v) : NULL;
}

static long now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return -1;
    }
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* Spawn `pkexec <entrypoint>`, feed `req` on a private stdin pipe (bounded write),
 * capture stdout under a byte cap and a shared deadline. Child runs with default
 * SIGPIPE; the parent guards only its write. Every syscall is checked; a non-EINTR
 * read/poll failure is a FAILURE, never partial success. *out = malloc'd stdout,
 * *rc = exit code. Returns 0 iff the child ran to completion within bounds. */
static int run_helper(const char *entrypoint, const char *req, size_t reqlen,
                      char **out, int *rc) {
    *out = NULL;
    *rc = -1;
    long start = now_ms();
    if (start < 0) {
        fprintf(stderr, "clock_gettime failed\n");
        return -1;
    }
    long deadline = start + HELPER_DEADLINE_MS;
    int inp[2], outp[2];
    if (pipe(inp) != 0 || pipe(outp) != 0) {
        perror("pipe");
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        signal(SIGPIPE, SIG_DFL);
        if (dup2(inp[0], STDIN_FILENO) < 0 || dup2(outp[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        close(inp[0]);
        close(inp[1]);
        close(outp[0]);
        close(outp[1]);
        execlp("pkexec", "pkexec", entrypoint, (char *) NULL);
        _exit(127);
    }
    close(inp[0]);
    close(outp[1]);

    struct sigaction ign, old;
    memset(&ign, 0, sizeof ign);
    ign.sa_handler = SIG_IGN;
    int have_old = (sigaction(SIGPIPE, &ign, &old) == 0);
    int wflags = fcntl(inp[1], F_GETFL, 0);
    int rflags = fcntl(outp[0], F_GETFL, 0);
    int setup_ok = have_old && wflags >= 0 && rflags >= 0 &&
                   fcntl(inp[1], F_SETFL, wflags | O_NONBLOCK) == 0 &&
                   fcntl(outp[0], F_SETFL, rflags | O_NONBLOCK) == 0;

    int failed = !setup_ok;
    /* bounded write of the request */
    size_t off = 0;
    while (setup_ok && off < reqlen) {
        long rem = deadline - now_ms();
        if (rem <= 0) {
            failed = 1;
            break;
        }
        struct pollfd pw = {inp[1], POLLOUT, 0};
        int pr = poll(&pw, 1, (int) rem);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            failed = 1;
            break;
        }
        if (pr == 0) {
            failed = 1;
            break;
        }
        ssize_t w = write(inp[1], req + off, reqlen - off);
        if (w < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            failed = 1; /* EPIPE: the child died/denied before reading */
            break;
        }
        off += (size_t) w;
    }
    if (have_old) {
        sigaction(SIGPIPE, &old, NULL);
    }
    close(inp[1]);

    /* bounded, deadline-aware capture of stdout */
    size_t cap = 4096, len = 0;
    char *buf = failed ? NULL : malloc(cap);
    if (!failed && buf == NULL) {
        failed = 1;
    }
    while (!failed) {
        long rem = deadline - now_ms();
        if (rem <= 0) {
            failed = 1;
            break;
        }
        struct pollfd pr = {outp[0], POLLIN, 0};
        int p = poll(&pr, 1, (int) rem);
        if (p < 0) {
            if (errno == EINTR) {
                continue;
            }
            failed = 1;
            break;
        }
        if (p == 0) {
            failed = 1;
            break;
        }
        if (len + 4096 > cap) {
            if (cap >= MAX_RESULT) {
                failed = 1;
                break;
            }
            char *nb = realloc(buf, cap * 2);
            if (nb == NULL) {
                failed = 1;
                break;
            }
            buf = nb;
            cap *= 2;
        }
        ssize_t r = read(outp[0], buf + len, cap - len - 1);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            failed = 1; /* a real read error is a failure, not partial output */
            break;
        }
        if (r == 0) {
            break; /* EOF */
        }
        len += (size_t) r;
    }
    close(outp[0]);
    if (failed) {
        kill(pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
        }
        free(buf);
        return -1;
    }
    buf[len] = '\0';
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    *rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    *out = buf;
    return 0;
}

typedef struct {
    int parsed;
    int exit_code;
    int effect_issued;
    char status[64];
    char detail[80];
    char rcid[CID_LEN + 1];
} helper_outcome;

/* Build {receipt,cid,plan_schema:1,packages,lock_timeout}, run the entrypoint, and
 * parse the result against the EXACT result schema (closed keys, dup-key rejecting,
 * status in the closed set, boolean effect_issued). Wipes the request buffer (which
 * carried the receipt) the instant it is sent. */
static void invoke_helper(const char *entrypoint, const char *receipt,
                          const char *cid, char **pkgs, int npkgs,
                          helper_outcome *ho) {
    memset(ho, 0, sizeof *ho);
    ho->exit_code = -1;
    json_t *pkg_arr = json_array();
    for (int i = 0; i < npkgs; i++) {
        json_array_append_new(pkg_arr, json_string(pkgs[i]));
    }
    json_t *hreq = json_pack("{s:s, s:s, s:i, s:o, s:i}", "effect_receipt",
                             receipt, "correlation_id", cid, "plan_schema", 1,
                             "packages", pkg_arr, "lock_timeout", LOCK_TIMEOUT);
    char *hreq_s = hreq ? json_dumps(hreq, JSON_COMPACT) : NULL;
    json_decref(hreq);
    if (hreq_s == NULL) {
        return;
    }
    char *result = NULL;
    int hrc = 0;
    int ran = run_helper(entrypoint, hreq_s, strlen(hreq_s), &result, &hrc);
    explicit_bzero(hreq_s, strlen(hreq_s));
    free(hreq_s);
    ho->exit_code = hrc;
    if (ran != 0 || result == NULL || result[0] == '\0') {
        free(result);
        return;
    }
    json_error_t jerr;
    json_t *res = json_loads(result, JSON_REJECT_DUPLICATES, &jerr);
    free(result);
    static const char *const rk[] = {"status", "effect_issued", "correlation_id",
                                     "detail"};
    const char *status = res ? reply_str(res, "status") : NULL;
    json_t *jeff = res ? json_object_get(res, "effect_issued") : NULL;
    const char *rcid = res ? reply_str(res, "correlation_id") : NULL;
    const char *detail = res ? reply_str(res, "detail") : NULL;
    if (res != NULL && obj_exact_keys(res, rk, 4) && status != NULL &&
        status_known(status) && json_is_boolean(jeff) && rcid != NULL &&
        detail != NULL) {
        ho->parsed = 1;
        ho->effect_issued = json_is_true(jeff) ? 1 : 0;
        snprintf(ho->status, sizeof ho->status, "%s", status);
        snprintf(ho->detail, sizeof ho->detail, "%s", detail);
        snprintf(ho->rcid, sizeof ho->rcid, "%s", rcid);
    }
    json_decref(res);
}

/* All the result semantics on one path: exit/status agreement, ok => effect:true +
 * matching cid, no_op => effect:false, effect:true => matching cid, and a
 * (pre-redeem) refusal => empty-or-matching cid. */
static int result_semantics_ok(const helper_outcome *ho, const char *cid) {
    if ((ho->exit_code == 0) != status_is_success(ho->status)) {
        return 0;
    }
    if (strcmp(ho->status, "ok") == 0 &&
        !(ho->effect_issued && strcmp(ho->rcid, cid) == 0)) {
        return 0;
    }
    if (strcmp(ho->status, "no_op") == 0 && ho->effect_issued) {
        return 0;
    }
    if (ho->effect_issued) {
        return strcmp(ho->rcid, cid) == 0;
    }
    return ho->rcid[0] == '\0' || strcmp(ho->rcid, cid) == 0;
}

/* Write ONE outcome via the retained binding, carrying the helper's real
 * effect_issued and an observed{status,detail} object. The serialized request
 * holds the binding and is wiped after sending. Returns 1 iff persisted. */
static int write_outcome(const char *sock, const char *binding, const char *verb,
                         const char *resource, const char *status,
                         const char *detail, int effect_issued) {
    const char *ol = status_is_success(status) ? "ok" : "error";
    int ofd = connect_broker(sock);
    if (ofd < 0) {
        return 0;
    }
    json_t *out_body = json_pack(
        "{s:s, s:s, s:{s:s, s:s, s:b, s:s, s:{s:s, s:s}}}", "type",
        "write_outcome", "binding", binding, "record", "operation", verb,
        "resource", resource, "effect_issued", effect_issued, "outcome", ol,
        "observed", "status", status, "detail", detail);
    char *outs = out_body ? json_dumps(out_body, JSON_COMPACT) : NULL;
    json_decref(out_body);
    if (outs == NULL) {
        close(ofd);
        return 0;
    }
    json_t *rep = rpc(ofd, outs);
    explicit_bzero(outs, strlen(outs)); /* the outcome request carried the binding */
    free(outs);
    close(ofd);
    static const char *const ok_keys[] = {"ok", "persisted"};
    int ok = rep != NULL && obj_exact_keys(rep, ok_keys, 2) && reply_ok(rep) &&
             reply_persisted(rep);
    if (!ok) {
        const char *code = rep ? reply_str(rep, "error") : NULL;
        fprintf(stderr, "write_outcome refused: %s\n", code ? code : "(no reply)");
    }
    json_decref(rep);
    return ok;
}

static void evidence(const char *cid, const char *plan_hash, const char *verb,
                     const char *status, const char *detail, int effect_issued,
                     const char *outcome, const char *replay) {
    printf("RESULT cid=%s plan_hash=%s verb=%s status=%s detail=%s "
           "effect_issued=%s outcome=%s%s%s\n",
           cid, plan_hash, verb, status, detail, effect_issued ? "true" : "false",
           outcome, replay ? " replay=" : "", replay ? replay : "");
}

static int left_open(const char *cid, const char *plan_hash, const char *verb,
                     const char *why) {
    fprintf(stderr, "%s; intent LEFT OPEN for reconciliation\n", why);
    printf("RESULT cid=%s plan_hash=%s verb=%s status=unknown detail=unknown "
           "effect_issued=unknown outcome=open\n",
           cid, plan_hash, verb);
    return EX_OPEN_LEFT;
}

int main(int argc, char **argv) {
    int replay = 0;
    int a = 1;
    if (a < argc && strcmp(argv[a], "--replay") == 0) {
        replay = 1;
        a++;
    }
    if (argc - a < 4) {
        fprintf(stderr, "usage: rab-exercise [--replay] <socket> <verb> "
                        "<resource> <plan_hash> [pkg ...]\n");
        return EX_USAGE;
    }
    const char *sock = argv[a];
    const char *verb = argv[a + 1];
    const char *resource = argv[a + 2];
    const char *plan_hash = argv[a + 3];
    char **pkgs = &argv[a + 4];
    int npkgs = argc - (a + 4);

    const char *entrypoint = entrypoint_for(verb);
    if (entrypoint == NULL) {
        fprintf(stderr, "unknown verb: %s\n", verb);
        return EX_USAGE;
    }
    if (replay && strcmp(verb, "apt.update") != 0) {
        fprintf(stderr, "--replay supports only apt.update (stable descriptor)\n");
        return EX_USAGE;
    }
    if (!is_hex_lc(plan_hash, PLAN_HEX)) {
        fprintf(stderr, "plan_hash must be %d lowercase hex chars\n", PLAN_HEX);
        return EX_USAGE;
    }

    int fd = connect_broker(sock);
    if (fd < 0) {
        return EX_FAIL;
    }
    json_t *open_body = json_pack(
        "{s:s, s:{s:s, s:s, s:b, s:s}, s:{s:b, s:i, s:s}}", "type", "open_intent",
        "record", "operation", verb, "resource", resource, "effect_issued", 0,
        "outcome", "intent", "effect", "required", 1, "plan_schema", 1,
        "plan_hash", plan_hash);
    char *ob = open_body ? json_dumps(open_body, JSON_COMPACT) : NULL;
    json_decref(open_body);
    if (ob == NULL) {
        close(fd);
        return EX_FAIL;
    }
    json_t *open_rep = rpc(fd, ob);
    free(ob);
    close(fd);
    if (open_rep == NULL || !reply_ok(open_rep) || !reply_persisted(open_rep)) {
        const char *code = open_rep ? reply_str(open_rep, "error") : NULL;
        fprintf(stderr, "open_intent not durably created: %s\n",
                code ? code : "(no reply / not persisted)");
        json_decref(open_rep);
        return EX_FAIL;
    }
    /* From here the intent is durable: EVERY failure leaves it open. */
    char cid[CID_LEN + 1] = {0};
    char binding[BIND_HEX + 1] = {0};
    char receipt[RCPT_HEX + 1] = {0};
    static const char *const open_keys[] = {"ok",       "correlation_id",
                                            "binding",  "effect_receipt",
                                            "persisted", "audit_scope"};
    const char *scid = reply_str(open_rep, "correlation_id");
    const char *sbind = reply_str(open_rep, "binding");
    const char *srcpt = reply_str(open_rep, "effect_receipt");
    const char *scope = reply_str(open_rep, "audit_scope");
    int schema_ok = obj_exact_keys(open_rep, open_keys, 6) && scid != NULL &&
                    sbind != NULL && srcpt != NULL && scope != NULL &&
                    cid_valid(scid) && is_hex_lc(sbind, BIND_HEX) &&
                    is_hex_lc(srcpt, RCPT_HEX) && strcmp(sbind, srcpt) != 0 &&
                    strcmp(scope, "system") == 0;
    if (!schema_ok) {
        json_decref(open_rep);
        return left_open("", plan_hash, verb, "open reply failed exact schema");
    }
    memcpy(cid, scid, CID_LEN);
    memcpy(binding, sbind, BIND_HEX);
    memcpy(receipt, srcpt, RCPT_HEX);
    json_decref(open_rep);

    helper_outcome ho1;
    invoke_helper(entrypoint, receipt, cid, pkgs, npkgs, &ho1);
    int first_ok = ho1.parsed && result_semantics_ok(&ho1, cid);

    if (!replay) {
        explicit_bzero(receipt, sizeof receipt);
        if (!first_ok) {
            explicit_bzero(binding, sizeof binding);
            return left_open(cid, plan_hash, verb, "helper result invalid");
        }
        int persisted = write_outcome(sock, binding, verb, resource, ho1.status,
                                      ho1.detail, ho1.effect_issued);
        explicit_bzero(binding, sizeof binding);
        if (!persisted) {
            return left_open(cid, plan_hash, verb, "outcome not persisted");
        }
        evidence(cid, plan_hash, verb, ho1.status, ho1.detail, ho1.effect_issued,
                 "persisted", NULL);
        return EX_OK;
    }

    /* replay path (apt.update only) */
    if (!first_ok || strcmp(ho1.status, "ok") != 0 || ho1.effect_issued != 1) {
        explicit_bzero(receipt, sizeof receipt);
        explicit_bzero(binding, sizeof binding);
        return left_open(cid, plan_hash, verb,
                         "first update did not cleanly apply (cannot test replay)");
    }
    helper_outcome ho2;
    invoke_helper(entrypoint, receipt, cid, pkgs, npkgs, &ho2);
    explicit_bzero(receipt, sizeof receipt);
    if (ho2.parsed && ho2.effect_issued == 1) {
        explicit_bzero(binding, sizeof binding);
        return left_open(cid, plan_hash, verb,
                         "SINGLE-USE VIOLATION: replay produced an effect");
    }
    int replay_rejected =
        ho2.parsed && strcmp(ho2.status, "no_intent") == 0 &&
        strcmp(ho2.detail, "receipt_redeemed") == 0 && ho2.effect_issued == 0 &&
        ho2.exit_code != 0 &&
        (ho2.rcid[0] == '\0' || strcmp(ho2.rcid, cid) == 0);
    if (!replay_rejected) {
        explicit_bzero(binding, sizeof binding);
        return left_open(cid, plan_hash, verb,
                         "replay not a clean receipt_redeemed rejection");
    }
    int persisted = write_outcome(sock, binding, verb, resource, ho1.status,
                                  ho1.detail, ho1.effect_issued);
    explicit_bzero(binding, sizeof binding);
    if (!persisted) {
        return left_open(cid, plan_hash, verb, "outcome not persisted");
    }
    evidence(cid, plan_hash, verb, ho1.status, ho1.detail, ho1.effect_issued,
             "persisted", "rejected");
    return EX_OK;
}
