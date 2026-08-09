/* Socket-level tests: the real broker binary is exec'd (an ASan build, so the
 * daemon runs under the sanitizer during live socket load) and driven over an
 * AF_UNIX socket. Covers the end-to-end lifecycle, SO_PEERCRED overriding
 * payload identity, malformed frames, slowloris (stall + drip, with a second
 * client still served), concurrent writers, disconnect durability, and per-uid
 * connection-attempt limiting. Conformance 11,12,15,17,19,28. */
#include "../src/broker.h"
#include "../src/proto.h"

#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                    \
        checks++;                                                           \
        if (!(cond)) {                                                      \
            failures++;                                                     \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        }                                                                  \
    } while (0)

static const char *broker_bin(void) {
    const char *b = getenv("RAB_BROKER_BIN");
    return (b && b[0]) ? b : "./build-broker-asan";
}

/* ---- temp dir ---------------------------------------------------------- */

static void tmpdir(char *out, size_t n) {
    char tmpl[] = "/tmp/rab-sock-XXXXXX";
    char *d = mkdtemp(tmpl);
    snprintf(out, n, "%s", d ? d : "/tmp/rab-sock-fb");
}

static void cleanup_dir(const char *dir) {
    /* remove the well-known files; leftover archives are harmless in /tmp */
    char p[512];
    snprintf(p, sizeof p, "%s/audit.jsonl", dir);
    unlink(p);
    snprintf(p, sizeof p, "%s/audit.jsonl.pending", dir);
    unlink(p);
    snprintf(p, sizeof p, "%s/sock", dir);
    unlink(p);
    rmdir(dir);
}

/* ---- broker process ---------------------------------------------------- */

/* Start the broker on `sock`/`sink` with short deadlines. Returns the pid. */
static pid_t start_broker(const char *sock, const char *sink, int recv_ms,
                          unsigned conn_max) {
    char recv_s[16], conn_s[16];
    snprintf(recv_s, sizeof recv_s, "%d", recv_ms);
    snprintf(conn_s, sizeof conn_s, "%u", conn_max);
    setenv("RAB_RECV_TIMEOUT_MS", recv_s, 1);
    setenv("RAB_SEND_TIMEOUT_MS", "2000", 1);
    setenv("RAB_CONN_MAX_PER_UID", conn_s, 1);
    setenv("RAB_CONN_WINDOW_MS", "60000", 1);
    pid_t pid = fork();
    if (pid == 0) {
        execl(broker_bin(), broker_bin(), "--listen", sock, "--sink", sink,
              (char *) NULL);
        perror("execl");
        _exit(127);
    }
    return pid;
}

static int wait_for_socket(const char *path, int timeout_ms) {
    struct timespec step = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
    for (int waited = 0; waited < timeout_ms; waited += 5) {
        struct stat st;
        if (stat(path, &st) == 0) {
            return 0;
        }
        nanosleep(&step, NULL);
    }
    return -1;
}

static void stop_broker(pid_t pid, int *exit_ok) {
    kill(pid, SIGTERM);
    int status = 0;
    for (int i = 0; i < 400; i++) { /* up to ~2s */
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (exit_ok) {
                *exit_ok = (WIFEXITED(status) && WEXITSTATUS(status) == 0);
            }
            return;
        }
        struct timespec step = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&step, NULL);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    if (exit_ok) {
        *exit_ok = 0; /* had to be killed: not a clean exit */
    }
}

/* ---- client helpers ---------------------------------------------------- */

static int client_connect(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);
    if (connect(fd, (struct sockaddr *) &addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* One request over its own connection; returns the malloc'd response body (or
 * NULL). Closes the fd. */
static char *request(const char *path, const char *body) {
    int fd = client_connect(path);
    if (fd < 0) {
        return NULL;
    }
    if (rab_write_frame(fd, body, (uint32_t) strlen(body)) != 0) {
        close(fd);
        return NULL;
    }
    /* deadline read on a non-blocking fd */
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    struct timespec dl;
    clock_gettime(CLOCK_MONOTONIC, &dl);
    dl.tv_sec += 3;
    char *rbody = NULL;
    uint32_t rlen = 0;
    rab_frame_status s = rab_read_frame_deadline(fd, &rbody, &rlen, &dl);
    close(fd);
    if (s != RAB_FRAME_OK) {
        free(rbody);
        return NULL;
    }
    return rbody;
}

static int resp_ok(const char *body) {
    json_error_t e;
    json_t *r = json_loads(body, 0, &e);
    if (r == NULL) {
        return -1;
    }
    int ok = json_is_true(json_object_get(r, "ok"));
    json_decref(r);
    return ok;
}

static char *resp_str(const char *body, const char *key) {
    json_error_t e;
    json_t *r = json_loads(body, 0, &e);
    if (r == NULL) {
        return NULL;
    }
    json_t *v = json_object_get(r, key);
    char *out = (json_is_string(v)) ? strdup(json_string_value(v)) : NULL;
    json_decref(r);
    return out;
}

static const char *OPEN_BODY =
    "{\"type\":\"open_intent\",\"record\":"
    "{\"operation\":\"svc.restart\",\"outcome\":\"intent\"}}";

/* ---- tests ------------------------------------------------------------- */

static void test_end_to_end(void) {
    char dir[256], sock[320], sink[320];
    tmpdir(dir, sizeof dir);
    snprintf(sock, sizeof sock, "%s/sock", dir);
    snprintf(sink, sizeof sink, "%s/audit.jsonl", dir);
    pid_t pid = start_broker(sock, sink, 5000, 0);
    CHECK(wait_for_socket(sock, 3000) == 0, "broker socket appeared");

    char *r = request(sock, OPEN_BODY);
    CHECK(r != NULL, "open response received");
    CHECK(r && resp_ok(r) == 1, "open ok");
    char *binding = r ? resp_str(r, "binding") : NULL;
    char *cid = r ? resp_str(r, "correlation_id") : NULL;
    CHECK(binding != NULL && cid != NULL, "open returns binding + cid");
    free(r);

    if (binding) {
        char ob[512];
        snprintf(ob, sizeof ob,
                 "{\"type\":\"write_outcome\",\"binding\":\"%s\",\"record\":"
                 "{\"operation\":\"svc.restart\",\"outcome\":\"ok\","
                 "\"effect_issued\":true}}",
                 binding);
        char *r2 = request(sock, ob);
        CHECK(r2 != NULL && resp_ok(r2) == 1, "outcome ok");
        free(r2);
    }

    /* an emit (single non-effect record) round-trips: ok + cid, no binding */
    char *re = request(sock,
                       "{\"type\":\"emit\",\"phase\":\"preview\",\"record\":"
                       "{\"operation\":\"svc.restart\",\"outcome\":\"preview\","
                       "\"effect_issued\":false}}");
    CHECK(re != NULL && resp_ok(re) == 1, "emit ok over socket");
    char *ecid = re ? resp_str(re, "correlation_id") : NULL;
    char *ebind = re ? resp_str(re, "binding") : NULL;
    CHECK(ecid != NULL, "emit returns a correlation id");
    CHECK(ebind == NULL, "emit returns no binding");
    free(ecid);
    free(ebind);
    free(re);

    int exit_ok = 0;
    stop_broker(pid, &exit_ok);
    CHECK(exit_ok, "broker exited cleanly (no ASan errors/leaks)");

    /* the sink recorded the actor from SO_PEERCRED (== our uid), and a matching
     * intent/outcome pair. */
    rab_config cfg;
    rab_config_defaults(&cfg);
    const char *err = NULL;
    rab_broker *b = rab_broker_open(sink, &cfg, NULL, NULL, &err);
    CHECK(b != NULL, "sink reconstructs after run");
    CHECK(b != NULL && rab_broker_open_count(b) == 0,
          "intent was closed by the outcome");
    if (b) {
        rab_broker_close(b);
    }
    free(binding);
    free(cid);
    cleanup_dir(dir);
}

static void test_payload_identity_ignored(void) {
    char dir[256], sock[320], sink[320];
    tmpdir(dir, sizeof dir);
    snprintf(sock, sizeof sock, "%s/sock", dir);
    snprintf(sink, sizeof sink, "%s/audit.jsonl", dir);
    pid_t pid = start_broker(sock, sink, 5000, 0);
    CHECK(wait_for_socket(sock, 3000) == 0, "broker up (identity)");

    /* a record carrying an actor/uid claim is rejected by the schema (broker
     * stamps identity from SO_PEERCRED, never the payload). */
    const char *forged =
        "{\"type\":\"open_intent\",\"record\":"
        "{\"operation\":\"x\",\"outcome\":\"intent\",\"actor\":{\"uid\":0}}}";
    char *r = request(sock, forged);
    CHECK(r != NULL, "forged-identity response received");
    char *code = r ? resp_str(r, "error") : NULL;
    CHECK(code != NULL && strcmp(code, "schema_invalid") == 0,
          "payload identity claim rejected");
    free(code);
    free(r);

    /* a clean open records the real caller uid */
    char *r2 = request(sock, OPEN_BODY);
    CHECK(r2 && resp_ok(r2) == 1, "clean open ok");
    free(r2);

    int exit_ok = 0;
    stop_broker(pid, &exit_ok);
    CHECK(exit_ok, "broker clean exit (identity)");

    /* read the sink line and confirm actor.uid == our uid */
    FILE *f = fopen(sink, "r");
    CHECK(f != NULL, "sink readable");
    int matched_uid = 0;
    if (f) {
        char line[4096];
        while (fgets(line, sizeof line, f)) {
            json_error_t e;
            json_t *rec = json_loads(line, 0, &e);
            if (rec) {
                /* the numeric identity lives in broker.peer.uid; the canonical
                 * actor is the "uid:<n>" string. Both must be the caller. */
                json_t *peer =
                    json_object_get(json_object_get(rec, "broker"), "peer");
                json_t *uid = json_object_get(peer, "uid");
                json_t *actor = json_object_get(rec, "actor");
                char want[32];
                snprintf(want, sizeof want, "uid:%ld", (long) getuid());
                if (json_is_integer(uid) &&
                    (uid_t) json_integer_value(uid) == getuid() &&
                    json_is_string(actor) &&
                    strcmp(json_string_value(actor), want) == 0) {
                    matched_uid = 1;
                }
                json_decref(rec);
            }
        }
        fclose(f);
    }
    CHECK(matched_uid, "recorded actor.uid is the SO_PEERCRED uid");
    cleanup_dir(dir);
}

static void test_malformed_frames(void) {
    char dir[256], sock[320], sink[320];
    tmpdir(dir, sizeof dir);
    snprintf(sock, sizeof sock, "%s/sock", dir);
    snprintf(sink, sizeof sink, "%s/audit.jsonl", dir);
    pid_t pid = start_broker(sock, sink, 5000, 0);
    CHECK(wait_for_socket(sock, 3000) == 0, "broker up (malformed)");

    /* bad version byte */
    {
        int fd = client_connect(sock);
        unsigned char hdr[5] = {2, 0, 0, 0, 5};
        (void) !write(fd, hdr, sizeof hdr);
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        struct timespec dl;
        clock_gettime(CLOCK_MONOTONIC, &dl);
        dl.tv_sec += 2;
        char *rb = NULL;
        uint32_t rl = 0;
        rab_frame_status s = rab_read_frame_deadline(fd, &rb, &rl, &dl);
        CHECK(s == RAB_FRAME_OK && rb != NULL, "bad-version got a response");
        if (rb) {
            char *code = resp_str(rb, "error");
            CHECK(code && strcmp(code, "bad_frame") == 0, "bad_frame code");
            free(code);
        }
        free(rb);
        close(fd);
    }
    /* oversize length prefix (> 64 KiB) */
    {
        int fd = client_connect(sock);
        unsigned char hdr[5] = {1, 0x00, 0x02, 0x00, 0x00}; /* 131072 */
        (void) !write(fd, hdr, sizeof hdr);
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        struct timespec dl;
        clock_gettime(CLOCK_MONOTONIC, &dl);
        dl.tv_sec += 2;
        char *rb = NULL;
        uint32_t rl = 0;
        rab_frame_status s = rab_read_frame_deadline(fd, &rb, &rl, &dl);
        CHECK(s == RAB_FRAME_OK && rb != NULL, "oversize got a response");
        if (rb) {
            char *code = resp_str(rb, "error");
            CHECK(code && strcmp(code, "too_large") == 0, "too_large code");
            free(code);
        }
        free(rb);
        close(fd);
    }
    /* truncated body then disconnect: broker must survive and keep serving */
    {
        int fd = client_connect(sock);
        unsigned char hdr[5] = {1, 0, 0, 0, 100}; /* claims 100 bytes */
        (void) !write(fd, hdr, sizeof hdr);
        (void) !write(fd, "short", 5);
        close(fd); /* EOF mid-body */
    }
    char *r = request(sock, OPEN_BODY);
    CHECK(r && resp_ok(r) == 1, "broker still serves after truncated frame");
    free(r);

    int exit_ok = 0;
    stop_broker(pid, &exit_ok);
    CHECK(exit_ok, "broker clean exit (malformed)");
    cleanup_dir(dir);
}

static void test_slowloris(void) {
    char dir[256], sock[320], sink[320];
    tmpdir(dir, sizeof dir);
    snprintf(sock, sizeof sock, "%s/sock", dir);
    snprintf(sink, sizeof sink, "%s/audit.jsonl", dir);
    /* short receive deadline so the stalled connection is reclaimed fast */
    pid_t pid = start_broker(sock, sink, 300, 0);
    CHECK(wait_for_socket(sock, 3000) == 0, "broker up (slowloris)");

    /* client A: send one byte, then stall (never complete the frame) */
    int a = client_connect(sock);
    CHECK(a >= 0, "slowloris client connected");
    unsigned char one = 1; /* a lone version byte */
    (void) !write(a, &one, 1);

    /* client B connects and sends a full request; it must be served within a
     * bounded time (~the deadline), proving A did not monopolize the loop. */
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    char *r = request(sock, OPEN_BODY);
    long long took = (long long) (0);
    {
        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        took = (t1.tv_sec - t0.tv_sec) * 1000LL +
               (t1.tv_nsec - t0.tv_nsec) / 1000000LL;
    }
    CHECK(r && resp_ok(r) == 1, "second client served despite slow client");
    CHECK(took < 2000, "second client served promptly (within ~deadline)");
    free(r);

    /* client A's connection is closed by the broker at the deadline: a read
     * now returns EOF (0). */
    int fl = fcntl(a, F_GETFL, 0);
    fcntl(a, F_SETFL, fl | O_NONBLOCK);
    struct timespec dl;
    clock_gettime(CLOCK_MONOTONIC, &dl);
    dl.tv_sec += 2;
    char buf[8];
    int got_eof = 0;
    while (1) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > dl.tv_sec) {
            break;
        }
        ssize_t n = read(a, buf, sizeof buf);
        if (n == 0) {
            got_eof = 1;
            break;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct timespec s = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
            nanosleep(&s, NULL);
            continue;
        }
        if (n < 0) {
            break;
        }
    }
    CHECK(got_eof, "stalled connection closed at the absolute deadline");
    close(a);

    /* drip variant: send a byte at a time slower than the frame needs; the
     * absolute deadline still fires (progress does not reset it). */
    int c = client_connect(sock);
    CHECK(c >= 0, "drip client connected");
    struct timespec drip_start;
    clock_gettime(CLOCK_MONOTONIC, &drip_start);
    unsigned char frame[9] = {1, 0, 0, 0, 4, 't', 'e', 's', 't'};
    int drip_closed = 0;
    for (int i = 0; i < 9; i++) {
        ssize_t w = write(c, &frame[i], 1);
        if (w <= 0) {
            drip_closed = 1;
            break; /* broker closed the connection mid-drip */
        }
        struct timespec s = {.tv_sec = 0, .tv_nsec = 100 * 1000000L}; /* 100ms */
        nanosleep(&s, NULL);
    }
    long long drip_ms = (long long) 0;
    {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        drip_ms = (now.tv_sec - drip_start.tv_sec) * 1000LL +
                  (now.tv_nsec - drip_start.tv_nsec) / 1000000LL;
    }
    /* Either the write failed (SIGPIPE ignored -> EPIPE) once the broker closed
     * the connection past the 300ms deadline, or we finished dripping and a
     * subsequent read sees EOF. Confirm the broker did not accept the frame. */
    if (!drip_closed) {
        int fl2 = fcntl(c, F_GETFL, 0);
        fcntl(c, F_SETFL, fl2 | O_NONBLOCK);
        struct timespec ddl;
        clock_gettime(CLOCK_MONOTONIC, &ddl);
        ddl.tv_sec += 1;
        char *rb = NULL;
        uint32_t rl = 0;
        rab_frame_status s = rab_read_frame_deadline(c, &rb, &rl, &ddl);
        CHECK(s != RAB_FRAME_OK, "dripped frame not accepted as a valid frame");
        free(rb);
    } else {
        CHECK(1, "drip connection closed by the broker mid-drip");
    }
    CHECK(drip_ms >= 300, "drip ran past the absolute receive deadline");
    close(c);

    int exit_ok = 0;
    stop_broker(pid, &exit_ok);
    CHECK(exit_ok, "broker clean exit (slowloris)");
    cleanup_dir(dir);
}

static void test_concurrent_writers(void) {
    char dir[256], sock[320], sink[320];
    tmpdir(dir, sizeof dir);
    snprintf(sock, sizeof sock, "%s/sock", dir);
    snprintf(sink, sizeof sink, "%s/audit.jsonl", dir);
    pid_t pid = start_broker(sock, sink, 5000, 0);
    CHECK(wait_for_socket(sock, 3000) == 0, "broker up (concurrent)");

    const int N = 8;
    for (int i = 0; i < N; i++) {
        pid_t c = fork();
        if (c == 0) {
            char *r = request(sock, OPEN_BODY);
            if (r && resp_ok(r) == 1) {
                char *binding = resp_str(r, "binding");
                if (binding) {
                    char ob[512];
                    snprintf(ob, sizeof ob,
                             "{\"type\":\"write_outcome\",\"binding\":\"%s\","
                             "\"record\":{\"operation\":\"svc.restart\","
                             "\"outcome\":\"ok\",\"effect_issued\":true}}",
                             binding);
                    char *r2 = request(sock, ob);
                    free(r2);
                    free(binding);
                }
            }
            free(r);
            _exit(0); /* skip child ASan atexit (inherited allocations) */
        }
    }
    for (int i = 0; i < N; i++) {
        wait(NULL);
    }

    int exit_ok = 0;
    stop_broker(pid, &exit_ok);
    CHECK(exit_ok, "broker clean exit (concurrent)");

    /* every line is a whole, parseable record, and all intents are closed */
    FILE *f = fopen(sink, "r");
    CHECK(f != NULL, "sink readable (concurrent)");
    int lines = 0, parseable = 0;
    if (f) {
        char line[8192];
        while (fgets(line, sizeof line, f)) {
            lines++;
            json_error_t e;
            json_t *rec = json_loads(line, 0, &e);
            if (rec) {
                parseable++;
                json_decref(rec);
            }
        }
        fclose(f);
    }
    CHECK(lines == 2 * N, "one intent + one outcome per writer");
    CHECK(parseable == lines, "every line is a whole, parseable record");

    rab_config cfg;
    rab_config_defaults(&cfg);
    const char *err = NULL;
    rab_broker *b = rab_broker_open(sink, &cfg, NULL, NULL, &err);
    CHECK(b != NULL && rab_broker_open_count(b) == 0,
          "all concurrent intents closed and reconstruct clean");
    if (b) {
        rab_broker_close(b);
    }
    cleanup_dir(dir);
}

static void test_disconnect_durability(void) {
    char dir[256], sock[320], sink[320];
    tmpdir(dir, sizeof dir);
    snprintf(sock, sizeof sock, "%s/sock", dir);
    snprintf(sink, sizeof sink, "%s/audit.jsonl", dir);
    pid_t pid = start_broker(sock, sink, 5000, 0);
    CHECK(wait_for_socket(sock, 3000) == 0, "broker up (disconnect)");

    /* open an intent, read the response, then disconnect without an outcome */
    char *r = request(sock, OPEN_BODY);
    CHECK(r && resp_ok(r) == 1, "open ok (disconnect)");
    char *cid = r ? resp_str(r, "correlation_id") : NULL;
    CHECK(cid != NULL, "got cid");
    free(r);

    int exit_ok = 0;
    stop_broker(pid, &exit_ok);
    CHECK(exit_ok, "broker clean exit (disconnect)");

    /* the intent is durable and still open after the disconnect */
    rab_config cfg;
    rab_config_defaults(&cfg);
    const char *err = NULL;
    rab_broker *b = rab_broker_open(sink, &cfg, NULL, NULL, &err);
    CHECK(b != NULL, "reconstruct after disconnect");
    CHECK(b && cid && rab_broker_has_open(b, cid),
          "disconnected intent stays durably open");
    if (b) {
        rab_broker_close(b);
    }
    free(cid);
    cleanup_dir(dir);
}

static void test_conn_attempt_limit(void) {
    char dir[256], sock[320], sink[320];
    tmpdir(dir, sizeof dir);
    snprintf(sock, sizeof sock, "%s/sock", dir);
    snprintf(sink, sizeof sink, "%s/audit.jsonl", dir);
    /* allow only 3 connection attempts per uid in the window */
    pid_t pid = start_broker(sock, sink, 5000, 3);
    CHECK(wait_for_socket(sock, 3000) == 0, "broker up (conn limit)");

    int served = 0, dropped = 0;
    for (int i = 0; i < 5; i++) {
        char *r = request(sock, OPEN_BODY);
        if (r != NULL) {
            served++;
            free(r);
        } else {
            dropped++;
        }
    }
    CHECK(served == 3, "three connections served");
    CHECK(dropped == 2, "connections beyond the per-uid cap dropped");

    int exit_ok = 0;
    stop_broker(pid, &exit_ok);
    CHECK(exit_ok, "broker clean exit (conn limit)");
    cleanup_dir(dir);
}

int main(void) {
    /* writing to a broker-closed socket (slowloris drip, dropped connection)
     * must yield EPIPE, not kill the test process. */
    signal(SIGPIPE, SIG_IGN);
    alarm(60); /* safety net: never hang CI */
    test_end_to_end();
    test_payload_identity_ignored();
    test_malformed_frames();
    test_slowloris();
    test_concurrent_writers();
    test_disconnect_durability();
    test_conn_attempt_limit();
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
