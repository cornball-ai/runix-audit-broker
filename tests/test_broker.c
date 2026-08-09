/* Broker state-machine tests: the intent/outcome lifecycle, full-identity
 * matching, single-use bindings, startup reconstruction (fail-closed cases),
 * partial-tail recovery, carry-forward rotation + idempotency, bounded open
 * intents, and rate limits that survive a restart. Conformance tests 22-27
 * plus the core lifecycle. Built against Jansson with ASan/UBSan. */
#include "../src/broker.h"
#include "../src/json.h"
#include "../src/record.h"

#include <dirent.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* ---- injectable clock -------------------------------------------------- */

static unsigned long long g_now = 1700000000000000ull; /* fixed base (us) */
static unsigned long long g_step = 1;                   /* advance per call */

static unsigned long long test_clock(void *ctx) {
    (void) ctx;
    unsigned long long t = g_now;
    g_now += g_step;
    return t;
}

/* ---- temp sink directory ---------------------------------------------- */

static void tmpdir(char *out, size_t n) {
    char tmpl[] = "/tmp/rab-brk-XXXXXX";
    char *d = mkdtemp(tmpl);
    snprintf(out, n, "%s", d ? d : "/tmp/rab-brk-fallback");
}

static void sink_path(const char *dir, char *out, size_t n) {
    snprintf(out, n, "%s/audit.jsonl", dir);
}

static void cleanup_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (d != NULL) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
                continue;
            }
            char p[512];
            snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

/* ---- actor helpers ----------------------------------------------------- */

static rab_actor mk_actor(uid_t uid, pid_t pid, const char *boot,
                          const char *start) {
    rab_actor a;
    memset(&a, 0, sizeof a);
    a.uid = uid;
    a.gid = uid;
    a.pid = pid;
    snprintf(a.boot_id, sizeof a.boot_id, "%s", boot);
    snprintf(a.starttime, sizeof a.starttime, "%s", start);
    return a;
}

/* ---- request helpers --------------------------------------------------- */

/* Send an open_intent; on success copy the minted binding + cid out (buffers
 * must be RAB_BINDING_STR_MAX / RAB_CID_MAX). Returns the response error code
 * ("OK" on success). */
static const char *do_open(rab_broker *b, const rab_actor *actor, char *binding,
                           char *cid) {
    const char *body = "{\"type\":\"open_intent\",\"record\":"
                       "{\"operation\":\"svc.restart\",\"outcome\":\"intent\"}}";
    rab_request req;
    const char *e = NULL;
    if (rab_parse_request(body, strlen(body), &req, &e) != 0) {
        return "PARSE_FAIL";
    }
    char *resp = NULL;
    int rc = rab_broker_handle(b, actor, &req, &resp);
    rab_request_free(&req);
    if (rc != 0 || resp == NULL) {
        return "HANDLE_FAIL";
    }
    static char code[32];
    json_error_t jerr;
    json_t *r = json_loads(resp, 0, &jerr);
    free(resp);
    if (r == NULL) {
        return "RESP_PARSE_FAIL";
    }
    const char *ret = "OK";
    json_t *ok = json_object_get(r, "ok");
    if (json_is_true(ok)) {
        json_t *jb = json_object_get(r, "binding");
        json_t *jc = json_object_get(r, "correlation_id");
        if (binding && json_is_string(jb)) {
            snprintf(binding, RAB_BINDING_STR_MAX, "%s", json_string_value(jb));
        }
        if (cid && json_is_string(jc)) {
            snprintf(cid, RAB_CID_MAX, "%s", json_string_value(jc));
        }
    } else {
        json_t *err = json_object_get(r, "error");
        snprintf(code, sizeof code, "%s",
                 json_is_string(err) ? json_string_value(err) : "?");
        ret = code;
    }
    json_decref(r);
    return ret;
}

/* Send a write_outcome with the given binding; returns the response code. */
static const char *do_outcome(rab_broker *b, const rab_actor *actor,
                              const char *binding) {
    char body[512];
    snprintf(body, sizeof body,
             "{\"type\":\"write_outcome\",\"binding\":\"%s\",\"record\":"
             "{\"operation\":\"svc.restart\",\"outcome\":\"ok\","
             "\"effect_issued\":true}}",
             binding);
    rab_request req;
    const char *e = NULL;
    if (rab_parse_request(body, strlen(body), &req, &e) != 0) {
        return "PARSE_FAIL";
    }
    char *resp = NULL;
    int rc = rab_broker_handle(b, actor, &req, &resp);
    rab_request_free(&req);
    if (rc != 0 || resp == NULL) {
        return "HANDLE_FAIL";
    }
    static char code[32];
    json_error_t jerr;
    json_t *r = json_loads(resp, 0, &jerr);
    free(resp);
    if (r == NULL) {
        return "RESP_PARSE_FAIL";
    }
    const char *ret = "OK";
    if (!json_is_true(json_object_get(r, "ok"))) {
        json_t *err = json_object_get(r, "error");
        snprintf(code, sizeof code, "%s",
                 json_is_string(err) ? json_string_value(err) : "?");
        ret = code;
    }
    json_decref(r);
    return ret;
}

/* Append a raw crafted record line (built via rab_build_record) to a file. */
static void craft_line(FILE *f, const char *phase, const char *cid,
                       const char *binding, const rab_actor *actor) {
    json_t *rec = json_object();
    json_object_set_new(rec, "operation", json_string("svc.restart"));
    json_object_set_new(rec, "outcome",
                        json_string(strcmp(phase, RAB_PHASE_OUTCOME) == 0
                                        ? "ok"
                                        : "intent"));
    char *line = rab_build_audit(phase, cid, binding, actor, "host",
                                 1700000000000000ull, rec);
    json_decref(rec);
    fputs(line, f);
    fputc('\n', f);
    free(line);
}

/* craft a broker_checkpoint line (carry-forward of a still-open intent). */
static void craft_checkpoint(FILE *f, const char *cid, const char *binding,
                             const rab_actor *actor) {
    char *line = rab_build_checkpoint(cid, binding, actor, 1700000000000000ull,
                                      "svc.restart", "nginx.service", "system");
    fputs(line, f);
    fputc('\n', f);
    free(line);
}

/* ---- tests ------------------------------------------------------------- */

static void test_record_schema(void) {
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    a.gid = 1000;

    /* an intent audit record: canonical fields + versioned broker extension */
    json_t *rec = json_object();
    json_object_set_new(rec, "operation", json_string("systemd.restart"));
    json_object_set_new(rec, "resource", json_string("cups.service"));
    json_object_set_new(rec, "scope", json_string("system"));
    json_object_set_new(rec, "outcome", json_string("intent"));
    char *line = rab_build_audit(RAB_PHASE_INTENT, "cid1", "bind1", &a, "h",
                                 1786238615572863ull, rec);
    json_decref(rec);
    CHECK(line != NULL, "intent record built");
    json_error_t e;
    json_t *r = json_loads(line, 0, &e);
    CHECK(r != NULL, "intent record parses");
    if (r) {
        CHECK(json_integer_value(json_object_get(r, "schema_version")) == 1,
              "schema_version 1");
        CHECK(json_is_string(json_object_get(r, "record_type")) &&
                  strcmp(json_string_value(json_object_get(r, "record_type")),
                         "audit") == 0,
              "record_type audit");
        CHECK(json_is_string(json_object_get(r, "actor")) &&
                  strcmp(json_string_value(json_object_get(r, "actor")),
                         "uid:1000") == 0,
              "actor is uid:1000 string");
        CHECK(json_integer_value(json_object_get(r, "pid")) == 4321,
              "top-level pid is the peer pid");
        CHECK(json_is_string(json_object_get(r, "time")) &&
                  strcmp(json_string_value(json_object_get(r, "time")),
                         "2026-08-09T01:23:35Z") == 0,
              "time is RFC 3339 UTC");
        json_t *brk = json_object_get(r, "broker");
        CHECK(json_is_object(brk), "broker extension present");
        CHECK(json_integer_value(json_object_get(brk, "schema_version")) == 1,
              "broker.schema_version 1");
        json_t *peer = json_object_get(brk, "peer");
        CHECK(json_integer_value(json_object_get(peer, "uid")) == 1000 &&
                  json_integer_value(json_object_get(peer, "gid")) == 1000 &&
                  json_integer_value(json_object_get(peer, "pid")) == 4321,
              "broker.peer full numeric identity");
        CHECK(json_is_string(json_object_get(peer, "boot_id")) &&
                  json_is_string(json_object_get(peer, "starttime")),
              "broker.peer boot_id + starttime");
        CHECK(json_is_string(json_object_get(brk, "binding")),
              "intent carries broker.binding");
        CHECK(json_is_string(json_object_get(brk, "accepted_time_us")),
              "accepted_time_us is a string");
        json_decref(r);
    }
    free(line);

    /* an outcome record must NOT carry the binding (sensitive, intent-only) */
    json_t *orec = json_object();
    json_object_set_new(orec, "operation", json_string("systemd.restart"));
    json_object_set_new(orec, "outcome", json_string("ok"));
    line = rab_build_audit(RAB_PHASE_OUTCOME, "cid1", NULL, &a, "h",
                           1786238615572863ull, orec);
    json_decref(orec);
    r = json_loads(line, 0, &e);
    CHECK(r != NULL && json_object_get(json_object_get(r, "broker"),
                                       "binding") == NULL,
          "outcome record has no broker.binding");
    if (r) {
        json_decref(r);
    }
    free(line);

    /* round-trip a checkpoint: parse-back yields checkpoint type + metadata */
    line = rab_build_checkpoint("cidc", "bindc", &a, 1786238615572863ull,
                                "systemd.restart", "cups.service", "system");
    rab_stored s;
    CHECK(rab_parse_stored(line, strlen(line), &s) == 0, "checkpoint parses");
    CHECK(s.type == RAB_REC_CHECKPOINT, "parsed as checkpoint");
    CHECK(strcmp(s.correlation_id, "cidc") == 0, "checkpoint cid");
    CHECK(strcmp(s.binding, "bindc") == 0, "checkpoint binding");
    CHECK(strcmp(s.operation, "systemd.restart") == 0, "checkpoint operation");
    CHECK(strcmp(s.resource, "cups.service") == 0, "checkpoint resource");
    CHECK(strcmp(s.scope, "system") == 0, "checkpoint scope");
    CHECK(s.actor.uid == 1000 && s.actor.pid == 4321, "checkpoint peer");
    CHECK(s.time_us == 1786238615572863ull, "checkpoint accepted_time_us");
    free(line);
}

static void test_lifecycle_and_reconstruction(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    const char *err = NULL;

    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    char binding[RAB_BINDING_STR_MAX] = {0};
    char cid[RAB_CID_MAX] = {0};

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open fresh");
    CHECK(strcmp(do_open(b, &a, binding, cid), "OK") == 0, "open ok");
    CHECK(rab_broker_open_count(b) == 1, "one open intent");
    CHECK(rab_broker_has_open(b, cid), "cid is open");
    rab_broker_close(b);

    /* restart: reconstruct from the sink */
    b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker reopen");
    CHECK(rab_broker_open_count(b) == 1, "open intent survived restart");
    CHECK(rab_broker_has_open(b, cid), "cid still open after restart");

    /* the pre-restart intent is closable with its original binding */
    CHECK(strcmp(do_outcome(b, &a, binding), "OK") == 0, "close after restart");
    CHECK(rab_broker_open_count(b) == 0, "closed");
    rab_broker_close(b);

    b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL && rab_broker_open_count(b) == 0, "stays closed on restart");
    rab_broker_close(b);
    cleanup_dir(dir);
}

static void test_identity_and_replay(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    const char *err = NULL;
    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open");

    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    char binding[RAB_BINDING_STR_MAX] = {0};
    char cid[RAB_CID_MAX] = {0};
    CHECK(strcmp(do_open(b, &a, binding, cid), "OK") == 0, "open ok");

    /* unknown binding */
    CHECK(strcmp(do_outcome(b, &a, "not-a-real-binding"), "unknown_intent") == 0,
          "unknown binding rejected");

    /* same uid, different pid (PID reuse) */
    rab_actor diff_pid = mk_actor(1000, 9999, "boot-abc", "555");
    CHECK(strcmp(do_outcome(b, &diff_pid, binding), "actor_mismatch") == 0,
          "different pid rejected");
    /* same uid+pid, different start time (PID reuse, same number) */
    rab_actor diff_start = mk_actor(1000, 4321, "boot-abc", "777");
    CHECK(strcmp(do_outcome(b, &diff_start, binding), "actor_mismatch") == 0,
          "different starttime rejected");
    /* different boot id (post-reboot collision) */
    rab_actor diff_boot = mk_actor(1000, 4321, "boot-xyz", "555");
    CHECK(strcmp(do_outcome(b, &diff_boot, binding), "actor_mismatch") == 0,
          "different boot id rejected");
    /* different uid */
    rab_actor diff_uid = mk_actor(2000, 4321, "boot-abc", "555");
    CHECK(strcmp(do_outcome(b, &diff_uid, binding), "actor_mismatch") == 0,
          "different uid rejected");

    /* the true opener closes it */
    CHECK(strcmp(do_outcome(b, &a, binding), "OK") == 0, "opener closes");
    /* replay of the now-consumed binding is rejected (single-use) */
    CHECK(strcmp(do_outcome(b, &a, binding), "unknown_intent") == 0,
          "replayed binding rejected");
    rab_broker_close(b);
    cleanup_dir(dir);
}

static void test_reconstruction_fails_closed(void) {
    rab_config cfg;
    rab_config_defaults(&cfg);
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");

    /* outcome with no matching intent */
    {
        char dir[256], path[512];
        tmpdir(dir, sizeof dir);
        sink_path(dir, path, sizeof path);
        FILE *f = fopen(path, "w");
        craft_line(f, RAB_PHASE_OUTCOME, "cid-orphan", NULL, &a);
        fclose(f);
        err = NULL;
        rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
        CHECK(b == NULL, "outcome-without-intent refused");
        CHECK(err != NULL, "outcome-without-intent sets err");
        cleanup_dir(dir);
    }
    /* double outcome */
    {
        char dir[256], path[512];
        tmpdir(dir, sizeof dir);
        sink_path(dir, path, sizeof path);
        FILE *f = fopen(path, "w");
        craft_line(f, RAB_PHASE_INTENT, "cid-dbl", "bind-dbl", &a);
        craft_line(f, RAB_PHASE_OUTCOME, "cid-dbl", NULL, &a);
        craft_line(f, RAB_PHASE_OUTCOME, "cid-dbl", NULL, &a);
        fclose(f);
        err = NULL;
        rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
        CHECK(b == NULL, "double-outcome refused");
        cleanup_dir(dir);
    }
    /* inconsistent duplicate intent (same cid, different binding) */
    {
        char dir[256], path[512];
        tmpdir(dir, sizeof dir);
        sink_path(dir, path, sizeof path);
        FILE *f = fopen(path, "w");
        craft_line(f, RAB_PHASE_INTENT, "cid-dup", "bind-1", &a);
        craft_line(f, RAB_PHASE_INTENT, "cid-dup", "bind-2", &a);
        fclose(f);
        err = NULL;
        rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
        CHECK(b == NULL, "inconsistent-duplicate-intent refused");
        cleanup_dir(dir);
    }
    /* corrupt (non-JSON) non-final line */
    {
        char dir[256], path[512];
        tmpdir(dir, sizeof dir);
        sink_path(dir, path, sizeof path);
        FILE *f = fopen(path, "w");
        fputs("this is not json\n", f);
        craft_line(f, RAB_PHASE_INTENT, "cid-x", "bind-x", &a);
        fclose(f);
        err = NULL;
        rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
        CHECK(b == NULL, "corrupt line refused");
        cleanup_dir(dir);
    }
}

/* count how many whole newline-terminated lines a file has, and whether every
 * one of them parses as JSON (no torn/concatenated bytes). */
static void file_line_stats(const char *path, int *lines, int *parseable,
                            long *size) {
    *lines = 0;
    *parseable = 0;
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        *size = -1;
        return;
    }
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char line[8192];
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        if (n == 0 || line[n - 1] != '\n') {
            continue; /* torn tail: not a whole line */
        }
        (*lines)++;
        json_error_t e;
        json_t *r = json_loads(line, 0, &e);
        if (r) {
            (*parseable)++;
            json_decref(r);
        }
    }
    fclose(f);
}

static void test_partial_tail_recovery(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");

    /* one good intent, then a torn final record (no trailing newline). Capture
     * the good portion's size so we can prove the tail is truncated on disk. */
    FILE *f = fopen(path, "w");
    craft_line(f, RAB_PHASE_INTENT, "cid-good", "bind-good", &a);
    fflush(f);
    long good_size = ftell(f);
    fputs("{\"phase\":\"intent\",\"correlation_id\":\"cid-tor", f); /* torn */
    fclose(f);

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "partial tail recovered (broker opens)");
    CHECK(b != NULL && rab_broker_open_count(b) == 1, "good record kept");
    CHECK(b != NULL && rab_broker_has_open(b, "cid-good"), "good cid open");

    /* the torn bytes are physically removed from the file, not merely ignored */
    {
        int lines = 0, ok = 0;
        long size = 0;
        file_line_stats(path, &lines, &ok, &size);
        CHECK(size == good_size, "torn tail truncated on disk");
        CHECK(lines == 1 && ok == 1, "exactly one whole, parseable line remains");
    }

    /* appending after recovery must not concatenate onto torn bytes: closing
     * the good intent yields a clean two-line, fully-parseable file. */
    CHECK(strcmp(do_outcome(b, &a, "bind-good"), "OK") == 0,
          "recovered intent closable");
    rab_broker_close(b);
    {
        int lines = 0, ok = 0;
        long size = 0;
        file_line_stats(path, &lines, &ok, &size);
        CHECK(lines == 2 && ok == 2,
              "post-recovery append leaves two whole, parseable lines");
    }
    cleanup_dir(dir);
}

static void test_free_space_refusal(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.min_free_bytes = (unsigned long long) -1; /* larger than any disk */
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (free space)");
    char bind[RAB_BINDING_STR_MAX], cid[RAB_CID_MAX];
    CHECK(strcmp(do_open(b, &a, bind, cid), "persist_failed") == 0,
          "append refused below the free-space reserve");
    CHECK(rab_broker_open_count(b) == 0, "nothing recorded when refused");
    rab_broker_close(b);
    cleanup_dir(dir);
}

static void test_carry_forward_idempotency(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");

    /* two identical carry-forward checkpoints for one cid collapse to one open
     * intent (crash-during-rotation duplicate) and remain closable. */
    FILE *f = fopen(path, "w");
    craft_checkpoint(f, "cid-cf", "bind-cf", &a);
    craft_checkpoint(f, "cid-cf", "bind-cf", &a);
    fclose(f);

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "duplicate carry-forward opens");
    CHECK(b != NULL && rab_broker_open_count(b) == 1,
          "duplicate carry-forward collapses to one");
    CHECK(strcmp(do_outcome(b, &a, "bind-cf"), "OK") == 0,
          "carried-forward intent closable");
    rab_broker_close(b);

    /* an inconsistent duplicate carry-forward (different actor) fails closed */
    char dir2[256], path2[512];
    tmpdir(dir2, sizeof dir2);
    sink_path(dir2, path2, sizeof path2);
    rab_actor a2 = mk_actor(2000, 4321, "boot-abc", "555");
    f = fopen(path2, "w");
    craft_checkpoint(f, "cid-cf", "bind-cf", &a);
    craft_checkpoint(f, "cid-cf", "bind-cf", &a2);
    fclose(f);
    err = NULL;
    rab_broker *b2 = rab_broker_open(path2, &cfg, test_clock, NULL, &err);
    CHECK(b2 == NULL, "inconsistent carry-forward refused");
    cleanup_dir(dir2);
    cleanup_dir(dir);
}

static void test_rotation_preserves_open_intents(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.rotate_bytes = 256; /* force rotation after a couple of records */
    g_step = 2;             /* ensure distinct archive timestamps */
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (rotation)");

    /* open several intents; each record is well over 100 bytes, so rotation
     * triggers while intents are open. */
    char bindings[5][RAB_BINDING_STR_MAX];
    char cids[5][RAB_CID_MAX];
    int all_ok = 1;
    for (int i = 0; i < 5; i++) {
        if (strcmp(do_open(b, &a, bindings[i], cids[i]), "OK") != 0) {
            all_ok = 0;
        }
    }
    CHECK(all_ok, "opens across rotation succeed");
    CHECK(rab_broker_open_count(b) == 5, "five open intents held");
    rab_broker_close(b);

    /* restart: reconstruction must find all five via carry-forward records in
     * the post-rotation current segment. */
    b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "reopen after rotation");
    CHECK(b != NULL && rab_broker_open_count(b) == 5,
          "all open intents survived rotation + restart");
    int closable = 1;
    for (int i = 0; i < 5; i++) {
        if (strcmp(do_outcome(b, &a, bindings[i]), "OK") != 0) {
            closable = 0;
        }
    }
    CHECK(closable, "all carried-forward intents closable");
    CHECK(rab_broker_open_count(b) == 0, "all closed");
    rab_broker_close(b);
    g_step = 1;
    cleanup_dir(dir);
}

static void test_bounded_open_intents(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.max_open_per_uid = 3;
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (caps)");

    char bind[RAB_BINDING_STR_MAX], cid[RAB_CID_MAX];
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0, "open 1");
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0, "open 2");
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0, "open 3");
    CHECK(strcmp(do_open(b, &a, bind, cid), "rate_limited") == 0,
          "open beyond per-uid cap rejected");
    CHECK(rab_broker_open_count(b) == 3, "cap held at 3");
    rab_broker_close(b);
    cleanup_dir(dir);
}

static void test_rate_limit_survives_restart(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.rate_max_in_window = 3;
    cfg.rate_window_sec = 100;
    cfg.max_open_per_uid = 100; /* don't let the open cap interfere */
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");

    unsigned long long base = 2000000000000000ull;
    g_now = base;
    g_step = 0; /* all ops share a timestamp inside the window */

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (rate)");
    char bind[RAB_BINDING_STR_MAX], cid[RAB_CID_MAX];
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0, "rate open 1");
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0, "rate open 2");
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0, "rate open 3");
    CHECK(strcmp(do_open(b, &a, bind, cid), "rate_limited") == 0,
          "fourth op rate-limited");
    rab_broker_close(b);

    /* restart at the same wall-clock time: the three appended records are
     * re-counted, so the limit is not reset by the restart. */
    g_now = base;
    b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker reopen (rate)");
    CHECK(strcmp(do_open(b, &a, bind, cid), "rate_limited") == 0,
          "rate limit survives restart");
    rab_broker_close(b);

    /* advance well past the window: the old records fall out, ops allowed. */
    g_now = base + (unsigned long long) cfg.rate_window_sec * 1000000ull + 1;
    b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker reopen (rate, later)");
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0,
          "ops allowed after the window elapses");
    rab_broker_close(b);
    g_step = 1;
    g_now = 1700000000000000ull;
    cleanup_dir(dir);
}

int main(void) {
    test_record_schema();
    test_lifecycle_and_reconstruction();
    test_identity_and_replay();
    test_reconstruction_fails_closed();
    test_partial_tail_recovery();
    test_free_space_refusal();
    test_carry_forward_idempotency();
    test_rotation_preserves_open_intents();
    test_bounded_open_intents();
    test_rate_limit_survives_restart();
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
