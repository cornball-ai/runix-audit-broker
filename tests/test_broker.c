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
#include <sys/stat.h>
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

/* Send an emit (single non-effect record); copy the minted cid out. Returns the
 * response code, or "HAS_BINDING" if the response wrongly carried a binding. */
static const char *do_emit(rab_broker *b, const rab_actor *actor,
                           const char *phase, char *cid) {
    char body[256];
    snprintf(body, sizeof body,
             "{\"type\":\"emit\",\"phase\":\"%s\",\"record\":{\"operation\":"
             "\"svc.restart\",\"outcome\":\"%s\",\"effect_issued\":false}}",
             phase, phase);
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
    json_error_t je;
    json_t *r = json_loads(resp, 0, &je);
    free(resp);
    if (r == NULL) {
        return "RESP_PARSE_FAIL";
    }
    const char *ret = "OK";
    if (json_is_true(json_object_get(r, "ok"))) {
        json_t *jc = json_object_get(r, "correlation_id");
        if (cid && json_is_string(jc)) {
            snprintf(cid, RAB_CID_MAX, "%s", json_string_value(jc));
        }
        if (json_object_get(r, "binding") != NULL) {
            ret = "HAS_BINDING";
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

/* Append a raw crafted record line (built via rab_build_audit) to a file. */
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

static int parses_ok(const char *s); /* defined below; used by rate-parse tests */

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
    rab_stored_free(&s);
    free(line);
}

/* Build a broker_rate carry record, round-trip it, and check strict rejection
 * of malformed variants. */
static void test_rate_record_parse(void) {
    unsigned long long times[] = {1700000000000000ull, 1700000000000005ull};
    unsigned long long bytes[] = {321ull, 654ull};
    char *line = rab_build_rate(1000, times, bytes, 2);
    CHECK(line != NULL, "rate record built");
    if (line != NULL) {
        rab_stored s;
        CHECK(rab_parse_stored(line, strlen(line), &s) == 0, "rate record parses");
        CHECK(s.type == RAB_REC_RATE, "parsed as rate");
        CHECK(s.rate_uid == 1000, "rate uid");
        CHECK(s.rate_n == 2, "rate count");
        CHECK(s.rate_times != NULL && s.rate_times[0] == times[0] &&
                  s.rate_times[1] == times[1],
              "rate timestamps round-trip");
        CHECK(s.rate_bytes != NULL && s.rate_bytes[0] == bytes[0] &&
                  s.rate_bytes[1] == bytes[1],
              "rate bytes round-trip");
        rab_stored_free(&s);
        free(line);
    }

    /* strict: a valid bytes array isolates each timestamp/shape defect */
    CHECK(!parses_ok("{\"schema_version\":1,\"record_type\":\"broker_rate\","
                     "\"uid\":1000,\"times_us\":[123],\"bytes\":[\"10\"]}"),
          "non-string rate timestamp rejected");
    CHECK(!parses_ok("{\"schema_version\":1,\"record_type\":\"broker_rate\","
                     "\"uid\":1000,\"times_us\":[\"12x\"],\"bytes\":[\"10\"]}"),
          "non-decimal rate timestamp rejected");
    CHECK(!parses_ok("{\"schema_version\":1,\"record_type\":\"broker_rate\","
                     "\"uid\":1000,\"times_us\":[\"1\"],\"bytes\":[\"x\"]}"),
          "non-decimal rate byte rejected");
    CHECK(!parses_ok("{\"schema_version\":1,\"record_type\":\"broker_rate\","
                     "\"uid\":1000,\"times_us\":[\"1\",\"2\"],\"bytes\":[\"10\"]}"),
          "times/bytes length mismatch rejected");
    CHECK(!parses_ok("{\"schema_version\":1,\"record_type\":\"broker_rate\","
                     "\"uid\":1000,\"times_us\":[\"1\"]}"),
          "missing bytes array rejected");
    CHECK(!parses_ok("{\"schema_version\":1,\"record_type\":\"broker_rate\","
                     "\"uid\":1000,\"times_us\":[],\"bytes\":[],\"x\":1}"),
          "extra key on rate record rejected");
    CHECK(!parses_ok("{\"schema_version\":1,\"record_type\":\"broker_rate\","
                     "\"uid\":-1,\"times_us\":[],\"bytes\":[]}"),
          "negative uid on rate record rejected");
    /* an empty carry is well-formed (a uid with no in-window history) */
    CHECK(parses_ok("{\"schema_version\":1,\"record_type\":\"broker_rate\","
                    "\"uid\":1000,\"times_us\":[],\"bytes\":[]}"),
          "empty rate carry accepted");
}

/* Count archived segments (<base>.<all-digits>) in dir. -1 if dir unreadable. */
static int count_archives(const char *dir, const char *base) {
    DIR *d = opendir(dir);
    if (d == NULL) {
        return -1;
    }
    size_t bl = strlen(base);
    int c = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, base, bl) != 0 || e->d_name[bl] != '.') {
            continue;
        }
        const char *suf = e->d_name + bl + 1;
        if (suf[0] == '\0') {
            continue;
        }
        int digits = 1;
        for (const char *p = suf; *p != '\0'; p++) {
            if (*p < '0' || *p > '9') {
                digits = 0;
                break;
            }
        }
        if (digits) {
            c++;
        }
    }
    closedir(d);
    return c;
}

static int parses_ok(const char *s) {
    rab_stored st;
    int rc = rab_parse_stored(s, strlen(s), &st);
    if (rc == 0) {
        rab_stored_free(&st); /* release a rate record's carried timestamps */
    }
    return rc == 0;
}

static void test_strict_parsing(void) {
    /* a well-formed intent record (baseline: must parse) */
    const char *ok =
        "{\"schema_version\":1,\"record_type\":\"audit\",\"correlation_id\":"
        "\"c1\",\"phase\":\"intent\",\"host\":\"h\",\"pid\":4321,\"actor\":"
        "\"uid:1000\",\"operation\":\"op\",\"outcome\":\"intent\",\"time\":"
        "\"2026-01-01T00:00:00Z\",\"broker\":{\"schema_version\":1,\"peer\":"
        "{\"uid\":1000,\"gid\":1000,\"pid\":4321,\"boot_id\":\"b\","
        "\"starttime\":\"555\"},\"binding\":\"bind1\",\"accepted_time_us\":"
        "\"1700000000000000\"}}";
    CHECK(parses_ok(ok), "valid intent parses");

    /* unknown record_type: no silent audit fall-through */
    CHECK(!parses_ok(
              "{\"schema_version\":1,\"record_type\":\"bogus\","
              "\"correlation_id\":\"c1\",\"phase\":\"intent\",\"host\":\"h\","
              "\"pid\":4321,\"actor\":\"uid:1000\",\"operation\":\"op\","
              "\"outcome\":\"intent\",\"time\":\"t\",\"broker\":{"
              "\"schema_version\":1,\"peer\":{\"uid\":1000,\"gid\":1000,"
              "\"pid\":4321,\"boot_id\":\"b\",\"starttime\":\"555\"},"
              "\"binding\":\"x\",\"accepted_time_us\":\"1\"}}"),
          "unknown record_type rejected");

    /* missing record_type is rejected (strict recovery path) */
    CHECK(!parses_ok(
              "{\"schema_version\":1,\"correlation_id\":\"c1\",\"phase\":"
              "\"intent\",\"host\":\"h\",\"pid\":4321,\"actor\":\"uid:1000\","
              "\"operation\":\"op\",\"time\":\"t\",\"broker\":{"
              "\"schema_version\":1,\"peer\":{\"uid\":1000,\"gid\":1000,"
              "\"pid\":4321,\"boot_id\":\"b\",\"starttime\":\"555\"},"
              "\"binding\":\"x\",\"accepted_time_us\":\"1\"}}"),
          "missing record_type rejected");

    /* unknown top-level schema_version */
    CHECK(!parses_ok(
              "{\"schema_version\":2,\"record_type\":\"audit\","
              "\"correlation_id\":\"c1\",\"phase\":\"intent\",\"host\":\"h\","
              "\"pid\":4321,\"actor\":\"uid:1000\",\"operation\":\"op\","
              "\"time\":\"t\",\"broker\":{\"schema_version\":1,\"peer\":{"
              "\"uid\":1000,\"gid\":1000,\"pid\":4321,\"boot_id\":\"b\","
              "\"starttime\":\"555\"},\"binding\":\"x\","
              "\"accepted_time_us\":\"1\"}}"),
          "unknown schema_version rejected");

/* helper: the baseline with the broker object replaced */
#define WITHBROKER(b)                                                        \
    "{\"schema_version\":1,\"record_type\":\"audit\",\"correlation_id\":"    \
    "\"c1\",\"phase\":\"%s\",\"host\":\"h\",\"pid\":4321,\"actor\":"         \
    "\"uid:1000\",\"operation\":\"op\",\"time\":\"t\",\"broker\":" b "}"

    char buf[1024];
    /* malformed accepted_time_us: trailing chars, empty, sign, non-digit */
    const char *bad_ats[] = {
        "{\"schema_version\":1,\"peer\":{\"uid\":1000,\"gid\":1000,\"pid\":"
        "4321,\"boot_id\":\"b\",\"starttime\":\"555\"},\"binding\":\"x\","
        "\"accepted_time_us\":\"123x\"}",
        "{\"schema_version\":1,\"peer\":{\"uid\":1000,\"gid\":1000,\"pid\":"
        "4321,\"boot_id\":\"b\",\"starttime\":\"555\"},\"binding\":\"x\","
        "\"accepted_time_us\":\"\"}",
        "{\"schema_version\":1,\"peer\":{\"uid\":1000,\"gid\":1000,\"pid\":"
        "4321,\"boot_id\":\"b\",\"starttime\":\"555\"},\"binding\":\"x\","
        "\"accepted_time_us\":\"-5\"}"};
    for (size_t i = 0; i < 3; i++) {
        snprintf(buf, sizeof buf, WITHBROKER("%s"), "intent", bad_ats[i]);
        CHECK(!parses_ok(buf), "malformed accepted_time_us rejected");
    }

    /* binding present on an outcome (must be intent-only) */
    snprintf(buf, sizeof buf, WITHBROKER("%s"), "outcome",
             "{\"schema_version\":1,\"peer\":{\"uid\":1000,\"gid\":1000,"
             "\"pid\":4321,\"boot_id\":\"b\",\"starttime\":\"555\"},"
             "\"binding\":\"x\",\"accepted_time_us\":\"1\"}");
    CHECK(!parses_ok(buf), "binding on an outcome rejected");

    /* intent without a binding */
    snprintf(buf, sizeof buf, WITHBROKER("%s"), "intent",
             "{\"schema_version\":1,\"peer\":{\"uid\":1000,\"gid\":1000,"
             "\"pid\":4321,\"boot_id\":\"b\",\"starttime\":\"555\"},"
             "\"accepted_time_us\":\"1\"}");
    CHECK(!parses_ok(buf), "intent without a binding rejected");

    /* unknown key in the broker extension / peer */
    snprintf(buf, sizeof buf, WITHBROKER("%s"), "intent",
             "{\"schema_version\":1,\"peer\":{\"uid\":1000,\"gid\":1000,"
             "\"pid\":4321,\"boot_id\":\"b\",\"starttime\":\"555\"},"
             "\"binding\":\"x\",\"accepted_time_us\":\"1\",\"foo\":1}");
    CHECK(!parses_ok(buf), "unknown broker key rejected");
    snprintf(buf, sizeof buf, WITHBROKER("%s"), "intent",
             "{\"schema_version\":1,\"peer\":{\"uid\":1000,\"gid\":1000,"
             "\"pid\":4321,\"boot_id\":\"b\",\"starttime\":\"555\",\"x\":1},"
             "\"binding\":\"x\",\"accepted_time_us\":\"1\"}");
    CHECK(!parses_ok(buf), "unknown peer key rejected");

    /* top-level pid / actor inconsistent with broker.peer */
    CHECK(!parses_ok(
              "{\"schema_version\":1,\"record_type\":\"audit\","
              "\"correlation_id\":\"c1\",\"phase\":\"intent\",\"host\":\"h\","
              "\"pid\":9999,\"actor\":\"uid:1000\",\"operation\":\"op\","
              "\"time\":\"t\",\"broker\":{\"schema_version\":1,\"peer\":{"
              "\"uid\":1000,\"gid\":1000,\"pid\":4321,\"boot_id\":\"b\","
              "\"starttime\":\"555\"},\"binding\":\"x\","
              "\"accepted_time_us\":\"1\"}}"),
          "top-level pid != peer.pid rejected");
    CHECK(!parses_ok(
              "{\"schema_version\":1,\"record_type\":\"audit\","
              "\"correlation_id\":\"c1\",\"phase\":\"intent\",\"host\":\"h\","
              "\"pid\":4321,\"actor\":\"uid:999\",\"operation\":\"op\","
              "\"time\":\"t\",\"broker\":{\"schema_version\":1,\"peer\":{"
              "\"uid\":1000,\"gid\":1000,\"pid\":4321,\"boot_id\":\"b\","
              "\"starttime\":\"555\"},\"binding\":\"x\","
              "\"accepted_time_us\":\"1\"}}"),
          "actor != uid:peer.uid rejected");
#undef WITHBROKER
}

/* Conformance 32: a fixed record built by the R file sink (runix
 * .finish_record + rsystemd uid:N actor) and by the broker agree field-for-field
 * on the canonical schema. Byte identity is not required (different encoders,
 * different insertion order for actor); the broker's `broker` extension is
 * broker-only. The R line is a committed golden produced by runix/rsystemd. */
static void test_cross_sink_schema(void) {
    static const char *R_GOLDEN =
        "{\"schema_version\":1,\"record_type\":\"audit\",\"correlation_id\":"
        "\"00001786238615000000-1-abcdef0123456789\",\"phase\":\"intent\","
        "\"host\":\"troy-ai\",\"pid\":1032147,\"operation\":"
        "\"systemd.restart\",\"resource\":\"cups.service\",\"scope\":"
        "\"system\",\"actor\":\"uid:1000\",\"outcome\":\"intent\",\"time\":"
        "\"2026-08-09T01:23:35Z\"}";

    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    json_t *dom = json_object();
    json_object_set_new(dom, "operation", json_string("systemd.restart"));
    json_object_set_new(dom, "resource", json_string("cups.service"));
    json_object_set_new(dom, "scope", json_string("system"));
    json_object_set_new(dom, "outcome", json_string("intent"));
    char *bline = rab_build_audit(RAB_PHASE_INTENT, "cidX", "bindX", &a, "h",
                                  1786238615000000ull, dom);
    json_decref(dom);
    json_error_t e;
    json_t *R = json_loads(R_GOLDEN, 0, &e);
    json_t *B = bline ? json_loads(bline, 0, &e) : NULL;
    free(bline);
    CHECK(R != NULL && B != NULL, "both records parse");
    if (R == NULL || B == NULL) {
        json_decref(R);
        json_decref(B);
        return;
    }

    /* every canonical R field is present in the broker record with same type */
    const char *k;
    json_t *rv;
    int same_types = 1;
    json_object_foreach(R, k, rv) {
        json_t *bv = json_object_get(B, k);
        if (bv == NULL || json_typeof(bv) != json_typeof(rv)) {
            same_types = 0;
        }
    }
    CHECK(same_types, "all canonical fields present in broker record, same type");

    /* the broker record adds exactly the broker extension, nothing else */
    int only_broker_extra = 1;
    json_object_foreach(B, k, rv) {
        if (strcmp(k, "broker") == 0) {
            continue;
        }
        if (json_object_get(R, k) == NULL) {
            only_broker_extra = 0;
        }
    }
    CHECK(only_broker_extra, "broker record adds only the broker extension");
    CHECK(json_object_get(B, "broker") != NULL, "broker extension present");
    CHECK(json_object_get(R, "broker") == NULL, "R record has no broker key");

    /* value-fixed canonical fields agree */
    CHECK(json_integer_value(json_object_get(R, "schema_version")) ==
              json_integer_value(json_object_get(B, "schema_version")),
          "schema_version equal");
    const char *sfields[] = {"record_type", "phase",    "operation", "resource",
                             "scope",       "actor",     "outcome",   "time"};
    int vals_equal = 1;
    for (size_t i = 0; i < sizeof sfields / sizeof sfields[0]; i++) {
        const char *rvs = json_string_value(json_object_get(R, sfields[i]));
        const char *bvs = json_string_value(json_object_get(B, sfields[i]));
        if (rvs == NULL || bvs == NULL || strcmp(rvs, bvs) != 0) {
            vals_equal = 0;
        }
    }
    CHECK(vals_equal, "record_type/phase/domain/actor/time values agree");
    json_decref(R);
    json_decref(B);
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

static void test_emit(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (emit)");

    char cid[RAB_CID_MAX] = {0};
    CHECK(strcmp(do_emit(b, &a, "preview", cid), "OK") == 0, "emit preview ok");
    CHECK(cid[0] != '\0', "emit returns a correlation id");
    CHECK(rab_broker_open_count(b) == 0, "emit opens no intent");
    CHECK(strcmp(do_emit(b, &a, "noop", NULL), "OK") == 0, "emit noop ok");
    CHECK(rab_broker_open_count(b) == 0, "still nothing open after emit");
    rab_broker_close(b);

    /* restart: emit records are standalone; reconstruction opens nothing */
    b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL && rab_broker_open_count(b) == 0,
          "emit records reconstruct as standalone (nothing open)");
    /* an outcome cannot follow an emit: it minted no binding */
    CHECK(strcmp(do_outcome(b, &a, cid), "unknown_intent") == 0,
          "emit cannot be paired with a write_outcome");
    rab_broker_close(b);

    /* the emit record carries its phase and no broker.binding */
    FILE *f = fopen(path, "r");
    int preview_no_binding = 0;
    if (f != NULL) {
        char line[4096];
        while (fgets(line, sizeof line, f)) {
            json_error_t e;
            json_t *r = json_loads(line, 0, &e);
            if (r) {
                json_t *ph = json_object_get(r, "phase");
                json_t *brk = json_object_get(r, "broker");
                if (json_is_string(ph) &&
                    strcmp(json_string_value(ph), "preview") == 0 &&
                    json_object_get(brk, "binding") == NULL) {
                    preview_no_binding = 1;
                }
                json_decref(r);
            }
        }
        fclose(f);
    }
    CHECK(preview_no_binding, "emit preview record has no broker.binding");
    cleanup_dir(dir);

    /* emit is rate-accounted like the effect paths */
    char dir2[256], path2[512];
    tmpdir(dir2, sizeof dir2);
    sink_path(dir2, path2, sizeof path2);
    rab_config cfg2;
    rab_config_defaults(&cfg2);
    cfg2.rate_max_in_window = 2;
    cfg2.rate_window_sec = 100;
    unsigned long long save_now = g_now, save_step = g_step;
    g_step = 0;
    g_now = 3000000000000000ull;
    rab_broker *b2 = rab_broker_open(path2, &cfg2, test_clock, NULL, &err);
    CHECK(b2 != NULL, "broker open (emit rate)");
    CHECK(strcmp(do_emit(b2, &a, "preview", NULL), "OK") == 0, "emit rate 1");
    CHECK(strcmp(do_emit(b2, &a, "preview", NULL), "OK") == 0, "emit rate 2");
    CHECK(strcmp(do_emit(b2, &a, "preview", NULL), "rate_limited") == 0,
          "emit beyond the rate window is rejected");
    rab_broker_close(b2);
    g_now = save_now;
    g_step = save_step;
    cleanup_dir(dir2);
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

/* Requirement 4: rotation -> idle exit -> restart resets NEITHER the open-intent
 * set NOR the per-uid rate limit. Small rotate_bytes forces the rate-seeding
 * audit records into archives (which reconstruction never reads), so only the
 * carried rate history keeps the limit alive across the restart. */
static void test_rate_carry_survives_rotation(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.rate_max_in_window = 3;
    cfg.rate_window_sec = 100;
    cfg.max_open_per_uid = 100; /* don't let the open cap interfere */
    cfg.rotate_bytes = 256;     /* each op rotates: seeders move to archives */
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");

    unsigned long long base = 2500000000000000ull;
    unsigned long long window_us = (unsigned long long) cfg.rate_window_sec * 1000000ull;
    g_now = base;
    g_step = 1; /* advance so archive suffixes are distinct across rotations */

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (rate carry)");
    char bind[3][RAB_BINDING_STR_MAX], cid[3][RAB_CID_MAX];
    CHECK(strcmp(do_open(b, &a, bind[0], cid[0]), "OK") == 0, "carry open 1");
    CHECK(strcmp(do_open(b, &a, bind[1], cid[1]), "OK") == 0, "carry open 2");
    CHECK(strcmp(do_open(b, &a, bind[2], cid[2]), "OK") == 0, "carry open 3");
    CHECK(strcmp(do_open(b, &a, bind[0], cid[0]), "rate_limited") == 0,
          "fourth op rate-limited before restart");
    CHECK(rab_broker_open_count(b) == 3, "three intents open before restart");
    /* rotation must have happened, moving the seeder audit records to archives */
    CHECK(count_archives(dir, "audit.jsonl") >= 1, "rotation produced archives");
    rab_broker_close(b);

    /* restart still inside the window: open intents AND the rate limit persist */
    b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "reopen (rate carry, in window)");
    CHECK(rab_broker_open_count(b) == 3, "open intents survived rotation+restart");
    CHECK(rab_broker_has_open(b, cid[0]) && rab_broker_has_open(b, cid[1]) &&
              rab_broker_has_open(b, cid[2]),
          "exact intents survived");
    CHECK(strcmp(do_open(b, &a, bind[0], cid[0]), "rate_limited") == 0,
          "per-uid rate limit survived rotation+restart");
    rab_broker_close(b);

    /* restart well past the window: the carried timestamps age out, ops allowed */
    g_now = base + window_us + 1000000ull;
    b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "reopen (rate carry, after window)");
    char nb[RAB_BINDING_STR_MAX], nc[RAB_CID_MAX];
    CHECK(strcmp(do_open(b, &a, nb, nc), "OK") == 0,
          "ops allowed once the carried window elapses");
    rab_broker_close(b);
    g_step = 1;
    g_now = 1700000000000000ull;
    cleanup_dir(dir);
}

/* Requirement 3 + 5: retention bounds total on-disk audit by BOTH segment count
 * and total bytes, and never discards an unresolved intent (carry-forward keeps
 * every open intent in the retained active segment). */
static void test_retention_bounds(void) {
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    const char *err = NULL;

    /* --- segment-count retention --- */
    {
        char dir[256], path[512];
        tmpdir(dir, sizeof dir);
        sink_path(dir, path, sizeof path);
        rab_config cfg;
        rab_config_defaults(&cfg);
        cfg.rotate_bytes = 256;  /* rotate on every op */
        cfg.retain_segments = 2; /* keep at most 2 archives */
        cfg.retain_bytes = 0;    /* count-only here */
        g_step = 2;              /* distinct archive suffixes */

        rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
        CHECK(b != NULL, "broker open (count retention)");
        char keep_bind[RAB_BINDING_STR_MAX], keep_cid[RAB_CID_MAX];
        CHECK(strcmp(do_open(b, &a, keep_bind, keep_cid), "OK") == 0,
              "unresolved intent opened");
        int emits_ok = 1;
        for (int i = 0; i < 8; i++) {
            if (strcmp(do_emit(b, &a, "preview", NULL), "OK") != 0) {
                emits_ok = 0;
            }
        }
        CHECK(emits_ok, "emits across many rotations succeed");
        CHECK(count_archives(dir, "audit.jsonl") >= 1, "rotation happened");
        CHECK(count_archives(dir, "audit.jsonl") <= 2,
              "archive count held at the retention bound");
        rab_broker_close(b);

        b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
        CHECK(b != NULL, "reopen after count pruning");
        CHECK(rab_broker_open_count(b) == 1,
              "unresolved intent survived count pruning");
        CHECK(rab_broker_has_open(b, keep_cid), "the exact intent survived");
        CHECK(strcmp(do_outcome(b, &a, keep_bind), "OK") == 0,
              "survived intent still closable");
        rab_broker_close(b);
        cleanup_dir(dir);
    }

    /* --- a byte budget below one segment is rejected (fail closed) --- */
    {
        char dir[256], path[512];
        tmpdir(dir, sizeof dir);
        sink_path(dir, path, sizeof path);
        rab_config cfg;
        rab_config_defaults(&cfg);
        cfg.rotate_bytes = 4096;
        cfg.retain_bytes = 1024; /* < rotate_bytes: unsatisfiable */
        err = NULL;
        rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
        CHECK(b == NULL, "retain_bytes < rotate_bytes rejected");
        CHECK(err != NULL, "config rejection sets err");
        cleanup_dir(dir);
    }

    /* --- total-byte retention; the active segment alone can exceed the budget,
     * and when it does every archive is pruned while the active segment (and its
     * unresolved intents) stands. --- */
    {
        char dir[256], path[512];
        tmpdir(dir, sizeof dir);
        sink_path(dir, path, sizeof path);
        rab_config cfg;
        rab_config_defaults(&cfg);
        cfg.rotate_bytes = 256;
        cfg.retain_segments = 0;   /* count unlimited */
        cfg.retain_bytes = 256;    /* == rotate_bytes (minimal valid budget) */
        cfg.max_open_per_uid = 100;
        g_step = 2;
        err = NULL;

        rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
        CHECK(b != NULL, "broker open (byte retention)");
        /* four unresolved intents: each rotation re-checkpoints all of them, so
         * the active segment's checkpoint set alone exceeds retain_bytes. */
        char kb[4][RAB_BINDING_STR_MAX], kc[4][RAB_CID_MAX];
        int opened = 1;
        for (int i = 0; i < 4; i++) {
            if (strcmp(do_open(b, &a, kb[i], kc[i]), "OK") != 0) {
                opened = 0;
            }
        }
        CHECK(opened, "four unresolved intents opened");
        CHECK(count_archives(dir, "audit.jsonl") == 0,
              "active exceeding the budget prunes every archive");
        rab_broker_close(b);

        b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
        CHECK(b != NULL, "reopen after byte pruning");
        CHECK(rab_broker_open_count(b) == 4,
              "all unresolved intents survived byte pruning");
        CHECK(rab_broker_has_open(b, kc[0]) && rab_broker_has_open(b, kc[3]),
              "the exact intents survived");
        rab_broker_close(b);
        cleanup_dir(dir);
    }
    g_step = 1;
}

/* Requirement (c): retention only ever touches broker-owned regular archive
 * files. A symlink named like an archive is neither followed nor deleted, and
 * its target is untouched. */
static void test_retention_symlink_safety(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.rotate_bytes = 256;
    cfg.retain_segments = 1;
    cfg.retain_bytes = 0;
    g_step = 2;
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");

    /* a precious file outside the sink, and a symlink named like an archive */
    char precious[600], link[600];
    snprintf(precious, sizeof precious, "%s/precious.txt", dir);
    FILE *pf = fopen(precious, "w");
    if (pf) {
        fputs("do not delete\n", pf);
        fclose(pf);
    }
    snprintf(link, sizeof link, "%s.9999999999999999", path); /* archive-shaped */
    CHECK(symlink(precious, link) == 0, "planted archive-named symlink");

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (symlink safety)");
    char keep_bind[RAB_BINDING_STR_MAX], keep_cid[RAB_CID_MAX];
    CHECK(strcmp(do_open(b, &a, keep_bind, keep_cid), "OK") == 0, "open");
    int emits_ok = 1;
    for (int i = 0; i < 6; i++) {
        if (strcmp(do_emit(b, &a, "preview", NULL), "OK") != 0) {
            emits_ok = 0;
        }
    }
    CHECK(emits_ok, "emits force pruning");
    rab_broker_close(b);

    /* the symlink was skipped (not treated as an archive) and its target lives */
    struct stat st;
    CHECK(lstat(link, &st) == 0 && S_ISLNK(st.st_mode),
          "archive-named symlink not deleted by retention");
    CHECK(stat(precious, &st) == 0, "symlink target untouched");
    cleanup_dir(dir);
}

/* Requirement (d): the rate window boundary is inclusive. An op whose timestamp
 * is exactly `now - window` old still counts against the limit; one microsecond
 * older does not. */
static void test_rate_window_boundary(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.rate_max_in_window = 1;
    cfg.rate_window_sec = 10;
    cfg.max_open_per_uid = 100;
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    unsigned long long window_us = (unsigned long long) cfg.rate_window_sec * 1000000ull;
    unsigned long long t0 = 2600000000000000ull;

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (boundary)");
    char bind[RAB_BINDING_STR_MAX], cid[RAB_CID_MAX];

    g_step = 0;
    g_now = t0;
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0, "op at t0 fills the limit");

    /* now exactly one window later: the t0 op is at now-window, still in-window */
    g_now = t0 + window_us;
    CHECK(strcmp(do_open(b, &a, bind, cid), "rate_limited") == 0,
          "op exactly at now-window is still counted (inclusive boundary)");

    /* one microsecond past the boundary: the t0 op ages out, op allowed */
    g_now = t0 + window_us + 1;
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0,
          "op one microsecond past the boundary is allowed");
    rab_broker_close(b);
    g_step = 1;
    g_now = 1700000000000000ull;
    cleanup_dir(dir);
}

/* The per-uid write-byte quota bounds appended bytes/uid/window independently of
 * the op count: with a high op-count limit, a flood is stopped by bytes, only
 * that uid is affected, and the window slides. */
static void test_byte_quota_per_uid(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.rate_max_in_window = 1000;       /* op-count will not trip */
    cfg.rate_max_bytes_per_uid = 1000;   /* a few records' worth */
    cfg.rate_max_bytes_global = 0;       /* isolate the per-uid quota */
    cfg.rate_window_sec = 100;
    cfg.max_open_per_uid = 1000;
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    unsigned long long base = 2700000000000000ull;
    unsigned long long window_us =
        (unsigned long long) cfg.rate_window_sec * 1000000ull;
    g_now = base;
    g_step = 0;

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (byte quota per-uid)");
    char bind[RAB_BINDING_STR_MAX], cid[RAB_CID_MAX];
    int ok_count = 0;
    const char *code = "OK";
    for (int i = 0; i < 50; i++) {
        code = do_open(b, &a, bind, cid);
        if (strcmp(code, "OK") != 0) {
            break;
        }
        ok_count++;
    }
    CHECK(ok_count >= 1, "at least one op fits under the per-uid byte quota");
    CHECK(ok_count < 50, "the per-uid byte quota stops the flood");
    CHECK(strcmp(code, "rate_limited") == 0,
          "over the per-uid byte quota is rate_limited");
    /* a different uid is unaffected: the quota is per-uid */
    rab_actor a2 = mk_actor(2000, 4321, "boot-abc", "555");
    char b2[RAB_BINDING_STR_MAX], c2[RAB_CID_MAX];
    CHECK(strcmp(do_open(b, &a2, b2, c2), "OK") == 0,
          "a different uid is not blocked by another uid's byte quota");
    /* advance past the window: the byte window slides, ops allowed again */
    g_now = base + window_us + 1;
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0,
          "per-uid byte window slides open after the window elapses");
    rab_broker_close(b);
    g_step = 1;
    g_now = 1700000000000000ull;
    cleanup_dir(dir);
}

/* The global write-byte quota spans uids: alternating callers, each under the
 * (disabled) per-uid quota, together trip the global ceiling. */
static void test_byte_quota_global(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.rate_max_in_window = 1000;
    cfg.rate_max_bytes_per_uid = 0;    /* off: only the global quota can bite */
    cfg.rate_max_bytes_global = 1000;
    cfg.rate_window_sec = 100;
    cfg.max_open_per_uid = 1000;
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    rab_actor a2 = mk_actor(2000, 4321, "boot-abc", "555");
    unsigned long long base = 2900000000000000ull;
    unsigned long long window_us =
        (unsigned long long) cfg.rate_window_sec * 1000000ull;
    g_now = base;
    g_step = 0;

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (byte quota global)");
    char bind[RAB_BINDING_STR_MAX], cid[RAB_CID_MAX];
    int ok_count = 0;
    const char *code = "OK";
    for (int i = 0; i < 50; i++) {
        code = do_open(b, (i % 2 == 0) ? &a : &a2, bind, cid);
        if (strcmp(code, "OK") != 0) {
            break;
        }
        ok_count++;
    }
    CHECK(ok_count >= 1, "at least one op fits under the global byte quota");
    CHECK(ok_count < 50, "the global byte quota stops a cross-uid flood");
    CHECK(strcmp(code, "rate_limited") == 0,
          "over the global byte quota is rate_limited");
    /* advance past the window: the tumbling global window rolls over */
    g_now = base + window_us + 1;
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0,
          "global byte window rolls over after the window elapses");
    rab_broker_close(b);
    g_step = 1;
    g_now = 1700000000000000ull;
    cleanup_dir(dir);
}

/* The per-uid byte quota survives rotation + restart: a small rotate_bytes
 * forces the seeding audit records into archives, so only the byte history
 * carried in broker_rate keeps the quota tripped across the restart. */
static void test_byte_quota_survives_rotation(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.rate_max_in_window = 1000;
    cfg.rate_max_bytes_per_uid = 1500;
    cfg.rate_max_bytes_global = 0;
    cfg.rate_window_sec = 100;
    cfg.rotate_bytes = 256;   /* rotate each op: seeders move to archives */
    cfg.max_open_per_uid = 1000;
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    unsigned long long base = 3100000000000000ull;
    unsigned long long window_us =
        (unsigned long long) cfg.rate_window_sec * 1000000ull;
    g_now = base;
    g_step = 1;

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (byte quota rotation)");
    char bind[RAB_BINDING_STR_MAX], cid[RAB_CID_MAX];
    int ok_count = 0;
    const char *code = "OK";
    for (int i = 0; i < 50; i++) {
        code = do_open(b, &a, bind, cid);
        if (strcmp(code, "OK") != 0) {
            break;
        }
        ok_count++;
    }
    CHECK(ok_count >= 1, "at least one op fits before the byte quota trips");
    CHECK(strcmp(code, "rate_limited") == 0, "byte quota trips before restart");
    CHECK(count_archives(dir, "audit.jsonl") >= 1,
          "rotation happened (seeders archived)");
    rab_broker_close(b);

    /* restart within the window: byte history reseeded from broker_rate carries */
    b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "reopen (byte quota survives)");
    CHECK(strcmp(do_open(b, &a, bind, cid), "rate_limited") == 0,
          "per-uid byte quota survived rotation + restart");
    rab_broker_close(b);

    /* well past the window: the carried bytes age out, ops allowed */
    g_now = base + window_us + 1000000ull;
    b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "reopen (byte quota, after window)");
    CHECK(strcmp(do_open(b, &a, bind, cid), "OK") == 0,
          "byte window slides open once the carried window elapses");
    rab_broker_close(b);
    g_step = 1;
    g_now = 1700000000000000ull;
    cleanup_dir(dir);
}

/* A per-uid byte quota needs the op-count limit (which bounds the ring); the
 * combination without it is rejected at open. */
static void test_byte_quota_config(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.rate_max_bytes_per_uid = 1000;
    cfg.rate_max_in_window = 0; /* invalid: unbounded ring */
    const char *err = NULL;
    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b == NULL, "per-uid byte quota without an op-count limit is rejected");
    CHECK(err != NULL, "config rejection sets err");
    cleanup_dir(dir);
}

/* Many open intents exercise the hash tables (collisions, chain unlink) and
 * reconstruction at a scale the old linked-list scan made O(n^2). */
static void test_hashed_scale(void) {
    char dir[256], path[512];
    tmpdir(dir, sizeof dir);
    sink_path(dir, path, sizeof path);
    rab_config cfg;
    rab_config_defaults(&cfg);
    cfg.rate_max_in_window = 0;      /* op-count off: unbounded ops */
    cfg.rate_max_bytes_per_uid = 0;  /* off (would else require op-count) */
    cfg.rate_max_bytes_global = 0;   /* off */
    cfg.max_open_per_uid = 100000;
    cfg.max_open_global = 100000;
    cfg.rotate_bytes = 0;            /* no rotation: pure open-set scale */
    const char *err = NULL;
    rab_actor a = mk_actor(1000, 4321, "boot-abc", "555");
    g_now = 2800000000000000ull;
    g_step = 1;

    rab_broker *b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
    CHECK(b != NULL, "broker open (scale)");
    enum { N = 2000 };
    char (*binds)[RAB_BINDING_STR_MAX] = malloc(N * sizeof *binds);
    char (*cids)[RAB_CID_MAX] = malloc(N * sizeof *cids);
    CHECK(binds != NULL && cids != NULL, "scale arrays allocated");
    if (binds != NULL && cids != NULL) {
        int all_ok = 1;
        for (int i = 0; i < N; i++) {
            if (strcmp(do_open(b, &a, binds[i], cids[i]), "OK") != 0) {
                all_ok = 0;
            }
        }
        CHECK(all_ok, "N opens all succeed");
        CHECK(rab_broker_open_count(b) == (size_t) N, "all N intents open");
        int found = 0;
        for (int i = 0; i < N; i++) {
            if (rab_broker_has_open(b, cids[i])) {
                found++;
            }
        }
        CHECK(found == N, "every cid resolves via the by-cid hash");
        int closed = 0;
        for (int i = 0; i < N; i++) {
            if (strcmp(do_outcome(b, &a, binds[i]), "OK") == 0) {
                closed++;
            }
        }
        CHECK(closed == N, "every intent closes via its binding (by-bind hash)");
        CHECK(rab_broker_open_count(b) == 0, "open set empty after closing all");
        rab_broker_close(b);

        /* reconstruct the whole 2N-record segment cleanly */
        b = rab_broker_open(path, &cfg, test_clock, NULL, &err);
        CHECK(b != NULL && rab_broker_open_count(b) == 0,
              "reconstruction of 2N records is consistent and empty");
        rab_broker_close(b);
    } else if (b != NULL) {
        rab_broker_close(b);
    }
    free(binds);
    free(cids);
    g_step = 1;
    g_now = 1700000000000000ull;
    cleanup_dir(dir);
}

int main(void) {
    test_record_schema();
    test_rate_record_parse();
    test_cross_sink_schema();
    test_strict_parsing();
    test_lifecycle_and_reconstruction();
    test_identity_and_replay();
    test_reconstruction_fails_closed();
    test_partial_tail_recovery();
    test_free_space_refusal();
    test_emit();
    test_carry_forward_idempotency();
    test_rotation_preserves_open_intents();
    test_bounded_open_intents();
    test_rate_limit_survives_restart();
    test_rate_carry_survives_rotation();
    test_retention_bounds();
    test_retention_symlink_safety();
    test_rate_window_boundary();
    test_byte_quota_per_uid();
    test_byte_quota_global();
    test_byte_quota_survives_rotation();
    test_byte_quota_config();
    test_hashed_scale();
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
