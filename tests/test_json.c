/* Parser/schema tests: the parse-side abuse cases (duplicate keys, trailing
 * content, invalid UTF-8, schema confusion, depth) and golden response bytes.
 * Built against system Jansson with ASan/UBSan (see Makefile `test-json`). */
#include "../src/json.h"

#include <stdio.h>
#include <string.h>

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

/* parse and report the error code (or "OK"); frees on success. */
static const char *parse_code(const char *body, size_t len) {
    rab_request req;
    const char *err = NULL;
    int rc = rab_parse_request(body, len, &req, &err);
    if (rc == 0) {
        rab_request_free(&req);
        return "OK";
    }
    return err;
}
#define PARSE(s) parse_code((s), strlen(s))

int main(void) {
    /* --- valid requests --- */
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"record\":"
                       "{\"operation\":\"systemd.restart\",\"outcome\":"
                       "\"intent\"}}"), "OK") == 0, "valid open_intent");
    CHECK(strcmp(PARSE("{\"type\":\"write_outcome\",\"binding\":\"abc123\","
                       "\"record\":{\"operation\":\"systemd.restart\","
                       "\"outcome\":\"ok\",\"effect_issued\":true}}"),
                 "OK") == 0, "valid write_outcome");

    /* binding is extracted */
    {
        rab_request req;
        const char *err = NULL;
        const char *b = "{\"type\":\"write_outcome\",\"binding\":\"deadbeef\","
                        "\"record\":{\"operation\":\"x\",\"outcome\":\"ok\"}}";
        CHECK(rab_parse_request(b, strlen(b), &req, &err) == 0, "parse wo");
        CHECK(strcmp(req.binding, "deadbeef") == 0, "binding extracted");
        rab_request_free(&req);
    }

    /* --- duplicate keys rejected (JSON_REJECT_DUPLICATES) --- */
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"type\":\"open_intent\","
                       "\"record\":{\"operation\":\"x\",\"outcome\":\"i\"}}"),
                 "bad_json") == 0, "duplicate top-level key rejected");
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"record\":"
                       "{\"operation\":\"x\",\"operation\":\"y\","
                       "\"outcome\":\"i\"}}"), "bad_json") == 0,
          "duplicate record key rejected");

    /* --- trailing content rejected (strict EOF) --- */
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"record\":"
                       "{\"operation\":\"x\",\"outcome\":\"i\"}} garbage"),
                 "bad_json") == 0, "trailing content rejected");

    /* --- invalid UTF-8 rejected (Jansson validates) --- */
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"record\":"
                       "{\"operation\":\"\xff\xfe\",\"outcome\":\"i\"}}"),
                 "bad_json") == 0, "invalid UTF-8 rejected");

    /* --- unknown request type --- */
    CHECK(strcmp(PARSE("{\"type\":\"delete_everything\",\"record\":"
                       "{\"operation\":\"x\",\"outcome\":\"i\"}}"),
                 "unknown_request") == 0, "unknown request type");

    /* --- schema confusion --- */
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"record\":"
                       "{\"operation\":\"x\",\"outcome\":\"i\"},\"extra\":1}"),
                 "schema_invalid") == 0, "extra top-level key rejected");
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"record\":"
                       "{\"operation\":\"x\",\"outcome\":\"i\",\"bogus\":1}}"),
                 "schema_invalid") == 0, "unknown record field rejected");
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"record\":"
                       "{\"operation\":123,\"outcome\":\"i\"}}"),
                 "schema_invalid") == 0, "wrong field type rejected");
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"record\":"
                       "{\"outcome\":\"i\"}}"), "schema_invalid") == 0,
          "missing required field rejected");
    CHECK(strcmp(PARSE("{\"type\":\"write_outcome\",\"record\":"
                       "{\"operation\":\"x\",\"outcome\":\"ok\"}}"),
                 "schema_invalid") == 0, "write_outcome without binding");
    /* a broker-owned field in the client record is unexpected -> rejected */
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"record\":"
                       "{\"operation\":\"x\",\"outcome\":\"i\","
                       "\"correlation_id\":\"forged\"}}"),
                 "schema_invalid") == 0, "broker-owned field rejected");
    /* negative elapsed out of range */
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"record\":"
                       "{\"operation\":\"x\",\"outcome\":\"i\","
                       "\"elapsed\":-5}}"), "schema_invalid") == 0,
          "negative elapsed rejected");

    /* --- depth limit --- */
    CHECK(strcmp(PARSE("{\"type\":\"open_intent\",\"record\":{\"operation\":"
                       "\"x\",\"outcome\":\"i\",\"observed\":{\"a\":{\"b\":"
                       "{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":\"h\"}}}}}}}}}"),
                 "schema_invalid") == 0, "over-deep nesting rejected");

    /* --- rab_json_depth --- */
    {
        json_t *scalar = json_string("x");
        CHECK(rab_json_depth(scalar) == 0, "scalar depth 0");
        json_decref(scalar);
        json_error_t e;
        json_t *o = json_loadb("{\"a\":{\"b\":1}}", 13, 0, &e);
        CHECK(o != NULL && rab_json_depth(o) == 2, "nested object depth 2");
        if (o) json_decref(o);
    }

    /* --- golden response bytes (JSON_COMPACT | JSON_SORT_KEYS) --- */
    {
        char *r = rab_response_open_ok("cid1", "bind1", "system");
        CHECK(r != NULL && strcmp(r,
            "{\"audit_scope\":\"system\",\"binding\":\"bind1\","
            "\"correlation_id\":\"cid1\",\"ok\":true,\"persisted\":true}")
            == 0, "open_ok golden bytes");
        free(r);
        r = rab_response_outcome_ok();
        CHECK(r != NULL && strcmp(r, "{\"ok\":true,\"persisted\":true}") == 0,
              "outcome_ok golden bytes");
        free(r);
        r = rab_response_error("schema_invalid", "nope");
        CHECK(r != NULL && strcmp(r,
            "{\"error\":\"schema_invalid\",\"message\":\"nope\",\"ok\":false}")
            == 0, "error golden bytes");
        free(r);
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
