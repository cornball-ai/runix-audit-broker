/* Cross-repo fixture cross-check. The broker and the runix R adapter share ONE
 * response-fixture corpus (audit-broker-contract.md). It is authored in runix
 * (inst/tinytest/fixtures/broker-frames/) and vendored here; this test proves
 * the broker side of the contract against the same bytes the adapter validates:
 *
 *   - body fixtures tagged as accept goldens: the broker's response BUILDER
 *     emits exactly these bytes for the documented-format id/binding;
 *   - frame fixtures: the broker's frame READER (rab_read_frame, over a
 *     socketpair) accepts/rejects each raw frame per its category, matching how
 *     the adapter's C client treats the same bytes.
 *
 * If the two corpora ever drift, one side's build goes red. Built against
 * system Jansson with ASan/UBSan (see Makefile `test-fixtures`). */
#include "../src/json.h"
#include "../src/proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

#define FX_DIR "tests/fixtures/broker-frames/"

/* Read a whole fixture file into a malloc'd buffer; *len set. NULL on error. */
static unsigned char *slurp(const char *name, size_t *len) {
    char path[512];
    snprintf(path, sizeof path, "%s%s", FX_DIR, name);
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    unsigned char *buf = malloc((size_t) sz + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t) sz, f);
    fclose(f);
    buf[got] = '\0';
    *len = got;
    return buf;
}

/* Assert a builder's bytes equal the named body fixture. */
static void check_golden(const char *fixture, char *built, const char *label) {
    if (built == NULL) {
        CHECK(0, label);
        return;
    }
    size_t flen = 0;
    unsigned char *want = slurp(fixture, &flen);
    if (want == NULL) {
        CHECK(0, "fixture missing");
        free(built);
        return;
    }
    CHECK(strlen(built) == flen && memcmp(built, want, flen) == 0, label);
    free(want);
    free(built);
}

/* Feed a raw frame fixture through rab_read_frame over a socketpair and return
 * its status; body freed. */
static rab_frame_status read_frame_fixture(const char *fixture) {
    size_t flen = 0;
    unsigned char *bytes = slurp(fixture, &flen);
    if (bytes == NULL) {
        return RAB_FRAME_IO;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        free(bytes);
        return RAB_FRAME_IO;
    }
    /* write the fixture, then close the writer so a truncated frame hits EOF */
    if (rab_write_full(sv[1], bytes, flen) != 0) {
        close(sv[0]);
        close(sv[1]);
        free(bytes);
        return RAB_FRAME_IO;
    }
    close(sv[1]);
    free(bytes);
    char *body = NULL;
    uint32_t len = 0;
    rab_frame_status st = rab_read_frame(sv[0], &body, &len);
    free(body);
    close(sv[0]);
    return st;
}

int main(void) {
    /* --- body accept goldens: the builder emits exactly the shared bytes ---
     * The id/binding must match the corpus generator's documented-format
     * values. */
    check_golden("open_ok.json",
                 rab_response_open_ok("00001786382512165708-a061ec02cffe1b2b",
                                      "c7eb72753bf700824daf45442abd39c2",
                                      "system", NULL),
                 "open_ok builder matches the shared fixture");
    /* a receipt-bearing open_ok: the effect_receipt is distinct from the binding
     * and must equal the corpus generator's RECEIPT value byte-for-byte. */
    check_golden("open_ok_effect.json",
                 rab_response_open_ok("00001786382512165708-a061ec02cffe1b2b",
                                      "c7eb72753bf700824daf45442abd39c2", "system",
                                      "1b9d6bcd1e7f4a3bd2c5e8f0a4d7c9e2"),
                 "open_ok_effect builder matches the shared fixture");
    check_golden("redeem_ok.json",
                 rab_response_redeem_ok("00001786382512165708-a061ec02cffe1b2b"),
                 "redeem_ok builder matches the shared fixture");
    check_golden("outcome_ok.json", rab_response_outcome_ok(),
                 "outcome_ok builder matches the shared fixture");
    check_golden("emit_ok.json",
                 rab_response_emit_ok("00001786382512165708-a061ec02cffe1b2b",
                                      "system"),
                 "emit_ok builder matches the shared fixture");
    /* the capability is honoured now, so the builder emits the POPULATED
     * capabilities golden (effect_receipt:1, plan_schemas:[1]); the empty
     * capabilities_ok.json remains a valid shape the parser still accepts. */
    check_golden("caps_effect_receipt.json", rab_response_capabilities(),
                 "capabilities builder matches the populated fixture");
    check_golden("error.json", rab_response_error("schema_invalid", "nope"),
                 "error builder matches the shared fixture");

    /* --- frame fixtures: the reader agrees with the adapter on each frame --- */
    CHECK(read_frame_fixture("frame_valid_open.frame") == RAB_FRAME_OK,
          "valid frame accepted");
    CHECK(read_frame_fixture("frame_bad_version.frame") == RAB_FRAME_BAD,
          "bad-version frame rejected");
    CHECK(read_frame_fixture("frame_oversize.frame") == RAB_FRAME_TOO_LARGE,
          "oversize frame rejected");
    CHECK(read_frame_fixture("frame_truncated.frame") == RAB_FRAME_BAD,
          "truncated frame rejected");

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
