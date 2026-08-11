/* Receipt-token crypto unit tests: SHA-256 known-answer vectors and the
 * constant-time digest compare (src/receipt.c). Built against libcrypto with
 * ASan/UBSan (see Makefile `test-receipt`). */
#include "../src/receipt.h"

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

static void hex(const unsigned char *in, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = h[in[i] >> 4];
        out[2 * i + 1] = h[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

int main(void) {
    unsigned char d[RAB_SHA256_LEN];
    char h[RAB_SHA256_HEX_MAX];

    /* FIPS 180-4 / RFC 6234 known-answer vectors. */
    CHECK(rab_sha256("abc", 3, d) == 0, "sha256(abc) ok");
    hex(d, sizeof d, h);
    CHECK(strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a"
                    "9cb410ff61f20015ad") == 0,
          "sha256(abc) known answer");

    CHECK(rab_sha256("", 0, d) == 0, "sha256(empty) ok");
    hex(d, sizeof d, h);
    CHECK(strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b93"
                    "4ca495991b7852b855") == 0,
          "sha256(empty) known answer");

    /* a real 32-hex (128-bit) receipt-token-shaped input digests
     * deterministically, and two digests of the same token compare equal in
     * constant time. */
    const char *tok = "00112233445566778899aabbccddeeff";
    unsigned char d2[RAB_SHA256_LEN];
    CHECK(rab_sha256(tok, strlen(tok), d) == 0, "sha256(token) ok");
    CHECK(rab_sha256(tok, strlen(tok), d2) == 0, "sha256(token) again");
    CHECK(rab_sha256_eq(d, d2) == 1, "identical digests compare equal");

    /* any single-bit difference (first or last byte) compares unequal */
    unsigned char d3[RAB_SHA256_LEN];
    memcpy(d3, d, sizeof d3);
    d3[0] ^= 0x01;
    CHECK(rab_sha256_eq(d, d3) == 0, "first-byte difference compares unequal");
    memcpy(d3, d, sizeof d3);
    d3[RAB_SHA256_LEN - 1] ^= 0x80;
    CHECK(rab_sha256_eq(d, d3) == 0, "last-byte difference compares unequal");

    /* the digest of a different token differs */
    const char *tok2 = "00112233445566778899aabbccddee00";
    CHECK(rab_sha256(tok2, strlen(tok2), d3) == 0, "sha256(token2) ok");
    CHECK(rab_sha256_eq(d, d3) == 0, "distinct tokens digest differently");

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
