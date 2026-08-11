/* Receipt-token crypto for the effect-receipt capability. The broker persists a
 * SHA-256 *verifier* of a receipt token (never the live token) and, at redeem,
 * re-derives the digest from the presented token and compares it in constant
 * time. SHA-256 comes from OpenSSL's EVP interface and the compare from
 * CRYPTO_memcmp, so this is apt-serviced crypto in the root daemon, not a
 * vendored hash. */
#ifndef RAB_RECEIPT_H
#define RAB_RECEIPT_H

#include <stddef.h>

#define RAB_SHA256_LEN 32u     /* raw SHA-256 digest, bytes */
#define RAB_SHA256_HEX_MAX 65u /* 64 lowercase hex chars + NUL */

/* SHA-256 of `len` bytes at `data` into out[RAB_SHA256_LEN]. Returns 0 on
 * success, -1 on any OpenSSL error (out is then unspecified). */
int rab_sha256(const void *data, size_t len, unsigned char out[RAB_SHA256_LEN]);

/* Constant-time equality of two SHA-256 digests (CRYPTO_memcmp): 1 if equal,
 * 0 otherwise. The timing does not depend on where the buffers first differ,
 * so comparing a presented token's digest against the stored verifier leaks no
 * position information. */
int rab_sha256_eq(const unsigned char a[RAB_SHA256_LEN],
                  const unsigned char b[RAB_SHA256_LEN]);

#endif /* RAB_RECEIPT_H */
