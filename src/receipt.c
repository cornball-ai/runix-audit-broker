#include "receipt.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

int rab_sha256(const void *data, size_t len, unsigned char out[RAB_SHA256_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    unsigned int outlen = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, data, len) == 1 &&
             EVP_DigestFinal_ex(ctx, out, &outlen) == 1;
    EVP_MD_CTX_free(ctx);
    return (ok && outlen == RAB_SHA256_LEN) ? 0 : -1;
}

int rab_sha256_eq(const unsigned char a[RAB_SHA256_LEN],
                  const unsigned char b[RAB_SHA256_LEN]) {
    /* CRYPTO_memcmp returns 0 iff the buffers are equal, in constant time. */
    return CRYPTO_memcmp(a, b, RAB_SHA256_LEN) == 0 ? 1 : 0;
}
