#include "id.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/random.h>
#include <time.h>

/* Fill n bytes from the kernel CSPRNG, retrying partial reads and EINTR. */
static int fill_random(unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom(buf + got, n - got, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        got += (size_t) r;
    }
    return 0;
}

static void to_hex(const unsigned char *in, size_t n, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hex[in[i] >> 4];
        out[2 * i + 1] = hex[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

int rab_make_correlation_id(char *buf, size_t buflen) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return -1;
    }
    uint64_t micros = (uint64_t) ts.tv_sec * 1000000ull +
                      (uint64_t) (ts.tv_nsec / 1000);
    unsigned char rnd[8];
    if (fill_random(rnd, sizeof rnd) != 0) {
        return -1;
    }
    char hex[2 * sizeof rnd + 1];
    to_hex(rnd, sizeof rnd, hex);
    int n = snprintf(buf, buflen, "%020" PRIu64 "-%s", micros, hex);
    if (n < 0 || (size_t) n >= buflen) {
        return -1;
    }
    return 0;
}

int rab_make_binding(char *buf, size_t buflen) {
    if (buflen < RAB_BINDING_MAX) {
        return -1;
    }
    unsigned char rnd[16];
    if (fill_random(rnd, sizeof rnd) != 0) {
        return -1;
    }
    to_hex(rnd, sizeof rnd, buf); /* 32 hex chars + NUL */
    return 0;
}

int rab_make_receipt(char *buf, size_t buflen) {
    if (buflen < RAB_RECEIPT_MAX) {
        return -1;
    }
    unsigned char rnd[32];
    if (fill_random(rnd, sizeof rnd) != 0) {
        return -1;
    }
    to_hex(rnd, sizeof rnd, buf); /* 64 hex chars + NUL */
    return 0;
}
