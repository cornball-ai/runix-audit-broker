#include "proto.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

int rab_read_full(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (r == 0) {
            return 1; /* EOF before n bytes */
        }
        got += (size_t) r;
    }
    return 0;
}

int rab_write_full(int fd, const void *buf, size_t n) {
    const unsigned char *p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        sent += (size_t) w;
    }
    return 0;
}

rab_frame_status rab_read_frame(int fd, char **body, uint32_t *len) {
    *body = NULL;
    *len = 0;

    unsigned char header[5];
    int hr = rab_read_full(fd, header, sizeof header);
    if (hr == 1) {
        /* EOF: clean if it happened before any header byte was consumed.
         * rab_read_full cannot distinguish 0-vs-partial here, so a partial
         * header reads as EOF and is treated as a clean disconnect; a
         * mid-body EOF below is a bad frame. */
        return RAB_FRAME_EOF;
    }
    if (hr < 0) {
        return RAB_FRAME_IO;
    }

    if (header[0] != RAB_PROTO_VERSION) {
        return RAB_FRAME_BAD;
    }

    uint32_t n = ((uint32_t) header[1] << 24) | ((uint32_t) header[2] << 16) |
                 ((uint32_t) header[3] << 8) | (uint32_t) header[4];
    if (n > RAB_MAX_BODY) {
        return RAB_FRAME_TOO_LARGE;
    }

    char *buf = malloc((size_t) n + 1);
    if (buf == NULL) {
        return RAB_FRAME_IO;
    }
    if (n > 0) {
        int br = rab_read_full(fd, buf, n);
        if (br != 0) {
            free(buf);
            return (br == 1) ? RAB_FRAME_BAD : RAB_FRAME_IO;
        }
    }
    buf[n] = '\0';
    *body = buf;
    *len = n;
    return RAB_FRAME_OK;
}

int rab_write_frame(int fd, const char *body, uint32_t len) {
    if (len > RAB_MAX_BODY) {
        return -1;
    }
    unsigned char header[5];
    header[0] = (unsigned char) RAB_PROTO_VERSION;
    header[1] = (unsigned char) ((len >> 24) & 0xff);
    header[2] = (unsigned char) ((len >> 16) & 0xff);
    header[3] = (unsigned char) ((len >> 8) & 0xff);
    header[4] = (unsigned char) (len & 0xff);
    if (rab_write_full(fd, header, sizeof header) != 0) {
        return -1;
    }
    if (len > 0 && rab_write_full(fd, body, len) != 0) {
        return -1;
    }
    return 0;
}
