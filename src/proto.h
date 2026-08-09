/* Wire framing for the runix-audit-broker protocol (see PROTOCOL.md).
 * A frame is: [version:1][length:uint32 big-endian][body:length bytes].
 * Blocking stream socket; complete read/write loops handle partial I/O. */
#ifndef RAB_PROTO_H
#define RAB_PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define RAB_PROTO_VERSION 1u
#define RAB_MAX_BODY 65536u /* hard maximum body size (64 KiB) */

typedef enum {
    RAB_FRAME_OK = 0,
    RAB_FRAME_BAD,   /* wrong version, or truncated/interrupted frame */
    RAB_FRAME_TOO_LARGE, /* length prefix exceeds RAB_MAX_BODY */
    RAB_FRAME_EOF,   /* clean EOF before any byte of a frame */
    RAB_FRAME_IO,    /* underlying read/write error */
    RAB_FRAME_TIMEOUT /* absolute deadline passed before the frame completed */
} rab_frame_status;

/* Read exactly n bytes into buf, retrying short reads and EINTR.
 * Returns 0 on success, 1 on clean EOF before n, -1 on error. */
int rab_read_full(int fd, void *buf, size_t n);

/* Write exactly n bytes from buf, retrying short writes and EINTR.
 * Returns 0 on success, -1 on error. */
int rab_write_full(int fd, const void *buf, size_t n);

/* Read one frame. On RAB_FRAME_OK, *body is a malloc'd, NUL-terminated buffer
 * of *len bytes (caller frees) and *len <= RAB_MAX_BODY. On any other status
 * *body is NULL. A zero-length body is valid framing (schema rejects it). */
rab_frame_status rab_read_frame(int fd, char **body, uint32_t *len);

/* Write one frame with the given body. Returns 0 on success, -1 on error.
 * len must be <= RAB_MAX_BODY. */
int rab_write_frame(int fd, const char *body, uint32_t len);

/* Deadline-aware framing for the (non-blocking) accept loop. `deadline` is an
 * ABSOLUTE CLOCK_MONOTONIC instant; the remaining budget is recomputed on every
 * partial read/write and never reset by progress, so a client dripping one byte
 * at a time still hits the same wall-clock limit (anti-slowloris). The fd must
 * be non-blocking. */
rab_frame_status rab_read_frame_deadline(int fd, char **body, uint32_t *len,
                                         const struct timespec *deadline);
/* 0 on success, -1 on error/timeout. */
int rab_write_frame_deadline(int fd, const char *body, uint32_t len,
                             const struct timespec *deadline);

/* Absolute-deadline complete read/write of n bytes on a non-blocking fd.
 * Return: 0 ok, 1 EOF (read only), -1 error, -2 timeout. Exposed for tests. */
int rab_read_full_deadline(int fd, void *buf, size_t n,
                           const struct timespec *deadline);
int rab_write_full_deadline(int fd, const void *buf, size_t n,
                            const struct timespec *deadline);

#endif /* RAB_PROTO_H */
