/* Broker-minted identifiers. Correlation ids are time-orderable (a sortable
 * sink stays chronological); the opaque binding token is unguessable, drawn
 * wholly from kernel randomness (getrandom), never from rand()/time/pid. */
#ifndef RAB_ID_H
#define RAB_ID_H

#include <stddef.h>

#define RAB_CID_MAX 64u     /* buffer for a correlation id incl. NUL */
#define RAB_BINDING_MAX 33u /* 32 hex chars + NUL */

/* Write a time-orderable correlation id into buf:
 * "<20-digit microsecond timestamp>-<16 hex random>". The timestamp makes it
 * sortable; the getrandom suffix makes it unique. 0 on success, -1 on error. */
int rab_make_correlation_id(char *buf, size_t buflen);

/* Write an unguessable binding token (32 hex chars = 16 getrandom bytes) into
 * buf. buf must be at least RAB_BINDING_MAX. 0 on success, -1 on error. */
int rab_make_binding(char *buf, size_t buflen);

#endif /* RAB_ID_H */
