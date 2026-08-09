/* The broker's durable state and request handling: the open-intent set, the
 * per-uid rate/quota accounting, startup reconstruction from the sink (the
 * single source of truth), carry-forward rotation, and the two request
 * handlers. Decoupled from the socket/event loop (main.c) so it is unit
 * testable by calling rab_broker_handle directly with a synthesized actor. */
#ifndef RAB_BROKER_H
#define RAB_BROKER_H

#include "json.h" /* rab_request */
#include "peer.h" /* rab_actor */

#include <stddef.h>

typedef struct {
    unsigned max_open_per_uid;       /* cap on open intents per uid */
    unsigned max_open_global;        /* cap on total open intents */
    unsigned rate_window_sec;        /* per-uid op rate window (seconds) */
    unsigned rate_max_in_window;     /* max appended records/uid/window (0=off) */
    unsigned long long rotate_bytes; /* rotate segment past this (0=never) */
    unsigned long long min_free_bytes; /* refuse appends below this fs free (0=off) */
    unsigned retain_segments;        /* max archived segments to keep (0=unlimited) */
    unsigned long long retain_bytes; /* max total bytes, active+archives (0=unlimited) */
} rab_config;

void rab_config_defaults(rab_config *cfg);

typedef struct rab_broker rab_broker;

/* Injectable microsecond wall clock (broker-assigned timestamps; the rate
 * window must survive a restart, so this is real time, not monotonic). */
typedef unsigned long long (*rab_clock_fn)(void *ctx);

/* Open (creating if absent) the sink at `path`, reconstruct the open-intent set
 * and per-uid rate state from it, and return a ready broker. Fails closed
 * (NULL, *err set to a static string) on any inconsistent reconstruction:
 * outcome-without-intent, double outcome, inconsistent duplicate intent, or
 * unexplained corruption. A torn final line (crash mid-append) is recovered by
 * discarding just that trailing partial record. `clock`/`ctx` NULL uses the
 * real clock. */
rab_broker *rab_broker_open(const char *path, const rab_config *cfg,
                            rab_clock_fn clock, void *ctx, const char **err);
void rab_broker_close(rab_broker *b);

/* Handle one already-parsed, schema-valid request from `actor`. Always writes a
 * framed response body to *resp (malloc'd; caller frees) and returns 0; returns
 * -1 only on allocation failure (*resp == NULL). On any typed error nothing is
 * appended to the sink. */
int rab_broker_handle(rab_broker *b, const rab_actor *actor,
                      const rab_request *req, char **resp);

/* Inspection for tests. */
size_t rab_broker_open_count(const rab_broker *b);
int rab_broker_has_open(const rab_broker *b, const char *correlation_id);

#endif /* RAB_BROKER_H */
