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
    unsigned long long rate_max_bytes_per_uid; /* max appended bytes/uid/window (0=off) */
    unsigned long long rate_max_bytes_global;  /* max appended bytes/window, all uids (0=off) */
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

/* Issue an effect receipt bound to an already-open intent (by correlation_id):
 * mint a 128-bit token, persist an `issued` broker_receipt record durably
 * (fsync), THEN install the receipt state on the intent (never before the
 * durable append succeeds). On success returns 0 and writes the token into
 * `out_token` (capacity out_cap >= RAB_RECEIPT_MAX). Fails closed: an
 * append/fsync failure poisons the broker and returns no token; a missing,
 * closed, already-receipted intent, or low free space returns -1 without
 * poisoning. The receipt binds the intent's opener uid, verb (operation) and
 * resource, plus the caller-supplied plan digest and broker-assigned
 * CLOCK_BOOTTIME issue time / TTL / boot id. This is the state primitive the
 * redemption work (2c) and the public effect path will call once wired; the
 * wire path does not reach it in this slice. */
int rab_broker_issue_receipt(rab_broker *b, const char *correlation_id,
                             long long plan_schema, const char *plan_hash,
                             unsigned long long issue_boottime_us,
                             unsigned long long ttl_us, const char *boot_id,
                             char *out_token, size_t out_cap);

/* Inspection for tests. */
size_t rab_broker_open_count(const rab_broker *b);
int rab_broker_has_open(const rab_broker *b, const char *correlation_id);
/* -1 = no such open intent or it has no receipt; 0 = issued; 1 = redeemed. */
int rab_broker_receipt_state(const rab_broker *b, const char *correlation_id);
int rab_broker_poisoned(const rab_broker *b);

/* Test seam: force the NEXT sink append to fail as if the write tore, so the
 * poison-on-append-failure path is exercised deterministically. */
void rab_broker_test_fail_next_append(rab_broker *b);

#endif /* RAB_BROKER_H */
