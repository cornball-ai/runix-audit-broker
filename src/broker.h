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
    unsigned receipt_ttl_sec;        /* effect-receipt TTL, seconds (fixed, bounded) */
} rab_config;

/* Upper bound on the receipt TTL (30 days): keeps issue_boottime + ttl well
 * inside a 64-bit microsecond counter and rejects a nonsensical config. */
#define RAB_MAX_RECEIPT_TTL_SEC (30u * 24u * 60u * 60u)

void rab_config_defaults(rab_config *cfg);

typedef struct rab_broker rab_broker;

/* Injectable microsecond wall clock (broker-assigned timestamps; the rate
 * window must survive a restart, so this is real time, not monotonic). */
typedef unsigned long long (*rab_clock_fn)(void *ctx);

/* Injectable CLOCK_BOOTTIME microsecond source and boot-id provider for
 * effect-receipt issuance. Both return 0 on success (writing the result) and -1
 * on failure, which fails issuance closed. The broker owns the receipt's issue
 * time, TTL, and boot id structurally; a client never supplies them. */
typedef int (*rab_boottime_fn)(void *ctx, unsigned long long *out_us);
typedef int (*rab_bootid_fn)(void *ctx, char *out, size_t cap);

/* Durability-failure injection mode for the append test seam. */
typedef enum {
    RAB_FAIL_NONE = 0,
    RAB_FAIL_PARTIAL, /* a torn write: partial bytes land, then the append fails */
    RAB_FAIL_SYNC     /* a complete record written, then the fdatasync fails */
} rab_test_fail_mode;

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

/* rab_broker_issue_receipt return: 0 success; RAB_ISSUE_RATE_LIMITED when the
 * receipt append would exceed the opener's per-uid op/byte quota (nothing is
 * written); -1 for any other failure. */
#define RAB_ISSUE_RATE_LIMITED (-2)

/* Issue an effect receipt bound to an already-open intent (by correlation_id):
 * mint a 128-bit token, persist an `issued` broker_receipt record durably
 * (fsync), THEN install the receipt state on the intent (never before the
 * durable append succeeds). On success returns 0 and writes the token into
 * `out_token` (capacity out_cap >= RAB_RECEIPT_MAX). Fails closed: an
 * append/fsync failure poisons the broker and returns no token; a missing,
 * closed, already-receipted intent, or low free space returns -1 without
 * poisoning. The receipt binds the intent's opener uid, verb (operation) and
 * resource, plus the caller-supplied plan digest and broker-assigned
 * CLOCK_BOOTTIME issue time (broker-derived), the fixed config TTL, and the
 * broker's boot id. This is the state primitive the redemption work (2c) and
 * the public effect path will call once wired; the wire path does not reach it
 * in this slice. `out_token` is cleared to "" on every failure path. */
int rab_broker_issue_receipt(rab_broker *b, const char *correlation_id,
                             long long plan_schema, const char *plan_hash,
                             char *out_token, size_t out_cap);

/* Outcome of a redemption attempt. Every value but RAB_REDEEM_OK is a
 * fail-closed refusal that leaves the receipt untouched; the wire redeem path
 * (a later slice) maps these to typed protocol errors, but the primitive itself
 * performs every identity/crypto/expiry check. */
typedef enum {
    RAB_REDEEM_OK = 0,       /* redeemed: state advanced to redeemed, durable */
    RAB_REDEEM_UNKNOWN,      /* no such open intent, or it carries no receipt */
    RAB_REDEEM_NOT_REDEEMER, /* the redeemer is not the root helper (uid 0) */
    RAB_REDEEM_PRINCIPAL,    /* PKEXEC principal != the intent's bound opener uid */
    RAB_REDEEM_TOKEN,        /* the presented token's verifier does not match */
    RAB_REDEEM_BINDING,      /* verb/resource/plan_schema/plan_hash disagree */
    RAB_REDEEM_EXPIRED,      /* the TTL elapsed, or a reboot invalidated it */
    RAB_REDEEM_ALREADY,      /* already redeemed (single-use) */
    RAB_REDEEM_RATE,         /* the redeemed append would exceed the bound actor's quota */
    RAB_REDEEM_PERSIST       /* poisoned, no free space, or a durable-append fault */
} rab_redeem_result;

/* Redeem the effect receipt bound to an open intent (by correlation_id): the
 * state transition the root helper performs BEFORE it commits the effect. The
 * redeemer must be uid 0 (the pkexec'd helper) and `principal_uid` (its
 * PKEXEC_UID) must equal the intent's bound opener uid. The presented `token`'s
 * SHA-256 is compared against the stored verifier in constant time
 * (CRYPTO_memcmp on the raw digests, never a byte-early strcmp of the hex), and
 * the presented {verb, resource, plan_schema, plan_hash} must equal the bound
 * ones. The receipt must be unexpired: the current boot id equals the issue-time
 * boot id AND the elapsed CLOCK_BOOTTIME is within the receipt's TTL. On success
 * the redeemed transition is durably appended (fsync) BEFORE the in-memory state
 * advances to redeemed, and RAB_REDEEM_OK is returned; a durable-append fault
 * poisons the broker (RAB_REDEEM_PERSIST) and leaves the state issued. Redeeming
 * is single-use: a second attempt is RAB_REDEEM_ALREADY. This is the state
 * primitive the wire redeem path will call once wired; the wire does not reach
 * it in this slice. */
rab_redeem_result rab_broker_redeem_receipt(rab_broker *b,
                                            const char *correlation_id,
                                            const char *token, uid_t redeemer_uid,
                                            uid_t principal_uid, const char *verb,
                                            const char *resource,
                                            long long plan_schema,
                                            const char *plan_hash);

/* Inspection for tests. */
size_t rab_broker_open_count(const rab_broker *b);
int rab_broker_has_open(const rab_broker *b, const char *correlation_id);
/* -1 = no such open intent or it has no receipt; 0 = issued; 1 = redeemed. */
int rab_broker_receipt_state(const rab_broker *b, const char *correlation_id);
int rab_broker_poisoned(const rab_broker *b);

/* Test seam: force the NEXT sink append to fail at the sink append/sync
 * boundary (partial write, or fdatasync-after-write), exercising the
 * poison-on-durability-failure path deterministically. */
void rab_broker_test_fail_next_append(rab_broker *b, rab_test_fail_mode mode);

/* Test seam: override the receipt CLOCK_BOOTTIME / boot-id sources (and ctx).
 * Passing NULL for a source restores the real one. */
void rab_broker_test_set_receipt_time(rab_broker *b, rab_boottime_fn bt,
                                      rab_bootid_fn bid, void *ctx);

#endif /* RAB_BROKER_H */
