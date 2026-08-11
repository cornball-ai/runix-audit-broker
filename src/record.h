/* Marshalling of the broker's on-disk records to the shared cross-sink schema
 * (docs/durable-audit-contract.md): canonical audit fields in insertion order
 * plus a single, versioned `broker` extension object. Also the broker-internal
 * `broker_checkpoint` record (carry-forward of a still-open intent), and the
 * parse-back used during startup reconstruction.
 *
 * Canonical audit line (insertion order): schema_version, record_type="audit",
 * correlation_id, phase, host, pid (peer), actor ("uid:<n>"), <domain...>,
 * time (RFC 3339 UTC), then the trailing `broker` extension. The `broker`
 * object carries the full peer identity, the binding (intent records only,
 * sensitive), and a string `accepted_time_us` used only for reconstruction and
 * rate windows (the canonical human timestamp is `time`). */
#ifndef RAB_RECORD_H
#define RAB_RECORD_H

#include "id.h"
#include "peer.h"

#include <jansson.h>
#include <stddef.h>

#define RAB_PHASE_INTENT "intent"
#define RAB_PHASE_OUTCOME "outcome"

/* Public audit-record schema version: the top-level `schema_version` stamped on
 * every record and enforced on reconstruction. This is the single axis the
 * `capabilities` response advertises as `record_schema_version`, so the wire
 * value cannot drift from what the broker actually stamps and validates. */
#define RAB_RECORD_SCHEMA_VERSION 1u

/* max stored open-intent metadata strings (operation/resource/scope) */
#define RAB_META_MAX 128
#define RAB_SCOPE_MAX 32

/* 64 lowercase-hex chars + NUL: a SHA-256 verifier or a plan-hash digest.
 * (RAB_BOOT_ID_MAX for the receipt's boot id comes from peer.h.) */
#define RAB_HEX64_MAX 65

/* On-disk broker-STATE schema version: the durable receipt representation
 * (broker_receipt), distinct from RAB_RECORD_SCHEMA_VERSION (the public
 * audit-record schema) and from the wire capability version. It gates receipt
 * reconstruction and evolves independently. */
#define RAB_BROKER_STATE_SCHEMA_VERSION 1

/* Receipt lifecycle state. issued -> redeemed is the only durable transition
 * (expired is derived from the TTL/boot-id at read time, never persisted). */
typedef enum { RAB_RCPT_ISSUED = 0, RAB_RCPT_REDEEMED = 1 } rab_rcpt_state;

/* Build a canonical "audit" record line. `binding` non-NULL only for intent
 * records (it is sensitive and appears nowhere else). `client_record` is the
 * schema-validated domain object (borrowed); its keys are merged in canonical
 * position and never collide with broker-owned keys. Returns a malloc'd
 * NUL-terminated line with no embedded newline (caller frees), or NULL. */
char *rab_build_audit(const char *phase, const char *correlation_id,
                      const char *binding, const rab_actor *actor,
                      const char *host, unsigned long long time_us,
                      json_t *client_record);

/* Build a `broker_checkpoint` record line: a still-open intent carried forward
 * during rotation, retaining its operation/resource/scope plus binding and
 * peer identity so it stays meaningful after archives are pruned. Returns a
 * malloc'd line or NULL. */
char *rab_build_checkpoint(const char *correlation_id, const char *binding,
                           const rab_actor *actor, unsigned long long time_us,
                           const char *operation, const char *resource,
                           const char *scope);

/* Build a `broker_rate` record line: the per-uid rate-window history carried
 * forward during rotation so the per-uid rate AND write-byte limits survive a
 * restart (the client audit records that seeded them move to the archive, which
 * reconstruction never reads). `times` are broker-assigned microsecond
 * timestamps and `bytes` the appended size of each op (record + newline), one
 * per timestamp, only those still inside the rate window at rotation time.
 * Returns a malloc'd line or NULL. */
char *rab_build_rate(uid_t uid, const unsigned long long *times,
                     const unsigned long long *bytes, size_t n);

/* Build a `broker_receipt` record line: the durable effect-receipt state bound
 * to an open intent's `correlation_id`. It carries the SHA-256 `verifier` of the
 * receipt token (NEVER the live token), the bound {actor_uid, verb, resource,
 * plan_schema, plan_hash}, the CLOCK_BOOTTIME issue time + TTL, and the boot id.
 * `state` is RAB_RCPT_ISSUED or RAB_RCPT_REDEEMED. Written at issue/redeem and,
 * on rotation, as a carry-forward for every still-open intent. Returns a
 * malloc'd line or NULL. */
char *rab_build_receipt(const char *correlation_id, rab_rcpt_state state,
                        const char *verifier_hex, uid_t actor_uid,
                        const char *verb, const char *resource,
                        long long plan_schema, const char *plan_hash,
                        unsigned long long issue_boottime_us,
                        unsigned long long ttl_us, const char *boot_id);

typedef enum {
    RAB_REC_AUDIT,
    RAB_REC_CHECKPOINT,
    RAB_REC_RATE,
    RAB_REC_RECEIPT
} rab_rec_type;

/* The broker-owned facts recovered from one stored line. */
typedef struct {
    rab_rec_type type;
    char phase[16];               /* audit only; "" for a checkpoint */
    char correlation_id[RAB_CID_MAX];
    char binding[RAB_BINDING_MAX]; /* "" if the record carried none */
    rab_actor actor;              /* from broker.peer */
    unsigned long long time_us;   /* from broker.accepted_time_us */
    char operation[RAB_META_MAX]; /* open-intent metadata ("" if absent) */
    char resource[RAB_META_MAX];
    char scope[RAB_SCOPE_MAX];
    /* RAB_REC_RATE only: a per-uid carry of rate-window timestamps and the
     * appended byte size of each op. rate_times and rate_bytes are malloc'd
     * (NULL if none), same length rate_n; free with rab_stored_free. */
    uid_t rate_uid;
    unsigned long long *rate_times;
    unsigned long long *rate_bytes;
    size_t rate_n;
    /* RAB_REC_RECEIPT only (correlation_id above is the bound intent's cid). */
    rab_rcpt_state rcpt_state;
    char rcpt_verifier[RAB_HEX64_MAX];
    uid_t rcpt_actor_uid; /* range-checked at parse; never a truncating cast */
    char rcpt_verb[RAB_META_MAX];
    char rcpt_resource[RAB_META_MAX];
    long long rcpt_plan_schema;
    char rcpt_plan_hash[RAB_HEX64_MAX];
    unsigned long long rcpt_issue_boottime_us;
    unsigned long long rcpt_ttl_us;
    char rcpt_boot_id[RAB_BOOT_ID_MAX];
} rab_stored;

/* Parse one stored line into *out. Returns 0 on a well-formed broker record,
 * -1 otherwise. Strict: duplicate keys, a missing correlation id, a missing or
 * malformed `broker` extension, or (for audit) a missing phase all fail. On
 * success for a RAB_REC_RATE record, *out owns a malloc'd rate_times; release
 * every parsed *out with rab_stored_free. */
int rab_parse_stored(const char *line, size_t len, rab_stored *out);

/* Release any heap owned by a parsed record (the RAB_REC_RATE rate_times).
 * Safe on any *out, including one from a failed parse. */
void rab_stored_free(rab_stored *out);

#endif /* RAB_RECORD_H */
