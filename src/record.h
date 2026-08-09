/* Marshalling of the broker's own on-disk audit records: build a canonical
 * JSONL line from broker-stamped fields plus the client's schema-validated
 * domain content, and parse such a line back during startup reconstruction.
 *
 * A stored record carries broker-owned fields the client can never set
 * (`correlation_id`, `phase`, `actor`, `time`, `host`) merged with the client
 * `record` content. `phase` is one of "intent", "outcome", "carry_forward".
 * Only "intent" and "carry_forward" carry a `binding`. */
#ifndef RAB_RECORD_H
#define RAB_RECORD_H

#include "id.h"
#include "peer.h"

#include <jansson.h>
#include <stddef.h>

#define RAB_PHASE_INTENT "intent"
#define RAB_PHASE_OUTCOME "outcome"
#define RAB_PHASE_CARRY "carry_forward"

/* Build a canonical (compact, sorted-key) record line. `binding` may be NULL
 * for an outcome record. `client_record` is the schema-validated domain object
 * (borrowed); its keys are merged in and never collide with broker-owned keys
 * (the schema rejects broker-owned keys in client records). Returns a malloc'd
 * NUL-terminated string with no embedded newline (caller frees), or NULL. */
char *rab_build_record(const char *phase, const char *correlation_id,
                       const char *binding, const rab_actor *actor,
                       const char *host, unsigned long long time_us,
                       json_t *client_record);

/* The broker-owned facts recovered from one stored line. */
typedef struct {
    char phase[16];
    char correlation_id[RAB_CID_MAX];
    char binding[RAB_BINDING_MAX]; /* "" if the record carried none */
    rab_actor actor;
    unsigned long long time_us;
} rab_stored;

/* Parse one stored line into *out. Returns 0 on a well-formed broker record,
 * -1 otherwise (the caller decides whether that is a torn tail or corruption).
 * Strict: duplicate keys, a missing/!string phase, a missing correlation id,
 * or a malformed actor all fail. */
int rab_parse_stored(const char *line, size_t len, rab_stored *out);

#endif /* RAB_RECORD_H */
