/* Strict request parsing/validation and canonical response building, on top
 * of system Jansson. Parsing uses json_loadb(..., JSON_REJECT_DUPLICATES):
 * that rejects duplicate keys natively, and leaving JSON_DISABLE_EOF_CHECK
 * unset enforces complete-input consumption (no trailing content). Jansson
 * always validates UTF-8. The protocol's tighter nesting limit is enforced
 * here (Jansson's own compiled limit is 2048, far too deep for our records).
 * Responses are emitted with JSON_COMPACT | JSON_SORT_KEYS for deterministic,
 * golden-testable bytes. */
#ifndef RAB_JSON_H
#define RAB_JSON_H

#include <jansson.h>
#include <stddef.h>

#define RAB_MAX_DEPTH 8       /* records are shallow: object > record > observed */
#define RAB_BINDING_STR_MAX 128
#define RAB_PLAN_HASH_MAX 65  /* 64-hex SHA-256 plan digest + NUL */

typedef enum {
    RAB_REQ_OPEN_INTENT,
    RAB_REQ_WRITE_OUTCOME,
    RAB_REQ_EMIT,
    RAB_REQ_CAPABILITIES
} rab_req_type;

typedef struct {
    rab_req_type type;
    char binding[RAB_BINDING_STR_MAX]; /* write_outcome only; "" otherwise */
    char phase[16];                    /* emit only: "preview"|"noop"; "" else */
    /* open_intent effect request (opt-in). effect_present == 0 is today's
     * behaviour; when set, `effect.required` was literal true (the presence of
     * `effect` is itself the opt-in), the fields are grammar-validated here, and
     * the broker decides whether it can honour issuance (fail-closed until it
     * can). */
    int effect_present;
    json_int_t effect_plan_schema;            /* effect.plan_schema (>= 1) */
    char effect_plan_hash[RAB_PLAN_HASH_MAX]; /* effect.plan_hash (64 lc hex) */
    json_t *record;                    /* borrowed from root */
    json_t *root;                      /* owned; free via rab_request_free */
} rab_request;

/* Parse and validate a request body. On success returns 0 and fills *req
 * (caller must rab_request_free). On failure returns -1 and sets *errcode to
 * a typed protocol error string ("bad_json", "unknown_request",
 * "schema_invalid"). */
int rab_parse_request(const char *body, size_t len, rab_request *req,
                      const char **errcode);

void rab_request_free(rab_request *req);

/* Maximum container nesting depth of a value (a scalar is depth 0, an object
 * or array containing only scalars is depth 1, ...). */
int rab_json_depth(const json_t *v);

/* Canonical (compact, sorted-key) response builders. Each returns a malloc'd
 * NUL-terminated string (caller frees) or NULL on allocation failure. */
/* open_intent success. `effect_receipt` is the opaque receipt token when the
 * open issued one (a receipt-bearing open_ok), or NULL to omit the member (an
 * ordinary open_ok). The receipt is a distinct token from `binding`; the caller
 * guarantees they differ via the mint-time collision check. */
char *rab_response_open_ok(const char *correlation_id, const char *binding,
                           const char *audit_scope, const char *effect_receipt);
char *rab_response_outcome_ok(void);
/* redeem_receipt success: a correlation id only (no binding, no audit_scope). */
char *rab_response_redeem_ok(const char *correlation_id);
/* emit success: a minted correlation id and no binding (opens no intent). */
char *rab_response_emit_ok(const char *correlation_id, const char *audit_scope);
/* capability negotiation: what this broker supports. `extensions` is empty and
 * `plan_schemas` is [] until the effect-receipt capability is honoured; a client
 * treats an absent `effect_receipt` member as "receipts unsupported". */
char *rab_response_capabilities(void);
char *rab_response_error(const char *code, const char *message);

#endif /* RAB_JSON_H */
