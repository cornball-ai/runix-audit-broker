#include "json.h"

#include "proto.h"   /* RAB_PROTO_VERSION: the frame-protocol version */
#include "record.h"  /* RAB_RECORD_SCHEMA_VERSION: the public record schema */

#include <string.h>

/* Allowed record fields and their permitted JSON types. The client sends only
 * durable-audit domain content; broker-owned fields (correlation_id, actor,
 * phase, host, pid, time, schema_version) are NOT accepted here (they are not
 * in this allowlist, so they are rejected as unexpected) and are stamped by
 * the broker itself. */
typedef enum {
    T_STRING, /* JSON string or null */
    T_BOOL,   /* JSON true/false or null */
    T_NUMBER, /* JSON integer/real (>= 0) or null */
    T_OBJECT  /* JSON object or null */
} field_type;

typedef struct {
    const char *key;
    field_type type;
    int required;
} field_spec;

static const field_spec RECORD_SCHEMA[] = {
    {"operation", T_STRING, 1},
    {"outcome", T_STRING, 1},
    {"resource", T_STRING, 0},
    {"scope", T_STRING, 0},
    {"audit_scope", T_STRING, 0},
    {"authorized_via", T_STRING, 0},
    {"completion_method", T_STRING, 0},
    {"job_result", T_STRING, 0},
    {"observed_reason", T_STRING, 0},
    {"preview", T_BOOL, 0},
    {"effect_issued", T_BOOL, 0},
    {"changed", T_BOOL, 0},
    {"state_changed", T_BOOL, 0},
    {"observed_failed", T_BOOL, 0},
    {"elapsed", T_NUMBER, 0},
    {"observed", T_OBJECT, 0}
};
static const size_t RECORD_SCHEMA_N =
    sizeof RECORD_SCHEMA / sizeof RECORD_SCHEMA[0];

int rab_json_depth(const json_t *v) {
    if (v == NULL) {
        return 0;
    }
    int max_child = 0;
    if (json_is_object(v)) {
        const char *k;
        json_t *child;
        json_object_foreach((json_t *) v, k, child) {
            int d = rab_json_depth(child);
            if (d > max_child) {
                max_child = d;
            }
        }
        return max_child + 1;
    }
    if (json_is_array(v)) {
        size_t i;
        json_t *child;
        json_array_foreach(v, i, child) {
            int d = rab_json_depth(child);
            if (d > max_child) {
                max_child = d;
            }
        }
        return max_child + 1;
    }
    return 0;
}

static const field_spec *find_field(const char *key) {
    for (size_t i = 0; i < RECORD_SCHEMA_N; i++) {
        if (strcmp(RECORD_SCHEMA[i].key, key) == 0) {
            return &RECORD_SCHEMA[i];
        }
    }
    return NULL;
}

static int type_ok(field_type t, const json_t *v) {
    if (json_is_null(v)) {
        return 1; /* null is allowed for every optional-typed field */
    }
    switch (t) {
    case T_STRING:
        return json_is_string(v);
    case T_BOOL:
        return json_is_boolean(v);
    case T_NUMBER:
        return json_is_number(v) && json_number_value(v) >= 0.0;
    case T_OBJECT:
        return json_is_object(v);
    }
    return 0;
}

static int record_valid(json_t *record) {
    if (!json_is_object(record)) {
        return 0;
    }
    /* every present key must be known and correctly typed */
    const char *key;
    json_t *val;
    json_object_foreach(record, key, val) {
        const field_spec *f = find_field(key);
        if (f == NULL || !type_ok(f->type, val)) {
            return 0;
        }
    }
    /* every required key must be present and non-null */
    for (size_t i = 0; i < RECORD_SCHEMA_N; i++) {
        if (RECORD_SCHEMA[i].required) {
            json_t *v = json_object_get(record, RECORD_SCHEMA[i].key);
            if (v == NULL || json_is_null(v)) {
                return 0;
            }
        }
    }
    return 1;
}

/* Reject a top-level object with any key outside the allowed set. */
static int only_keys(json_t *obj, const char *const *allowed, size_t n) {
    const char *key;
    json_t *val;
    json_object_foreach(obj, key, val) {
        int ok = 0;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(key, allowed[i]) == 0) {
                ok = 1;
                break;
            }
        }
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

/* A 64-char lowercase-hex string (a SHA-256 digest), NUL-terminated at 64. */
static int is_hex64(const char *s) {
    for (size_t i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    return s[64] == '\0';
}

/* An open_intent `effect` object is exactly {required: true, plan_schema:
 * int >= 1, plan_hash: 64 lowercase hex}. `required` must be literal `true`:
 * the presence of `effect` IS the opt-in, so a `false` (or non-boolean) value
 * is rejected rather than left as an ambiguous downgrade path. Grammar only;
 * the broker decides whether it can honour the request. */
static int effect_valid(json_t *e) {
    if (!json_is_object(e)) {
        return 0;
    }
    static const char *const ek[] = {"required", "plan_schema", "plan_hash"};
    if (!only_keys(e, ek, 3)) {
        return 0;
    }
    json_t *req = json_object_get(e, "required");
    json_t *ps = json_object_get(e, "plan_schema");
    json_t *ph = json_object_get(e, "plan_hash");
    if (!json_is_true(req) || !json_is_integer(ps) ||
        json_integer_value(ps) < 1 || !json_is_string(ph)) {
        return 0;
    }
    return is_hex64(json_string_value(ph));
}

int rab_parse_request(const char *body, size_t len, rab_request *req,
                      const char **errcode) {
    *errcode = "bad_json";
    req->root = NULL;
    req->record = NULL;
    req->binding[0] = '\0';
    req->phase[0] = '\0';
    req->effect_present = 0;
    req->effect_plan_schema = 0;
    req->effect_plan_hash[0] = '\0';

    json_error_t jerr;
    /* JSON_REJECT_DUPLICATES: reject duplicate keys. No JSON_DISABLE_EOF_CHECK
     * so trailing content is rejected. UTF-8 is validated by Jansson. */
    json_t *root = json_loadb(body, len, JSON_REJECT_DUPLICATES, &jerr);
    if (root == NULL) {
        return -1; /* bad_json: malformed, dup keys, trailing, or bad UTF-8 */
    }

    if (!json_is_object(root) || rab_json_depth(root) > RAB_MAX_DEPTH) {
        json_decref(root);
        *errcode = "schema_invalid";
        return -1;
    }

    json_t *jtype = json_object_get(root, "type");
    if (!json_is_string(jtype)) {
        json_decref(root);
        *errcode = "schema_invalid";
        return -1;
    }
    const char *type = json_string_value(jtype);

    json_t *record = json_object_get(root, "record");

    if (strcmp(type, "open_intent") == 0) {
        static const char *const allowed[] = {"type", "record", "effect"};
        json_t *effect = json_object_get(root, "effect");
        if (!only_keys(root, allowed, 3) || !json_is_object(record) ||
            !record_valid(record)) {
            json_decref(root);
            *errcode = "schema_invalid";
            return -1;
        }
        if (effect != NULL) {
            /* an effect request is opt-in; when present its grammar is exact. */
            if (!effect_valid(effect)) {
                json_decref(root);
                *errcode = "schema_invalid";
                return -1;
            }
            req->effect_present = 1; /* effect_valid guaranteed required==true */
            req->effect_plan_schema =
                json_integer_value(json_object_get(effect, "plan_schema"));
            memcpy(req->effect_plan_hash,
                   json_string_value(json_object_get(effect, "plan_hash")), 64);
            req->effect_plan_hash[64] = '\0';
        }
        req->type = RAB_REQ_OPEN_INTENT;
    } else if (strcmp(type, "write_outcome") == 0) {
        static const char *const allowed[] = {"type", "binding", "record"};
        json_t *jbind = json_object_get(root, "binding");
        if (!only_keys(root, allowed, 3) || !json_is_string(jbind) ||
            !json_is_object(record) || !record_valid(record)) {
            json_decref(root);
            *errcode = "schema_invalid";
            return -1;
        }
        const char *b = json_string_value(jbind);
        if (strlen(b) >= RAB_BINDING_STR_MAX) {
            json_decref(root);
            *errcode = "schema_invalid";
            return -1;
        }
        /* copy the binding out; it is validated further by the broker loop */
        size_t bl = strlen(b);
        memcpy(req->binding, b, bl);
        req->binding[bl] = '\0';
        req->type = RAB_REQ_WRITE_OUTCOME;
    } else if (strcmp(type, "emit") == 0) {
        /* a single non-effect record: only preview/noop, effect_issued false,
         * no binding, opens no intent. Deliberately NOT a generic append. */
        static const char *const allowed[] = {"type", "phase", "record"};
        json_t *jphase = json_object_get(root, "phase");
        if (!only_keys(root, allowed, 3) || !json_is_string(jphase) ||
            !json_is_object(record) || !record_valid(record)) {
            json_decref(root);
            *errcode = "schema_invalid";
            return -1;
        }
        const char *ph = json_string_value(jphase);
        if ((strcmp(ph, "preview") != 0 && strcmp(ph, "noop") != 0) ||
            strlen(ph) >= sizeof req->phase) {
            json_decref(root);
            *errcode = "schema_invalid";
            return -1;
        }
        json_t *ei = json_object_get(record, "effect_issued");
        if (ei != NULL && json_is_true(ei)) { /* non-effect path only */
            json_decref(root);
            *errcode = "schema_invalid";
            return -1;
        }
        size_t pl = strlen(ph);
        memcpy(req->phase, ph, pl);
        req->phase[pl] = '\0';
        req->type = RAB_REQ_EMIT;
    } else if (strcmp(type, "capabilities") == 0) {
        /* discovery only: read-only, no record, no binding, opens no intent. */
        static const char *const allowed[] = {"type"};
        if (!only_keys(root, allowed, 1)) {
            json_decref(root);
            *errcode = "schema_invalid";
            return -1;
        }
        req->type = RAB_REQ_CAPABILITIES;
    } else {
        json_decref(root);
        *errcode = "unknown_request";
        return -1;
    }

    req->root = root;
    req->record = record;
    *errcode = NULL;
    return 0;
}

void rab_request_free(rab_request *req) {
    if (req != NULL && req->root != NULL) {
        json_decref(req->root);
        req->root = NULL;
        req->record = NULL;
    }
}

static char *dump_compact(json_t *obj) {
    char *s = json_dumps(obj, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(obj);
    return s;
}

char *rab_response_open_ok(const char *correlation_id, const char *binding,
                           const char *audit_scope) {
    json_t *o = json_object();
    if (o == NULL) {
        return NULL;
    }
    json_object_set_new(o, "ok", json_true());
    json_object_set_new(o, "correlation_id", json_string(correlation_id));
    json_object_set_new(o, "binding", json_string(binding));
    json_object_set_new(o, "persisted", json_true());
    json_object_set_new(o, "audit_scope", json_string(audit_scope));
    return dump_compact(o);
}

char *rab_response_outcome_ok(void) {
    json_t *o = json_object();
    if (o == NULL) {
        return NULL;
    }
    json_object_set_new(o, "ok", json_true());
    json_object_set_new(o, "persisted", json_true());
    return dump_compact(o);
}

char *rab_response_emit_ok(const char *correlation_id, const char *audit_scope) {
    json_t *o = json_object();
    if (o == NULL) {
        return NULL;
    }
    json_object_set_new(o, "ok", json_true());
    json_object_set_new(o, "correlation_id", json_string(correlation_id));
    json_object_set_new(o, "persisted", json_true());
    json_object_set_new(o, "audit_scope", json_string(audit_scope));
    return dump_compact(o);
}

char *rab_response_capabilities(void) {
    json_t *o = json_object();
    json_t *ext = json_object();
    json_t *schemas = json_array();
    if (o == NULL || ext == NULL || schemas == NULL) {
        json_decref(o);
        json_decref(ext);
        json_decref(schemas);
        return NULL;
    }
    json_object_set_new(o, "ok", json_true());
    json_object_set_new(o, "frame_version", json_integer(RAB_PROTO_VERSION));
    json_object_set_new(o, "record_schema_version",
                        json_integer(RAB_RECORD_SCHEMA_VERSION));
    /* effect_receipt is advertised (and plan_schemas populated) only once the
     * broker actually honours redemption; until then the map is empty so a
     * client never assumes a capability the broker cannot back. */
    json_object_set_new(o, "extensions", ext);
    json_object_set_new(o, "plan_schemas", schemas);
    return dump_compact(o);
}

char *rab_response_error(const char *code, const char *message) {
    json_t *o = json_object();
    if (o == NULL) {
        return NULL;
    }
    json_object_set_new(o, "ok", json_false());
    json_object_set_new(o, "error", json_string(code));
    json_object_set_new(o, "message", json_string(message));
    return dump_compact(o);
}
