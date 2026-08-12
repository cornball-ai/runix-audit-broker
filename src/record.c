#include "record.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Copy a NUL-terminated string into a fixed buffer; -1 if it would not fit. */
static int copy_bounded(char *dst, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (n >= cap) {
        return -1;
    }
    memcpy(dst, src, n + 1);
    return 0;
}

/* A 64-char lowercase-hex string (SHA-256 verifier or plan digest). NULL fails. */
static int is_hex64_lc(const char *s) {
    if (s == NULL) {
        return 0;
    }
    for (size_t i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    return s[64] == '\0';
}

/* time_us -> "YYYY-MM-DDTHH:MM:SSZ" (RFC 3339 UTC, seconds precision, matching
 * the R sink's canonical `time`). Returns 0 on success, -1 on failure. */
static int format_rfc3339(unsigned long long time_us, char *buf, size_t cap) {
    time_t secs = (time_t) (time_us / 1000000ull);
    struct tm tmv;
    if (gmtime_r(&secs, &tmv) == NULL) {
        return -1;
    }
    if (strftime(buf, cap, "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0) {
        return -1;
    }
    return 0;
}

/* The versioned `broker` extension object. `binding` and the checkpoint
 * metadata (operation/resource/scope) are included only when non-NULL. */
static json_t *broker_object(const rab_actor *a, const char *binding,
                             unsigned long long time_us, const char *operation,
                             const char *resource, const char *scope) {
    json_t *b = json_object();
    json_t *peer = json_object();
    if (b == NULL || peer == NULL) {
        json_decref(b);
        json_decref(peer);
        return NULL;
    }
    char ats[24];
    snprintf(ats, sizeof ats, "%llu", time_us);
    int bad = 0;
    bad |= json_object_set_new(b, "schema_version", json_integer(1));
    bad |= json_object_set_new(peer, "uid", json_integer((json_int_t) a->uid));
    bad |= json_object_set_new(peer, "gid", json_integer((json_int_t) a->gid));
    bad |= json_object_set_new(peer, "pid", json_integer((json_int_t) a->pid));
    bad |= json_object_set_new(peer, "boot_id", json_string(a->boot_id));
    bad |= json_object_set_new(peer, "starttime", json_string(a->starttime));
    bad |= json_object_set_new(b, "peer", peer); /* steals peer */
    if (binding != NULL) {
        bad |= json_object_set_new(b, "binding", json_string(binding));
    }
    bad |= json_object_set_new(b, "accepted_time_us", json_string(ats));
    if (operation != NULL) {
        bad |= json_object_set_new(b, "operation", json_string(operation));
    }
    if (resource != NULL) {
        bad |= json_object_set_new(b, "resource", json_string(resource));
    }
    if (scope != NULL) {
        bad |= json_object_set_new(b, "scope", json_string(scope));
    }
    if (bad) {
        json_decref(b);
        return NULL;
    }
    return b;
}

char *rab_build_audit(const char *phase, const char *correlation_id,
                      const char *binding, const rab_actor *actor,
                      const char *host, unsigned long long time_us,
                      json_t *client_record) {
    char ts[32];
    char actor_s[32];
    if (format_rfc3339(time_us, ts, sizeof ts) != 0) {
        return NULL;
    }
    snprintf(actor_s, sizeof actor_s, "uid:%ld", (long) actor->uid);

    json_t *root = json_object();
    if (root == NULL) {
        return NULL;
    }
    int bad = 0;
    /* canonical framing, insertion order */
    bad |= json_object_set_new(root, "schema_version",
                               json_integer(RAB_RECORD_SCHEMA_VERSION));
    bad |= json_object_set_new(root, "record_type", json_string("audit"));
    bad |= json_object_set_new(root, "correlation_id",
                               json_string(correlation_id));
    bad |= json_object_set_new(root, "phase", json_string(phase));
    bad |= json_object_set_new(root, "host", json_string(host));
    bad |= json_object_set_new(root, "pid", json_integer((json_int_t) actor->pid));
    bad |= json_object_set_new(root, "actor", json_string(actor_s));
    if (bad) {
        json_decref(root);
        return NULL;
    }
    /* domain content (schema-validated; no broker-owned keys), in its order */
    const char *k;
    json_t *v;
    json_object_foreach(client_record, k, v) {
        if (json_object_set(root, k, v) != 0) {
            json_decref(root);
            return NULL;
        }
    }
    /* canonical time last, then the trailing broker extension */
    json_t *brk = broker_object(actor, binding, time_us, NULL, NULL, NULL);
    if (brk == NULL || json_object_set_new(root, "time", json_string(ts)) != 0 ||
        json_object_set_new(root, "broker", brk) != 0) {
        json_decref(brk);
        json_decref(root);
        return NULL;
    }
    char *s = json_dumps(root, JSON_COMPACT); /* insertion order, not sorted */
    json_decref(root);
    return s;
}

char *rab_build_checkpoint(const char *correlation_id, const char *binding,
                           const rab_actor *actor, unsigned long long time_us,
                           const char *operation, const char *resource,
                           const char *scope) {
    json_t *root = json_object();
    if (root == NULL) {
        return NULL;
    }
    json_t *brk = broker_object(actor, binding, time_us,
                                operation ? operation : "",
                                resource ? resource : "", scope ? scope : "");
    int bad = 0;
    bad |= json_object_set_new(root, "schema_version",
                               json_integer(RAB_RECORD_SCHEMA_VERSION));
    bad |= json_object_set_new(root, "record_type",
                               json_string("broker_checkpoint"));
    bad |= json_object_set_new(root, "correlation_id",
                               json_string(correlation_id));
    bad |= (brk == NULL);
    if (!bad) {
        bad |= json_object_set_new(root, "broker", brk); /* steals brk */
    } else {
        json_decref(brk);
    }
    if (bad) {
        json_decref(root);
        return NULL;
    }
    char *s = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    return s;
}

char *rab_build_rate(uid_t uid, const unsigned long long *times,
                     const unsigned long long *bytes, size_t n) {
    json_t *root = json_object();
    json_t *tarr = json_array();
    json_t *barr = json_array();
    if (root == NULL || tarr == NULL || barr == NULL) {
        json_decref(root);
        json_decref(tarr);
        json_decref(barr);
        return NULL;
    }
    int bad = 0;
    for (size_t i = 0; i < n; i++) {
        char buf[24];
        snprintf(buf, sizeof buf, "%llu", times[i]);
        bad |= json_array_append_new(tarr, json_string(buf));
        snprintf(buf, sizeof buf, "%llu", bytes[i]);
        bad |= json_array_append_new(barr, json_string(buf));
    }
    /* insertion order: schema_version, record_type, uid, times_us, bytes */
    bad |= json_object_set_new(root, "schema_version",
                               json_integer(RAB_RECORD_SCHEMA_VERSION));
    bad |= json_object_set_new(root, "record_type", json_string("broker_rate"));
    bad |= json_object_set_new(root, "uid", json_integer((json_int_t) uid));
    if (!bad) {
        bad |= json_object_set_new(root, "times_us", tarr); /* steals tarr */
        bad |= json_object_set_new(root, "bytes", barr);    /* steals barr */
    } else {
        json_decref(tarr);
        json_decref(barr);
    }
    if (bad) {
        json_decref(root);
        return NULL;
    }
    char *s = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    return s;
}

char *rab_build_receipt(const char *correlation_id, rab_rcpt_state state,
                        int checkpoint, const char *verifier_hex, uid_t actor_uid,
                        const char *verb, const char *resource,
                        long long plan_schema, const char *plan_hash,
                        unsigned long long issue_boottime_us,
                        unsigned long long ttl_us, const char *boot_id) {
    /* Fail closed on any input the strict parser would later reject, and never
     * silently coerce an unknown state to "issued": the builder is as strict as
     * rab_parse_stored, so a bad receipt is never written in the first place. */
    if (correlation_id == NULL || correlation_id[0] == '\0' ||
        strlen(correlation_id) >= RAB_CID_MAX ||
        (state != RAB_RCPT_ISSUED && state != RAB_RCPT_REDEEMED) ||
        !is_hex64_lc(verifier_hex) || !is_hex64_lc(plan_hash) ||
        verb == NULL || verb[0] == '\0' || strlen(verb) >= RAB_META_MAX ||
        resource == NULL || strlen(resource) >= RAB_META_MAX ||
        plan_schema < 1 || boot_id == NULL || boot_id[0] == '\0' ||
        strlen(boot_id) >= RAB_BOOT_ID_MAX) {
        return NULL;
    }
    json_t *root = json_object();
    if (root == NULL) {
        return NULL;
    }
    char ibt[24];
    char ttl[24];
    snprintf(ibt, sizeof ibt, "%llu", issue_boottime_us);
    snprintf(ttl, sizeof ttl, "%llu", ttl_us);
    int bad = 0;
    bad |= json_object_set_new(root, "schema_version",
                               json_integer(RAB_RECORD_SCHEMA_VERSION));
    bad |= json_object_set_new(root, "record_type",
                               json_string("broker_receipt"));
    bad |= json_object_set_new(root, "state_schema_version",
                               json_integer(RAB_BROKER_STATE_SCHEMA_VERSION));
    bad |= json_object_set_new(root, "correlation_id",
                               json_string(correlation_id));
    bad |= json_object_set_new(root, "checkpoint",
                               checkpoint ? json_true() : json_false());
    bad |= json_object_set_new(
        root, "state",
        json_string(state == RAB_RCPT_REDEEMED ? "redeemed" : "issued"));
    bad |= json_object_set_new(root, "verifier", json_string(verifier_hex));
    bad |= json_object_set_new(root, "actor_uid",
                               json_integer((json_int_t) actor_uid));
    bad |= json_object_set_new(root, "verb", json_string(verb));
    bad |= json_object_set_new(root, "resource", json_string(resource));
    bad |= json_object_set_new(root, "plan_schema",
                               json_integer((json_int_t) plan_schema));
    bad |= json_object_set_new(root, "plan_hash", json_string(plan_hash));
    bad |= json_object_set_new(root, "issue_boottime_us", json_string(ibt));
    bad |= json_object_set_new(root, "ttl_us", json_string(ttl));
    bad |= json_object_set_new(root, "boot_id", json_string(boot_id));
    if (bad) {
        json_decref(root);
        return NULL;
    }
    char *s = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    return s;
}

void rab_stored_free(rab_stored *out) {
    if (out == NULL) {
        return;
    }
    free(out->rate_times);
    free(out->rate_bytes);
    out->rate_times = NULL;
    out->rate_bytes = NULL;
    out->rate_n = 0;
}

/* ---- parse-back for reconstruction ------------------------------------- */

/* Reject an object with any key outside the allowed set (exact validation). */
static int obj_only_keys(json_t *obj, const char *const *allowed, size_t n) {
    const char *k;
    json_t *v;
    json_object_foreach(obj, k, v) {
        int ok = 0;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(k, allowed[i]) == 0) {
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

/* Strict unsigned-decimal parse: non-empty, all digits (no sign/space/trailing),
 * no overflow. A malformed value fails rather than silently becoming zero. */
static int parse_u64_strict(const char *s, unsigned long long *out) {
    if (s == NULL || s[0] < '0' || s[0] > '9') {
        return -1; /* empty, sign, or leading space */
    }
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno == ERANGE || end == s || *end != '\0') {
        return -1; /* overflow, no digits, or trailing characters */
    }
    *out = v;
    return 0;
}

/* Validate and load the broker.peer object exactly. */
static int load_peer_strict(json_t *broker, rab_actor *actor) {
    json_t *peer = json_object_get(broker, "peer");
    if (!json_is_object(peer)) {
        return -1;
    }
    static const char *const pk[] = {"uid", "gid", "pid", "boot_id",
                                     "starttime"};
    if (!obj_only_keys(peer, pk, 5)) {
        return -1;
    }
    json_t *uid = json_object_get(peer, "uid");
    json_t *gid = json_object_get(peer, "gid");
    json_t *pid = json_object_get(peer, "pid");
    json_t *boot = json_object_get(peer, "boot_id");
    json_t *start = json_object_get(peer, "starttime");
    if (!json_is_integer(uid) || !json_is_integer(gid) ||
        !json_is_integer(pid) || !json_is_string(boot) ||
        !json_is_string(start)) {
        return -1;
    }
    json_int_t u = json_integer_value(uid);
    json_int_t g = json_integer_value(gid);
    json_int_t p = json_integer_value(pid);
    if (u < 0 || g < 0 || p <= 0) { /* uid/gid non-negative, pid positive */
        return -1;
    }
    actor->uid = (uid_t) u;
    actor->gid = (gid_t) g;
    actor->pid = (pid_t) p;
    const char *bs = json_string_value(boot);
    const char *ss = json_string_value(start);
    if (bs[0] == '\0' || ss[0] == '\0' ||
        copy_bounded(actor->boot_id, sizeof actor->boot_id, bs) != 0 ||
        copy_bounded(actor->starttime, sizeof actor->starttime, ss) != 0) {
        return -1;
    }
    for (const char *c = ss; *c != '\0'; c++) { /* starttime is proc ticks */
        if (*c < '0' || *c > '9') {
            return -1;
        }
    }
    return 0;
}

/* copy an optional string field; absent/null -> "" (still 0). */
static int load_opt_str(json_t *obj, const char *key, char *dst, size_t cap) {
    json_t *v = json_object_get(obj, key);
    if (v == NULL || json_is_null(v)) {
        dst[0] = '\0';
        return 0;
    }
    if (!json_is_string(v)) {
        return -1;
    }
    return copy_bounded(dst, cap, json_string_value(v));
}

/* Strict parse for the broker's authoritative recovery path: an unknown
 * record_type or schema_version, a malformed known record, an out-of-shape
 * broker extension, a misplaced binding, or a pid/actor inconsistent with
 * broker.peer all fail closed (return -1). A generic audit reader may be more
 * lenient; the broker, which restores authority-bound intent state, is not. */
int rab_parse_stored(const char *line, size_t len, rab_stored *out) {
    memset(out, 0, sizeof *out);
    json_error_t jerr;
    json_t *root = json_loadb(line, len, JSON_REJECT_DUPLICATES, &jerr);
    if (root == NULL) {
        return -1;
    }
    int rc = -1;
    if (!json_is_object(root)) {
        goto done;
    }
    /* top-level schema_version must be exactly 1 (unknown version fails) */
    json_t *sv = json_object_get(root, "schema_version");
    if (!json_is_integer(sv) ||
        json_integer_value(sv) != RAB_RECORD_SCHEMA_VERSION) {
        goto done;
    }
    /* record_type must be a known value: no silent "audit" fall-through */
    json_t *rtype = json_object_get(root, "record_type");
    if (!json_is_string(rtype)) {
        goto done;
    }
    const char *rts = json_string_value(rtype);
    if (strcmp(rts, "audit") == 0) {
        out->type = RAB_REC_AUDIT;
    } else if (strcmp(rts, "broker_checkpoint") == 0) {
        out->type = RAB_REC_CHECKPOINT;
    } else if (strcmp(rts, "broker_rate") == 0) {
        /* broker-internal per-uid rate carry: a fixed, self-contained shape
         * with no correlation id and no broker extension. Validated exactly and
         * handled here in full (it is not an open/close event). Carries the
         * window timestamps and the appended byte size of each op, one-to-one. */
        static const char *const rk[] = {"schema_version", "record_type", "uid",
                                         "times_us", "bytes"};
        if (!obj_only_keys(root, rk, 5)) {
            goto done;
        }
        json_t *juid = json_object_get(root, "uid");
        if (!json_is_integer(juid) || json_integer_value(juid) < 0) {
            goto done;
        }
        json_t *tarr = json_object_get(root, "times_us");
        json_t *barr = json_object_get(root, "bytes");
        if (!json_is_array(tarr) || !json_is_array(barr)) {
            goto done;
        }
        size_t n = json_array_size(tarr);
        if (json_array_size(barr) != n) {
            goto done; /* times and bytes must correspond one-to-one */
        }
        unsigned long long *times = NULL;
        unsigned long long *bytes = NULL;
        if (n > 0) {
            times = malloc(n * sizeof *times);
            bytes = malloc(n * sizeof *bytes);
            if (times == NULL || bytes == NULL) {
                free(times);
                free(bytes);
                goto done;
            }
            for (size_t i = 0; i < n; i++) {
                json_t *te = json_array_get(tarr, i);
                json_t *be = json_array_get(barr, i);
                if (!json_is_string(te) ||
                    parse_u64_strict(json_string_value(te), &times[i]) != 0 ||
                    !json_is_string(be) ||
                    parse_u64_strict(json_string_value(be), &bytes[i]) != 0) {
                    free(times);
                    free(bytes);
                    goto done;
                }
            }
        }
        out->type = RAB_REC_RATE;
        out->rate_uid = (uid_t) json_integer_value(juid);
        out->rate_times = times;
        out->rate_bytes = bytes;
        out->rate_n = n;
        rc = 0;
        goto done;
    } else if (strcmp(rts, "broker_receipt") == 0) {
        /* durable effect-receipt state: a self-contained flat record with its
         * own state schema version, no broker.peer extension, and no phase. It
         * carries only the SHA-256 verifier, never the token. Validated exactly
         * and in full here; any missing/extra/malformed field fails closed. */
        static const char *const rk[] = {
            "schema_version",   "record_type",  "state_schema_version",
            "correlation_id",   "checkpoint",   "state",
            "verifier",         "actor_uid",    "verb",
            "resource",         "plan_schema",  "plan_hash",
            "issue_boottime_us", "ttl_us",      "boot_id"};
        if (!obj_only_keys(root, rk, 15)) {
            goto done;
        }
        json_t *ssv = json_object_get(root, "state_schema_version");
        if (!json_is_integer(ssv) ||
            json_integer_value(ssv) != RAB_BROKER_STATE_SCHEMA_VERSION) {
            goto done;
        }
        json_t *jcid = json_object_get(root, "correlation_id");
        if (!json_is_string(jcid) || json_string_value(jcid)[0] == '\0' ||
            copy_bounded(out->correlation_id, sizeof out->correlation_id,
                         json_string_value(jcid)) != 0) {
            goto done;
        }
        json_t *jckpt = json_object_get(root, "checkpoint");
        if (!json_is_boolean(jckpt)) {
            goto done;
        }
        out->rcpt_is_checkpoint = json_is_true(jckpt) ? 1 : 0;
        json_t *jstate = json_object_get(root, "state");
        if (!json_is_string(jstate)) {
            goto done;
        }
        const char *st = json_string_value(jstate);
        if (strcmp(st, "issued") == 0) {
            out->rcpt_state = RAB_RCPT_ISSUED;
        } else if (strcmp(st, "redeemed") == 0) {
            out->rcpt_state = RAB_RCPT_REDEEMED;
        } else {
            goto done;
        }
        json_t *jver = json_object_get(root, "verifier");
        if (!json_is_string(jver) || !is_hex64_lc(json_string_value(jver)) ||
            copy_bounded(out->rcpt_verifier, sizeof out->rcpt_verifier,
                         json_string_value(jver)) != 0) {
            goto done;
        }
        json_t *jauid = json_object_get(root, "actor_uid");
        if (!json_is_integer(jauid)) {
            goto done;
        }
        json_int_t auid = json_integer_value(jauid);
        /* reject anything outside uid_t rather than truncating a 64-bit value */
        if (auid < 0 || (json_int_t) (uid_t) auid != auid) {
            goto done;
        }
        out->rcpt_actor_uid = (uid_t) auid;
        json_t *jverb = json_object_get(root, "verb");
        if (!json_is_string(jverb) || json_string_value(jverb)[0] == '\0' ||
            copy_bounded(out->rcpt_verb, sizeof out->rcpt_verb,
                         json_string_value(jverb)) != 0) {
            goto done;
        }
        json_t *jres = json_object_get(root, "resource");
        if (!json_is_string(jres) || /* resource may be empty, but is a string */
            copy_bounded(out->rcpt_resource, sizeof out->rcpt_resource,
                         json_string_value(jres)) != 0) {
            goto done;
        }
        json_t *jps = json_object_get(root, "plan_schema");
        if (!json_is_integer(jps) || json_integer_value(jps) < 1) {
            goto done;
        }
        out->rcpt_plan_schema = (long long) json_integer_value(jps);
        json_t *jph = json_object_get(root, "plan_hash");
        if (!json_is_string(jph) || !is_hex64_lc(json_string_value(jph)) ||
            copy_bounded(out->rcpt_plan_hash, sizeof out->rcpt_plan_hash,
                         json_string_value(jph)) != 0) {
            goto done;
        }
        json_t *jibt = json_object_get(root, "issue_boottime_us");
        if (!json_is_string(jibt) ||
            parse_u64_strict(json_string_value(jibt),
                             &out->rcpt_issue_boottime_us) != 0) {
            goto done;
        }
        json_t *jttl = json_object_get(root, "ttl_us");
        if (!json_is_string(jttl) ||
            parse_u64_strict(json_string_value(jttl), &out->rcpt_ttl_us) != 0) {
            goto done;
        }
        json_t *jboot = json_object_get(root, "boot_id");
        if (!json_is_string(jboot) || json_string_value(jboot)[0] == '\0' ||
            copy_bounded(out->rcpt_boot_id, sizeof out->rcpt_boot_id,
                         json_string_value(jboot)) != 0) {
            goto done;
        }
        out->type = RAB_REC_RECEIPT;
        rc = 0;
        goto done;
    } else {
        goto done; /* unknown record_type: fail closed */
    }

    json_t *cid = json_object_get(root, "correlation_id");
    if (!json_is_string(cid) || json_string_value(cid)[0] == '\0' ||
        copy_bounded(out->correlation_id, sizeof out->correlation_id,
                     json_string_value(cid)) != 0) {
        goto done;
    }

    /* broker extension: versioned, peer validated, strict accepted_time_us */
    json_t *broker = json_object_get(root, "broker");
    if (!json_is_object(broker)) {
        goto done;
    }
    json_t *bsv = json_object_get(broker, "schema_version");
    if (!json_is_integer(bsv) || json_integer_value(bsv) != 1) {
        goto done;
    }
    if (load_peer_strict(broker, &out->actor) != 0) {
        goto done;
    }
    json_t *ats = json_object_get(broker, "accepted_time_us");
    if (!json_is_string(ats) ||
        parse_u64_strict(json_string_value(ats), &out->time_us) != 0) {
        goto done;
    }
    json_t *bind = json_object_get(broker, "binding");
    int has_binding = (bind != NULL);
    if (has_binding) {
        if (!json_is_string(bind) || json_string_value(bind)[0] == '\0' ||
            copy_bounded(out->binding, sizeof out->binding,
                         json_string_value(bind)) != 0) {
            goto done;
        }
    }

    if (out->type == RAB_REC_AUDIT) {
        /* exact broker keys for an audit record (no checkpoint metadata) */
        static const char *const bk[] = {"schema_version", "peer",
                                         "accepted_time_us", "binding"};
        if (!obj_only_keys(broker, bk, 4)) {
            goto done;
        }
        json_t *phase = json_object_get(root, "phase");
        if (!json_is_string(phase) || json_string_value(phase)[0] == '\0' ||
            copy_bounded(out->phase, sizeof out->phase,
                         json_string_value(phase)) != 0) {
            goto done;
        }
        /* binding present iff this is an intent */
        int is_intent = strcmp(out->phase, RAB_PHASE_INTENT) == 0;
        if (is_intent != has_binding) {
            goto done;
        }
        /* top-level pid and actor must agree with broker.peer */
        json_t *pid = json_object_get(root, "pid");
        if (!json_is_integer(pid) ||
            (pid_t) json_integer_value(pid) != out->actor.pid) {
            goto done;
        }
        char want[32];
        snprintf(want, sizeof want, "uid:%ld", (long) out->actor.uid);
        json_t *actor = json_object_get(root, "actor");
        if (!json_is_string(actor) ||
            strcmp(json_string_value(actor), want) != 0) {
            goto done;
        }
        /* open-intent metadata lives in the domain fields (top level) */
        if (load_opt_str(root, "operation", out->operation,
                         sizeof out->operation) != 0 ||
            load_opt_str(root, "resource", out->resource,
                         sizeof out->resource) != 0 ||
            load_opt_str(root, "scope", out->scope, sizeof out->scope) != 0) {
            goto done;
        }
    } else {
        /* checkpoint: fixed top-level shape and full broker key set; a
         * checkpoint always carries a binding. */
        static const char *const tk[] = {"schema_version", "record_type",
                                         "correlation_id", "broker"};
        static const char *const bk[] = {"schema_version",   "peer",
                                         "accepted_time_us", "binding",
                                         "operation",        "resource",
                                         "scope"};
        if (!obj_only_keys(root, tk, 4) || !obj_only_keys(broker, bk, 7) ||
            !has_binding) {
            goto done;
        }
        if (load_opt_str(broker, "operation", out->operation,
                         sizeof out->operation) != 0 ||
            load_opt_str(broker, "resource", out->resource,
                         sizeof out->resource) != 0 ||
            load_opt_str(broker, "scope", out->scope, sizeof out->scope) != 0) {
            goto done;
        }
    }
    rc = 0;
done:
    json_decref(root);
    return rc;
}
