#include "record.h"

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
    bad |= json_object_set_new(root, "schema_version", json_integer(1));
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
    bad |= json_object_set_new(root, "schema_version", json_integer(1));
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

/* ---- parse-back for reconstruction ------------------------------------- */

static int load_peer(json_t *broker, rab_actor *actor) {
    json_t *peer = json_object_get(broker, "peer");
    if (!json_is_object(peer)) {
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
    actor->uid = (uid_t) json_integer_value(uid);
    actor->gid = (gid_t) json_integer_value(gid);
    actor->pid = (pid_t) json_integer_value(pid);
    if (copy_bounded(actor->boot_id, sizeof actor->boot_id,
                     json_string_value(boot)) != 0 ||
        copy_bounded(actor->starttime, sizeof actor->starttime,
                     json_string_value(start)) != 0) {
        return -1;
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
    json_t *rtype = json_object_get(root, "record_type");
    /* missing record_type reads as "audit" for forward/backward compat */
    int is_ckpt = json_is_string(rtype) &&
                  strcmp(json_string_value(rtype), "broker_checkpoint") == 0;
    if (rtype != NULL && !json_is_string(rtype)) {
        goto done;
    }
    out->type = is_ckpt ? RAB_REC_CHECKPOINT : RAB_REC_AUDIT;

    json_t *cid = json_object_get(root, "correlation_id");
    if (!json_is_string(cid) ||
        copy_bounded(out->correlation_id, sizeof out->correlation_id,
                     json_string_value(cid)) != 0) {
        goto done;
    }

    json_t *broker = json_object_get(root, "broker");
    if (!json_is_object(broker) || load_peer(broker, &out->actor) != 0) {
        goto done;
    }
    if (load_opt_str(broker, "binding", out->binding, sizeof out->binding) != 0) {
        goto done;
    }
    json_t *ats = json_object_get(broker, "accepted_time_us");
    if (!json_is_string(ats)) {
        goto done;
    }
    out->time_us = strtoull(json_string_value(ats), NULL, 10);

    if (out->type == RAB_REC_AUDIT) {
        json_t *phase = json_object_get(root, "phase");
        if (!json_is_string(phase) ||
            copy_bounded(out->phase, sizeof out->phase,
                         json_string_value(phase)) != 0) {
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
        /* checkpoint: metadata lives inside the broker extension */
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
