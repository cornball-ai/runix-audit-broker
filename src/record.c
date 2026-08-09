#include "record.h"

#include <string.h>

/* Copy a NUL-terminated string into a fixed buffer; -1 if it would not fit. */
static int copy_bounded(char *dst, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (n >= cap) {
        return -1;
    }
    memcpy(dst, src, n + 1);
    return 0;
}

static json_t *actor_object(const rab_actor *a) {
    json_t *o = json_object();
    if (o == NULL) {
        return NULL;
    }
    /* json_object_set_new steals the ref and tolerates a NULL value by
     * failing; check the aggregate at the end via a sentinel. */
    if (json_object_set_new(o, "uid", json_integer((json_int_t) a->uid)) != 0 ||
        json_object_set_new(o, "gid", json_integer((json_int_t) a->gid)) != 0 ||
        json_object_set_new(o, "pid", json_integer((json_int_t) a->pid)) != 0 ||
        json_object_set_new(o, "boot_id", json_string(a->boot_id)) != 0 ||
        json_object_set_new(o, "starttime", json_string(a->starttime)) != 0) {
        json_decref(o);
        return NULL;
    }
    return o;
}

char *rab_build_record(const char *phase, const char *correlation_id,
                       const char *binding, const rab_actor *actor,
                       const char *host, unsigned long long time_us,
                       json_t *client_record) {
    json_t *root = json_object();
    if (root == NULL) {
        return NULL;
    }
    json_t *actor_o = actor_object(actor);
    int bad = 0;
    bad |= (actor_o == NULL);
    bad |= json_object_set_new(root, "actor", actor_o);
    bad |= json_object_set_new(root, "correlation_id",
                               json_string(correlation_id));
    bad |= json_object_set_new(root, "phase", json_string(phase));
    bad |= json_object_set_new(root, "time",
                               json_integer((json_int_t) time_us));
    bad |= json_object_set_new(root, "host", json_string(host));
    if (binding != NULL) {
        bad |= json_object_set_new(root, "binding", json_string(binding));
    }
    if (bad) {
        json_decref(root);
        return NULL;
    }
    /* merge client domain content (schema-validated; no broker-owned keys) */
    const char *k;
    json_t *v;
    json_object_foreach(client_record, k, v) {
        if (json_object_set(root, k, v) != 0) {
            json_decref(root);
            return NULL;
        }
    }
    char *s = json_dumps(root, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(root);
    return s;
}

static int load_actor(json_t *root, rab_actor *actor) {
    json_t *a = json_object_get(root, "actor");
    if (!json_is_object(a)) {
        return -1;
    }
    json_t *uid = json_object_get(a, "uid");
    json_t *gid = json_object_get(a, "gid");
    json_t *pid = json_object_get(a, "pid");
    json_t *boot = json_object_get(a, "boot_id");
    json_t *start = json_object_get(a, "starttime");
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
    json_t *phase = json_object_get(root, "phase");
    json_t *cid = json_object_get(root, "correlation_id");
    json_t *time = json_object_get(root, "time");
    if (!json_is_string(phase) || !json_is_string(cid) ||
        !json_is_integer(time)) {
        goto done;
    }
    if (copy_bounded(out->phase, sizeof out->phase,
                     json_string_value(phase)) != 0 ||
        copy_bounded(out->correlation_id, sizeof out->correlation_id,
                     json_string_value(cid)) != 0) {
        goto done;
    }
    out->time_us = (unsigned long long) json_integer_value(time);
    json_t *binding = json_object_get(root, "binding");
    if (binding != NULL) {
        if (!json_is_string(binding) ||
            copy_bounded(out->binding, sizeof out->binding,
                         json_string_value(binding)) != 0) {
            goto done;
        }
    }
    if (load_actor(root, &out->actor) != 0) {
        goto done;
    }
    rc = 0;
done:
    json_decref(root);
    return rc;
}
