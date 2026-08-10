#include "peer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int rab_peer_cred(int fd, uid_t *uid, gid_t *gid, pid_t *pid) {
    struct ucred cred;
    socklen_t len = sizeof cred;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        return -1;
    }
    *uid = cred.uid;
    *gid = cred.gid;
    *pid = cred.pid;
    return 0;
}

/* Read a small file completely into buf (NUL-terminated). Returns bytes read
 * (>= 0) or -1. Uses a complete-read loop; fails if the file exceeds the
 * buffer (these /proc files are tiny and bounded). */
static ssize_t read_small(const char *path, char *buf, size_t buflen) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    size_t got = 0;
    for (;;) {
        if (got >= buflen - 1) {
            /* would overflow: the file is larger than expected, refuse */
            close(fd);
            return -1;
        }
        ssize_t r = read(fd, buf + got, buflen - 1 - got);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (r == 0) {
            break;
        }
        got += (size_t) r;
    }
    close(fd);
    buf[got] = '\0';
    return (ssize_t) got;
}

int rab_boot_id(char *buf, size_t buflen) {
    if (buflen < RAB_BOOT_ID_MAX) {
        return -1;
    }
    char raw[64];
    ssize_t n = read_small("/proc/sys/kernel/random/boot_id", raw, sizeof raw);
    if (n <= 0) {
        return -1;
    }
    /* strip a trailing newline (and any stray CR) */
    while (n > 0 && (raw[n - 1] == '\n' || raw[n - 1] == '\r')) {
        raw[--n] = '\0';
    }
    if (n == 0 || (size_t) n >= buflen) {
        return -1;
    }
    memcpy(buf, raw, (size_t) n + 1);
    return 0;
}

int rab_proc_starttime(pid_t pid, char *buf, size_t buflen) {
    if (buflen < RAB_STARTTIME_MAX || pid <= 0) {
        return -1;
    }
    char path[64];
    int pn = snprintf(path, sizeof path, "/proc/%d/stat", (int) pid);
    if (pn < 0 || (size_t) pn >= sizeof path) {
        return -1;
    }
    /* /proc/<pid>/stat is a single line; comm can contain spaces and parens,
     * so scan to the LAST ')' and count space-separated fields after it. */
    char raw[512];
    ssize_t n = read_small(path, raw, sizeof raw);
    if (n <= 0) {
        return -1;
    }
    char *rparen = strrchr(raw, ')');
    if (rparen == NULL || *(rparen + 1) == '\0') {
        return -1;
    }
    /* Field 3 (state) is the first token after ')'. starttime is field 22, so
     * it is the 20th token (1-based) after the ')'. */
    const char *p = rparen + 1;
    int field = 2; /* we are positioned just past field 2 (comm) */
    const char *tok = NULL;
    size_t toklen = 0;
    while (*p != '\0') {
        while (*p == ' ') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        field++;
        tok = p;
        while (*p != '\0' && *p != ' ' && *p != '\n') {
            p++;
        }
        toklen = (size_t) (p - tok);
        if (field == 22) {
            break;
        }
    }
    if (field != 22 || tok == NULL || toklen == 0 || toklen >= buflen) {
        return -1;
    }
    /* starttime must be all digits */
    for (size_t i = 0; i < toklen; i++) {
        if (tok[i] < '0' || tok[i] > '9') {
            return -1;
        }
    }
    memcpy(buf, tok, toklen);
    buf[toklen] = '\0';
    return 0;
}

int rab_peer_identity(int fd, rab_actor *actor) {
    memset(actor, 0, sizeof *actor);
    if (rab_peer_cred(fd, &actor->uid, &actor->gid, &actor->pid) != 0) {
        return -1;
    }
    if (rab_boot_id(actor->boot_id, sizeof actor->boot_id) != 0) {
        return -1;
    }
    if (rab_proc_starttime(actor->pid, actor->starttime,
                           sizeof actor->starttime) != 0) {
        return -1;
    }
    return 0;
}

int rab_actor_eq(const rab_actor *a, const rab_actor *b) {
    return a->uid == b->uid && a->gid == b->gid && a->pid == b->pid &&
           strcmp(a->boot_id, b->boot_id) == 0 &&
           strcmp(a->starttime, b->starttime) == 0;
}
