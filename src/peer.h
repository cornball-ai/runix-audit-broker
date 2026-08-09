/* Peer identity from the connected socket, kernel-verified. This is the only
 * identity the broker trusts; payload identity is ignored.
 *
 * The full actor is uid/gid/pid PLUS the host boot id and the peer's process
 * start time. The boot id and start time defeat PID reuse: after the opener
 * exits, a new process that inherits its PID has a different start time, and a
 * PID collision across a reboot has a different boot id. An outcome is bound to
 * the full actor, so a reused PID cannot impersonate the original opener. */
#ifndef RAB_PEER_H
#define RAB_PEER_H

#include <stddef.h>
#include <sys/types.h>

#define RAB_BOOT_ID_MAX 40u   /* UUID (36) + NUL, rounded up */
#define RAB_STARTTIME_MAX 24u /* unsigned long long ticks + NUL */

typedef struct {
    uid_t uid;
    gid_t gid;
    pid_t pid;
    char boot_id[RAB_BOOT_ID_MAX];
    char starttime[RAB_STARTTIME_MAX];
} rab_actor;

/* Fill uid, gid, pid from SO_PEERCRED on the connected stream socket `fd`.
 * Returns 0 on success, -1 on error (errno set). */
int rab_peer_cred(int fd, uid_t *uid, gid_t *gid, pid_t *pid);

/* Write the host boot id (/proc/sys/kernel/random/boot_id, trailing newline
 * stripped) into buf. buf must be >= RAB_BOOT_ID_MAX. 0 on success, -1 on
 * error. The boot id is host-global and identical for the broker and every
 * local peer during one boot. */
int rab_boot_id(char *buf, size_t buflen);

/* Write process `pid`'s start time (field 22 of /proc/<pid>/stat, in clock
 * ticks since boot) into buf as a decimal string. buf must be >=
 * RAB_STARTTIME_MAX. 0 on success, -1 on error (process gone, unreadable, or
 * unparseable). The comm field (parenthesized, may contain spaces/parens) is
 * skipped by scanning to the last ')'. */
int rab_proc_starttime(pid_t pid, char *buf, size_t buflen);

/* Fill the full actor for the peer on `fd`: SO_PEERCRED credentials, the
 * current host boot id, and the peer process start time. Returns 0 on success,
 * -1 on any failure (fails closed; the caller must reject the request). */
int rab_peer_identity(int fd, rab_actor *actor);

/* True iff two actors are the same principal-instance: every field equal. */
int rab_actor_eq(const rab_actor *a, const rab_actor *b);

#endif /* RAB_PEER_H */
