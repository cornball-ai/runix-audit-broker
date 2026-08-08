/* Peer identity from the connected socket, kernel-verified. This is the only
 * identity the broker trusts; payload identity is ignored. */
#ifndef RAB_PEER_H
#define RAB_PEER_H

#include <sys/types.h>

/* Fill uid, gid, pid from SO_PEERCRED on the connected stream socket `fd`.
 * Returns 0 on success, -1 on error (errno set). */
int rab_peer_cred(int fd, uid_t *uid, gid_t *gid, pid_t *pid);

#endif /* RAB_PEER_H */
