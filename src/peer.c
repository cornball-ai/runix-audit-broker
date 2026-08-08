#include "peer.h"

#include <sys/socket.h>

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
