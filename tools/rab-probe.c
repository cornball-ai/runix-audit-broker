/* rab-probe: connect to a running broker's AF_UNIX socket, send one open_intent,
 * print the response frame body, and exit 0 iff the broker replied ok. Used by
 * the CI packaging/activation gate (and handy on the troy-g5 canary) to prove
 * socket activation actually starts the service and writes the sink. */
#include "../src/proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: rab-probe <socket-path>\n");
        return 2;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(argv[1]) >= sizeof addr.sun_path) {
        fprintf(stderr, "socket path too long\n");
        close(fd);
        return 2;
    }
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", argv[1]);
    if (connect(fd, (struct sockaddr *) &addr, sizeof addr) != 0) {
        perror("connect");
        close(fd);
        return 1;
    }
    const char *body = "{\"type\":\"open_intent\",\"record\":"
                       "{\"operation\":\"ci.probe\",\"outcome\":\"intent\"}}";
    if (rab_write_frame(fd, body, (uint32_t) strlen(body)) != 0) {
        fprintf(stderr, "write failed\n");
        close(fd);
        return 1;
    }
    char *rbody = NULL;
    uint32_t rlen = 0;
    rab_frame_status s = rab_read_frame(fd, &rbody, &rlen);
    close(fd);
    if (s != RAB_FRAME_OK || rbody == NULL) {
        fprintf(stderr, "no valid response frame (status %d)\n", (int) s);
        free(rbody);
        return 1;
    }
    printf("%.*s\n", (int) rlen, rbody);
    int ok = (strstr(rbody, "\"ok\":true") != NULL);
    free(rbody);
    return ok ? 0 : 1;
}
