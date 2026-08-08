/* Unit tests for the json-c-independent core: framing, hardened sink, and
 * peer credentials. Built with ASan/UBSan (see Makefile `make test`). */
#include "../src/peer.h"
#include "../src/proto.h"
#include "../src/sink.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                    \
        checks++;                                                           \
        if (!(cond)) {                                                      \
            failures++;                                                     \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        }                                                                  \
    } while (0)

static void test_frame_roundtrip(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    const char *body = "{\"type\":\"open_intent\"}";
    CHECK(rab_write_frame(sv[0], body, (uint32_t) strlen(body)) == 0,
          "write_frame");
    char *out = NULL;
    uint32_t len = 0;
    rab_frame_status s = rab_read_frame(sv[1], &out, &len);
    CHECK(s == RAB_FRAME_OK, "roundtrip status ok");
    CHECK(len == strlen(body), "roundtrip len");
    CHECK(out != NULL && strcmp(out, body) == 0, "roundtrip body");
    free(out);
    close(sv[0]);
    close(sv[1]);
}

static void test_frame_too_large(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    /* header claiming a body of 131072 bytes (> 64 KiB max) */
    unsigned char header[5] = {1, 0x00, 0x02, 0x00, 0x00};
    CHECK(write(sv[0], header, sizeof header) == (ssize_t) sizeof header,
          "write oversize header");
    char *out = NULL;
    uint32_t len = 0;
    rab_frame_status s = rab_read_frame(sv[1], &out, &len);
    CHECK(s == RAB_FRAME_TOO_LARGE, "oversize rejected");
    CHECK(out == NULL, "oversize no body allocated");
    close(sv[0]);
    close(sv[1]);
}

static void test_frame_bad_version(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    unsigned char header[5] = {2, 0, 0, 0, 0}; /* version 2 */
    CHECK(write(sv[0], header, sizeof header) == (ssize_t) sizeof header,
          "write bad-version header");
    char *out = NULL;
    uint32_t len = 0;
    rab_frame_status s = rab_read_frame(sv[1], &out, &len);
    CHECK(s == RAB_FRAME_BAD, "bad version rejected");
    close(sv[0]);
    close(sv[1]);
}

static void test_sink_append(void) {
    char path[] = "/tmp/rab-sink-XXXXXX";
    int tmp = mkstemp(path);
    CHECK(tmp >= 0, "mkstemp");
    close(tmp);
    unlink(path); /* rab_sink_open creates it fresh */

    int fd = rab_sink_open(path);
    CHECK(fd >= 0, "sink_open create");
    CHECK(rab_sink_append(fd, "line1", 5) == 0, "append 1");
    CHECK(rab_sink_append(fd, "line2", 5) == 0, "append 2");
    close(fd);

    FILE *f = fopen(path, "r");
    CHECK(f != NULL, "reopen for read");
    char buf[64] = {0};
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    CHECK(n == 12, "two lines + newlines");
    CHECK(strcmp(buf, "line1\nline2\n") == 0, "line content");

    /* a record with an embedded newline is refused */
    fd = rab_sink_open(path);
    CHECK(fd >= 0, "sink_open existing");
    CHECK(rab_sink_append(fd, "a\nb", 3) == -1, "embedded newline refused");
    close(fd);
    unlink(path);
}

static void test_sink_refuses_symlink(void) {
    char target[] = "/tmp/rab-tgt-XXXXXX";
    int t = mkstemp(target);
    CHECK(t >= 0, "mkstemp target");
    close(t);
    char link[] = "/tmp/rab-lnk-XXXXXX";
    int l = mkstemp(link);
    CHECK(l >= 0, "mkstemp link");
    close(l);
    unlink(link);
    CHECK(symlink(target, link) == 0, "make symlink");

    int fd = rab_sink_open(link);
    CHECK(fd < 0, "symlinked sink refused");
    if (fd >= 0) {
        close(fd);
    }
    unlink(link);
    unlink(target);
}

static void test_sink_refuses_world_writable(void) {
    char path[] = "/tmp/rab-ww-XXXXXX";
    int t = mkstemp(path);
    CHECK(t >= 0, "mkstemp ww");
    close(t);
    CHECK(chmod(path, 0666) == 0, "chmod 0666");

    int fd = rab_sink_open(path);
    CHECK(fd < 0, "world-writable sink refused");
    if (fd >= 0) {
        close(fd);
    }
    unlink(path);
}

static void test_peer_cred(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    uid_t uid = (uid_t) -1;
    gid_t gid = (gid_t) -1;
    pid_t pid = -1;
    CHECK(rab_peer_cred(sv[0], &uid, &gid, &pid) == 0, "peer_cred ok");
    CHECK(uid == getuid(), "peer uid matches caller");
    CHECK(pid == getpid(), "peer pid matches caller");
    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    test_frame_roundtrip();
    test_frame_too_large();
    test_frame_bad_version();
    test_sink_append();
    test_sink_refuses_symlink();
    test_sink_refuses_world_writable();
    test_peer_cred();
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
