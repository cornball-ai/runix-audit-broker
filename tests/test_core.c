/* Unit tests for the json-c-independent core: framing, hardened sink, and
 * peer credentials. Built with ASan/UBSan (see Makefile `make test`). */
#include "../src/id.h"
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

static void test_boot_id(void) {
    char a[RAB_BOOT_ID_MAX];
    char b[RAB_BOOT_ID_MAX];
    CHECK(rab_boot_id(a, sizeof a) == 0, "boot_id read");
    CHECK(strlen(a) > 0 && strlen(a) < RAB_BOOT_ID_MAX, "boot_id nonempty");
    CHECK(strchr(a, '\n') == NULL, "boot_id newline stripped");
    CHECK(rab_boot_id(b, sizeof b) == 0, "boot_id read again");
    CHECK(strcmp(a, b) == 0, "boot_id stable within a boot");
    char tiny[8];
    CHECK(rab_boot_id(tiny, sizeof tiny) == -1, "boot_id fails on tiny buf");
}

static void test_proc_starttime(void) {
    char a[RAB_STARTTIME_MAX];
    char b[RAB_STARTTIME_MAX];
    CHECK(rab_proc_starttime(getpid(), a, sizeof a) == 0, "starttime self");
    CHECK(strlen(a) > 0, "starttime nonempty");
    int all_digit = 1;
    for (size_t i = 0; i < strlen(a); i++) {
        if (a[i] < '0' || a[i] > '9') {
            all_digit = 0;
        }
    }
    CHECK(all_digit, "starttime is all digits");
    CHECK(rab_proc_starttime(getpid(), b, sizeof b) == 0, "starttime again");
    CHECK(strcmp(a, b) == 0, "starttime stable for a live pid");
    /* PID 1 exists on any running system; its start time is readable. */
    char one[RAB_STARTTIME_MAX];
    CHECK(rab_proc_starttime(1, one, sizeof one) == 0, "starttime pid 1");
    /* An almost-certainly-absent pid fails closed. */
    char gone[RAB_STARTTIME_MAX];
    CHECK(rab_proc_starttime(0x7ffffff0, gone, sizeof gone) == -1,
          "starttime absent pid fails");
    char tiny[4];
    CHECK(rab_proc_starttime(getpid(), tiny, sizeof tiny) == -1,
          "starttime fails on tiny buf");
}

static void test_peer_identity(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    rab_actor a;
    CHECK(rab_peer_identity(sv[0], &a) == 0, "peer_identity ok");
    CHECK(a.uid == getuid(), "identity uid matches caller");
    CHECK(a.pid == getpid(), "identity pid matches caller");
    CHECK(strlen(a.boot_id) > 0, "identity has boot_id");
    CHECK(strlen(a.starttime) > 0, "identity has starttime");

    /* self-equality and a mutated copy inequality */
    rab_actor b = a;
    CHECK(rab_actor_eq(&a, &b), "actor equals itself");
    b.pid = a.pid + 1;
    CHECK(!rab_actor_eq(&a, &b), "different pid is a different actor");
    b = a;
    b.starttime[0] = (b.starttime[0] == '9') ? '8' : '9';
    CHECK(!rab_actor_eq(&a, &b),
          "same pid different starttime is a different actor");
    b = a;
    b.boot_id[0] = (b.boot_id[0] == 'a') ? 'b' : 'a';
    CHECK(!rab_actor_eq(&a, &b),
          "different boot id is a different actor");
    close(sv[0]);
    close(sv[1]);
}

static void test_ids(void) {
    char a[RAB_CID_MAX];
    char b[RAB_CID_MAX];
    CHECK(rab_make_correlation_id(a, sizeof a) == 0, "correlation id a");
    CHECK(rab_make_correlation_id(b, sizeof b) == 0, "correlation id b");
    CHECK(strcmp(a, b) != 0, "correlation ids differ (random suffix)");
    CHECK(strchr(a, '-') != NULL, "correlation id has separator");
    CHECK(a[0] >= '0' && a[0] <= '9', "correlation id is time-prefixed");

    char ba[RAB_BINDING_MAX];
    char bb[RAB_BINDING_MAX];
    CHECK(rab_make_binding(ba, sizeof ba) == 0, "binding a");
    CHECK(rab_make_binding(bb, sizeof bb) == 0, "binding b");
    CHECK(strcmp(ba, bb) != 0, "bindings differ (unguessable)");
    CHECK(strlen(ba) == 32, "binding is 32 hex chars");
    int all_hex = 1;
    for (size_t i = 0; i < 32; i++) {
        char c = ba[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            all_hex = 0;
        }
    }
    CHECK(all_hex, "binding is lowercase hex");

    char tiny[4];
    CHECK(rab_make_binding(tiny, sizeof tiny) == -1, "binding fails on tiny buf");

    char ra[RAB_RECEIPT_MAX];
    char rb[RAB_RECEIPT_MAX];
    CHECK(rab_make_receipt(ra, sizeof ra) == 0, "receipt a");
    CHECK(rab_make_receipt(rb, sizeof rb) == 0, "receipt b");
    CHECK(strcmp(ra, rb) != 0, "receipts differ (unguessable)");
    CHECK(strlen(ra) == 32, "receipt is 32 hex chars (128-bit)");
    int rhex = 1;
    for (size_t i = 0; i < 32; i++) {
        char c = ra[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            rhex = 0;
        }
    }
    CHECK(rhex, "receipt is lowercase hex");
    CHECK(rab_make_receipt(tiny, sizeof tiny) == -1, "receipt fails on tiny buf");
}

int main(void) {
    test_frame_roundtrip();
    test_frame_too_large();
    test_frame_bad_version();
    test_sink_append();
    test_sink_refuses_symlink();
    test_sink_refuses_world_writable();
    test_peer_cred();
    test_boot_id();
    test_proc_starttime();
    test_peer_identity();
    test_ids();
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
