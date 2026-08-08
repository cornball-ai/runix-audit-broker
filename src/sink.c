#include "sink.h"
#include "proto.h" /* rab_write_full */

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* fsync the directory containing `path` so a create/rename is durable. */
static int fsync_parent_dir(const char *path) {
    char *copy = strdup(path);
    if (copy == NULL) {
        return -1;
    }
    char *dir = dirname(copy); /* may return a pointer into copy */
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int rc = 0;
    if (dfd < 0) {
        rc = -1;
    } else {
        if (fsync(dfd) != 0) {
            rc = -1;
        }
        close(dfd);
    }
    free(copy);
    return rc;
}

int rab_sink_open(const char *path) {
    int created = 0;
    int fd = open(path,
                  O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW | O_CLOEXEC,
                  0640);
    if (fd >= 0) {
        created = 1;
        /* enforce exact mode regardless of umask */
        if (fchmod(fd, 0640) != 0) {
            close(fd);
            return -1;
        }
    } else if (errno == EEXIST) {
        fd = open(path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            return -1; /* ELOOP here means the sink is a symlink: refuse */
        }
    } else {
        return -1;
    }

    /* refuse a world-writable sink (hijack guard) */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }
    if ((st.st_mode & S_IWOTH) != 0) {
        close(fd);
        errno = EPERM;
        return -1;
    }

    if (created && fsync_parent_dir(path) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int rab_sink_append(int fd, const char *record, size_t len) {
    if (memchr(record, '\n', len) != NULL) {
        errno = EINVAL; /* a record must be a single line */
        return -1;
    }
    if (flock(fd, LOCK_EX) != 0) {
        return -1;
    }
    int rc = 0;
    if (rab_write_full(fd, record, len) != 0) {
        rc = -1;
    } else if (rab_write_full(fd, "\n", 1) != 0) {
        rc = -1;
    } else if (fdatasync(fd) != 0) {
        rc = -1;
    }
    /* release the lock regardless; preserve the operation's errno */
    int saved = errno;
    flock(fd, LOCK_UN);
    errno = saved;
    return rc;
}
