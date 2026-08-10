/* Hardened append-only sink writer. Descriptor-based, symlink-refusing,
 * lock + complete-write + fdatasync, with a parent-directory fsync when the
 * sink file is created. */
#ifndef RAB_SINK_H
#define RAB_SINK_H

#include <stddef.h>

/* Open (creating if absent, mode 0640) the sink at `path` for append, using
 * O_APPEND | O_NOFOLLOW | O_CLOEXEC. Refuses a symlink (ELOOP) and a
 * world-writable file. On create, fsyncs the parent directory so the new
 * entry is durable. Returns an fd (>= 0) or -1 (errno set). */
int rab_sink_open(const char *path);

/* Append one record as a single line (a trailing '\n' is added). Takes an
 * exclusive advisory lock, writes completely, fdatasyncs, then unlocks.
 * `record` must contain no newline. Returns 0 on success, -1 on failure. */
int rab_sink_append(int fd, const char *record, size_t len);

/* fsync the directory containing `path` so a create/rename/unlink in it is
 * durable. Returns 0 on success, -1 on failure. Used by rotation. */
int rab_fsync_parent_dir(const char *path);

#endif /* RAB_SINK_H */
