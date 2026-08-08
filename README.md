# runix-audit-broker

A small, privileged, single-purpose audit broker for the [Runix](https://github.com/cornball-ai/runix)
durable-audit system. It lets an **unprivileged** system-scope mutation obtain
a **system-durable** audit record by appending the caller's validated record to
the root-owned system sink on its behalf, over a local `AF_UNIX` socket.

It exists because the durable-audit authority matrix
([`durable-audit-contract.md`](https://github.com/cornball-ai/runix/blob/master/docs/durable-audit-contract.md))
requires a system-durable path that an unprivileged caller cannot provide
itself, and that path must be a dedicated component — **not** a privileged R
process and **not** the apt mutation helper. The full design and wire protocol
are pinned in
[`audit-broker-contract.md`](https://github.com/cornball-ai/runix/blob/master/docs/audit-broker-contract.md).

## What it is (and is not)

- **Is:** a native (C) daemon that validates and *appends audit records*, and
  nothing else. Socket-activated, sandboxed, no resident privilege when idle.
- **Is not:** an R process running as root (that would violate Runix's own
  "no privileged R" principle), a general command channel, or anything with
  authority to perform a mutation. It never runs `systemctl`, `apt`, or any
  effect.

## Security posture

This is root-privileged code, so the design is deliberately minimal and
paranoid:

- actor identity from `SO_PEERCRED`, never from the payload;
- exactly two request types (`open_intent`, `write_outcome`);
- versioned, length-prefixed frames with a hard maximum;
- strict UTF-8 JSON parsed by system **Jansson** (an audited, apt-serviced
  library with native duplicate-key rejection via `JSON_REJECT_DUPLICATES`)
  with strict EOF, UTF-8 validation, bounded depth, and explicit schema and
  integer-range checks — no hand-written parser;
- the broker owns a fixed sink path; a client can never choose where root
  writes;
- descriptor-based `O_APPEND | O_NOFOLLOW | O_CLOEXEC`, advisory locking,
  complete-write loops, `fdatasync`, and parent-directory fsync;
- built with Debian hardening flags; ASan/UBSan and protocol fuzzing in CI.

## Layout

- `src/` — the C source (framing, sink, peer credentials, JSON, main).
- `systemd/` — `runix-audit.socket` and `runix-audit.service` (sandboxed).
- `debian/` — Debian packaging (`runix-audit-broker`).
- `PROTOCOL.md` — the pinned wire protocol.
- `Makefile` — build with hardening flags; sanitizer and fuzz targets.

## Install (target)

Packaged as the Debian package `runix-audit-broker`; the binary installs to
`/usr/libexec/runix/audit-broker`, activated by `runix-audit.socket`.

## Status

Early. The wire protocol is pinned; implementation is in progress on feature
branches, with the client adapter, protocol/abuse tests, and the live
unprivileged gate as separate review steps before Runix advertises
`system_durable_audit = TRUE`.
