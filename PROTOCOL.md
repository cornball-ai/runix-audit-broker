# runix-audit-broker wire protocol (v1)

The concrete framing and message shapes the broker and its clients speak over
the local `AF_UNIX` stream socket. Pinned in
[`audit-broker-contract.md`](https://github.com/cornball-ai/runix/blob/master/docs/audit-broker-contract.md);
this file is the byte-level spec the C implements.

## Framing

Every message is one frame:

```
+---------+------------------+------------------------+
| version | length (uint32)  | body (JSON, UTF-8)     |
| 1 byte  | big-endian       | `length` bytes         |
+---------+------------------+------------------------+
```

- `version` MUST be `1`. Any other value: the broker replies with a
  `bad_frame` error (if it can) and closes the connection.
- `length` is the body size in bytes, big-endian. It MUST be `<= 65536`
  (64 KiB). A larger value is a `too_large` error and the connection closes.
- `body` is exactly `length` bytes of UTF-8 JSON (one object). Reads use a
  complete-read loop; a short/interrupted read is retried, EOF mid-frame is a
  `bad_frame`.

One request frame yields exactly one response frame (same framing).

## Requests (client -> broker)

Exactly two `type`s. Any other is `unknown_request`.

```jsonc
// open an intent (before the effect is issued)
{ "type": "open_intent",
  "record": { /* durable-audit domain content: operation, resource, ... */ } }

// write the outcome (after the effect), bound to the intent's receipt
{ "type": "write_outcome",
  "binding": "<opaque token from the open_intent response>",
  "record": { /* domain content: outcome, effect_issued, observed, ... */ } }
```

- The `record` is validated against the durable-audit schema: required fields
  present, correct types, integers in range, **no** unexpected fields, no
  trailing content after the JSON object, bounded nesting depth.
- Any `actor`/identity field in `record` is **ignored**: the broker stamps the
  actor from `SO_PEERCRED` (uid/gid/pid) over anything the payload claims.
- The broker mints `correlation_id`, `schema_version`, `host`, `pid`, `time`,
  and the `phase` (`intent`/`outcome`); a client cannot set them.

## Responses (broker -> client)

```jsonc
// open_intent success
{ "ok": true, "correlation_id": "<minted>", "binding": "<opaque>",
  "persisted": true, "audit_scope": "system" }

// write_outcome success
{ "ok": true, "persisted": true }

// any error (typed, closed set)
{ "ok": false, "error": "<code>", "message": "<human detail>" }
```

Error codes (closed set; deterministic per input):

| code | meaning |
|---|---|
| `bad_frame` | version wrong, or a truncated/interrupted frame |
| `too_large` | body length exceeds the maximum |
| `bad_json` | body is not valid UTF-8 JSON, or has trailing content |
| `unknown_request` | `type` is not `open_intent`/`write_outcome` |
| `schema_invalid` | record fails schema/type/range/extra-field checks |
| `unknown_intent` | `binding` matches no open intent |
| `actor_mismatch` | `binding` belongs to a different `SO_PEERCRED` actor |
| `rate_limited` | per-actor rate/quota exceeded |
| `persist_failed` | the durable append or fsync failed |
| `internal` | unexpected broker fault |

## The receipt binding

`binding` is an opaque, broker-issued token. It authorizes **nothing**: it
cannot cause a mutation, cannot write to a different intent, and is
meaningless to the client beyond echoing it back on `write_outcome`. The
broker uses it only to match an outcome to its intent and to confirm the same
`SO_PEERCRED` actor. It is **single-use**: a second `write_outcome` for the
same intent is rejected (`unknown_intent`), so a replayed receipt cannot
produce a duplicate or misattributed outcome.

## Durability and disconnect

- `open_intent` appends the intent and `fdatasync`s (and fsyncs the parent
  directory on create/rotation) **before** replying `persisted: true`. Once
  that reply is sent, the intent is durable regardless of the connection.
- A disconnect between `open_intent` and `write_outcome` leaves the intent as
  a durable, queryable **open** operation. It is never rolled back or erased.

## Identity and paths

- The actor is `SO_PEERCRED` (`uid`, `gid`, `pid`), kernel-verified, and is
  the only identity the record carries.
- The sink path is fixed in the broker's configuration. It is **never** a
  protocol input; a client cannot tell the broker where to write. A test-path
  override is process configuration (CLI/env), not a message field.
