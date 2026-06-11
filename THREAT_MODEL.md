# zttp Threat Model

This document describes the security model of zttp: what it defends against, what
it deliberately leaves to the integrator, and the residual risks. It reflects two
security audits (a code-level review and a CVE-driven review that worked backward
from real HTTP-parser CVEs across Node, Go, Python, Rust, and C servers).

zttp is an HTTP/1.1 **parser and serializer**, not a server. It does no I/O. That
shapes everything below: zttp owns the *protocol*, the integrator owns the *I/O,
the connection lifecycle, and the policy*.

## Scope

In scope:

- HTTP/1.1 request and response message framing (request/status line, headers,
  Content-Length and chunked bodies, trailers).
- The read side (`receive_data` / `next_event`) and the write side
  (`send_*` / `data_to_send`).

Out of scope (by design - see [Integrator responsibilities](#integrator-responsibilities)):

- Sockets, TLS, timeouts, and connection concurrency.
- HTTP/2 and HTTP/3 (roadmap).
- WebSocket / `Upgrade` / `CONNECT` tunnel semantics.
- URL, query-string, cookie, multipart, and form parsing.
- Authentication, authorization, and application logic.

## Trust boundary

```
   untrusted network bytes
            │
            ▼
   conn.receive_data(data)      ← THE trust boundary: every byte here is hostile
            │
   ┌────────────────────┐
   │  zttp parser core  │       pure Zig, no I/O, no syscalls
   └────────────────────┘
            │
   conn.next_event()  ──►  Request / Data / EndOfMessage   (trusted, validated)
```

The **adversary is the peer** whose bytes reach `receive_data()`. zttp assumes:

- The bytes are fully attacker-controlled and may be malformed, fragmented
  arbitrarily, or crafted to desynchronize a downstream parser.
- The **calling application is trusted.** Arguments to the write side
  (`send_request` / `send_response` / `send_data`) come from the application, not
  the network. (zttp still validates them defensively - see below - but the
  threat model does not treat the local caller as an attacker.)

The security goal: **no attacker-controlled byte stream can cause memory unsafety,
crash the host process, desynchronize message framing, or force unbounded
resource use** - within zttp's scope.

## What zttp defends against

Each item below is enforced in the parser core and covered by tests. Citations
are to `src/core/`.

### Request smuggling (the primary threat)

- **Content-Length + Transfer-Encoding together** → rejected outright
  (`framing.zig`), rather than the weaker "Transfer-Encoding wins, strip CL".
- **Conflicting duplicate Content-Length** → rejected; identical duplicates are
  accepted (RFC-permitted, unambiguous).
- **Transfer-Encoding folding** → all `Transfer-Encoding` field-lines are combined
  into one ordered list; `chunked` must appear exactly once and be the final
  coding. `chunked, gzip`, `chunked` twice, or split across lines → rejected.
- **Obfuscated `chunked`** → whole-token, case-insensitive match; `xchunked`,
  `chunked\x0b`, etc. do not match.
- **Bare LF / bare CR line endings** → rejected by default (`strict_crlf`); CR is
  excluded from every character-class table, so it can never delimit or hide in a
  line, header, target, or chunk frame. This is the Node CVE-2023-30589 class.
- **obs-fold (line folding)** and **whitespace before the colon** → rejected.
- **Lenient Content-Length** (`+5`, `0x10`, embedded spaces, overflow) → rejected;
  parsing is digits-only with checked arithmetic.
- **Version confusion** → only `HTTP/1.x` is accepted; `HTTP/0.9` / `HTTP/2.0`
  request/status lines are rejected.

### Memory safety and crashes

- Written in Zig and shipped in the safety-checked `ReleaseSafe` build, so a
  reachable bounds/overflow error traps cleanly instead of becoming undefined
  behavior.
- The SWAR newline scanner reads 8-byte words only under an `i + 8 <= len` guard.
- Integer handling uses `u64` throughout with a 16-hex-digit cap on chunk sizes
  (before the shift) and checked `mul`/`add` on Content-Length - no overflow.
- Parsing is iterative; there is no input-driven recursion, so no stack
  exhaustion.
- Event payloads handed to Python are copied into owned `bytes` objects, so no
  slice into the parser's buffer can dangle.

### Resource exhaustion (DoS)

Bounded by `Limits` (per-connection), all enforced before unbounded growth:

| Limit | Default | Bounds |
| --- | --- | --- |
| `max_line` | 16 KiB | any single request/status/header/chunk-size line |
| `max_headers` | 100 | header count |
| `max_header_bytes` | 64 KiB | total header block (checked on partial *and* complete heads) |
| `max_trailers` | 100 | chunked trailer count |
| `max_trailer_bytes` | 64 KiB | chunked trailer bytes |
| `max_buffer` | 8 MiB | total unconsumed buffered bytes (checked in `feed`) |

There is no Content-Length-driven pre-allocation, and buffer compaction is
amortized O(n). A peer cannot force an allocation larger than `max_buffer`.

### Terminal errors (anti-desync)

A parse error **poisons the connection permanently**: every subsequent
`next_event()` re-raises it, and `start_next_cycle()` cannot revive a failed
connection. A desynchronized byte stream can never be re-parsed as if it
were valid.

### Outbound injection (response splitting)

The serializer validates every component it emits - method, target, version,
reason phrase, and each header/trailer name and value - rejecting CR, LF, NUL, and
other control bytes. It also refuses to serialize ambiguous framing
(Transfer-Encoding + Content-Length, or conflicting/duplicate Content-Length), so
a re-serialized message cannot be turned into two.

## Integrator responsibilities

zttp is sans-IO, so the embedding server/framework **must** handle these. Getting
them wrong can reintroduce a smuggling or DoS class that the core sidesteps.

1. **Timeouts.** zttp has no timers. The host must impose header-receipt and
   idle timeouts; otherwise a slowloris-style peer ties up a connection
   (memory stays bounded by `max_buffer`, but the connection does not close).
2. **Connection concurrency / request caps.** The host must cap concurrent
   connections and may cap requests-per-connection.
3. **Bodyless responses (client role).** Responses to `HEAD` and all
   `1xx` / `204` / `304` have no body regardless of headers. The connection
   handles this automatically: it remembers the method from `send_request` and
   auto-frames the matching response as bodyless. The integrator's only
   responsibility is to send the request through the **same** `Connection` so the
   method is known; parsing a response on a connection that never saw the request
   will desynchronize a keep-alive stream.
4. **`Upgrade` / `CONNECT` / `101`.** zttp has no tunnel awareness. After a
   protocol switch the integrator must stop feeding bytes to zttp as HTTP/1.1,
   must not call `start_next_cycle()` on a tunneled connection, and must strip
   hop-by-hop `Connection`/`Upgrade` headers itself. **This is the highest-risk
   integration point and must be designed before any upgrade feature is added.**
5. **HTTP/1.0 policy.** zttp's framing is version-agnostic. RFC rules such as
   "an HTTP/1.0 message must not use chunked" and the 1.0-vs-1.1 keep-alive
   defaults belong in a version-aware connection layer the integrator provides.
6. **Discard poisoned connections.** When `next_event()` raises
   `RemoteProtocolError`, the connection is terminally failed; the host should
   send an error response (if appropriate) and close it.
7. **Know the `Limits`.** The defaults (above) are conservative and are not
   configurable from the Python API today; the host's own caps (timeouts,
   concurrency) are the tunable defense.

## Residual risks

These are not defects in the current parser; they are the places where the
*system* can still go wrong:

- **Misuse of the integration contract** (items 3-5 above) - parsing a response
  on a connection that never sent the request, or a mishandled `CONNECT`, can
  desynchronize a stream that the core itself parses correctly.
- **Lenient mode.** The Zig core has `strict_crlf` / chunk-strictness toggles that
  default to strict and are **not** exposed through the Python API. If a future
  binding ever exposes them, the bare-LF/CR smuggling classes re-open. Keep
  leniency non-configurable from Python, or document the risk loudly.
- **Future features.** Adding body/form/multipart parsing, or `Upgrade`/`CONNECT`
  support, brings new CVE classes (e.g. decompression bombs, tunnel desync) into
  scope; they must be designed with the same strict-reject discipline.

## Reporting a vulnerability

Open a security advisory at <https://github.com/Kludex/zttp/security/advisories>
or contact the maintainer privately. Please do not file public issues for
suspected vulnerabilities.
