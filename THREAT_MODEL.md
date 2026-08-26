# zttp Threat Model

This document describes the security model of zttp: what it defends against, what
it deliberately leaves to the integrator, and the residual risks. It reflects two
security audits (a code-level review and a CVE-driven review that worked backward
from real HTTP-parser CVEs across Node, Go, Python, Rust, and C servers).

zttp is an HTTP **parser and serializer**, not a server. It does no I/O. That
shapes everything below: zttp owns the *protocol*, the integrator owns the *I/O,
the connection lifecycle, and the policy*.

## Scope

In scope:

- HTTP/1.1 request and response message framing (request/status line, headers,
  Content-Length and chunked bodies, trailers).
- HTTP/2 (RFC 9113): frame codec, HPACK, stream multiplexing and state, flow
  control, and the connection lifecycle, plus h2c upgrade (RFC 7540 3.2).
- HTTP/3 (RFC 9114) over a QUIC transport (RFC 9000/9001/9002): QPACK, request-
  stream framing, the peer control stream and its SETTINGS, and the connection
  lifecycle (GOAWAY, per-stream cancellation), in both roles.
- The read side (`receive_data` / `next_event`) and the write side
  (`send_*` / `data_to_send`).

Out of scope (by design - see [Integrator responsibilities](#integrator-responsibilities)):

- Sockets, TLS *termination* (HTTP/1.1 and HTTP/2 run over the integrator's
  TLS), timeouts, and connection concurrency.
- WebSocket / `Upgrade` (other than h2c) / `CONNECT` tunnel semantics.
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

## What zttp defends against (HTTP/1.1)

Each item below is enforced in the parser core and covered by tests. Citations
are to `src/core/h1/`. The HTTP/2 and HTTP/3 defenses follow in their own
sections; the memory-safety guarantees (Zig `ReleaseSafe`, no input-driven
recursion, owned-copy event payloads) apply across all three.

### Request smuggling (the primary threat)

- **Content-Length + Transfer-Encoding together** → rejected outright
  (`framing.zig`), rather than the weaker "Transfer-Encoding wins, strip CL".
- **Conflicting duplicate Content-Length** → field values must match byte-for-byte.
  The parser accepts identical duplicates, but the writer never emits duplicates.
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
- **Version confusion** → on an HTTP/1.1 request/status line only `HTTP/1.x` is
  accepted; a smuggled `HTTP/0.9` / `HTTP/2.0` version token on the H1 line is
  rejected. (HTTP/2 and HTTP/3 are first-class protocols selected at connection
  construction, not by a version token on a request line - see below.)

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

## HTTP/2 defenses

HTTP/2 (RFC 9113) adds its own attack surface - multiplexing, HPACK compression,
and flow control. The defenses below are enforced in `src/core/h2/` and covered
by tests; the citations are to that tree.

### DoS / resource exhaustion (the H2-specific CVE classes)

| Defense | Limit (default) | Class |
| --- | --- | --- |
| **Rapid-reset** (CVE-2023-44487) → bounded total resets *and* total streams ever opened; exceeding either trips `ENHANCE_YOUR_CALM` → GOAWAY | `max_stream_resets` (256), `max_streams` (4096) | churn flood |
| **CONTINUATION flood** (CVE-2024-27316) → an open field block is bounded by both a frame count and a byte size | `max_continuation_frames` (16), `max_field_block_bytes` (64 KiB) | unbounded field block |
| **HPACK bomb** → the *decoded* header-list size is checked mid-decode, before the full list is materialized | `max_header_list_size` (64 KiB) | decompression amplification |
| **Stream concurrency** → excess concurrent peer streams are refused with `REFUSED_STREAM`, never inserted into the map | `max_concurrent_streams` (128) | per-connection work |
| **Oversized frame** → a frame whose declared length exceeds the advertised size is rejected at parse, before its payload is buffered | `max_frame_size` (16 KiB) | memory spike |
| **Input buffer** → unconsumed bytes are capped (a fatal breach poisons the connection and owes a GOAWAY) | `max_buffer` (8 MiB) | slow-loris memory |

The server advertises these limits in its SETTINGS preface, and **what it
advertises is exactly what it enforces** (`localSettingsParams` builds the
SETTINGS from the same `Limits`), so a conformant peer self-limits rather than
flooding and being mass-refused.

### Request smuggling and h2→h1 downgrade

zttp is frequently a front-end that downgrades HTTP/2 to HTTP/1.1, so it
validates inbound H2 messages against the exact shapes that smuggle across that
boundary (RFC 9113 8):

- **Connection-specific fields** (`connection`, `keep-alive`, `proxy-connection`,
  `transfer-encoding`, `upgrade`) → rejected on the read path (request, response,
  and trailers) and refused by the writer (8.2.2).
- **`TE`** → only the literal `trailers` value is allowed (8.2.2).
- **Field names** → must be lowercase RFC 9110 tokens; uppercase or any non-token
  byte is malformed (8.2.1).
- **Field values** → no CR/LF/NUL/other control or DEL, no leading/trailing
  whitespace (8.2.1). The *write* side is intentionally stricter (it also rejects
  an inner HTAB), so a value the read side accepts can always be re-serialized
  without a peer re-trimming or splitting it.
- **Content-Length vs body** → at end-of-stream a declared `content-length` that
  does not equal the DATA bytes seen resets the stream (`PROTOCOL_ERROR`). The
  check runs on **every** end path - DATA, a bodyless HEADERS frame, and trailers
  - so a request that lies about its body length cannot be downgraded into a
  smuggled HTTP/1.1 message. Legitimately bodyless responses (HEAD / 204 / 304)
  skip it.
- **Duplicate Content-Length** with disagreeing values → rejected (no folding
  into a single ambiguous value).
- **Pseudo-headers** → must precede regular fields, none may be duplicated or
  unknown, `:method`/`:path`/`:scheme` are required, `:path` is non-empty, and
  `:status` is exactly three digits in 100..599 (8.3). A malformed message is a
  *stream* error - the field block is still HPACK-decoded so the
  connection-global dynamic table stays in sync with the peer's encoder.

### Framing, flow control, and protocol state

- A server connection must begin with the exact client preface, and the peer's
  first frame must be SETTINGS (3.4); per-frame-type fixed/minimum lengths are
  enforced, and a PADDED frame whose pad length underflows the payload is
  rejected (no OOB read).
- Stream-state transitions are validated (5.1): frames on idle/closed/half-closed
  streams are rejected; new request stream ids must be odd and strictly
  increasing (5.1.1); the reserved id high bit is masked off.
- Flow-control windows are overflow/underflow checked: a zero or 31-bit-overflow
  WINDOW_UPDATE is rejected, and a peer cannot send more DATA than the advertised
  receive window (6.9).
- On a connection-fatal error the engine arms **exactly one** GOAWAY carrying the
  RFC 9113 7 error code, emitted before the connection closes (5.4.1).
- Frame dispatch is iterative (a run of no-event frames cannot overflow the
  stack), and the frame codec is zero-copy (it never owns or copies payload).

## HTTP/3

HTTP/3 (RFC 9114) over QUIC is the **least mature** of the three protocols - not
because it enforces less, but because it is the newest code with the least
adversarial exposure. The defenses below are enforced in `src/core/h3/` and
covered by tests.

### Field validation

It reuses the shared field validators on **regular** header fields - lowercase
token names, no control bytes in values, connection-specific fields and a
non-`trailers` `TE` rejected, duplicate Content-Length conflict rejected
(`decodeRequest`, `src/core/h3/connection.zig`). It enforces the pseudo-header
structure rules (pseudo before regular, no duplicates, required request
pseudo-headers, CONNECT's `:authority`-only shape) and validates pseudo-header
**values** with the same check as regular values, so an `:authority` carrying
CR/LF cannot be synthesized into a `host` header on an h3→h1 downgrade.

### Control stream and SETTINGS

The peer's unidirectional streams are classified and pumped, and the control
stream is held to RFC 9114 6.2.1:

- A request stream arriving **before** the peer's SETTINGS is rejected; a control
  stream that does not begin with SETTINGS, or sends a second SETTINGS, is a
  connection error.
- A **second** control, QPACK-encoder, or QPACK-decoder stream is a connection
  error, as is closing any of those critical streams.
- HTTP/2-only frame types, control frames on a request stream, DATA before
  HEADERS, and frames not allowed on the control stream are all rejected.
- GOAWAY and MAX_PUSH_ID are validated for malformed/trailing bytes, wrong role,
  and monotonicity (a GOAWAY id that increases, or a MAX_PUSH_ID that decreases,
  is an error); CANCEL_PUSH for an unpromised push is rejected. Server push is
  disabled, so a client-opened push stream is a connection error.

### QPACK and field-section bounds

| Defense | Limit (default) | Class |
| --- | --- | --- |
| Decoded field-section size, checked mid-decode | `MAX_FIELD_SECTION_SIZE` (64 KiB) | QPACK bomb |
| Dynamic table capacity | `QPACK_MAX_TABLE_CAPACITY` (4 KiB) | encoder-driven memory |
| Streams blocked on encoder updates | `QPACK_BLOCKED_STREAMS` (16) | blocked-stream pile-up |

As on the H2 path, **what zttp advertises is exactly what it enforces**: these
three values are sent verbatim in its own SETTINGS, so a conformant peer
self-limits. Exceeding the blocked-stream cap is `QPACK_DECOMPRESSION_FAILED`;
an oversized or malformed field section is rejected before the list is
materialized.

### The transport

The QUIC transport (RFC 9000/9001/9002) - handshake, packet protection,
amplification limits, loss recovery, and flow control - is in scope and held to
the strict-reject bar. HTTP/3 clients pin the exact server certificate or raw
P-256 public key before accepting its TLS flight. The transport's threat surface
is broad and has had far less adversarial exposure than the H1/H2 paths. Treat
HTTP/3 as experimental from a security standpoint.

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

### Additional HTTP/2 responsibilities

The H2 core enforces the stream/frame/HPACK limits above, but a few duties stay
with the host:

8. **Rate-limit control-frame floods.** zttp auto-ACKs every peer SETTINGS and
   PING (in `autoRespond`) with no per-connection budget. A peer that streams
   SETTINGS/PING frames forces an equal stream of ACKs; the host must impose a
   control-frame rate limit (or an overall idle/throughput timeout) so a peer
   cannot pin a connection busy on ACKs.
9. **Send the GOAWAY and close.** On a connection-fatal error zttp *queues* one
   GOAWAY into the writer; the host must call `data_to_send()` to flush it and
   then close the transport. The core cannot close a socket it does not own.
10. **Own the h2→h1 translation contract.** A proxy that downgrades H2 to H1 must
    strip the pseudo-headers, bridge `:authority` → `Host`, and never forward a
    connection-specific field. zttp validates the *inbound* H2 message (above),
    but the *downgraded* H1 message it builds is the proxy's to keep unambiguous.
11. **Trust the h2c upgrade before seeding it.** `initiate_upgrade_connection`
    takes an already-parsed HTTP/1.1 request on faith; the host must have decided
    the `Upgrade: h2c` request is well-formed and authorized before seeding it as
    stream 1.

## Residual risks

These are not defects in the current parser; they are the places where the
*system* can still go wrong:

- **Misuse of the integration contract** (items 3-5 above) - parsing a response
  on a connection that never sent the request, or a mishandled `CONNECT`, can
  desynchronize a stream that the core itself parses correctly.
- **The h2→h1 downgrade boundary (integrator responsibility 10).** zttp's
  inbound validation makes an H2 request *safe to read*, but the H1 request a
  proxy *synthesizes* from it is the proxy's to keep unambiguous. The residual
  hazards live entirely on that outbound path:
  - **`:path` is a request target, not a header value.** zttp rejects CR/LF/NUL
    inside header *values*, but a downgrading proxy that splices `:path` into an
    H1 request line without its own request-target check can still emit a
    smuggled line if it ever relaxes that. Re-validate the target you write.
  - **Body framing is yours to re-declare.** The inbound `content-length`-vs-DATA
    guard guarantees the H2 body length is *honest*; it does not write your H1
    framing. When you build the H1 message, emit exactly one unambiguous framing
    (a single `Content-Length`, or `Transfer-Encoding: chunked`) - never both,
    and never a `content-length` you copied without re-counting the bytes you
    actually forward.
  - **Don't reintroduce hop-by-hop fields.** zttp strips `connection`,
    `transfer-encoding`, `upgrade`, etc. on the way in; do not let your H1
    builder re-add a `Connection`/`Keep-Alive` header derived from anything the
    peer controlled.
  A proxy that forwards the *parsed* `Request` fields verbatim and re-derives its
  own framing is safe; one that string-concatenates peer-controlled bytes into an
  H1 message owns the smuggling risk regardless of zttp's inbound checks.
- **Lenient mode.** The Zig core has `strict_crlf` / chunk-strictness toggles that
  default to strict and are **not** exposed through the Python API. If a future
  binding ever exposes them, the bare-LF/CR smuggling classes re-open. Keep
  leniency non-configurable from Python, or document the risk loudly.
- **Control-frame ACK floods.** zttp auto-ACKs SETTINGS/PING without a budget
  (integrator responsibility 8); a host that imposes no control-frame rate limit
  can be kept busy answering ACKs even though no memory grows.
- **HTTP/3 maturity.** The QUIC + HTTP/3 path is the newest code and has had less
  adversarial exposure than the H1/H2 paths; the transport's threat surface
  (amplification, key/packet handling) is broad. Treat it as the least
  battle-tested protocol.
- **Future features.** Adding body/form/multipart parsing, or WebSocket/`CONNECT`
  tunnel support, brings new CVE classes (e.g. decompression bombs, tunnel
  desync) into scope; they must be designed with the same strict-reject
  discipline.

## Reporting a vulnerability

Open a security advisory at <https://github.com/Kludex/zttp/security/advisories>
or contact the maintainer privately. Please do not file public issues for
suspected vulnerabilities.
