# HTTP/2 design

This is the internal design note for zttp's HTTP/2 layer. It records the decisions
that the implementation follows so the *why* lives next to the code, not only in a
reviewer's head. It is repo-only (not shipped in the wheel/sdist).

## Goal

HTTP/2 support that reuses the **same public event model** as HTTP/1.1. A consumer
keeps the h11-style pull API:

```python
conn = zttp.Connection(zttp.SERVER, protocol=zttp.HTTP2)
conn.receive_data(frames)
while (event := conn.next_event()) is not zttp.NEED_DATA:
    ...  # Request / Data / EndOfMessage, plus H2 control events, each with .stream_id
```

## The central tension and its resolution

One HTTP/2 connection multiplexes many concurrent streams, but `next_event()` is a
single, flat pull. The resolution:

- **Single, frame-arrival-ordered pull queue.** Every event self-describes its
  stream via a `stream_id` field. The caller demuxes by reading `event.stream_id`.
- **Wire order is forced anyway.** HPACK's dynamic table is connection-global and
  order-dependent, so frames *must* be processed in wire order. There is no freedom
  to reorder by stream, so a single arrival-ordered queue is the only correct shape.
- **One frame fans out into a bounded ring.** `nextEvent()` drains a fixed
  `pending: [PENDING_CAP]Event` ring before decoding the next frame. A HEADERS frame
  with END_STREAM produces `{Request, EndOfMessage}` = 2 events; the max fan-out is
  small and comptime-asserted. No heap FIFO, no hot-path allocation - mirrors
  `reader.zig`'s existing single-slot `eom_pending` idiom.

This keeps the h11-shaped contract the Python adapter and uvicorn integration assume.

## Event model changes (additive, H1-safe)

`events.zig`:

- Add `stream_id: u32 = 0` to `Request`/`Response`/`Data`/`EndOfMessage`. The `= 0`
  default is the entire back-compat mechanism: every H1 construction site omits it
  and is unchanged; H1 never surfaces it.
- Add five control variants produced **only** by the H2 engine: `rst_stream`,
  `goaway`, `settings`, `ping`, `window_update`.
- Pseudo-headers collapse in `connection.zig` before the event is pushed:
  `:method`->method, `:path`->target, `:status`->status_code, `http_version`="2",
  `reason`="" (empty), `:authority`-> synthesized lowercase `host` header. So the
  Python `Request`/`Response` objects are byte-identical to H1 except `stream_id`.

Python adapter: `stream_id` is a read-only member, **excluded from repr and
richcompare**, so every existing H1 repr/equality test passes byte-for-byte. A
`protocol=` selector on `Connection` picks the engine; the H1 path is untouched.

## Module map (`src/core/h2/`)

| Module | LOC | Responsibility |
| --- | --- | --- |
| `constants.zig` | ~120 | Frame codes, flags, SETTINGS ids/defaults/ranges, error codes, `CLIENT_PREFACE`, per-type length rules. Pure leaf. |
| `frame.zig` | ~200 | Zero-copy frame codec: parse the 9-octet header (R-masked 31-bit id), payload sub-slice, de-pad, per-type length checks; reject `Length > advertised max_frame_size` before buffering. Also the serializer. |
| `hpack/static_table.zig` | ~90 | The 61-entry RFC 7541 static table as comptime literals. |
| `hpack/huffman.zig` | ~200 | Comptime canonical Huffman decode FSM into a bounded buffer; rejects bad padding / embedded EOS. |
| `hpack/decoder.zig` | ~360 | Stateful HPACK decoder; dynamic table in a decoder-owned arena; resolve-before-evict; oversized-entry-empties-table; `max_header_list_size` enforced incrementally. |
| `hpack/encoder.zig` | ~150 | Stateless encoder (static-table match + literal-without-indexing). No dynamic table - no compression oracle. |
| `stream.zig` | ~240 | Pure per-stream state machine + flow-control accounting; `(state, frame) -> Transition{action, code}` classifying stream vs connection error with the exact error code. |
| `settings.zig` | ~130 | Parse/validate a SETTINGS payload; per-id range checks; INITIAL_WINDOW_SIZE delta applies to per-stream windows only. |
| `connection.zig` | ~650 | Orchestrator (H2 analogue of `reader.zig`): input buffer, preface/SETTINGS phase machine, HPACK decoder, stream map, connection windows, bounded pending ring, single open-field-block marker, two-tier poison. |
| `writer.zig` | ~420 | Write side: frame serialization, flow-control-aware DATA scheduling, handshake/control emission. |
| `root.zig` | ~45 | Aggregator; wired into `src/core/root.zig` so `zig build test`/`fuzz` cover H2. |

## Load-bearing invariants

These are the rules that are easy to regress silently. Each has a dedicated test.

1. **HPACK out_store lifetime.** `out_store` is cleared at the **start** of
   `decodeBlock`, never the end. Combined with "one field-block decode per
   `nextEvent`, drain the pending ring before decoding the next frame", a pushed-but-
   not-yet-drained `Request`'s header slices stay valid until the next decode begins
   (by which point the borrower was drained). This is the single most important
   correctness fix.
2. **Always decode the full field block, validate after.** Even a stream that will be
   reset (malformed pseudo-headers, forbidden headers) must have its HPACK block fully
   decoded first, so the connection-global dynamic table stays in sync. Resetting mid-
   decode desyncs the table and turns every later stream into a COMPRESSION_ERROR.
3. **Single open field block.** The "a field block is open" marker (`fb_stream`) is a
   single connection-level slot, not per-stream. Only one block may be open across the
   whole connection (RFC 9113 4.3 contiguity). This also makes CONTINUATION-flood
   fanout structurally impossible.
4. **Flow-control overflow checked in i64.** Windows store as `i32` (negative legal on
   send); the overflow check against `2^31-1` computes the intermediate sum in `i64`
   before narrowing.
5. **DATA stays zero-copy.** `fromEvent()` materializes every event into Python bytes
   synchronously inside `next_event()`, before control returns to Python and before any
   further frame is decoded - so a `Data` slice into the fed buffer is safe. A future
   pure-Zig consumer pulling two events before copying would see the first clobbered;
   this lifetime contract is documented.

## DoS defenses

- **CONTINUATION flood** (CVE-2024-27316): `max_field_block_bytes` (64KB) and
  `max_continuation_frames` (16) enforced *during* accumulation; the single
  connection-level open-block marker makes cross-stream fanout impossible.
- **HPACK bomb**: `max_header_list_size` on decoded size, enforced incrementally;
  integer-octet cap; dynamic table capped at the locally advertised size.
- **Rapid Reset** (CVE-2023-44487): reset/complete counters + a hard
  `max_reset_streams` threshold -> `ENHANCE_YOUR_CALM`, protecting even a naive loop.
- **Settings/empty-frame flood** (CVE-2019-9512/9515/9518): per-feed zero-progress
  frame budget; we advertise `MAX_FRAME_SIZE=16384` and reject `Length >` that before
  buffering; 8MB `max_buffer` cap as in H1.
- **Padding underflow**: `pad_len < remaining` validated before the data subslice;
  full frame length (incl. padding) charged to the window.
- **Stream-state smuggling**: monotonic `highest_peer_id`; wrong-parity id rejected;
  bounded live-stream map; content-length-vs-DATA-sum validated at END_STREAM.

## Error model

- **Stream error** -> `RST_STREAM` event, connection survives (recoverable).
- **Connection error** -> `GOAWAY` + terminal `.failed` poison, re-raises forever
  (same two-tier discipline as H1's `.failed`).
- HPACK `COMPRESSION_ERROR` is always connection-fatal (the table is global).

## Build order

Each step is independently testable; pure leaves are fuzzed in isolation.

0. Test harness: an H2 drain helper that pulls until `NEED_DATA` *without* stopping at
   the first `EndOfMessage` (the H1 `drain()` is wrong for multiplexed streams).
1. `constants.zig` + `frame.zig` (parse/serialize/de-pad) + frame fuzz target.
2. `hpack/static_table.zig` + `hpack/huffman.zig` (RFC 7541 Appendix C vectors).
3. `hpack/decoder.zig` (Appendix C.2-C.6 incl. eviction; out_store lifetime test).
4. `stream.zig` + `settings.zig` (full transition matrix; window math).
5. `connection.zig` handshake + DATA path (defer HEADERS).
6. `connection.zig` HEADERS + CONTINUATION -> Request + EndOfMessage (the key step).
7. Remaining control frames; rapid-reset cap; trailers; content-length validation.
8. `writer.zig` + `encoder.zig`; round-trip writer -> a second connection's `feed`.
9. `events.zig` `stream_id` + control variants; wire `h2/root.zig`; `driveH2` fuzz;
   confirm all H1 Zig tests pass unchanged.
10. Python adapter; a real h2-prior-knowledge exchange through the public API; confirm
    every existing H1 test is byte-for-byte unchanged.

## Scope

Server role first (most uvicorn use); client role lands in steps 8/10. Server push is
out of scope: we advertise `ENABLE_PUSH=0` and treat an incoming `PUSH_PROMISE` as a
connection error.
