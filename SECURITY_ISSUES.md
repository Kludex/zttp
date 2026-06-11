# Security Audit

zhttp - Zig-core sans-IO HTTP/1.1 + HTTP/2 parser/serializer with a CPython C-API binding
Audit date: 2026-06-09
Branch audited: `main`
Build profile audited: ReleaseSafe (safety checks ON)

## Executive Summary

Overall the codebase is in good shape. The HTTP/1.1 core remains hardened against the request-smuggling, framing-desync, integer-overflow, and DoS classes that the two prior audits addressed - every one of those invariants was re-verified against the current code and still holds. The HTTP/2 protocol state machine is thorough and standards-aware (pseudo-header rules, connection-specific-header rejection, content-length vs DATA reconciliation, trailers, stream-id parity/monotonicity, CONTINUATION-flood capping, flow-control window math), and the Python C-API binding is careful with reference counts, buffer ownership, GC type selection, and error/exception consistency. There is no memory-unsafety finding: no use-after-free, no out-of-bounds, no reachable bounds/overflow trap was found on any attacker-reachable path.

The one genuinely serious problem is a single root cause with two symptoms: the HTTP/2 connection never removes a stream from its `streams` map once that stream is closed. A peer can open-then-RST streams forever, growing per-connection memory toward OOM (high) and inflating every per-frame map scan into O(map-size) work (medium). This is the resource-exhaustion half of the HTTP/2 Rapid Reset class (CVE-2023-44487). It is peer-triggerable from `feed()`/`receive_data()` with ~25-26 wire bytes per leaked entry, and the integrator has no API to evict the stale entries. **This is the top risk and the one finding worth fixing before anything else; the fix - evict closed streams and/or cap total tracked streams - resolves both symptoms at once.**

The second-most-notable issue is the inverse of the threat model on one specific surface: the HTTP/2 server read path does not validate header / pseudo-header *values* for control bytes (CR/LF/NUL), even though the H2 write path and the entire H1 path both reject exactly those bytes. This is an RFC 9113 8.2.1 malformed-field acceptance and an H2->H1 smuggling/splitting footgun for any integrator that re-serializes a surfaced H2 request to HTTP/1.1 (the canonical use of a sans-IO H2 core).

Everything else is low/info: a spec-conformance differential (empty `:path` accepted), two OOM-only robustness gaps in the Python binding, and two fuzzing/CI hygiene gaps (the libFuzzer/OSS-Fuzz target does not compile against current `main`, and the H2 core has no fuzz coverage). None of these are independently exploitable for memory unsafety or a crash.

### What is well-defended (re-verified)

- **HTTP/1.1 smuggling and framing (Part A):** CL+TE rejected, conflicting duplicate CL rejected, TE-chunked enforced exactly-once-and-last, obfuscated chunked tokens not matched, bare LF/CR rejected by default, obs-fold and space-before-colon rejected, lenient/`+5`/`0x10` content-length rejected with checked arithmetic, HTTP version restricted to 1.x, chunk-size 16-hex cap before shift, trailer count/byte caps, `max_buffer` cap in `feed`, SWAR scanner bounds guard, terminal `.failed` poison latch.
- **HTTP/2 protocol state:** pseudo-header presence/uniqueness/ordering, response-vs-request pseudo rejection, `:status` range, connection-specific-header rejection (with uppercase-name catch), `te: trailers`-only exception, content-length reconciliation at END_STREAM, trailer validation, stream-id parity/monotonicity, idle-vs-closed distinction for WINDOW_UPDATE/RST_STREAM, CONTINUATION-flood capping (CVE-2024-27316), flow-control overflow/zero-increment handling.
- **HTTP/2 frame arithmetic (Part B):** `length > max_frame_size` rejected before buffering, `dePad` underflow guard before subslicing, fixed-offset payload reads all guarded by `checkLength`, flow-control `@intCast` narrowing guarded by i64 intermediates, SETTINGS value range validation, HPACK integer/string/Huffman decoding fully bounds-checked with overflow caps and store-compaction safety.
- **HTTP/2 DoS classes other than rapid reset:** PING flood (one event per frame, ring drained per frame, no auto-ACK), SETTINGS flood, WINDOW_UPDATE games, per-frame scratch buffers bounded and reused, refused-stream path does not insert a map entry, pending ring cannot overflow `PENDING_CAP`.
- **HTTP/2 memory lifetime:** data-event slices into `self.buf` are always drained before `compact()`, HPACK `out_store` cleared only at block start with at-most-one block decoded per `nextEvent`, all event payloads copied into owned Python bytes synchronously before any later mutation.
- **Python binding:** borrowed-header UAF site fixed (owned refs held until after writer consumes slices), event-constructor partial-init error paths NULL-safe, `buildHeaders`/`borrowHeaders` refcounting correct, GC type selection and traverse/clear correct, no cycle structurally possible, every `return null` preceded by a set exception, integer/size conversions range-checked before `@intCast`.
- **Build / supply chain:** shipped wheel is ReleaseSafe with no `ReleaseFast` anywhere (worst-case fallback is Debug, never unsafe), strictness/leniency toggles are not reachable from Python, H2 default `Limits` are conservative and not raisable from Python, CI workflows hardened (empty top-level permissions, SHA-pinned actions, `persist-credentials: false`, OIDC publishing, zizmor scan, no workflow-injection), packaging clean (PEP 561, no leaked artifacts), free-threading ABI handled conditionally.

### Top risks (in order)

1. **HTTP/2 stream map is never pruned** - per-connection memory grows to OOM under an open+RST flood, bypassing `max_concurrent_streams` (high).
2. **Quadratic CPU from the same unpruned map** - per-HEADERS `liveStreamCount()` and per-SETTINGS/WINDOW_UPDATE sweeps become O(map-size) (medium; same root cause as #1).
3. **H2 read path accepts CR/LF/NUL in header/pseudo-header values** - RFC 9113 8.2.1 malformed-field acceptance, H2->H1 smuggling/splitting vector for re-serializing integrators (high).

---

## Findings

### 1. HTTP/2 stream map is never pruned: opened-then-RST streams accumulate permanently, an unbounded-memory DoS that bypasses `max_concurrent_streams`

- **Severity:** High
- **CWE:** CWE-400 / CWE-770 (Uncontrolled Resource Consumption / Allocation of Resources Without Limits)
- **Location:** `src/core/h2/connection.zig:431` (insert), `:373-384` (`handleRstStream`, no removal), `:429` + `:778-785` (`liveStreamCount` cap excludes closed streams), `:547-550` (`resetStream`, same), `src/core/h2/stream.zig:71-76` (`countsTowardConcurrency`), `:131` (`recvApply` sets `.closed`)

**Attacker scenario.** After the HTTP/2 preface + SETTINGS handshake, the peer repeats, for `k = 1, 3, 5, ...` up to `2^31-1`: a minimal HEADERS frame opening stream `k` (e.g. the 3-byte fully-indexed HPACK block `82 86 84` = `:method GET` / `:scheme http` / `:path /`, with END_HEADERS, no END_STREAM), immediately followed by a RST_STREAM frame on stream `k`. Each cycle is ~25-26 bytes on the wire:
`00 00 03 01 04 00 00 00 0k <82 86 84>` then `00 00 04 03 00 00 00 00 0k <00 00 00 08>`.

**Impact.** Unbounded per-connection process-memory growth (resource-exhaustion DoS). Each opened-then-RST stream leaves a permanent `Stream` entry (the struct plus its `AutoHashMap` slot, on the order of ~64-100 bytes) in `self.streams`. RST_STREAM moves the stream to `.closed` (`stream.zig:131`), for which `countsTowardConcurrency()` returns false (`stream.zig:71-76`), so `liveStreamCount()` stays at 0 and the `max_concurrent_streams` refusal at `connection.zig:429` never fires. No `Limits` field bounds total map size, and `max_buffer` only caps the unconsumed input buffer (the ~25-byte cycles are consumed and compacted away at `connection.zig:169,813`), so cumulative input - and the map - is unbounded. With ~`2^30` usable odd ids, a few hundred MB of attacker input inflates resident memory into the multi-GB range; the host OOMs (or, in ReleaseSafe, the eventual `put` surfaces `error.MessageTooLong` and poisons the connection) long before id exhaustion. Either way it is a single-connection DoS with attacker-favorable amplification (~25 wire bytes per permanent heap entry). The `EnhanceYourCalm` error code exists (`constants.zig:85`) but is wired only to the CONTINUATION flood (`connection.zig:450`), never to stream/reset churn.

**Evidence.** `handleHeaders` inserts on the under-cap path: `self.streams.put(self.gpa, id, Stream.init(...))` at `connection.zig:431`, then `highest_peer_id = id` at `:434`. `handleRstStream` (`:373-384`) calls `s.recvApply(.rst_stream, false)`, which in `stream.zig:131` sets `self.state = .closed` and returns - the map entry is untouched. `resetStream` (`:547-550`) likewise only flips state. A grep over `connection.zig` for `.remove`/`.swapRemove`/`.fetchRemove`/`removeByPtr` on `self.streams` returns zero hits; the only teardown is `streams.deinit` in `deinit` (`:133`). New request streams require only `id % 2 == 1` and `id > highest_peer_id` (`:424`), both satisfied by the increasing-odd-id pattern. `liveStreamCount` (`:778-785`) counts only open/half-closed streams, so the concurrency cap is checked against live streams only and never bounds the churn rate or the map size. A secondary effect compounds the DoS: `applyInitialWindowDelta` (`:278-283`) iterates the entire map on every INITIAL_WINDOW_SIZE-changing SETTINGS, turning one frame into O(map-size) work (see Finding 2).

**Note on prior audits.** A prior CVE audit concluded rapid reset is "structurally absent in a pull-based sans-IO design." That holds for *handler-work* amplification - the integrator decides whether to spawn work per stream - but not for this consequence: the core's own `streams` HashMap grows without bound regardless of integrator behaviour, and the integrator has no API to evict the stale entries. This is the memory-exhaustion variant of the rapid-reset class and is a genuine, peer-triggerable bug.

**Remediation.** Remove the stream from `self.streams` when it transitions to a fully-closed terminal state (on RST_STREAM receipt, on `resetStream`, and on normal close after END_STREAM both ways and any pending send drains). If a closed entry must linger briefly (e.g. to detect late frames on a recently-closed stream per RFC 9113 5.1), bound that with a small fixed-size recently-closed set rather than the unbounded map. Independently, add a `Limits` field capping the total number of streams ever tracked and/or the RST_STREAM rate, and trip `EnhanceYourCalm` (GOAWAY) when exceeded - mirroring the existing CONTINUATION-flood defence. Caching a live-stream count (see Finding 2) is complementary.

---

### 2. HTTP/2 closed streams are never evicted, so per-HEADERS `liveStreamCount()` and per-SETTINGS/WINDOW_UPDATE map sweeps become O(map-size) - quadratic CPU under an open+RST flood

- **Severity:** Medium (same root cause as Finding 1)
- **CWE:** CWE-407 (Inefficient Algorithmic Complexity)
- **Location:** `src/core/h2/connection.zig:778-785` (`liveStreamCount`), called at `:429`; `:278-283` (`applyInitialWindowDelta`); `:724-727`, `:770-776` (`flushSendable` / `hasPendingSend`)

**Attacker scenario.** The same open+reset flood as Finding 1: `HEADERS(N) + RST_STREAM(N)` for increasing odd `N`. The CPU cost compounds because the closed entries are never removed.

**Impact.** An algorithmic-complexity DoS in addition to the memory growth. Every new request HEADERS evaluates `refused = self.liveStreamCount() >= max_concurrent_streams` (`:429`), and `liveStreamCount` iterates the *entire* `self.streams` map (`:778-785`) - including all lingering closed entries - with no early exit and no cached count. After `M` churned streams the map holds `M` entries, so the `N`-th new HEADERS costs O(M) and a flood of `N` streams costs O(N^2) CPU; at ~100k churned streams each subsequent minimal HEADERS triggers a 100k-entry scan, pinning a CPU core from cheap attacker bytes. The same lingering-entry cost also hits `applyInitialWindowDelta` (`:278-283`, per inbound SETTINGS that changes INITIAL_WINDOW_SIZE) and `flushSendable`/`hasPendingSend` (`:724-727`, `:770-776`, invoked from `connection_obj.zig:464` on every inbound window_update or settings event), so a peer can additionally amplify each SETTINGS/WINDOW_UPDATE into an O(map-size) sweep once the map is bloated.

This is rated medium rather than high because it shares its single root cause with Finding 1 and is not a pure tiny-input unbounded-amplification: the attacker must spend bandwidth and memory proportional to `M` to set up the O(M) per-frame cost, so attacker cost grows alongside inflicted cost. It is, however, genuine quadratic blow-up.

**Evidence.** `connection.zig:429` `refused = self.liveStreamCount() >= self.limits.max_concurrent_streams;` is evaluated on every new server HEADERS. `liveStreamCount` (`:778-785`) is `var it = self.streams.valueIterator(); while (it.next()) |s| { if (s.countsTowardConcurrency()) n += 1; }` - a full O(entries) walk. `applyInitialWindowDelta` (`:278-283`) and `flushSendable`/`hasPendingSend` (`:724-727`, `:770-776`) iterate `self.streams.valueIterator()` identically. Because closed streams are never removed (Finding 1), `entries` grows monotonically with the attacker's open+reset count.

**Remediation.** Fixed by evicting closed streams (Finding 1). Additionally, replace the O(n) `liveStreamCount` scan with an incrementally maintained live-stream counter (incremented when a stream enters a concurrency-counting state, decremented on transition out), so the concurrency gate is O(1) regardless of map size.

---

### 3. HTTP/2 server read path never validates header / pseudo-header VALUES for control bytes (CR/LF/NUL) - RFC 9113 8.2.1 malformed-field acceptance, H2->H1 smuggling/splitting vector

- **Severity:** High
- **CWE:** CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
- **Location:** `src/core/h2/connection.zig:603` (regular header values), `:607-624`/`:621` (`:path` -> target, `:method`), `:612-616` (`:authority` -> synthesized `host`); decoder stages raw value bytes at `src/core/h2/hpack/decoder.zig:144-148`

**Attacker scenario.** A valid HTTP/2 client preface + SETTINGS, then a HEADERS frame on stream 1 whose HPACK block decodes to a field carrying an embedded CR/LF (or NUL):
- a regular field, e.g. name `x-evil` value `a\r\nSmuggled: 1`, or
- a literal `:path` value `/\r\nX: y`, or
- a literal `:authority` value `evil.com\r\nX-Injected: 1`.

HPACK string literals (Huffman or raw) can carry any byte `0x00-0xFF`.

**Impact.** This is a receive-side RFC 9113 8.2.1 violation (a receiver must treat a field containing these bytes as malformed) and a concrete H2->H1 smuggling/splitting footgun realized one hop downstream. An integrator that re-serializes the surfaced `Request` to HTTP/1.1 - a gateway/translator, the canonical use of a sans-IO H2 core - emits the CRLF verbatim into the request line (from `target`/`method`) or into a header line (from any value or the synthesized `host`), splitting one H2 request into two H1 requests or injecting arbitrary headers. NUL and other controls in values are likewise passed through. The bytes reach Python verbatim (`request.target`, `request.method`, header values) via raw `PyBytes` copies with no validation (`events_obj.zig:688-691`, `:630-631`). Within zhttp's own bytes this is not memory unsafety and the byte is not an H2 frame boundary, so the in-scope realized effect is surfacing malformed/dangerous data to the caller; the splitting is downstream. It is rated high (not critical) on that basis.

**Evidence.** `collapseRequest` validates only the field *name* (`isValidFieldName(h.name)`, `connection.zig:593`, which at `:829-836` iterates `name` only and never touches `h.value`) plus the `te`/`content-length` special cases; the generic value goes straight to `self.req_headers.append(self.gpa, h)` at `:603` with no byte check. `:path` becomes `request.target`/`path`/`query` unchecked (`:607-624`), `:method` becomes `request.method` unchecked (`:621`), and `:authority` is copied verbatim into a synthesized `host` header (`:612-616`). The HPACK decoder stages raw value bytes into `out_store` with no control-byte filtering (`hpack/decoder.zig:144-148`, literal path), so a literal value can carry any byte. A grep over `connection.zig` finds no `is_field_vchar` / control-byte check anywhere on the read path.

The asymmetry is decisive: the **write** path (trusted local app) rejects exactly these bytes - `validateValue` (`writer.zig:254-263`) rejects any byte `< 0x20` or `== 0x7F` in every value, applied to both pseudo-header values (`:151`) and regular headers (`:242`), with the explicit comment that this stops a CR/LF from being smuggled into the request line. H1 likewise rejects them - `parseHeaderLine` (`headers.zig:108-110`) checks every value byte against `tables.is_field_vchar`. The hostile read path is the one place these bytes pass unvalidated, exactly inverting the threat model. Because the H1 path guarantees CR/LF-free surfaced values, an integrator reasonably trusts the same of the H2 path - making this a genuine footgun.

**Remediation.** On the H2 read path, validate every regular header value and every pseudo-header value (`:path`, `:method`, `:authority`, `:scheme`, `:status`) against the same control-byte rule the write path already enforces (`validateValue`): reject any byte `< 0x20` or `== 0x7F` (and explicitly CR/LF/NUL), treating a violation as a stream error (`RST_STREAM` / malformed) per RFC 9113 8.1.1. Reuse the existing `writer.zig` predicate so the read and write sides share one definition of a legal value byte.

---

### 4. Empty `:path` accepted on the H2 read path (RFC 9113 8.3.1 violation; H1/H2 differential)

- **Severity:** Low
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `src/core/h2/connection.zig:606`

**Attacker scenario.** A HEADERS block with `:method GET`, `:scheme http`, and a literal `:path` whose value is the empty string (length 0), with no other path-bearing pseudo-header.

**Impact.** RFC 9113 8.3.1 requires `:path` to be non-empty for http/https URIs (the empty-path carve-outs are asterisk-form `*` and CONNECT, which this does not distinguish). The core checks only presence, not emptiness, so `request.target`/`path` are surfaced as empty strings. No memory-safety issue (`target[target.len..]` with `target.len == 0` is a valid empty slice, no OOB/panic under ReleaseSafe), no framing desync, no resource exhaustion. The only consequence is a conformance differential - the H1 side rejects an empty request-target (`headers.zig:38`), so H1 rejects what H2 accepts - and a downstream consumer could interpret an empty target differently from the peer's intent. That downstream impact is speculative, which keeps this at low.

**Evidence.** `collapseRequest` at `connection.zig:606` checks `if (method == null or path == null or scheme == null) return error.Malformed` - presence only. An empty `:path` value is non-null (`path = h.value` at `:580`), so it passes and flows to `target = path.?` (`:607`), `req_query = target[target.len..]` (`:610`), and into the emitted Request `.target` (`:622`). There is no `len == 0` rejection and no method-aware (asterisk-form / CONNECT) carve-out in the whole `collapseRequest` body (`:561-631`).

**Remediation.** Reject an empty `:path` as malformed unless the method is CONNECT (no `:path`) or the path is the asterisk-form `*` for `OPTIONS`. Match the H1 side's non-empty-target requirement.

---

### 5. `next_event` leaves a pending `MemoryError` set (and silently drops the Upgrade value) when building the H1 upgrade bytes fails, returning a valid Request

- **Severity:** Low
- **CWE:** CWE-755 (Improper Handling of Exceptional Conditions)
- **Location:** `src/python/connection_obj.zig:473`

**Attacker scenario.** A request whose head asks to upgrade (e.g. `GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n`) fed via `receive_data`, parsed via `next_event`, under a memory-pressure condition where `PyBytes_FromStringAndSize` for the Upgrade value fails. The hostile peer cannot deterministically force this small-allocation OOM - only race it under memory pressure.

**Impact.** OOM-only robustness/correctness gap. `py.fromBytes(u)` at line 473 can return null and set `MemoryError`, but the result is stored into `e.upgrade_obj` unchecked and execution falls through to `events_obj.fromH1Event(ev)` at line 475. If `makeRequest`'s own allocations succeed, `next_event` returns a valid non-NULL `Request` while a `MemoryError` is left set on the thread - a CPython C-API contract violation (non-NULL return with an exception pending). A secondary effect: `upgrade_obj` is left null, so a later `.upgrade()` accessor (`connection_obj.zig:733`) returns `None` even though the peer asked to upgrade, silently losing the value. No memory unsafety, no crash, no framing desync.

**Evidence.** Line 473: `e.upgrade_obj = if (e.reader.upgrade()) |u| py.fromBytes(u) else null;`. `py.fromBytes` (`py.zig:105`) is `PyBytes_FromStringAndSize`, which returns NULL + `MemoryError` on allocation failure. The null is assigned without an `errOccurred()` check (that helper exists at `py.zig:85-86` and is used elsewhere, e.g. `connection_obj.zig:750`), and line 475 proceeds to build and return the Request regardless. Contrast `makeRequest` (`events_obj.zig:696-699`), which does check every `fromBytes` result and returns null to propagate.

**Remediation.** Check the result of `py.fromBytes(u)` at line 473: on null (i.e. `errOccurred()`), return null from `next_event` to propagate the `MemoryError` rather than falling through to build the Request. Mirror the pattern already used in `makeRequest`.

---

### 6. `H2Engine.flushSendable` swallows `OutOfMemory` when draining parked DATA after WINDOW_UPDATE/SETTINGS

- **Severity:** Info
- **CWE:** CWE-391 (Unchecked Error Condition)
- **Location:** `src/python/connection_obj.zig:124-126`, called at `:464`

**Attacker scenario.** A peer sends a WINDOW_UPDATE or SETTINGS frame crediting a send window while the local app has parked outbound DATA, under memory pressure where the re-framing allocation fails. The peer controls only the WINDOW_UPDATE/SETTINGS timing, not the allocator, and the parked DATA is locally supplied by the trusted app - so this is not peer-exploitable for crash/unsafety/desync.

**Impact.** OOM-only robustness gap. `self.conn.flushSendable(self.writer) catch {};` discards an `OutOfMemory` error. `next_event` still returns the WINDOW_UPDATE/SETTINGS event successfully, but parked DATA may silently fail to be framed and the OOM is hidden from the caller. This is `catch {}`, not an unhandled trap - no abort, no memory unsafety, no inbound framing desync. Noted for completeness only.

**Evidence.** `connection_obj.zig:124-126` `fn flushSendable(self: *H2Engine) void { self.conn.flushSendable(self.writer) catch {}; }` swallows the error union, called from `next_event:464` `if (ev == .window_update or ev == .settings) e.flushSendable();` with no error surfaced to Python. Tracing the flush path (`flushSendable` -> `flushStreamPtr` -> `writer.writeDataFrame` -> `writeFrame` -> `frame.write`), the only realistic error is `OutOfMemory` (`TooLarge` is unreachable because the chunk is bounded by `@min(room, max_frame, remaining)`; no header validation runs in the DATA-only flush path).

**Remediation.** Surface the error - either propagate it out of `next_event` (returning null with an exception set) or buffer the unflushed DATA and retry on the next opportunity. At minimum, do not silently discard `OutOfMemory`.

---

### 7. OSS-Fuzz / libFuzzer target (`fuzz/target.zig`) fails to compile after the `h1/` package reorg, disabling the only ASan/UBSan fuzzing oracle

- **Severity:** Low (build/tooling regression; no attacker input)
- **CWE:** coverage gap (CWE-1127-adjacent)
- **Location:** `fuzz/target.zig:13-14`

**Description.** `fuzz/target.zig:13-14` reference `core.reader.Reader` / `core.reader.Role`, but `src/core/root.zig` exports only `h1` and `h2` (the reader now lives at `core.h1.reader`). The Python binding was migrated (`connection_obj.zig:10` uses `core.h1.reader.Reader`), but the fuzz target was left behind. `zig build fuzz-obj` fails with `error: root source file struct 'root' has no member named 'reader'`, and `.oss-fuzz/build.sh:7` runs `zig build fuzz-obj` as step 1, so the OSS-Fuzz image build aborts before linking.

**Impact.** Defense-in-depth / CI-hygiene gap, not an exploitable vulnerability (no attacker input, no attacker-reachable code path). The only sanitizer-backed (ASan + UBSan, per `.oss-fuzz/project.yaml`) continuous-fuzzing oracle is dead, so a latent use-after-free / out-of-bounds / UB that ReleaseSafe does not trap (e.g. a benign-looking OOB read within an allocation, or a UAF that does not immediately fault) could go uncaught by OSS-Fuzz. The build failure was reproduced end-to-end; the one-line fix compiles cleanly.

**Remediation.** Change `fuzz/target.zig:13-14` to `core.h1.reader.Reader` / `core.h1.reader.Role`. Consider a CI smoke step that runs `zig build fuzz-obj` so this regression class is caught at PR time.

---

### 8. HTTP/2 core (connection / HPACK / frame / stream) is attacker-reachable via the Python binding but has zero fuzz coverage

- **Severity:** Low (coverage gap; no named exploitable defect)
- **CWE:** coverage gap
- **Location:** `fuzz/target.zig` (drives only `core.h1.reader`); `fuzz/harness.py:30` (constructs `zttp.Connection(role)` with the default HTTP/1.1 protocol); empty H2 seed corpus

**Description.** The newest, least-audited, most complex parser surface - `h2/connection.zig`, `hpack/decoder.zig` (Huffman + dynamic-table + integer decoding), `frame.zig`, `stream.zig` - is reached by hostile bytes through the Python binding (`receive_data` -> `e.conn.feed(bytes)`, `connection_obj.zig:445`) but is exercised by no fuzzer. The libFuzzer target drives only `core.h1.reader`; the Python oracle (`harness.py`) constructs only `zttp.Connection(role)` with the default HTTP/1.1 protocol; the seed corpus (`run.py` SEEDS, `structured.py`, `roundtrip.py`) is exclusively HTTP/1.1 wire bytes containing no H2 preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), so random mutation essentially never reaches the H2 state machine. A grep for `h2|http2|hpack|preface` across `fuzz/` returns nothing; the corpus dir holds only `.gitkeep`.

**Impact.** Test-coverage / hardening gap, not a vulnerability - it names no specific exploitable defect and by itself lets an attacker do nothing; its impact is meta (it raises the probability that an as-yet-undiscovered bug survives). The H2 surface does carry genuine risk a fuzzer would exercise: the CONTINUATION accumulator `fb_buf`, HPACK integer/Huffman decoding, dynamic-table eviction, and several `@intCast`/arithmetic operations on attacker-controlled lengths and flow-control windows, any reachable overflow of which would trap (process abort = DoS) under ReleaseSafe.

**Remediation.** Add a third oracle that builds valid H2 frame sequences (preface + SETTINGS + crafted HEADERS/CONTINUATION/HPACK/DATA/WINDOW_UPDATE), or an H2 libFuzzer target driving `core.h2.connection.Connection.feed` under ASan/UBSan, with an H2 seed corpus. This is the natural companion fix to Finding 7.

---

## Scope and Method

This audit covered the `main`-branch state of the Zig core and Python binding: HTTP/1.1 core (`src/core/h1/`, `src/core/scanner.zig`, `tables.zig`, `events.zig`), HTTP/2 core (`src/core/h2/` - `frame.zig`, `connection.zig`, `hpack/`, `stream.zig`, `settings.zig`, `writer.zig`), and the CPython C-API binding (`src/python/` - `connection_obj.zig`, `events_obj.zig`, `exceptions.zig`, `module.zig`, `py.zig`). The build profile reasoned about is the shipped ReleaseSafe (safety checks ON), so a reachable bounds/overflow traps (process abort = DoS) rather than becoming silent UB; a reachable panic is itself treated as a finding.

The threat model is sans-IO: the adversary is the **peer** whose bytes reach `receive_data()`/`feed()`. Every fed byte is treated as hostile; the local calling application is trusted (write-side arguments are validated defensively but the local app is not modelled as an attacker). The security goal is that no attacker-controlled byte stream can cause memory unsafety, crash the host process, desynchronize message framing, or force unbounded resource use.

Method: data-flow tracing from the trust boundary (`feed`/`receive_data`) to each sink, reading the relevant source directly. Per-finding code paths were independently re-verified by an adversarial reviewer who read the code; refuted candidates were dropped, and severities reflect the verifier's corrected ratings. Two prior audits had already hardened HTTP/1.1; those invariants were re-verified against current code (see "What is well-defended") and continue to hold. HTTP/2 and the Python binding received the most weight as the newer, less-audited surfaces.

## Out of Scope / Residual Risks

- **HTTP/3 / QUIC** is not on `main` and was not audited.
- **Downstream integrator behaviour** is out of scope but is the realization point for Finding 3: zhttp is sans-IO, so the actual request-splitting happens in whatever code re-serializes a surfaced H2 request to the wire. The fix belongs in zhttp (validate on receive), but integrators that have already shipped against the current behaviour should be aware.
- **OOM-only robustness gaps (Findings 5 and 6)** depend on allocation failure that the hostile peer can race but not deterministically force. They are correctness/contract bugs, not peer-driven exploits, and sit at the edge of the threat model.
- **Latent memory bugs in the H2 core** cannot be ruled out as confidently as in H1, because the sanitizer-backed fuzzing oracle is currently broken (Finding 7) and the H2 core has no fuzz coverage at all (Finding 8). No such bug was found by manual review - the frame arithmetic, HPACK decoding, and flow-control math were each traced and found bounds-checked - but the absence of running ASan/UBSan fuzzing means this is the area with the least automated assurance. Restoring the fuzzer and adding an H2 oracle is the highest-value follow-up after the rapid-reset fix.
- **`ReleaseFast` builds** are not shipped (verified: no `ReleaseFast` anywhere in the repo; the fallback is Debug). Any "would be UB under ReleaseFast" note is therefore theoretical for the shipped artifact - the installed wheel traps rather than misbehaves.
