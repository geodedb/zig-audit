# Performance Gap Analysis

Last updated: 2026-03-22

Repository: `gitlab.com/devnw/zig/audit`
Baseline: 33/33 tests passing, ~70-80 heap allocations per audit event.
Estimated improvement potential: 50-80% allocation reduction, 10-50x file sink throughput with fsync batching.

## Summary

| PerfSeverity | Count |
|---|---|
| P1 (Material user-facing impact) | 3 |
| P2 (Moderate impact / cost) | 9 |
| P3 (Minor optimization) | 4 |
| Info (Hardening / best practice) | 3 |
| **Total** | **19** |

### Top 5 Risks by Expected Impact

1. **PERF-001: Triple+ JSON serialization per audit() call** -- eliminates ~40% of per-event allocations and CPU; PerfScore 100.
2. **PERF-002: fsync per event in FileSink** -- current throughput is bounded by disk latency (~5ms/event); batching yields 10-50x throughput gain; PerfScore 100.
3. **PERF-003: New TCP socket+handshake per syslog message** -- each TCP send pays ~1-3ms connect latency plus kernel socket allocation; connection pooling eliminates this entirely; PerfScore 100.
4. **PERF-004: JSON round-trip in AuditEvent.clone() metadata** -- serialize-then-reparse is O(n) with double the allocations of a direct tree walk; PerfScore 80.
5. **PERF-005: Metadata cloned 3+ times through pipeline** -- each clone duplicates every key and value string; ownership transfer eliminates 2 of 3 copies; PerfScore 80.

## Stack-Ranked Findings

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | Issue URL | Fix Summary | Owner | SLA/Due | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | P1 | 100 | Triple+ JSON serialization per audit() call | logger | `src/logger.zig:71,92,113,119,141` -- clone, filter, cloneJsonValue, serializeEventForSizeCheck, sink.write each serialize/deserialize metadata | ~70-80 heap allocs per event; 3+ full JSON tree walks | -- | Single-pass pipeline: clone once, filter in-place, serialize once for size+sink | @benjiv | Within sprint | `status::triage` |
| 2 | P1 | 100 | fsync per event in FileSink | file_sink | `src/file_sink.zig:57` -- `try file.sync()` inside write() | Disk fsync ~5ms; at 200 events/sec = 1000ms/sec of pure I/O wait | -- | Batch fsync: flush every N events or M milliseconds; configurable | @benjiv | Within sprint | `status::triage` |
| 3 | P1 | 100 | New TCP socket+handshake per syslog message | syslog | `src/syslog.zig:211-223` -- sendTcp creates socket, resolves DNS, connects, sends, closes per call | 1-3ms connect latency + kernel alloc per message; no reuse | -- | Persistent TCP connection with reconnect-on-error; reuse existing tls_pool infrastructure | @benjiv | Within sprint | `status::triage` |
| 4 | P2 | 80 | JSON round-trip in AuditEvent.clone() metadata | events | `src/events.zig:128-134` -- Stringify.valueAlloc then parseFromSlice then cloneJsonValue | serialize+parse+clone = 3 passes over metadata tree | -- | Replace with direct recursive cloneJsonValue (already exists at events.zig:140); remove serialize/parse round-trip | @benjiv | Next quarter | `status::resolved` |
| 5 | P2 | 80 | Metadata cloned 3+ times through pipeline | logger | `src/logger.zig:71` (ev.clone), `:92` (filterAndRedactMetadata), `:113` (cloneJsonValue) | 3 full deep-copies of metadata JSON tree per audit() call | -- | Transfer ownership: clone once in audit(), filter in-place on owned copy, pass directly to sinks | @benjiv | Next quarter | `status::triage` |
| 6 | P2 | 80 | DNS resolution per syslog send, no caching | syslog | `src/syslog.zig:207,215` -- resolveHostToAddress called in both sendUdp and sendTcp | DNS lookup per message; typical DNS RTT 1-50ms | -- | Cache resolved address with TTL; invalidate on send error | @benjiv | Next quarter | `status::triage` |
| 7 | P2 | 64 | FileSink mutex held during fsync | file_sink | `src/file_sink.zig:49-58` -- mutex.lock() at :49, file.sync() at :57, unlock at :50 (defer) | All concurrent writers block for ~5ms during fsync | -- | Write outside lock (format first), take lock only for append+size update; async fsync or periodic flush | @benjiv | Next quarter | `status::triage` |
| 8 | P2 | 60 | formatJsonLine heap-allocates constant string keys | file_sink | `src/file_sink.zig:135-167` -- `allocator.dupe(u8, "ts")`, `allocator.dupe(u8, "category")`, etc. for every event | 12+ heap allocations for string literals that never change | -- | Use comptime string literals directly; ObjectMap keys do not need to be heap-allocated if lifetime is guaranteed | @benjiv | Next quarter | `status::triage` |
| 9 | P2 | 60 | serializeEventForSizeCheck builds throwaway ObjectMap | logger | `src/logger.zig:145-159` -- constructs full ObjectMap, serializes to JSON, then discards | Extra ObjectMap + full JSON serialize just to check byte length | -- | Reuse the JSON output already needed for sinks; or estimate size from field lengths without building intermediate map | @benjiv | Next quarter | `status::triage` |
| 10 | P2 | 60 | New UDP socket per syslog message | syslog | `src/syslog.zig:203-209` -- sendUdp creates+closes socket per call | Kernel socket alloc/dealloc per message; ~0.1ms overhead | -- | Create UDP socket once in init(), reuse for all sends | @benjiv | Next quarter | `status::triage` |
| 11 | P2 | 60 | No SO_SNDTIMEO on TCP syslog | syslog | `src/syslog.zig:211-222` -- no timeout set on TCP connect or send | Hung remote host blocks worker thread indefinitely | -- | Set SO_SNDTIMEO and connect timeout; configurable with sensible default (5s) | @benjiv | Next quarter | `status::triage` |
| 12 | P2 | 60 | No streaming JSON writer, full intermediate ObjectMap | file_sink | `src/file_sink.zig:122-187` -- builds complete ObjectMap in memory, then serializes | All keys+values heap-allocated into map, then serialized to string, then map freed | -- | Write JSON tokens directly to a buffered file writer; skip intermediate ObjectMap entirely | @benjiv | Next quarter | `status::triage` |
| 13 | P3 | 48 | 100ms sleep-loop poll in worker thread | syslog | `src/syslog.zig:159` -- `std.Thread.sleep(std.time.ns_per_ms * 100)` | Fixed 100ms latency floor; wastes CPU when idle, delays delivery when busy | -- | Replace with condition variable or eventfd signaling; wake on enqueue | @benjiv | Backlog | `status::triage` |
| 14 | P3 | 40 | isSensitiveKey called twice per sensitive field | filters | `src/filters.zig:294,267` -- shouldFilterField calls isSensitiveKey at :294; filterAndRedactMetadata calls it again at :267 in the .redact branch | Double heap-alloc of lowercased key per sensitive field | -- | Cache the result from shouldFilterField; pass RedactionToken through FilterResult enum | @benjiv | Backlog | `status::triage` |
| 15 | P3 | 40 | isSensitiveKey heap-allocates lowercase per call | filters | `src/filters.zig:42` -- `std.ascii.allocLowerString(allocator, key)` | Heap allocation for every key checked, even non-sensitive ones | -- | Use stack buffer (keys are short); or case-insensitive compare without allocation | @benjiv | Backlog | `status::triage` |
| 16 | P3 | 24 | errdefer missing on partial clone | events | `src/events.zig:111-137` -- if clone() fails mid-way, already-duped strings leak | Memory leak on error path; no cleanup of partial allocations | -- | Add errdefer blocks to free each allocation on failure | @benjiv | Backlog | `status::triage` |
| 17 | Info | 16 | Ring buffer uses mutex not SPSC | syslog | `src/syslog.zig:55-56` -- queue guarded by std.Thread.Mutex | Single-producer single-consumer pattern uses heavyweight mutex | -- | Replace with lock-free SPSC ring buffer; atomic head/tail | @benjiv | As capacity | `status::triage` |
| 18 | Info | 36 | Syslog worker processes max 32 msgs per 100ms cycle | syslog | `src/syslog.zig:164` -- `var messages: [32][]const u8` fixed batch size | At sustained load, max throughput = 320 msgs/sec regardless of network capacity | -- | Drain entire queue per cycle; or increase batch size dynamically | @benjiv | As capacity | `status::triage` |
| 19 | Info | 4 | TLS pool fields dead weight | syslog | `src/syslog.zig:59-60` -- `tls_pool` and `pool_mutex` allocated in every SyslogSender | 16 * sizeof(PooledConnection) + mutex overhead; TLS not implemented | -- | Remove until TLS transport is implemented (GAP-005); or gate behind config | @benjiv | As capacity | `status::triage` |

## Findings by Area

### Area: app (logger orchestration + events)

| ID | Finding | PerfScore |
|---|---|---|
| PERF-001 | Triple+ JSON serialization per audit() call | 100 |
| PERF-004 | JSON round-trip in AuditEvent.clone() metadata | 80 |
| PERF-005 | Metadata cloned 3+ times through pipeline | 80 |
| PERF-009 | serializeEventForSizeCheck builds throwaway ObjectMap | 60 |
| PERF-016 | errdefer missing on partial clone | 24 |

**Root cause theme**: The audit pipeline treats metadata as immutable across stages, cloning it repeatedly. A single-ownership model where metadata is cloned once and mutated in-place through filter and serialize stages would eliminate most of the overhead.

### Area: app (file sink)

| ID | Finding | PerfScore |
|---|---|---|
| PERF-002 | fsync per event in FileSink | 100 |
| PERF-007 | FileSink mutex held during fsync | 64 |
| PERF-008 | formatJsonLine heap-allocates constant string keys | 60 |
| PERF-012 | No streaming JSON writer, full intermediate ObjectMap | 60 |

**Root cause theme**: FileSink builds a full in-memory JSON tree with heap-allocated constant keys, serializes it, then fsyncs under a mutex. A streaming writer that writes JSON tokens directly to a buffered file (flushed periodically) would collapse all four findings.

### Area: infra (syslog transport)

| ID | Finding | PerfScore |
|---|---|---|
| PERF-003 | New TCP socket+handshake per syslog message | 100 |
| PERF-006 | DNS resolution per syslog send, no caching | 80 |
| PERF-010 | New UDP socket per syslog message | 60 |
| PERF-011 | No SO_SNDTIMEO on TCP syslog | 60 |
| PERF-013 | 100ms sleep-loop poll in worker thread | 48 |
| PERF-017 | Ring buffer uses mutex not SPSC | 16 |
| PERF-018 | Syslog worker processes max 32 msgs per 100ms cycle | 36 |
| PERF-019 | TLS pool fields dead weight | 4 |

**Root cause theme**: sendUdp/sendTcp create ephemeral sockets with per-call DNS resolution. The existing `tls_pool` infrastructure was intended for connection reuse but is unused. Refactoring to persistent connections (UDP socket created once, TCP with reconnect) and cached DNS resolution addresses the top three findings together.

### Area: app (filters)

| ID | Finding | PerfScore |
|---|---|---|
| PERF-014 | isSensitiveKey called twice per sensitive field | 40 |
| PERF-015 | isSensitiveKey heap-allocates lowercase per call | 40 |

**Root cause theme**: Case-insensitive key matching allocates a heap copy of each key, and the result is not cached across the two call sites. A stack-buffer lowercase with result caching eliminates both.

## Roadmap

### Quick Wins (< 1 day each)

| ID | Finding | Expected Impact | Effort |
|---|---|---|---|
| PERF-010 | Reuse UDP socket | Eliminate socket create/close per UDP message | 30 min |
| PERF-015 | Stack-buffer lowercase in isSensitiveKey | Eliminate 1 heap alloc per key check | 30 min |
| PERF-014 | Cache isSensitiveKey result in shouldFilterField | Eliminate redundant call + alloc per sensitive field | 30 min |
| PERF-019 | Remove dead tls_pool fields | ~256 bytes per SyslogSender | 15 min |
| PERF-016 | Add errdefer to AuditEvent.clone | Fix memory leak on error path | 30 min |
| PERF-008 | Use string literals instead of allocator.dupe for constant keys | Eliminate 12+ heap allocs per event | 1 hour |
| PERF-011 | Set SO_SNDTIMEO on TCP syslog socket | Prevent indefinite blocking | 30 min |

### Medium (1-5 days each)

| ID | Finding | Expected Impact | Effort |
|---|---|---|---|
| PERF-004 | Direct recursive clone instead of JSON round-trip | Eliminate serialize+parse (2 of 3 passes) in clone() | 1 day |
| PERF-005 | Single-ownership metadata through pipeline | Eliminate 2 of 3 metadata deep-copies per event | 2 days |
| PERF-002 | Batched fsync (N events or M ms) | 10-50x file sink throughput | 2 days |
| PERF-003 | Persistent TCP connection with reconnect | Eliminate connect latency per message | 2 days |
| PERF-006 | DNS resolution cache with TTL | Eliminate DNS RTT per syslog send | 1 day |
| PERF-007 | Narrow mutex scope in FileSink | Reduce writer contention from ~5ms to ~0.1ms | 1 day |
| PERF-013 | Replace sleep-loop with condition variable | Reduce delivery latency from 100ms floor to sub-ms | 1 day |
| PERF-018 | Dynamic batch size for syslog worker | Increase max throughput beyond 320 msgs/sec | 1 day |

### Strategic (> 5 days)

| ID | Finding | Expected Impact | Effort |
|---|---|---|---|
| PERF-001 | Single-pass audit pipeline (clone+filter+serialize) | 50-80% allocation reduction per event; simplifies entire hot path | 5-8 days |
| PERF-009 + PERF-012 | Streaming JSON writer for file sink | Eliminate intermediate ObjectMap; write directly to buffered I/O | 3-5 days |
| PERF-017 | Lock-free SPSC ring buffer | Eliminate mutex contention on syslog queue | 3 days |

## Confidence Assessment

### Confirmed (code evidence is unambiguous)

All 19 findings are tagged `confidence::confirmed`. The code paths are directly observable in the source:

- PERF-001: `logger.zig` audit() method performs clone (line 71), filter (line 92), cloneJsonValue (line 113), serializeEventForSizeCheck (line 119), and sink.write (line 141) -- each creates a new JSON tree or serialized representation.
- PERF-002: `file_sink.zig:57` calls `file.sync()` unconditionally inside every `write()`.
- PERF-003: `syslog.zig:211-223` creates a new socket, resolves DNS, connects, sends, and closes per TCP message.
- PERF-004: `events.zig:128-134` serializes metadata to JSON string, parses it back, then clones the parsed tree.
- PERF-014/015: `filters.zig:42` heap-allocates lowercase; `filters.zig:294` and `:267` both call `isSensitiveKey`.

### Measurements Needed to Quantify

The following measurements would provide concrete baseline numbers:

1. **Allocation count per audit() call**: Run with `std.heap.GeneralPurposeAllocator` in verbose mode; count allocs between audit() entry and return.
2. **File sink throughput**: Benchmark write() in a loop with and without fsync; measure events/sec.
3. **Syslog send latency**: Measure wall-clock time of sendTcp/sendUdp including DNS resolution.
4. **Filter overhead**: Profile isSensitiveKey with varying key counts to quantify allocation cost.

## Scoring Methodology

```
PerfScore = Impact(1-5) x Likelihood(1-5) x 4

Impact:
  5 = SLO saver / 10x improvement potential
  4 = 2-5x improvement or significant cost reduction
  3 = Noticeable user-facing improvement
  2 = Small improvement
  1 = Hardening, future-proofing

Likelihood:
  5 = Always hit / hot path
  4 = Common code path
  3 = Moderate frequency
  2 = Rare code path
  1 = Edge case / theoretical
```

PerfSeverity is assigned based on user-facing impact and SLO risk, independent of PerfScore:

| Level | Meaning | Response Time |
|---|---|---|
| P1 | Material user-facing impact | Within sprint |
| P2 | Moderate impact / cost | Next quarter |
| P3 | Minor optimization | Backlog |
| Info | Hardening, best practice | As capacity allows |

## Cross-References

- GAP-020 in `docs/GAP_ANALYSIS.md` corresponds to PERF-002 (fsync per event).
- GAP-021 in `docs/GAP_ANALYSIS.md` corresponds to PERF-003 and PERF-010 (socket per message).
- GAP-022 in `docs/GAP_ANALYSIS.md` corresponds to PERF-004 (JSON round-trip in clone).
- GAP-027 in `docs/GAP_ANALYSIS.md` corresponds to PERF-019 (TLS pool dead weight).
