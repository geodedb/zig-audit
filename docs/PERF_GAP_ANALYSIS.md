# Performance Gap Analysis

Last updated: 2026-06-11

Repository: `gitlab.com/devnw/zig/audit`
Baseline: tests passing; ~70-80 heap allocations per audit event (PR-004); file sink ~92µs/op even with fsync off (PR-006).
Estimated improvement potential: 50-80% allocation reduction (per-event arena + filter-once + streaming serialize), and a large file/syslog throughput gain from buffered/batched I/O.

This document tracks two finding series:

- **PERF-001..019** — the original 2026-03 performance review. Several are now **RESOLVED** by the syslog/channel redesign (persistent sockets, DNS cache, blocking condvar channel, `BoundedChannel` replacing the mutex `RingBuffer` in the hot path). The remainder are kept **OPEN** and cross-referenced to the GAP-* master series.
- **PR-001..013** — the 2026-06-11 deep performance review. These are NEW findings, tracked as GitLab issues (links below). PR-011 was folded into GAP-041 and PR-014 into GAP-056; neither has a PR-series issue.

> Cross-series note: the GAP-* master series and QR-* quality issues are maintained by a separate workstream in `docs/GAP_ANALYSIS.md`. This document does not create or own GAP-*/QR-* items; it only references them.

## Summary

### PR-001..013 (2026-06-11 deep perf review) — NEW

| PerfSeverity | Count |
|---|---|
| P0 (SLO breach / outage risk) | 1 |
| P1 (Material user-facing impact) | 4 |
| P2 (Moderate impact / cost) | 6 |
| P3 (Minor optimization) | 1 |
| **Total (issues created)** | **12** |

### PERF-001..019 (2026-03 review) — status

| Status | Count | IDs |
|---|---|---|
| Resolved | 12 | PERF-003, PERF-004, PERF-006, PERF-010, PERF-011, PERF-013, PERF-015, PERF-016, PERF-017, PERF-018, PERF-019, PERF-002(superseded by PR-006 — see note) |
| Open | 6 | PERF-001, PERF-005, PERF-008, PERF-009, PERF-012, PERF-014 |
| Design decision (open, by design) | 1 | PERF-002 (batching implemented; default `.per_event` is intentional — GAP-DD1) |

### Top 5 Risks by Expected Impact (current)

1. **PR-006 (P0): unbuffered file writes — 2 syscalls/event, no batching.** ~92µs/op even with fsync off; throughput is syscall-bound. Issue #74.
2. **PR-004 (P1): no per-event arena — ~70-80 alloc/free pairs per `audit()`.** A request-scoped arena collapses these to a handful of bump allocations. Issue #68.
3. **PR-012 (P1): worker drains one item per `receive()`.** No batch primitive; one lock + syscall(s) per item. Issue #89.
4. **PR-009 (P1): single-mutex MPSC channel signals every send.** Expected to collapse under multi-producer load. Issue #82.
5. **PR-007 (P1): TCP syslog sends 2 syscalls per record (prefix + payload).** No `writev`/batch. Issue #78.

## Consolidation Architecture (design note)

The PR-series findings share a single root cause: the audit hot path re-derives, re-allocates, and re-walks the same data in each stage and sink. The target design consolidates them:

1. **Per-event arena for scratch.** Lifetime = the `audit()` call only. The filtered metadata tree, CEF extension buffers, escaped strings, and all formatting temporaries allocate from the arena and are freed by a single reset at return (PR-004, PR-005). Nothing arena-allocated may escape the call.
2. **Filter once into one redacted tree, shared read-only by both sinks.** Run the redaction detector chain a single time per value (PR-003), producing one redacted metadata tree that the file sink and syslog/CEF formatter both read without re-cloning or re-scanning (PR-001 metadata merge, PR-008 timestamp).
3. **Streaming serialize per wire format directly into the durable buffer handed to the channel.** No intermediate `ObjectMap` rebuild; write JSON / CEF / RFC5424 tokens straight into the line buffer that is enqueued (PR-001, PERF-012). The size gate folds into the writer (count bytes as you stream — no throwaway serialize pass, PERF-009).
4. **Orthogonal buffered/batched I/O layer.** A `receiveBatch` channel primitive (PR-012) lets each worker drain many items per wakeup under one lock, then flush them with a single `writev`/`sendmsg` (PR-006 file, PR-007 syslog). This layer is independent of fsync policy and of the serialization changes above.

### Sequencing

1. **PR-006 + PR-012** — buffered/batched I/O + `receiveBatch` (biggest, lowest-risk throughput win; unblocks the rest).
2. **PR-004** — per-event arena (collapses allocation count; depends on stable hot-path shape from step 1).
3. **PR-001 / GAP-055 / GAP-056 / GAP-057** — filter-once + streaming serialize into the durable buffer.
4. **PR-005 + PR-007** — CEF escape fast path + vectored TCP send.
5. **PR-013** — multi-producer benchmark (gates the concurrency work).
6. **PR-009 / PR-010** — channel contention + false-sharing fixes, validated against the PR-013 benchmark.

## Stack-Ranked Findings — PR-001..013 (2026-06-11)

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | Issue URL | Fix Summary | Owner | SLA/Due | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | P0 | 100 | Unbuffered file writes: 2 syscalls/event, no batching | file_sink | `src/file_sink.zig:127-128` (line + `"\n"` = 2 writes), `:111-118` (1 item/receive) | ~92µs/op with `sync_mode = .none`; throughput syscall-bound | [#74](https://gitlab.com/devnw/zig/audit/-/work_items/74) | Buffer lines + newline; flush one `writev` per batch; pair with PR-012 | @benjiv | Immediate | `confidence::confirmed` |
| 2 | P1 | 100 | No per-event arena; ~70-80 alloc/free pairs per `audit()` | logger/cef/file_sink | `src/logger.zig:79-204`, `src/cef.zig`, `src/file_sink.zig:153-223` | ~70-80 discrete alloc/free pairs per event | [#68](https://gitlab.com/devnw/zig/audit/-/work_items/68) | Request-scoped arena for all scratch; reset at `audit()` return | @benjiv | Within sprint | `confidence::confirmed` |
| 3 | P1 | 80 | Worker drains one item per `receive()`; no batch primitive | file_sink/syslog | `src/file_sink.zig:111-118`, `src/syslog.zig:213-220` | 1 lock + I/O syscall(s) per item | [#89](https://gitlab.com/devnw/zig/audit/-/work_items/89) | Add `receiveBatch`; flush batch with one vectored I/O | @benjiv | Within sprint | `confidence::confirmed` |
| 4 | P1 | 80 | Single-mutex MPSC channel signals on every send | channel | `src/channel.zig:45-58` (lock + `signal()` per send), `:63-73` | Expected throughput collapse under multi-producer | [#82](https://gitlab.com/devnw/zig/audit/-/work_items/82) | Signal on empty→non-empty only; batch/lock-amortized enqueue | @benjiv | Within sprint | `confidence::suspected` |
| 5 | P1 | 80 | TCP syslog: 2 send syscalls per record (prefix + payload) | syslog | `src/syslog.zig:313-328` (two `sendto`) | 2 syscalls/record; possible stream fragmentation | [#78](https://gitlab.com/devnw/zig/audit/-/work_items/78) | `writev`/`sendmsg` iovec [prefix,payload]; one syscall | @benjiv | Within sprint | `confidence::confirmed` |
| 6 | P2 | 60 | `formatJsonLine` rebuilds ObjectMap; O(N·M) `fetchSwapRemove` | file_sink | `src/file_sink.zig:206-218` (collision scan), `:161-224` | Quadratic metadata merge + ~12+N allocs/event | [#59](https://gitlab.com/devnw/zig/audit/-/work_items/59) | Stream JSON directly; drop intermediate map + collision scan | @benjiv | Next quarter | `confidence::confirmed` |
| 7 | P2 | 60 | Redaction re-scans every string with 5 sequential detectors | filters | `src/filters.zig:435` (per-string call), `:253-267` (detector chain) | 5 O(len) scans per allowed string value | [#65](https://gitlab.com/devnw/zig/audit/-/work_items/65) | Cheap pre-gates + order by likelihood; filter-once shared tree | @benjiv | Next quarter | `confidence::confirmed` |
| 8 | P2 | 60 | RFC3339 timestamp formatted 2-3x per event across sinks | file_sink/cef/syslog | `src/file_sink.zig:173`, `src/cef.zig:31`, `src/syslog.zig:353` | 2-3 redundant timestamp formats/event | [#80](https://gitlab.com/devnw/zig/audit/-/work_items/80) | Format once per `audit()`; pass slice to all sinks | @benjiv | Next quarter | `confidence::confirmed` |
| 9 | P2 | 60 | No multi-producer benchmark; concurrency regressions unguarded | benchmarks | `benchmarks/scale_bench.zig:244-333` (single-producer only) | N/A — coverage gap | [#91](https://gitlab.com/devnw/zig/audit/-/work_items/91) | Add 1/2/4/8/16-producer scenario; gate PR-009/010/012 | @benjiv | Next quarter | `confidence::confirmed` |
| 10 | P2 | 48 | `escapeCefString` always allocates even with no escaping | cef | `src/cef.zig:218-234` (unconditional `initCapacity`) | One ArrayList growth/value even on no-escape common case | [#71](https://gitlab.com/devnw/zig/audit/-/work_items/71) | Scan-first fast path; dupe/borrow when nothing to escape | @benjiv | Next quarter | `confidence::confirmed` |
| 11 | P2 | 48 | False sharing: `dropped_count` adjacent to hot fields; channel head/tail/mutex share cache line | syslog/channel | `src/syslog.zig:97-115`, `src/channel.zig:17-24` | Cache-line bouncing under multi-producer | [#86](https://gitlab.com/devnw/zig/audit/-/work_items/86) | Cache-line-pad producer/consumer-written fields | @benjiv | Next quarter | `confidence::suspected` |
| 12 | P3 | 40 | `getEventName` linear `mem.eql` chain per CEF format | cef | `src/cef.zig:117-135` | Linear compare ladder per CEF event | [#61](https://gitlab.com/devnw/zig/audit/-/work_items/61) | `std.StaticStringMap` comptime lookup | @benjiv | Backlog | `confidence::confirmed` |

## Stack-Ranked Findings — PERF-001..019 (2026-03)

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Resolution / Cross-ref | Status |
|---|---|---|---|---|---|---|---|
| 1 | P1 | 100 | Triple+ JSON serialization per audit() call | logger | `src/logger.zig` clone/filter/serialize stages | #39; GAP-049 supersedes/extends; addressed by filter-once + streaming serialize design | **OPEN** |
| 2 | P1 | 100 | fsync per event in FileSink | file_sink | `src/file_sink.zig:135-148` `maybeFsync` | Batching implemented (`.periodic`/`.none` sync modes, `sync_interval`); default `.per_event` retained intentionally — GAP-DD1 design decision | **OPEN (by design)** |
| 3 | P1 | 100 | New TCP socket+handshake per syslog message | syslog | `src/syslog.zig:107,283-309` persistent `tcp_socket` created on first use, reused thereafter | **RESOLVED** — socket created once and reused; reconnect-on-error path retained | **RESOLVED** |
| 4 | P2 | 80 | JSON round-trip in AuditEvent.clone() metadata | events | direct `cloneJsonValue` replaces serialize/parse | **RESOLVED** (already resolved; GAP-022) | **RESOLVED** |
| 5 | P2 | 80 | Metadata cloned 3+ times through pipeline | logger | `src/logger.zig` ownership model | GAP-049 (consolidation); addressed by per-event arena + single-ownership design | **OPEN → GAP-049** |
| 6 | P2 | 80 | DNS resolution per syslog send, no caching | syslog | `src/syslog.zig:111-114,235-246` DNS TTL cache (`resolved_addr`, `dns_cache_ttl_ms`, `last_dns_resolve_ms`) | **RESOLVED** — cached resolved address with 5-min TTL | **RESOLVED** |
| 7 | P2 | 64 | FileSink mutex held during fsync | file_sink | worker thread writes outside any mutex now (`writeLine` runs only on the worker; `src/file_sink.zig:111-132`) | Superseded by channel/worker redesign; remaining buffering tracked by PR-006 | **RESOLVED (architecture)** |
| 8 | P2 | 60 | formatJsonLine heap-allocates constant string keys | file_sink | `src/file_sink.zig:150-159,161-224` `putField` still dupes keys | GAP-055; superseded/extended by PR-001 (streaming serialize removes the map entirely) | **OPEN → GAP-055** |
| 9 | P2 | 60 | serializeEventForSizeCheck builds throwaway ObjectMap | logger | size-check pass | GAP-056; size gate folds into streaming writer (PR-001 design) | **OPEN → GAP-056** |
| 10 | P2 | 60 | New UDP socket per syslog message | syslog | `src/syslog.zig:108,263-268` persistent `udp_socket` reused | **RESOLVED** — UDP socket created once, reused for all sends | **RESOLVED** |
| 11 | P2 | 60 | No SO_SNDTIMEO on TCP syslog | syslog | `src/syslog.zig:289-298` 5s `SO_SNDTIMEO` set on connect | **RESOLVED** — 5-second send timeout configured | **RESOLVED** |
| 12 | P2 | 60 | No streaming JSON writer, full intermediate ObjectMap | file_sink | `src/file_sink.zig:161-224` | GAP-057; addressed by streaming serialize design (PR-001) | **OPEN → GAP-057** |
| 13 | P3 | 48 | 100ms sleep-loop poll in worker thread | syslog | `src/channel.zig:63-73` blocking `receive()` on condvar (`not_empty.wait`) | **RESOLVED** — sleep-loop replaced by blocking condition-variable receive | **RESOLVED** |
| 14 | P3 | 40 | isSensitiveKey called twice per sensitive field | filters | redundant call across `shouldFilterField`/redact branch | GAP-054 | **OPEN → GAP-054** |
| 15 | P3 | 40 | isSensitiveKey heap-allocates lowercase per call | filters | `src/filters.zig:46-51` stack buffer used for lowercase | **RESOLVED** — stack-buffer lowercase, no per-call heap alloc | **RESOLVED** |
| 16 | Info | 24 | errdefer missing on partial clone | events | `src/events.zig:111-129` errdefer chain frees each allocation on failure | **RESOLVED** — errdefer cleanup added | **RESOLVED** |
| 17 | Info | 16 | Ring buffer uses mutex not SPSC | syslog | hot path now uses `BoundedChannel` (`src/channel.zig`); mutex `RingBuffer` removed from the sink path | **RESOLVED (by redesign)** — `BoundedChannel` replaced `RingBuffer` in the hot path | **RESOLVED** |
| 18 | Info | 36 | Syslog worker processes max 32 msgs per 100ms cycle | syslog | the 32-msg fixed-batch code no longer exists; worker is strictly 1-item-per-`receive()` | **RESOLVED (stale)** — superseded by PR-012, which tracks the current 1-per-receive design and adds a batch primitive | **RESOLVED** |
| 19 | Info | 4 | TLS pool fields dead weight | syslog | TLS pool fields removed (GAP-027) | **RESOLVED** (already resolved) | **RESOLVED** |

## Findings by Area

### Area: app (logger orchestration + events)

| ID | Finding | PerfScore | Status |
|---|---|---|---|
| PR-004 | No per-event arena; ~70-80 alloc/free pairs per audit() | 100 | OPEN (#68) |
| PERF-001 | Triple+ JSON serialization per audit() call | 100 | OPEN (#39 / GAP-049) |
| PERF-005 | Metadata cloned 3+ times through pipeline | 80 | OPEN (GAP-049) |
| PERF-009 | serializeEventForSizeCheck builds throwaway ObjectMap | 60 | OPEN (GAP-056) |
| PERF-004 | JSON round-trip in clone() | 80 | RESOLVED |
| PERF-016 | errdefer missing on partial clone | 24 | RESOLVED |

**Root cause theme**: the audit pipeline still treats metadata as immutable across stages and uses the long-lived allocator for scratch. The per-event arena (PR-004) + single-ownership filter-once design (PERF-005/GAP-049) eliminates most of this.

### Area: app (file sink)

| ID | Finding | PerfScore | Status |
|---|---|---|---|
| PR-006 | Unbuffered writes, 2 syscalls/event | 100 | OPEN (#74) |
| PR-001 | ObjectMap rebuild + O(N·M) merge | 60 | OPEN (#59) |
| PR-008 | RFC3339 formatted 2-3x | 60 | OPEN (#80) |
| PERF-002 | fsync per event | 100 | OPEN by design (GAP-DD1) |
| PERF-008 | constant key heap-dupe | 60 | OPEN (GAP-055) |
| PERF-012 | no streaming JSON writer | 60 | OPEN (GAP-057) |
| PERF-007 | mutex held during fsync | 64 | RESOLVED (architecture) |

**Root cause theme**: the file sink lacks a userspace write buffer (PR-006) and still builds a full intermediate `ObjectMap` per event (PR-001, PERF-008/012). A buffered, streaming writer plus `receiveBatch` (PR-012) collapses these.

### Area: infra (syslog transport + channel)

| ID | Finding | PerfScore | Status |
|---|---|---|---|
| PR-012 | 1 item per receive(); no batch | 80 | OPEN (#89) |
| PR-009 | single-mutex MPSC; signal/send | 80 | OPEN (#82) |
| PR-007 | 2 send syscalls/record | 80 | OPEN (#78) |
| PR-010 | false sharing | 48 | OPEN (#86) |
| PR-013 | no multi-producer bench | 60 | OPEN (#91) |
| PERF-003 | TCP socket/handshake per message | 100 | RESOLVED |
| PERF-006 | DNS per send | 80 | RESOLVED |
| PERF-010 | UDP socket per message | 60 | RESOLVED |
| PERF-011 | no SO_SNDTIMEO | 60 | RESOLVED |
| PERF-013 | 100ms sleep-loop poll | 48 | RESOLVED |
| PERF-017 | mutex RingBuffer not SPSC | 16 | RESOLVED (redesign) |
| PERF-018 | 32-msg/100ms cap | 36 | RESOLVED (stale) |
| PERF-019 | dead TLS pool fields | 4 | RESOLVED |

**Root cause theme**: the connection-level inefficiencies (PERF-003/006/010/011/013/017/018) are resolved by the persistent-socket + DNS-cache + `BoundedChannel` redesign. The remaining open work is throughput-shaping: batched dequeue (PR-012), vectored send (PR-007), and the contention/false-sharing fixes (PR-009/010) that the new benchmark (PR-013) will guard.

### Area: app (filters)

| ID | Finding | PerfScore | Status |
|---|---|---|---|
| PR-003 | 5 sequential detectors per string | 60 | OPEN (#65) |
| PERF-014 | isSensitiveKey called twice | 40 | OPEN (GAP-054) |
| PERF-015 | isSensitiveKey heap-alloc lowercase | 40 | RESOLVED |

**Root cause theme**: detection runs unconditionally and per value (PR-003). Cheap pre-gates + filter-once shared tree address the dominant cost; the lowercase allocation (PERF-015) is already fixed via a stack buffer.

## Roadmap

### Quick Wins (< 1 day each)

| ID | Finding | Expected Impact | Effort |
|---|---|---|---|
| PR-002 | StaticStringMap for getEventName | Constant-time event-name lookup | 1 hour |
| PR-005 | Fast-path escapeCefString | Skip ArrayList on no-escape common case | 2 hours |
| PR-008 | Format RFC3339 once per event | Remove 1-2 redundant timestamp formats/event | 2 hours |
| PR-010 | Cache-line-pad hot fields | Reduce coherence misses under load | 2 hours |

### Medium (1-5 days each)

| ID | Finding | Expected Impact | Effort |
|---|---|---|---|
| PR-006 | Buffered/batched file writes | syscalls/op → ~1/batch; ns/op well below 92µs | 2 days |
| PR-012 | receiveBatch channel primitive | 1 lock + 1 syscall per batch (both workers) | 2 days |
| PR-007 | writev/sendmsg for TCP syslog | 2 → 1 send syscall/record | 1 day |
| PR-001 | Streaming JSON serialize (file sink) | Remove intermediate ObjectMap + quadratic merge | 2-3 days |
| PR-003 | Detector pre-gates + ordering | Common-case strings skip Luhn/JWT/phone scans | 2 days |
| PR-013 | Multi-producer benchmark | Gates PR-009/010/012; enables regression detection | 1-2 days |

### Strategic (> 5 days)

| ID | Finding | Expected Impact | Effort |
|---|---|---|---|
| PR-004 | Per-event arena for all scratch | 50-80% allocation reduction; simplifies hot path | 3-5 days |
| PR-009 | Reduce channel contention (MPSC) | Throughput scales with producers instead of collapsing | 3-5 days |
| PERF-001 / GAP-049 | Single-pass consolidated pipeline | Filter-once + streaming serialize across both sinks | 5-8 days |

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

| Level | Meaning | Response Time |
|---|---|---|
| P0 | SLO breach / outage risk | Immediate |
| P1 | Material user-facing impact | Within sprint |
| P2 | Moderate impact / cost | Next quarter |
| P3 | Minor optimization | Backlog |
| Info | Hardening, best practice | As capacity allows |

## Confidence Assessment

Most findings are `confidence::confirmed` from direct code evidence. Two are `confidence::suspected` pending the PR-013 multi-producer benchmark:

- **PR-009** (single-mutex MPSC collapse) — confirmed code shape (lock + signal per send), but the magnitude of collapse under multi-producer load needs measurement.
- **PR-010** (false sharing) — confirmed adjacent field layout, but the cache-line-bounce cost requires `perf stat` under the multi-producer benchmark to quantify.

## Cross-References

- **PR-001..013** → GitLab issues #59, #61, #65, #68, #71, #74, #78, #80, #82, #86, #89, #91 (this workstream).
- **GAP-049** supersedes/extends PERF-001 and PERF-005 (consolidated pipeline) — see `docs/GAP_ANALYSIS.md` (separate workstream).
- **GAP-054** ↔ PERF-014; **GAP-055** ↔ PERF-008; **GAP-056** ↔ PERF-009 (and folds in PR-014); **GAP-057** ↔ PERF-012 — see `docs/GAP_ANALYSIS.md`.
- **GAP-DD1** records the design decision to keep `sync_mode = .per_event` as the default despite batching being available (PERF-002).
- **GAP-041** folds in PR-011 (not tracked as a PR-series issue).
- PERF-019 / Q18 ↔ GAP-027 (TLS pool removal, resolved).
