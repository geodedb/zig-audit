# GAP Analysis -- Resolved

Items closed or dispositioned during the 2026-03-22 extraction.

## Closed

### GAP-001: Build-time product identity leaks into formatting/config [RESOLVED]

- **Issue:** N/A (resolved during extraction)
- **Category:** Bug
- **Resolution:** All `@import("build_options")` references removed. `CefIdentityConfig` now takes vendor/product/version as explicit fields passed by the consumer. `config.loadTestConfig` uses `root.version` (library constant) instead of `build_options.version`.
- **Evidence:** `grep -r 'build_options' src/` returns no matches. `src/config.zig:295` uses `root.version`.
- **Resolved date:** 2026-03-22

### GAP-004: External dependencies are implicit today [RESOLVED]

- **Issue:** N/A (resolved during extraction)
- **Category:** Bug
- **Resolution:**
  - `dns` added as an explicit dependency in `build.zig.zon` (git URL).
  - `logging` (Geode-specific slog wrapper) replaced with `std.log.scoped(.audit)`.
  - `json` (external JSON library) replaced with `std.json.Stringify.valueAlloc` and `std.json.ObjectMap`.
- **Evidence:** `build.zig.zon:6-9` declares `dns` dependency. `src/syslog.zig:11` uses `std.log.scoped(.audit)`. Library builds with only `dns` as an external dependency.
- **Resolved date:** 2026-03-22

### GAP-006: CEF escape functions are no-ops -- log injection risk [RESOLVED]

- **Issue:** [#1](https://gitlab.com/devnw/zig/audit/-/issues/1)
- **Category:** Security
- **Severity:** Critical
- **Resolution:**
  - Replaced three no-op escape functions with allocating implementations that delegate to `escapeCefString`
  - Fixed bug in `escapeCefString` where `=` was incorrectly escaped in header mode (CEF spec: `=` is only escaped in extensions)
  - Updated all call sites in `formatCef`, `addMetadataExtensions`, and `addGenericExtension` to pass allocator and handle memory
  - Added unit tests in `src/cef.zig` for header escaping, extension value escaping, and empty/clean input
  - Added integration tests in `tests/test_cef.zig` for header pipe/backslash escaping, extension equals/newline escaping, and adversarial full-pipeline test
- **Evidence:** `src/cef.zig:152-180`, `tests/test_cef.zig`. 8 new tests, all pass.
- **Resolved date:** 2026-03-22

### GAP-007: pii_mode and pci_mode config flags parsed but never enforced [RESOLVED]

- **Issue:** [#2](https://gitlab.com/devnw/zig/audit/-/issues/2)
- **Category:** Security
- **Severity:** High
- **Resolution:**
  - Wired `pii_mode` and `pci_mode` into filter pipeline via `detectValueTypeFiltered` and `redactOrMaskValue`
  - `pii_mode: mask` masks email/phone values using existing `maskEmail`/`maskPhone`
  - `pci_mode: true` scans all string values for PAN patterns
  - Value-type detection respects both modes through the redaction pipeline
- **Evidence:** `src/filters.zig` (detectValueTypeFiltered, redactOrMaskValue). Commits: 87c5e8f, df01e98.
- **Resolved date:** 2026-03-22

### GAP-008: Metadata redaction does not recurse into nested objects/arrays [RESOLVED]

- **Issue:** [#3](https://gitlab.com/devnw/zig/audit/-/issues/3)
- **Category:** Security
- **Severity:** High
- **Resolution:**
  - Refactored `filterAndRedactMetadata` into a recursive implementation with `max_redaction_depth=10`
  - Added `redactValueRecursive` to process allowed values: recurses into nested objects, scans array elements for sensitive values (PAN, JWT, email, phone, PEM keys), and applies value-type detection on strings
  - Fixed silent field drop bug: when `shouldFilterField` returns `.redact` but `isSensitiveKey` returns null, the field now gets a generic `[REDACTED]` token instead of being silently omitted
  - Added 3 tests: recursive nested object redaction, array element value-type scanning, generic redaction fallback for deny-pattern-only matches
- **Evidence:** `src/filters.zig` (filterAndRedactMetadata, redactValueRecursive). Commit: 45c2e45.
- **Resolved date:** 2026-03-22

### GAP-009: CI pipeline does not run external test files [RESOLVED]

- **Issue:** [#4](https://gitlab.com/devnw/zig/audit/-/issues/4)
- **Category:** CI-CD
- **Severity:** High
- **Resolution:** Changed CI `test` job from `zig build test` to `zig build test-all --summary all`, which runs unit, integration, CEF, filter, and transport tests in one command.
- **Evidence:** `.gitlab-ci.yml:54-63`. All 81 tests pass. Commit: df01e98.
- **Resolved date:** 2026-03-22

### GAP-010: Redaction bypass via unrecognized key names [RESOLVED]

- **Issue:** [#5](https://gitlab.com/devnw/zig/audit/-/issues/5)
- **Category:** Security
- **Severity:** High
- **Resolution:**
  - Added 7 new patterns to `isSensitiveKey` in `src/filters.zig`:
    - `"secret"` -> `.token`, `"credential"` -> `.token`, `"bearer"` -> `.token`
    - `"authorization"` -> `.token`, `"access_key"` -> `.token`
    - `"passphrase"` -> `.password`, `"pin"` -> `.card`
  - Added "expanded sensitive key detection" test verifying all new patterns including case insensitivity
- **Evidence:** `src/filters.zig:41-87`. Commit: 45c2e45.
- **Resolved date:** 2026-03-22

### GAP-011: Plaintext syslog with no encryption warning to consumers [RESOLVED]

- **Issue:** [#6](https://gitlab.com/devnw/zig/audit/-/issues/6)
- **Category:** Security
- **Severity:** Medium
- **Resolution:** Plaintext transport warning logged at `SyslogSender.init` when protocol is UDP or TCP.
- **Evidence:** `src/syslog.zig`. Commit: df01e98.
- **Resolved date:** 2026-03-22

### GAP-012: README claims Zero Dependencies -- factually incorrect [RESOLVED]

- **Issue:** [#7](https://gitlab.com/devnw/zig/audit/-/issues/7)
- **Category:** Docs
- **Severity:** Medium
- **Resolution:** Changed "Zero Dependencies: Pure Zig standard library only" to "Minimal Dependencies: Zig standard library plus a small DNS resolution library".
- **Evidence:** `README.md:10`. Commit: df01e98.
- **Resolved date:** 2026-03-22

### GAP-013: README Quick Start calls non-existent audit.init() function [RESOLVED]

- **Issue:** [#8](https://gitlab.com/devnw/zig/audit/-/issues/8)
- **Category:** Docs
- **Severity:** Medium
- **Resolution:** README Quick Start replaced with working example matching actual public API from `src/root.zig` doc comments.
- **Evidence:** `README.md`. Commit: 87c5e8f.
- **Resolved date:** 2026-03-22

### GAP-014: docs/README.md links to 5 non-existent documentation pages [RESOLVED]

- **Issue:** [#9](https://gitlab.com/devnw/zig/audit/-/issues/9)
- **Category:** Docs
- **Severity:** Low
- **Resolution:** Broken documentation links replaced with real files.
- **Evidence:** `docs/` directory. Commit: df01e98.
- **Resolved date:** 2026-03-22

### GAP-015: No file logging or syslog usage examples [RESOLVED]

- **Issue:** [#10](https://gitlab.com/devnw/zig/audit/-/issues/10)
- **Category:** Docs
- **Severity:** Medium
- **Resolution:** Working example created in `examples/basic.zig` demonstrating audit library usage.
- **Evidence:** `examples/basic.zig`. Commit: df01e98.
- **Resolved date:** 2026-03-22

### GAP-016: PRNG seeded from microTimestamp -- predictable trace/span IDs [RESOLVED]

- **Issue:** [#11](https://gitlab.com/devnw/zig/audit/-/issues/11)
- **Category:** Security
- **Severity:** Medium
- **Resolution:** Replaced `std.time.microTimestamp()` seed with `std.crypto.random.bytes()` for OS-sourced entropy. `FixedIdGen` unchanged for test determinism.
- **Evidence:** `src/time.zig:137-139`. Commit: 45c2e45.
- **Resolved date:** 2026-03-22

### GAP-017: No AuditEvent field validation [RESOLVED]

- **Issue:** [#12](https://gitlab.com/devnw/zig/audit/-/issues/12)
- **Category:** Feature
- **Severity:** Medium
- **Resolution:** Added `AuditEvent.validate()` method with 7 tests. Validates non-empty `category`, `action`, `actor_id`. Called from `AuditLogger.audit()` before processing.
- **Evidence:** `src/events.zig`. Commit: df01e98.
- **Resolved date:** 2026-03-22

### GAP-018: Config parser uses force-unwrap -- panics on malformed JSON [RESOLVED]

- **Issue:** [#13](https://gitlab.com/devnw/zig/audit/-/issues/13)
- **Category:** Bug
- **Severity:** Medium
- **Resolution:** Replaced all ~20 `.?` force-unwraps with typed helper functions (`jsonString`, `jsonInteger`, `jsonBool`, `jsonObject`, `jsonArray`) that return `error.InvalidConfig` on missing/wrong-type fields. Added 8 inline tests for missing version, invalid version type, unsupported version, missing service, missing service.name, wrong type for service.name, and valid complete config parsing.
- **Evidence:** `src/config.zig`. Commit: 87c5e8f.
- **Resolved date:** 2026-03-22

### GAP-019: freeJsonValue and cloneJsonValue duplicated across 4 files [RESOLVED]

- **Issue:** [#14](https://gitlab.com/devnw/zig/audit/-/issues/14)
- **Category:** Code Quality
- **Severity:** Low
- **Resolution:**
  - Created `src/json_util.zig` with shared `freeJsonValue` and `cloneJsonValue` functions
  - Removed local duplicates from `src/events.zig`, `src/filters.zig`, `src/file_sink.zig`, `src/logger.zig`
  - Removed local `freeJsonValue` from `tests/test_filters.zig`
  - Re-exported `json_util` through `src/root.zig` for external test access
  - Added unit tests for scalars, strings, nested objects, and arrays in `src/json_util.zig`
- **Evidence:** `src/json_util.zig`. ~170 LOC deduplication. Commit: 45c2e45.
- **Resolved date:** 2026-03-22

### GAP-022: JSON round-trip in AuditEvent.clone() [RESOLVED]

- **Issue:** [#17](https://gitlab.com/devnw/zig/audit/-/issues/17)
- **Category:** Performance
- **Severity:** Low
- **Resolution:** Replaced the three-step round-trip (serialize -> parse -> clone) in `AuditEvent.clone()` with a single `json_util.cloneJsonValue(allocator, metadata)` call. Eliminates intermediate JSON string allocation and re-parsing.
- **Evidence:** `src/events.zig`. Commit: 45c2e45.
- **Resolved date:** 2026-03-22

### GAP-023: Silent ring buffer overflow -- no alerting [RESOLVED]

- **Issue:** [#18](https://gitlab.com/devnw/zig/audit/-/issues/18)
- **Category:** Observability
- **Severity:** Medium
- **Resolution:** Added `dropped_count` atomic counter incremented on every ring buffer overflow. Warning logged on overflow. Counter exposed via public method for application monitoring.
- **Evidence:** `src/syslog.zig`. Commit: 87c5e8f.
- **Resolved date:** 2026-03-22

### GAP-024: CODEOWNERS placeholder @your-username [RESOLVED]

- **Issue:** [#19](https://gitlab.com/devnw/zig/audit/-/issues/19)
- **Category:** Config
- **Severity:** Low
- **Resolution:** Replaced `@your-username` with `@benjiv`.
- **Evidence:** `CODEOWNERS:3`. Commit: df01e98.
- **Resolved date:** 2026-03-22

### GAP-025: CHANGELOG placeholder YYYY-MM-DD [RESOLVED]

- **Issue:** [#20](https://gitlab.com/devnw/zig/audit/-/issues/20)
- **Category:** Docs
- **Severity:** Low
- **Resolution:** Replaced `YYYY-MM-DD` with `2026-03-22`. Updated boilerplate entries with actual 0.1.0 extraction feature descriptions.
- **Evidence:** `CHANGELOG.md`. Commit: df01e98.
- **Resolved date:** 2026-03-22

### GAP-026: Dead code -- unused functions never called [RESOLVED]

- **Issue:** [#21](https://gitlab.com/devnw/zig/audit/-/issues/21)
- **Category:** Code Quality
- **Severity:** Low
- **Resolution:** Removed dead code: `releasePooledConnection`, `verifyCertificatePin`, `AuditEvent.init`.
- **Evidence:** `src/syslog.zig`, `src/events.zig`. Commit: df01e98.
- **Resolved date:** 2026-03-22

### GAP-027: TLS pool struct fields allocated but unused [RESOLVED]

- **Issue:** [#22](https://gitlab.com/devnw/zig/audit/-/issues/22)
- **Category:** Code Quality
- **Severity:** Low
- **Resolution:** TLS pool fields (`tls_pool`, `pool_mutex`) removed from `SyslogSender`. No longer allocated for UDP/TCP connections.
- **Evidence:** `src/syslog.zig`. Commit: df01e98.
- **Resolved date:** 2026-03-22

### GAP-028: examples/basic.zig is placeholder not wired into build [RESOLVED]

- **Issue:** [#23](https://gitlab.com/devnw/zig/audit/-/issues/23)
- **Category:** Docs
- **Severity:** Low
- **Resolution:** `examples/basic.zig` rewritten with working audit library API usage. Wired into `build.zig` as example build step. Compiles successfully as part of build.
- **Evidence:** `examples/basic.zig`, `build.zig`. Commit: df01e98.
- **Resolved date:** 2026-03-22

### GAP-030: Missing `spice` dependency -- hand-rolled threading instead of proven concurrency library [RESOLVED]

- **Issue:** N/A
- **Category:** Architecture / Concurrency
- **Severity:** High
- **Resolution:**
  - Added `spice` as a dependency in `build.zig.zon` and wired into `build.zig`
  - Created `src/channel.zig` with `BoundedChannel(T)` — a thread-safe bounded channel with mutex + condition variable, blocking receive, and close-with-drain semantics
  - `SyslogSender` now uses `BoundedChannel` instead of `RingBuffer` + external `Mutex` + `should_stop` atomic
  - `FileSink` now uses `BoundedChannel` with a background worker thread for async I/O
  - Both sinks dispatch concurrently via independent background worker threads
  - Spice thread pool available for compute-parallel tasks; I/O workers use channel-based pattern
- **Evidence:** `build.zig.zon` (spice dependency), `src/channel.zig`, `src/syslog.zig`, `src/file_sink.zig`. 102/102 tests pass.
- **Resolved date:** 2026-03-30

### GAP-031: Sequential sink dispatch -- no parallel fan-out in logger [RESOLVED]

- **Issue:** N/A
- **Category:** Performance / Architecture
- **Severity:** Medium
- **Resolution:**
  - Both syslog and file sinks now use `BoundedChannel` + background worker threads
  - `audit()` method does two fast channel enqueues (microseconds), actual I/O happens on separate worker threads concurrently
  - Logger now attempts both sinks independently — one sink failure doesn't block the other
- **Evidence:** `src/logger.zig` (independent error handling for each sink). Both sinks process events concurrently on their own worker threads.
- **Resolved date:** 2026-03-30

### GAP-032: Syslog worker uses busy-polling with 100ms sleep [RESOLVED]

- **Issue:** N/A
- **Category:** Performance
- **Severity:** Medium
- **Resolution:**
  - Replaced `std.Thread.sleep(100ms)` polling loop with `BoundedChannel.receive()` which blocks on a condition variable
  - Worker thread wakes immediately when a message is sent, eliminating the 100ms latency floor
  - No batch size limit — worker processes each message as it arrives
  - Throughput limited only by network I/O, not polling interval
- **Evidence:** `src/syslog.zig:workerThread` — `while (self.ch.receive()) |msg|` blocks until message or close.
- **Resolved date:** 2026-03-30

### GAP-033: RingBuffer has no internal thread safety -- relies on external mutex discipline [RESOLVED]

- **Issue:** N/A
- **Category:** Correctness / Concurrency
- **Severity:** Medium
- **Resolution:**
  - `SyslogSender` replaced `RingBuffer` + external `Mutex` with `BoundedChannel` (internal mutex + condition variable)
  - `FileSink` similarly uses `BoundedChannel` for its write queue
  - `RingBuffer` documentation updated to explicitly state it is NOT thread-safe and points to `BoundedChannel` for concurrent use
  - `RingBuffer` retained for non-concurrent use cases (single-threaded batch processing)
- **Evidence:** `src/syslog.zig` (no `RingBuffer` import), `src/ring_buffer.zig` (doc comment), `src/channel.zig` (BoundedChannel with 7 tests including multi-threaded).
- **Resolved date:** 2026-03-30

### GAP-034: File sink write blocks the caller thread -- no async I/O path [RESOLVED]

- **Issue:** N/A
- **Category:** Performance
- **Severity:** Medium
- **Resolution:**
  - `FileSink.write()` now formats JSON on the caller thread, enqueues the formatted string to a `BoundedChannel`, and returns immediately
  - A dedicated background worker thread consumes from the channel and handles file I/O (write, rotation, fsync)
  - File mutex removed — only the single background worker accesses the file, eliminating contention
  - Rotation logic runs on the worker thread, correct by construction (single writer)
- **Evidence:** `src/file_sink.zig` (channel-based async write path, `workerThread` method). All file sink tests pass.
- **Resolved date:** 2026-03-30

### GAP-035: No structured shutdown or drain guarantee for background workers [RESOLVED]

- **Issue:** N/A
- **Category:** Correctness
- **Severity:** Medium
- **Resolution:**
  - Both `SyslogSender.deinit()` and `FileSink.deinit()` implement two-phase shutdown:
    1. `ch.close()` — stops accepting new messages, signals blocked receivers
    2. Worker's `receive()` loop drains all remaining messages (sends to network / writes to disk)
    3. `receive()` returns null when closed AND empty — worker exits
    4. `thread.join()` — waits for worker to finish draining
    5. Any remaining messages freed as safety net
  - `BoundedChannel.close()` + `receive()` provides the drain guarantee: receiver keeps processing until all items consumed
  - `AuditLogger.deinit()` deinits syslog first (network drain), then file (disk drain)
- **Evidence:** `src/syslog.zig:deinit`, `src/file_sink.zig:deinit`, `src/channel.zig:close/receive`. Integration tests verify drain behavior.
- **Resolved date:** 2026-03-30

### GAP-020: fsync per event in file_sink [RESOLVED]

- **Issue:** [#15](https://gitlab.com/devnw/zig/audit/-/issues/15) (closed)
- **Category:** Performance
- **Resolution:** A configurable `SyncMode` was added so callers choose per-event durability or periodic flushing instead of an unconditional `fsync` per write. Verified during the 2026-06-11 audit.
- **Evidence:** `src/config.zig:88-108` defines the `SyncMode` enum and wiring; the file sink honors it on the write path.
- **Resolved date:** 2026-06-11

### GAP-021: New socket per UDP/TCP syslog message -- no connection reuse [RESOLVED]

- **Issue:** [#16](https://gitlab.com/devnw/zig/audit/-/issues/16) (closed)
- **Category:** Performance
- **Resolution:** The syslog sender now maintains persistent UDP/TCP sockets with reconnect-on-error and caches DNS resolution instead of creating a socket and resolving the host per message. Verified during the 2026-06-11 audit.
- **Evidence:** `src/syslog.zig:107-114` (persistent socket/connection state), `src/syslog.zig:235-247` (`resolveOrCached` DNS cache).
- **Resolved date:** 2026-06-11

## 2026-06-12 Cycle Resolutions (GAP-040..074, QR-*, PR-*, PERF-001)

Commits: afcd0bc..9391d12 (branch fix/audit-remediation-2026-06-11). Verified by docs/APPSEC_REVIEW_2026-06-12_iter2.md (iter-2 appsec re-review) and independent gap-closure verification. Gate: 158 tests / 157 pass / 1 otel skip (pre-existing); ReleaseSafe/ReleaseFast green; pre-commit clean.

### GAP-040 (A1): config @intCast panic/truncation on integer fields [RESOLVED]

- **Issue:** [#57](https://gitlab.com/devnw/zig/audit/-/issues/57) (closed)
- **Resolution:** All integer config fields flow through `jsonIntegerInRange` (`std.math.cast(T,…) orelse error.InvalidConfig`) at `config.zig:239-242`; port==0 rejected at `:411`. Out-of-range sweep test `:679-732`. ReleaseSafe build passes.
- **Evidence:** `config.zig:239-242`, `config.zig:679-732`
- **Resolved date:** 2026-06-12

### GAP-041 (A2): file-sink drops audit records silently under backpressure [RESOLVED]

- **Issue:** [#58](https://gitlab.com/devnw/zig/audit/-/issues/58) (closed)
- **Resolution:** `file_sink.zig:39` dropped_count atomic; `enqueueLine :96-105` counts + rate-limited warn; `getDroppedCount :89`; write/writeError return SendStatus. `logger.zig:185-215` sets span_durable=false on any drop.
- **Evidence:** `file_sink.zig:39,89,96-105`, `logger.zig:185-215`, tests `:1386-1435`
- **Resolved date:** 2026-06-12

### GAP-042 (A3): control characters unescaped in CEF/syslog output [RESOLVED]

- **Issue:** [#60](https://gitlab.com/devnw/zig/audit/-/issues/60) (closed)
- **Resolution:** `cef.zig:272` escapes 0x00..0x1F and 0x7F to `\xNN`; fast-path `needsCefEscape :288-291`; escape-ordering argument `:247-253`.
- **Evidence:** `cef.zig:247-291`, tests `test_cef.zig:331-343`, `cef.zig:401-418`
- **Resolved date:** 2026-06-12

### GAP-043 (A4): path-traversal mitigation incomplete [RESOLVED (residual documented)]

- **Issue:** [#62](https://gitlab.com/devnw/zig/audit/-/issues/62) (closed)
- **Resolution:** `file_sink.zig:420-466` component-wise `..` reject + allowed_base_dir jail + isUnderBase separator-boundary check; empty-base fail-closed `:459`. Symlink-parent limitation documented `config.zig:117-131`; abs-path notice `file_sink.zig:442-447`.
- **Evidence:** `file_sink.zig:420-466`, `config.zig:117-131`, tests `:1214-1384`
- **Resolved date:** 2026-06-12

### GAP-044 (A5): formatRfc3339 panics on negative timestamp [RESOLVED]

- **Issue:** [#63](https://gitlab.com/devnw/zig/audit/-/issues/63) (closed)
- **Resolution:** `time.zig:51` returns `""` for negative timestamps; `:53` year-9999 guard; `:57` `std.math.cast(u64,…) orelse ""`.
- **Evidence:** `time.zig:51-57`, tests `:288-305`
- **Resolved date:** 2026-06-12

### GAP-046 (A7): event ts_unix_ms never rendered; output timestamp is worker-thread now [RESOLVED]

- **Issue:** [#66](https://gitlab.com/devnw/zig/audit/-/issues/66) (closed)
- **Resolution:** Authoritative event ts rendered at `file_sink.zig:313-316`, `cef.zig:27-30`, `syslog.zig:200-203`, `:373-376`. Clock fallback only for unstamped (ts==0) direct calls.
- **Evidence:** `file_sink.zig:313-316`, `cef.zig:27-30`, `syslog.zig:200-203`
- **Resolved date:** 2026-06-12

### GAP-047 (A8): validate() does not reject control characters in core fields [RESOLVED]

- **Issue:** [#67](https://gitlab.com/devnw/zig/audit/-/issues/67) (closed)
- **Resolution:** `events.zig:128-132` `checkNoControlChars` (<0x20 or 0x7F) applied to core fields `:118` and optional fields `:121`.
- **Evidence:** `events.zig:118-132`, tests `:282-315`
- **Resolved date:** 2026-06-12

### GAP-048: cloneJsonValue missing errdefer on partial clone (OOM leak) [RESOLVED]

- **Issue:** [#69](https://gitlab.com/devnw/zig/audit/-/issues/69) (closed)
- **Resolution:** `json_util.zig:54-65, 72-89` errdefer frees partial array/object clones. FailingAllocator sweep test `:162-203`.
- **Evidence:** `json_util.zig:54-89`, test `:162-203`
- **Resolved date:** 2026-06-12

### GAP-049: metadata deep-copied 4x through the pipeline [RESOLVED]

- **Issue:** [#70](https://gitlab.com/devnw/zig/audit/-/issues/70) (closed)
- **Resolution:** Single-copy metadata pipeline -- `audit()` filters once into one redacted tree, moves onto the event clone (`logger.zig:254-277`). Each sink serializes into its own owned `[]const u8` before returning. Exactly one deferred `freeCloned` owns the tree. Baseline: 3004 -> 32717 ops/sec at 10K tier.
- **Evidence:** `logger.zig:125,254-276`, `file_sink.zig:308-372`
- **Resolved date:** 2026-06-12

### GAP-050: PiiMode.hash unhandled, silently degrades to no-op [RESOLVED]

- **Issue:** [#72](https://gitlab.com/devnw/zig/audit/-/issues/72) (closed)
- **Resolution:** `filters.zig:295-300` hashValue (SHA-256, `sha256:`+16 hex); applied value-path `:312-314` and key-token path `:432-438`. Unkeyed-hash limitation documented `:286-294`.
- **Evidence:** `filters.zig:286-314,432-438`, tests `test_filters.zig:1041-1099`
- **Resolved date:** 2026-06-12

### GAP-051: TCP length-prefix heap allocation per syslog send [RESOLVED]

- **Issue:** [#73](https://gitlab.com/devnw/zig/audit/-/issues/73) (closed)
- **Resolution:** `syslog.zig:329-332` formats octet-count prefix into stack buffer `[24]u8` instead of allocating. Note: the 2-sendto-call pattern was not consolidated to writev in this cycle; PR-007 (#78) remains open for that.
- **Evidence:** `syslog.zig:329-332`
- **Resolved date:** 2026-06-12

### GAP-052: double CEF escaping of actor_id/request_id [RESOLVED]

- **Issue:** [#75](https://gitlab.com/devnw/zig/audit/-/issues/75) (closed)
- **Resolution:** Fields escaped once at format time; double-escape path eliminated in the CEF/syslog pipeline rewrite.
- **Evidence:** `cef.zig` + `syslog.zig` rewrite (commit 89a0780)
- **Resolved date:** 2026-06-12

### GAP-053: ObjectMap built without capacity hint [RESOLVED]

- **Issue:** [#76](https://gitlab.com/devnw/zig/audit/-/issues/76) (closed)
- **Resolution:** Intermediate ObjectMap eliminated entirely -- file sink now streams JSON directly via std.json.Stringify without building an ObjectMap.
- **Evidence:** `file_sink.zig:308-372` (commit 412cc14)
- **Resolved date:** 2026-06-12

### GAP-054: detectValueType called twice per value [RESOLVED]

- **Issue:** [#77](https://gitlab.com/devnw/zig/audit/-/issues/77) (closed)
- **Resolution:** detectValueType called once per field via cached result; dual-call pattern eliminated.
- **Evidence:** `filters.zig` (commit 57852e2)
- **Resolved date:** 2026-06-12

### GAP-055: constant JSON key string heap-duped per line [RESOLVED]

- **Issue:** [#79](https://gitlab.com/devnw/zig/audit/-/issues/79) (closed)
- **Resolution:** Streaming JSON writer uses comptime string literals directly; no per-line heap dupe.
- **Evidence:** `file_sink.zig:308-372` (commit 412cc14)
- **Resolved date:** 2026-06-12

### GAP-056: serialize-to-measure in estimateEventSize [RESOLVED]

- **Issue:** [#81](https://gitlab.com/devnw/zig/audit/-/issues/81) (closed)
- **Resolution:** estimateEventSize replaced by counting writer that streams and counts bytes in one pass; no throwaway ObjectMap.
- **Evidence:** `file_sink.zig` (commit 412cc14)
- **Resolved date:** 2026-06-12

### GAP-057: no streaming JSON writer in file sink [RESOLVED]

- **Issue:** [#83](https://gitlab.com/devnw/zig/audit/-/issues/83) (closed)
- **Resolution:** `formatJsonLine` streams through std.json.Stringify (`file_sink.zig:323-367`) directly. Metadata-key collision resolves with "metadata wins" deterministically (`streamFixedField :293-299`). Characterization test `:710-810`.
- **Evidence:** `file_sink.zig:293-367`, test `:710-810`
- **Resolved date:** 2026-06-12

### GAP-058: audit() is 129 lines [RESOLVED]

- **Issue:** [#84](https://gitlab.com/devnw/zig/audit/-/issues/84) (closed)
- **Resolution:** `audit()` decomposed into focused helper functions; public surface trimmed (commit 716e34b).
- **Evidence:** `logger.zig`, `config.zig` (commit 716e34b)
- **Resolved date:** 2026-06-12

### GAP-059: parseConfig is 112 lines [RESOLVED]

- **Issue:** [#85](https://gitlab.com/devnw/zig/audit/-/issues/85) (closed)
- **Resolution:** `parseConfig` decomposed and reduced (commit 716e34b).
- **Evidence:** `config.zig` (commit 716e34b)
- **Resolved date:** 2026-06-12

### GAP-060: complex redaction control flow [RESOLVED]

- **Issue:** [#87](https://gitlab.com/devnw/zig/audit/-/issues/87) (closed)
- **Resolution:** Redaction control flow simplified and decomposed (commit 716e34b).
- **Evidence:** `filters.zig` (commit 716e34b)
- **Resolved date:** 2026-06-12

### GAP-061: unreachable PEM branch in filters [RESOLVED]

- **Issue:** [#88](https://gitlab.com/devnw/zig/audit/-/issues/88) (closed)
- **Resolution:** `filters.zig:560-562` isPemPrivateKey triggers drop_event; documented asymmetry vs value-only PEM `:550-559`.
- **Evidence:** `filters.zig:550-562`, test `logger.zig:709-758`
- **Resolved date:** 2026-06-12

### GAP-062: unused pub helpers exported [RESOLVED]

- **Issue:** [#90](https://gitlab.com/devnw/zig/audit/-/issues/90) (closed)
- **Resolution:** Unused pub helpers removed from public surface; RingBuffer removed from public API (`root.zig`).
- **Evidence:** `root.zig`, commits cb07dae + 716e34b
- **Resolved date:** 2026-06-12

### GAP-063: umask race before setPermissions(0o640) [RESOLVED]

- **Issue:** [#92](https://gitlab.com/devnw/zig/audit/-/issues/92) (closed)
- **Resolution:** `file_sink.zig:509-515` sets 0o640 at createFile via permissions parameter; post-hoc normalize `:521-528` only after restrictive creation.
- **Evidence:** `file_sink.zig:509-528`, test `:1180-1212`
- **Resolved date:** 2026-06-12

### GAP-064: CI components and pre-commit hooks pinned to mutable tags [RESOLVED]

- **Issue:** [#93](https://gitlab.com/devnw/zig/audit/-/issues/93) (closed)
- **Resolution:** CI components and pre-commit hooks pinned to SHA digests.
- **Evidence:** `.gitlab-ci.yml`, `.pre-commit-config.yaml` (commit 14ee8bc)
- **Resolved date:** 2026-06-12

### GAP-065: zig toolchain single-origin trust [RESOLVED]

- **Issue:** [#94](https://gitlab.com/devnw/zig/audit/-/issues/94) (closed)
- **Resolution:** Zig toolchain single-origin trust documented; CI toolchain pinning improved.
- **Evidence:** `.gitlab-ci.yml` (commit 14ee8bc)
- **Resolved date:** 2026-06-12

### GAP-066: pkg_hash path-join unsanitized [RESOLVED]

- **Issue:** [#95](https://gitlab.com/devnw/zig/audit/-/issues/95) (closed)
- **Resolution:** Input validated in `scripts/sync_diamond_deps.py:80`; list-form subprocess.run confirmed repo-wide (no shell=True).
- **Evidence:** `scripts/sync_diamond_deps.py:80` (commit 24b782e)
- **Resolved date:** 2026-06-12

### GAP-067: parse_target unhandled ValueError [RESOLVED]

- **Issue:** [#96](https://gitlab.com/devnw/zig/audit/-/issues/96) (closed)
- **Resolution:** parse_target ValueError now handled; raises on malformed input.
- **Evidence:** `scripts/sync_diamond_deps.py` (commit 24b782e)
- **Resolved date:** 2026-06-12

### GAP-068: rewrite_pin no quoting guard [RESOLVED]

- **Issue:** [#97](https://gitlab.com/devnw/zig/audit/-/issues/97) (closed)
- **Resolution:** rewrite_pin now has quoting guards; input validation added.
- **Evidence:** `scripts/sync_diamond_deps.py` (commit 24b782e)
- **Resolved date:** 2026-06-12

### GAP-069: integration.zig missing from gitleaks allowlist [RESOLVED]

- **Issue:** [#98](https://gitlab.com/devnw/zig/audit/-/issues/98) (closed)
- **Resolution:** `tests/integration.zig` test fixture strings added to gitleaks allowlist.
- **Evidence:** `.gitleaks.toml` (commit 14ee8bc)
- **Resolved date:** 2026-06-12

### GAP-070: no CI cache (zig binary + .zig-cache) [RESOLVED]

- **Issue:** [#99](https://gitlab.com/devnw/zig/audit/-/issues/99) (closed)
- **Resolution:** CI caches added for zig binary and .zig-cache.
- **Evidence:** `.gitlab-ci.yml` (commit 14ee8bc)
- **Resolved date:** 2026-06-12

### GAP-071: no ruff/typecheck CI gate for scripts [RESOLVED]

- **Issue:** [#100](https://gitlab.com/devnw/zig/audit/-/issues/100) (closed)
- **Resolution:** ruff and Python typecheck CI gate added for scripts/.
- **Evidence:** `.gitlab-ci.yml` (commit 14ee8bc)
- **Resolved date:** 2026-06-12

### GAP-072 (Q11): requestId catch returns empty string on OOM [RESOLVED]

- **Issue:** [#101](https://gitlab.com/devnw/zig/audit/-/issues/101) (closed)
- **Resolution:** requestId vtable method removed from IdGen entirely -- `time.zig:124-127` IdGen.VTable has only traceId/spanId; the OOM-swallowing implementation was removed with the method.
- **Evidence:** `time.zig:124-127` (commit 365aeb9)
- **Resolved date:** 2026-06-12

### GAP-073 (Q19): requestId vtable still present though doc says removed [RESOLVED]

- **Issue:** [#102](https://gitlab.com/devnw/zig/audit/-/issues/102) (closed)
- **Resolution:** requestId vtable field, dispatch, and impls removed from IdGen. `time.zig:124-127` IdGen.VTable now has only traceId/spanId.
- **Evidence:** `time.zig:124-127` (commit 365aeb9)
- **Resolved date:** 2026-06-12

### GAP-074: version drift root.zig 0.1.0 vs zon 0.1.6 [RESOLVED]

- **Issue:** [#103](https://gitlab.com/devnw/zig/audit/-/issues/103) (closed)
- **Resolution:** `root.zig:39` aliases `build_options.package_version` injected from `@import("build.zig.zon").version` (`build.zig:29`).
- **Evidence:** `root.zig:39`, `build.zig:29` (commit f875548)
- **Resolved date:** 2026-06-12

### GAP-DD1: sync_mode default .per_event vs .periodic (design decision) [RESOLVED-BY-DECISION]

- **Issue:** [#104](https://gitlab.com/devnw/zig/audit/-/issues/104) (closed)
- **Resolution:** Design decision documented. sync_mode default stays .per_event; durability/throughput tradeoff documented in README and config.zig. Batching available via .periodic mode.
- **Evidence:** `config.zig` (commit 84c976d), README
- **Resolved date:** 2026-06-12

### QR-001: use-after-return in buildAuditLogger (SystemClock/SystemIdGen) [RESOLVED]

- **Issue:** [#105](https://gitlab.com/devnw/zig/audit/-/issues/105) (closed)
- **Resolution:** `logger.zig:347-360` heap-allocates SystemClock/SystemIdGen, transfers ownership (owned_system_clock/owned_system_id_gen `:29-30`), freed in deinit `:80-85`.
- **Evidence:** `logger.zig:29-30,80-85,347-360`, test `:364-396`
- **Resolved date:** 2026-06-12

### QR-002: double-free/UAF when metadata is non-object [RESOLVED]

- **Issue:** [#106](https://gitlab.com/devnw/zig/audit/-/issues/106) (closed)
- **Resolution:** `filters.zig:398` else branch deep-copies non-object metadata via json_util.cloneJsonValue.
- **Evidence:** `filters.zig:398`, test `logger.zig:612-627`
- **Resolved date:** 2026-06-12

### QR-003: truncation path frees string literals [RESOLVED]

- **Issue:** [#107](https://gitlab.com/devnw/zig/audit/-/issues/107) (closed)
- **Resolution:** `logger.zig:158-179` heap-dupes `_truncated`/`_original_size` keys with errdefer cleanup.
- **Evidence:** `logger.zig:158-179`, test `:760-788`
- **Resolved date:** 2026-06-12

### QR-004: Config pass-by-value double-free trap [RESOLVED]

- **Issue:** [#108](https://gitlab.com/devnw/zig/audit/-/issues/108) (closed)
- **Resolution:** buildAuditLogger takes Config by value; heap-owned clock/idgen transferred to logger; ownership documented.
- **Evidence:** `logger.zig` (commit 5af9f06)
- **Resolved date:** 2026-06-12

### QR-005: span_durable reports durable=true even when both sinks dropped [RESOLVED]

- **Issue:** [#109](https://gitlab.com/devnw/zig/audit/-/issues/109) (closed)
- **Resolution:** `logger.zig:185-215` sets span_durable=false on any drop; dropped_count exposed.
- **Evidence:** `logger.zig:185-215`, `file_sink.zig:39,89`, tests `file_sink.zig:1386-1435`
- **Resolved date:** 2026-06-12

### QR-007: RingBuffer dead code exported as public API [RESOLVED]

- **Issue:** [#115](https://gitlab.com/devnw/zig/audit/-/issues/115) (closed)
- **Resolution:** RingBuffer removed from public API (`root.zig`).
- **Evidence:** `root.zig` (commit cb07dae)
- **Resolved date:** 2026-06-12

### QR-009: rotation size accounting off-by-one [RESOLVED]

- **Issue:** [#117](https://gitlab.com/devnw/zig/audit/-/issues/117) (closed)
- **Resolution:** `file_sink.zig:259-263` line owns its newline; rotation checks before write.
- **Evidence:** `file_sink.zig:259-263`, test `:593-633`
- **Resolved date:** 2026-06-12

### QR-010: resolveOrCached i128->i64 @intCast [RESOLVED]

- **Issue:** [#118](https://gitlab.com/devnw/zig/audit/-/issues/118) (closed)
- **Resolution:** `syslog.zig:253-254` saturating `std.math.cast(i64,…) orelse maxInt/minInt`.
- **Evidence:** `syslog.zig:253-254`, test `:686-726`
- **Resolved date:** 2026-06-12

### QR-011: isSensitiveKey treats keys >256 bytes as not sensitive [RESOLVED]

- **Issue:** [#110](https://gitlab.com/devnw/zig/audit/-/issues/110) (closed)
- **Resolution:** `filters.zig:56-117` matches case-insensitively against the full key; no 256-byte buffer truncation.
- **Evidence:** `filters.zig:56-117` (commit a17fe8c)
- **Resolved date:** 2026-06-12

### QR-012: missing negative/boundary tests [RESOLVED]

- **Issue:** [#111](https://gitlab.com/devnw/zig/audit/-/issues/111) (closed)
- **Resolution:** Negative/boundary tests added across QR-001/002/003 and GAP-041 -- channel-full drop tests (`file_sink.zig:1386-1435`), truncation tests (`logger.zig:760-788`), non-object metadata tests (`logger.zig:612-627`), buildAuditLogger UAR test (`logger.zig:364-396`).
- **Evidence:** Multiple test locations cited above
- **Resolved date:** 2026-06-12

### QR-013: integration tests pass even when nothing written [RESOLVED]

- **Issue:** [#119](https://gitlab.com/devnw/zig/audit/-/issues/119) (closed)
- **Resolution:** `tests/integration.zig:126-133, 265-271, 329-335` read after drain and `expect(content.len > 0)`.
- **Evidence:** `tests/integration.zig:126-133,265-271,329-335` (commit fb95a1c)
- **Resolved date:** 2026-06-12

### QR-014: shared mutable tmpdir across test files [RESOLVED]

- **Issue:** [#120](https://gitlab.com/devnw/zig/audit/-/issues/120) (closed)
- **Resolution:** Rotation test uses isolated tmpdir helper; shared mutable tmpdir eliminated.
- **Evidence:** `src/file_sink.zig` (commit 8d27d41)
- **Resolved date:** 2026-06-12

### QR-015: SECURITY.md claims No-UB / compile-time memory safety [RESOLVED]

- **Issue:** [#112](https://gitlab.com/devnw/zig/audit/-/issues/112) (closed)
- **Resolution:** SECURITY.md updated to reflect actual guarantees -- no longer claims blanket No-UB / compile-time memory safety.
- **Evidence:** `SECURITY.md` (commit e5f0e98)
- **Resolved date:** 2026-06-12

### QR-016: README claims Zig 0.15.1+, build requires 0.16.0 [RESOLVED]

- **Issue:** [#113](https://gitlab.com/devnw/zig/audit/-/issues/113) (closed)
- **Resolution:** README updated -- now correctly states Zig 0.16.0 requirement and documents TLS requires stunnel.
- **Evidence:** `README.md` (commit e5f0e98)
- **Resolved date:** 2026-06-12

### PR-001: ObjectMap rebuild / O(N*M) merge in file sink [RESOLVED]

- **Issue:** [#59](https://gitlab.com/devnw/zig/audit/-/issues/59) (closed)
- **Resolution:** Streaming JSON serialization -- `formatJsonLine` streams through std.json.Stringify, eliminating intermediate ObjectMap rebuild.
- **Evidence:** `file_sink.zig:293-367` (commit 412cc14)
- **Resolved date:** 2026-06-12

### PR-005: escapeCefString always allocates even with no escaping [RESOLVED]

- **Issue:** [#71](https://gitlab.com/devnw/zig/audit/-/issues/71) (closed)
- **Resolution:** Scan-first fast path; no ArrayList growth on the no-escape common case.
- **Evidence:** `cef.zig` (commit 89a0780)
- **Resolved date:** 2026-06-12

### PR-006: unbuffered file writes -- 2 syscalls/event, no batching [RESOLVED]

- **Issue:** [#74](https://gitlab.com/devnw/zig/audit/-/issues/74) (closed)
- **Resolution:** Buffered/batched file writes -- single write per record; batch worker drain. .per_event: one write+fsync per line; .periodic: counts records; rotation checked before each buffered line.
- **Evidence:** `file_sink.zig` (commits e4f5da3 + a0c0d4e)
- **Resolved date:** 2026-06-12

### PR-008: RFC3339 timestamp formatted 2-3x per event [RESOLVED]

- **Issue:** [#80](https://gitlab.com/devnw/zig/audit/-/issues/80) (closed)
- **Resolution:** Timestamp formatted once per event -- SyslogSender.send formats ts once, shares with CEF payload and RFC5424 header (`syslog.zig:200-207`). File sink uses event ts at `file_sink.zig:313-316`.
- **Evidence:** `syslog.zig:200-207`, `file_sink.zig:313-316` (commit 89a0780)
- **Resolved date:** 2026-06-12

### PR-010: false sharing -- dropped_count adjacent to hot fields; channel head/tail [RESOLVED (partial -- remainder in #82)]

- **Issue:** [#86](https://gitlab.com/devnw/zig/audit/-/issues/86) (closed)
- **Resolution:** Empty-transition signaling (`channel.zig:72-79` signal only on 0->1) and cache-line layout isolation of producer/consumer cursors (`:33-42`) done. Full false-sharing quantification and remaining contention work folded into #82 (PR-009).
- **Evidence:** `channel.zig:33-42,72-79` (commit 5d3704f)
- **Resolved date:** 2026-06-12

### PR-012: worker drains one item per receive(); no batch primitive [RESOLVED]

- **Issue:** [#89](https://gitlab.com/devnw/zig/audit/-/issues/89) (closed)
- **Resolution:** Batch worker drain implemented. .per_event never coalesces; .periodic counts records; rotation checked before each buffered line. 50-line cross-rotation test `:1098-1178`.
- **Evidence:** `file_sink.zig:1098-1178` (commits a0c0d4e + 5d3704f)
- **Resolved date:** 2026-06-12

### PR-013: no multi-producer benchmark [RESOLVED]

- **Issue:** [#91](https://gitlab.com/devnw/zig/audit/-/issues/91) (closed)
- **Resolution:** Multi-producer bench added with 1/2/4/8/16-producer scenarios; gates PR-009/010/012.
- **Evidence:** `benchmarks/` (commit 5d3704f)
- **Resolved date:** 2026-06-12

### PERF-001: triple+ JSON serialization per audit() call [RESOLVED]

- **Issue:** [#39](https://gitlab.com/devnw/zig/audit/-/issues/39) (closed)
- **Resolution:** Single-copy metadata pipeline (GAP-049 + GAP-057). Filter once per audit(); streaming serialize per sink. `logger.zig:125,254-276`; `file_sink.zig:308-372`. Baseline 3004 -> 32717 ops/sec at 10K tier.
- **Evidence:** `logger.zig:125,254-276`, `file_sink.zig:308-372`
- **Resolved date:** 2026-06-12

## Won't Do

### GAP-002: Geode DB adapter is mixed into the same package tree [WON'T DO]

- **Issue:** N/A (Geode-side task)
- **Category:** Feature
- **Resolution:** `db_adapter.zig` is Geode-specific persistence code. By design, it stays in Geode. Geode should import this library for the core audit surface and keep only the DB adapter locally.
- **Evidence:** `db_adapter.zig` is not present in this repository.
- **Resolved date:** 2026-03-22

### GAP-003: Duplicate audit stack exists under `src/security` [WON'T DO]

- **Issue:** N/A (Geode-side task)
- **Category:** Feature
- **Resolution:** This is a Geode-side reconciliation task. The canonical audit source is now this library. Geode should redirect `src/security/audit*.zig` to import from here, but that refactoring belongs in the Geode repo.
- **Evidence:** No `src/security/` directory exists in this repository.
- **Resolved date:** 2026-03-22
