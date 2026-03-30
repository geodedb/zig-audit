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
