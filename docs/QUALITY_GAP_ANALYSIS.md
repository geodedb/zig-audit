# Quality Gap Analysis

Last updated: 2026-06-12

Repository: `gitlab.com/devnw/zig/audit`
Branch: `main`
Source: Deep quality review of all source modules and test files; refreshed against current code by the 2026-06-11 full audit.

---

## Summary

| Severity | Open | Partial | Resolved | Total |
|----------|------|---------|----------|-------|
| Critical | 0 | 0 | 2 (Q1, Q2) | 2 |
| High     | 0 | 0 | 5 (Q3, Q4, Q5, Q6, Q7) | 5 |
| Medium   | 0 | 0 | 8 (Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15) | 8 |
| Low      | 0 | 1 (Q16) | 5 (Q17, Q18, Q19, Q20, Q21) | 6 |
| **Total** | **0** | **1** | **20** | **21** |

**All Critical and High findings are resolved. 20 of 21 findings resolved; 1 partial (Q16).**

*2026-06-12 update:* Q11 (GAP-072) and Q19 (GAP-073) resolved by removal of the `requestId` vtable method from IdGen entirely (`time.zig:124-127`, commit 365aeb9). Q16 remains partial: `RingBuffer` extracted, but `src/syslog.zig` is now 775 LOC (was 652) due to persistent-socket and batch-drain additions -- further decomposition still pending. QR-001..003 Criticals (memory safety) closed.

### Remaining Partial

1. **Q16 (Low, partial)**: `src/syslog.zig` now 775 LOC (grown from 652 due to remediation additions). RingBuffer was extracted; further decomposition of SyslogSender/MockSyslogSender deferred.

---

## Stack-Ranked Findings

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Evidence | Issue | Fix Summary | Owner | ETA | Status |
|------|-----|----------|---------------|----------|---------|-----------|----------|-------|-------------|-------|-----|--------|
| 1 | Q1 | Critical | 100 | api-contract | CEF escape functions are no-ops | `src/cef.zig` | `escapeHeader`, `escapeValue`, `escapeKey` at lines 152-162 return input unmodified; `escapeCefString` exists at line 164 but is never called | GAP-006 | Replaced no-op escapes with allocating implementations; 8 new tests | @benjiv | S | **resolved** |
| 2 | Q2 | Critical | 100 | architecture | IdGen vtable dispatch passes wrong pointer as context | `src/time.zig` | Lines 115-125: `self.vtable.traceId(@ptrCast(@constCast(self.vtable)), buf)` passes the vtable address, not the struct address; impl functions cast this to `*SystemIdGen` -- UB | -- | Add a `context: *anyopaque` field to `IdGen` (like `Clock` already has) and pass it instead of the vtable pointer | TBD | S | resolved |
| 3 | Q5 | High | 80 | architecture | Config parser panics on malformed JSON | `src/config.zig` | 24 `.?` force-unwrap sites in `parseConfig` (lines 187-252); any missing or wrong-typed field triggers unreachable panic | GAP-018 | Replaced all force-unwraps with typed helpers; 8 inline tests | @benjiv | M | **resolved** |
| 4 | Q4 | High | 80 | api-contract | Redaction silently drops fields on deny-pattern match without sensitive-key match | `src/filters.zig` | Lines 266-271: when `shouldFilterField` returns `.redact` but `isSensitiveKey` returns `null`, the field is silently omitted from output | GAP-008 | Fixed: generic `[REDACTED]` token used when isSensitiveKey returns null | @benjiv | S | **resolved** |
| 5 | Q6 | High | 64 | maintainability | File rotation silently swallows rename errors | `src/file_sink.zig` | Rotation errors now logged: `src/file_sink.zig:248-258` uses `catch \|err\| log.warn(...)` instead of `catch {}` | -- | Rotation failures emit a warning via `log.warn` | @benjiv | S | **resolved** |
| 6 | Q3 | High | 60 | maintainability | freeJsonValue duplicated 3x, cloneJsonValue duplicated 4x | `src/events.zig`, `src/file_sink.zig`, `src/filters.zig`, `src/logger.zig` | Identical `freeJsonValue` at events.zig:87, file_sink.zig:99, logger.zig:205; identical `cloneJsonValue` at events.zig:140, file_sink.zig:189, filters.zig:320, logger.zig:177 (~180 LOC total) | -- | Extract into a shared `json_util.zig` module; import from all consumers | TBD | S | resolved |
| 7 | Q7 | High | 60 | tests | No test coverage for config parsing error paths | `src/config.zig`, `tests/` | Zero test files reference `loadConfig`, `parseConfig`, `ConfigNotFound`, `InvalidJson`, or `MissingVersion`; 24 panic-prone unwrap sites are untested | GAP-018 | 8 inline tests added covering all error paths | @benjiv | M | **resolved** |
| 8 | Q8 | Medium | 48 | maintainability | nowRfc3339Impl duplicated between SystemClock and FixedClock | `src/time.zig` | Shared `formatRfc3339` helper now used by both clocks: `src/time.zig:40` | -- | Single shared `formatRfc3339` helper; no duplication | @benjiv | S | **resolved** |
| 9 | Q9 | Medium | 48 | maintainability | formatRfc5424 logic duplicated between SyslogSender and MockSyslogSender | `src/syslog.zig` | Standalone shared `formatRfc5424` at `src/syslog.zig:347`, called from both SyslogSender and MockSyslogSender | -- | Single shared `formatRfc5424` function | @benjiv | S | **resolved** |
| 10 | Q11 | Medium | 48 | api-contract | requestIdImpl returns "" on OOM instead of error | `src/time.zig` | Line 163: `catch ""` on `allocPrint`; line 201: `catch ""` on `allocator.dupe`; callers cannot distinguish OOM from a legitimate empty ID | -- | requestId vtable method removed entirely from IdGen | TBD | S | **resolved** (GAP-072/GAP-073 -- vtable method removed, commit 365aeb9) |
| 11 | Q10 | Medium | 36 | readability | escapeCefString has redundant = handling in both branches | `src/cef.zig` | Line 172: `'=' => if (is_header) try result.appendSlice(allocator, "\\=") else try result.appendSlice(allocator, "\\=")` -- both branches do the same thing | GAP-006 | Fixed during CEF escape rewrite: = only escaped in extensions per spec | @benjiv | S | **resolved** |
| 12 | Q13 | Medium | 36 | perf | truncateEvent result allocated and immediately freed | `src/logger.zig` | `truncateEvent` removed; truncation handled inline at `src/logger.zig:165-175` with no throwaway allocation | -- | Dead `truncateEvent` call removed | @benjiv | S | **resolved** |
| 13 | Q12 | Medium | 24 | cleanup | Dead AuditEvent.init() and deinit() methods | `src/events.zig` | Lines 62-85: `init` takes an allocator it ignores; `deinit` is never called (callers use `freeCloned`); zero references in codebase | GAP-026 | Dead AuditEvent.init removed | @benjiv | S | **resolved** |
| 14 | Q14 | Medium | 24 | docs | 8 of 9 source files lack module-level doc comments | `src/*.zig` | All source modules now carry `//!` headers (verified: cef, config, events, file_sink, filters, logger, syslog, time, channel, sync, json_util, ring_buffer, observability, root, ...) | -- | `//!` module docs added to every source file | @benjiv | M | **resolved** |
| 15 | Q15 | Medium | 20 | readability | Missing explanatory comments on non-obvious filter logic | `src/filters.zig` | Explanatory comment now present at `src/filters.zig:466` explaining the negated `isPemPrivateKey` / `-----BEGIN` guard | -- | Comment added explaining the forward-looking PEM guard | @benjiv | S | **resolved** |
| 16 | Q16 | Low | 16 | architecture | syslog.zig has multiple types in one file | `src/syslog.zig` | `RingBuffer` extracted to `src/ring_buffer.zig`; however `src/syslog.zig` is now 775 LOC (grown from 652 due to remediation additions) -- further decomposition pending | -- | RingBuffer extracted; remaining decomposition of SyslogSender/MockSyslogSender deferred | @benjiv | S | **partial** |
| 17 | Q17 | Low | 16 | readability | formatJsonLine repetitive field insertion | `src/file_sink.zig` | `putField` helper extracted (`src/file_sink.zig:150`); `formatJsonLine` now calls `self.putField(...)` instead of repeating the dupe+put pattern | -- | `putField` helper added; repetition removed | @benjiv | S | **resolved** |
| 18 | Q18 | Low | 12 | cleanup | Dead TLS pool management code | `src/syslog.zig` | Lines 238-271: `releasePooledConnection` and `verifyCertificatePin` are never called; TLS transport returns `error.TlsNotImplemented` | GAP-026/027 | Dead functions and TLS pool fields removed | @benjiv | S | **resolved** |
| 19 | Q19 | Low | 12 | cleanup | Dead IdGen.requestId vtable method | `src/time.zig` | requestId vtable field, dispatch, and impls removed. `time.zig:124-127` IdGen.VTable now has only traceId/spanId. | GAP-073 | Removed requestId from the IdGen vtable and impls (commit 365aeb9) | @benjiv | S | **resolved** |
| 20 | Q20 | Low | 8 | cleanup | ErrorLogJson struct used only for default values | `src/file_sink.zig` | `ErrorLogJson` removed -- grep finds zero references in `src/`; error-log defaults inlined | -- | Struct removed; defaults inlined | @benjiv | S | **resolved** |
| 21 | Q21 | Low | 8 | docs | Placeholder example not wired into build | `examples/basic.zig` | 24-line file prints "Example completed successfully!" with commented-out audit usage; not referenced in `build.zig` | GAP-028 | Working example wired into build.zig | @benjiv | M | **resolved** |

---

## Findings by Category

### Security / API Contract (Q1, Q4, Q11)

| ID | Severity | Summary |
|----|----------|---------|
| Q1 | Critical | CEF escape no-ops -- log injection in all CEF output |
| Q4 | High | Redaction drops fields silently on deny-pattern match without sensitive-key recognition |
| Q11 | Medium | requestIdImpl swallows OOM, returns "" |

### Architecture / Correctness (Q2, Q5)

| ID | Severity | Summary |
|----|----------|---------|
| Q2 | Critical | IdGen vtable passes vtable address instead of struct context pointer -- UB |
| Q5 | High | Config parser panics on any missing/malformed JSON field (24 force-unwrap sites) |

### Maintainability / Duplication (Q3, Q8, Q9)

| ID | Severity | Summary |
|----|----------|---------|
| Q3 | High | freeJsonValue (3x) and cloneJsonValue (4x) duplicated across modules |
| Q8 | Medium | nowRfc3339Impl duplicated in SystemClock and FixedClock |
| Q9 | Medium | RFC 5424 formatting duplicated in SyslogSender and MockSyslogSender |

### Reliability (Q6, Q13)

| ID | Severity | Summary | Status |
|----|----------|---------|--------|
| Q6 | High | File rotation silently swallows rename errors | resolved |
| Q13 | Medium | truncateEvent allocates string that is immediately freed without being read | resolved |

### Test Coverage (Q7)

| ID | Severity | Summary | Status |
|----|----------|---------|--------|
| Q7 | High | Config parsing has zero test coverage for error/edge-case paths | resolved |

### Dead Code / Cleanup (Q12, Q18, Q19, Q20)

| ID | Severity | Summary | Status |
|----|----------|---------|--------|
| Q12 | Medium | AuditEvent.init() and deinit() never called | resolved |
| Q18 | Low | TLS pool management code unreachable (TLS not implemented) | resolved |
| Q19 | Low | IdGen.requestId vtable method never called by any consumer | **resolved → GAP-073 closed** |
| Q20 | Low | ErrorLogJson struct only used for inline default values | resolved |

### Readability / Documentation (Q10, Q14, Q15, Q17)

| ID | Severity | Summary | Status |
|----|----------|---------|--------|
| Q10 | Medium | CEF escape has redundant = branch | resolved |
| Q14 | Medium | source files lack module-level doc comments | resolved |
| Q15 | Medium | Non-obvious filter logic lacks explanatory comments | resolved |
| Q17 | Low | formatJsonLine repetitive field insertion | resolved |

### Structure (Q16, Q21)

| ID | Severity | Summary | Status |
|----|----------|---------|--------|
| Q16 | Low | syslog.zig still 775 LOC (grew; RingBuffer extracted; decomposition deferred) | **partial** |
| Q21 | Low | Placeholder example not wired into build | resolved |

---

## Roadmap (remaining open / partial only)

All Q-findings are resolved except Q16 (partial). GAP-072 (Q11) and GAP-073 (Q19) both closed 2026-06-12 via requestId vtable removal.

### Remaining (1-5 days)

| ID | Severity | Fix | Tracking |
|----|----------|-----|----------|
| Q16 | Low (partial) | Further decompose `src/syslog.zig` (775 LOC) beyond the already-extracted `RingBuffer` | deferred |

---

## 2026-06-11 Audit Pointer

The 2026-06-11 full audit added quality findings tracked as **GAP-058..062, GAP-072..074** and **QR-001..018**. As of 2026-06-12:

- **GAP-072** (Q11 requestId OOM swallowing) -- **CLOSED** -- vtable method removed entirely (commit 365aeb9).
- **GAP-073** (Q19 requestId vtable still present) -- **CLOSED** -- vtable method, dispatch, and impls removed (commit 365aeb9).
- **GAP-058..062** (decomposition/cleanup findings) -- **CLOSED** (commit 716e34b).
- **QR-001..003** (Critical memory-safety) -- **CLOSED** (commits 5af9f06, a4b0ccb, 7aaac81).
- **QR-004..016** -- **CLOSED** per 2026-06-12 cycle. See `docs/APPSEC_REVIEW_2026-06-12_iter2.md`.

---

## Cross-References to GAP_ANALYSIS.md

Several quality findings overlap with gaps already tracked in `docs/GAP_ANALYSIS.md`:

| Quality Finding | Existing GAP | Relationship |
|-----------------|-------------|--------------|
| Q1 (CEF escape no-ops) | GAP-006 | Same root cause |
| Q4 (Redaction drops fields) | GAP-010 | Q4 identifies a specific code path within GAP-010 |
| Q5 (Config parser panics) | GAP-018 | Same root cause |
| Q3 (freeJsonValue/cloneJsonValue duplication) | GAP-019 | Same root cause |
| Q18 (Dead TLS pool code) | GAP-027 | Same root cause (resolved) |
| Q19 (requestId vtable still present) | GAP-073 | Reopened by 2026-06-11 audit; not actually removed |
| Q11 (requestId OOM swallowing) | GAP-072 | Carried forward; open |
| Q12 (Dead AuditEvent.init/deinit) | GAP-026 | Q12 is a specific instance of GAP-026 (resolved) |
| Q21 (Placeholder example) | GAP-028 | Same root cause (resolved) |

---

## Confidence Notes

| ID | Confidence | Verification |
|----|------------|--------------|
| Q1 | confirmed | `escapeHeader`, `escapeValue`, `escapeKey` at cef.zig:152-162 literally `return s;` |
| Q2 | confirmed | time.zig:116 passes `@ptrCast(@constCast(self.vtable))`; `IdGen` struct has no `context` field unlike `Clock` |
| Q3 | confirmed | `freeJsonValue` at 3 locations, `cloneJsonValue` at 4 locations via grep |
| Q4 | confirmed | filters.zig:266-271: `.redact` branch only emits a field when `isSensitiveKey` returns non-null |
| Q5 | confirmed | 24 `.?` sites counted in config.zig:187-252 via grep |
| Q6 | confirmed (resolved) | file_sink.zig:248-258 now uses `catch \|err\| log.warn(...)` on rotation errors |
| Q7 | confirmed (resolved) | config parser error-path tests added |
| Q8 | confirmed (resolved) | time.zig:40 shared `formatRfc3339` helper used by both clocks |
| Q9 | confirmed (resolved) | syslog.zig:347 standalone shared `formatRfc5424` called from both senders |
| Q10 | confirmed (resolved) | redundant `=` branch removed during CEF escape rewrite |
| Q11 | confirmed (resolved) | requestId vtable method removed entirely; GAP-072 closed 2026-06-12 |
| Q12 | confirmed (resolved) | grep for `AuditEvent.init` returns zero matches |
| Q13 | confirmed (resolved) | `truncateEvent` removed; inline truncation at logger.zig:165-175 |
| Q14 | confirmed (resolved) | every `src/*.zig` carries a `//!` module header (verified via grep) |
| Q15 | confirmed (resolved) | filters.zig:466 comment explains the PEM guard |
| Q16 | confirmed (partial) | `ring_buffer.zig` extracted, but `wc -l src/syslog.zig` = 775 (grown due to remediation additions) |
| Q17 | confirmed (resolved) | `putField` helper at file_sink.zig:150 removes the repeated dupe+put pattern |
| Q18 | confirmed (resolved) | `releasePooledConnection`/`verifyCertificatePin` removed |
| Q19 | confirmed (resolved) | `requestId` vtable field, dispatch, and impls removed: `time.zig:124-127` now has only traceId/spanId; GAP-073 closed 2026-06-12 |
| Q20 | confirmed (resolved) | `ErrorLogJson` removed; grep returns zero references in `src/` |
| Q21 | confirmed (resolved) | working example wired into build.zig |
