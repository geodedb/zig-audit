# Quality Gap Analysis

Last updated: 2026-03-22

Repository: `gitlab.com/devnw/zig/audit`
Branch: `main`
Source: Deep quality review of all 9 source modules (2,355 LOC) and 4 test files (912 LOC).

---

## Summary

| Severity | Open | Resolved | Total |
|----------|------|----------|-------|
| Critical | 0 | 2 (Q1, Q2) | 2 |
| High     | 1 (Q6) | 4 (Q3, Q4, Q5, Q7) | 5 |
| Medium   | 5 (Q8, Q9, Q11, Q13, Q14, Q15) | 3 (Q10, Q12) | 8 |
| Low      | 3 (Q16, Q17, Q20) | 3 (Q18, Q19, Q21) | 6 |
| **Total** | **9** | **12** | **21** |

**All Critical findings are resolved. 12 of 21 findings resolved during gap closure.**

### Remaining Top Risks

1. **Q6 (High)**: File rotation silently swallows rename errors -- log data can be silently lost during rotation failures.
2. **Q8 (Medium)**: nowRfc3339Impl duplicated between SystemClock and FixedClock.
3. **Q9 (Medium)**: formatRfc5424 logic duplicated between SyslogSender and MockSyslogSender.
4. **Q11 (Medium)**: requestIdImpl returns "" on OOM instead of error.
5. **Q13 (Medium)**: truncateEvent result allocated and immediately freed.

---

## Stack-Ranked Findings

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Evidence | Issue | Fix Summary | Owner | ETA | Status |
|------|-----|----------|---------------|----------|---------|-----------|----------|-------|-------------|-------|-----|--------|
| 1 | Q1 | Critical | 100 | api-contract | CEF escape functions are no-ops | `src/cef.zig` | `escapeHeader`, `escapeValue`, `escapeKey` at lines 152-162 return input unmodified; `escapeCefString` exists at line 164 but is never called | GAP-006 | Replaced no-op escapes with allocating implementations; 8 new tests | @benjiv | S | **resolved** |
| 2 | Q2 | Critical | 100 | architecture | IdGen vtable dispatch passes wrong pointer as context | `src/time.zig` | Lines 115-125: `self.vtable.traceId(@ptrCast(@constCast(self.vtable)), buf)` passes the vtable address, not the struct address; impl functions cast this to `*SystemIdGen` -- UB | -- | Add a `context: *anyopaque` field to `IdGen` (like `Clock` already has) and pass it instead of the vtable pointer | TBD | S | resolved |
| 3 | Q5 | High | 80 | architecture | Config parser panics on malformed JSON | `src/config.zig` | 24 `.?` force-unwrap sites in `parseConfig` (lines 187-252); any missing or wrong-typed field triggers unreachable panic | GAP-018 | Replaced all force-unwraps with typed helpers; 8 inline tests | @benjiv | M | **resolved** |
| 4 | Q4 | High | 80 | api-contract | Redaction silently drops fields on deny-pattern match without sensitive-key match | `src/filters.zig` | Lines 266-271: when `shouldFilterField` returns `.redact` but `isSensitiveKey` returns `null`, the field is silently omitted from output | GAP-008 | Fixed: generic `[REDACTED]` token used when isSensitiveKey returns null | @benjiv | S | **resolved** |
| 5 | Q6 | High | 64 | maintainability | File rotation silently swallows rename errors | `src/file_sink.zig` | Lines 237, 243, 251: `catch {}` on `rename` and `makePath` calls; rotation failures produce no diagnostic output | -- | Log warnings on rotation errors; propagate fatal errors (e.g., permission denied) | TBD | S | triage |
| 6 | Q3 | High | 60 | maintainability | freeJsonValue duplicated 3x, cloneJsonValue duplicated 4x | `src/events.zig`, `src/file_sink.zig`, `src/filters.zig`, `src/logger.zig` | Identical `freeJsonValue` at events.zig:87, file_sink.zig:99, logger.zig:205; identical `cloneJsonValue` at events.zig:140, file_sink.zig:189, filters.zig:320, logger.zig:177 (~180 LOC total) | -- | Extract into a shared `json_util.zig` module; import from all consumers | TBD | S | resolved |
| 7 | Q7 | High | 60 | tests | No test coverage for config parsing error paths | `src/config.zig`, `tests/` | Zero test files reference `loadConfig`, `parseConfig`, `ConfigNotFound`, `InvalidJson`, or `MissingVersion`; 24 panic-prone unwrap sites are untested | GAP-018 | 8 inline tests added covering all error paths | @benjiv | M | **resolved** |
| 8 | Q8 | Medium | 48 | maintainability | nowRfc3339Impl duplicated between SystemClock and FixedClock | `src/time.zig` | Lines 38-58 (SystemClock) and 82-103 (FixedClock) contain identical date-formatting logic differing only in timestamp source | -- | Extract a shared `formatTimestamp(ts: i128, buf: []u8) []const u8` helper | TBD | S | triage |
| 9 | Q9 | Medium | 48 | maintainability | formatRfc5424 logic duplicated between SyslogSender and MockSyslogSender | `src/syslog.zig` | SyslogSender.formatRfc5424 (lines 136-152) and MockSyslogSender.send (lines 294-312) contain identical RFC 5424 formatting | -- | Extract a standalone `formatRfc5424` function; call from both types | TBD | S | triage |
| 10 | Q11 | Medium | 48 | api-contract | requestIdImpl returns "" on OOM instead of error | `src/time.zig` | Line 163: `catch ""` on `allocPrint`; line 201: `catch ""` on `allocator.dupe`; callers cannot distinguish OOM from a legitimate empty ID | -- | Change `requestId` vtable signature to return `![]const u8`; propagate errors | TBD | S | triage |
| 11 | Q10 | Medium | 36 | readability | escapeCefString has redundant = handling in both branches | `src/cef.zig` | Line 172: `'=' => if (is_header) try result.appendSlice(allocator, "\\=") else try result.appendSlice(allocator, "\\=")` -- both branches do the same thing | GAP-006 | Fixed during CEF escape rewrite: = only escaped in extensions per spec | @benjiv | S | **resolved** |
| 12 | Q13 | Medium | 36 | perf | truncateEvent result allocated and immediately freed | `src/logger.zig` | Lines 123-124: `const truncated = try self.truncateEvent(&event); defer self.allocator.free(truncated);` -- the returned string is never read; only the side-effect metadata replacement matters | -- | Remove the `truncateEvent` call; build truncation metadata directly | TBD | S | triage |
| 13 | Q12 | Medium | 24 | cleanup | Dead AuditEvent.init() and deinit() methods | `src/events.zig` | Lines 62-85: `init` takes an allocator it ignores; `deinit` is never called (callers use `freeCloned`); zero references in codebase | GAP-026 | Dead AuditEvent.init removed | @benjiv | S | **resolved** |
| 14 | Q14 | Medium | 24 | docs | 8 of 9 source files lack module-level doc comments | `src/cef.zig`, `src/config.zig`, `src/events.zig`, `src/file_sink.zig`, `src/filters.zig`, `src/logger.zig`, `src/syslog.zig`, `src/time.zig` | Only `src/root.zig` has `//!` module-level documentation; all other modules start with license header only | -- | Add `//!` doc comments to each module describing purpose and public API | TBD | M | triage |
| 15 | Q15 | Medium | 20 | readability | Missing explanatory comments on non-obvious filter logic | `src/filters.zig` | Line 299: `isPemPrivateKey(str_value) and !std.mem.startsWith(u8, str_value, "-----BEGIN")` -- the negated condition is counter-intuitive with no comment explaining why both checks exist | -- | Add comment explaining this detects embedded private keys (not standalone PEM blocks) | TBD | S | triage |
| 16 | Q16 | Low | 16 | architecture | syslog.zig is 424 LOC with 3 types | `src/syslog.zig` | Contains `SyslogSender` (272 LOC), `MockSyslogSender` (60 LOC), and `RingBuffer` (55 LOC) in a single file | -- | Extract `RingBuffer` to `ring_buffer.zig`; optionally move `MockSyslogSender` to test support | TBD | S | triage |
| 17 | Q17 | Low | 16 | readability | formatJsonLine 65 lines of repetitive insertion | `src/file_sink.zig` | Lines 122-187: each field insertion is ~3 lines of allocator.dupe + json_obj.put with identical pattern repeated 12 times | -- | Extract a helper `putStringField(obj, allocator, key, value)` to reduce repetition | TBD | S | triage |
| 18 | Q18 | Low | 12 | cleanup | Dead TLS pool management code | `src/syslog.zig` | Lines 238-271: `releasePooledConnection` and `verifyCertificatePin` are never called; TLS transport returns `error.TlsNotImplemented` | GAP-026/027 | Dead functions and TLS pool fields removed | @benjiv | S | **resolved** |
| 19 | Q19 | Low | 12 | cleanup | Dead IdGen.requestId vtable method | `src/time.zig` | Lines 112, 123-125: `requestId` is defined on the `IdGen` vtable and dispatched but never called by any consumer (logger only uses `traceId`/`spanId`) | GAP-026 | Dead code removed | @benjiv | S | **resolved** |
| 20 | Q20 | Low | 8 | cleanup | ErrorLogJson struct used only for default values | `src/file_sink.zig` | Lines 69-77: struct defined, instantiated, but only its fields are read to populate a manual `ObjectMap`; the struct is not serialized | -- | Inline the string constants directly into the ObjectMap puts | TBD | S | triage |
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

| ID | Severity | Summary |
|----|----------|---------|
| Q6 | High | File rotation silently swallows rename errors |
| Q13 | Medium | truncateEvent allocates string that is immediately freed without being read |

### Test Coverage (Q7)

| ID | Severity | Summary |
|----|----------|---------|
| Q7 | High | Config parsing has zero test coverage for error/edge-case paths |

### Dead Code / Cleanup (Q12, Q18, Q19, Q20)

| ID | Severity | Summary |
|----|----------|---------|
| Q12 | Medium | AuditEvent.init() and deinit() never called |
| Q18 | Low | TLS pool management code unreachable (TLS not implemented) |
| Q19 | Low | IdGen.requestId vtable method never called by any consumer |
| Q20 | Low | ErrorLogJson struct only used for inline default values |

### Readability / Documentation (Q10, Q14, Q15, Q17)

| ID | Severity | Summary |
|----|----------|---------|
| Q10 | Medium | CEF escape has redundant = branch |
| Q14 | Medium | 8 of 9 source files lack module-level doc comments |
| Q15 | Medium | Non-obvious filter logic lacks explanatory comments |
| Q17 | Low | formatJsonLine has 65 lines of repetitive field insertion |

### Structure (Q16, Q21)

| ID | Severity | Summary |
|----|----------|---------|
| Q16 | Low | syslog.zig 424 LOC with 3 types in one file |
| Q21 | Low | Placeholder example not wired into build |

---

## Roadmap

### Quick Wins (< 1 day)

| ID | PriorityScore | Fix |
|----|---------------|-----|
| Q1 | 100 | Wire `escapeCefString` into escapeHeader/escapeValue/escapeKey stubs |
| Q2 | 100 | Add `context: *anyopaque` to `IdGen`; pass struct address in dispatch |
| Q4 | 80 | Fall back to generic `[REDACTED]` when `isSensitiveKey` returns null |
| Q6 | 64 | Add `log.warn` on rename failures; propagate permission errors |
| Q10 | 36 | Remove redundant conditional on `=` escape |
| Q13 | 36 | Remove unused `truncateEvent` call; build truncation metadata inline |
| Q12 | 24 | Delete dead `init`/`deinit` on AuditEvent |
| Q15 | 20 | Add comment explaining negated PEM check in filter logic |
| Q18 | 12 | Remove dead TLS pool management functions |
| Q19 | 12 | Remove dead `requestId` from vtable |
| Q20 | 8 | Inline ErrorLogJson default values directly |

### Medium (1-5 days)

| ID | PriorityScore | Fix |
|----|---------------|-----|
| Q5 | 80 | Replace 24 `.?` with `orelse return error.*`; add union-type guards |
| Q3 | 60 | Extract `json_util.zig` with shared freeJsonValue/cloneJsonValue |
| Q7 | 60 | Write config parser error-path tests (missing fields, bad types, bad JSON) |
| Q8 | 48 | Extract shared `formatTimestamp` helper in time.zig |
| Q9 | 48 | Extract standalone `formatRfc5424` function |
| Q11 | 48 | Change `requestId` return type to `![]const u8` |
| Q14 | 24 | Add `//!` module docs to 8 source files |
| Q16 | 16 | Extract RingBuffer to own module |
| Q17 | 16 | Extract `putStringField` helper for JSON line formatting |

### Strategic (> 5 days)

| ID | PriorityScore | Fix |
|----|---------------|-----|
| Q21 | 8 | Implement working examples with real API usage; wire into build |

---

## Cross-References to GAP_ANALYSIS.md

Several quality findings overlap with gaps already tracked in `docs/GAP_ANALYSIS.md`:

| Quality Finding | Existing GAP | Relationship |
|-----------------|-------------|--------------|
| Q1 (CEF escape no-ops) | GAP-006 | Same root cause |
| Q4 (Redaction drops fields) | GAP-010 | Q4 identifies a specific code path within GAP-010 |
| Q5 (Config parser panics) | GAP-018 | Same root cause |
| Q3 (freeJsonValue/cloneJsonValue duplication) | GAP-019 | Same root cause |
| Q18 (Dead TLS pool code) | GAP-027 | Same root cause |
| Q19 (Dead requestId vtable) | GAP-026 | Q19 is a specific instance of GAP-026 |
| Q12 (Dead AuditEvent.init/deinit) | GAP-026 | Q12 is a specific instance of GAP-026 |
| Q21 (Placeholder example) | GAP-028 | Same root cause |

---

## Confidence Notes

| ID | Confidence | Verification |
|----|------------|--------------|
| Q1 | confirmed | `escapeHeader`, `escapeValue`, `escapeKey` at cef.zig:152-162 literally `return s;` |
| Q2 | confirmed | time.zig:116 passes `@ptrCast(@constCast(self.vtable))`; `IdGen` struct has no `context` field unlike `Clock` |
| Q3 | confirmed | `freeJsonValue` at 3 locations, `cloneJsonValue` at 4 locations via grep |
| Q4 | confirmed | filters.zig:266-271: `.redact` branch only emits a field when `isSensitiveKey` returns non-null |
| Q5 | confirmed | 24 `.?` sites counted in config.zig:187-252 via grep |
| Q6 | confirmed | file_sink.zig:237,243,251 all use `catch {}` |
| Q7 | confirmed | grep for `loadConfig`/`parseConfig`/error names in `tests/` returns zero matches |
| Q8 | confirmed | time.zig lines 38-58 and 82-103 contain identical formatting logic |
| Q9 | confirmed | syslog.zig:136-152 and syslog.zig:294-312 duplicate RFC 5424 format string and PRI calculation |
| Q10 | confirmed | cef.zig:172 both branches of `if (is_header)` produce `"\\="` |
| Q11 | confirmed | time.zig:163 and time.zig:201 both `catch ""` |
| Q12 | confirmed | grep for `AuditEvent.init` across entire repo returns zero matches |
| Q13 | confirmed | logger.zig:123-124 allocates `truncated` string, immediately defers free, never reads it |
| Q14 | confirmed | grep for `^//!` in `src/` finds only `root.zig` |
| Q15 | confirmed | filters.zig:299 has no comment explaining the seemingly contradictory condition |
| Q16 | confirmed | `wc -l` reports 424 lines for syslog.zig |
| Q17 | confirmed | file_sink.zig:122-187 shows 12 repetitions of dupe+put pattern |
| Q18 | confirmed | `releasePooledConnection` and `verifyCertificatePin` have zero callers |
| Q19 | confirmed | `IdGen.requestId` only called by its own vtable dispatch; no consumer calls it |
| Q20 | confirmed | ErrorLogJson fields are read into a manual ObjectMap; struct is not serialized directly |
| Q21 | confirmed | examples/basic.zig contains commented-out usage and prints placeholder text |
