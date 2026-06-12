# 2026-06-11 Full-Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every fixable finding from the 2026-06-11 appsec review (A1–A8 / GAP-040..047) and full codebase audit (GAP-048..074, QR-001..018, PR-001..013) in the `audit` Zig library, leaving only explicitly-blocked items (GAP-005 TLS, GAP-045 cross-repo pin) open.

**Architecture:** Fix waves ordered by blast radius: (A) critical memory safety in the logger orchestration layer, (B) security mediums (config casts, PiiMode.hash, control chars, path handling, file perms, drop visibility), (C) low-severity correctness, (D) hot-path perf quick wins (single-write + drain batching + streaming JSON serialization), (E) metadata copy-reduction, (F) docs/CI/scripts hygiene. Every code change is TDD: failing test first, minimal fix, full `zig build test-all` green, commit.

**Tech Stack:** Zig 0.16.0 (`zig build check`, `zig build test-all --summary all`, `zig fmt`), Python 3 + ruff for scripts/, GitLab CI, pre-commit.

**Verification commands (run after every task):**

- `zig build check` → must succeed
- `zig build test-all --summary all` → all pass (currently 106/107 + 1 expected otel skip)
- `zig fmt src/ tests/ benchmarks/ build.zig` before committing

**Conventions:** Commit messages reference the Gap-IDs (e.g. `fix(logger): heap-own system clock/idgen in buildAuditLogger (QR-001)`). One commit per task. Do NOT change public API gratuitously; this library is 0.1.x so targeted breaking changes called out below are acceptable.

---

## Wave A — Critical memory safety

### Task A1: QR-001 — `buildAuditLogger` use-after-return (Critical)

**Files:**

- Modify: `src/logger.zig:250-255` (buildAuditLogger), `src/logger.zig:21-77` (AuditLogger struct/init/deinit)
- Test: add to `src/logger.zig` tests

**Problem:** `buildAuditLogger` creates `SystemClock`/`SystemIdGen` as stack locals and captures `@ptrCast(&stack_local)` into vtable contexts that outlive the frame. `SystemIdGen.traceIdImpl` dereferences the dangling pointer (`self.rng`).

- [ ] **Step 1: Write the failing test** (in `src/logger.zig`; it will pass-by-luck only in some modes, so also assert behavior — under Debug with fresh stack reuse the trace IDs degrade; the deterministic part of the test is the ownership API):

```zig
test "buildAuditLogger: system idgen survives the builder frame (QR-001)" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_config = try config.loadTestConfig(allocator);
    const logger = try buildAuditLogger(allocator, test_config);
    defer logger.deinit();

    // Drive the id_gen through the vtable from a *different* stack depth.
    // Before the fix this reads a dangling stack frame (UB; DebugAllocator
    // or @returnAddress clobber makes it produce invalid/identical hex).
    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;
    logger.id_gen.traceId(&buf1);
    logger.id_gen.traceId(&buf2);
    for (buf1) |c| try std.testing.expect(std.ascii.isHex(c));
    try std.testing.expect(!std.mem.eql(u8, &buf1, &buf2));

    const event = events.AuditEvent{
        .category = "auth", .action = "login", .outcome = .success,
        .ts_unix_ms = 0, .severity = .INFO, .actor_id = "u1",
        .subject_id = null, .request_id = null, .session_id = null,
        .source_ip = null, .trace_id = null, .span_id = null, .metadata = null,
    };
    try logger.audit(&event);
}
```

Note: `buildAuditLogger` signature changes in Step 3 to take `config.Config` by value (see Task A4 rationale) — write the test against the new signature.

- [ ] **Step 2: Run `zig build test --summary all`** — expect FAIL/erratic behavior or compile error against new signature.

- [ ] **Step 3: Fix.** Heap-own the system implementations inside `AuditLogger`:

```zig
pub const AuditLogger = struct {
    allocator: std.mem.Allocator,
    config: config.Config,
    clock: time.Clock,
    id_gen: time.IdGen,
    syslog_sender: ?*syslog.SyslogSender,
    file_sink: ?*file_sink.FileSink,
    // Owned only when constructed via buildAuditLogger; freed in deinit.
    owned_system_clock: ?*time.SystemClock = null,
    owned_system_id_gen: ?*time.SystemIdGen = null,
    ...
```

`init` sets both to `null` (add to the struct literal). `deinit` (after destroying sinks, before `self.config.deinit()`):

```zig
        if (self.owned_system_clock) |c| self.allocator.destroy(c);
        if (self.owned_system_id_gen) |g| self.allocator.destroy(g);
```

`buildAuditLogger` (also moves Config by value — Task A4):

```zig
/// Construct an AuditLogger with system clock and secure ID generation.
/// Takes ownership of `cfg`; the logger frees it in `deinit()`. Do not
/// call `cfg.deinit()` after passing it here.
pub fn buildAuditLogger(allocator: std.mem.Allocator, cfg: config.Config) !*AuditLogger {
    const sys_clock = try allocator.create(time.SystemClock);
    errdefer allocator.destroy(sys_clock);
    sys_clock.* = .{};

    const sys_id_gen = try allocator.create(time.SystemIdGen);
    errdefer allocator.destroy(sys_id_gen);
    sys_id_gen.* = time.SystemIdGen.init();

    const logger = try AuditLogger.init(allocator, cfg, sys_clock.clock(), sys_id_gen.idGen());
    logger.owned_system_clock = sys_clock;
    logger.owned_system_id_gen = sys_id_gen;
    return logger;
}
```

- [ ] **Step 4: Run `zig build test-all --summary all`** — expect PASS.
- [ ] **Step 5: `zig fmt src/`, commit** `fix(logger): heap-own system clock/idgen in buildAuditLogger; take Config by value (QR-001, QR-004)`

### Task A2: QR-002 — double-free/UAF on non-object metadata (Critical)

**Files:**

- Modify: `src/filters.zig:372` (the `else => metadata` aliasing branch)
- Test: add to `tests/test_filters.zig` and `src/logger.zig`

**Problem:** `filterAndRedactMetadataRecursive` returns the *input value unchanged (aliased)* for non-object top-level metadata. `audit()` then frees the original (`logger.zig:154`) and reads/frees the alias → UAF + double-free.

- [ ] **Step 1: Failing tests.**

In `tests/test_filters.zig`:

```zig
test "filterAndRedactMetadata: non-object top-level metadata returns an independent copy (QR-002)" {
    const allocator = std.testing.allocator;
    const cfg = audit.config.FiltersConfig{
        .default_deny = false,
        .allow_fields = &.{},
        .deny_key_patterns = &.{},
        .pii_mode = .off,
        .pci_mode = false,
    };
    const original = std.json.Value{ .string = try allocator.dupe(u8, "plain-string") };
    const filtered = (try audit.filters.filterAndRedactMetadata(allocator, original, &cfg)).?;
    // Must be a deep copy, not an alias
    try std.testing.expect(filtered.string.ptr != original.string.ptr);
    audit.json_util.freeJsonValue(allocator, original);
    audit.json_util.freeJsonValue(allocator, filtered); // double-free before fix
    try std.testing.expectEqualStrings("plain-string", "plain-string");
}
```

In `src/logger.zig` (end-to-end repro):

```zig
test "audit: non-object metadata does not double-free (QR-002)" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const test_config = try config.loadTestConfig(allocator);
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID, time.TEST_REQUEST_ID);
    const logger = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());
    defer logger.deinit();

    var event = makeTestEvent(); // reuse/extract the literal used by "audit logger basic functionality"
    event.metadata = std.json.Value{ .string = "not-an-object" };
    try logger.audit(&event); // DebugAllocator catches the double-free before fix
}
```

(If `makeTestEvent` doesn't exist, extract the event literal from the existing "audit logger basic functionality" test into a file-local `fn makeTestEvent() events.AuditEvent`.)

- [ ] **Step 2: Run; expect DebugAllocator double-free panic / failure.**
- [ ] **Step 3: Fix `src/filters.zig:372`:**

```zig
        else => try json_util.cloneJsonValue(allocator, metadata),
```

- [ ] **Step 4: `zig build test-all --summary all`** — PASS.
- [ ] **Step 5: Commit** `fix(filters): deep-copy non-object metadata instead of aliasing (QR-002)`

### Task A3: QR-003 — truncation path frees string literals (Critical)

**Files:**

- Modify: `src/logger.zig:171-174`
- Test: add to `src/logger.zig`

- [ ] **Step 1: Failing test** — end-to-end `audit()` with metadata serializing > 8192 bytes (also closes the QR-012 truncation-coverage gap):

```zig
test "audit: oversize metadata truncation does not free literals (QR-003)" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const test_config = try config.loadTestConfig(allocator);
    var fixed_clock = time.FixedClock.init(time.TEST_TIMESTAMP_MS);
    var fixed_id_gen = time.FixedIdGen.init(time.TEST_TRACE_ID, time.TEST_SPAN_ID, time.TEST_REQUEST_ID);
    const logger = try AuditLogger.init(allocator, test_config, fixed_clock.clock(), fixed_id_gen.idGen());
    defer logger.deinit();

    var event = makeTestEvent();
    var metadata_obj: std.json.ObjectMap = .empty;
    defer metadata_obj.deinit(allocator);
    const big = try allocator.alloc(u8, 9000);
    defer allocator.free(big);
    @memset(big, 'x');
    try metadata_obj.put(allocator, "big", std.json.Value{ .string = big });
    event.metadata = std.json.Value{ .object = metadata_obj };

    try logger.audit(&event); // freeCloned frees literal keys before fix → DebugAllocator panic
}
```

NOTE: `loadTestConfig` must allow the `big` key through the filters (check `allow_fields`); if `default_deny` redacts it the value is replaced by a short token and truncation never triggers. If so, set the event's metadata key to a name present in `allow_fields` from `loadTestConfig` (read `src/config.zig:loadTestConfig` to pick one), or include many allowed keys to exceed 8192.

- [ ] **Step 2: Run; expect invalid-free panic.**
- [ ] **Step 3: Fix `src/logger.zig:171-174`** — dupe the keys so `freeCloned`'s uniform key-free is sound:

```zig
            var truncation_obj: std.json.ObjectMap = .empty;
            errdefer {
                var it = truncation_obj.iterator();
                while (it.next()) |e| self.allocator.free(e.key_ptr.*);
                truncation_obj.deinit(self.allocator);
            }
            try truncation_obj.put(self.allocator, try self.allocator.dupe(u8, "_truncated"), std.json.Value{ .bool = true });
            try truncation_obj.put(self.allocator, try self.allocator.dupe(u8, "_original_size"), std.json.Value{ .integer = @intCast(estimated_size) });
            event.metadata = std.json.Value{ .object = truncation_obj };
```

- [ ] **Step 4: `zig build test-all`** — PASS. **Step 5: Commit** `fix(logger): heap-dupe truncation marker keys (QR-003)`

### Task A4: QR-004 — Config ownership contract (High)

**Files:**

- Modify: `src/config.zig:144-171` (doc comment on `Config`), `src/logger.zig:29-34` (doc comment on `init`)
- (Signature change of `buildAuditLogger` already done in Task A1.)

- [ ] **Step 1:** Add explicit ownership docs:

On `Config` (config.zig, above `pub const Config`):

```zig
/// Parsed configuration. OWNERSHIP: `AuditLogger.init`/`buildAuditLogger`
/// take ownership of a `Config` passed to them — the logger calls
/// `config.deinit()` in its own `deinit()`. Callers must NOT call
/// `deinit()` on a Config after handing it to a logger, and must not
/// retain copies of it (the struct embeds heap pointers).
```

On `AuditLogger.init` (logger.zig):

```zig
    /// Takes ownership of `audit_config`; freed in `deinit()`. Do not call
    /// `audit_config.deinit()` after a successful `init`.
```

- [ ] **Step 2:** `zig build test-all` PASS (doc-only + already-changed signature). **Commit** `docs(config): document Config ownership transfer to AuditLogger (QR-004)`

---

## Wave B — Security mediums

### Task B1: GAP-040 (A1) — range-checked config integer parsing

**Files:**

- Modify: `src/config.zig` lines ~231, 242, 272, 278, 279, 291 (every `@intCast(try jsonInteger(...))`)
- Test: add to `src/config.zig` tests

- [ ] **Step 1: Failing tests** (pattern; write one per field — port, pid, max_bytes, backup_count, sync_interval, version — both negative and over-max):

```zig
test "loadConfig rejects out-of-range port instead of panicking (GAP-040)" {
    const allocator = std.testing.allocator;
    // Copy the valid test-config JSON used by existing parse tests and set "port": 99999
    // (find the existing inline JSON fixture in this file and reuse its shape).
    const cfg_json = ...; // full JSON literal with "port": 99999
    try std.testing.expectError(error.InvalidConfig, parseConfigFromSlice(allocator, cfg_json));
}
```

(Use whatever internal parse-from-string helper the existing negative tests use — `config.zig` has solid negative tests already; mirror their mechanism.)

- [ ] **Step 2: Run** — Debug build panics (test runner reports crash), proving the bug.
- [ ] **Step 3: Fix.** Add a helper and use it at all six sites:

```zig
fn jsonIntegerInRange(comptime T: type, obj: std.json.ObjectMap, key: []const u8) !T {
    const raw = try jsonInteger(obj, key);
    return std.math.cast(T, raw) orelse error.InvalidConfig;
}
```

Replace e.g. `.port = @as(u16, @intCast(try jsonInteger(syslog_obj, "port")))` with `.port = try jsonIntegerInRange(u16, syslog_obj, "port")`. Additionally reject `port == 0` (`if (port == 0) return error.InvalidConfig;`).

- [ ] **Step 4: test-all PASS. Step 5: Commit** `fix(config): range-check all JSON integer fields (GAP-040/A1)`

### Task B2: GAP-050 — implement `PiiMode.hash`

**Files:**

- Modify: `src/filters.zig:273-279` (`redactOrMaskValue`), `src/filters.zig:346-357` (key-token mask path)
- Test: `tests/test_filters.zig`

**Design:** `.hash` produces a deterministic pseudonymization token: `sha256:<first 16 hex of SHA-256(value)>`. Unkeyed SHA-256 of low-entropy PII is dictionary-attackable — document that in the doc comment; it matches the "correlatable pseudonym" intent. Never silently fall back.

- [ ] **Step 1: Failing tests:**

```zig
test "pii_mode=hash produces deterministic sha256 token for emails (GAP-050)" {
    const allocator = std.testing.allocator;
    const cfg = audit.config.FiltersConfig{
        .default_deny = false, .allow_fields = &.{}, .deny_key_patterns = &.{},
        .pii_mode = .hash, .pci_mode = false,
    };
    // build {"contact":"user@example.com"} metadata, run filterAndRedactMetadata
    ...
    const v = filtered.object.get("contact").?.string;
    try std.testing.expect(std.mem.startsWith(u8, v, "sha256:"));
    try std.testing.expectEqual(@as(usize, "sha256:".len + 16), v.len);
    // determinism: run twice, same token; different input → different token
}
```

- [ ] **Step 2: Run — fails (current output is the full-redaction token `[EMAIL_REDACTED]`-style).**
- [ ] **Step 3: Fix:**

```zig
fn hashValue(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(value, &digest, .{});
    const hex = std.fmt.bytesToHex(digest[0..8].*, .lower); // 16 hex chars
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{hex});
}
```

In `redactOrMaskValue`, before the mask branch:

```zig
    if (filters_cfg.pii_mode == .hash) {
        if (detected == .email or detected == .phone) return hashValue(allocator, value);
    }
```

In the key-token path of `filterAndRedactMetadataRecursive` (currently `pii_mode == .mask` only, line ~348), extend symmetrically:

```zig
    if (value == .string) {
        if (filters_cfg.pii_mode == .mask) {
            if (kt == .email and isEmail(value.string)) break :redact_blk try maskEmail(allocator, value.string);
            if (kt == .phone and isPhone(value.string)) break :redact_blk try maskPhone(allocator, value.string);
        } else if (filters_cfg.pii_mode == .hash) {
            if ((kt == .email and isEmail(value.string)) or (kt == .phone and isPhone(value.string)))
                break :redact_blk try hashValue(allocator, value.string);
        }
    }
```

- [ ] **Step 4: test-all PASS. Step 5: Commit** `feat(filters): implement pii_mode=hash sha256 pseudonymization (GAP-050)`

### Task B3: GAP-042 + GAP-047 (A3+A8) — control-character neutralization

**Files:**

- Modify: `src/cef.zig:218-234` (`escapeCefString`), `src/events.zig:75-101` (`validate`)
- Test: `tests/test_cef.zig`, `src/events.zig` tests

- [ ] **Step 1: Failing tests:**

```zig
// tests/test_cef.zig
test "escapeCefString neutralizes C0 control bytes and DEL (GAP-042)" {
    const allocator = std.testing.allocator;
    const escaped = try audit.cef.escapeCefString(allocator, "a\x00b\x07c\x7fd\te", false);
    defer allocator.free(escaped);
    for (escaped) |c| try std.testing.expect(c >= 0x20 and c != 0x7f);
    try std.testing.expectEqualStrings("a\\x00b\\x07c\\x7fd\\x09e", escaped);
}
```

(If `escapeCefString` is not `pub`, test through `formatCef` with a control char in `actor_id`, asserting no raw byte < 0x20 in output.)

```zig
// src/events.zig
test "validate rejects control characters in core fields (GAP-047)" {
    var event = makeValidEvent();
    event.actor_id = "user\x00name";
    try std.testing.expectError(error.InvalidCharacter, event.validate());
}
```

- [ ] **Step 2: Run — both fail.**
- [ ] **Step 3: Fix.** In `escapeCefString`'s switch, before the `else` passthrough add:

```zig
                0x00...0x08, 0x0B, 0x0C, 0x0E...0x1F, 0x7F => {
                    var hex_buf: [4]u8 = undefined;
                    const hex = std.fmt.bufPrint(&hex_buf, "\\x{x:0>2}", .{c}) catch unreachable;
                    try result.appendSlice(allocator, hex);
                },
                0x09 => try result.appendSlice(allocator, "\\x09"),
```

(`\n`/`\r` already handled above as `\\n`/`\\r`; keep those.)

In `validate()`, add `error.InvalidCharacter` to `ValidateError` and after the length loops:

```zig
        const all_checked = [_]?[]const u8{
            self.category, self.action, self.actor_id,
            self.subject_id, self.request_id, self.session_id, self.source_ip,
        };
        for (all_checked) |maybe_field| {
            if (maybe_field) |field| {
                for (field) |c| {
                    if (c < 0x20 or c == 0x7F) return error.InvalidCharacter;
                }
            }
        }
```

- [ ] **Step 4: test-all PASS. Step 5: Commit** `fix(cef,events): neutralize and reject control characters (GAP-042/A3, GAP-047/A8)`

### Task B4: GAP-043 (A4) — proper path validation + allowed base dir

**Files:**

- Modify: `src/file_sink.zig:264-288` (`openCurrentFile`), `src/config.zig` (`FileSinkConfig` + parser)
- Test: `src/file_sink.zig` tests

**Design:** (1) Replace the `".."` *substring* check with a *component-wise* check (fixes both the bypass-by-absolute-symlink concern's `..` half and the `my..app.log` false positive). (2) Add optional `allowed_base_dir: ?[]const u8 = null` to `FileSinkConfig`; when set, the resolved absolute path of `config.path` must start with the resolved absolute base. Absolute paths remain allowed when no base is configured (legit `/var/log/...` use), and this is documented. (3) `createDirPath` errors are no longer swallowed (ignore only "already exists" semantics — `createDirPath` succeeding when the dir exists is its normal behavior, so propagate all errors it returns).

- [ ] **Step 1: Failing tests:**

```zig
test "openCurrentFile rejects '..' path components but allows dots in names (GAP-043)" {
    // path "zig-out/tmp/../escape.log" → error.PathTraversalRejected
    // path "zig-out/tmp/my..app.log" → succeeds (false positive before fix)
}

test "openCurrentFile enforces allowed_base_dir when configured (GAP-043)" {
    // base "zig-out/tmp/jail", path "/tmp/outside.log" → error.PathOutsideAllowedBase
    // base "zig-out/tmp/jail", path "zig-out/tmp/jail/audit.log" → succeeds
}
```

Write them as real FileSink.init calls with `enabled = true` and unique test dirs (`zig-out/tmp/test-gap043-*`), expecting the named errors.

- [ ] **Step 2: Run — first half of test 1 fails (substring check passes `my..app.log` → wrongly rejected; the component case is accepted-by-accident? verify: substring check rejects both — assert the false-positive case to get a true failing test).**
- [ ] **Step 3: Fix:**

```zig
    fn validatePath(self: *FileSink) !void {
        var it = try std.fs.path.componentIterator(self.config.path);
        while (it.next()) |comp| {
            if (std.mem.eql(u8, comp.name, "..")) return error.PathTraversalRejected;
        }
        if (self.config.allowed_base_dir) |base| {
            // Resolve both to absolute, normalized paths and require prefix match
            const resolved_path = try std.fs.path.resolve(self.allocator, &.{self.config.path});
            defer self.allocator.free(resolved_path);
            const resolved_base = try std.fs.path.resolve(self.allocator, &.{base});
            defer self.allocator.free(resolved_base);
            if (!std.mem.startsWith(u8, resolved_path, resolved_base) or
                (resolved_path.len > resolved_base.len and resolved_path[resolved_base.len] != std.fs.path.sep))
                return error.PathOutsideAllowedBase;
        }
    }
```

Call `try self.validatePath();` at the top of `openCurrentFile` (replacing the substring check). Change the `createDirPath` catch to propagate: `try cwd.createDirPath(io, dir_path);` — if the std API errors on pre-existing dirs, keep `catch |err| switch (err) { error.PathAlreadyExists => {}, else => return err }`. Add `allowed_base_dir: ?[]const u8 = null` to `FileSinkConfig`, parse it optionally in the config parser (and free it in `Config.deinit` if heap-allocated). Note in the field doc that symlinked parents are not resolved (documented limitation; `realpath` of not-yet-existing files is unreliable) — base enforcement uses lexical resolution.

- [ ] **Step 4: test-all PASS. Step 5: Commit** `fix(file_sink): component-wise traversal check + allowed_base_dir enforcement (GAP-043/A4)`

### Task B5: GAP-063 — create log file with restrictive mode atomically

**Files:**

- Modify: `src/file_sink.zig:278-287`

- [ ] **Step 1:** Check `std.Io.Dir.createFile` options for a `mode`/`permissions` field (read the std source for the installed 0.16 toolchain: `~/zig/.../lib/std/Io/Dir.zig` or wherever `createFile`'s options struct is defined).
- [ ] **Step 2: Failing test:** create file via FileSink on a fresh path with a permissive umask and assert mode 0o640 immediately (read via `file.stat`/`std.posix.fstat` mode bits, non-Windows only).
- [ ] **Step 3: Fix:** pass the mode in the `createFile` options if supported (e.g. `.{ .truncate = false, .permissions = std.Io.File.Permissions.fromMode(0o640) }` — adapt to the actual API); keep the `setPermissions` call only as a fallback if the API has no creation mode. If the API genuinely lacks creation-mode support, instead pre-create with `std.posix.open(..., .{ .CREAT = true }, 0o640)` on non-Windows and fall back to the current behavior on Windows; document whichever path is taken.
- [ ] **Step 4: test-all PASS. Step 5: Commit** `fix(file_sink): apply 0o640 at file creation, not after (GAP-063)`

### Task B6: GAP-041 (A2) + QR-005 — drop visibility and honest durability

**Files:**

- Modify: `src/file_sink.zig` (struct, `write`, `writeError`), `src/syslog.zig` (`send` return), `src/logger.zig:177-204`
- Test: `src/file_sink.zig`, `src/logger.zig`

**Design:** `FileSink.write`/`writeError` and `SyslogSender.send` return `enum { enqueued, dropped }` (still `!SendStatus` for real errors). `FileSink` gains `dropped_count: std.atomic.Value(u64)` + `getDroppedCount()` (mirror of syslog GAP-023), warning logged on first drop and every 1000th. `audit()` sets `span_durable = false` if either sink reported `.dropped`.

- [ ] **Step 1: Failing test** — fill the channel and assert the counter:

```zig
test "FileSink counts dropped events when channel is full (GAP-041)" {
    // init FileSink with enabled=true but do NOT let the worker drain:
    // easiest deterministic approach: init with a tiny private queue size.
    // Add a `queue_size` field default FILE_QUEUE_SIZE to FileSink.init's behavior
    // via a new internal initWithQueueSize used by tests, queue_size=1,
    // and a worker that is paused — simplest: enabled=true with path under
    // zig-out/tmp, send a burst of writes larger than the queue from the test
    // thread while the worker fsyncs per_event on a slow path; if flaky,
    // instead test the drop branch directly: construct the sink, close nothing,
    // and call write repeatedly after manually filling sink.ch via trySend.
    // Deterministic version: fill sink.ch with dummy allocations until trySend
    // returns false, then call sink.write(...) once and assert
    // sink.getDroppedCount() == 1 and the function returned .dropped.
}
```

Use the deterministic version: pre-fill `sink.ch` directly from the test (it's the same module) until `trySend` returns `false`, then one `write()` → expect `.dropped` and counter 1.

- [ ] **Step 2: Run — compile error (return type) → implement.**
- [ ] **Step 3: Implementation sketch:**

```zig
pub const SendStatus = enum { enqueued, dropped };
// file_sink.zig
    dropped_count: std.atomic.Value(u64),
    pub fn getDroppedCount(self: *const FileSink) u64 {
        return self.dropped_count.load(.monotonic);
    }
    pub fn write(...) !SendStatus {
        ...
        if (!self.ch.trySend(json_line)) {
            self.allocator.free(json_line);
            const n = self.dropped_count.fetchAdd(1, .monotonic) + 1;
            if (n == 1 or n % 1000 == 0)
                log.warn("file sink channel full; {d} audit events dropped so far", .{n});
            return .dropped;
        }
        return .enqueued;
    }
```

Same shape for `writeError`. `SyslogSender.send` already counts (GAP-023): change its return to `!SendStatus` analogously. In `audit()`:

```zig
        var any_dropped = false;
        if (self.syslog_sender) |sender| {
            const st = sender.send(&event) catch |err| blk: { syslog_err = err; break :blk .dropped; };
            if (st == .dropped) any_dropped = true;
        }
        ... // same for file sink
        span_ok = true;
        span_durable = !any_dropped;
```

Update all existing callers/tests of `write`/`send` for the new return type (`_ = try sink.write(...)`).

- [ ] **Step 4: test-all PASS. Step 5: Commit** `feat(sinks): surface enqueue-vs-drop to callers; file-sink drop counter (GAP-041/A2, QR-005)`

---

## Wave C — Correctness (low severity)

### Task C1: GAP-048 — `cloneJsonValue` errdefer

**Files:** Modify `src/json_util.zig:50-66`; test in `src/json_util.zig` using `std.testing.FailingAllocator`.

- [ ] **Step 1: Failing test:**

```zig
test "cloneJsonValue frees partial clones on OOM (GAP-048)" {
    // Build a 4-element array of duped strings with testing.allocator,
    // then clone with std.testing.FailingAllocator at fail_index = 3.
    // Before fix: the partially-built clone leaks (FailingAllocator's
    // deinit/testing harness reports the leak). After: clean error.OutOfMemory.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 3 });
    const result = cloneJsonValue(failing.allocator(), original);
    try std.testing.expectError(error.OutOfMemory, result);
    // testing.allocator leak check at test end is the assertion
}
```

- [ ] **Step 3: Fix:** in the `.array` branch add `errdefer { for (cloned_array.items) |it| freeJsonValue(allocator, it); cloned_array.deinit(); }` immediately after `init`; in the `.object` branch add the matching errdefer freeing duped keys + values + map, and free `cloned_key` if the value-clone fails before `put` (`errdefer allocator.free(cloned_key);` scoped per-iteration via a block).
- [ ] **Step 4/5: test-all PASS; commit** `fix(json_util): errdefer partial clones (GAP-048)`

### Task C2: GAP-044 (A5) — `formatRfc3339` negative-timestamp guard

**Files:** `src/time.zig:40-59`; tests in `src/time.zig`.

- [ ] **Step 1: Failing test:** `try std.testing.expectEqualStrings("", formatRfc3339(-1000, &buf));` (panics before fix).
- [ ] **Step 3: Fix:** at the top: `const secs_u64 = std.math.cast(u64, seconds) orelse return "";` then use `.{ .secs = secs_u64 }`. (Empty-string failure contract already documented on the vtable.)
- [ ] **Commit** `fix(time): formatRfc3339 returns "" for pre-epoch timestamps (GAP-044/A5)`

### Task C3: QR-011 — `isSensitiveKey` long-key fail-open

**Files:** `src/filters.zig:40-60` (read the function first); test in `tests/test_filters.zig`.

- [ ] **Step 1: Failing test:** key of 300 chars ending in `"password"` with a sensitive value must be redacted.
- [ ] **Step 3: Fix:** drop the 256-byte stack-lowercase approach; match patterns case-insensitively without materializing a lowered copy, using `std.ascii.indexOfIgnoreCase(key, pattern)` per sensitive pattern (the deny-pattern loop at `filters.zig:449-451` already uses exactly this — make `isSensitiveKey` consistent). Preserve exact-match vs substring semantics the current implementation has (read it first; replicate behavior 1:1 apart from the length cap).
- [ ] **Commit** `fix(filters): isSensitiveKey no longer fail-opens on keys >256 bytes (QR-011)`

### Task C4: QR-009 — rotation accounting off-by-one

**Files:** `src/file_sink.zig:122-129`.

- [ ] **Step 1: Failing test:** with `max_bytes` set so that `current_size + line.len == max_bytes` but `+1` (the newline) exceeds it, assert rotation occurs (file `.1` exists after exactly the boundary write).
- [ ] **Step 3: Fix:** `try self.checkRotation(line.len + 1);`
- [ ] **Commit** `fix(file_sink): include newline in rotation size check (QR-009)`

### Task C5: QR-010 — `resolveOrCached` clock cast hardening

**Files:** `src/syslog.zig:235-247`.

- [ ] **Step 3 (no practical failing test — absurd-clock guard):** replace `const now_ms: i64 = @intCast(now_i128)` with `const now_ms: i64 = std.math.lossyClamp` equivalent: `const now_ms: i64 = std.math.cast(i64, now_i128) orelse std.math.maxInt(i64);` and make the TTL comparison explicit: `if (elapsed >= 0 and elapsed < @as(i64, @intCast(self.dns_cache_ttl_ms)))`. Add a unit test with a `FixedClock` set to a huge i128 value driving `resolveOrCached` if testable through the mock; otherwise document with a comment + keep the clamp.
- [ ] **Commit** `fix(syslog): clamp i128 clock to i64 in DNS cache (QR-010)`

### Task C6: GAP-074 + QR-017 — version single-source

**Files:** `src/root.zig:36`, `tests/integration.zig:19,60`, `src/config.zig:519` (loadTestConfig uses root.version — verify).

- [ ] **Step 1: Failing test (in `src/root.zig`):**

```zig
test "root.version matches build.zig.zon (GAP-074)" {
    const zon = @embedFile("../build.zig.zon");
    var buf: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&buf, ".version = \"{s}\"", .{version}) catch unreachable;
    try std.testing.expect(std.mem.indexOf(u8, zon, needle) != null);
}
```

(If `@embedFile` outside the module root path is rejected, instead add `version` to `build.zig.zon`-driven build options, or simplest: keep the literal but add this test via `@embedFile` after adding `build.zig.zon` to the module include set — if neither works, update the literal and leave a comment pairing it with `.cz.yaml`'s bump config so commitizen bumps both: check `.cz.yaml` `version_files` and ADD `src/root.zig` to it so future bumps stay in sync.)

- [ ] **Step 3: Fix:** set `pub const version = "0.1.6";`, update the two integration assertions, and add `src/root.zig:version` to `.cz.yaml` `version_files` list.
- [ ] **Commit** `fix(root): sync version to 0.1.6 and wire into cz bump (GAP-074, QR-017)`

### Task C7: GAP-046 (A7) — render the event's own timestamp

**Files:** `src/file_sink.zig:172-174` + `formatJsonLine` signature already has `event`; `src/cef.zig:~25-35` (`formatCef`); `src/syslog.zig:~347-360` (`formatRfc5424`); callers/tests.

- [ ] **Step 1: Failing test:** build an event with `ts_unix_ms = time.TEST_TIMESTAMP_MS + 5000` while the `FixedClock` stays at `TEST_TIMESTAMP_MS`; assert the file line / CEF output contains the *event's* timestamp (`...:05.000Z`), not the clock's.
- [ ] **Step 3: Fix:** in each formatter replace `self.clock.nowRfc3339(&ts_buf)` with `time.formatRfc3339(event.ts_unix_ms, &ts_buf)`. `audit()` already stamps `ts_unix_ms` when 0; formatters can still fall back to the clock when `event.ts_unix_ms == 0` (direct public-formatter calls): `const timestamp = if (event.ts_unix_ms != 0) time.formatRfc3339(event.ts_unix_ms, &ts_buf) else self.clock.nowRfc3339(&ts_buf);`. Existing tests keep passing because Fixed clocks and TEST_TIMESTAMP_MS agree; update any that don't.
- [ ] **Commit** `fix(sinks): render event ts_unix_ms as the authoritative timestamp (GAP-046/A7)`

### Task C8: GAP-072 + GAP-073 + QR-006 — remove the dead `requestId` vtable

**Files:** `src/time.zig:111-129` (VTable + method), `:138,172-176` (SystemIdGen), `:187,212-215` (FixedIdGen), tests `:255-265,283-285`; grep repo-wide for `requestId` (logger does not use it; `TEST_REQUEST_ID` stays for FixedIdGen.init compat — also remove the `request_id` field of FixedIdGen and the third `init` arg, updating all callers: `src/logger.zig` tests, `tests/*.zig`, `benchmarks/*.zig`).

- [ ] **Step 1:** `grep -rn "requestId\|TEST_REQUEST_ID\|request_id: \[\]const u8" src/ tests/ benchmarks/ examples/` — enumerate all call sites.
- [ ] **Step 2: Remove** the vtable entry, both impls, the `IdGen.requestId` wrapper, FixedIdGen's `request_id` field + init param, and the two requestId tests. Update every `FixedIdGen.init(a, b, c)` call to `FixedIdGen.init(a, b)`. Keep `TEST_REQUEST_ID` deleted unless used elsewhere.
- [ ] **Step 3: test-all PASS (this IS the test — full suite + `zig build check` proves no dangling references). Commit** `refactor(time): remove unused requestId vtable method (GAP-072, GAP-073, QR-006, Q11, Q19)`

### Task C9: QR-007 — remove dead `RingBuffer`

**Files:** Delete `src/ring_buffer.zig`; modify `src/root.zig:81` (remove re-export); grep for `ring_buffer`/`RingBuffer` (syslog doc comments may reference it — update prose).

- [ ] **Step 1:** `grep -rn "RingBuffer\|ring_buffer" src/ tests/ benchmarks/ build.zig` — confirm only root re-export + own file (+ comments).
- [ ] **Step 2: Delete + update.** `zig build test-all` PASS.
- [ ] **Commit** `refactor: remove superseded RingBuffer from public API (QR-007, NEW-Q-009)`

### Task C10: GAP-061 — remove unreachable PEM branch; S13 — Mock @panic

**Files:** `src/filters.zig:464-472`; `src/syslog.zig` (MockSyslogSender init `@panic` — locate with grep).

- [ ] **Step 1:** Delete the documented-unreachable `isPemPrivateKey(...) and !startsWith(...)` block (PEM values are already redacted via the surrounding `.redact` path; `drop_event` for PEM remains reachable through `shouldFilterField`'s detection on *values* — verify with the existing drop_event test in test_filters.zig before deleting; if drop_event is ONLY produced here, keep the drop semantics by instead making the condition reachable: `if (isPemPrivateKey(str_value)) return .drop_event;` — read the tests and pick the variant that keeps them green and the documented behavior "PEM in metadata drops the event" true).
- [ ] **Step 2:** Replace MockSyslogSender's `@panic` in init with returning an error (`error.MockInitFailed` or similar) and update its test usage.
- [ ] **Step 3: test-all PASS. Commit** `fix(filters,syslog): resolve unreachable PEM branch; Mock returns error not panic (GAP-061, S13)`

### Task C11: QR-013 + QR-014 — strengthen weak integration assertions; isolate tmpdirs

**Files:** `tests/integration.zig:108-120,134,235-246,297-305`; `src/file_sink.zig:303` etc.

- [ ] **Step 1:** Replace every `readFileAlloc(...) catch return;` + `if (content.len > 0)` guard with hard assertions: `const content = try cwd.readFileAlloc(...); try testing.expect(content.len > 0);` then the redaction asserts unconditionally.
- [ ] **Step 2:** Give each test file a unique tmp dir (`zig-out/tmp/it-<testname>` / `zig-out/tmp/fs-<testname>`), removing the shared `test-logs` collision.
- [ ] **Step 3: test-all PASS. Commit** `test: harden integration assertions, isolate tmpdirs (QR-013, QR-014)`

---

## Wave D — Perf quick wins

### Task D1: PR-006a — one write per line (append newline at format time)

**Files:** `src/file_sink.zig:122-132` (`writeLine`), `formatJsonLine`, `writeError`.

- [ ] **Step 1:** Make `formatJsonLine`/`writeError` produce the line **with trailing `\n`** (serialize into `std.array_list` buffer via `std.json.Stringify` writer + `append('\n')` + `toOwnedSlice`; or post-process: `valueAlloc` then `allocator.realloc`+append — prefer the writer). `writeLine` then issues a single `writeStreamingAll(io, line)` and `current_size += line.len`.
- [ ] **Step 2:** Existing line-count tests assert content; they keep passing. Add assertion that file content ends with exactly one `\n` per record (reuse the periodic test's split logic).
- [ ] **Commit** `perf(file_sink): single write per record (PR-006 part 1)`

### Task D2: PR-012 + PR-006b — worker drain batching with buffered flush

**Files:** `src/file_sink.zig:111-118` (worker), `src/syslog.zig:213-220` (worker); `src/channel.zig` (add `tryReceive` exists — verify; worker uses blocking `receive()` then non-blocking `tryReceive()` loop).

- [ ] **Step 1: Failing test (behavioral):** burst N=500 writes, deinit, assert all 500 lines present (drain correctness under batching).
- [ ] **Step 2: Implement file worker batching:**

```zig
    fn workerThread(self: *FileSink) void {
        var batch: std.ArrayList([]const u8) = .empty;
        defer batch.deinit(self.allocator);
        while (self.ch.receive()) |first| {
            batch.append(self.allocator, first) catch { self.writeOne(first); continue; };
            while (batch.items.len < 256) {
                const next = self.ch.tryReceive() orelse break;
                batch.append(self.allocator, next) catch { self.writeOne(next); break; };
            }
            self.writeBatch(batch.items) catch |err| log.warn("file sink write error: {s}", .{@errorName(err)});
            for (batch.items) |line| self.allocator.free(line);
            batch.clearRetainingCapacity();
        }
    }
```

`writeBatch` concatenates into a reusable `std.ArrayList(u8)` buffer (rotation check per line with each line's len; flush buffer before rotating when a rotation boundary hits mid-batch — simplest correct: for each line, if rotation needed: flush buffer, rotate, continue filling), one `writeStreamingAll` per flush, then ONE `maybeFsync` per batch — with `.per_event` mode still fsyncing once per batch flush is a behavior change; preserve `.per_event` semantics by treating batch flushes as the event boundary **only when sync_mode != .per_event**; for `.per_event`, write+fsync per line (durability contract preserved).

- [ ] **Step 3: test-all PASS (incl. rotation + periodic tests). Run `zig build scale-bench 2>/dev/null | head -40` and record `file_sink_ns` / `logger_ops_sec` before/after in the commit message.**
- [ ] **Commit** `perf(file_sink,syslog): batch worker drains; buffered writes (PR-012, PR-006)`

### Task D3: GAP-057 + GAP-055 + GAP-053 + PR-001 + NEW-PERF-005 — streaming JSON serialization for the file line

**Files:** `src/file_sink.zig:150-224` (replace `putField` + `formatJsonLine` map-building wholesale).

- [ ] **Step 1: Characterization test first:** capture current `formatJsonLine` output for a fully-populated event + metadata (all optional fields set, nested metadata object) into expected JSON, asserting parsed-equality (parse both with `std.json.parseFromSlice` and compare values — field order may change; do NOT compare raw strings).
- [ ] **Step 2: Reimplement** using `std.json.Stringify` writer API directly into an `std.ArrayList(u8)`:

```zig
    fn formatJsonLine(self: *FileSink, event: *const events.AuditEvent, filtered_metadata: ?std.json.Value) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        var stringify: std.json.Stringify = .{ .writer = ..., .options = .{} }; // adapt to 0.16 API; read std source
        try stringify.beginObject();
        var ts_buf: [64]u8 = undefined;
        const timestamp = if (event.ts_unix_ms != 0) time.formatRfc3339(event.ts_unix_ms, &ts_buf) else self.clock.nowRfc3339(&ts_buf);
        try stringify.objectField("ts");  try stringify.write(timestamp);
        try stringify.objectField("category"); try stringify.write(event.category);
        ... // all fixed fields, optionals behind if
        if (filtered_metadata) |metadata| if (metadata == .object) {
            var iter = metadata.object.iterator();
            while (iter.next()) |entry| {
                if (isFixedFieldName(entry.key_ptr.*)) continue; // metadata may not shadow fixed keys anymore — see note
                try stringify.objectField(entry.key_ptr.*);
                try stringify.write(entry.value_ptr.*); // Stringify.write handles std.json.Value
            }
        };
        try stringify.endObject();
        try out.append(self.allocator, '\n');
        return out.toOwnedSlice(self.allocator);
    }
```

**Behavior note:** the old code let metadata *overwrite* fixed fields via fetchSwapRemove. Preserve that: metadata keys win. With streaming, invert: when writing fixed fields, skip any whose name exists in `metadata.object` (single `metadata.object.contains(name)` check per fixed field), then write all metadata entries. Assert this in the characterization test (metadata key `"category"` overrides). This removes the 4th metadata deep-copy, the constant-key dupes, and the throwaway ObjectMap in one change. Adapt the exact `std.json.Stringify` streaming API from the installed std (read `lib/std/json/Stringify.zig`); if the writer-based API differs, use whatever incremental emitter 0.16 provides.

- [ ] **Step 3: test-all PASS; scale-bench delta recorded. Commit** `perf(file_sink): stream JSON line directly, drop intermediate ObjectMap (GAP-057, GAP-055, GAP-053, PR-001, NEW-PERF-005)`

### Task D4: small allocations — GAP-051, GAP-052, PR-005, PR-008, GAP-056

**Files:** `src/syslog.zig:313-314`; `src/cef.zig:35-101, 218-234`; `src/logger.zig:209-247`.

- [ ] **Step 1 (GAP-051):** TCP length prefix via `var prefix_buf: [24]u8 = undefined; const prefix = try std.fmt.bufPrint(&prefix_buf, "{d} ", .{message.len});` — delete the allocPrint/free pair.
- [ ] **Step 2 (GAP-052):** in `formatCef`, escape `actor_id` once into a local, reuse for `suser` and `cs1`; same for `request_id` (`requestId`/`deviceExternalId`). Free once.
- [ ] **Step 3 (PR-005):** `escapeCefString` fast path: pre-scan for any byte needing escape; if none, return `allocator.dupe(u8, input)` (single exact-size alloc, no ArrayList growth); else `initCapacity(input.len + 16)` as today.
- [ ] **Step 4 (PR-008):** format the RFC3339 timestamp once per `send`/`write` call rather than once per nested helper where applicable after Task C7 (verify with grep that each sink formats it exactly once per record; CEF + RFC5424 within a single syslog send currently each format — pass the formatted slice from `send` into both).
- [ ] **Step 5 (GAP-056):** replace `estimateEventSize`'s `valueAlloc` metadata measurement with a counting writer (`std.Io.Writer` discarding/counting adapter from std, or a tiny local `CountingWriter` struct) + `std.json.Stringify` into it — byte-exact without allocation.
- [ ] **Step 6: test-all PASS; `zig build bench` sanity. Commit** `perf(cef,syslog,logger): kill per-event micro-allocations (GAP-051, GAP-052, GAP-056, PR-005, PR-008)`

### Task D5: GAP-054 — single detection pass in filters

**Files:** `src/filters.zig:444-488` (`shouldFilterField`), `FilterResult` type (read its definition), `:328-362`.

- [ ] **Step 1:** Extend the `.redact` payload to carry the detected *value* token as well: `.redact: struct { key_token: ?RedactionToken, value_token: ?RedactionToken }` (read `FilterResult`'s current shape and keep naming consistent). `shouldFilterField` computes `detectValueType*` at most once, stores it; the redact block in `filterAndRedactMetadataRecursive` uses the precomputed `value_token` instead of calling `detectValueType` again (line ~341).
- [ ] **Step 2:** Tests: existing filter tests cover semantics; add one asserting a PAN value under a sensitive key still maps to the card token (the precomputed path).
- [ ] **Step 3: test-all PASS. Commit** `perf(filters): detect value type once per field (GAP-054, PERF-014)`

### Task D6: PR-013 + PR-010 partial — multi-producer bench + channel signal/padding

**Files:** `benchmarks/scale_bench.zig`; `src/channel.zig:17-73`.

- [ ] **Step 1 (PR-013):** add `benchChannelMultiProducer` to scale_bench: P ∈ {1,2,4,8} producer threads × 100k sends each into one consumer; emit `channel_mp{P}_ops_sec` into the JSON output (follow the existing bench JSON emit pattern).
- [ ] **Step 2 (PR-010/PR-009 cheap part):** in `BoundedChannel`: (a) signal `not_empty` only when the queue was empty before the send (`if (count_before == 0) self.not_empty.signal();` — single-consumer invariant documented in the struct doc, assert it); (b) cache-line-pad: reorder fields grouping producer-written (`tail`, `count`, `mutex`) vs consumer-read (`head`) with `cache_line`-aligned padding (`std.atomic.cache_line`).
- [ ] **Step 3:** run the new bench before/after, record numbers in commit message. All channel tests (`channel.zig:120-255`) must stay green — they exercise MT producer/consumer.
- [ ] **Commit** `perf(channel): empty-transition signaling + cache-line layout; add multi-producer bench (PR-013, PR-010, PR-009-partial)`

---

## Wave E — Metadata copy reduction (GAP-049, PERF-001/#39, PERF-005)

### Task E1: filter directly from caller metadata; move (don't clone) the filtered tree

**Files:** `src/logger.zig:108-160`; `src/events.zig:109-151` (add `cloneWithoutMetadata` or an option).

**Design:** copies today: (1) `ev.clone()` deep-clones metadata; (2) filter builds a new tree from the clone; (3) `cloneJsonValue(filtered)` back onto the event; plus file sink used to re-clone (killed in D3). Target: ONE owned tree — filter reads the **caller's** metadata (read-only) and produces the owned filtered tree, which is **moved** onto the cloned event.

- [ ] **Step 1: Characterization tests already cover redaction end-to-end (integration.zig). Add a leak-sensitive test:** `audit()` with nested metadata under DebugAllocator (leak check on deinit) — guards the move semantics.
- [ ] **Step 2: Implement:**

In `events.zig` add:

```zig
    /// Like `clone`, but does not copy `metadata` (left null). Used by the
    /// logger, which derives the event's metadata from the *original* via
    /// the redaction filter and attaches the filtered tree directly.
    pub fn cloneWithoutMetadata(self: *const AuditEvent, allocator: std.mem.Allocator) !AuditEvent {
        var copy = self.*;
        copy.metadata = null;
        // reuse the field-dupe logic: factor the string-field duping out of
        // clone() into a private helper used by both.
        ...
    }
```

In `audit()`:

```zig
        var event = try ev.cloneWithoutMetadata(self.allocator);
        defer event.freeCloned(self.allocator);
        ...
        if (ev.metadata) |original_metadata| {
            const filtered = try filters.filterAndRedactMetadata(self.allocator, original_metadata, &self.config.filters);
            if (filtered == null) {
                // drop_event path (unchanged semantics)
                if (self.file_sink) |sink| _ = try sink.writeError("Event dropped due to unredactable sensitive content");
                span_ok = true; span_durable = false; return;
            }
            event.metadata = filtered; // MOVE: freeCloned frees it
        }
```

Delete the old free/clone-back block (lines 152-160) and the `filtered_metadata` defer. `filters.filterAndRedactMetadata` already returns an independently-owned tree for all input shapes (after Task A2).

- [ ] **Step 3: test-all PASS under DebugAllocator; scale-bench `clone_ns`+`logger_ops_sec` delta recorded.**
- [ ] **Commit** `perf(logger): single-copy metadata pipeline — filter from caller tree, move into event (GAP-049, PERF-001, PERF-005, #39)`

---

## Wave F — Docs, CI, scripts, hygiene

### Task F1: QR-015, QR-016, QR-018 — truthful docs

**Files:** `SECURITY.md:42-43`, `README.md:4,12,143-209,213-214`.

- [ ] Replace "No Undefined Behavior … / Memory Safety: Zig's compile-time memory safety checks" claims with accurate language: "Memory-safety bugs found by audit are tracked and fixed under TDD; ReleaseSafe builds keep runtime safety checks enabled." Update Zig badge + Requirements to **0.16.0**. Change "Cross-Platform: Linux, macOS, Windows" to reflect reality: file sink cross-platform; syslog transport currently Linux-only (`std.os.linux`), tracked in the issue for QR-018.
- [ ] **Commit** `docs: truthful security/platform/version claims (QR-015, QR-016, QR-018)`

### Task F2: GAP-DD1 — document the sync_mode decision

**Files:** `README.md` (file sink section), `src/config.zig:88-99` (SyncMode doc comment).

- [ ] Decision: KEEP `.per_event` as the default (audit libraries default to durability; throughput opt-in). Document the tradeoff and the `periodic`/`none` options with the measured throughput difference. Note decision in the GAP-DD1 issue and close it as resolved-by-documentation.
- [ ] **Commit** `docs(config): document sync_mode durability/throughput tradeoff (GAP-DD1)`

### Task F3: GAP-069, GAP-070, GAP-071, GAP-064, GAP-065 — CI & supply chain

**Files:** `.gitleaks.toml:11-15`, `.gitlab-ci.yml`, `.pre-commit-config.yaml`.

- [ ] **GAP-069:** add `tests/integration\.zig` to the gitleaks allowlist paths.
- [ ] **GAP-070:** add GitLab `cache:` keyed on `$ZIG_VERSION` covering the zig install dir and `.zig-cache/` for the build/test jobs (follow GitLab cache syntax; key: `zig-$ZIG_VERSION-$CI_JOB_IMAGE`).
- [ ] **GAP-071:** add a `lint:python` job running `ruff check scripts/ && ruff format --check scripts/` (use a pinned ruff image/version).
- [ ] **GAP-064:** pin pre-commit hook `rev:` entries to full commit SHAs (resolve each tag: `git ls-remote <repo> <tag>`); add a comment with the human-readable tag next to each SHA. For CI catalog components: pin `@v1.7.1`-style includes to the component release SHA if the catalog supports it (`@<sha>`); if unsupported by `gitlab.com/devnw/ci-catalog`, document the residual risk in the issue and keep tags (first-party catalog).
- [ ] **GAP-065:** record the expected Zig tarball SHA-256 directly in `.gitlab-ci.yml` as a variable (out-of-band trust anchor), verify against it instead of (or in addition to) the fetched index.
- [ ] Validate: `pre-commit run --all-files` (hooks still resolve), CI lint passes (`yamllint`-by-eye; can't run pipelines locally).
- [ ] **Commit** `ci: caches, python lint gate, SHA pinning, gitleaks allowlist (GAP-064, GAP-065, GAP-069, GAP-070, GAP-071)`

### Task F4: GAP-066, GAP-067, GAP-068 — Python script robustness + formatting debt

**Files:** `scripts/detect_diamond_deps.py:178`, `scripts/sync_diamond_deps.py:248-253,353-357`; pre-commit formatting failures (`scripts/detect_diamond_deps.py` ruff-format; MD040 in `.gitlab/issue_templates/Bug Report.md:44`, `docs/PERF_GAP_ANALYSIS.md:158`, `CONTRIBUTING.md:48`, `docs/SECURITY_GAP_ANALYSIS.md:37`; `.cz.yaml` pretty-format).

- [ ] **GAP-066:** in `_zon_path_for_hash`, validate `pkg_hash` against `^[A-Za-z0-9._-]+$` before path join; raise a clear error otherwise. Add a pytest-style unit or a simple `if __name__` self-test only if the repo has a Python test pattern — otherwise inline `assert`-style validation with a unit test added under `scripts/` if a test convention exists (check; if none, validation + manual run is acceptable, note it).
- [ ] **GAP-067:** wrap `parse_target` splits with validation: malformed `--target` → `sys.exit(2)` with usage message instead of traceback.
- [ ] **GAP-068:** in `rewrite_pin`, reject `new_url`/`new_hash` containing `"` or newline before substitution.
- [ ] Run `ruff format scripts/ && ruff check scripts/`; fix MD040 by adding languages to the bare code fences (```text where unknown); run `pre-commit run --all-files` until clean (it will rewrite `.cz.yaml`).
- [ ] **Commit** `fix(scripts): input validation; format debt cleanup (GAP-066, GAP-067, GAP-068)`

### Task F5: GAP-058, GAP-059, GAP-060, GAP-062 — readability refactors (no behavior change)

**Files:** `src/logger.zig:79-207`, `src/config.zig:225-336`, `src/filters.zig:308-378`.

- [ ] **GAP-058:** extract from `audit()`: `enrichClonedEvent(&event)` (timestamp + trace/span stamping), `applyRedaction(...)` (the metadata block), keeping `audit()` ≤ ~60 lines of orchestration. No semantic change — full suite green is the gate.
- [ ] **GAP-059:** extract `parseService`, `parseIdentity`, `parseSinks`, `parseFilters` private fns from `parseConfig`.
- [ ] **GAP-060:** name the redact-string resolution as `resolveRedactedString(allocator, value, key_token, filters_cfg) ![]const u8` replacing the labeled block.
- [ ] **GAP-062:** for each `pub` helper in `filters.zig` flagged unused (`detectValueType`, `isEmail`, `isJwt`, `isPan`, `isPemPrivateKey`, `isPhone`, `maskEmail`, `maskPhone`): grep `tests/` — if used by external test files keep `pub` (document "exposed for testing"), otherwise drop `pub`.
- [ ] **Commit** `refactor: decompose audit()/parseConfig/redaction flow (GAP-058, GAP-059, GAP-060, GAP-062)`

### Task F6: Final verification + tracking close-out

- [ ] `zig fmt --check src/ build.zig tests/ benchmarks/ examples/` clean
- [ ] `zig build check && zig build test-all --summary all` — all green
- [ ] `zig build test -Doptimize=ReleaseSafe && zig build test -Doptimize=ReleaseFast` — green (CI parity for the config-cast fix)
- [ ] `pre-commit run --all-files` — clean
- [ ] `zig build scale-bench` — record final numbers vs `benchmarks/results/baseline.json`; if logger_ops_sec improved >20%, refresh the baseline per `make bench-baseline` and commit it
- [ ] Update `docs/GAP_ANALYSIS.md` / domain docs: move every fixed Gap-ID to `docs/GAP_ANALYSIS_RESOLVED.md` with evidence (file:line of fix + test name); close the corresponding GitLab issues with a comment citing commit SHAs (`glab issue close <n> -m "..."`). Leave open: GAP-005/#25 (blocked Zig stdlib), GAP-045/#24 dns-tag dimension (blocked cross-repo), PR-009 full channel redesign (gated on the new MP bench data — note D6 partial), QR-018 syslog portability (feature work, tracked).
- [ ] **Commit** `docs: reconcile gap analyses after remediation cycle`

---

## Self-review notes

- Spec coverage: A1–A8 → B1/B6/B3/B4/C2/(GAP-045 blocked)/C7/B3; QR-001..018 → A1/A2/A3/A4/B6/C8/C9/(QR-008 deferred — explicit error sets is an API-design change; tracked, see below)/C4/C5/C3/A2+A3 tests/C11/C11/F1/F1/C6/F1; PR-001..013 → D3/D4(PR-002 folded: optional — see note)/D5-adjacent/D-waves/E1/D1-D2/D4/D4/D6-partial/D6/B6/D2/D6; GAP-040..074 all mapped above except GAP-045 (blocked cross-repo) and GAP-005 (blocked).
- **Explicitly deferred (tracked, not fixed this cycle):** QR-008 (explicit error sets — public API design pass, schedule with next minor), PR-002 (getEventName StaticStringMap — optional micro-opt; fold into D4 if trivial), PR-009 full lock-free MPSC (needs D6 bench data first), PR-003 detector short-circuiting (fold into D5 only if tests stay green trivially; otherwise tracked).
- Placeholder scan: code sketches above marked "adapt to the actual API" require the implementer to read the installed std source — intentional for 0.16 API drift; each such step names the exact file to consult.
- Type consistency: `SendStatus` defined once in file_sink.zig and re-used by syslog (move to a shared location if import direction is awkward — `events.zig` or a small `types.zig`; implementer picks, tests gate).
