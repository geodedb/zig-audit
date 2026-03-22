# GAP Analysis — Resolved Items

Items closed or dispositioned during the 2026-03-22 extraction.

## Closed

### GAP-001: Build-time product identity leaks into formatting/config

**Evidence:** `src/audit/cef.zig:206` and `src/audit/config.zig:310` imported `build_options`.

**Resolution:** All `@import("build_options")` references removed. `CefIdentityConfig` now takes vendor/product/version as explicit fields passed by the consumer. `config.loadTestConfig` uses `root.version` (library constant) instead of `build_options.version`.

**Verified:** `grep -r 'build_options' src/` returns no matches.

### GAP-004: External dependencies are implicit today

**Evidence:** `src/audit/syslog.zig` and `src/audit/logger.zig` relied on Geode's repo-level module wiring for `logging`, `json`, and `dns`.

**Resolution:**
- `dns` added as an explicit dependency in `build.zig.zon` (git URL).
- `logging` (Geode-specific slog wrapper) replaced with `std.log.scoped(.audit)`.
- `json` (external JSON library) replaced with `std.json.Stringify.valueAlloc` and `std.json.ObjectMap`.

**Verified:** Library builds with only `dns` as an external dependency.

## Won't Do

### GAP-002: Geode DB adapter is mixed into the same package tree

**Reason:** `db_adapter.zig` is Geode-specific persistence code. By design, it stays in Geode. Geode should import this library for the core audit surface and keep only the DB adapter locally.

### GAP-003: Duplicate audit stack exists under `src/security`

**Reason:** This is a Geode-side reconciliation task. The canonical audit source is now this library. Geode should redirect `src/security/audit*.zig` to import from here, but that refactoring belongs in the Geode repo.

## Blocked

### GAP-005: TLS syslog transport

**Evidence:** Geode's `sendTls` used `std.crypto.tls.Client` which is not stable for generic stream wrapping in Zig 0.15.

**Unblock:** Either wait for std.crypto.tls stabilization, or add an external TLS library (e.g., OpenSSL/BoringSSL bindings). Current workaround: `sendTls` returns `error.TlsNotImplemented` with a log message. Consumers needing TLS should use stunnel or a TCP tunnel.
