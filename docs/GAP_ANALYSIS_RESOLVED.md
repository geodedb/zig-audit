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

## Won't Do

### GAP-002: Geode DB adapter is mixed into the same package tree [RESOLVED]

- **Issue:** N/A (Geode-side task)
- **Category:** Feature
- **Resolution:** `db_adapter.zig` is Geode-specific persistence code. By design, it stays in Geode. Geode should import this library for the core audit surface and keep only the DB adapter locally.
- **Evidence:** `db_adapter.zig` is not present in this repository.
- **Resolved date:** 2026-03-22

### GAP-003: Duplicate audit stack exists under `src/security` [RESOLVED]

- **Issue:** N/A (Geode-side task)
- **Category:** Feature
- **Resolution:** This is a Geode-side reconciliation task. The canonical audit source is now this library. Geode should redirect `src/security/audit*.zig` to import from here, but that refactoring belongs in the Geode repo.
- **Evidence:** No `src/security/` directory exists in this repository.
- **Resolved date:** 2026-03-22
