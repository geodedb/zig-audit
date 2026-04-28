# audit

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.15.1+-orange.svg)](https://ziglang.org/)

A Zig library for audit

## Features

- **Minimal Dependencies**: Zig standard library plus a small DNS resolution library
- **Memory Safe**: Proper allocation patterns with no leaks
- **Cross-Platform**: Linux, macOS, Windows support
- **Well Tested**: Comprehensive unit and integration tests

## Installation

### Using Zig Package Manager

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .audit = .{
        .url = "https://gitlab.com/devnw/zig/audit/-/archive/v0.1.0/audit-v0.1.0.tar.gz",
        .hash = "...",
    },
},
```

Then in your `build.zig`:

```zig
const audit = b.dependency("audit", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("audit", audit.module("audit"));
```

## Quick Start

```zig
const audit = @import("audit");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Load configuration from a JSON file
    var cfg = try audit.config.loadConfig(allocator, "audit.json");

    // Create a logger with file + syslog sinks
    const logger = try audit.logger.buildAuditLogger(allocator, &cfg);
    defer logger.deinit();

    // Emit an audit event
    try logger.audit(&.{
        .category = "auth",
        .action   = "login",
        .outcome  = .success,
        .severity = .INFO,
        .actor_id = "jane.doe",
        .ts_unix_ms = 0, // 0 = use injected clock
        .subject_id = null,
        .request_id = null,
        .session_id = null,
        .source_ip  = null,
        .trace_id   = null,
        .span_id    = null,
        .metadata   = null,
    });
}
```

## CEF Identity Configuration

Audit events are formatted using the Common Event Format (CEF). The CEF header
includes vendor, product, and version fields that identify the source of audit
records. Configure these via the `identity.cef` section of your JSON config
file:

```json
{
  "identity": {
    "cef": {
      "vendor": "YourCompany",
      "product": "YourProduct",
      "version": "2.1.0"
    }
  }
}
```

These values appear in every CEF-formatted syslog message as:

```text
CEF:0|YourCompany|YourProduct|2.1.0|...
```

When using `loadTestConfig`, the defaults are `DEVNW`, `AUDIT`, and the
library version (`0.1.0`).

## What's NOT in This Library

This library provides the core, reusable audit infrastructure: event modeling,
metadata filtering/redaction, CEF formatting, file and syslog sinks, and logger
orchestration.

The following remain in [Geode](https://gitlab.com/devnw/geode) and are **not**
included here:

- **Database adapters** (`db_adapter.zig`) -- Geode-specific persistence layer
- **Geode-specific schemas** -- application-level audit record definitions
- **Legacy security audit stack** (`src/security/audit*.zig`) -- to be
  reconciled toward this library in a future release

See [docs/GAP_ANALYSIS.md](docs/GAP_ANALYSIS.md) for the full extraction
boundary and remaining open items.

## Security Considerations

**Syslog destination: prefer IP addresses over hostnames.** In high-security
environments, configure syslog destinations using IP addresses (e.g.,
`"host": "10.0.0.50"`) rather than hostnames. This eliminates the risk of DNS
spoofing attacks redirecting audit logs to an attacker-controlled server. If
hostnames are required, ensure DNSSEC validation is enabled on the resolver or
use a trusted internal DNS infrastructure.

**Transport encryption.** The syslog sink supports UDP and TCP transports. TLS
transport is not yet available natively (see GAP-005 in the gap analysis).
For encrypted syslog transport, use an external TLS tunnel such as
[stunnel](https://www.stunnel.org/) between the application and the syslog
collector.

**File sink permissions.** The file sink sets log files to mode `0640` on
Unix systems, restricting read access to the owner and group. Ensure the
audit log directory has appropriate ownership and permissions.

## Observability

This library ships an optional OpenTelemetry seam, gated behind
`-Dwith_otel=<bool>` (default `false`).

When `-Dwith_otel=false` (the default) the seam collapses to a
comptime-known no-op: every public helper in `audit.observability`
returns a zero-sized `Span{}`, the otel dependency is never resolved,
and the produced artifact contains zero otel symbols (verified by
`otel/scripts/verify-consumer-noop.sh`).

When `-Dwith_otel=true`, the logger emits **one internal-kind span per
audit-record write** at the canonical entry point
`audit.AuditLogger.audit`. Each span is named `"audit.{category}.{action}"`
(e.g. `"audit.auth.login"`) and carries two attributes:

- `event.kind` -- the composed `category.action` taxonomy label.
- `audit.durable` -- `true` if the record reached at least one sink,
  `false` if the redaction policy dropped it or a sink errored.

**PII invariant**: span attributes carry only the kind label and the
durability flag. The audit event PAYLOAD (`actor_id`, `subject_id`,
`source_ip`, `metadata`, etc.) is **never** copied into span
attributes. Operators correlate spans with the persisted audit log via
the standard `trace_id` / `span_id` already recorded on each
`AuditEvent`.

Bootstrap from your application entry point:

```zig
const std = @import("std");
const audit = @import("audit");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();

    var otel = try audit.observability_init.Otel.init(gpa.allocator(), "my-app");
    otel.installGlobals();
    defer otel.deinit();

    var cfg = try audit.config.loadConfig(gpa.allocator(), "audit.json");
    const logger = try audit.logger.buildAuditLogger(gpa.allocator(), &cfg);
    defer logger.deinit();

    try logger.audit(&.{
        .category = "auth",
        .action = "login",
        .outcome = .success,
        .severity = .INFO,
        .actor_id = "jane.doe",
        .ts_unix_ms = 0,
        .subject_id = null,
        .request_id = null,
        .session_id = null,
        .source_ip = null,
        .trace_id = null,
        .span_id = null,
        .metadata = null,
    }); // emits an `audit.auth.login` span
}
```

Configuration follows the OpenTelemetry environment-variable contract
(`OTEL_SERVICE_NAME`, `OTEL_TRACES_SAMPLER`,
`OTEL_EXPORTER_OTLP_ENDPOINT`, etc). Defaults:
`parentbased_traceidratio` @ 5%, OTLP/HTTP to `http://localhost:4318`.

See [otel/docs/integration/RECIPE.md](https://gitlab.com/devnw/zig/otel/-/blob/main/docs/integration/RECIPE.md)
for the full recipe.

## Requirements

- Zig 0.15.1 or later

## Building

```bash
# Build the library
make build

# Run tests
make test

# Quick development iteration
make dev

# Full CI pipeline
make ci
```

## Documentation

See the [docs](docs/) directory for detailed documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
