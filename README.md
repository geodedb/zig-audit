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
