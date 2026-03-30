# Benchmark Results

This directory stores JSON benchmark results from `scale_bench.zig` for tracking performance over time.

## File Format

Each file is a JSON document with version, timestamp, system info, and per-tier metrics:

```json
{
  "version": 1,
  "timestamp": "2026-03-30T12:00:00Z",
  "git_commit": "abc1234",
  "system": { "os": "linux", "arch": "x86_64" },
  "tiers": [
    {
      "name": "1K",
      "event_count": 1000,
      "logger_ops_sec": 50000,
      "channel_ops_sec": 5000000,
      "validate_ns": 15,
      "clone_ns": 500,
      "cef_format_ns": 2000,
      "filter_redact_ns": 3000,
      "file_sink_ns": 800,
      "mixed_ops_sec": 2000000
    }
  ]
}
```

## Naming Convention

- `baseline.json` -- the current accepted performance baseline
- `<short-sha>.json` -- results saved per commit via `make bench-save`

## Usage

```bash
make bench                 # Run micro-benchmarks
make scale-bench           # Run incremental scale benchmark
make bench-save            # Run and save to results/<sha>.json
make bench-baseline        # Save current results as baseline
make bench-compare         # Compare current against baseline
```
