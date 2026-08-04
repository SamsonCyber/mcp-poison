# mcp-poison

Protocol-native **MCP tool-surface auditor** in Rust.

Connects like an MCP client (or loads a captured `tools/list`), walks **every schema string leaf** (full-schema / FSP), runs static detectors for tool poisoning, and supports **content-hash pin/check** for rugpulls.

Default path is **non-mutating** (no `tools/call`).

## Build

```bash
cargo build --release
# binary: target/release/mcp-poison
```

## Quick start (offline fixtures)

```bash
# Line-jump poison (T3) — expect findings, exit 2
cargo run -- scan --from-list fixtures/t3_line_jump.json --markdown

# Clean baseline — expect 0 findings, exit 0
cargo run -- scan --from-list fixtures/clean_calculator.json --fail-on high

# Param-name semantic exfil (T6 / FSP)
cargo run -- scan --from-list fixtures/t6_param_names.json

# ANSI concealment (T8)
cargo run -- scan --from-list fixtures/t8_ansi.json
```

## Pin / rugpull check

```bash
cargo run -- pin --from-list fixtures/clean_calculator.json --store .mcp-poison/pins.json --server-key calc

# After a description swap, check fails:
cargo run -- check --from-list fixtures/t1_description_poison.json --store .mcp-poison/pins.json --server-key calc
```

## Live stdio server

```bash
cargo run -- scan --command npx --arg -y --arg some-mcp-server -o report.json
```

Uses MCP **Content-Length** framing: `initialize` → `notifications/initialized` → `tools/list` (paginated).

## Detectors (MVP)

| ID | Technique | What |
|----|-----------|------|
| D01 | T1 | Instruction-override language |
| D02 | T1 | Secret path / network exfil directives |
| D03 | T3 | Line-jump (consult first / prefix all shell) |
| D04 | T4 | Conceal-from-user / cross-server phrases |
| D05 | T4 | Extreme whitespace hide |
| D06 | T8 | ANSI concealment |
| D07 | T8 | Bidi / zero-width / tag chars |
| D08 | T6 | Param/tool **name** semantic exfil |
| D09 | T12 | Long description + late payload |
| D10 | T11 | Deferred sleeper triggers |
| D11 | T1 | Trusted host tool name collision |
| D12 | T6 | Schema oddity / size |
| D20–D24 | T2 | Pin drift / command swap / new tool |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | OK (no findings at or above `--fail-on`) |
| 1 | Usage / IO / protocol error |
| 2 | Findings at or above threshold |

## Library

```rust
use mcp_poison::scan::{scan_from_tools_list, ScanOptions};
use std::path::Path;

let report = scan_from_tools_list(
    Path::new("fixtures/t3_line_jump.json"),
    &ScanOptions::default(),
    Some("t3"),
)?;
assert!(report.summary.findings > 0);
```

## Safety

- Static analysis only by default
- Fixtures use `CANARY` / `FOO` markers
- Do not point live `--command` at untrusted packages without a sandbox
- Not a jailbreak generator; not a substitute for least-privilege agent design

## Roadmap

- Multi-server config scan + cross-server graph (D04 inventory-aware)
- `serve-mcp` agent tools
- SARIF export
- Optional policy-gated dynamic `tools/call` output scan (D30)

## License

MIT
