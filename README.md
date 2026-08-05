<p align="center">
  <img src="assets/banner.jpg" alt="MCPDoctor banner" width="100%"/>
</p>

# MCPDoctor

**Lint and pin MCP tool catalogs.** Full-schema static analysis for tool poisoning (MCP03), plus content-hash pin/check for rugpulls.

Not a jailbreak generator. Not a model judge. Default path is **non-mutating** (no `tools/call`).

[![CI](https://github.com/SamsonCyber/mcpdoctor/actions/workflows/ci.yml/badge.svg)](https://github.com/SamsonCyber/mcpdoctor/actions/workflows/ci.yml)

## Install

```bash
cargo install --path .
# binary: mcpdoctor  (compat alias: mcp-poison)
```

## Happy path

```bash
# Offline fixtures (exit 2 = findings at/above --fail-on)
mcpdoctor fixtures/t3_line_jump.json
mcpdoctor scan fixtures/clean_calculator.json --trusted   # expect 0 findings

# Cross-server shadow (two tools/list dumps)
mcpdoctor multi fixtures/t4_cross_server_a.json fixtures/t4_cross_server_b.json

# Live stdio (Python FastMCP = NDJSON)
mcpdoctor scan -- python -m agent_tooling.sqlite_mcp
mcpdoctor scan --command python --arg=-m --arg agent_tooling.sqlite_mcp

# Pin / rugpull gate
mcpdoctor pin fixtures/clean_calculator.json --server-key calc
mcpdoctor check fixtures/t1_description_poison.json --server-key calc
```

Exit codes: **0** clean · **2** findings · **1** error.

## What it does

1. Speaks MCP over stdio (`initialize` → `tools/list`) or loads a captured list.
2. Walks **every schema string leaf** (name, title, description, param keys, nested schema).
3. Runs static detectors (instruction override, exfil paths, line-jump, ANSI, semantic param names, pin drift, …).
4. Emits structured JSON findings with technique tags (T1–T12 style) and OWASP MCP03 / ATLAS hints.
5. Optional **pin store**: hash inventory after human review; CI fails on silent description swap.

### Hard limits (anti-DoS)

| Limit | Value |
|-------|------:|
| tools/list file size | 8 MiB |
| tools per inventory | 5_000 |
| schema walk depth | 64 |
| string leaves | 50_000 |
| string chars (clip) | 500_000 |
| stdio handshake | timeout + kill |

### Honest scope

| This tool | Not this tool |
|-----------|----------------|
| Static schema / metadata poison | Live ASR against a specific model |
| Pin/rugpull for supply chain | Full MCP gateway runtime |
| Cross-server description shadow (multi lists) | Dynamic `tools/call` output injection (roadmap) |
| NDJSON + Content-Length read | Hosted SaaS |

Hygiene docs ("do not put API keys in the query") and lab canary writeups are filtered so red-team servers do not always fail closed.

## Architecture

```text
CLI (clap)
  → scan | multi | pin | check | detectors
  → client/stdio (NDJSON or Content-Length)
  → normalize (full-schema walk, caps)
  → detectors (rules + concealment + semantic + pin)
  → report (JSON / Markdown, exit codes)
```

Library crate: `mcpdoctor` (`scan_from_tools_list`, `scan_stdio`, `scan_multi_lists`).

## Tests

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

Includes offline fixtures (T1/T3/T6/T8), pin rugpull, multi-list, and a live NDJSON mock server under `tests/mock_mcp_server.py`.

## License

MIT