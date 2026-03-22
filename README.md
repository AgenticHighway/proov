# ah-scanner

**Detect, analyze, and report AI execution artifacts on a host machine.**

ah-scanner is a Rust CLI tool that scans your system for AI-related configuration files — things like `.cursorrules`, MCP server configs, prompt files, and container definitions — analyzes them for risk, and optionally submits findings to a verification server.

## How it works

```
Your machine                                 Server (optional)
┌──────────────────────┐                     ┌──────────────────────┐
│                      │                     │                      │
│  ah-scan quick       │   HTTP POST         │  ah-verified-poc     │
│                      │ ──────────────────► │                      │
│  1. Walk filesystem  │  /api/scans/ingest  │  Next.js + Postgres  │
│  2. Detect artifacts │                     │  Stores + displays   │
│  3. Score risk       │                     │  scan results        │
│  4. Report findings  │                     │                      │
└──────────────────────┘                     └──────────────────────┘
```

The scanner is the **client side** of a two-repo system. The companion server is [`AgenticHighway/ah-verified-poc`](https://github.com/AgenticHighway/ah-verified-poc). The scanner works fully offline — server submission is optional and opt-in.

## Install

### From a release binary

Download the latest binary for your platform from [GitHub Releases](https://github.com/AgenticHighway/ah-scanner/releases).

```bash
# macOS (Apple Silicon)
tar xzf ah-scanner-darwin-arm64.tar.gz
./ah-scanner quick

# Linux (x86_64)
tar xzf ah-scanner-linux-amd64.tar.gz
./ah-scanner quick
```

### From source

```bash
git clone https://github.com/AgenticHighway/ah-scanner.git
cd ah-scanner
cargo build --release
./target/release/ah-scan quick
```

## Quick start

```bash
ah-scan                    # Interactive wizard — walks you through options
ah-scan quick              # Fast scan of AI config areas (~/.cursor, VS Code, Claude, etc.)
ah-scan scan               # Default scan (home directory, recursive)
ah-scan full               # Deep system-wide scan (slow, thorough)
ah-scan file <path>        # Scan a single file
ah-scan folder <path>      # Scan a directory
ah-scan repo <path>        # Deep-scan a git repository
```

## Output formats

```bash
ah-scan quick              # Overview with risk bars (default)
ah-scan quick --full       # Detailed per-artifact breakdown
ah-scan quick --summary    # Compact statistics only
ah-scan quick --json       # JSON to stdout
ah-scan quick --out        # JSON to ./ahscan-report.json
ah-scan quick --out r.json # JSON to custom path
```

## What it detects

| Detector              | Files                                                         | What it looks for                                    |
| --------------------- | ------------------------------------------------------------- | ---------------------------------------------------- |
| Cursor / editor rules | `.cursorrules`, `agents.md`, `AGENTS.md`                      | AI instruction files with capability keywords        |
| Prompt configs        | `*.prompt.md`, `*.instructions.md`, `copilot-instructions.md` | Prompt configuration for GitHub Copilot and similar  |
| MCP configs           | `mcp.json`, `claude_desktop_config.json`                      | Model Context Protocol server declarations           |
| Container configs     | `Dockerfile`, `compose.yaml`, `docker-compose.yml`            | Containers with AI-related tooling                   |
| Browser footprints    | Chrome, Edge, Brave, Arc profiles                             | Extension directory presence only (no content reads) |
| Custom rules          | Any `.toml` in `~/.ahscan/rules/`                             | Declarative rules you define                         |

## Risk scoring

Every artifact gets a risk score from 0–100:

| Score | Severity | Color   | Meaning                              |
| ----- | -------- | ------- | ------------------------------------ |
| 90+   | CRITICAL | Magenta | Credential exposure or extreme risk  |
| 70-89 | HIGH     | Red     | Dangerous capability combinations    |
| 40-69 | MEDIUM   | Yellow  | Notable capabilities worth reviewing |
| 10-39 | LOW      | Cyan    | Minor signals, likely benign         |
| 0-9   | INFO     | Dim     | Informational only                   |

Scores are based on: artifact type, detected capability keywords (shell, network, filesystem, etc.), dangerous keywords (exfiltrate, steal, bypass, etc.), and whether capabilities are explicitly declared.

## Access tiers

| Feature           | Lite (default) | Licensed |
| ----------------- | :------------: | :------: |
| Local scanning    |       ✅       |    ✅    |
| Risk scoring      |       ✅       |    ✅    |
| Visible artifacts |     Top 3      |   All    |
| JSON export       |       ❌       |    ✅    |
| Server submission |       ❌       |    ✅    |

Configure in `.ahscan.toml`:

```toml
[access]
mode = "licensed"
license_key = "your-key-here"
```

## Submitting to a server

With a licensed configuration and API key:

```bash
# First-time setup (saves credentials)
ah-scan setup

# Or set credentials directly
ah-scan auth --key your-api-key

# Submit during a scan
ah-scan repo . --submit http://localhost:3000/api/scans/ingest --api-key your-key
```

### Safety defaults

- Only local/private endpoints are allowed by default (`localhost`, `127.0.0.1`, `192.168.x.x`)
- Pass `--allow-public-endpoint` to submit to public servers
- Retry logic handles transient failures (429, 502, 503, 504)
- Audit log is written to `.ahscan-submissions.json` (tokens are never logged)

## Self-update

```bash
ah-scan update           # Check for and install updates
```

The scanner checks S3 for the latest release, verifies SHA-256 checksums, and replaces itself.

## Privacy

- **Path-first scanning** — content is only read from specific allowlisted file types
- **Bounded walking** — max depth of 5, file count limits (50K shallow / 500K deep)
- **No broad ingestion** — `.git/`, `node_modules/`, `.venv/`, `target/` and similar are always excluded
- **Secret detection without storage** — token patterns trigger a signal tag, but values are never stored or transmitted
- **Browser presence only** — extension directories are noted, but no extension content or preferences are read
- **Declarative rules** — custom rules are TOML config files; they use the same content-read allowlist as built-in detectors

## Project structure

```
ah-scanner/
├── crates/
│   └── ah-scan/          # CLI binary (scanning, detection, submission)
├── examples/
│   └── rules/            # Example custom detection rules (.toml)
├── scripts/
│   ├── test-scanner.sh   # Automated test suite
│   └── test-submit.sh    # Manual submission test
├── docs/
│   ├── architecture.md   # System design and data flow
│   ├── detectors.md      # How detection works
│   └── custom-rules.md   # Writing custom detection rules
└── scanner-data-contract.json  # JSON Schema for the ingest API
```

## Developing

```bash
cargo build              # Debug build
cargo test               # Run all tests
cargo clippy             # Lint check (should be 0 warnings)
./scripts/test-scanner.sh  # Exercise all CLI subcommands
```

For detailed development instructions: [CONTRIBUTING.md](CONTRIBUTING.md)
For architecture and code walkthrough: [docs/architecture.md](docs/architecture.md)

## Configuration reference

| File                           | Purpose                                         |
| ------------------------------ | ----------------------------------------------- |
| `~/.config/ahscan/config.json` | API key + endpoint (created by `ah-scan setup`) |
| `.ahscan.toml`                 | Access tier + license key (project-level)       |
| `~/.ahscan/scanner_uuid`       | Persistent scanner identity (auto-generated)    |
| `~/.ahscan/rules/*.toml`       | Custom detection rules                          |

Full `.ahscan.toml` options:

```toml
[access]
mode = "lite"                   # lite | licensed
license_key = ""                # required for licensed mode

[submit]
endpoint = "http://localhost:3000/api/scans/ingest"
token = ""
scanner_uuid = ""               # auto-generated if empty
scanner_account_uuid = ""       # auto-generated if empty
timeout_seconds = 10
include_informational = false
allow_public_endpoint = false
audit_log_enabled = true
audit_log_path = ".ahscan-submissions.json"
```
