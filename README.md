# proov

**Detect, analyze, and report AI execution artifacts on a host machine.**

proov is a Rust CLI tool that scans your system for AI-related configuration files — things like `.cursorrules`, MCP server configs, prompt files, and container definitions — analyzes them for risk, and produces structured reports.

## How it works

proov is local-first. It walks your filesystem, identifies AI execution artifacts, scores them for risk, and writes results locally. Network activity only happens when you explicitly opt into connected features such as `--submit`, `proov auth`, `proov setup`, or `proov update`.

If you want a hosted review and governance surface, proov can submit to compatible ingest APIs, including [Vettd](https://vettd.agentichighway.ai).

## System requirements

| Requirement | Detail                                                               |
| ----------- | -------------------------------------------------------------------- |
| **OS**      | macOS (ARM64, x86_64), Linux (ARM64, x86_64), Windows (x86_64)       |
| **Runtime** | None — proov is a single static binary with no dependencies          |
| **Build**   | Rust 1.85.1+ (pinned via `rust-toolchain.toml`)                      |
| **Network** | Optional — only needed for connected features such as submission, setup/auth, and updates |
| **Disk**    | ~15 MB for the binary; scans are read-only and produce no temp files |

## Install

### From a release binary

Download the latest binary for your platform from [GitHub Releases](https://github.com/AgenticHighway/proov/releases).

```bash
# macOS (Apple Silicon)
tar xzf proov-darwin-arm64.tar.gz
./proov quick

# Linux (x86_64)
tar xzf proov-linux-amd64.tar.gz
./proov quick
```

### From source

```bash
git clone https://github.com/AgenticHighway/proov.git
cd proov
cargo build --release
./target/release/proov quick
```

## Quick start

```bash
proov                      # Interactive wizard — walks you through options
proov quick                # Fast scan of AI config areas (~/.cursor, VS Code, Claude, etc.)
proov scan                 # Default scan (home directory, recursive)
proov full                 # Deep system-wide scan (slow, thorough)
proov file <path>          # Scan a single file
proov folder <path>        # Scan a directory
proov repo <path>          # Deep-scan a git repository
proov setup                # Interactive connected-mode setup (API key + endpoint)
proov auth                 # Prompt securely for an API key and save it
proov auth --key <key>     # Save API credentials directly (useful for automation)
proov update               # Check for and install updates
proov rules list           # List installed custom detection rules
proov rules add <file>     # Install a TOML rule file
proov rules remove <name>  # Remove an installed rule by name
proov rules validate <f>   # Validate a rule file without installing
```

## Output formats

```bash
proov quick              # Overview with risk bars (default)
proov quick --full       # Detailed per-artifact breakdown
proov quick --summary    # Compact statistics only
proov quick --json       # JSON to stdout
proov quick --out        # JSON to ./ahscan-report.json
proov quick --out r.json # JSON to custom path
proov quick --contract   # AH data contract JSON to stdout
proov quick --contract --out r.json  # Contract JSON to file
proov quick --contract --submit --api-key <key>  # Contract to file + submit
```

## What it detects

| Detector              | Files                                                         | What it looks for                                                                                    |
| --------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Cursor / editor rules | `.cursorrules`, `agents.md`, `AGENTS.md`                      | AI instruction files with capability keywords (TOML rule)                                            |
| Prompt configs        | `*.prompt.md`, `*.instructions.md`, `copilot-instructions.md` | Prompt configuration for GitHub Copilot and similar (TOML rule)                                      |
| MCP configs           | `mcp.json`, `claude_desktop_config.json`                      | Model Context Protocol server declarations                                                           |
| Container configs     | `Dockerfile`, `compose.yaml`, `docker-compose.yml`            | Docker image definitions and service orchestration with direct AI evidence or nearby agent artifacts |
| Browser footprints    | Chrome, Edge, Brave, Arc profiles                             | Extension directory presence only (no content reads)                                                 |
| Custom rules          | Any `.toml` in `~/.ahscan/rules/`                             | Declarative rules you define                                                                         |

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

## Submitting to Vettd or another endpoint

With a licensed configuration and API key:

```bash
# First-time setup (saves credentials and endpoint)
proov setup

# Or prompt securely for credentials
proov auth

# Or set credentials directly for automation
proov auth --key your-api-key

# Submit scan results
proov repo . --submit --api-key your-key

# Submit to a custom compatible endpoint
proov repo . --submit https://example.com/api/scans/ingest --api-key your-key
```

### Safety defaults

- Scans stay local unless you explicitly opt into connected commands
- The default hosted submission target is Vettd, but custom compatible endpoints are supported
- Contract sync only runs during explicit submission flows, when the target endpoint exposes a compatible contract API
- Retry logic handles transient failures (429, 502, 503, 504)
- API keys saved by proov are written to `~/.config/ahscan/config.json` with private permissions on Unix-like systems

## Self-update

```bash
proov update           # Check for and install updates
proov update --check   # Check only, don't install
proov update --force   # Force update even if current
```

`proov update` explicitly checks for the latest release, verifies SHA-256 checksums, and replaces the local binary.

## Privacy

- **Path-first scanning** — content is only read from specific allowlisted file types
- **Bounded walking** — max depth of 5 for shallow scans; full scan enumerates the entire filesystem with no caps
- **Scoped exclusions** — `.git/`, `node_modules/`, `.venv/`, `target/` and similar are excluded from home/workdir/filesystem scans (full scan has no exclusions)
- **Secret detection without storage** — token patterns trigger a signal tag, but values are never stored or transmitted
- **Browser presence only** — extension directories are noted, but no extension content or preferences are read
- **Declarative rules** — custom rules are TOML config files; they use the same content-read allowlist as built-in detectors

## Project structure

```
proov/
├── crates/
│   └── proov/                    # CLI binary (scanning, detection, submission)
│       └── src/
│           ├── detectors/         # Built-in artifact detectors
│           └── contract/          # AH contract format builders
├── rules/                        # Built-in TOML detection rules (compiled into binary)
├── examples/
│   └── rules/                    # Example custom detection rules (.toml)
├── scripts/
│   ├── test-scanner.sh           # Automated test suite
│   └── test-submit.sh            # Manual submission test
├── docs/
│   ├── architecture.md           # System design and data flow
│   ├── detectors.md              # How detection works
│   ├── output-spec.md            # Plain-English spec for contract outputs
│   └── custom-rules.md           # Writing custom detection rules
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                # PR checks: fmt, clippy, test, audit
│   │   └── release.yml           # Build + GitHub Release + artifact publishing
│   ├── dependabot.yml            # Automated dependency updates
│   └── CODEOWNERS                # Required reviewers for security-sensitive files
├── agents.md                     # Project guidelines for AI coding agents
├── deny.toml                     # Supply chain policy (licenses, advisories)
├── rust-toolchain.toml           # Pinned Rust compiler version
├── SECURITY.md                   # Vulnerability disclosure policy
└── scanner-data-contract.json    # JSON Schema for scan output
```

## Developing

```bash
cargo build                         # Debug build
cargo fmt --check                   # Formatting check
cargo clippy --all-targets -- -D warnings  # Lint (must be 0 warnings)
cargo test                          # Run all 337+ tests
cargo deny check                    # License + advisory audit
cargo audit                         # RustSec vulnerability scan
./scripts/test-scanner.sh           # Exercise all CLI subcommands
```

> **CI runs all of these automatically on every PR.** See [.github/workflows/ci.yml](.github/workflows/ci.yml) for the full pipeline.

For detailed development instructions: [CONTRIBUTING.md](CONTRIBUTING.md)
For architecture and code walkthrough: [docs/architecture.md](docs/architecture.md)
For the plain-English output spec: [docs/output-spec.md](docs/output-spec.md)
For security vulnerability reports: [SECURITY.md](SECURITY.md)

## Configuration reference

| File                           | Purpose                                       |
| ------------------------------ | --------------------------------------------- |
| `~/.config/ahscan/config.json` | API key + endpoint (created by `proov setup`) |
| `.ahscan.toml`                 | Access tier + license key (project-level)     |
| `~/.ahscan/scanner_uuid`       | Persistent scanner identity (auto-generated)  |
| `~/.ahscan/rules/*.toml`       | Custom detection rules                        |

Example `.ahscan.toml`:

```toml
[access]
mode = "lite"                   # lite | licensed
license_key = ""                # required for licensed mode
```
