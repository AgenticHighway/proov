# ah-scanner — Client / Scanner

> **Two-repo system:** This is the **client side**. The companion server is [`AgenticHighway/ah-verified-poc`](https://github.com/AgenticHighway/ah-verified-poc), a Next.js + PostgreSQL app that ingests these scan reports via `POST /api/ingest` and renders the verification dashboard.

**AI Execution Inventory** — detect, analyze, and report AI execution artifacts on a host. Rust rewrite of the Python ah-scanner-poc for production deployment.

## Access modes

The client supports two access tiers:

- **Lite mode** (default): scans everything locally and offline, then shows only the top 3 highest-risk artifacts. Remaining artifacts are locked.
- **Licensed mode**: unlocks full artifact output and submission features. Requires a license key and live connectivity to your ah-verified-poc server.

This keeps the local runtime lightweight while allowing fuller downstream analysis on the server.

Lite mode local analysis profile (allowlisted risk signals):

- `credential_exposure_signal`
- `dangerous_combo:shell+network+fs`
- dangerous keywords: `exfiltrate`, `reverse`, `steal`, `wipe`, `bypass`
- high-risk capability keywords: `shell`, `browser`, `api`, `execute`, `network`, `filesystem`

When findings are locked in lite mode, CLI output includes a locked summary by:

- `analysis_origin` (`local` vs `server_candidate`)
- verification status
- artifact type

## Quick start

```bash
cargo build --release
./target/release/ah-scan              # interactive wizard
./target/release/ah-scan quick        # fast scan
./target/release/ah-scan full         # deep system scan
./target/release/ah-scan file <path>  # single file
./target/release/ah-scan folder <path> # directory
./target/release/ah-scan repo <path>  # git repo scan
```

## CLI usage

```
ah-scan                           # interactive wizard (default)

ah-scan quick                     # critical user config areas (overview output)
ah-scan quick --full              # full per-artifact detail
ah-scan quick --summary           # compact stats only
ah-scan quick --json              # JSON to stdout
ah-scan quick --out               # JSON to ./ahscan-report.json
ah-scan quick --out report.json   # JSON to custom path

ah-scan full                      # deep system-wide scan
ah-scan full --full               # full per-artifact detail
ah-scan full --json               # JSON output

ah-scan file <path>               # scan a single file
ah-scan file agents.md --full     # full detail output

ah-scan folder <path>             # scan a directory
ah-scan folder . --full           # full detail output
ah-scan folder . --json           # JSON output
ah-scan folder . --summary        # compact summary

ah-scan repo <path>               # deep-scan a local git repo
ah-scan repo . --json             # JSON output
ah-scan repo . --summary          # compact summary
```

## Submission to ah-verified-poc

Submission performs a `POST` to the ah-verified-poc ingest API (`/api/ingest`).

Default endpoint:

```text
http://localhost:3000/api/ingest
```

By default, only registry-eligible artifacts are submitted.

### Optional config (`.ahscan.toml`)

```toml
[access]
mode = "lite" # lite | licensed
license_key = "" # required when mode = "licensed"
endpoint = "http://localhost:3000/api/ingest"
license_timeout_seconds = 3

[submit]
endpoint = "http://localhost:3000/api/ingest"
token = ""
scanner_uuid = "" # optional override; auto-generated/persisted by default
scanner_account_uuid = "" # optional override; auto-generated/persisted by default
timeout_seconds = 10
include_informational = false
allow_public_endpoint = false
source = "api"
audit_log_enabled = true
audit_log_path = ".ahscan-submissions.json"
```

Submission requires licensed mode and server connectivity.

### Client submission audit log

Each submit attempt appends to `.ahscan-submissions.json` (by default), including:

- timestamp
- endpoint
- run_id
- submitted_artifacts
- ok / error
- status_code
- response summary counts (when available)

Token values are never written to the audit log.

`scanner_account_uuid` is included in every submit payload as
`client_details_scanner_account_uuid`.
By default, scanner auto-generates and persists this UUID at
`~/.ahscan/scanner_account_uuid` to avoid per-run config drift.

`scanner_uuid` is included in every submit payload as
`client_details_scanner_uuid`.
By default, scanner auto-generates and persists this UUID at
`~/.ahscan/scanner_uuid`.

Audit log format behavior:

- `.json` path: pretty-printed JSON array (easier to inspect/edit)
- `.jsonl` path: one compact JSON object per line (append-optimized)

### Safety defaults

- Endpoint must use `http://` or `https://`.
- Public hostnames are blocked by default.
- Local/private targets (for example `localhost`, `127.0.0.1`, `192.168.x.x`) are allowed.
- Use `--allow-public-endpoint` only when intentionally submitting outside your local/private network.

## What it detects (v1)

| Detector              | Artifact types                                                | Strategy                         |
| --------------------- | ------------------------------------------------------------- | -------------------------------- |
| Cursor / editor rules | `.cursorrules`, `agents.md`, `AGENTS.md`                      | Path match + keyword signals     |
| Prompt configs        | `*.prompt.md`, `*.instructions.md`, `copilot-instructions.md` | Path match + keyword signals     |
| Container configs     | `Dockerfile`, `compose.yaml`, `docker-compose.yml`            | Path match                       |
| Browser footprints    | Chrome, Edge, Brave, Arc profiles                             | Presence-only (no content reads) |
| MCP configs           | MCP server configuration files                                | Path match + keyword signals     |

## Output schema (locked v1)

```json
{
  "run_id": "...",
  "scanned_path": "...",
  "timestamp": "...",
  "artifacts": [
    {
      "artifact_hash": "sha256...",
      "artifact_type": "cursor_rules",
      "confidence": 0.9,
      "signals": ["filename_match:.cursorrules", "keyword:shell"],
      "metadata": {"paths": ["/path/to/.cursorrules"], "origin": "workdir"},
      "risk_score": 35,
      "verification_status": "conditional_pass"
    }
  ]
}
```

## Privacy boundaries (v1)

- **Path-first scanning** — content is only read for allowlisted files (`.cursorrules`, `agents.md`, prompt files).
- **No broad host file ingestion** — discovery walks bounded roots with depth/count limits.
- **Secret redaction** — token-like strings trigger a `possible_secret_detected` signal; values are never stored.
- **Browser** — presence-only detection; no extension content or preferences parsing.

## Host scan surfaces

| Root                               | Platform      |
| ---------------------------------- | ------------- |
| `~/.config/**`                     | Linux / macOS |
| `~/.local/share/**`                | Linux / macOS |
| `~/Library/Application Support/**` | macOS         |

## Project structure

```
src/
  main.rs             # Entry point
  cli.rs              # CLI argument parsing (clap)
  scan.rs             # Scan orchestration
  discovery.rs        # Filesystem candidate discovery
  models.rs           # Data models (ArtifactReport, ScanReport)
  detectors/          # Artifact detectors
    mod.rs
    cursor_rules.rs
    prompt_configs.rs
    containers.rs
    browser_footprints.rs
    mcp_configs.rs
    content_analysis.rs
  risk_engine.rs      # Risk scoring
  verifier.rs         # Verification status
  capabilities.rs     # Capability derivation
  formatters.rs       # CLI output formatting
  lite_mode.rs        # Lite-tier rate limiting
  payload.rs          # Ingest API payload building
  submit.rs           # HTTP submission + audit
  network.rs          # Endpoint safety validation
  identity.rs         # Scanner UUID management
  wizard.rs           # Interactive wizard
  progress.rs         # Progress reporting
```

## Running tests

```bash
cargo test
```

## Building release

```bash
cargo build --release
```

Single binary at `target/release/ah-scan`.
