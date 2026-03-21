# Architecture

This document explains how ah-scanner is built, how data flows through it, and how the modules connect. Read this before diving into the source code.

## System context

ah-scanner is one half of a two-repo client/server system:

```
┌──────────────────┐         HTTP POST          ┌──────────────────────┐
│   ah-scanner     │ ──────────────────────────► │   ah-verified-poc    │
│   (this repo)    │    /api/scans/ingest        │   (server repo)      │
│                  │                              │                      │
│  Rust CLI binary │                              │  Next.js + Postgres  │
│  Runs on target  │                              │  Stores results      │
│  machines        │                              │  Renders dashboard   │
└──────────────────┘                              └──────────────────────┘
```

The scanner runs locally on a developer's machine, discovers AI-related configuration files, analyzes them for risk, and optionally submits findings to the verification server.

## Workspace layout

```
ah-scanner/
├── crates/
│   ├── ah-scan/              # The main CLI binary
│   │   └── src/
│   │       ├── main.rs       # Entry point, module declarations
│   │       ├── cli.rs        # Command-line parsing + dispatch
│   │       ├── scan.rs       # Scan orchestration pipeline
│   │       ├── discovery.rs  # Filesystem walking
│   │       ├── detectors/    # Built-in artifact detectors
│   │       ├── engine/       # WASM plugin runtime
│   │       ├── models.rs     # Core data types
│   │       ├── risk_engine.rs # Risk scoring (0-100)
│   │       ├── verifier.rs   # Pass/fail determination
│   │       ├── contract.rs   # Output format builder
│   │       ├── submit.rs     # HTTP submission + retry
│   │       ├── identity.rs   # Scanner UUID management
│   │       ├── payload.rs    # API payload construction
│   │       ├── network.rs    # Endpoint validation
│   │       ├── network_evidence.rs # Firewall + network metadata
│   │       ├── formatters.rs # Terminal output rendering
│   │       ├── wizard.rs     # Interactive mode UI
│   │       ├── setup.rs      # First-run configuration
│   │       ├── updater.rs    # Self-update from S3
│   │       ├── plugins.rs    # Plugin management CLI
│   │       ├── lite_mode.rs  # Free-tier output limiting
│   │       ├── capabilities.rs # Signal-to-capability mapping
│   │       ├── progress.rs   # Progress indicator
│   │       └── wasm_bridge.rs # Native ↔ WASM communication
│   └── ah-scan-sdk/          # Types shared with WASM plugins
│       └── src/
│           ├── lib.rs        # SDK entry point + version
│           ├── types.rs      # DetectRequest, Finding, etc.
│           └── guest.rs      # Plugin-side helpers (decode/encode)
├── examples/
│   ├── detector-template/    # Starter template for new plugins
│   └── detector-cursor-rules/ # Working example plugin
├── scripts/
│   ├── test-scanner.sh       # Automated test suite (all subcommands)
│   └── test-submit.sh        # Manual submission test
├── scanner-data-contract.json # JSON Schema for the ingest API
├── ahscan-contract.json       # Example output payload
└── .github/workflows/
    └── release.yml            # CI: build + GitHub Release + S3 upload
```

## Data flow

Here is the complete path data takes through the scanner, from CLI invocation to output:

```
 ┌─────────────┐
 │  User runs   │  ah-scan quick / scan / file <path> / ...
 │  CLI command  │
 └──────┬───────┘
        │
        ▼
 ┌─────────────┐   Parses arguments, loads .ahscan.toml for access tier
 │   cli.rs     │   (lite vs licensed), dispatches to scan or wizard
 └──────┬───────┘
        │
        ▼
 ┌─────────────┐   Picks discovery mode based on subcommand:
 │   scan.rs    │   host, home, workdir, filesystem, root, or file
 └──────┬───────┘
        │
   ┌────┴────┐
   ▼         ▼
┌────────┐ ┌──────────────┐
│discovery│ │ wasm_bridge  │   discovery.rs walks the filesystem
│  .rs   │ │    .rs       │   wasm_bridge loads WASM plugins
└───┬────┘ └──────┬───────┘
    │              │
    │   Candidates │   Plugin findings
    └──────┬───────┘
           │
           ▼
    ┌─────────────┐   Each detector scans candidates for patterns:
    │  detectors/  │   filename matching, keyword analysis, JSON parsing
    │  (built-in)  │
    └──────┬───────┘
           │
           ▼  ArtifactReport[]
    ┌─────────────┐
    │ risk_engine  │   Computes score 0-100 from signals + type base
    │    .rs       │   Discounts for declared permissions
    └──────┬───────┘
           │
           ▼
    ┌─────────────┐
    │  verifier    │   Determines pass / conditional_pass / fail
    │    .rs       │   Based on score thresholds + dangerous signals
    └──────┬───────┘
           │
           ▼  ScanReport
    ┌─────────────┐
    │ Output stage │   Branching depending on flags:
    └──┬───┬───┬──┘
       │   │   │
       │   │   └──► formatters.rs → terminal output (human/overview/summary)
       │   └──────► contract.rs → JSON file (--out, --json)
       └──────────► submit.rs → HTTP POST to server (--submit)
```

## Module responsibilities

### Pure logic (no I/O)

These modules never touch the filesystem, network, or terminal. They are safe to unit test:

| Module            | Purpose                                   |
| ----------------- | ----------------------------------------- |
| `risk_engine.rs`  | Score artifacts 0-100 based on signals    |
| `verifier.rs`     | Assign pass/conditional_pass/fail         |
| `payload.rs`      | Build the ingest JSON payload             |
| `capabilities.rs` | Map signals → high-level capability names |
| `lite_mode.rs`    | Filter results for free-tier users        |

### Side-effect modules (I/O)

These modules interact with the outside world:

| Module                | Side effect                              |
| --------------------- | ---------------------------------------- |
| `discovery.rs`        | Reads filesystem (directory walking)     |
| `detectors/*`         | Read file contents                       |
| `submit.rs`           | HTTP POST, read/write config files       |
| `identity.rs`         | Read/write UUID files in ~/.ahscan/      |
| `network_evidence.rs` | Runs macOS firewall commands             |
| `updater.rs`          | HTTP GET to S3 for update manifests      |
| `setup.rs`            | Interactive prompts + config file writes |
| `wizard.rs`           | Interactive terminal UI                  |
| `progress.rs`         | Writes to stderr                         |

### Orchestration

| Module           | Role                                                           |
| ---------------- | -------------------------------------------------------------- |
| `cli.rs`         | Entry point: argument parsing, dispatch, output mode selection |
| `scan.rs`        | Pipeline: discovery → detection → scoring → verification       |
| `contract.rs`    | Transform `ScanReport` → AH-Verify v2.1.0 contract format      |
| `wasm_bridge.rs` | Load WASM plugins, convert types, call plugin `detect()`       |

## Key data types

All defined in `models.rs`:

```
Candidate            What we found on disk (path, origin tag)
     │
     ▼
ArtifactReport       After detection + scoring:
  - artifact_type      "cursor_rules", "mcp_config", etc.
  - confidence         0.0 – 1.0
  - signals            ["filename_match:.cursorrules", "keyword:shell"]
  - metadata           paths, origins, tool names
  - risk_score         0 – 100
  - risk_reasons       top contributing factors
  - verification_status  "pass" | "conditional_pass" | "fail"
  - artifact_hash      content-based identity (path-independent)
  - artifact_id        hash + scope = unique ID
  - artifact_scope     "host" | "project" | "container"
  - registry_eligible  whether it qualifies for server submission
     │
     ▼
ScanReport           Collection of artifacts from one scan run:
  - run_id, timestamp, scanned_path, artifacts[]
     │
     ▼
ContractPayload      Server-facing format (scanner-data-contract.json):
  - scanMeta, prompts, skills, mcpServers, agents, agenticApps
```

## Risk scoring algorithm

The risk engine in `risk_engine.rs` works like this:

1. **Base score** — depends on artifact type:
    - `mcp_config`: 20 (MCP servers have inherent risk)
    - `cursor_rules`: 10
    - `agents_md`: 8
    - Everything else: 5

2. **Signal weights** — each signal adds points:
    - `keyword:shell`: 15
    - `keyword:network`: 12
    - `dangerous_keyword:exfiltrate`: 35
    - `mcp_server_declared`: 20
    - See `risk_engine.rs` for the full table

3. **Declared-tools discount** — if the artifact explicitly declares a tool in its permissions section, the signal's weight is halved (50% discount). This rewards transparency.

4. **Caps** — individual signal categories are capped (extensions at 10, MCP at 20) and the final score is capped at 100.

## Verification rules

In `verifier.rs`, the verification status is determined in priority order:

1. If `credential_exposure_signal` is present → **fail** (always)
2. Score ≥ 50 → **fail**, ≥ 20 → **conditional_pass**, < 20 → **pass**
3. If `dangerous_keyword:*` is present and not governed by declared permissions → **fail**
4. If `dangerous_keyword:*` is present but governed → escalate to at least **conditional_pass**
5. If `dangerous_combo:*` (e.g., shell+network+fs) → escalate to at least **conditional_pass**

## Artifact identity

Artifacts are identified by content, not by file path. This means:

- Moving a file to a different directory doesn't change its hash
- The same content in two locations produces the same `artifact_hash`
- `artifact_id` = `SHA256(artifact_hash + scope)` makes it unique per scope

This is calculated in `models.rs` via `content_digest()` → `compute_hash()` → `registry_identity()`.

## Access tiers

| Feature           | Lite (free) | Licensed |
| ----------------- | :---------: | :------: |
| Local scanning    |     ✅      |    ✅    |
| Risk scoring      |     ✅      |    ✅    |
| Visible artifacts |    Top 3    |   All    |
| JSON export       |     ❌      |    ✅    |
| Server submission |     ❌      |    ✅    |

Access is controlled via `.ahscan.toml` in the working directory.

## Configuration files

| File                             | Purpose                     | Created by                        |
| -------------------------------- | --------------------------- | --------------------------------- |
| `~/.config/ahscan/config.json`   | API key + endpoint          | `ah-scan setup` or `ah-scan auth` |
| `.ahscan.toml`                   | Access mode + license key   | User creates manually             |
| `~/.ahscan/scanner_uuid`         | Persistent scanner identity | Auto-generated on first submit    |
| `~/.ahscan/scanner_account_uuid` | Persistent account identity | Auto-generated on first submit    |
| `~/.ahscan/plugins/*.wasm`       | Installed detector plugins  | `ah-scan plugins install`         |

## WASM plugin system

Plugins extend the scanner with custom detectors without modifying the core binary.

```
~/.ahscan/plugins/
├── my_detector.wasm              # The compiled plugin
└── my_detector.manifest.json     # Plugin metadata (name, version, SDK version)
```

The host (ah-scan) communicates with plugins via JSON:

1. Pre-reads file content from candidates
2. Base64-encodes content (8 KB limit per file)
3. Sends `DetectRequest` JSON to the plugin's `detect()` export
4. Receives `DetectResponse` JSON with findings
5. Converts findings to `ArtifactReport`s

Plugins never access the filesystem directly — the host provides everything they need.

## Network safety

The scanner enforces strict endpoint validation in `network.rs`:

- URLs must use `http://` or `https://`
- Public hostnames are **blocked by default**
- Local/private addresses are allowed: `localhost`, `127.0.0.1`, RFC 1918 ranges, IPv6 link-local
- Use `--allow-public-endpoint` to explicitly opt into public submission

## Release process

1. Bump version in workspace `Cargo.toml`
2. Commit: `chore: bump version to X.Y.Z`
3. Tag: `git tag vX.Y.Z`
4. Push: `git push origin main --tags`
5. GitHub Actions builds binaries for 5 targets (macOS arm64/x86, Linux arm64/x86, Windows x86)
6. Uploads to GitHub Releases + S3 bucket
7. Generates `latest.json` manifest with SHA-256 checksums for self-update
