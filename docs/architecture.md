# Architecture

This document explains how proov is built, how data flows through it, and how
the modules connect. Read this before diving into the source code.

For public-facing CLI journeys, see [user-flows.md](user-flows.md).

## System context

proov is a local-first scanner that can operate standalone or connect to a
compatible backend when you explicitly opt into submission:

```
┌──────────────────┐         HTTP POST          ┌──────────────────────┐
│   proov          │ ──────────────────────────► │ Compatible Backend   │
│   (this repo)    │    /api/scans/ingest        │ (e.g. Vettd)         │
│                  │                              │                      │
│  Rust CLI binary │                              │  Stores results      │
│  Runs on target  │                              │  Renders review UI   │
│  machines        │                              │  Applies governance  │
└──────────────────┘                              └──────────────────────┘
```

The scanner runs locally on a developer's machine, discovers AI-related configuration files, analyzes them for risk, and optionally submits findings to a connected backend.

## Workspace layout

```
proov/
├── crates/
│   ├── proov/                # The main CLI binary
│   │   └── src/
│   │       ├── main.rs       # Entry point, module declarations
│   │       ├── cli.rs        # Command-line parsing + dispatch
│   │       ├── scan.rs       # Scan orchestration pipeline
│   │       ├── discovery.rs  # Filesystem walking
│   │       ├── detectors/    # Built-in artifact detectors
│   │       ├── rule_engine.rs # Declarative TOML rule loader + matcher
│   │       ├── rules.rs      # CLI subcommand: list/add/remove/validate rules
│   │       ├── models.rs     # Core data types
│   │       ├── risk_engine.rs # Risk scoring (0-100)
│   │       ├── verifier.rs   # Pass/fail determination
│   │       ├── contract/     # AH contract format builders
│   │       │   ├── mod.rs       # Module declarations
│   │       │   ├── types.rs     # Contract type definitions
│   │       │   ├── prompts.rs   # Prompt contract builder
│   │       │   ├── skills.rs    # Skills contract builder
│   │       │   ├── agents.rs    # Agents contract builder
│   │       │   ├── mcp.rs       # MCP server contract builder
│   │       │   ├── apps.rs      # Agentic app contract builder
│   │       │   └── helpers.rs   # Shared contract utilities
│   │       ├── contract_sync.rs  # Server contract version sync + caching
│   │       ├── submit.rs     # HTTP submission + retry
│   │       ├── identity.rs   # Scanner UUID management
│   │       ├── payload.rs    # API payload construction
│   │       ├── network.rs    # Endpoint validation
│   │       ├── network_evidence.rs # Firewall + network metadata
│   │       ├── formatters.rs # Terminal output rendering
│   │       ├── wizard.rs     # Interactive mode UI
│   │       ├── setup.rs      # Optional auth + endpoint setup
│   │       ├── updater.rs    # Signed manifest update flow
│   │       ├── lite_mode.rs  # Free-tier output limiting
│   │       ├── capabilities.rs # Signal-to-capability mapping
│   │       └── progress.rs   # Progress indicator
├── examples/
│   └── rules/                # Example custom detection rules (.toml)
├── scripts/
│   ├── test-scanner.sh       # Automated test suite (all subcommands)
│   └── test-submit.sh        # Manual submission test
├── .github/
│   ├── workflows/
│   │   ├── ci.yml            # PR checks: fmt, clippy, test, audit
│   │   └── release.yml       # Build + GitHub Release + signed update metadata
│   ├── dependabot.yml        # Automated dependency updates
│   └── CODEOWNERS            # Required reviewers
├── scanner-data-contract.json # JSON Schema for the ingest API
├── deny.toml                  # Supply chain policy (licenses, advisories)
└── rust-toolchain.toml        # Pinned Rust compiler version
```

## Data flow

Here is the complete path data takes through the scanner, from CLI invocation
to local output or optional submission:

```
 ┌─────────────┐
 │  User runs   │  proov quick / scan / file <path> / ...
 │  CLI command  │
 └──────┬───────┘
        │
        ▼
 ┌─────────────┐   Parses arguments, loads .ahscan.toml for access tier
 │   cli.rs     │   (lite vs licensed), dispatches to scan, wizard,
 └──────┬───────┘   setup/auth/rules/update, and post-scan actions
        │
        ▼
 ┌─────────────┐   Picks discovery mode based on subcommand:
 │   scan.rs    │   host, home, workdir, filesystem, root, or file
 └──────┬───────┘
        │
   ┌────┴────┐
   ▼         ▼
┌────────┐ ┌──────────────┐
│discovery│ │ rule_engine   │   discovery.rs walks the filesystem
│  .rs   │ │    .rs       │   rule_engine loads custom TOML rules
└───┬────┘ └──────┬───────┘
    │              │
    │   Candidates │   Custom rule findings
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
    │ Output stage │   Local-first branching depending on flags + TTY:
    └──┬───┬───┬───┬──┘
       │   │   │   │
       │   │   │   └──► post-scan next step (TTY + no --json/--contract/--submit)
       │   │   │         ├─ write report to disk
       │   │   │         ├─ continue into submission
       │   │   │         └─ do nothing
       │   │   └──────► formatters.rs → terminal output (overview/full/summary)
       │   └──────────► output.rs → JSON stdout or file (--json, --out, --contract)
       └──────────────► output.rs + submit.rs → contract sync + HTTP POST (--submit)
```

## Module responsibilities

### Pure logic (no I/O)

These modules never touch the filesystem, network, or terminal. They are safe to unit test:

| Module            | Purpose                                                                                        |
| ----------------- | ---------------------------------------------------------------------------------------------- |
| `risk_engine.rs`  | Score artifacts 0-100 based on signals                                                         |
| `verifier.rs`     | Assign pass/conditional_pass/fail                                                              |
| `payload.rs`      | Build the ingest JSON payload                                                                  |
| `capabilities.rs` | Map signals → high-level capability names                                                      |
| `lite_mode.rs`    | Filter results for free-tier users                                                             |
| `contract/`       | Transform ScanReport → AH contract format (types, prompts, skills, agents, mcp, apps, helpers) |

### Side-effect modules (I/O)

These modules interact with the outside world:

| Module                | Side effect                                                               |
| --------------------- | ------------------------------------------------------------------------- |
| `discovery.rs`        | Reads filesystem (directory walking)                                      |
| `detectors/*`         | Read file contents                                                        |
| `submit.rs`           | HTTP POST, read/write config files                                        |
| `identity.rs`         | Read/write UUID files in ~/.ahscan/                                       |
| `network_evidence.rs` | Runs macOS firewall commands                                              |
| `updater.rs`          | HTTP GET to hosted signed release metadata + artifact download            |
| `contract_sync.rs`    | HTTP GET contract version from server, local cache in ~/.ahscan/contract/ |
| `setup.rs`            | Interactive prompts + config file writes                                  |
| `wizard.rs`           | Interactive terminal UI                                                   |
| `progress.rs`         | Writes to stderr                                                          |

### Orchestration

| Module             | Role                                                                                                                              |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `cli.rs`           | Entry point: argument parsing, dispatch, access gating, and post-scan decision flow                                              |
| `scan.rs`          | Pipeline: discovery → detection → scoring → verification                                                                          |
| `contract/`        | Transform `ScanReport` → scanner data contract v2.1.0 format (split into type-specific builders: prompts, skills, agents, mcp, apps) |
| `contract_sync.rs` | Sync contract schema version from server, cache locally in `~/.ahscan/contract/`, warn on version mismatch                        |
| `rule_engine.rs`   | Load TOML rules from `~/.ahscan/rules/`, match against candidates                                                                 |
| `rules.rs`         | CLI subcommand for rule management (list, add, remove, validate)                                                                  |

## File primitives

Every file-backed artifact includes **file primitives** — filesystem metadata gathered once at detection time. This design eliminates redundant file reads (previously the contract builder would re-read the same files 3-4 times for hashing, size, and modification date).

Detectors call `gather_file_primitives(path)` which returns:

| Key               | Type   | Description                             |
| ----------------- | ------ | --------------------------------------- |
| `file_size_bytes` | number | Exact file size in bytes                |
| `last_modified`   | string | RFC 3339 timestamp of last modification |
| `content_hash`    | string | SHA-256 hex digest of the **full** file |

Downstream consumers (contract builder, formatters) read these from `ArtifactReport.metadata` instead of touching the filesystem. This makes the scanner:

- **Efficient** — each file is read exactly once, at detection time
- **Reliable** — no TOCTOU race between detection and contract building
- **Portable** — post-detection logic is pure data transformation

Each artifact type also has **type-specific primitives** — structured metadata relevant to that artifact. See [detectors.md](detectors.md) for the complete metadata contract per type.

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
                                                   For Docker artifacts, "container" currently means container-related config files on disk, not live runtime instances.
  - registry_eligible  whether it qualifies for server submission
     │
     ▼
ScanReport           Collection of artifacts from one scan run:
  - run_id, timestamp, scanned_path, artifacts[]
     │
     ▼
ContractPayload      Server-facing format (scanner-data-contract.json):
  - scanMeta, prompts, skills, mcpServers, agents, agenticApps

`agenticApps` are built conservatively from container artifacts: a Dockerfile or compose file is only promoted when it contains direct agentic signals or has real co-located agent artifacts. Proximity to AI files alone is not enough.
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

At runtime, `cli.rs` loads this file before output is rendered. In `lite`
mode, proov keeps local scanning and scoring but limits the visible artifact
set before formatting or JSON emission.

## Configuration files

| File                             | Purpose                     | Created by                         |
| -------------------------------- | --------------------------- | ---------------------------------- |
| `~/.config/ahscan/config.json`   | API key + endpoint          | `proov setup` or `proov auth`      |
| `.ahscan.toml`                   | Access mode + license key   | User creates manually              |
| `~/.ahscan/scanner_uuid`         | Persistent scanner identity | Auto-generated on first submit     |
| `~/.ahscan/scanner_account_uuid` | Persistent account identity | Auto-generated on first submit     |
| `~/.ahscan/rules/*.toml`         | Custom detection rules      | User creates (see custom-rules.md) |

## Custom rule system

The scanner can be extended with declarative TOML rule files placed in `~/.ahscan/rules/`.

```
~/.ahscan/rules/
├── terraform-ai.toml             # Match .tf files with AI keywords
└── internal-tool.toml            # Match proprietary config files
```

Each rule defines:

1. Filename patterns (exact names, globs, or suffixes) to match
2. A base confidence score
3. Optional keyword lists that boost confidence when found in content
4. Optional deep-keyword lists for deep-scan modes

Rules produce standard `ArtifactReport`s, which flow through the same risk scoring and verification pipeline as built-in detector findings.

See [docs/custom-rules.md](custom-rules.md) for the full specification.

## Network safety

The scanner enforces strict endpoint validation in `network.rs`:

- URLs must use `http://` or `https://`
- Public hostnames are **blocked by default**
- Local/private addresses are allowed: `localhost`, `127.0.0.1`, RFC 1918 ranges, IPv6 link-local
- Use `--allow-public-endpoint` to explicitly opt into public submission

## Release process

1. Bump version in workspace `Cargo.toml`
2. Commit: `chore: release vX.Y.Z`
3. Tag: `git tag vX.Y.Z`
4. Push: `git push origin main --tags`
5. GitHub Actions builds binaries for 5 targets (macOS arm64/x86, Linux arm64/x86, Windows x86)
6. Publishes GitHub release assets and refreshes the hosted signed update metadata
7. Serves the signed manifest + signature used by official self-updating clients

## CI/CD

The project uses two GitHub Actions workflows, both running on [Blacksmith](https://blacksmith.sh) runners for speed:

**CI** (`.github/workflows/ci.yml`) — runs on every PR and push to `main`:

- Steps ordered cheapest-first for fast failure (fmt → clippy → test)
- Parallel supply chain audit job (cargo-deny + cargo-audit)

**Release** (`.github/workflows/release.yml`) — runs on version tags (`v*`):

- Cross-platform builds (5 targets)
- GitHub Release creation
- Signed manifest publication for self-update

**Supply chain hardening:**

- All third-party Actions pinned to full commit SHAs
- Dependabot auto-updates for both Cargo crates and Actions
- `deny.toml` enforces license allowlist and blocks non-crates.io sources
- CODEOWNERS requires review on security-sensitive files
- AWS credentials use OIDC federation (no long-lived keys)
