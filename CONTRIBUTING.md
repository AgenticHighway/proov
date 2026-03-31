# Contributing to proov

## Getting started

### Prerequisites

- **Rust 1.85.1** (stable) — install via [rustup.rs](https://rustup.rs). The exact version is pinned in `rust-toolchain.toml`; rustup will install it automatically.
- **Git**
- **macOS, Linux, or Windows** (macOS is the primary dev platform)
- **cargo-deny** (optional, for local supply chain checks) — `cargo install cargo-deny`
- **cargo-audit** (optional, for local vulnerability scans) — `cargo install cargo-audit`

### Clone and build

```bash
git clone https://github.com/AgenticHighway/proov.git
cd proov
cargo build
```

This builds the `proov` binary in debug mode at `target/debug/proov`.

### Run the scanner

```bash
# Interactive wizard
cargo run -p proov

# Quick scan (AI config areas only)
cargo run -p proov -- quick

# Scan a specific file
cargo run -p proov -- file agents.md

# Scan current directory
cargo run -p proov -- folder .

# Full system scan
cargo run -p proov -- full
```

### Run tests

```bash
# All tests
cargo test

# Tests for the main crate
cargo test -p proov

# Run with output shown
cargo test -- --nocapture
```

### Run the automated test suite

The `scripts/test-scanner.sh` script exercises every non-interactive subcommand:

```bash
./scripts/test-scanner.sh
```

Results are saved to the `test-runs/` directory.

### Check for lint issues

```bash
# Formatting (must pass — CI rejects unformatted code)
cargo fmt --check

# Clippy with deny-warnings (must pass — CI rejects any warnings)
cargo clippy --all-targets -- -D warnings

# Supply chain audit (checks licenses + known CVEs)
cargo deny check

# RustSec vulnerability scan
cargo audit
```

All of these run automatically in CI on every PR.

## Project structure

The workspace has one crate:

| Crate   | Path            | Purpose                                 |
| ------- | --------------- | --------------------------------------- |
| `proov` | `crates/proov/` | The CLI binary — all the scanning logic |

For detailed architecture, see [docs/architecture.md](docs/architecture.md).

## Development workflow

### Branch naming

- `feat/<description>` — new features
- `fix/<description>` — bug fixes
- `chore/<description>` — maintenance (deps, CI, docs)
- `refactor/<description>` — code restructuring

### Making changes

1. Create a branch from `main`:

    ```bash
    git checkout -b feat/my-feature
    ```

2. Make your changes, keeping commits small and focused.

3. Run checks locally before pushing:

    ```bash
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo test
    ```

4. Push and open a PR:

    ```bash
    git push origin feat/my-feature
    ```

    CI will automatically run formatting, clippy, tests, and supply chain audit.
    All checks must pass before merging.

### Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new detector for X
fix: handle empty MCP config gracefully
chore: bump serde to 1.0.200
refactor: split submit.rs into smaller modules
docs: add custom detection rule guide
```

## Code guidelines

### File size limits

- Files: ≤ 400 lines
- Functions: ≤ 50 lines
- If something is getting too big, split it

### Module design

- **Pure logic** modules (risk_engine, verifier, payload) must not do I/O
- **Side-effect** modules (submit, discovery, identity) isolate all external interactions
- Pass dependencies explicitly — no hidden globals

### Adding a new detector

See [docs/detectors.md](docs/detectors.md) for a step-by-step guide.

### Adding a custom detection rule

See [docs/custom-rules.md](docs/custom-rules.md).

## Release process

Releases happen via git tags. The CI pipeline handles everything after tagging.

1. Bump `version` in the workspace `Cargo.toml`
2. Commit: `chore: release vX.Y.Z`
3. Tag: `git tag vX.Y.Z`
4. Push: `git push origin main --tags`

The [release workflow](.github/workflows/release.yml) will:

- Build binaries for macOS (ARM64 + x86), Linux (ARM64 + x86), Windows (x86)
- Create a GitHub Release with all binaries and auto-generated release notes
- Upload to S3 for the self-update mechanism
- Generate `latest.json` with SHA-256 checksums for integrity verification

> **Note:** All Actions in the release workflow are pinned to full commit SHAs to prevent supply chain attacks. See the comments in `release.yml` for details.

## CI pipeline

Every PR and push to `main` triggers the [CI workflow](.github/workflows/ci.yml), which runs two parallel jobs:

**Lint & test** (Blacksmith 4vCPU runner):

1. `cargo fmt --check` — formatting (~1s, fails fast)
2. `cargo clippy --all-targets -- -D warnings` — compile + lint (~30s)
3. `cargo test` — run all tests (~3s, reuses clippy build)

**Supply chain audit** (Blacksmith 2vCPU runner):

1. `cargo deny check` — licenses, advisories, sources
2. `cargo audit` — RustSec vulnerability database

[Dependabot](.github/dependabot.yml) automatically opens PRs for outdated Cargo crates and GitHub Actions.

## Troubleshooting

### `cargo clippy` fails with unstable feature errors

You’re likely using a Rust version newer than what’s pinned. Run `rustup show` to verify you’re using the toolchain from `rust-toolchain.toml` (currently 1.85.1).

### `cargo deny check` fails locally

If you see CVSS parsing errors, your local `cargo-deny` may be too old. Install the latest: `cargo install cargo-deny`. The CI uses a pre-built binary that always has the latest version.

### Tests pass locally but CI fails

CI runs on Linux (Blacksmith Ubuntu 22.04). If you’re developing on macOS, path-related tests should use platform-agnostic assertions. Check the CI logs at the GitHub Actions tab for details.

### `proov update` fails during development

The self-updater checks S3 for releases. During development, you’re running a debug build that won’t match any published version. This is expected — use `cargo run` instead.

## Testing submission

To test submitting scan results to a server:

```bash
# Requires a running ah-verified-poc instance
./scripts/test-submit.sh <API_KEY> [SCAN_TARGET] [ENDPOINT]

# Examples
./scripts/test-submit.sh ah_abc123def456
./scripts/test-submit.sh ah_abc123def456 ~/my-project
./scripts/test-submit.sh ah_abc123def456 . http://localhost:3000/api/scans/ingest
```

You can also run the full test suite with submission tests enabled:

```bash
AH_TEST_API_KEY=your_key ./scripts/test-scanner.sh
```

## Getting help

- Read the architecture docs: [docs/architecture.md](docs/architecture.md)
- Check existing detectors in `crates/proov/src/detectors/` for patterns to follow
- Look at `examples/rules/` for custom rule examples
- Run `proov --help` for CLI usage
