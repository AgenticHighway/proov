# Contributing to ah-scanner

## Getting started

### Prerequisites

- **Rust** (stable) — install via [rustup.rs](https://rustup.rs)
- **Git**
- **macOS, Linux, or Windows** (macOS is the primary dev platform)

### Clone and build

```bash
git clone https://github.com/AgenticHighway/ah-scanner.git
cd ah-scanner
cargo build
```

This builds the `ah-scan` binary in debug mode at `target/debug/ah-scan`.

### Run the scanner

```bash
# Interactive wizard
cargo run -p ah-scan

# Quick scan (AI config areas only)
cargo run -p ah-scan -- quick

# Scan a specific file
cargo run -p ah-scan -- file agents.md

# Scan current directory
cargo run -p ah-scan -- folder .

# Full system scan
cargo run -p ah-scan -- full
```

### Run tests

```bash
# All tests
cargo test

# Tests for the main crate
cargo test -p ah-scan

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
cargo clippy
```

This should produce zero warnings. Fix any that appear before submitting a PR.

## Project structure

The workspace has one crate:

| Crate     | Path              | Purpose                                 |
| --------- | ----------------- | --------------------------------------- |
| `ah-scan` | `crates/ah-scan/` | The CLI binary — all the scanning logic |

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

3. Run tests and clippy:

    ```bash
    cargo test
    cargo clippy
    ```

4. Push and open a PR:
    ```bash
    git push origin feat/my-feature
    ```

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

Releases happen via git tags. The CI pipeline handles building and distribution.

1. Bump `version` in the workspace `Cargo.toml`
2. Commit: `chore: bump version to X.Y.Z`
3. Tag: `git tag vX.Y.Z`
4. Push: `git push origin main --tags`

The GitHub Actions workflow will:

- Build binaries for macOS (ARM64 + x86), Linux (ARM64 + x86), Windows (x86)
- Create a GitHub Release with all binaries
- Upload to S3 for the self-update mechanism
- Generate `latest.json` with SHA-256 checksums

## Testing submission

To test submitting scan results to a server:

```bash
# Requires a running ah-verified-poc instance
./scripts/test-submit.sh <API_KEY> [SCAN_TARGET] [ENDPOINT]

# Examples
./scripts/test-submit.sh your-api-key
./scripts/test-submit.sh your-api-key ~/my-project
./scripts/test-submit.sh your-api-key . http://localhost:3000/api/scans/ingest
```

You can also run the full test suite with submission tests enabled:

```bash
AH_TEST_API_KEY=your_key ./scripts/test-scanner.sh
```

## Getting help

- Read the architecture docs: [docs/architecture.md](docs/architecture.md)
- Check existing detectors in `crates/ah-scan/src/detectors/` for patterns to follow
- Look at `examples/rules/` for custom rule examples
- Run `ah-scan --help` for CLI usage
