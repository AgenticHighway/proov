# Deployment & Release Guide

This document covers how to cut a release of proov, what happens behind the scenes, common problems, and how to fix them.

## Prerequisites

Before releasing, make sure:

- [ ] You have push access to `main` and can create tags
- [ ] You have access to the [GitHub Actions](https://github.com/AgenticHighway/proov/actions) dashboard to monitor builds
- [ ] All CI checks on `main` are green
- [ ] You've tested the changes locally with `cargo test` and `cargo clippy --all-targets -- -D warnings`

## Release process

### 1. Decide what changed

Check what's been committed since the last release:

```bash
git log --oneline $(git describe --tags --abbrev=0)..HEAD
```

Use [Conventional Commits](https://www.conventionalcommits.org/) to decide the version bump:

| Change type | Bump | Example |
| ----------- | ---- | ------- |
| Breaking changes | Major (X.0.0) | API contract schema v3 |
| New features, new detectors | Minor (0.X.0) | New MCP detector |
| Bug fixes, dependency updates, docs | Patch (0.0.X) | Fix clippy warning |

### 2. Bump the version

The version lives in **one place** — the workspace `Cargo.toml`:

```bash
# Edit this line:
# version = "0.6.0"
vim Cargo.toml
```

**Important:** The crate `Cargo.toml` at `crates/proov/Cargo.toml` uses `version.workspace = true`, so it inherits automatically. Do **not** set the version in the crate's `Cargo.toml`.

### 3. Check if COMPILED_CONTRACT_VERSION needs updating

If the scan output format changed (new fields, removed fields, schema version bump), update the constant in `crates/proov/src/contract_sync.rs`:

```rust
pub const COMPILED_CONTRACT_VERSION: &str = "2.1.0";
```

This must match the version the server expects. If you're only fixing bugs or updating CI, skip this step.

### 4. Commit the version bump

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: release vX.Y.Z"
```

Include any other files that changed as part of the release (e.g., `contract_sync.rs` if you bumped the contract version).

### 5. Create and push the tag

```bash
git tag vX.Y.Z
git push origin main --tags
```

**The tag name must start with `v`** — the release workflow triggers on `v*` tags only.

### 6. Monitor the release

Go to [GitHub Actions](https://github.com/AgenticHighway/proov/actions) and watch the Release workflow. It runs three jobs:

1. **build** — Cross-compiles for 5 targets (runs in parallel):
   - `aarch64-apple-darwin` (macOS ARM64) — GitHub-hosted runner
   - `x86_64-apple-darwin` (macOS x86) — GitHub-hosted runner
   - `aarch64-unknown-linux-gnu` (Linux ARM64) — Blacksmith runner
   - `x86_64-unknown-linux-gnu` (Linux x86) — Blacksmith runner
   - `x86_64-pc-windows-msvc` (Windows x86) — Blacksmith runner

2. **release** — Downloads all 5 artifacts and creates a GitHub Release with auto-generated release notes

3. **upload-s3** — Uploads binaries to `s3://ah-scanner-releases/vX.Y.Z/`, generates SHA-256 checksums, and writes `latest.json` for the self-updater

### 7. Verify the release

After the workflow completes:

```bash
# Check the GitHub Release page exists with all 5 binaries
open https://github.com/AgenticHighway/proov/releases/tag/vX.Y.Z

# Check the S3 manifest is updated
curl -s https://ah-scanner-releases.s3.amazonaws.com/latest.json | python3 -m json.tool

# Verify the self-updater works (from an older installed binary)
proov update --check
```

## What the release workflow does

```
Tag push (v*)
    │
    ▼
┌─────────────────────────────────────────────┐
│ build (5 parallel matrix legs)              │
│                                             │
│  checkout → install rust → cache → build    │
│  → package (.tar.gz / .exe) → upload artifact│
└──────────────────┬──────────────────────────┘
                   │
          ┌────────┴────────┐
          ▼                 ▼
┌─────────────────┐  ┌──────────────────┐
│ release         │  │ upload-s3        │
│                 │  │                  │
│ download all    │  │ download all     │
│ artifacts       │  │ artifacts        │
│ create GitHub   │  │ OIDC → AWS creds │
│ Release         │  │ upload to S3     │
│                 │  │ SHA-256 checksums│
│                 │  │ write latest.json│
└─────────────────┘  └──────────────────┘
```

**Security notes:**
- All Actions are pinned to full commit SHAs (not mutable tags)
- AWS credentials use OIDC federation — no long-lived keys in secrets
- SHA-256 checksums are embedded in `latest.json` for client-side integrity verification

## Pre-release checklist

```
□ cargo fmt --check                          passes
□ cargo clippy --all-targets -- -D warnings  passes
□ cargo test                                 337+ tests pass
□ cargo deny check                           no advisory/license issues
□ cargo audit                                no known vulnerabilities
□ Version bumped in workspace Cargo.toml
□ COMPILED_CONTRACT_VERSION correct (if schema changed)
□ All changes committed, working tree clean
□ CI green on main
```

## Common problems and resolutions

### Build fails on one platform

**Symptom:** 4 of 5 matrix legs succeed, one fails.

**Common causes:**
- **Linux ARM64 cross-compile fails:** The `gcc-aarch64-linux-gnu` package may have changed. Check the "Install cross-compilation tools" step logs.
- **Windows build fails:** Windows runners can have transient issues. Re-run the failed job from the Actions UI.
- **macOS build fails:** Often a Rust toolchain installation issue with GitHub-hosted runners. Re-run.

**Resolution:** Use the "Re-run failed jobs" button on the Actions page. If the failure is deterministic, investigate the build logs.

### Tag was pushed but workflow didn't trigger

**Symptom:** You pushed a tag but no workflow run appears.

**Causes:**
- The tag name doesn't match `v*` (e.g., you used `0.6.1` instead of `v0.6.1`)
- The tag was created on a branch other than what's expected

**Resolution:**
```bash
# Delete the bad tag
git tag -d bad-tag
git push origin :refs/tags/bad-tag

# Create correctly
git tag vX.Y.Z
git push origin --tags
```

### S3 upload fails

**Symptom:** GitHub Release was created but `latest.json` wasn't updated.

**Causes:**
- OIDC token exchange failed (transient GitHub/AWS issue)
- The `SCANNER_RELEASE_ROLE_ARN` secret is misconfigured

**Resolution:**
1. Check the "Configure AWS credentials (OIDC)" step logs for the error
2. Re-run the `upload-s3` job from the Actions UI
3. If OIDC is persistently failing, verify the IAM role trust policy allows the repo's OIDC subject

### SHA-256 checksums are empty in latest.json

**Symptom:** `latest.json` has empty string values for `sha256` fields.

**Cause:** The `checksums` step output variable names didn't match. This happens if artifact filenames change.

**Resolution:** Check that artifact names in the matrix match what the `Write latest.json` step expects. The variable names are derived by replacing non-alphanumeric characters with underscores.

### Users report `proov update` doesn't find the new version

**Symptom:** The release is on GitHub but `proov update --check` says "already up to date."

**Causes:**
- `latest.json` on S3 wasn't updated (S3 upload job failed or was skipped)
- Client-side 24-hour check cache hasn't expired

**Resolution:**
```bash
# Verify latest.json
curl -s https://ah-scanner-releases.s3.amazonaws.com/latest.json

# If it shows the old version, re-run the upload-s3 job

# To bypass the client cache:
rm -f ~/.ahscan/update_check_cache
proov update --check
```

### Need to re-release the same version

**Symptom:** A release was published but had a bug. You need to re-do it.

**Resolution:**
```bash
# Delete the tag locally and remotely
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z

# Delete the GitHub Release from the web UI (Releases → edit → delete)

# Fix the issue, commit
git add . && git commit -m "fix: <description>"

# Re-tag and push
git tag vX.Y.Z
git push origin main --tags
```

### Cargo.lock is out of sync after version bump

**Symptom:** `cargo build` modifies `Cargo.lock` after you changed the version in `Cargo.toml`.

**Resolution:** Always run `cargo check` or `cargo build` after bumping the version, then commit both files:

```bash
# After editing Cargo.toml
cargo check
git add Cargo.toml Cargo.lock
git commit -m "chore: release vX.Y.Z"
```

## Rollback

If a release is broken and users are affected:

1. **Immediate:** Re-upload the previous version's `latest.json` to S3 so `proov update` pulls the old binary:
   ```bash
   aws s3 cp s3://ah-scanner-releases/vPREVIOUS/latest.json s3://ah-scanner-releases/latest.json
   ```

2. **Thorough:** Follow the "re-release" steps above to publish a fixed version.

Users who haven't run `proov update` yet won't be affected — the binary is self-contained.
