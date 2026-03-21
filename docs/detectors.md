# Detectors

Detectors are the core of what ah-scanner does — they examine filesystem candidates and produce `ArtifactReport`s describing what they found.

## How detection works

1. **Discovery** (`discovery.rs`) walks the filesystem and produces a list of `Candidate`s (file paths with origin tags)
2. **Detectors** receive the candidate list and examine each file
3. Each detector returns zero or more `ArtifactReport`s with signals, confidence scores, and metadata
4. Reports are then scored by `risk_engine.rs` and verified by `verifier.rs`

## Built-in detectors

All built-in detectors live in `crates/ah-scan/src/detectors/` and implement the `Detector` trait:

```rust
pub trait Detector {
    fn name(&self) -> &'static str;
    fn detect(&self, candidates: &[Candidate], deep: bool) -> Vec<ArtifactReport>;
}
```

### Cursor Rules (`cursor_rules.rs`)

**Detects:** `.cursorrules`, `agents.md`, `AGENTS.md`

These are instruction files for AI coding assistants. The detector:
- Matches filenames exactly
- Reads content and scans for capability keywords (shell, browser, api, execute, etc.)
- Checks for dangerous keywords (steal, exfiltrate, bypass, etc.)
- Assigns confidence: 0.7 baseline, boosted by keyword matches up to 0.9+

### Prompt Configs (`prompt_configs.rs`)

**Detects:** `*.prompt.md`, `*.instructions.md`, `copilot-instructions.md`

These are prompt configuration files for GitHub Copilot and similar tools. Detection:
- Matches by file extension pattern
- Keyword scanning similar to cursor_rules
- Lower baseline confidence (0.4) since these files are more common

### MCP Configs (`mcp_configs.rs`)

**Detects:** `mcp.json`, `claude_desktop_config.json`

Model Context Protocol server configurations. The detector:
- Validates the file is JSON
- Looks for execution tokens (command, args, env patterns)
- Extracts declared MCP server names
- Higher baseline risk (MCP configs define what tools AI has access to)

### Container Configs (`containers.rs`)

**Detects:** `Dockerfile`, `compose.yaml`, `docker-compose.yml`

Container configurations that may affect AI execution environments:
- Filename pattern matching
- Scans for AI-relevance tokens within the file
- Lower confidence unless clear AI integration found

### Browser Footprints (`browser_footprints.rs`)

**Detects:** Chrome, Edge, Brave, Arc extension directories

This detector is unique — it **only checks for the presence** of browser profile directories. It never reads extension content or user data. This is a privacy-first design choice.

- Only runs in host/root/filesystem/home scan modes (not in project scans)
- Confidence: fixed 0.6 (presence-only)

### Content Analysis (`content_analysis.rs`)

This is a **helper module**, not a standalone detector. It provides:
- `extract_declared_tools()` — finds tool/permission declarations in content
- Used by other detectors to determine if capabilities are explicitly declared (which reduces risk scores)

## The Detector trait

The `detect()` method receives:
- `candidates: &[Candidate]` — files to examine
- `deep: bool` — whether to do deeper content analysis (slower but more thorough)

Each candidate has:
- `path` — absolute file path
- `origin` — where it came from ("host", "workdir", "filesystem")

### Content reading limit

All detectors respect an 8 KB content limit. Files larger than this are truncated. This keeps scanning fast and prevents memory issues with large files.

## Signals

Signals are string tags that describe what a detector found. They follow a naming convention:

| Pattern | Example | Meaning |
|---------|---------|---------|
| `filename_match:<name>` | `filename_match:.cursorrules` | File matched by name |
| `keyword:<word>` | `keyword:shell` | Capability keyword found in content |
| `dangerous_keyword:<word>` | `dangerous_keyword:exfiltrate` | High-risk keyword found |
| `dangerous_combo:<combo>` | `dangerous_combo:shell+network+fs` | Multiple risky capabilities together |
| `credential_exposure_signal` | `credential_exposure_signal` | Possible secret/token detected |
| `mcp_server_declared` | `mcp_server_declared` | MCP server configuration found |

## Adding a new built-in detector

1. Create a new file in `crates/ah-scan/src/detectors/`, e.g., `my_detector.rs`

2. Implement the `Detector` trait:
   ```rust
   use crate::detectors::base::{Candidate, Detector};
   use crate::models::ArtifactReport;

   pub struct MyDetector;

   impl Detector for MyDetector {
       fn name(&self) -> &'static str {
           "my_detector"
       }

       fn detect(&self, candidates: &[Candidate], deep: bool) -> Vec<ArtifactReport> {
           let mut results = Vec::new();
           for candidate in candidates {
               // Your detection logic here
               // Check candidate.path, read content, pattern match
           }
           results
       }
   }
   ```

3. Register in `detectors/mod.rs`:
   ```rust
   mod my_detector;
   // Add to get_all_detectors() function
   ```

4. Add risk weights in `risk_engine.rs` for your new artifact type

5. Run `cargo test` to verify nothing breaks

## Adding a WASM plugin detector

If you want detection logic that can be distributed independently, see [docs/plugin-guide.md](plugin-guide.md).
