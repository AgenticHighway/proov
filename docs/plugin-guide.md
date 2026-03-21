# Writing a WASM Detector Plugin

This guide walks you through building a custom detector plugin for ah-scanner. Plugins are compiled to WebAssembly (WASM) and loaded at runtime — no changes to the core scanner needed.

## Prerequisites

- Rust toolchain installed (`rustup`)
- The `wasm32-wasip1` target:
    ```bash
    rustup target add wasm32-wasip1
    ```

## Quick start

1. **Copy the template:**

    ```bash
    cp -r examples/detector-template my-detector
    cd my-detector
    ```

2. **Edit `Cargo.toml`** — update the package name and description:

    ```toml
    [package]
    name = "my-detector"
    version = "0.1.0"
    edition = "2021"
    description = "Detects my-config.json files"
    ```

3. **Write your detection logic** in `src/lib.rs` (see below)

4. **Create a manifest file** — `my_detector.manifest.json`:

    ```json
    {
      "name": "my_detector",
      "description": "Detects my-config.json files",
      "version": "0.1.0",
      "sdk_version": "0.1.0",
      "artifact_types": ["my_artifact_type"]
    }
    ```

5. **Build:**

    ```bash
    cargo build --target wasm32-wasip1 --release
    ```

6. **Install:**

    ```bash
    ah-scan plugins install target/wasm32-wasip1/release/my_detector.wasm
    ```

7. **Verify:**
    ```bash
    ah-scan plugins list
    ah-scan plugins info my_detector
    ```

## How plugins work

When the scanner runs, it:

1. Discovers WASM files in `~/.ahscan/plugins/`
2. For each plugin, checks the `.manifest.json` sidecar for SDK version compatibility
3. Pre-reads file content from candidates (up to 8 KB per file)
4. Base64-encodes the content
5. Sends a `DetectRequest` JSON to the plugin's `detect()` export
6. Receives a `DetectResponse` JSON with findings
7. Converts findings to `ArtifactReport`s for scoring and verification

**Plugins never access the filesystem directly.** The scanner provides everything via the request payload.

## Writing the detect function

Your plugin must export a function named `detect` that takes a JSON string and returns a JSON string:

```rust
use ah_scan_sdk::guest::decode_content;
use ah_scan_sdk::{DetectRequest, DetectResponse, Finding, FindingMetadata};
use extism_pdk::*;
use serde_json::json;

#[plugin_fn]
pub fn detect(input: String) -> FnResult<String> {
    // 1. Parse the request
    let request: DetectRequest = serde_json::from_str(&input)
        .map_err(|e| Error::msg(format!("bad request: {e}")))?;

    let mut findings = Vec::new();

    // 2. Examine each candidate
    for candidate in &request.candidates {
        // Check the filename
        if candidate.file_name != "my-config.json" {
            continue;
        }

        // 3. Create a finding
        let mut finding = Finding::new(
            "my_artifact_type",  // must match manifest artifact_types
            0.85,                // confidence 0.0-1.0
            &candidate.path,
        );

        // 4. Add signals (used by risk scoring)
        finding.signals.push("filename_match:my-config.json".into());

        // 5. Add metadata
        finding.metadata.entries
            .insert("paths".into(), json!([&candidate.path]));

        // 6. Optionally analyze content
        if let Some(content) = decode_content(candidate.content_b64.as_deref()) {
            if content.contains("dangerous_setting") {
                finding.signals.push("keyword:dangerous_setting".into());
            }
        }

        findings.push(finding);
    }

    // 7. Return the response
    let response = DetectResponse { findings };
    let output = serde_json::to_string(&response)
        .map_err(|e| Error::msg(format!("serialize error: {e}")))?;
    Ok(output)
}
```

## SDK types reference

### DetectRequest (input to your plugin)

| Field        | Type                 | Description                              |
| ------------ | -------------------- | ---------------------------------------- |
| `deep`       | `bool`               | Whether the scanner is in deep-scan mode |
| `mode`       | `String`             | Scan mode ("host", "workdir", etc.)      |
| `candidates` | `Vec<ScanCandidate>` | Files to examine                         |

### ScanCandidate

| Field         | Type             | Description                                          |
| ------------- | ---------------- | ---------------------------------------------------- |
| `path`        | `String`         | Absolute file path                                   |
| `origin`      | `String`         | Where it was found ("host", "workdir", "filesystem") |
| `file_name`   | `String`         | Just the filename part                               |
| `content_b64` | `Option<String>` | Base64-encoded file content (up to 8 KB)             |
| `file_size`   | `u64`            | Original file size in bytes                          |

### Finding (output from your plugin)

| Field            | Type              | Description                           |
| ---------------- | ----------------- | ------------------------------------- |
| `artifact_type`  | `String`          | Must match a type in your manifest    |
| `confidence`     | `f64`             | 0.0 to 1.0                            |
| `signals`        | `Vec<String>`     | Detection signals (see signal naming) |
| `metadata`       | `FindingMetadata` | Key-value metadata                    |
| `candidate_path` | `String`          | Path of the file that matched         |

### DetectResponse

| Field      | Type           | Description                   |
| ---------- | -------------- | ----------------------------- |
| `findings` | `Vec<Finding>` | All findings from this plugin |

## Signal naming conventions

Follow these patterns so the risk engine and verifier handle your signals correctly:

- `filename_match:<pattern>` — file matched by name
- `keyword:<word>` — capability keyword found (e.g., shell, network, api)
- `dangerous_keyword:<word>` — high-risk keyword (e.g., exfiltrate, steal)
- Use existing signal names from built-in detectors when applicable

## The manifest file

The manifest tells the scanner about your plugin. It must be named `<plugin_name>.manifest.json` and placed next to the `.wasm` file.

```json
{
  "name": "my_detector",
  "description": "What this plugin detects",
  "version": "0.1.0",
  "sdk_version": "0.1.0",
  "artifact_types": ["my_artifact_type"]
}
```

The `sdk_version` must be compatible with the scanner's SDK version (same major.minor).

## Plugin management commands

```bash
ah-scan plugins list              # List installed plugins
ah-scan plugins install <path>    # Install a .wasm plugin
ah-scan plugins remove <name>     # Uninstall a plugin
ah-scan plugins info <name>       # Show plugin details
```

## Tips

- **Keep plugins small.** Each plugin runs in a WASM sandbox with limited resources.
- **Test with real files.** Create test files matching your pattern and run `ah-scan folder .` to verify detection.
- **Check the example.** `examples/detector-cursor-rules/` is a complete working plugin you can reference.
- **Content may be truncated.** Files over 8 KB are cut off. Design your detection to work with partial content.
