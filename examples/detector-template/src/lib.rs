//! Detector plugin template.
//!
//! Copy this crate and modify it to create your own ah-scan detector plugin.
//!
//! ## Quick start
//!
//! 1. Copy this directory and rename it.
//! 2. Update `Cargo.toml` with your plugin's name and description.
//! 3. Edit the `detect` function below with your detection logic.
//! 4. Create a `.manifest.json` sidecar file describing your plugin.
//! 5. Build and install:
//!
//! ```bash
//! rustup target add wasm32-wasip1
//! cargo build --target wasm32-wasip1 --release
//! ah-scan plugins install target/wasm32-wasip1/release/your_plugin.wasm
//! ```

use ah_scan_sdk::guest::decode_content;
use ah_scan_sdk::{DetectRequest, DetectResponse, Finding, FindingMetadata};
use extism_pdk::*;
use serde_json::json;

/// The main entry point called by the scanner host.
///
/// Receives a JSON-encoded `DetectRequest` and must return a JSON-encoded
/// `DetectResponse`.
#[plugin_fn]
pub fn detect(input: String) -> FnResult<String> {
    let request: DetectRequest =
        serde_json::from_str(&input).map_err(|e| Error::msg(format!("bad request: {e}")))?;

    let mut findings = Vec::new();

    for candidate in &request.candidates {
        // TODO: Replace this with your detection logic.
        //
        // Check `candidate.file_name` to match files you care about.
        // Use `decode_content(candidate.content_b64.as_deref())` to read
        // the file content (base64-decoded to a String).
        //
        // Example: detect files named "my-config.json"
        if candidate.file_name == "my-config.json" {
            let mut finding = Finding::new(
                "my_artifact_type", // artifact type you're detecting
                0.9,                // confidence 0.0–1.0
                &candidate.path,
            );

            // Add signals describing what you found
            finding.signals.push("my_signal".to_string());

            // Add metadata
            finding
                .metadata
                .entries
                .insert("paths".into(), json!([&candidate.path]));

            // Optionally analyze content
            if let Some(content) = decode_content(candidate.content_b64.as_deref()) {
                // ... analyze content ...
                let _ = content;
            }

            findings.push(finding);
        }
    }

    let response = DetectResponse { findings };
    let output = serde_json::to_string(&response)
        .map_err(|e| Error::msg(format!("serialize error: {e}")))?;
    Ok(output)
}
