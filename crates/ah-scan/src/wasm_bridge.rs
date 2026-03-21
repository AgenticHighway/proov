//! Bridge between the scanner's native types and the WASM plugin engine.
//!
//! Converts `Candidate` → `ScanCandidate`, runs WASM plugins via
//! `ah_scan_engine`, and converts `Finding` → `ArtifactReport`.

use std::path::{Path, PathBuf};

use crate::engine::PluginRegistry;
use ah_scan_sdk::{DetectRequest, Finding, ScanCandidate};

use crate::discovery::Candidate;
use crate::models::ArtifactReport;

/// Default plugin directory: `~/.ahscan/plugins/`
fn default_plugin_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ahscan").join("plugins"))
}

const MAX_CONTENT_BYTES: usize = 8192;

/// Convert a native `Candidate` to a WASM-safe `ScanCandidate`.
///
/// Reads the first `MAX_CONTENT_BYTES` of the file and base64-encodes them.
fn candidate_to_scan_candidate(candidate: &Candidate) -> ScanCandidate {
    let file_name = candidate
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    let (content_b64, file_size) = match std::fs::metadata(&candidate.path) {
        Ok(meta) => {
            let size = meta.len();
            let content = if crate::models::is_content_read_allowed(&candidate.path) {
                read_and_encode(&candidate.path)
            } else {
                None
            };
            (content, size)
        }
        Err(_) => (None, 0),
    };

    ScanCandidate {
        path: candidate.path.to_string_lossy().to_string(),
        origin: candidate.origin.clone(),
        file_name,
        content_b64,
        file_size,
    }
}

/// Read the head of a file and base64-encode it.
fn read_and_encode(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let len = bytes.len().min(MAX_CONTENT_BYTES);
    Some(base64_encode(&bytes[..len]))
}

/// Minimal base64 encoder (standard alphabet with padding).
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Convert a WASM `Finding` into the scanner's native `ArtifactReport`.
fn finding_to_artifact(finding: &Finding) -> ArtifactReport {
    let mut report = ArtifactReport::new(&finding.artifact_type, finding.confidence);
    report.signals = finding.signals.clone();

    // Copy metadata entries
    for (k, v) in &finding.metadata.entries {
        report.metadata.insert(k.clone(), v.clone());
    }

    // Ensure paths metadata is set
    if !report.metadata.contains_key("paths") {
        report.metadata.insert(
            "paths".to_string(),
            serde_json::json!([&finding.candidate_path]),
        );
    }

    report.compute_hash();
    report
}

/// Run all WASM detector plugins against the given candidates.
///
/// Returns converted `ArtifactReport`s. Errors from individual plugins
/// are logged to stderr but do not halt the scan.
pub fn run_wasm_detectors(
    candidates: &[Candidate],
    mode: &str,
    deep: bool,
    tick: &dyn Fn(&str),
) -> Vec<ArtifactReport> {
    let plugin_dir = match default_plugin_dir() {
        Some(d) if d.is_dir() => d,
        _ => return Vec::new(),
    };

    let mut registry = PluginRegistry::new();
    match registry.load_from_dir(&plugin_dir) {
        Ok(0) => return Vec::new(),
        Ok(n) => tick(&format!("Loaded {n} WASM detector plugin(s)")),
        Err(e) => {
            eprintln!("Warning: failed to load WASM plugins: {e}");
            return Vec::new();
        }
    }

    // Convert candidates to WASM-safe format
    let scan_candidates: Vec<ScanCandidate> = candidates
        .iter()
        .map(candidate_to_scan_candidate)
        .collect();

    let request = DetectRequest {
        deep,
        mode: mode.to_string(),
        candidates: scan_candidates,
    };

    let mut artifacts = Vec::new();
    for (plugin, _source) in registry.plugins_mut() {
        tick(&format!("WASM detector: {}", plugin.name()));
        match plugin.detect(&request) {
            Ok(response) => {
                for finding in &response.findings {
                    artifacts.push(finding_to_artifact(finding));
                }
            }
            Err(e) => {
                eprintln!("Warning: WASM plugin '{}' failed: {e}", plugin.name());
            }
        }
    }

    artifacts
}
