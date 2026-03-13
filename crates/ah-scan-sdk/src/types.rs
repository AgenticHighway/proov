//! Core data types shared between the scanner host and WASM detector plugins.
//!
//! All types are serialized as JSON across the WASM boundary via Extism's
//! host↔guest memory protocol.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Manifest — describes a detector plugin
// ---------------------------------------------------------------------------

/// Static metadata about a detector plugin, embedded in the WASM module
/// or provided in a sidecar manifest file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorManifest {
    /// Unique machine-readable name (e.g. `"cursor_rules"`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Semver of this detector.
    pub version: String,
    /// SDK version this detector targets.
    pub sdk_version: String,
    /// Artifact types this detector can produce.
    pub artifact_types: Vec<String>,
}

// ---------------------------------------------------------------------------
// Input — what the host sends to the plugin
// ---------------------------------------------------------------------------

/// A single file candidate for inspection.
///
/// The host reads the file and provides content bytes so that WASM plugins
/// never need filesystem access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCandidate {
    /// Relative or display path (never used for filesystem access inside WASM).
    pub path: String,
    /// Origin tag: `"host"`, `"workdir"`, `"filesystem"`.
    pub origin: String,
    /// File name component (e.g. `".cursorrules"`).
    pub file_name: String,
    /// First N bytes of the file content, base64-encoded.
    /// The host controls how much content is provided.
    pub content_b64: Option<String>,
    /// File size in bytes (full file, not just the head).
    pub file_size: u64,
}

/// The request payload sent from the host to a detector plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectRequest {
    /// Whether the scan is running in deep mode.
    pub deep: bool,
    /// The scan mode: `"host"`, `"workdir"`, `"filesystem"`, `"file"`.
    pub mode: String,
    /// Candidate files to inspect.
    pub candidates: Vec<ScanCandidate>,
}

// ---------------------------------------------------------------------------
// Output — what the plugin returns to the host
// ---------------------------------------------------------------------------

/// Structured metadata attached to a finding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingMetadata {
    /// Free-form key-value pairs.
    #[serde(flatten)]
    pub entries: serde_json::Map<String, serde_json::Value>,
}

/// A single detection finding produced by a plugin.
///
/// This maps closely to the host's `ArtifactReport` but uses only
/// serializable, WASM-safe types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// The artifact type (e.g. `"cursor_rules"`, `"mcp_config"`).
    pub artifact_type: String,
    /// Detection confidence in `[0.0, 1.0]`.
    pub confidence: f64,
    /// Signal strings (e.g. `"keyword:shell"`, `"credential_exposure_signal"`).
    pub signals: Vec<String>,
    /// Structured metadata.
    pub metadata: FindingMetadata,
    /// Path of the candidate that produced this finding.
    pub candidate_path: String,
}

impl Finding {
    pub fn new(artifact_type: &str, confidence: f64, candidate_path: &str) -> Self {
        Self {
            artifact_type: artifact_type.to_string(),
            confidence,
            signals: Vec::new(),
            metadata: FindingMetadata::default(),
            candidate_path: candidate_path.to_string(),
        }
    }
}

/// The response payload returned from a detector plugin to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectResponse {
    pub findings: Vec<Finding>,
}
