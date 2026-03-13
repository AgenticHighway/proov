//! Canonical data models for the AI Execution Inventory report.
//!
//! These structs define the locked v1 schema contract.
//! All detectors, analysis, and reporting modules MUST produce / consume
//! these types so the output stays consistent.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

// ---------------------------------------------------------------------------
// Per-artifact model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactReport {
    pub artifact_type: String,
    pub confidence: f64,
    pub signals: Vec<String>,
    pub metadata: serde_json::Map<String, serde_json::Value>,
    pub risk_score: i32,
    pub risk_reasons: Vec<String>,
    pub verification_status: String,
    pub artifact_id: String,
    pub artifact_hash: String,
    pub registry_eligible: bool,
    pub artifact_scope: String,
}

impl ArtifactReport {
    pub fn new(artifact_type: &str, confidence: f64) -> Self {
        Self {
            artifact_type: artifact_type.to_string(),
            confidence,
            signals: Vec::new(),
            metadata: serde_json::Map::new(),
            risk_score: 0,
            risk_reasons: Vec::new(),
            verification_status: "pending".to_string(),
            artifact_id: String::new(),
            artifact_hash: String::new(),
            registry_eligible: true,
            artifact_scope: "project".to_string(),
        }
    }

    /// Build a path-independent content digest.
    pub fn content_digest(&self) -> String {
        if let Some(serde_json::Value::Array(paths)) = self.metadata.get("paths") {
            let mut sorted: Vec<&str> = paths
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            sorted.sort();

            if let Some(first) = sorted.first() {
                let p = Path::new(first);
                if p.is_file() {
                    if let Ok(bytes) = std::fs::read(p) {
                        return hex_sha256(&bytes);
                    }
                }
            }
        }

        let mut metadata_without_paths = self.metadata.clone();
        metadata_without_paths.remove("paths");

        let mut sorted_signals = self.signals.clone();
        sorted_signals.sort();
        let mut sorted_reasons = self.risk_reasons.clone();
        sorted_reasons.sort();

        let fallback = serde_json::json!({
            "metadata": metadata_without_paths,
            "risk_reasons": sorted_reasons,
            "signals": sorted_signals,
        });
        hex_sha256(fallback.to_string().as_bytes())
    }

    /// Compute path-independent artifact identity hashes.
    ///
    /// `artifact_hash` derives from content digest, artifact type, and
    /// contract version. File path is intentionally excluded so moving
    /// files does not change artifact identity.
    pub fn compute_hash(&mut self) -> String {
        let content_digest = self.content_digest();
        let contract_version = self
            .metadata
            .get("schema_version")
            .and_then(|v| v.as_str())
            .unwrap_or("v1");

        let identity = serde_json::json!({
            "artifact_content": content_digest,
            "artifact_type": self.artifact_type,
            "version": contract_version,
        });
        self.artifact_hash = hex_sha256(identity.to_string().as_bytes());

        let id_identity = serde_json::json!({
            "artifact_hash": self.artifact_hash,
            "artifact_scope": self.artifact_scope,
        });
        self.artifact_id = hex_sha256(id_identity.to_string().as_bytes());
        self.artifact_id.clone()
    }

    /// Return a registry-ready identity block for this artifact.
    pub fn registry_identity(&self) -> serde_json::Value {
        let locator = self
            .metadata
            .get("paths")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        serde_json::json!({
            "artifact_hash": self.artifact_hash,
            "artifact_kind": self.artifact_type,
            "artifact_locator": locator,
            "artifact_scope": self.artifact_scope,
            "registry_eligible": self.registry_eligible,
            "schema_version": "v1",
        })
    }

    /// Serialize self plus registry_identity into a JSON value.
    pub fn to_value(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).expect("ArtifactReport serialization");
        if let serde_json::Value::Object(ref mut map) = v {
            map.insert("registry_identity".to_string(), self.registry_identity());
        }
        v
    }
}

// ---------------------------------------------------------------------------
// Top-level run report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scanned_path: String,
    pub run_id: String,
    pub timestamp: String,
    pub artifacts: Vec<ArtifactReport>,
}

impl ScanReport {
    pub fn new(scanned_path: &str) -> Self {
        let id = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(12)
            .collect::<String>();
        let ts = chrono::Utc::now().to_rfc3339();

        Self {
            scanned_path: scanned_path.to_string(),
            run_id: id,
            timestamp: ts,
            artifacts: Vec::new(),
        }
    }

    pub fn to_json(&self, pretty: bool) -> String {
        let val = self.to_value();
        if pretty {
            serde_json::to_string_pretty(&val).expect("ScanReport JSON serialization")
        } else {
            serde_json::to_string(&val).expect("ScanReport JSON serialization")
        }
    }

    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "run_id": self.run_id,
            "scanned_path": self.scanned_path,
            "timestamp": self.timestamp,
            "artifacts": self.artifacts.iter().map(|a| a.to_value()).collect::<Vec<_>>(),
        })
    }
}

// ---------------------------------------------------------------------------
// Privacy helpers
// ---------------------------------------------------------------------------

pub const SECRET_PATTERNS: &[&str] = &[
    "sk-",
    "ghp_",
    "gho_",
    "github_pat_",
    "AKIA",
    "eyJ",
];

pub const DANGEROUS_KEYWORDS: &[&str] = &[
    "exfiltrate",
    "wipe",
    "rm -rf",
    "steal",
    "upload credentials",
    "reverse shell",
    "disable security",
    "bypass auth",
];

const SHELL_WORDS: &[&str] = &["shell", "bash", "exec", "subprocess"];
const NETWORK_WORDS: &[&str] = &["http", "fetch", "curl", "requests", "network", "api"];
const FS_WORDS: &[&str] = &[
    "filesystem",
    "write_file",
    "read_file",
    "os.remove",
    "shutil",
];

/// Return redacted signals if token-like strings are found.
/// Never stores or returns the actual secret value.
pub fn check_for_secrets(content: &str) -> Vec<String> {
    for pattern in SECRET_PATTERNS {
        if content.contains(pattern) {
            return vec!["credential_exposure_signal".to_string()];
        }
    }
    Vec::new()
}

/// Return signals for dangerous instruction keywords and combos.
pub fn check_for_dangerous_patterns(content: &str) -> Vec<String> {
    let lowered = content.to_lowercase();
    let mut signals = Vec::new();

    for keyword in DANGEROUS_KEYWORDS {
        if lowered.contains(keyword) {
            let first_word = keyword.split_whitespace().next().unwrap_or(keyword);
            signals.push(format!("dangerous_keyword:{first_word}"));
        }
    }

    let has_shell = SHELL_WORDS.iter().any(|w| lowered.contains(w));
    let has_network = NETWORK_WORDS.iter().any(|w| lowered.contains(w));
    let has_fs = FS_WORDS.iter().any(|w| lowered.contains(w));
    if has_shell && has_network && has_fs {
        signals.push("dangerous_combo:shell+network+fs".to_string());
    }

    signals
}

// ---------------------------------------------------------------------------
// Content-read allowlist
// ---------------------------------------------------------------------------

pub const CONTENT_READ_ALLOWLIST: &[&str] = &[
    ".cursorrules",
    "agents.md",
    "AGENTS.md",
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
];

pub const CONTENT_READ_GLOB_PATTERNS: &[&str] = &["*prompt*", "*.instructions.md"];

/// Return true if the file's name is on the v1 content-read allowlist.
pub fn is_content_read_allowed(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };

    if CONTENT_READ_ALLOWLIST.contains(&name) {
        return true;
    }

    for pattern in CONTENT_READ_GLOB_PATTERNS {
        if let Ok(pat) = glob::Pattern::new(pattern) {
            if pat.matches(name) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
