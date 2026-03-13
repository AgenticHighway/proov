//! Example WASM detector plugin: cursor_rules
//!
//! Detects `.cursorrules` and `agents.md` / `AGENTS.md` files.
//! Demonstrates how to write an ah-scan detector plugin using the SDK.
//!
//! ## Building
//!
//! ```bash
//! # Install the WASM target
//! rustup target add wasm32-wasip1
//!
//! # Build the plugin
//! cargo build --target wasm32-wasip1 --release
//!
//! # Install it
//! mkdir -p ~/.ahscan/plugins
//! cp target/wasm32-wasip1/release/detector_cursor_rules.wasm ~/.ahscan/plugins/
//! ```

use ah_scan_sdk::guest::decode_content;
use ah_scan_sdk::{DetectRequest, DetectResponse, Finding, FindingMetadata};
use extism_pdk::*;
use serde_json::json;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const KEYWORD_SIGNALS: &[&str] = &[
    "tools",
    "permissions",
    "system",
    "instructions",
    "shell",
    "browser",
    "api",
];

const DEEP_KEYWORDS: &[&str] = &[
    "dependencies",
    "execute",
    "network",
    "filesystem",
    "docker",
    "secrets",
];

const DANGEROUS_KEYWORDS: &[&str] = &[
    "exfiltrate",
    "wipe",
    "rm -rf",
    "steal",
    "upload credentials",
    "reverse shell",
    "disable security",
    "bypass auth",
];

const SECRET_PREFIXES: &[&str] = &["sk-", "ghp_", "gho_", "github_pat_", "AKIA", "eyJ"];

// ---------------------------------------------------------------------------
// Plugin entry point
// ---------------------------------------------------------------------------

#[plugin_fn]
pub fn detect(input: String) -> FnResult<String> {
    let request: DetectRequest =
        serde_json::from_str(&input).map_err(|e| Error::msg(format!("bad request: {e}")))?;

    let mut findings = Vec::new();

    for candidate in &request.candidates {
        if let Some(finding) = classify_candidate(candidate, request.deep) {
            findings.push(finding);
        }
    }

    let response = DetectResponse { findings };
    let output = serde_json::to_string(&response)
        .map_err(|e| Error::msg(format!("serialize error: {e}")))?;
    Ok(output)
}

// ---------------------------------------------------------------------------
// Detection logic
// ---------------------------------------------------------------------------

fn classify_candidate(
    candidate: &ah_scan_sdk::ScanCandidate,
    deep: bool,
) -> Option<Finding> {
    let name = &candidate.file_name;

    let artifact_type = match name.as_str() {
        ".cursorrules" => "cursor_rules",
        "agents.md" | "AGENTS.md" => "agents_md",
        _ => return None,
    };

    let mut confidence = 0.7_f64;
    let mut signals = Vec::new();
    let mut metadata = FindingMetadata::default();

    metadata
        .entries
        .insert("paths".into(), json!([&candidate.path]));

    // Analyze content if provided
    if let Some(content) = decode_content(candidate.content_b64.as_deref()) {
        let (kw_signals, kw_count) = scan_keywords(&content, deep);
        signals.extend(kw_signals);

        if kw_count > 0 {
            confidence = 0.9;
        }
        if deep && kw_count >= 4 {
            confidence = (confidence + 0.05).min(1.0);
        }

        // Extract declared tools / permissions
        let content_meta = extract_content_metadata(&content);
        for (k, v) in content_meta {
            metadata.entries.insert(k, v);
        }

        signals.extend(check_for_secrets(&content));
        signals.extend(check_for_dangerous_patterns(&content));
    }

    let mut finding = Finding::new(artifact_type, confidence, &candidate.path);
    finding.signals = signals;
    finding.metadata = metadata;
    Some(finding)
}

// ---------------------------------------------------------------------------
// Analysis helpers
// ---------------------------------------------------------------------------

fn scan_keywords(content: &str, deep: bool) -> (Vec<String>, usize) {
    let lowered = content.to_lowercase();
    let mut signals = Vec::new();
    let mut count = 0_usize;

    for kw in KEYWORD_SIGNALS {
        if lowered.contains(kw) {
            signals.push(format!("keyword:{kw}"));
            count += 1;
        }
    }

    if deep {
        for kw in DEEP_KEYWORDS {
            if lowered.contains(kw) {
                signals.push(format!("deep_keyword:{kw}"));
                count += 1;
            }
        }
    }

    (signals, count)
}

fn check_for_secrets(content: &str) -> Vec<String> {
    for prefix in SECRET_PREFIXES {
        if content.contains(prefix) {
            return vec!["credential_exposure_signal".to_string()];
        }
    }
    Vec::new()
}

fn check_for_dangerous_patterns(content: &str) -> Vec<String> {
    let lowered = content.to_lowercase();
    let mut signals = Vec::new();

    for keyword in DANGEROUS_KEYWORDS {
        if lowered.contains(keyword) {
            let first_word = keyword.split_whitespace().next().unwrap_or(keyword);
            signals.push(format!("dangerous_keyword:{first_word}"));
        }
    }

    let shell_words = ["shell", "bash", "exec", "subprocess"];
    let network_words = ["http", "fetch", "curl", "requests", "network", "api"];
    let fs_words = ["filesystem", "write_file", "read_file", "os.remove", "shutil"];

    let has_shell = shell_words.iter().any(|w| lowered.contains(w));
    let has_network = network_words.iter().any(|w| lowered.contains(w));
    let has_fs = fs_words.iter().any(|w| lowered.contains(w));
    if has_shell && has_network && has_fs {
        signals.push("dangerous_combo:shell+network+fs".to_string());
    }

    signals
}

const TOOL_NAMES: &[&str] = &["filesystem", "shell", "browser", "api", "python", "docker"];
const PERMISSION_TOKENS: &[&str] = &["allow", "deny", "read", "write", "execute"];

fn extract_content_metadata(content: &str) -> Vec<(String, serde_json::Value)> {
    let lowered = content.to_lowercase();

    let tools: Vec<String> = TOOL_NAMES
        .iter()
        .filter(|t| lowered.contains(**t))
        .map(|s| s.to_string())
        .collect();

    let permissions: Vec<String> = PERMISSION_TOKENS
        .iter()
        .filter(|t| lowered.contains(**t))
        .map(|s| s.to_string())
        .collect();

    vec![
        ("declared_tools".into(), json!(tools)),
        ("permissions".into(), json!(permissions)),
    ]
}
