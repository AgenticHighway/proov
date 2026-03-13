use crate::discovery::Candidate;
use crate::models::{
    check_for_dangerous_patterns, check_for_secrets, is_content_read_allowed, ArtifactReport,
};

use super::base::Detector;
use super::content_analysis::extract_metadata;
use serde_json::json;
use std::fs;

const MAX_READ_BYTES: usize = 8192;

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

pub struct CursorRulesDetector;

impl Detector for CursorRulesDetector {
    fn name(&self) -> &str {
        "cursor_rules"
    }

    fn detect(&self, candidates: &[Candidate], deep: bool) -> Vec<ArtifactReport> {
        let mut results = Vec::new();
        for candidate in candidates {
            if let Some(report) = classify_candidate(candidate, deep) {
                results.push(report);
            }
        }
        results
    }
}

fn classify_candidate(candidate: &Candidate, deep: bool) -> Option<ArtifactReport> {
    let name = candidate.path.file_name()?.to_str()?;

    let artifact_type = match name {
        ".cursorrules" => "cursor_rules",
        "agents.md" | "AGENTS.md" => "agents_md",
        _ => return None,
    };

    let mut confidence = 0.7_f64;
    let mut signals = Vec::new();
    let mut metadata = serde_json::Map::new();

    metadata.insert(
        "paths".into(),
        json!([candidate.path.to_string_lossy()]),
    );

    if is_content_read_allowed(&candidate.path) {
        if let Some(content) = read_head(&candidate.path) {
            let (kw_signals, kw_count) =
                scan_keywords(&content, KEYWORD_SIGNALS, DEEP_KEYWORDS, deep);
            signals.extend(kw_signals);

            if kw_count > 0 {
                confidence = 0.9;
            }
            if deep && kw_count >= 4 {
                confidence = (confidence + 0.05).min(1.0);
            }

            let content_meta = extract_metadata(&content);
            for (k, v) in content_meta {
                metadata.insert(k, v);
            }

            signals.extend(check_for_secrets(&content));
            signals.extend(check_for_dangerous_patterns(&content));
        }
    }

    let mut report = ArtifactReport::new(artifact_type, confidence);
    report.signals = signals;
    report.metadata = metadata;
    report.artifact_scope = candidate.origin.clone();
    report.compute_hash();
    Some(report)
}

fn read_head(path: &std::path::Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let len = bytes.len().min(MAX_READ_BYTES);
    String::from_utf8(bytes[..len].to_vec()).ok()
}

fn scan_keywords(
    content: &str,
    primary: &[&str],
    deep_kw: &[&str],
    deep: bool,
) -> (Vec<String>, usize) {
    let lowered = content.to_lowercase();
    let mut signals = Vec::new();
    let mut count = 0_usize;

    for kw in primary {
        if lowered.contains(kw) {
            signals.push(format!("keyword:{kw}"));
            count += 1;
        }
    }

    if deep {
        for kw in deep_kw {
            if lowered.contains(kw) {
                signals.push(format!("deep_keyword:{kw}"));
                count += 1;
            }
        }
    }

    (signals, count)
}
