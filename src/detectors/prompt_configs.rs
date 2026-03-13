use crate::discovery::Candidate;
use crate::models::{
    check_for_dangerous_patterns, check_for_secrets, is_content_read_allowed, ArtifactReport,
};

use super::base::Detector;
use super::content_analysis::extract_metadata;
use serde_json::json;
use std::fs;

const MAX_READ_BYTES: usize = 8192;

const KEYWORDS: &[&str] = &[
    "tools",
    "permissions",
    "shell",
    "browser",
    "api",
    "dependencies",
];

const DEEP_KEYWORDS: &[&str] = &[
    "execute",
    "network",
    "filesystem",
    "docker",
    "secrets",
    "system",
];

const STRONG_NAMES: &[&str] = &["copilot-instructions.md"];
const STRONG_SUFFIXES: &[&str] = &[".prompt.md", ".instructions.md", ".prompt.yaml", ".prompt.yml"];
const WEAK_EXTENSIONS: &[&str] = &[".md", ".yaml", ".yml", ".txt"];

pub struct PromptConfigDetector;

impl Detector for PromptConfigDetector {
    fn name(&self) -> &str {
        "prompt_configs"
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

fn match_strength(name: &str) -> Option<&'static str> {
    if STRONG_NAMES.contains(&name) {
        return Some("strong");
    }
    for suffix in STRONG_SUFFIXES {
        if name.ends_with(suffix) {
            return Some("strong");
        }
    }

    let lower = name.to_lowercase();
    if lower.contains("prompt") {
        for ext in WEAK_EXTENSIONS {
            if lower.ends_with(ext) {
                return Some("weak");
            }
        }
    }
    None
}

fn classify_candidate(candidate: &Candidate, deep: bool) -> Option<ArtifactReport> {
    let name = candidate.path.file_name()?.to_str()?;
    let strength = match_strength(name)?;

    let mut confidence = if strength == "strong" { 0.65 } else { 0.4 };
    let mut signals = Vec::new();
    let mut metadata = serde_json::Map::new();

    metadata.insert(
        "paths".into(),
        json!([candidate.path.to_string_lossy()]),
    );
    metadata.insert("match_strength".into(), json!(strength));

    if is_content_read_allowed(&candidate.path) {
        if let Some(content) = read_head(&candidate.path) {
            let (kw_signals, kw_count) =
                scan_keywords(&content, KEYWORDS, DEEP_KEYWORDS, deep);
            signals.extend(kw_signals);

            if kw_count > 0 {
                confidence = 0.85;
            }
            if deep && kw_count >= 4 {
                confidence = (confidence + 0.05_f64).min(1.0);
            }

            let content_meta = extract_metadata(&content);
            for (k, v) in content_meta {
                metadata.insert(k, v);
            }

            signals.extend(check_for_secrets(&content));
            signals.extend(check_for_dangerous_patterns(&content));
        }
    }

    let mut report = ArtifactReport::new("prompt_config", confidence);
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
