//! Custom rules detector — applies declarative TOML rule files.
//!
//! Loads rules from `~/.ahscan/rules/` and evaluates them against
//! scan candidates during built-in detection.

use crate::discovery::Candidate;
use crate::models::{
    check_for_dangerous_patterns, check_for_secrets, gather_file_primitives,
    is_content_read_allowed, ArtifactReport,
};
use crate::rule_engine::{
    default_rules_dir, load_builtin_rules, load_rules_from_dir, matches_rule, scan_rule_keywords,
    scan_rule_patterns, DetectionRule,
};

use super::base::Detector;
use serde_json::json;
use std::fs;

const MAX_READ_BYTES: usize = 8192;

pub struct CustomRulesDetector {
    rules: Vec<DetectionRule>,
}

impl CustomRulesDetector {
    pub fn load() -> Self {
        // Always start with the built-in rules (compiled from rules/ in the repo)
        let mut rules = load_builtin_rules();

        // Supplement with user-installed rules from ~/.ahscan/rules/
        if let Some(dir) = default_rules_dir() {
            if dir.is_dir() {
                let user_rules = load_rules_from_dir(&dir);
                if !user_rules.is_empty() {
                    eprintln!(
                        "Loaded {} custom rule(s) from {}",
                        user_rules.len(),
                        dir.display()
                    );
                }
                rules.extend(user_rules);
            }
        }

        Self { rules }
    }
}

impl Detector for CustomRulesDetector {
    fn name(&self) -> &str {
        "custom_rules"
    }

    fn detect(&self, candidates: &[Candidate], deep: bool) -> Vec<ArtifactReport> {
        let mut results = Vec::new();
        for candidate in candidates {
            for rule in &self.rules {
                if let Some(report) = apply_rule(candidate, rule, deep) {
                    results.push(report);
                }
            }
        }
        results
    }
}

fn apply_rule(candidate: &Candidate, rule: &DetectionRule, deep: bool) -> Option<ArtifactReport> {
    let file_name = candidate.path.file_name()?.to_str()?;

    if !matches_rule(file_name, rule) {
        return None;
    }

    let mut confidence = rule.match_config.confidence;
    let mut signals = Vec::new();
    let mut metadata = serde_json::Map::new();

    // File primitives — gather once, avoid re-reads downstream
    let file_prims = gather_file_primitives(&candidate.path);
    metadata.extend(file_prims);

    signals.push(format!("filename_match:{file_name}"));
    metadata.insert("paths".into(), json!([candidate.path.to_string_lossy()]));
    metadata.insert("rule_name".into(), json!(rule.detector.name));

    // Content analysis (if allowed and readable)
    if is_content_read_allowed(&candidate.path) {
        if let Some(content) = read_head(&candidate.path) {
            // Primary keywords
            if let Some(ref kw) = rule.keywords {
                let (kw_signals, kw_count) = scan_rule_keywords(&content, kw);
                signals.extend(kw_signals);
                if kw_count >= kw.boost_threshold {
                    if let Some(boost) = kw.boost_confidence {
                        confidence = confidence.max(boost);
                    }
                }
            }

            if let Some(ref patterns) = rule.patterns {
                let (pattern_signals, pattern_count) = scan_rule_patterns(&content, patterns);
                signals.extend(pattern_signals);
                if pattern_count >= patterns.boost_threshold {
                    if let Some(boost) = patterns.boost_confidence {
                        confidence = confidence.max(boost);
                    }
                }
            }

            // Deep keywords (only in deep mode)
            if deep {
                if let Some(ref dk) = rule.deep_keywords {
                    let (dk_signals, dk_count) = scan_rule_keywords(&content, dk);
                    signals.extend(dk_signals);
                    if dk_count >= dk.boost_threshold {
                        if let Some(boost) = dk.boost_confidence {
                            confidence = confidence.max(boost);
                        }
                    }
                }

                if let Some(ref patterns) = rule.deep_patterns {
                    let (pattern_signals, pattern_count) = scan_rule_patterns(&content, patterns);
                    signals.extend(pattern_signals);
                    if pattern_count >= patterns.boost_threshold {
                        if let Some(boost) = patterns.boost_confidence {
                            confidence = confidence.max(boost);
                        }
                    }
                }
            }

            signals.extend(check_for_secrets(&content));
            signals.extend(check_for_dangerous_patterns(&content));
        }
    }

    confidence = confidence.min(1.0);

    let mut report = ArtifactReport::new(&rule.detector.artifact_type, confidence);
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
