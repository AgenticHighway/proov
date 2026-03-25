//! Declarative rule engine for custom detectors.
//!
//! Loads `.toml` rule files from `~/.ahscan/rules/` and applies them
//! during scanning. Each rule file defines filename patterns, keywords,
//! and signal mappings — no code required.

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Rule definition
// ---------------------------------------------------------------------------

/// A single declarative detection rule loaded from a `.toml` file.
#[derive(Debug, Clone, Deserialize)]
pub struct DetectionRule {
    pub detector: DetectorMeta,
    #[serde(rename = "match")]
    pub match_config: MatchConfig,
    #[serde(default)]
    pub keywords: Option<KeywordConfig>,
    #[serde(default)]
    pub deep_keywords: Option<KeywordConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DetectorMeta {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub artifact_type: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatchConfig {
    #[serde(default)]
    pub filenames: Vec<String>,
    #[serde(default)]
    pub suffixes: Vec<String>,
    #[serde(default)]
    pub confidence: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeywordConfig {
    pub keywords: Vec<String>,
    #[serde(default = "default_signals_prefix")]
    pub signals_prefix: String,
    #[serde(default)]
    pub boost_confidence: Option<f64>,
    #[serde(default = "default_boost_threshold")]
    pub boost_threshold: usize,
}

fn default_signals_prefix() -> String {
    "keyword".to_string()
}

fn default_boost_threshold() -> usize {
    1
}

// ---------------------------------------------------------------------------
// Rule loading
// ---------------------------------------------------------------------------

/// Built-in rules compiled into the binary from the repo's `rules/` directory.
///
/// These cover the standard AI artifact types (cursor_rules, agents_md,
/// prompt_config). They are always active and cannot be overridden by user
/// rules in `~/.ahscan/rules/`.
pub fn load_builtin_rules() -> Vec<DetectionRule> {
    const SOURCES: &[(&str, &str)] = &[
        ("cursor-rules",        include_str!("../../../rules/cursor-rules.toml")),
        ("agents-md",           include_str!("../../../rules/agents-md.toml")),
        ("prompt-configs",      include_str!("../../../rules/prompt-configs.toml")),
        ("prompt-configs-weak", include_str!("../../../rules/prompt-configs-weak.toml")),
    ];

    let mut rules = Vec::new();
    for (name, content) in SOURCES {
        match parse_rule_content(content) {
            Ok(rule) => rules.push(rule),
            Err(e) => eprintln!("Warning: built-in rule '{name}' failed to parse: {e}"),
        }
    }
    rules
}

/// Default rules directory: `~/.ahscan/rules/`
pub fn default_rules_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ahscan").join("rules"))
}

/// Load all `.toml` rule files from a directory.
///
/// Invalid rules are logged to stderr and skipped.
pub fn load_rules_from_dir(dir: &Path) -> Vec<DetectionRule> {
    let mut rules = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return rules,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        match load_rule_file(&path) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                eprintln!(
                    "Warning: skipping invalid rule {}: {e}",
                    path.display()
                );
            }
        }
    }

    rules
}

fn load_rule_file(path: &Path) -> Result<DetectionRule, String> {
    load_rule_file_pub(path)
}

/// Parse and validate a rule from raw TOML content (no file I/O).
pub fn parse_rule_content(content: &str) -> Result<DetectionRule, String> {
    let rule: DetectionRule =
        toml::from_str(content).map_err(|e| format!("parse error: {e}"))?;

    if rule.detector.name.is_empty() {
        return Err("detector.name is required".to_string());
    }
    if rule.detector.artifact_type.is_empty() {
        return Err("detector.artifact_type is required".to_string());
    }
    if rule.match_config.filenames.is_empty() && rule.match_config.suffixes.is_empty() {
        return Err("match.filenames or match.suffixes must be non-empty".to_string());
    }

    Ok(rule)
}

/// Public entry point for rule loading — used by `rules.rs` CLI commands.
pub fn load_rule_file_pub(path: &Path) -> Result<DetectionRule, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    parse_rule_content(&content).map_err(|e| format!("parse error in {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Rule matching
// ---------------------------------------------------------------------------

/// Check whether a filename matches a rule's patterns.
pub fn matches_rule(file_name: &str, rule: &DetectionRule) -> bool {
    let lower = file_name.to_lowercase();
    let cfg = &rule.match_config;

    for pattern in &cfg.filenames {
        if pattern.contains('*') {
            if let Ok(pat) = glob::Pattern::new(&pattern.to_lowercase()) {
                if pat.matches(&lower) {
                    return true;
                }
            }
        } else if lower == pattern.to_lowercase() {
            return true;
        }
    }

    for suffix in &cfg.suffixes {
        if lower.ends_with(&suffix.to_lowercase()) {
            return true;
        }
    }

    false
}

/// Scan content for keywords defined in a keyword config block.
///
/// Returns `(signals, match_count)`.
pub fn scan_rule_keywords(content: &str, kw: &KeywordConfig) -> (Vec<String>, usize) {
    let lowered = content.to_lowercase();
    let mut signals = Vec::new();
    let mut count = 0_usize;

    for keyword in &kw.keywords {
        if lowered.contains(&keyword.to_lowercase()) {
            signals.push(format!("{}:{keyword}", kw.signals_prefix));
            count += 1;
        }
    }

    (signals, count)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rule() -> DetectionRule {
        let toml_str = r#"
[detector]
name = "terraform_configs"
description = "Detect Terraform files with AI provider usage"
artifact_type = "terraform_config"

[match]
filenames = ["main.tf", "providers.tf"]
suffixes = [".tf"]
confidence = 0.7

[keywords]
keywords = ["openai", "anthropic", "langchain"]
signals_prefix = "keyword"
boost_confidence = 0.85
boost_threshold = 1

[deep_keywords]
keywords = ["secret", "api_key"]
signals_prefix = "deep_keyword"
"#;
        toml::from_str(toml_str).unwrap()
    }

    #[test]
    fn matches_exact_filename() {
        let rule = sample_rule();
        assert!(matches_rule("main.tf", &rule));
        assert!(matches_rule("providers.tf", &rule));
    }

    #[test]
    fn matches_suffix() {
        let rule = sample_rule();
        assert!(matches_rule("network.tf", &rule));
        assert!(!matches_rule("network.yaml", &rule));
    }

    #[test]
    fn matches_case_insensitive() {
        let rule = sample_rule();
        assert!(matches_rule("Main.TF", &rule));
    }

    #[test]
    fn keyword_scan_finds_matches() {
        let rule = sample_rule();
        let kw = rule.keywords.as_ref().unwrap();
        let content = "provider openai { model = gpt-4 }";
        let (signals, count) = scan_rule_keywords(content, kw);
        assert_eq!(count, 1);
        assert!(signals.contains(&"keyword:openai".to_string()));
    }

    #[test]
    fn keyword_scan_no_match() {
        let rule = sample_rule();
        let kw = rule.keywords.as_ref().unwrap();
        let (_, count) = scan_rule_keywords("nothing relevant here", kw);
        assert_eq!(count, 0);
    }

    #[test]
    fn parse_rule_file_validates_required_fields() {
        let bad_toml = r#"
[detector]
name = ""
artifact_type = "test"

[match]
filenames = ["test.txt"]
confidence = 0.5
"#;
        let tmp = std::env::temp_dir().join("ah_test_bad_rule.toml");
        fs::write(&tmp, bad_toml).unwrap();
        let result = load_rule_file(&tmp);
        assert!(result.is_err());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn glob_pattern_matching() {
        let toml_str = r#"
[detector]
name = "glob_test"
artifact_type = "test"

[match]
filenames = ["*.prompt.md"]
confidence = 0.7
"#;
        let rule: DetectionRule = toml::from_str(toml_str).unwrap();
        assert!(matches_rule("my-tool.prompt.md", &rule));
        assert!(!matches_rule("readme.md", &rule));
    }

    // -----------------------------------------------------------------------
    // Built-in rules
    // -----------------------------------------------------------------------

    #[test]
    fn builtin_rules_load_and_cover_expected_artifact_types() {
        let rules = load_builtin_rules();
        assert_eq!(rules.len(), 4, "expected 4 built-in rules");

        let types: Vec<&str> = rules.iter().map(|r| r.detector.artifact_type.as_str()).collect();
        assert!(types.contains(&"cursor_rules"),  "missing cursor_rules");
        assert!(types.contains(&"agents_md"),      "missing agents_md");
        // Two prompt_config rules (strong + weak)
        assert_eq!(types.iter().filter(|&&t| t == "prompt_config").count(), 2,
            "expected 2 prompt_config rules");
    }

    #[test]
    fn builtin_cursor_rules_matches_cursorrules_file() {
        let rules = load_builtin_rules();
        let rule = rules.iter().find(|r| r.detector.artifact_type == "cursor_rules").unwrap();
        assert!(matches_rule(".cursorrules", rule));
        assert!(!matches_rule("readme.md", rule));
    }

    #[test]
    fn builtin_agents_md_matches_both_casings() {
        let rules = load_builtin_rules();
        let rule = rules.iter().find(|r| r.detector.artifact_type == "agents_md").unwrap();
        assert!(matches_rule("agents.md", rule));
        assert!(matches_rule("AGENTS.md", rule));
        assert!(!matches_rule("agents.txt", rule));
    }

    #[test]
    fn builtin_prompt_configs_matches_copilot_instructions() {
        let rules = load_builtin_rules();
        // The strong rule should match copilot-instructions.md
        let matched = rules.iter().any(|r| {
            r.detector.artifact_type == "prompt_config" && matches_rule("copilot-instructions.md", r)
        });
        assert!(matched, "no prompt_config rule matched copilot-instructions.md");
    }

    #[test]
    fn builtin_prompt_configs_matches_prompt_md_suffix() {
        let rules = load_builtin_rules();
        let matched = rules.iter().any(|r| {
            r.detector.artifact_type == "prompt_config" && matches_rule("my-tool.prompt.md", r)
        });
        assert!(matched, "no prompt_config rule matched *.prompt.md");
    }

    #[test]
    fn builtin_prompt_configs_weak_matches_prompt_in_name() {
        let rules = load_builtin_rules();
        let matched = rules.iter().any(|r| {
            r.detector.artifact_type == "prompt_config" && matches_rule("my-prompt.md", r)
        });
        assert!(matched, "weak prompt_config rule did not match *prompt*.md");
    }
}
