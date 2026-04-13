use crate::content_patterns::scan_secret_signals;
use crate::discovery::Candidate;
use crate::models::{ArtifactReport, CONTENT_READ_ALLOWLIST, CONTENT_READ_GLOB_PATTERNS};
use crate::source_patterns::{
    json_secret_patterns, json_url_patterns, should_skip_json_config, MAX_JSON_CONFIG_BYTES,
};
use glob::Pattern;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const MAX_SOURCE_SURFACE_FILES: usize = 512;

const SOURCE_EXTENSIONS: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "go", "rs", "java", "rb", "sh",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceFinding {
    pub(crate) family: &'static str,
    pub(crate) signal: String,
    pub(crate) path: PathBuf,
    pub(crate) line: Option<usize>,
    pub(crate) summary: String,
}

pub(crate) fn is_supported_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            SOURCE_EXTENSIONS
                .iter()
                .any(|candidate| ext.eq_ignore_ascii_case(candidate))
        })
        .unwrap_or(false)
}

pub(crate) fn is_supported_json_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
}

pub(crate) fn is_scannable_json_file(path: &Path) -> bool {
    is_supported_json_file(path) && !should_skip_json_config(path)
}

pub(crate) fn has_ai_adjacent_candidate(candidates: &[Candidate]) -> bool {
    candidates
        .iter()
        .any(|candidate| is_ai_adjacent_path(&candidate.path))
}

pub(crate) fn build_source_risk_surface(
    root: &Path,
    scanned_source_count: usize,
    scanned_json_count: usize,
    findings: &[SourceFinding],
    ai_adjacent: bool,
    truncated: bool,
) -> ArtifactReport {
    let mut artifact = ArtifactReport::new(
        "source_risk_surface",
        if findings.is_empty() { 0.35 } else { 0.65 },
    );

    let mut families: BTreeSet<&str> = BTreeSet::new();
    let mut finding_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut file_counts: BTreeMap<String, usize> = BTreeMap::new();

    for finding in findings {
        families.insert(finding.family);
        *finding_counts.entry(finding.family).or_default() += 1;
        *file_counts
            .entry(finding.path.to_string_lossy().to_string())
            .or_default() += 1;
    }

    let mut signals: Vec<String> = findings
        .iter()
        .map(|finding| finding.signal.clone())
        .collect();
    signals.sort();
    signals.dedup();
    artifact.signals = signals;

    let top_risky_files: Vec<String> = file_counts
        .into_iter()
        .collect::<Vec<_>>()
        .into_iter()
        .sorted_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)))
        .into_iter()
        .take(5)
        .map(|(path, _)| path)
        .collect();

    artifact
        .metadata
        .insert("paths".into(), json!([root.to_string_lossy().to_string()]));
    artifact.metadata.insert(
        "matched_families".into(),
        json!(families.into_iter().collect::<Vec<_>>()),
    );
    artifact
        .metadata
        .insert("finding_counts".into(), json!(finding_counts));
    artifact
        .metadata
        .insert("top_risky_files".into(), json!(top_risky_files));
    artifact.metadata.insert(
        "scanned_source_file_count".into(),
        json!(scanned_source_count),
    );
    artifact
        .metadata
        .insert("scanned_json_file_count".into(), json!(scanned_json_count));
    artifact
        .metadata
        .insert("ai_adjacent_context".into(), json!(ai_adjacent));
    artifact
        .metadata
        .insert("bounded_scan_limit".into(), json!(MAX_SOURCE_SURFACE_FILES));
    artifact
        .metadata
        .insert("truncated".into(), json!(truncated));
    artifact.compute_hash();
    artifact
}

pub(crate) fn common_root(paths: &[PathBuf]) -> Option<PathBuf> {
    let mut components: Vec<_> = paths.first()?.components().collect();

    for path in paths.iter().skip(1) {
        let current: Vec<_> = path.components().collect();
        let shared_len = components
            .iter()
            .zip(current.iter())
            .take_while(|(left, right)| left == right)
            .count();
        components.truncate(shared_len);
        if components.is_empty() {
            break;
        }
    }

    if components.is_empty() {
        return None;
    }

    let mut root = PathBuf::new();
    for component in components {
        root.push(component.as_os_str());
    }
    Some(root)
}

pub(crate) fn is_ai_adjacent_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    if CONTENT_READ_ALLOWLIST.contains(&name) {
        return true;
    }

    CONTENT_READ_GLOB_PATTERNS.iter().any(|pattern| {
        Pattern::new(pattern)
            .map(|compiled| compiled.matches(name))
            .unwrap_or(false)
    })
}

pub(crate) fn scan_json_config_file(path: &Path) -> Vec<SourceFinding> {
    if !is_scannable_json_file(path) {
        return Vec::new();
    }

    if fs::metadata(path)
        .map(|metadata| metadata.len() > MAX_JSON_CONFIG_BYTES as u64)
        .unwrap_or(false)
    {
        return Vec::new();
    }

    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };

    scan_json_config_content(path, &content)
}

fn scan_json_config_content(path: &Path, content: &str) -> Vec<SourceFinding> {
    let mut findings = Vec::new();
    let mut seen_signals: BTreeSet<String> = BTreeSet::new();

    for signal in scan_secret_signals(content) {
        if seen_signals.insert(signal.clone()) {
            findings.push(SourceFinding {
                family: "json_secret",
                signal,
                path: path.to_path_buf(),
                line: None,
                summary: "JSON config contains embedded secret material".to_string(),
            });
        }
    }

    for pattern in json_secret_patterns() {
        if let Some(matched) = pattern.regex.find(content) {
            let signal = pattern.signal.to_string();
            if seen_signals.insert(signal.clone()) {
                findings.push(SourceFinding {
                    family: "json_secret",
                    signal,
                    path: path.to_path_buf(),
                    line: Some(line_number_for_offset(content, matched.start())),
                    summary: pattern.summary.to_string(),
                });
            }
        }
    }

    for pattern in json_url_patterns() {
        if let Some(matched) = pattern.regex.find(content) {
            let signal = pattern.signal.to_string();
            if seen_signals.insert(signal.clone()) {
                findings.push(SourceFinding {
                    family: "json_destination",
                    signal,
                    path: path.to_path_buf(),
                    line: Some(line_number_for_offset(content, matched.start())),
                    summary: pattern.summary.to_string(),
                });
            }
        }
    }

    findings.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.signal.cmp(&right.signal))
            .then_with(|| left.line.cmp(&right.line))
    });
    findings
}

fn line_number_for_offset(content: &str, offset: usize) -> usize {
    content[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

trait SortedBy: Iterator + Sized {
    fn sorted_by<F>(self, compare: F) -> Vec<Self::Item>
    where
        F: FnMut(&Self::Item, &Self::Item) -> std::cmp::Ordering,
    {
        let mut items: Vec<Self::Item> = self.collect();
        items.sort_by(compare);
        items
    }
}

impl<I: Iterator> SortedBy for I {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn candidate(path: &str) -> Candidate {
        Candidate {
            path: PathBuf::from(path),
            origin: "workdir".to_string(),
        }
    }

    #[test]
    fn supported_source_file_matches_expected_extensions() {
        assert!(is_supported_source_file(Path::new("src/main.ts")));
        assert!(is_supported_source_file(Path::new("src/lib.rs")));
        assert!(!is_supported_source_file(Path::new("README.md")));
    }

    #[test]
    fn supported_json_file_matches_json_only() {
        assert!(is_supported_json_file(Path::new("config/app.json")));
        assert!(!is_supported_json_file(Path::new("config/app.yaml")));
    }

    #[test]
    fn scannable_json_file_skips_noisy_metadata() {
        assert!(!is_scannable_json_file(Path::new("package.json")));
        assert!(!is_scannable_json_file(Path::new("package-lock.json")));
        assert!(is_scannable_json_file(Path::new("config/app.json")));
    }

    #[test]
    fn ai_adjacent_candidate_detected_from_known_prompt_files() {
        let candidates = vec![
            candidate("/project/AGENTS.md"),
            candidate("/project/src/main.ts"),
        ];
        assert!(has_ai_adjacent_candidate(&candidates));
    }

    #[test]
    fn common_root_returns_shared_parent() {
        let paths = vec![
            PathBuf::from("/project/src/main.ts"),
            PathBuf::from("/project/src/lib/util.ts"),
        ];
        assert_eq!(common_root(&paths), Some(PathBuf::from("/project/src")));
    }

    #[test]
    fn build_source_risk_surface_aggregates_findings() {
        let findings = vec![
            SourceFinding {
                family: "dynamic_execution",
                signal: "source:nonliteral_spawn".to_string(),
                path: PathBuf::from("/project/src/main.ts"),
                line: Some(12),
                summary: "spawn with non-literal command".to_string(),
            },
            SourceFinding {
                family: "dynamic_execution",
                signal: "source:nonliteral_spawn".to_string(),
                path: PathBuf::from("/project/src/main.ts"),
                line: Some(19),
                summary: "spawn with non-literal command".to_string(),
            },
            SourceFinding {
                family: "network_context",
                signal: "source:ssrf_internal_host".to_string(),
                path: PathBuf::from("/project/src/http.ts"),
                line: Some(7),
                summary: "internal hostname in request context".to_string(),
            },
        ];

        let artifact =
            build_source_risk_surface(Path::new("/project"), 2, 1, &findings, true, false);

        assert_eq!(artifact.artifact_type, "source_risk_surface");
        assert_eq!(artifact.metadata["scanned_source_file_count"], 2);
        assert_eq!(artifact.metadata["scanned_json_file_count"], 1);
        assert_eq!(artifact.metadata["ai_adjacent_context"], true);
        assert_eq!(artifact.metadata["truncated"], false);
        assert_eq!(
            artifact.metadata["matched_families"],
            json!(["dynamic_execution", "network_context"])
        );
        assert_eq!(artifact.signals.len(), 2);
        assert_eq!(
            artifact.metadata["top_risky_files"][0],
            "/project/src/main.ts"
        );
    }

    #[test]
    fn scan_json_config_file_reuses_secret_engine_and_json_specific_secret_patterns() {
        let temp = tempdir().unwrap();
        let config_path = temp.path().join("agent-config.json");
        fs::write(
            &config_path,
            r#"{
  "github_token": "ghp_123456789012345678901234567890123456",
  "password": "supersecret12345",
  "database_url": "postgres://alice:swordfish@example.com/app"
}"#,
        )
        .unwrap();

        let findings = scan_json_config_file(&config_path);

        assert!(findings
            .iter()
            .any(|finding| finding.signal == "secret:github:pat"));
        assert!(findings
            .iter()
            .any(|finding| finding.signal == "json_config:credential_value"));
        assert!(findings
            .iter()
            .any(|finding| finding.signal == "json_config:credential_connection_string"));
    }

    #[test]
    fn scan_json_config_file_detects_suspicious_urls() {
        let temp = tempdir().unwrap();
        let config_path = temp.path().join("destinations.json");
        fs::write(
            &config_path,
            r#"{
  "metadata": "http://169.254.169.254/latest/meta-data/",
  "relay": "https://service.internal.example/collect",
  "collector": "https://webhook.site/abc123"
}"#,
        )
        .unwrap();

        let findings = scan_json_config_file(&config_path);

        assert!(findings
            .iter()
            .any(|finding| finding.signal == "json_config:metadata_url"));
        assert!(findings
            .iter()
            .any(|finding| finding.signal == "json_config:internal_url"));
        assert!(findings
            .iter()
            .any(|finding| finding.signal == "json_config:c2_url"));
    }

    #[test]
    fn scan_json_config_file_skips_package_json() {
        let temp = tempdir().unwrap();
        let config_path = temp.path().join("package.json");
        fs::write(
            &config_path,
            r#"{
  "collector": "https://webhook.site/abc123"
}"#,
        )
        .unwrap();

        assert!(scan_json_config_file(&config_path).is_empty());
    }
}
