use crate::discovery::Candidate;
use crate::models::{ArtifactReport, CONTENT_READ_ALLOWLIST, CONTENT_READ_GLOB_PATTERNS};
use glob::Pattern;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
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
}
