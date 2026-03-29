//! Scan orchestration — wire discovery → detectors → risk scoring → verification.
//!
//! Runs built-in detectors and custom rule-based detectors,
//! merging their results into a single report.

use std::collections::HashSet;
use std::path::Path;

use crate::detectors::get_all_detectors;
use crate::discovery::{
    discover_file_surface, discover_filesystem_surfaces, discover_home_surfaces,
    discover_host_surfaces, discover_root_surfaces, discover_workdir_surfaces,
};
use crate::models::{ArtifactReport, ScanReport};
use crate::risk_engine::score_artifact;
use crate::verifier::verify;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Execute a full scan and return a populated [`ScanReport`].
///
/// `mode` selects the discovery strategy:
/// - `"host"` — bounded host config roots (quick scan / agentic areas)
/// - `"home"` — recursive home directory scan (default)
/// - `"filesystem"` — full home + system app paths (legacy)
/// - `"root"` — entire filesystem from / (full scan)
/// - `"workdir"` — explicit project directory
/// - `"file"` — single file
pub fn run_scan(
    mode: &str,
    workdir: Option<&Path>,
    file: Option<&Path>,
    deep: bool,
    on_tick: Option<&dyn Fn(&str)>,
) -> ScanReport {
    let noop = |_: &str| {};
    let tick: &dyn Fn(&str) = on_tick.unwrap_or(&noop);

    // 1. Discover candidates
    let (candidates, scanned_path) = match mode {
        "file" => {
            let p = file.expect("file path is required for file mode");
            let resolved = p
                .canonicalize()
                .unwrap_or_else(|_| p.to_path_buf())
                .display()
                .to_string();
            (discover_file_surface(p), resolved)
        }
        "workdir" => {
            let p = workdir.expect("workdir path is required for workdir mode");
            let resolved = p
                .canonicalize()
                .unwrap_or_else(|_| p.to_path_buf())
                .display()
                .to_string();
            (discover_workdir_surfaces(p, deep, Some(tick)), resolved)
        }
        "filesystem" => (
            discover_filesystem_surfaces(Some(tick)),
            "/ (full filesystem)".to_string(),
        ),
        "home" => (
            discover_home_surfaces(Some(tick)),
            "~ (home directory)".to_string(),
        ),
        "root" => (
            discover_root_surfaces(Some(tick)),
            "/ (full filesystem)".to_string(),
        ),
        _ => (discover_host_surfaces(Some(tick)), "~".to_string()),
    };

    // 2. Run built-in (native) detectors
    tick(&format!("Scanning {} files…", candidates.len()));
    let detectors = get_all_detectors(mode);
    let mut artifacts: Vec<ArtifactReport> = Vec::new();
    for (i, detector) in detectors.iter().enumerate() {
        tick(&format!(
            "detector {}/{}: {}",
            i + 1,
            detectors.len(),
            detector.name()
        ));
        artifacts.extend(detector.detect(&candidates, deep));
    }

    // 3. Score, verify, classify each artifact
    tick(&format!("Analyzing {} artifact(s)…", artifacts.len()));
    for artifact in &mut artifacts {
        score_artifact(artifact);
        verify(artifact);
        classify_artifact(artifact, mode);
    }

    tick(&format!(
        "Found {} artifact(s) across {} files",
        artifacts.len(),
        candidates.len()
    ));

    let mut report = ScanReport::new(&scanned_path);
    report.artifacts = artifacts;
    report
}

// ---------------------------------------------------------------------------
// Post-detection classification
// ---------------------------------------------------------------------------

const DOCS_PATH_SEGMENTS: &[&str] = &[
    "docs",
    "doc",
    "documentation",
    "reference",
    "concepts",
    "examples",
];

fn classify_artifact(artifact: &mut ArtifactReport, mode: &str) {
    let atype = artifact.artifact_type.as_str();
    let first_path = artifact
        .metadata
        .get("paths")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();

    let path_parts: HashSet<&str> = Path::new(&first_path)
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();

    // --- artifact_scope ---
    artifact.artifact_scope = if atype == "browser_footprint" {
        "host".to_string()
    } else if atype == "container_config" || atype == "container_candidate" {
        "container".to_string()
    } else if DOCS_PATH_SEGMENTS
        .iter()
        .any(|seg| path_parts.contains(seg))
    {
        "docs".to_string()
    } else if mode == "host" {
        "host".to_string()
    } else {
        "project".to_string()
    };

    // --- registry_eligible ---
    artifact.registry_eligible = match atype {
        "cursor_rules" | "agents_md" => true,
        "container_candidate" => false,
        "prompt_config" if artifact.artifact_scope == "docs" => false,
        "prompt_config" => {
            let has_keywords = artifact.signals.iter().any(|s| s.starts_with("keyword:"));
            has_keywords || artifact.confidence >= 0.85
        }
        "container_config" => true,
        _ => artifact.confidence >= 0.6,
    };

    tag_analysis_origin(artifact);
}

// ---------------------------------------------------------------------------
// Analysis-origin tagging
// ---------------------------------------------------------------------------

const LOCAL_ANALYSIS_SIGNALS: &[&str] = &[
    "credential_exposure_signal",
    "dangerous_combo:shell+network+fs",
    "dangerous_keyword:exfiltrate",
    "dangerous_keyword:reverse",
    "dangerous_keyword:steal",
    "dangerous_keyword:wipe",
    "dangerous_keyword:bypass",
    "keyword:shell",
    "keyword:browser",
    "keyword:api",
    "keyword:execute",
    "keyword:network",
    "keyword:filesystem",
];

fn tag_analysis_origin(artifact: &mut ArtifactReport) {
    let has_local_signal = artifact
        .signals
        .iter()
        .any(|s| LOCAL_ANALYSIS_SIGNALS.contains(&s.as_str()));

    let origin = if has_local_signal || artifact.verification_status == "fail" {
        "local"
    } else {
        "server_candidate"
    };

    artifact.metadata.insert(
        "analysis_origin".to_string(),
        serde_json::Value::String(origin.to_string()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn artifact_at(atype: &str, path: &str) -> ArtifactReport {
        let mut a = ArtifactReport::new(atype, 0.8);
        a.metadata.insert("paths".into(), json!([path]));
        a
    }

    // --- classify_artifact: scope ---

    #[test]
    fn browser_footprint_scope_is_host() {
        let mut a = artifact_at("browser_footprint", "/home/user/.config/chrome");
        classify_artifact(&mut a, "home");
        assert_eq!(a.artifact_scope, "host");
    }

    #[test]
    fn container_scope_is_container() {
        let mut a = artifact_at("container_config", "/project/Dockerfile");
        classify_artifact(&mut a, "workdir");
        assert_eq!(a.artifact_scope, "container");
    }

    #[test]
    fn container_candidate_scope_is_container() {
        let mut a = artifact_at("container_candidate", "/project/Dockerfile");
        classify_artifact(&mut a, "workdir");
        assert_eq!(a.artifact_scope, "container");
    }

    #[test]
    fn docs_path_produces_docs_scope() {
        let mut a = artifact_at("cursor_rules", "/project/docs/.cursorrules");
        classify_artifact(&mut a, "workdir");
        assert_eq!(a.artifact_scope, "docs");
    }

    #[test]
    fn host_mode_produces_host_scope() {
        let mut a = artifact_at("cursor_rules", "/home/user/.cursorrules");
        classify_artifact(&mut a, "host");
        assert_eq!(a.artifact_scope, "host");
    }

    #[test]
    fn workdir_mode_produces_project_scope() {
        let mut a = artifact_at("cursor_rules", "/project/.cursorrules");
        classify_artifact(&mut a, "workdir");
        assert_eq!(a.artifact_scope, "project");
    }

    // --- classify_artifact: registry_eligible ---

    #[test]
    fn cursor_rules_always_eligible() {
        let mut a = artifact_at("cursor_rules", "/project/.cursorrules");
        classify_artifact(&mut a, "workdir");
        assert!(a.registry_eligible);
    }

    #[test]
    fn container_candidate_never_eligible() {
        let mut a = artifact_at("container_candidate", "/project/Dockerfile");
        classify_artifact(&mut a, "workdir");
        assert!(!a.registry_eligible);
    }

    #[test]
    fn prompt_config_in_docs_not_eligible() {
        let mut a = artifact_at("prompt_config", "/project/docs/prompt.md");
        classify_artifact(&mut a, "workdir");
        assert!(!a.registry_eligible);
    }

    #[test]
    fn prompt_config_with_keywords_eligible() {
        let mut a = artifact_at("prompt_config", "/project/prompt.md");
        a.signals.push("keyword:shell".into());
        classify_artifact(&mut a, "workdir");
        assert!(a.registry_eligible);
    }

    #[test]
    fn prompt_config_high_confidence_eligible() {
        let mut a = ArtifactReport::new("prompt_config", 0.90);
        a.metadata
            .insert("paths".into(), json!(["/project/prompt.md"]));
        classify_artifact(&mut a, "workdir");
        assert!(a.registry_eligible);
    }

    // --- tag_analysis_origin ---

    #[test]
    fn local_signal_tags_local_origin() {
        let mut a = artifact_at("cursor_rules", "/project/.cursorrules");
        a.signals.push("keyword:shell".into());
        tag_analysis_origin(&mut a);
        assert_eq!(a.metadata["analysis_origin"], "local");
    }

    #[test]
    fn no_local_signal_tags_server_candidate() {
        let mut a = artifact_at("cursor_rules", "/project/.cursorrules");
        a.signals.push("filename_match:.cursorrules".into());
        tag_analysis_origin(&mut a);
        assert_eq!(a.metadata["analysis_origin"], "server_candidate");
    }

    #[test]
    fn failed_verification_tags_local_origin() {
        let mut a = artifact_at("cursor_rules", "/project/.cursorrules");
        a.verification_status = "fail".into();
        tag_analysis_origin(&mut a);
        assert_eq!(a.metadata["analysis_origin"], "local");
    }
}
