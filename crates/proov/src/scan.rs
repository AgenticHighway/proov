//! Scan orchestration — wire discovery → detectors → risk scoring → verification.
//!
//! Runs built-in detectors and custom rule-based detectors,
//! merging their results into a single report.

use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use crate::detectors::get_all_detectors;
use crate::discovery::{
    discover_file_surface, discover_filesystem_surfaces, discover_home_surfaces,
    discover_host_surfaces, discover_root_surfaces, discover_scan_surfaces,
    discover_workdir_surfaces,
};
use crate::models::{ArtifactReport, ScanReport};
use crate::risk_engine::score_artifact;
use crate::verifier::verify;

struct ScanTimings {
    enabled: bool,
}

impl ScanTimings {
    fn from_env() -> Self {
        let enabled = std::env::var("PROOV_TIMINGS")
            .ok()
            .is_some_and(|value| timing_value_enabled(&value));
        Self { enabled }
    }

    fn emit(&self, stage: &str, detail: &str, started_at: Instant) {
        if self.enabled {
            eprintln!(
                "[timing] stage={stage} elapsed_ms={} {detail}",
                started_at.elapsed().as_millis()
            );
        }
    }
}

fn timing_value_enabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Execute a full scan and return a populated [`ScanReport`].
///
/// `mode` selects the discovery strategy:
/// - `"host"` — bounded host config roots (quick scan / agentic areas)
/// - `"scan"` — tiered default scan across critical host roots and bounded user-space roots
/// - `"home"` — recursive home directory scan (legacy internal mode)
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
    let timings = ScanTimings::from_env();
    let scan_started_at = Instant::now();

    // 1. Discover candidates
    let discovery_started_at = Instant::now();
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
        "scan" => (
            discover_scan_surfaces(Some(tick)),
            "~ (default critical + user-space surfaces)".to_string(),
        ),
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
    timings.emit(
        "discovery",
        &format!("mode={mode} files={}", candidates.len()),
        discovery_started_at,
    );

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
        let detector_started_at = Instant::now();
        let before_len = artifacts.len();
        artifacts.extend(detector.detect(&candidates, deep));
        timings.emit(
            "detector",
            &format!(
                "index={}/{} name={} new_artifacts={}",
                i + 1,
                detectors.len(),
                detector.name(),
                artifacts.len() - before_len
            ),
            detector_started_at,
        );
    }

    // 3. Score, verify, classify each artifact
    tick(&format!("Analyzing {} artifact(s)…", artifacts.len()));
    let analysis_started_at = Instant::now();
    for artifact in &mut artifacts {
        score_artifact(artifact);
        verify(artifact);
        classify_artifact(artifact, mode);
    }
    timings.emit(
        "analysis",
        &format!("mode={mode} artifacts={}", artifacts.len()),
        analysis_started_at,
    );

    tick(&format!(
        "Found {} artifact(s) across {} files",
        artifacts.len(),
        candidates.len()
    ));
    timings.emit(
        "scan_total",
        &format!(
            "mode={mode} files={} artifacts={}",
            candidates.len(),
            artifacts.len()
        ),
        scan_started_at,
    );

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
    let discovery_origin = artifact.artifact_scope.clone();
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
    } else if mode == "host" || discovery_origin == "host" {
        "host".to_string()
    } else {
        "project".to_string()
    };

    // --- registry_eligible ---
    artifact.registry_eligible = match atype {
        "cursor_rules" | "agents_md" => true,
        "source_risk_surface" => false,
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
    let has_local_signal = artifact.artifact_type == "source_risk_surface"
        || artifact.signals.iter().any(|s| {
            LOCAL_ANALYSIS_SIGNALS.contains(&s.as_str())
                || s.starts_with("secret:")
                || s.starts_with("ssrf:")
                || s.starts_with("cognitive_tampering:")
        });

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
    use crate::contract::build_contract_payload;
    use serde_json::json;
    use std::path::{Path, PathBuf};

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
    fn scan_mode_preserves_host_origin_scope() {
        let mut a = artifact_at("cursor_rules", "/home/user/.cursor/rules.md");
        a.artifact_scope = "host".to_string();
        classify_artifact(&mut a, "scan");
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

    #[test]
    fn timing_value_enabled_accepts_true_like_values() {
        assert!(timing_value_enabled("1"));
        assert!(timing_value_enabled("true"));
        assert!(timing_value_enabled("YES"));
        assert!(timing_value_enabled("on"));
    }

    #[test]
    fn timing_value_enabled_rejects_other_values() {
        assert!(!timing_value_enabled("0"));
        assert!(!timing_value_enabled("false"));
        assert!(!timing_value_enabled(""));
        assert!(!timing_value_enabled("maybe"));
    }

    #[test]
    fn source_risk_surface_never_registry_eligible() {
        let mut a = artifact_at("source_risk_surface", "/project");
        classify_artifact(&mut a, "workdir");
        assert!(!a.registry_eligible);
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
    fn structured_ssrf_signal_tags_local_origin() {
        let mut a = artifact_at("prompt_config", "/project/prompt.md");
        a.signals.push("ssrf:metadata:aws".into());
        tag_analysis_origin(&mut a);
        assert_eq!(a.metadata["analysis_origin"], "local");
    }

    #[test]
    fn source_risk_surface_tags_local_origin() {
        let mut a = artifact_at("source_risk_surface", "/project");
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

    fn fixture_dir(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("docker")
            .join(name)
    }

    fn container_artifact<'a>(report: &'a ScanReport, suffix: &str) -> &'a ArtifactReport {
        report
            .artifacts
            .iter()
            .find(|artifact| {
                artifact
                    .metadata
                    .get("paths")
                    .and_then(|v| v.as_array())
                    .and_then(|paths| paths.first())
                    .and_then(|path| path.as_str())
                    .map(|path| path.ends_with(suffix))
                    .unwrap_or(false)
            })
            .expect("expected fixture artifact")
    }

    #[test]
    fn fixture_plain_docker_stays_candidate_and_not_agentic_app() {
        let fixture = fixture_dir("plain-image-definition");
        let report = run_scan("workdir", Some(&fixture), None, true, None);
        let docker = container_artifact(&report, "plain-image-definition/Dockerfile");

        assert_eq!(docker.artifact_type, "container_candidate");
        assert_eq!(docker.metadata["container_kind"], "image_definition");
        assert_eq!(docker.metadata["direct_ai_evidence"], false);
        assert_eq!(docker.metadata["direct_agentic_evidence"], false);

        let payload = build_contract_payload(&report, 0);
        assert!(payload.agentic_apps.is_empty());
    }

    #[test]
    fn fixture_direct_agentic_compose_builds_agentic_app() {
        let fixture = fixture_dir("direct-agentic-compose");
        let report = run_scan("workdir", Some(&fixture), None, true, None);
        let compose = container_artifact(&report, "direct-agentic-compose/docker-compose.yml");

        assert_eq!(compose.artifact_type, "container_config");
        assert_eq!(compose.metadata["container_kind"], "service_orchestration");
        assert_eq!(compose.metadata["direct_ai_evidence"], true);
        assert_eq!(compose.metadata["direct_agentic_evidence"], true);
        assert_eq!(compose.metadata["services"], json!(["orchestrator"]));

        let payload = build_contract_payload(&report, 0);
        assert_eq!(payload.agentic_apps.len(), 1);
        assert_eq!(payload.agentic_apps[0].agent_count, 0);
        assert!(payload.agentic_apps[0]
            .description
            .contains("Service orchestration configuration"));
    }

    #[test]
    fn fixture_colocated_agent_project_promotes_docker_candidate() {
        let fixture = fixture_dir("colocated-agent-project");
        let report = run_scan("workdir", Some(&fixture), None, true, None);
        let docker = container_artifact(&report, "colocated-agent-project/Dockerfile");

        assert_eq!(docker.artifact_type, "container_candidate");
        assert_eq!(docker.metadata["container_kind"], "image_definition");
        assert_eq!(docker.metadata["ai_artifact_proximity"], true);

        let payload = build_contract_payload(&report, 0);
        assert_eq!(payload.agents.len(), 1);
        assert_eq!(payload.agentic_apps.len(), 1);
        assert_eq!(payload.agentic_apps[0].agent_count, 1);
        assert!(payload.agentic_apps[0]
            .description
            .contains("Container image definition"));
    }
}
