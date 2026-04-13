//! Bounded source-risk detector.
//!
//! This detector emits one aggregated `source_risk_surface` artifact for
//! selected source files and JSON configs in file/workdir scans. Follow-on
//! issues can add more heuristic families without changing the artifact shape.

use crate::discovery::Candidate;
use crate::models::ArtifactReport;
use crate::source_analysis::{
    build_source_risk_surface, common_root, has_ai_adjacent_candidate, is_scannable_json_file,
    is_supported_source_file, scan_json_config_file, MAX_SOURCE_SURFACE_FILES,
};

use super::base::Detector;

pub struct SourceRiskDetector {
    mode: String,
}

impl SourceRiskDetector {
    pub fn new(mode: &str) -> Self {
        Self {
            mode: mode.to_string(),
        }
    }
}

impl Detector for SourceRiskDetector {
    fn name(&self) -> &str {
        "source_risks"
    }

    fn detect(&self, candidates: &[Candidate], _deep: bool) -> Vec<ArtifactReport> {
        let supported: Vec<&Candidate> = candidates
            .iter()
            .filter(|candidate| {
                is_supported_source_file(&candidate.path) || is_scannable_json_file(&candidate.path)
            })
            .take(MAX_SOURCE_SURFACE_FILES)
            .collect();

        if supported.is_empty() {
            return Vec::new();
        }

        let explicit_file_scan = self.mode == "file";
        let ai_adjacent = has_ai_adjacent_candidate(candidates);
        if !explicit_file_scan && !ai_adjacent {
            return Vec::new();
        }

        let source_count = supported
            .iter()
            .filter(|candidate| is_supported_source_file(&candidate.path))
            .count();
        let json_count = supported
            .iter()
            .filter(|candidate| is_scannable_json_file(&candidate.path))
            .count();
        let truncated = supported.len() == MAX_SOURCE_SURFACE_FILES
            && candidates.iter().any(|candidate| {
                is_supported_source_file(&candidate.path) || is_scannable_json_file(&candidate.path)
            });

        let findings = supported
            .iter()
            .filter(|candidate| is_scannable_json_file(&candidate.path))
            .flat_map(|candidate| scan_json_config_file(&candidate.path))
            .collect::<Vec<_>>();

        let supported_paths = supported
            .iter()
            .map(|candidate| candidate.path.clone())
            .collect::<Vec<_>>();
        let root = if explicit_file_scan {
            supported_paths[0].clone()
        } else {
            common_root(&supported_paths)
                .or_else(|| {
                    supported_paths
                        .first()
                        .and_then(|path| path.parent().map(|p| p.to_path_buf()))
                })
                .unwrap_or_else(|| supported_paths[0].clone())
        };

        vec![build_source_risk_surface(
            &root,
            source_count,
            json_count,
            &findings,
            ai_adjacent,
            truncated,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn candidate(path: &str) -> Candidate {
        Candidate {
            path: PathBuf::from(path),
            origin: "workdir".to_string(),
        }
    }

    #[test]
    fn workdir_ai_adjacent_source_files_emit_surface_artifact() {
        let detector = SourceRiskDetector::new("workdir");
        let reports = detector.detect(
            &[
                candidate("/project/AGENTS.md"),
                candidate("/project/src/main.ts"),
                candidate("/project/config/app.json"),
            ],
            false,
        );

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].artifact_type, "source_risk_surface");
        assert_eq!(reports[0].metadata["scanned_source_file_count"], 1);
        assert_eq!(reports[0].metadata["scanned_json_file_count"], 1);
        assert_eq!(reports[0].metadata["ai_adjacent_context"], true);
    }

    #[test]
    fn workdir_without_ai_adjacency_does_not_emit_surface_artifact() {
        let detector = SourceRiskDetector::new("workdir");
        let reports = detector.detect(&[candidate("/project/src/main.ts")], false);
        assert!(reports.is_empty());
    }

    #[test]
    fn file_mode_supported_source_file_emits_surface_artifact() {
        let detector = SourceRiskDetector::new("file");
        let reports = detector.detect(&[candidate("/project/src/main.ts")], false);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].metadata["scanned_source_file_count"], 1);
        assert_eq!(reports[0].metadata["ai_adjacent_context"], false);
    }

    #[test]
    fn file_mode_json_findings_flow_into_surface_artifact() {
        let temp = tempdir().unwrap();
        let config_path = temp.path().join("agent-config.json");
        fs::write(
            &config_path,
            r#"{
  "password": "supersecret12345",
  "collector": "https://webhook.site/abc123"
}"#,
        )
        .unwrap();

        let detector = SourceRiskDetector::new("file");
        let reports = detector.detect(
            &[Candidate {
                path: config_path,
                origin: "workdir".to_string(),
            }],
            false,
        );

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].metadata["scanned_json_file_count"], 1);
        assert!(reports[0]
            .signals
            .contains(&"json_config:credential_value".to_string()));
        assert!(reports[0]
            .signals
            .contains(&"json_config:c2_url".to_string()));
    }

    #[test]
    fn workdir_skips_noisy_package_json() {
        let temp = tempdir().unwrap();
        let package_path = temp.path().join("package.json");
        let agents_path = temp.path().join("AGENTS.md");
        fs::write(
            &package_path,
            r#"{
  "collector": "https://webhook.site/abc123"
}"#,
        )
        .unwrap();
        fs::write(&agents_path, "system prompt").unwrap();

        let detector = SourceRiskDetector::new("workdir");
        let reports = detector.detect(
            &[
                Candidate {
                    path: agents_path,
                    origin: "workdir".to_string(),
                },
                Candidate {
                    path: package_path,
                    origin: "workdir".to_string(),
                },
            ],
            false,
        );

        assert!(reports.is_empty());
    }
}
