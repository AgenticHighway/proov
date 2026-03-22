//! Prompt building for the AH-Verify contract.

use crate::capabilities::derive_capabilities;
use crate::models::ArtifactReport;

use super::helpers::{
    capability_level, compute_file_hash, first_path, humanize_capability, make_id, qualified_name,
    read_artifact_head,
};
use super::types::{InjectionSurface, Prompt, PromptCapability, SecretRef};

pub fn build_prompts(artifacts: &[&ArtifactReport]) -> Vec<Prompt> {
    artifacts.iter().map(|a| artifact_to_prompt(a)).collect()
}

fn artifact_to_prompt(a: &ArtifactReport) -> Prompt {
    let source_path = first_path(a).to_string();
    let name = qualified_name(&source_path);
    let id = make_id(&source_path, &a.artifact_hash);

    let classification = match a.artifact_type.as_str() {
        "cursor_rules" | "agents_md" => "System Prompt",
        _ => "User Prompt",
    };

    let tokens = resolve_tokens(a, &source_path);
    let content_hash = resolve_content_hash(a, &source_path);
    let last_changed_date = resolve_last_changed(a, &source_path);

    let capabilities = derive_capabilities(a)
        .into_iter()
        .map(|cap| {
            let level = capability_level(&cap);
            PromptCapability {
                text: humanize_capability(&cap),
                level: level.to_string(),
            }
        })
        .collect();

    let dependencies = a
        .metadata
        .get("dependencies")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Prompt {
        id,
        name,
        source_file_path: source_path,
        classification: classification.to_string(),
        tokens,
        content_hash,
        last_changed_date,
        capabilities,
        secret_refs: build_secret_refs(a),
        injection_surfaces: build_injection_surfaces(a),
        dependencies,
        risk_score: a.risk_score.clamp(0, 100),
    }
}

fn resolve_tokens(a: &ArtifactReport, source_path: &str) -> u64 {
    a.metadata
        .get("file_size_bytes")
        .and_then(|v| v.as_u64())
        .map(|size| size / 4)
        .unwrap_or_else(|| {
            std::fs::metadata(source_path)
                .ok()
                .map(|m| m.len() / 4)
                .unwrap_or(0)
        })
}

fn resolve_content_hash(a: &ArtifactReport, source_path: &str) -> String {
    a.metadata
        .get("content_hash")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| compute_file_hash(source_path))
}

fn resolve_last_changed(a: &ArtifactReport, source_path: &str) -> String {
    a.metadata
        .get("last_modified")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| {
            std::fs::metadata(source_path)
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.format("%Y-%m-%d").to_string()
                })
                .unwrap_or_else(|| "1970-01-01".to_string())
        })
}

fn build_secret_refs(a: &ArtifactReport) -> Vec<SecretRef> {
    let mut refs = Vec::new();
    for signal in &a.signals {
        if signal == "credential_exposure_signal" {
            refs.push(SecretRef {
                label: "Credential reference detected".to_string(),
                detail: "Redacted — matched known secret pattern".to_string(),
                tone: "danger".to_string(),
            });
        }
    }

    if let Some(content) = read_artifact_head(a) {
        for pattern in &["$", "process.env.", "os.environ"] {
            if content.contains(pattern) {
                let already_dangerous = refs.iter().any(|r| r.tone == "danger");
                if !already_dangerous {
                    refs.push(SecretRef {
                        label: "Env var reference (safe)".to_string(),
                        detail: format!("References environment variable via {pattern}"),
                        tone: "safe".to_string(),
                    });
                    break;
                }
            }
        }
    }
    refs
}

fn build_injection_surfaces(a: &ArtifactReport) -> Vec<InjectionSurface> {
    let mut surfaces = Vec::new();
    for signal in &a.signals {
        if signal.starts_with("dangerous_keyword:") {
            let keyword = signal.strip_prefix("dangerous_keyword:").unwrap_or(signal);
            surfaces.push(InjectionSurface {
                text: format!("Dangerous instruction keyword: {keyword}"),
                severity: "high".to_string(),
            });
        }
        if signal == "dangerous_combo:shell+network+fs" {
            surfaces.push(InjectionSurface {
                text: "Combined shell + network + filesystem access pattern".to_string(),
                severity: "high".to_string(),
            });
        }
    }

    if let Some(content) = read_artifact_head(a) {
        let lowered = content.to_lowercase();
        if lowered.contains("{{") || lowered.contains("{%") || lowered.contains("${") {
            surfaces.push(InjectionSurface {
                text: "Template interpolation detected — potential injection surface".to_string(),
                severity: "medium".to_string(),
            });
        }
        if lowered.contains("user_input") || lowered.contains("user_message") {
            surfaces.push(InjectionSurface {
                text: "Direct user input reference in prompt body".to_string(),
                severity: "medium".to_string(),
            });
        }
    }
    surfaces
}
