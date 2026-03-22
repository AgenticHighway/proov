use std::collections::HashSet;
use std::path::PathBuf;

use crate::discovery::Candidate;
use crate::models::{
    check_for_dangerous_patterns, check_for_secrets, gather_file_primitives,
    is_content_read_allowed, ArtifactReport,
};

use super::base::Detector;
use serde_json::json;
use std::fs;

const MAX_READ_BYTES: usize = 8192;

const CONTAINER_FILENAMES: &[&str] = &[
    "Dockerfile",
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
];

const AI_RELEVANCE_TOKENS: &[&str] = &[
    "langchain",
    "autogen",
    "crewai",
    "autogpt",
    "opendevin",
    "swe-agent",
    "aider",
    "cursor",
    "copilot",
    "openai",
    "anthropic",
    "ollama",
    "huggingface",
    "replicate",
    "together.ai",
    "groq",
    "mistral",
    "llm",
    "model",
    "embedding",
    "vector",
    "rag",
    "agent",
    "ai-tool",
    "mcp",
];

pub struct ContainerDetector;

impl Detector for ContainerDetector {
    fn name(&self) -> &str {
        "containers"
    }

    fn detect(&self, candidates: &[Candidate], _deep: bool) -> Vec<ArtifactReport> {
        let ai_dirs = build_ai_dir_set(candidates);
        let mut results = Vec::new();

        for candidate in candidates {
            if let Some(report) = classify_candidate(candidate, &ai_dirs) {
                results.push(report);
            }
        }
        results
    }
}

fn build_ai_dir_set(candidates: &[Candidate]) -> HashSet<PathBuf> {
    let mut dirs = HashSet::new();
    for c in candidates {
        let name = match c.path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        let is_ai_file = name == ".cursorrules"
            || name == "agents.md"
            || name == "AGENTS.md"
            || name == "mcp.json"
            || name == "mcp_config.json";
        if is_ai_file {
            if let Some(parent) = c.path.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }
    }
    dirs
}

fn classify_candidate(
    candidate: &Candidate,
    ai_dirs: &HashSet<PathBuf>,
) -> Option<ArtifactReport> {
    let name = candidate.path.file_name()?.to_str()?;
    if !CONTAINER_FILENAMES.contains(&name) {
        return None;
    }

    let mut signals = Vec::new();
    let mut has_ai_signal = false;
    let mut metadata = serde_json::Map::new();

    // File primitives — gather once
    let file_prims = gather_file_primitives(&candidate.path);
    metadata.extend(file_prims);

    // Proximity check: container file lives alongside AI artifacts
    if let Some(parent) = candidate.path.parent() {
        if ai_dirs.contains(parent) {
            signals.push("ai_artifact_proximity".to_string());
            has_ai_signal = true;
        }
    }

    // Content scan for AI relevance tokens + container-specific primitives
    if is_content_read_allowed(&candidate.path) {
        if let Some(content) = read_head(&candidate.path) {
            let lowered = content.to_lowercase();
            let found: Vec<String> = AI_RELEVANCE_TOKENS
                .iter()
                .filter(|t| lowered.contains(**t))
                .map(|s| format!("ai_token:{s}"))
                .collect();
            if !found.is_empty() {
                has_ai_signal = true;
                signals.extend(found);
            }
            signals.extend(check_for_secrets(&content));
            signals.extend(check_for_dangerous_patterns(&content));

            // Type-specific primitives
            let is_compose = name.contains("compose");
            if is_compose {
                let services = extract_compose_services(&content);
                if !services.is_empty() {
                    metadata.insert("services".into(), json!(services));
                }
            } else {
                // Dockerfile primitives
                if let Some(base) = extract_base_image(&content) {
                    metadata.insert("base_image".into(), json!(base));
                }
                let ports = extract_exposed_ports(&content);
                if !ports.is_empty() {
                    metadata.insert("exposed_ports".into(), json!(ports));
                }
            }
        }
    }

    let (artifact_type, confidence) = if has_ai_signal {
        ("container_config", 0.8)
    } else {
        ("container_candidate", 0.4)
    };

    metadata.insert(
        "paths".into(),
        json!([candidate.path.to_string_lossy()]),
    );

    let mut report = ArtifactReport::new(artifact_type, confidence);
    report.signals = signals;
    report.metadata = metadata;
    report.artifact_scope = candidate.origin.clone();
    report.compute_hash();
    Some(report)
}

/// Extract the base image from the first FROM instruction in a Dockerfile.
fn extract_base_image(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.to_uppercase().starts_with("FROM ") {
            // FROM image:tag AS stage  →  "image:tag"
            let rest = trimmed[5..].trim();
            let image = rest.split_whitespace().next()?;
            return Some(image.to_string());
        }
    }
    None
}

/// Extract EXPOSE port numbers from a Dockerfile.
fn extract_exposed_ports(content: &str) -> Vec<String> {
    let mut ports = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.to_uppercase().starts_with("EXPOSE ") {
            for token in trimmed[7..].split_whitespace() {
                // Strip protocol suffix like 8080/tcp
                let port = token.split('/').next().unwrap_or(token);
                if port.chars().all(|c| c.is_ascii_digit()) {
                    ports.push(port.to_string());
                }
            }
        }
    }
    ports
}

/// Extract top-level service names from a compose file.
///
/// Looks for the `services:` key and collects immediate children
/// using simple indentation-based parsing (avoids a YAML dependency).
fn extract_compose_services(content: &str) -> Vec<String> {
    let mut services = Vec::new();
    let mut in_services = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Top-level key detection (no leading whitespace)
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_services = trimmed.starts_with("services:");
            continue;
        }

        if in_services {
            // Service names are at indent level 1 (2-4 spaces) and end with ':'
            let leading = line.len() - line.trim_start().len();
            if (1..=6).contains(&leading) {
                if let Some(name) = trimmed.strip_suffix(':') {
                    let name = name.trim();
                    if !name.is_empty() && !name.contains(' ') {
                        services.push(name.to_string());
                    }
                }
            }
        }
    }
    services
}

fn read_head(path: &std::path::Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let len = bytes.len().min(MAX_READ_BYTES);
    String::from_utf8(bytes[..len].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_base_image_simple() {
        let content = "FROM python:3.11-slim\nRUN pip install -r requirements.txt";
        assert_eq!(extract_base_image(content).unwrap(), "python:3.11-slim");
    }

    #[test]
    fn extract_base_image_with_as_stage() {
        let content = "FROM node:20-alpine AS builder\nWORKDIR /app";
        assert_eq!(extract_base_image(content).unwrap(), "node:20-alpine");
    }

    #[test]
    fn extract_base_image_none_without_from() {
        assert!(extract_base_image("RUN echo hello").is_none());
    }

    #[test]
    fn extract_exposed_ports_single() {
        let content = "EXPOSE 8080";
        assert_eq!(extract_exposed_ports(content), vec!["8080"]);
    }

    #[test]
    fn extract_exposed_ports_multiple() {
        let content = "EXPOSE 8080 5432/tcp 3000";
        assert_eq!(extract_exposed_ports(content), vec!["8080", "5432", "3000"]);
    }

    #[test]
    fn extract_exposed_ports_empty() {
        assert!(extract_exposed_ports("RUN echo hello").is_empty());
    }

    #[test]
    fn extract_compose_services_basic() {
        let content = "services:\n  web:\n    image: nginx\n  redis:\n    image: redis:7";
        let services = extract_compose_services(content);
        assert_eq!(services, vec!["web", "redis"]);
    }

    #[test]
    fn extract_compose_services_with_other_keys() {
        let content = "version: '3'\nservices:\n  app:\n    build: .\nnetworks:\n  default:";
        let services = extract_compose_services(content);
        assert_eq!(services, vec!["app"]);
    }

    #[test]
    fn extract_compose_services_empty() {
        assert!(extract_compose_services("version: '3'").is_empty());
    }
}
