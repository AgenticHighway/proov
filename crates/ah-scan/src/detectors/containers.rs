use std::collections::HashSet;
use std::path::PathBuf;

use crate::discovery::Candidate;
use crate::models::{
    check_for_dangerous_patterns, check_for_secrets, is_content_read_allowed, ArtifactReport,
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

    // Proximity check: container file lives alongside AI artifacts
    if let Some(parent) = candidate.path.parent() {
        if ai_dirs.contains(parent) {
            signals.push("ai_artifact_proximity".to_string());
            has_ai_signal = true;
        }
    }

    // Content scan for AI relevance tokens
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
        }
    }

    let (artifact_type, confidence) = if has_ai_signal {
        ("container_config", 0.8)
    } else {
        ("container_candidate", 0.4)
    };

    let mut metadata = serde_json::Map::new();
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

fn read_head(path: &std::path::Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let len = bytes.len().min(MAX_READ_BYTES);
    String::from_utf8(bytes[..len].to_vec()).ok()
}
