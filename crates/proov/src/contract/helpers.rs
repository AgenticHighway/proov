//! Shared helpers used across contract submodules.

use sha2::{Digest, Sha256};

use crate::models::ArtifactReport;

pub fn first_path(a: &ArtifactReport) -> &str {
    a.metadata
        .get("paths")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
}

/// Build a project-qualified display name from an absolute path.
///
/// E.g. `/Users/will/project/foo/agents.md` → `foo/agents`
///      `/Users/will/bar/.cursorrules`      → `bar/.cursorrules`
pub fn qualified_name(path: &str) -> String {
    let p = std::path::Path::new(path);
    let file_name = p
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    let parent_name = p
        .parent()
        .and_then(|pp| pp.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    let stem = p
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(file_name);

    // For dotfiles, keep the full filename
    if file_name.starts_with('.') {
        format!("{parent_name}/{file_name}")
    } else {
        format!("{parent_name}/{stem}")
    }
}

/// Build a deterministic ID from source path + content hash.
pub fn make_id(source_path: &str, artifact_hash: &str) -> String {
    if !artifact_hash.is_empty() {
        format!(
            "{}:{}",
            source_path,
            &artifact_hash[..12.min(artifact_hash.len())]
        )
    } else {
        format!("{}:{}", source_path, short_hash(source_path))
    }
}

pub fn short_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = format!("{:x}", hasher.finalize());
    result[..12].to_string()
}

pub fn compute_file_hash(path: &str) -> String {
    match std::fs::read(path) {
        Ok(bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            format!("{:x}", hasher.finalize())
        }
        Err(_) => String::new(),
    }
}

/// Try to find the git remote origin URL for a file path.
pub fn detect_source_repo(file_path: &str) -> String {
    let mut dir = std::path::Path::new(file_path).parent();
    while let Some(d) = dir {
        let git_config = d.join(".git").join("config");
        if git_config.exists() {
            if let Ok(content) = std::fs::read_to_string(&git_config) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("url = ") {
                        return trimmed
                            .strip_prefix("url = ")
                            .unwrap_or("unknown")
                            .to_string();
                    }
                }
            }
        }
        dir = d.parent();
    }
    "unknown".to_string()
}

/// Check if two directories share the same tool scope.
pub fn is_same_tool_scope(dir_a: &str, dir_b: &str) -> bool {
    let scope_markers = [
        ".vscode",
        ".vscode-insiders",
        ".cursor",
        ".claude",
        "Code/User",
        "Cursor/User",
    ];
    for marker in &scope_markers {
        if dir_a.contains(marker) && dir_b.contains(marker) {
            return true;
        }
    }
    false
}

pub fn declared_tools(a: &ArtifactReport) -> Vec<String> {
    a.metadata
        .get("declared_tools")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

pub fn capability_level(cap: &str) -> &'static str {
    match cap {
        "shell_execution" | "code_execution" | "container_runtime" => "danger",
        "network_access" | "external_api_calls" | "browser_access" | "secret_references" => "warn",
        _ => "info",
    }
}

pub fn humanize_capability(cap: &str) -> String {
    match cap {
        "shell_execution" => "Shell execution".to_string(),
        "browser_access" => "Browser access".to_string(),
        "external_api_calls" => "External API calls".to_string(),
        "filesystem_access" => "Filesystem read/write".to_string(),
        "network_access" => "Network access".to_string(),
        "code_execution" => "Code execution".to_string(),
        "container_runtime" => "Container runtime".to_string(),
        "system_prompt" => "System prompt control".to_string(),
        "permission_scope" => "Permission scope declarations".to_string(),
        "dependency_execution" => "Dependency execution".to_string(),
        "tool_declarations" => "Tool declarations".to_string(),
        "secret_references" => "Secret references".to_string(),
        other => other.replace('_', " "),
    }
}

const MAX_READ_BYTES: usize = 8192;

pub fn read_artifact_head(a: &ArtifactReport) -> Option<String> {
    let path_str = first_path(a);
    if path_str == "unknown" {
        return None;
    }
    let path = std::path::Path::new(path_str);
    if !crate::models::is_content_read_allowed(path) {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let len = bytes.len().min(MAX_READ_BYTES);
    String::from_utf8(bytes[..len].to_vec()).ok()
}
