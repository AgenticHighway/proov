use crate::discovery::Candidate;
use crate::models::{check_for_secrets, ArtifactReport};

use super::base::Detector;
use serde_json::{json, Value};
use std::fs;

const MAX_READ_BYTES: usize = 8192;

const MCP_EXACT_NAMES: &[&str] = &[
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "mcp-config.json",
    "mcp_settings.json",
];

const EXECUTION_TOKENS: &[&str] = &["/bin/", "npx", "uvx", "node", "python", "deno"];
const SHELL_TOKENS: &[&str] = &["shell", "bash", "sh -c", "zsh"];

const CREDENTIAL_SIGNALS: &[&str] = &[
    "api_key",
    "apikey",
    "secret",
    "token",
    "password",
    "credential",
    "auth",
];

pub struct MCPConfigDetector;

impl Detector for MCPConfigDetector {
    fn name(&self) -> &str {
        "mcp_configs"
    }

    fn detect(&self, candidates: &[Candidate], _deep: bool) -> Vec<ArtifactReport> {
        let mut results = Vec::new();
        for candidate in candidates {
            if let Some(report) = classify_candidate(candidate) {
                results.push(report);
            }
        }
        results
    }
}

fn classify_candidate(candidate: &Candidate) -> Option<ArtifactReport> {
    let name = candidate.path.file_name()?.to_str()?;
    if !MCP_EXACT_NAMES.contains(&name) {
        return None;
    }

    let content = read_head(&candidate.path)?;
    let mut signals = Vec::new();
    let mut metadata = serde_json::Map::new();

    metadata.insert(
        "paths".into(),
        json!([candidate.path.to_string_lossy()]),
    );

    let confidence = match parse_mcp_json(&content) {
        Some(parsed) => {
            apply_parsed_signals(&parsed, &mut signals, &mut metadata);
            0.85
        }
        None => 0.75,
    };

    signals.extend(check_for_secrets(&content));

    let mut report = ArtifactReport::new("mcp_config", confidence);
    report.signals = signals;
    report.metadata = metadata;
    report.artifact_scope = candidate.origin.clone();
    report.compute_hash();
    Some(report)
}

fn parse_mcp_json(content: &str) -> Option<Value> {
    let val: Value = serde_json::from_str(content).ok()?;
    let obj = val.as_object()?;
    // Must contain mcpServers or servers
    if obj.contains_key("mcpServers") || obj.contains_key("servers") {
        Some(val)
    } else {
        None
    }
}

fn apply_parsed_signals(
    parsed: &Value,
    signals: &mut Vec<String>,
    metadata: &mut serde_json::Map<String, Value>,
) {
    let text = parsed.to_string().to_lowercase();

    let exec_found = scan_tokens(&text, EXECUTION_TOKENS);
    if !exec_found.is_empty() {
        signals.push("execution_tokens_present".to_string());
        metadata.insert("execution_tokens".into(), json!(exec_found));
    }

    let shell_found = scan_tokens(&text, SHELL_TOKENS);
    if !shell_found.is_empty() {
        signals.push("shell_access_detected".to_string());
        metadata.insert("shell_tokens".into(), json!(shell_found));
    }

    let endpoints = extract_endpoints(&parsed.to_string());
    if !endpoints.is_empty() {
        metadata.insert("api_endpoints".into(), json!(endpoints));
    }

    let cred_found = scan_tokens(&text, CREDENTIAL_SIGNALS);
    if !cred_found.is_empty() {
        signals.push("credential_references".to_string());
    }

    let server_count = count_servers(parsed);
    metadata.insert("server_count".into(), json!(server_count));
}

fn scan_tokens(text: &str, tokens: &[&str]) -> Vec<String> {
    tokens
        .iter()
        .filter(|t| text.contains(**t))
        .map(|s| s.to_string())
        .collect()
}

fn extract_endpoints(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r#"https?://[^\s"'\\,\]}>]+"#).unwrap();
    re.find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

fn count_servers(val: &Value) -> usize {
    let servers_obj = val
        .get("mcpServers")
        .or_else(|| val.get("servers"))
        .and_then(|v| v.as_object());
    servers_obj.map_or(0, |m| m.len())
}

fn read_head(path: &std::path::Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let len = bytes.len().min(MAX_READ_BYTES);
    String::from_utf8(bytes[..len].to_vec()).ok()
}
