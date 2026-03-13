use regex::Regex;
use serde_json::{json, Map, Value};

const TOOL_NAMES: &[&str] = &[
    "filesystem",
    "shell",
    "browser",
    "api",
    "python",
    "docker",
];

const PERMISSION_TOKENS: &[&str] = &["allow", "deny", "read", "write", "execute"];

const DEPENDENCY_NAMES: &[&str] = &["docker", "node", "python", "uv", "pip", "npm"];

pub fn extract_metadata(content: &str) -> Map<String, Value> {
    let lowered = content.to_lowercase();

    let tools: Vec<String> = TOOL_NAMES
        .iter()
        .filter(|t| lowered.contains(**t))
        .map(|s| s.to_string())
        .collect();

    let permissions: Vec<String> = PERMISSION_TOKENS
        .iter()
        .filter(|t| lowered.contains(**t))
        .map(|s| s.to_string())
        .collect();

    let re = Regex::new(r"https?://[^\s)\]}>]+").unwrap();
    let endpoints: Vec<String> = re
        .find_iter(content)
        .map(|m| m.as_str().to_string())
        .collect();

    let deps: Vec<String> = DEPENDENCY_NAMES
        .iter()
        .filter(|t| lowered.contains(**t))
        .map(|s| s.to_string())
        .collect();

    let mut map = Map::new();
    map.insert("declared_tools".into(), json!(tools));
    map.insert("permissions".into(), json!(permissions));
    map.insert("api_endpoints".into(), json!(endpoints));
    map.insert("dependencies".into(), json!(deps));
    map
}
