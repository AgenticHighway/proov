//! Transforms a [`ScanReport`] into the AH-Verify Scanner Data Contract (v2).
//!
//! The contract defines the exact payload shape the ingestion endpoint
//! expects:  `scanMeta`, `prompts`, `skills`, `mcpServers`, `agents`,
//! and `agenticApps`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capabilities::derive_capabilities;
use crate::models::{ArtifactReport, ScanReport};
use crate::network_evidence::{self, EnvVarRef, HostNetworkInfo, NetworkEvidence};

// ═══════════════════════════════════════════════════════════════════════════
// Top-level payload
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractPayload {
    pub scan_meta: ScanMeta,
    pub prompts: Vec<Prompt>,
    pub skills: Vec<Skill>,
    pub mcp_servers: Vec<McpServer>,
    pub agents: Vec<Agent>,
    pub agentic_apps: Vec<AgenticApp>,
}

// ═══════════════════════════════════════════════════════════════════════════
// scanMeta
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanMeta {
    pub scan_id: String,
    pub endpoint_hostname: String,
    pub scanned_at: String,
    pub scanner_version: String,
    pub scan_duration_ms: u64,
    pub scan_roots: Vec<String>,
    pub host_network: HostNetworkInfo,
}

// ═══════════════════════════════════════════════════════════════════════════
// prompts
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Prompt {
    pub id: String,
    pub name: String,
    pub source_file_path: String,
    pub classification: String,
    pub tokens: u64,
    pub content_hash: String,
    pub last_changed_date: String,
    pub capabilities: Vec<PromptCapability>,
    pub secret_refs: Vec<SecretRef>,
    pub injection_surfaces: Vec<InjectionSurface>,
    pub dependencies: Vec<String>,
    pub risk_score: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptCapability {
    pub text: String,
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRef {
    pub label: String,
    pub detail: String,
    pub tone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionSurface {
    pub text: String,
    pub severity: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// skills
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Skill {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub skill_type: String,
    pub trust_level: String,
    pub execution_environment: String,
    pub description: String,
    pub permissions: Vec<SkillPermission>,
    pub dependencies: SkillDependencies,
    pub consumers: Vec<SkillConsumer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillPermission {
    pub name: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDependencies {
    pub libraries: Vec<String>,
    pub binaries: Vec<String>,
    pub apis: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillConsumer {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub consumer_type: String,
    pub invocations: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// mcpServers
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServer {
    pub id: String,
    pub name: String,
    pub transport: String,
    pub network: String,
    pub auth: String,
    pub verified: bool,
    pub command: String,
    pub tools: Vec<McpTool>,
    pub dependent_agents: Vec<String>,
    pub network_evidence: Vec<NetworkEvidence>,
    pub env_vars: Vec<EnvVarRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub risk: String,
    pub description: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// agents
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub source_file_path: String,
    pub classification: String,
    pub execution_model: String,
    pub trust_score: i32,
    pub version: String,
    pub author: String,
    pub source_repo: String,
    pub capabilities: Vec<AgentCapability>,
    pub tools: Vec<AgentTool>,
    pub trust_breakdown: Vec<TrustFactor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapability {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTool {
    pub name: String,
    #[serde(rename = "type")]
    pub tool_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFactor {
    pub label: String,
    pub delta: i32,
}

// ═══════════════════════════════════════════════════════════════════════════
// agenticApps
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgenticApp {
    pub id: String,
    pub name: String,
    pub source_file_path: String,
    pub framework: String,
    pub agent_count: u32,
    pub risk: String,
    pub review_status: String,
    pub description: String,
    pub agents: Vec<AppAgent>,
    pub tools_by_agent: Vec<Vec<String>>,
    pub workflow: Vec<WorkflowStep>,
    pub integrations: Vec<Integration>,
    pub verification_checks: Vec<String>,
    pub risk_tags: Vec<String>,
    pub risk_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAgent {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub step: u32,
    pub agent: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integration {
    pub name: String,
    #[serde(rename = "type")]
    pub integration_type: String,
    pub risk: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Builder — transform ScanReport → ContractPayload (v2)
// ═══════════════════════════════════════════════════════════════════════════

pub fn build_contract_payload(report: &ScanReport, scan_duration_ms: u64) -> ContractPayload {
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    let host_network = network_evidence::gather_host_network();

    let scan_meta = ScanMeta {
        scan_id: uuid::Uuid::new_v4().to_string(),
        endpoint_hostname: hostname,
        scanned_at: report.timestamp.clone(),
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        scan_duration_ms,
        scan_roots: vec![report.scanned_path.clone()],
        host_network,
    };

    // Partition artifacts by type
    let mut prompt_artifacts: Vec<&ArtifactReport> = Vec::new();
    let mut mcp_artifacts: Vec<&ArtifactReport> = Vec::new();
    let mut container_artifacts: Vec<&ArtifactReport> = Vec::new();
    let mut agent_artifacts: Vec<&ArtifactReport> = Vec::new();

    for artifact in &report.artifacts {
        match artifact.artifact_type.as_str() {
            "cursor_rules" | "prompt_config" => prompt_artifacts.push(artifact),
            "agents_md" => {
                prompt_artifacts.push(artifact);
                agent_artifacts.push(artifact);
            }
            "mcp_config" => mcp_artifacts.push(artifact),
            "container_config" | "container_candidate" => container_artifacts.push(artifact),
            _ => {}
        }
    }

    let prompts = build_prompts(&prompt_artifacts);
    let agents = build_agents(&agent_artifacts, &mcp_artifacts);
    let skills = build_skills(&report.artifacts, &agents);
    let agentic_apps = build_agentic_apps(&container_artifacts, &agents);

    // Cross-link MCP server dependentAgents using agent IDs
    let agent_ids_by_mcp: std::collections::HashMap<String, Vec<String>> = {
        let mut map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for agent in &agents {
            for tool in &agent.tools {
                if tool.tool_type == "mcp" {
                    map.entry(tool.name.clone())
                        .or_default()
                        .push(agent.id.clone());
                }
            }
        }
        map
    };

    // We need to rebuild mcp_servers with the cross-links (deduplicated)
    let mcp_servers_linked: Vec<McpServer> = {
        let mut servers = build_mcp_servers(&mcp_artifacts);
        for server in &mut servers {
            if let Some(ids) = agent_ids_by_mcp.get(&server.name) {
                let mut unique_ids: Vec<String> = Vec::new();
                let mut seen = std::collections::HashSet::new();
                for id in ids {
                    if seen.insert(id.clone()) {
                        unique_ids.push(id.clone());
                    }
                }
                server.dependent_agents = unique_ids;
            }
        }
        servers
    };

    ContractPayload {
        scan_meta,
        prompts,
        skills,
        mcp_servers: mcp_servers_linked,
        agents,
        agentic_apps,
    }
}

// ─── prompts ────────────────────────────────────────────────────────────

fn build_prompts(artifacts: &[&ArtifactReport]) -> Vec<Prompt> {
    artifacts.iter().map(|a| artifact_to_prompt(a)).collect()
}

fn artifact_to_prompt(a: &ArtifactReport) -> Prompt {
    let source_path = first_path(a).to_string();
    let name = qualified_name(&source_path);
    let id = make_id(&source_path, &a.artifact_hash);

    let classification = match a.artifact_type.as_str() {
        "cursor_rules" => "System Prompt",
        "agents_md" => "System Prompt",
        _ => "User Prompt",
    };

    // Prefer file primitives from detection (avoids re-reading the file)
    let tokens = a
        .metadata
        .get("file_size_bytes")
        .and_then(|v| v.as_u64())
        .map(|size| size / 4)
        .unwrap_or_else(|| {
            std::fs::metadata(&source_path)
                .ok()
                .map(|m| m.len() / 4)
                .unwrap_or(0)
        });

    let content_hash = a
        .metadata
        .get("content_hash")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| compute_file_hash(&source_path));

    let last_changed_date = a
        .metadata
        .get("last_modified")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| {
            std::fs::metadata(&source_path)
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.format("%Y-%m-%d").to_string()
                })
                .unwrap_or_else(|| "1970-01-01".to_string())
        });

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

    let secret_refs = build_secret_refs(a);
    let injection_surfaces = build_injection_surfaces(a);

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
        secret_refs,
        injection_surfaces,
        dependencies,
        risk_score: a.risk_score.clamp(0, 100),
    }
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

// ─── skills ─────────────────────────────────────────────────────────────

fn build_skills(artifacts: &[ArtifactReport], agents: &[Agent]) -> Vec<Skill> {
    let mut seen = std::collections::HashSet::new();
    let mut skills = Vec::new();

    for artifact in artifacts {
        let tools = declared_tools(artifact);
        for tool in tools {
            if seen.insert(tool.clone()) {
                skills.push(tool_to_skill(&tool, artifact, agents));
            }
        }
    }

    // Add skills from MCP server tool commands
    for artifact in artifacts.iter().filter(|a| a.artifact_type == "mcp_config") {
        if let Some(content) = read_artifact_head(artifact) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                let servers = val
                    .get("mcpServers")
                    .or_else(|| val.get("servers"))
                    .and_then(|v| v.as_object());
                if let Some(servers) = servers {
                    for (_server_name, server_val) in servers {
                        if let Some(cmd) = server_val.get("command").and_then(|v| v.as_str()) {
                            let skill_name = cmd
                                .split('/')
                                .next_back()
                                .unwrap_or(cmd)
                                .to_string();
                            if seen.insert(skill_name.clone()) {
                                let args_str = server_val
                                    .get("args")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|v| v.as_str())
                                            .collect::<Vec<_>>()
                                            .join(" ")
                                    })
                                    .unwrap_or_default();
                                let full_cmd = if args_str.is_empty() {
                                    cmd.to_string()
                                } else {
                                    format!("{cmd} {args_str}")
                                };
                                skills.push(Skill {
                                    id: skill_name.clone(),
                                    name: skill_name.clone(),
                                    skill_type: "CLI Tool".to_string(),
                                    trust_level: "Conditional".to_string(),
                                    execution_environment: "Local Process".to_string(),
                                    description: format!(
                                        "Executes MCP server via: {full_cmd}"
                                    ),
                                    permissions: vec![SkillPermission {
                                        name: "Shell execution".to_string(),
                                        required: true,
                                    }],
                                    dependencies: SkillDependencies {
                                        libraries: Vec::new(),
                                        binaries: vec![cmd.to_string()],
                                        apis: Vec::new(),
                                    },
                                    consumers: find_skill_consumers(&skill_name, agents),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    skills
}

fn tool_to_skill(tool_name: &str, artifact: &ArtifactReport, agents: &[Agent]) -> Skill {
    let (skill_type, exec_env) = match tool_name {
        "shell" | "bash" => ("CLI Tool", "Local Process"),
        "browser" => ("HTTP Integration", "Remote API"),
        "api" => ("HTTP Integration", "Remote API"),
        "docker" => ("CLI Tool", "Container"),
        "python" | "node" => ("CLI Tool", "Local Process"),
        "filesystem" => ("Local Function", "Local Process"),
        _ => ("Local Function", "Local Process"),
    };

    let trust_level = if artifact.risk_score >= 70 {
        "Untrusted"
    } else if artifact.risk_score >= 40 {
        "Conditional"
    } else {
        "Trusted"
    };

    let permissions = infer_permissions(tool_name);

    let binaries: Vec<String> = match tool_name {
        "shell" | "bash" => vec!["bash".to_string()],
        "python" => vec!["python".to_string()],
        "node" => vec!["node".to_string()],
        "docker" => vec!["docker".to_string()],
        _ => Vec::new(),
    };

    let description = skill_description(tool_name);

    Skill {
        id: tool_name.to_string(),
        name: tool_name.to_string(),
        skill_type: skill_type.to_string(),
        trust_level: trust_level.to_string(),
        execution_environment: exec_env.to_string(),
        description,
        permissions,
        dependencies: SkillDependencies {
            libraries: Vec::new(),
            binaries,
            apis: Vec::new(),
        },
        consumers: find_skill_consumers(tool_name, agents),
    }
}

fn skill_description(tool_name: &str) -> String {
    match tool_name {
        "shell" | "bash" => {
            "Executes shell commands via local bash interpreter with unrestricted system access"
                .to_string()
        }
        "python" => {
            "Executes Python scripts via local interpreter with unrestricted filesystem access"
                .to_string()
        }
        "node" => {
            "Executes Node.js scripts via local runtime with unrestricted filesystem access"
                .to_string()
        }
        "filesystem" => {
            "Reads and writes files on the local filesystem".to_string()
        }
        "browser" => {
            "Controls a browser instance for web navigation and interaction".to_string()
        }
        "api" => {
            "Makes HTTP requests to external API services".to_string()
        }
        "docker" => {
            "Manages Docker containers and images via the Docker CLI".to_string()
        }
        other => format!("Provides {other} functionality", other = other.replace('_', " ")),
    }
}

fn infer_permissions(tool_name: &str) -> Vec<SkillPermission> {
    let mut perms = Vec::new();
    match tool_name {
        "shell" | "bash" => {
            perms.push(SkillPermission { name: "Shell execution".to_string(), required: true });
            perms.push(SkillPermission { name: "Filesystem read/write".to_string(), required: true });
        }
        "filesystem" => {
            perms.push(SkillPermission { name: "Filesystem read/write".to_string(), required: true });
        }
        "browser" | "api" => {
            perms.push(SkillPermission { name: "Network access".to_string(), required: true });
        }
        "docker" => {
            perms.push(SkillPermission { name: "Shell execution".to_string(), required: true });
            perms.push(SkillPermission { name: "Network access".to_string(), required: true });
        }
        "python" | "node" => {
            perms.push(SkillPermission { name: "Shell execution".to_string(), required: true });
        }
        _ => {}
    }
    perms
}

fn find_skill_consumers(tool_name: &str, agents: &[Agent]) -> Vec<SkillConsumer> {
    agents
        .iter()
        .filter(|agent| agent.tools.iter().any(|t| t.name == tool_name))
        .map(|agent| SkillConsumer {
            id: agent.id.clone(),
            name: agent.name.clone(),
            consumer_type: "Agent".to_string(),
            invocations: 0,
        })
        .collect()
}

// ─── mcpServers ─────────────────────────────────────────────────────────

fn build_mcp_servers(artifacts: &[&ArtifactReport]) -> Vec<McpServer> {
    let mut servers = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    for artifact in artifacts {
        let content = match read_artifact_head(artifact) {
            Some(c) => c,
            None => continue,
        };
        let val: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let servers_obj = val
            .get("mcpServers")
            .or_else(|| val.get("servers"))
            .and_then(|v| v.as_object());

        let server_map = match servers_obj {
            Some(m) => m,
            None => continue,
        };

        for (name, server_val) in server_map {
            // Deduplicate MCP servers by name — keep the first occurrence
            if seen_names.insert(name.clone()) {
                servers.push(mcp_entry_to_server(name, server_val, artifact));
            }
        }
    }

    servers
}

fn mcp_entry_to_server(
    name: &str,
    val: &serde_json::Value,
    artifact: &ArtifactReport,
) -> McpServer {
    // Transport type from config
    let transport = network_evidence::infer_transport(val);

    // Gather evidence from config, known packages, and env vars
    let network_ev = network_evidence::gather_server_evidence(name, val, &transport);
    let env_vars = network_evidence::resolve_env_refs(val);

    // Derive network classification from evidence
    let network = network_evidence::classify_from_evidence(&transport, &network_ev);

    // Per-server auth inference from env block and credential patterns
    let server_text = val.to_string().to_lowercase();
    let has_env_pattern = server_text.contains("${")
        || server_text.contains("process.env")
        || server_text.contains("os.environ");
    let has_cred_key = ["api_key", "apikey", "secret", "token", "password", "credential", "auth"]
        .iter()
        .any(|kw| server_text.contains(kw));
    let auth = if has_cred_key || has_env_pattern {
        "API Key"
    } else {
        "None"
    };

    let verified = artifact.verification_status == "pass";

    // Extract the launch command
    let command_str = val
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let args: Vec<&str> = val
        .get("args")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let full_command = if args.is_empty() {
        command_str.to_string()
    } else {
        format!("{} {}", command_str, args.join(" "))
    };

    let tools = extract_mcp_tools(val, name);

    // Build a deterministic ID from the server name + source file
    let source_path = first_path(artifact);
    let id = format!("{}-{}", name, short_hash(source_path));

    McpServer {
        id,
        name: name.to_string(),
        transport,
        network,
        auth: auth.to_string(),
        verified,
        command: full_command,
        tools,
        dependent_agents: Vec::new(),
        network_evidence: network_ev,
        env_vars,
    }
}

fn extract_mcp_tools(server_val: &serde_json::Value, server_name: &str) -> Vec<McpTool> {
    let mut tools = Vec::new();

    // Explicit tools array
    if let Some(tool_arr) = server_val.get("tools").and_then(|v| v.as_array()) {
        for tool in tool_arr {
            let tool_name = tool
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let desc = tool
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            tools.push(McpTool {
                name: tool_name.to_string(),
                risk: "Medium".to_string(),
                description: desc.to_string(),
            });
        }
    }

    // Infer from command/args when no explicit tools
    if tools.is_empty() {
        let command = server_val
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let args: Vec<&str> = server_val
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let has_shell = command.contains("sh") || args.iter().any(|a| a.contains("sh"));
        if has_shell {
            tools.push(McpTool {
                name: "run_shell_command".to_string(),
                risk: "High".to_string(),
                description: format!("Shell execution via {server_name}"),
            });
        }

        if command.contains("filesystem") || server_name.contains("filesystem") {
            tools.push(McpTool {
                name: "read_file".to_string(),
                risk: "Medium".to_string(),
                description: "Read file contents".to_string(),
            });
            tools.push(McpTool {
                name: "write_file".to_string(),
                risk: "Medium".to_string(),
                description: "Write file contents".to_string(),
            });
        }

        // Per v2 contract: empty array if enumeration fails, no generic stubs
    }

    tools
}

// ─── agents ─────────────────────────────────────────────────────────────

fn build_agents(
    agent_artifacts: &[&ArtifactReport],
    mcp_artifacts: &[&ArtifactReport],
) -> Vec<Agent> {
    agent_artifacts
        .iter()
        .map(|a| artifact_to_agent(a, mcp_artifacts))
        .collect()
}

fn artifact_to_agent(
    a: &ArtifactReport,
    mcp_artifacts: &[&ArtifactReport],
) -> Agent {
    let source_path = first_path(a).to_string();
    let name = qualified_name(&source_path);
    let id = make_id(&source_path, &a.artifact_hash);

    let caps = derive_capabilities(a);
    let classification = infer_agent_classification(&caps, a);
    let execution_model = infer_execution_model(a);

    let trust_score = (100 - a.risk_score).clamp(0, 100);

    let capabilities: Vec<AgentCapability> = [
        "Filesystem", "Browser", "Network", "Shell", "Database",
    ]
    .iter()
    .map(|cap_name| {
        let enabled = caps.iter().any(|c| {
            matches!(
                (cap_name, c.as_str()),
                (&"Filesystem", "filesystem_access")
                    | (&"Browser", "browser_access")
                    | (&"Network", "network_access" | "external_api_calls")
                    | (&"Shell", "shell_execution" | "code_execution")
                    | (&"Database", "database_access")
            )
        });
        AgentCapability {
            name: cap_name.to_string(),
            enabled,
        }
    })
    .collect();

    let mut tools: Vec<AgentTool> = declared_tools(a)
        .into_iter()
        .map(|t| AgentTool {
            name: t,
            tool_type: "skill".to_string(),
        })
        .collect();

    // Link MCP server tools — only from co-located config files
    let agent_dir = std::path::Path::new(&source_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut seen_mcp_names = std::collections::HashSet::new();

    for mcp in mcp_artifacts {
        let mcp_path = first_path(mcp);
        let mcp_dir = std::path::Path::new(mcp_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // Only link MCP configs that share a common ancestor or tool scope
        let related = agent_dir.starts_with(&mcp_dir)
            || mcp_dir.starts_with(&agent_dir)
            || is_same_tool_scope(&agent_dir, &mcp_dir);

        if !related {
            continue;
        }

        if let Some(content) = read_artifact_head(mcp) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                let servers = val
                    .get("mcpServers")
                    .or_else(|| val.get("servers"))
                    .and_then(|v| v.as_object());
                if let Some(servers) = servers {
                    for (server_name, _) in servers {
                        if seen_mcp_names.insert(server_name.clone()) {
                            tools.push(AgentTool {
                                name: server_name.clone(),
                                tool_type: "mcp".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    let trust_breakdown = build_trust_breakdown(a);

    // Try to detect source repo from nearest .git/config
    let source_repo = detect_source_repo(&source_path);

    Agent {
        id,
        name,
        source_file_path: source_path,
        classification,
        execution_model,
        trust_score,
        version: "unknown".to_string(),
        author: "unknown".to_string(),
        source_repo,
        capabilities,
        tools,
        trust_breakdown,
    }
}

fn infer_agent_classification(caps: &[String], a: &ArtifactReport) -> String {
    if caps.iter().any(|c| c == "code_execution" || c == "shell_execution") {
        return "Code".to_string();
    }
    if caps
        .iter()
        .any(|c| c == "container_runtime" || c == "dependency_execution")
    {
        return "Automation".to_string();
    }
    if caps
        .iter()
        .any(|c| c == "browser_access" || c == "external_api_calls")
    {
        return "Research".to_string();
    }
    if a.artifact_type == "agents_md" {
        return "System".to_string();
    }
    "System".to_string()
}

fn infer_execution_model(a: &ArtifactReport) -> String {
    let has_dangerous = a
        .signals
        .iter()
        .any(|s| s.starts_with("dangerous_keyword:") || s == "dangerous_combo:shell+network+fs");

    if has_dangerous {
        "Autonomous".to_string()
    } else {
        "User-in-the-loop".to_string()
    }
}

fn build_trust_breakdown(a: &ArtifactReport) -> Vec<TrustFactor> {
    let mut factors = Vec::new();

    let base = match a.artifact_type.as_str() {
        "agents_md" => 10,
        "cursor_rules" => 5,
        _ => 0,
    };
    if base > 0 {
        factors.push(TrustFactor {
            label: format!(
                "Known artifact type: {}",
                a.artifact_type.replace('_', " ")
            ),
            delta: base,
        });
    }

    for signal in &a.signals {
        let (delta, label) = match signal.as_str() {
            "credential_exposure_signal" => (-25, "Hardcoded credential or secret pattern detected".to_string()),
            "dangerous_combo:shell+network+fs" => (-30, "Combined shell, network, and filesystem access — high exfiltration risk".to_string()),
            s if s.starts_with("dangerous_keyword:") => {
                let kw = s.strip_prefix("dangerous_keyword:").unwrap_or(s);
                (-15, format!("Dangerous keyword detected: '{kw}' command"))
            }
            "execution_tokens_present" => (-10, "Execution tokens present in MCP configuration".to_string()),
            "shell_access_detected" => (-10, "Shell access detected in MCP configuration".to_string()),
            _ => (0, String::new()),
        };
        if delta != 0 {
            factors.push(TrustFactor { label, delta });
        }
    }

    if a.verification_status == "pass" {
        factors.push(TrustFactor {
            label: "Verification passed".to_string(),
            delta: 15,
        });
    }

    factors
}

// ─── agenticApps ────────────────────────────────────────────────────────

fn build_agentic_apps(
    container_artifacts: &[&ArtifactReport],
    agents: &[Agent],
) -> Vec<AgenticApp> {
    container_artifacts
        .iter()
        .filter(|a| a.artifact_type == "container_config")
        .map(|a| container_to_app(a, agents))
        .collect()
}

fn container_to_app(a: &ArtifactReport, agents: &[Agent]) -> AgenticApp {
    let source_path = first_path(a).to_string();
    let name = qualified_name(&source_path);
    let id = make_id(&source_path, &a.artifact_hash);

    let framework = detect_framework(a);

    let risk = if a.risk_score >= 70 {
        "High"
    } else if a.risk_score >= 40 {
        "Medium"
    } else {
        "Low"
    };

    let review_status = match a.verification_status.as_str() {
        "pass" => "Reviewed",
        "fail" => "Flagged",
        _ => "Unreviewed",
    };

    // Find agents local to this container's project directory
    let container_dir = std::path::Path::new(&source_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let local_agents: Vec<&Agent> = agents
        .iter()
        .filter(|ag| ag.source_file_path.starts_with(&container_dir))
        .collect();

    let app_agents: Vec<AppAgent> = local_agents
        .iter()
        .map(|ag| AppAgent {
            id: ag.id.clone(),
            name: ag.name.clone(),
        })
        .collect();

    let tools_by_agent: Vec<Vec<String>> = local_agents
        .iter()
        .map(|ag| ag.tools.iter().map(|t| t.name.clone()).collect())
        .collect();

    let workflow: Vec<WorkflowStep> = local_agents
        .iter()
        .enumerate()
        .map(|(i, ag)| WorkflowStep {
            step: (i + 1) as u32,
            agent: ag.name.clone(),
            action: format!(
                "Execute {} tasks using {} tools",
                ag.classification,
                ag.tools.len()
            ),
        })
        .collect();

    let integrations = build_integrations(a);
    let verification_checks = build_verification_checks(a);
    let risk_tags = build_risk_tags(a);
    let risk_summary = build_risk_summary(&name, a, risk);

    // Derive description from framework + signals
    let description = build_app_description(a, &framework, &local_agents);

    AgenticApp {
        id,
        name,
        source_file_path: source_path,
        framework,
        agent_count: app_agents.len() as u32,
        risk: risk.to_string(),
        review_status: review_status.to_string(),
        description,
        agents: app_agents,
        tools_by_agent,
        workflow,
        integrations,
        verification_checks,
        risk_tags,
        risk_summary,
    }
}

fn build_app_description(
    a: &ArtifactReport,
    framework: &str,
    local_agents: &[&Agent],
) -> String {
    let agent_count = local_agents.len();
    let has_ai_proximity = a.signals.iter().any(|s| s == "ai_artifact_proximity");

    if agent_count > 0 && has_ai_proximity {
        let classifications: Vec<&str> = local_agents
            .iter()
            .map(|ag| ag.classification.as_str())
            .collect();
        let unique_classes: std::collections::BTreeSet<&str> =
            classifications.into_iter().collect();
        format!(
            "Containerized {framework} application with {agent_count} agent(s) performing {} tasks",
            unique_classes
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
                .to_lowercase()
        )
    } else if has_ai_proximity {
        format!("Containerized {framework} application co-located with AI agent artifacts")
    } else {
        format!("Containerized application using {framework} orchestration")
    }
}

fn detect_framework(a: &ArtifactReport) -> String {
    for signal in &a.signals {
        let s = signal.to_lowercase();
        if s.contains("langchain") {
            return "LangGraph".to_string();
        }
        if s.contains("crewai") {
            return "CrewAI".to_string();
        }
        if s.contains("autogen") {
            return "AutoGen".to_string();
        }
    }
    "Custom".to_string()
}

fn build_integrations(a: &ArtifactReport) -> Vec<Integration> {
    let mut integrations = Vec::new();

    let endpoints: Vec<String> = a
        .metadata
        .get("api_endpoints")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    for ep in &endpoints {
        // Skip documentation URLs — only include runtime service deps
        let lower = ep.to_lowercase();
        if lower.contains("docs.") || lower.contains("/docs/") || lower.contains("readme") {
            continue;
        }
        let (name, itype, risk) = classify_endpoint(ep);
        integrations.push(Integration {
            name,
            integration_type: itype,
            risk,
        });
    }

    integrations
}

fn classify_endpoint(ep: &str) -> (String, String, String) {
    let lower = ep.to_lowercase();
    if lower.contains("github") {
        ("GitHub API".to_string(), "REST API".to_string(), "Medium".to_string())
    } else if lower.contains("openai") {
        ("OpenAI API".to_string(), "REST API".to_string(), "Medium".to_string())
    } else if lower.contains("anthropic") {
        ("Anthropic API".to_string(), "REST API".to_string(), "Medium".to_string())
    } else {
        (ep.to_string(), "REST API".to_string(), "Medium".to_string())
    }
}

fn build_verification_checks(a: &ArtifactReport) -> Vec<String> {
    let mut checks = vec![
        "Container configuration present".to_string(),
        "Risk score computed".to_string(),
    ];

    if a.verification_status == "pass" {
        checks.push("Verification passed".to_string());
    }
    if a.signals.iter().any(|s| s == "ai_artifact_proximity") {
        checks.push("AI artifact proximity detected".to_string());
    }

    checks
}

fn build_risk_tags(a: &ArtifactReport) -> Vec<String> {
    let mut tags = Vec::new();
    let caps = derive_capabilities(a);

    if caps.iter().any(|c| c == "shell_execution" || c == "code_execution") {
        tags.push("Autonomous Code Execution".to_string());
    }
    if a.signals.iter().any(|s| s == "credential_exposure_signal") {
        tags.push("Credential Exposure".to_string());
    }
    if caps.iter().any(|c| c == "network_access" || c == "external_api_calls") {
        tags.push("External Network Access".to_string());
    }
    if a.signals.iter().any(|s| s.starts_with("dangerous_keyword:")) {
        tags.push("Dangerous Instructions".to_string());
    }

    tags
}

fn build_risk_summary(app_name: &str, a: &ArtifactReport, risk_level: &str) -> String {
    let reasons: Vec<&str> = a.risk_reasons.iter().map(|r| r.as_str()).collect();

    if reasons.is_empty() {
        format!(
            "{risk_level}-risk containerized application '{app_name}'. No specific risk drivers identified."
        )
    } else {
        format!(
            "{risk_level}-risk containerized application '{app_name}'. Key risk drivers: {}.",
            reasons.join(", ")
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared helpers
// ═══════════════════════════════════════════════════════════════════════════

fn first_path(a: &ArtifactReport) -> &str {
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
fn qualified_name(path: &str) -> String {
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
fn make_id(source_path: &str, artifact_hash: &str) -> String {
    if !artifact_hash.is_empty() {
        format!("{}:{}", source_path, &artifact_hash[..12.min(artifact_hash.len())])
    } else {
        format!("{}:{}", source_path, short_hash(source_path))
    }
}

fn short_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = format!("{:x}", hasher.finalize());
    result[..12].to_string()
}

fn compute_file_hash(path: &str) -> String {
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
fn detect_source_repo(file_path: &str) -> String {
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
///
/// Two paths are in the same scope when they belong to the same
/// application config tree — e.g. VS Code, Cursor, or Claude settings.
fn is_same_tool_scope(dir_a: &str, dir_b: &str) -> bool {
    // Both under the same well-known tool config root?
    let scope_markers = [
        ".vscode", ".vscode-insiders", ".cursor",
        ".claude", "Code/User", "Cursor/User",
    ];
    for marker in &scope_markers {
        if dir_a.contains(marker) && dir_b.contains(marker) {
            return true;
        }
    }
    false
}

fn declared_tools(a: &ArtifactReport) -> Vec<String> {
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

fn capability_level(cap: &str) -> &'static str {
    match cap {
        "shell_execution" | "code_execution" | "container_runtime" => "danger",
        "network_access" | "external_api_calls" | "browser_access" | "secret_references" => "warn",
        _ => "info",
    }
}

fn humanize_capability(cap: &str) -> String {
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

fn read_artifact_head(a: &ArtifactReport) -> Option<String> {
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
