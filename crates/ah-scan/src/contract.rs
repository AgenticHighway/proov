//! Transforms a [`ScanReport`] into the AH-Verify Scanner Data Contract (v1).
//!
//! The contract defines the exact payload shape the ingestion endpoint
//! expects:  `scanMeta`, `prompts`, `skills`, `mcpServers`, `agents`,
//! and `agenticApps`.

use serde::{Deserialize, Serialize};

use crate::capabilities::derive_capabilities;
use crate::models::{ArtifactReport, ScanReport};

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
}

// ═══════════════════════════════════════════════════════════════════════════
// prompts
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Prompt {
    pub name: String,
    pub classification: String,
    pub tokens: u64,
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
    pub name: String,
    pub network: String,
    pub auth: String,
    pub verified: bool,
    pub tools: Vec<McpTool>,
    pub dependent_agents: Vec<String>,
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
    pub name: String,
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
    pub name: String,
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
// Builder — transform ScanReport → ContractPayload
// ═══════════════════════════════════════════════════════════════════════════

pub fn build_contract_payload(report: &ScanReport, scan_duration_ms: u64) -> ContractPayload {
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    let scan_meta = ScanMeta {
        scan_id: uuid::Uuid::new_v4().to_string(),
        endpoint_hostname: hostname,
        scanned_at: report.timestamp.clone(),
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        scan_duration_ms,
    };

    // Partition artifacts by type for mapping
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
    let mcp_servers = build_mcp_servers(&mcp_artifacts);
    let agents = build_agents(&agent_artifacts, &mcp_artifacts);
    let skills = build_skills(&report.artifacts, &agents);
    let agentic_apps = build_agentic_apps(&container_artifacts, &agents);

    ContractPayload {
        scan_meta,
        prompts,
        skills,
        mcp_servers,
        agents,
        agentic_apps,
    }
}

// ─── prompts ────────────────────────────────────────────────────────────

fn build_prompts(artifacts: &[&ArtifactReport]) -> Vec<Prompt> {
    artifacts.iter().map(|a| artifact_to_prompt(a)).collect()
}

fn artifact_to_prompt(a: &ArtifactReport) -> Prompt {
    let location = first_path(a);
    let name = slug_from_path(location);
    let classification = match a.artifact_type.as_str() {
        "cursor_rules" => "System Prompt",
        "agents_md" => "System Prompt",
        _ => "User Prompt",
    };

    // Rough token estimate: ~4 chars per token for English text
    let tokens = a
        .metadata
        .get("paths")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len() / 4)
        .unwrap_or(0);

    let last_changed_date = a
        .metadata
        .get("paths")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .and_then(|p| std::fs::metadata(p).ok())
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.format("%Y-%m-%d").to_string()
        })
        .unwrap_or_else(|| "1970-01-01".to_string());

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
        name,
        classification: classification.to_string(),
        tokens,
        last_changed_date,
        capabilities,
        secret_refs,
        injection_surfaces,
        dependencies,
        risk_score: a.risk_score.min(100).max(0),
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

    // Check metadata for env-var-style references (safe)
    if let Some(content) = read_artifact_head(a) {
        for pattern in &["$", "process.env.", "os.environ"] {
            if content.contains(pattern) {
                // Only flag env var refs if we haven't already flagged as dangerous
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

    // Check for user-controlled input surfaces
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

    // Add skills from MCP server tools
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
                                .last()
                                .unwrap_or(cmd)
                                .to_string();
                            if seen.insert(skill_name.clone()) {
                                skills.push(Skill {
                                    name: skill_name.clone(),
                                    skill_type: "CLI Tool".to_string(),
                                    trust_level: "Conditional".to_string(),
                                    execution_environment: "Local Process".to_string(),
                                    description: format!("MCP server command: {cmd}"),
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

    let apis: Vec<String> = a_metadata_endpoints(artifact);

    Skill {
        name: tool_name.to_string(),
        skill_type: skill_type.to_string(),
        trust_level: trust_level.to_string(),
        execution_environment: exec_env.to_string(),
        description: format!("{} capability", humanize_capability(tool_name)),
        permissions,
        dependencies: SkillDependencies {
            libraries: Vec::new(),
            binaries,
            apis,
        },
        consumers: find_skill_consumers(tool_name, agents),
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
        .filter(|agent| {
            agent.tools.iter().any(|t| t.name == tool_name)
        })
        .map(|agent| SkillConsumer {
            name: agent.name.clone(),
            consumer_type: "Agent".to_string(),
            invocations: 0,
        })
        .collect()
}

// ─── mcpServers ─────────────────────────────────────────────────────────

fn build_mcp_servers(artifacts: &[&ArtifactReport]) -> Vec<McpServer> {
    let mut servers = Vec::new();

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
            servers.push(mcp_entry_to_server(name, server_val, artifact));
        }
    }

    servers
}

fn mcp_entry_to_server(
    name: &str,
    val: &serde_json::Value,
    artifact: &ArtifactReport,
) -> McpServer {
    let has_endpoints = artifact
        .metadata
        .get("api_endpoints")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);

    let network = if has_endpoints {
        "Internet Exposed"
    } else {
        "Local Only"
    };

    let has_cred_signal = artifact.signals.iter().any(|s| s == "credential_references");
    let auth = if has_cred_signal { "API Key" } else { "None" };

    let verified = artifact.verification_status == "pass";

    let tools = extract_mcp_tools(val, name);

    McpServer {
        name: name.to_string(),
        network: network.to_string(),
        auth: auth.to_string(),
        verified,
        tools,
        dependent_agents: Vec::new(), // cross-linked after agent building
    }
}

fn extract_mcp_tools(server_val: &serde_json::Value, server_name: &str) -> Vec<McpTool> {
    // MCP configs typically declare tools via args or command — infer from structure
    let mut tools = Vec::new();

    // If there's an explicit `tools` array
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

    // If no explicit tools, infer from command/args
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

        // Generic fallback if nothing detected
        if tools.is_empty() {
            tools.push(McpTool {
                name: format!("{server_name}_invoke"),
                risk: "Low".to_string(),
                description: format!("Invoke {server_name} server"),
            });
        }
    }

    tools
}

// ─── agents ─────────────────────────────────────────────────────────────

fn build_agents(
    agent_artifacts: &[&ArtifactReport],
    mcp_artifacts: &[&ArtifactReport],
) -> Vec<Agent> {
    let mut agents = Vec::new();

    for artifact in agent_artifacts {
        agents.push(artifact_to_agent(artifact, mcp_artifacts));
    }

    // Also promote cursor_rules that declare significant capabilities as implicit agents
    agents
}

fn artifact_to_agent(
    a: &ArtifactReport,
    mcp_artifacts: &[&ArtifactReport],
) -> Agent {
    let location = first_path(a);
    let name = slug_from_path(location);

    let caps = derive_capabilities(a);
    let classification = infer_agent_classification(&caps, a);
    let execution_model = infer_execution_model(a);

    let trust_score = (100 - a.risk_score).max(0).min(100);

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

    // Link MCP server tools
    for mcp in mcp_artifacts {
        if let Some(content) = read_artifact_head(mcp) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                let servers = val
                    .get("mcpServers")
                    .or_else(|| val.get("servers"))
                    .and_then(|v| v.as_object());
                if let Some(servers) = servers {
                    for (server_name, _) in servers {
                        tools.push(AgentTool {
                            name: server_name.clone(),
                            tool_type: "mcp".to_string(),
                        });
                    }
                }
            }
        }
    }

    let trust_breakdown = build_trust_breakdown(a);

    Agent {
        name,
        classification,
        execution_model,
        trust_score,
        version: "v0.1.0".to_string(),
        author: "unknown".to_string(),
        source_repo: "unknown".to_string(),
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
    // Look for scheduling/autonomous indicators in signals
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

    // Base trust from artifact type
    let base = match a.artifact_type.as_str() {
        "agents_md" => 10,
        "cursor_rules" => 5,
        _ => 0,
    };
    if base > 0 {
        factors.push(TrustFactor {
            label: format!("Known artifact type: {}", a.artifact_type),
            delta: base,
        });
    }

    // Deductions from signals
    for signal in &a.signals {
        let delta = match signal.as_str() {
            "credential_exposure_signal" => -25,
            "dangerous_combo:shell+network+fs" => -30,
            s if s.starts_with("dangerous_keyword:") => -15,
            "execution_tokens_present" => -10,
            "shell_access_detected" => -10,
            _ => 0,
        };
        if delta != 0 {
            factors.push(TrustFactor {
                label: signal.clone(),
                delta,
            });
        }
    }

    // Positive signals
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
    let mut apps = Vec::new();

    for artifact in container_artifacts {
        if artifact.artifact_type == "container_config" {
            apps.push(container_to_app(artifact, agents));
        }
    }

    apps
}

fn container_to_app(a: &ArtifactReport, agents: &[Agent]) -> AgenticApp {
    let location = first_path(a);
    let name = slug_from_path(location);

    // Detect framework from AI signals
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

    // Map agents that could participate in this app
    let app_agents: Vec<AppAgent> = agents
        .iter()
        .map(|ag| AppAgent {
            name: ag.name.clone(),
        })
        .collect();

    let tools_by_agent: Vec<Vec<String>> = agents
        .iter()
        .map(|ag| ag.tools.iter().map(|t| t.name.clone()).collect())
        .collect();

    let workflow: Vec<WorkflowStep> = agents
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
    let risk_summary = build_risk_summary(a, risk);

    AgenticApp {
        name,
        framework,
        agent_count: app_agents.len().max(1) as u32,
        risk: risk.to_string(),
        review_status: review_status.to_string(),
        description: format!(
            "Containerized agentic application at {}",
            location
        ),
        agents: app_agents,
        tools_by_agent,
        workflow,
        integrations,
        verification_checks,
        risk_tags,
        risk_summary,
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

fn build_risk_summary(a: &ArtifactReport, risk_level: &str) -> String {
    let location = first_path(a);
    let reasons: Vec<&str> = a.risk_reasons.iter().map(|r| r.as_str()).collect();

    if reasons.is_empty() {
        format!(
            "{risk_level}-risk containerized application at {location}. No specific risk drivers identified."
        )
    } else {
        format!(
            "{risk_level}-risk containerized application at {location}. Key risk drivers: {}.",
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

fn slug_from_path(path: &str) -> String {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_lowercase()
        .replace(' ', "-")
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

fn a_metadata_endpoints(a: &ArtifactReport) -> Vec<String> {
    a.metadata
        .get("api_endpoints")
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
    // Only read files on the content-read allowlist
    if !crate::models::is_content_read_allowed(path) {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let len = bytes.len().min(MAX_READ_BYTES);
    String::from_utf8(bytes[..len].to_vec()).ok()
}
