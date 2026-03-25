//! Skill building for the AH-Verify contract.

use crate::models::ArtifactReport;

use super::helpers::{declared_tools, read_artifact_head};
use super::types::{Agent, Skill, SkillConsumer, SkillDependencies, SkillPermission};

pub fn build_skills(artifacts: &[ArtifactReport], agents: &[Agent]) -> Vec<Skill> {
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
                extract_mcp_command_skills(&val, &mut seen, &mut skills, agents);
            }
        }
    }

    skills
}

fn extract_mcp_command_skills(
    val: &serde_json::Value,
    seen: &mut std::collections::HashSet<String>,
    skills: &mut Vec<Skill>,
    agents: &[Agent],
) {
    let servers = val
        .get("mcpServers")
        .or_else(|| val.get("servers"))
        .and_then(|v| v.as_object());
    let servers = match servers {
        Some(s) => s,
        None => return,
    };

    for (_server_name, server_val) in servers {
        let cmd = match server_val.get("command").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => continue,
        };
        let skill_name = cmd.split('/').next_back().unwrap_or(cmd).to_string();
        if !seen.insert(skill_name.clone()) {
            continue;
        }

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
            description: format!("Executes MCP server via: {full_cmd}"),
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

    Skill {
        id: tool_name.to_string(),
        name: tool_name.to_string(),
        skill_type: skill_type.to_string(),
        trust_level: trust_level.to_string(),
        execution_environment: exec_env.to_string(),
        description: skill_description(tool_name),
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
        "filesystem" => "Reads and writes files on the local filesystem".to_string(),
        "browser" => {
            "Controls a browser instance for web navigation and interaction".to_string()
        }
        "api" => "Makes HTTP requests to external API services".to_string(),
        "docker" => "Manages Docker containers and images via the Docker CLI".to_string(),
        other => format!("Provides {} functionality", other.replace('_', " ")),
    }
}

fn infer_permissions(tool_name: &str) -> Vec<SkillPermission> {
    let mut perms = Vec::new();
    match tool_name {
        "shell" | "bash" => {
            perms.push(SkillPermission {
                name: "Shell execution".to_string(),
                required: true,
            });
            perms.push(SkillPermission {
                name: "Filesystem read/write".to_string(),
                required: true,
            });
        }
        "filesystem" => {
            perms.push(SkillPermission {
                name: "Filesystem read/write".to_string(),
                required: true,
            });
        }
        "browser" | "api" => {
            perms.push(SkillPermission {
                name: "Network access".to_string(),
                required: true,
            });
        }
        "docker" => {
            perms.push(SkillPermission {
                name: "Shell execution".to_string(),
                required: true,
            });
            perms.push(SkillPermission {
                name: "Network access".to_string(),
                required: true,
            });
        }
        "python" | "node" => {
            perms.push(SkillPermission {
                name: "Shell execution".to_string(),
                required: true,
            });
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
