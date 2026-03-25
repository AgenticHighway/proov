//! Transforms a [`ScanReport`] into the AH-Verify Scanner Data Contract (v2).
//!
//! The contract defines the exact payload shape the ingestion endpoint
//! expects:  `scanMeta`, `prompts`, `skills`, `mcpServers`, `agents`,
//! and `agenticApps`.

mod agents;
mod apps;
mod helpers;
mod mcp;
mod prompts;
mod skills;
pub mod types;

pub use types::*;

use crate::models::ScanReport;
use crate::network_evidence;

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
    let (prompt_artifacts, mcp_artifacts, container_artifacts, agent_artifacts) =
        partition_artifacts(report);

    let prompts_out = prompts::build_prompts(&prompt_artifacts);
    let agents_out = agents::build_agents(&agent_artifacts, &mcp_artifacts);
    let skills_out = skills::build_skills(&report.artifacts, &agents_out);
    let agentic_apps = apps::build_agentic_apps(&container_artifacts, &agents_out);

    let mcp_servers = build_mcp_with_links(&mcp_artifacts, &agents_out);

    ContractPayload {
        scan_meta,
        prompts: prompts_out,
        skills: skills_out,
        mcp_servers,
        agents: agents_out,
        agentic_apps,
    }
}

type ArtifactPartition<'a> = (
    Vec<&'a crate::models::ArtifactReport>,
    Vec<&'a crate::models::ArtifactReport>,
    Vec<&'a crate::models::ArtifactReport>,
    Vec<&'a crate::models::ArtifactReport>,
);

fn partition_artifacts(report: &ScanReport) -> ArtifactPartition<'_> {
    let mut prompts = Vec::new();
    let mut mcps = Vec::new();
    let mut containers = Vec::new();
    let mut agents = Vec::new();

    for artifact in &report.artifacts {
        match artifact.artifact_type.as_str() {
            "cursor_rules" | "prompt_config" => prompts.push(artifact),
            "agents_md" => {
                prompts.push(artifact);
                agents.push(artifact);
            }
            "mcp_config" => mcps.push(artifact),
            "container_config" | "container_candidate" => containers.push(artifact),
            _ => {}
        }
    }

    (prompts, mcps, containers, agents)
}

fn build_mcp_with_links(
    mcp_artifacts: &[&crate::models::ArtifactReport],
    agents_out: &[Agent],
) -> Vec<McpServer> {
    // Map: MCP server name → agent IDs that reference it
    let mut agent_ids_by_mcp: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for agent in agents_out {
        for tool in &agent.tools {
            if tool.tool_type == "mcp" {
                agent_ids_by_mcp
                    .entry(tool.name.clone())
                    .or_default()
                    .push(agent.id.clone());
            }
        }
    }

    let mut servers = mcp::build_mcp_servers(mcp_artifacts);
    for server in &mut servers {
        if let Some(ids) = agent_ids_by_mcp.get(&server.name) {
            let mut seen = std::collections::HashSet::new();
            server.dependent_agents = ids
                .iter()
                .filter(|id| seen.insert((*id).clone()))
                .cloned()
                .collect();
        }
    }
    servers
}
