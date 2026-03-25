//! AgenticApp building for the AH-Verify contract.

use crate::capabilities::derive_capabilities;
use crate::models::ArtifactReport;

use super::helpers::{first_path, make_id, qualified_name};
use super::types::{
    Agent, AgenticApp, AppAgent, Integration, WorkflowStep,
};

pub fn build_agentic_apps(
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
    let risk = risk_level(a.risk_score);
    let review_status = review_status_label(&a.verification_status);

    let local_agents = find_local_agents(&source_path, agents);
    let app_agents = build_app_agents(&local_agents);
    let tools_by_agent = build_tools_by_agent(&local_agents);
    let workflow = build_workflow(&local_agents);
    let integrations = build_integrations(a);
    let verification_checks = build_verification_checks(a);
    let risk_tags = build_risk_tags(a);
    let risk_summary = build_risk_summary(&name, a, risk);
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

fn risk_level(score: i32) -> &'static str {
    if score >= 70 {
        "High"
    } else if score >= 40 {
        "Medium"
    } else {
        "Low"
    }
}

fn review_status_label(status: &str) -> &'static str {
    match status {
        "pass" => "Reviewed",
        "fail" => "Flagged",
        _ => "Unreviewed",
    }
}

fn find_local_agents<'a>(source_path: &str, agents: &'a [Agent]) -> Vec<&'a Agent> {
    let container_dir = std::path::Path::new(source_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    agents
        .iter()
        .filter(|ag| ag.source_file_path.starts_with(&container_dir))
        .collect()
}

fn build_app_agents(local_agents: &[&Agent]) -> Vec<AppAgent> {
    local_agents
        .iter()
        .map(|ag| AppAgent {
            id: ag.id.clone(),
            name: ag.name.clone(),
        })
        .collect()
}

fn build_tools_by_agent(local_agents: &[&Agent]) -> Vec<Vec<String>> {
    local_agents
        .iter()
        .map(|ag| ag.tools.iter().map(|t| t.name.clone()).collect())
        .collect()
}

fn build_workflow(local_agents: &[&Agent]) -> Vec<WorkflowStep> {
    local_agents
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
        .collect()
}

fn build_app_description(
    a: &ArtifactReport,
    framework: &str,
    local_agents: &[&Agent],
) -> String {
    let agent_count = local_agents.len();
    let has_ai_proximity = a.signals.iter().any(|s| s == "ai_artifact_proximity");

    if agent_count > 0 && has_ai_proximity {
        let unique_classes: std::collections::BTreeSet<&str> =
            local_agents.iter().map(|ag| ag.classification.as_str()).collect();
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
    let endpoints: Vec<String> = a
        .metadata
        .get("api_endpoints")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    endpoints
        .iter()
        .filter(|ep| {
            let lower = ep.to_lowercase();
            !(lower.contains("docs.") || lower.contains("/docs/") || lower.contains("readme"))
        })
        .map(|ep| {
            let (name, itype, risk) = classify_endpoint(ep);
            Integration {
                name,
                integration_type: itype,
                risk,
            }
        })
        .collect()
}

fn classify_endpoint(ep: &str) -> (String, String, String) {
    let lower = ep.to_lowercase();
    if lower.contains("github") {
        (
            "GitHub API".to_string(),
            "REST API".to_string(),
            "Medium".to_string(),
        )
    } else if lower.contains("openai") {
        (
            "OpenAI API".to_string(),
            "REST API".to_string(),
            "Medium".to_string(),
        )
    } else if lower.contains("anthropic") {
        (
            "Anthropic API".to_string(),
            "REST API".to_string(),
            "Medium".to_string(),
        )
    } else {
        (
            ep.to_string(),
            "REST API".to_string(),
            "Medium".to_string(),
        )
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

    if caps
        .iter()
        .any(|c| c == "shell_execution" || c == "code_execution")
    {
        tags.push("Autonomous Code Execution".to_string());
    }
    if a.signals
        .iter()
        .any(|s| s == "credential_exposure_signal")
    {
        tags.push("Credential Exposure".to_string());
    }
    if caps
        .iter()
        .any(|c| c == "network_access" || c == "external_api_calls")
    {
        tags.push("External Network Access".to_string());
    }
    if a.signals
        .iter()
        .any(|s| s.starts_with("dangerous_keyword:"))
    {
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
