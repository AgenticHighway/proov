//! AgenticApp building for the AH-Verify contract.

use crate::capabilities::derive_capabilities;
use crate::models::ArtifactReport;

use super::helpers::{first_path, make_id, qualified_name};
use super::types::{Agent, AgenticApp, AppAgent, Integration, WorkflowStep};

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

fn build_app_description(a: &ArtifactReport, framework: &str, local_agents: &[&Agent]) -> String {
    let agent_count = local_agents.len();
    let has_ai_proximity = a.signals.iter().any(|s| s == "ai_artifact_proximity");

    if agent_count > 0 && has_ai_proximity {
        let unique_classes: std::collections::BTreeSet<&str> = local_agents
            .iter()
            .map(|ag| ag.classification.as_str())
            .collect();
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

    if caps
        .iter()
        .any(|c| c == "shell_execution" || c == "code_execution")
    {
        tags.push("Autonomous Code Execution".to_string());
    }
    if a.signals.iter().any(|s| s == "credential_exposure_signal") {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ArtifactReport;

    #[test]
    fn risk_level_high() {
        assert_eq!(risk_level(70), "High");
        assert_eq!(risk_level(100), "High");
    }

    #[test]
    fn risk_level_medium() {
        assert_eq!(risk_level(40), "Medium");
        assert_eq!(risk_level(69), "Medium");
    }

    #[test]
    fn risk_level_low() {
        assert_eq!(risk_level(0), "Low");
        assert_eq!(risk_level(39), "Low");
    }

    #[test]
    fn review_status_pass() {
        assert_eq!(review_status_label("pass"), "Reviewed");
    }

    #[test]
    fn review_status_fail() {
        assert_eq!(review_status_label("fail"), "Flagged");
    }

    #[test]
    fn review_status_unknown() {
        assert_eq!(review_status_label("pending"), "Unreviewed");
        assert_eq!(review_status_label("conditional_pass"), "Unreviewed");
    }

    #[test]
    fn detect_framework_langchain() {
        let mut a = ArtifactReport::new("container_config", 0.8);
        a.signals = vec!["uses_langchain_framework".to_string()];
        assert_eq!(detect_framework(&a), "LangGraph");
    }

    #[test]
    fn detect_framework_crewai() {
        let mut a = ArtifactReport::new("container_config", 0.8);
        a.signals = vec!["uses_crewai".to_string()];
        assert_eq!(detect_framework(&a), "CrewAI");
    }

    #[test]
    fn detect_framework_custom_default() {
        let a = ArtifactReport::new("container_config", 0.8);
        assert_eq!(detect_framework(&a), "Custom");
    }

    #[test]
    fn classify_endpoint_github() {
        let (name, itype, _risk) = classify_endpoint("https://api.github.com/repos");
        assert_eq!(name, "GitHub API");
        assert_eq!(itype, "REST API");
    }

    #[test]
    fn classify_endpoint_openai() {
        let (name, _, _) = classify_endpoint("https://api.openai.com/v1/chat");
        assert_eq!(name, "OpenAI API");
    }

    #[test]
    fn classify_endpoint_anthropic() {
        let (name, _, _) = classify_endpoint("https://api.anthropic.com/v1/messages");
        assert_eq!(name, "Anthropic API");
    }

    #[test]
    fn classify_endpoint_unknown() {
        let (name, _, _) = classify_endpoint("https://example.com/api");
        assert_eq!(name, "https://example.com/api");
    }

    #[test]
    fn build_verification_checks_basic() {
        let a = ArtifactReport::new("container_config", 0.8);
        let checks = build_verification_checks(&a);
        assert!(checks.contains(&"Container configuration present".to_string()));
        assert!(checks.contains(&"Risk score computed".to_string()));
    }

    #[test]
    fn build_verification_checks_pass() {
        let mut a = ArtifactReport::new("container_config", 0.8);
        a.verification_status = "pass".to_string();
        let checks = build_verification_checks(&a);
        assert!(checks.contains(&"Verification passed".to_string()));
    }

    #[test]
    fn build_verification_checks_ai_proximity() {
        let mut a = ArtifactReport::new("container_config", 0.8);
        a.signals = vec!["ai_artifact_proximity".to_string()];
        let checks = build_verification_checks(&a);
        assert!(checks.contains(&"AI artifact proximity detected".to_string()));
    }

    #[test]
    fn build_risk_tags_code_execution() {
        let mut a = ArtifactReport::new("container_config", 0.8);
        a.signals = vec!["keyword:shell".to_string()];
        let tags = build_risk_tags(&a);
        assert!(tags.contains(&"Autonomous Code Execution".to_string()));
    }

    #[test]
    fn build_risk_tags_credential_exposure() {
        let mut a = ArtifactReport::new("container_config", 0.8);
        a.signals = vec!["credential_exposure_signal".to_string()];
        let tags = build_risk_tags(&a);
        assert!(tags.contains(&"Credential Exposure".to_string()));
    }

    #[test]
    fn build_risk_tags_dangerous_instructions() {
        let mut a = ArtifactReport::new("container_config", 0.8);
        a.signals = vec!["dangerous_keyword:exfiltrate".to_string()];
        let tags = build_risk_tags(&a);
        assert!(tags.contains(&"Dangerous Instructions".to_string()));
    }

    #[test]
    fn build_risk_summary_no_reasons() {
        let a = ArtifactReport::new("container_config", 0.8);
        let summary = build_risk_summary("my-app", &a, "Low");
        assert!(summary.contains("Low-risk"));
        assert!(summary.contains("my-app"));
        assert!(summary.contains("No specific risk drivers"));
    }

    #[test]
    fn build_risk_summary_with_reasons() {
        let mut a = ArtifactReport::new("container_config", 0.8);
        a.risk_reasons = vec!["shell access".to_string(), "network calls".to_string()];
        let summary = build_risk_summary("my-app", &a, "High");
        assert!(summary.contains("High-risk"));
        assert!(summary.contains("shell access, network calls"));
    }

    #[test]
    fn build_agentic_apps_skips_container_candidates() {
        let mut a = ArtifactReport::new("container_candidate", 0.8);
        a.metadata
            .insert("paths".to_string(), serde_json::json!(["/tmp/Dockerfile"]));
        let apps = build_agentic_apps(&[&a], &[]);
        assert!(apps.is_empty());
    }
}
