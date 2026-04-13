use crate::models::ArtifactReport;
use std::collections::HashMap;

const DECLARED_DISCOUNT: f64 = 0.5;

fn capability_base_risk() -> HashMap<&'static str, i32> {
    HashMap::from([
        ("keyword:shell", 15),
        ("keyword:browser", 10),
        ("keyword:api", 10),
        ("keyword:permissions", 8),
        ("keyword:system", 5),
        ("keyword:tools", 5),
        ("keyword:instructions", 3),
        ("keyword:execute", 12),
        ("keyword:network", 10),
        ("keyword:filesystem", 5),
        ("keyword:docker", 5),
        ("keyword:secrets", 8),
        ("keyword:dependencies", 3),
    ])
}

fn keyword_to_declared() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("keyword:shell", "shell"),
        ("keyword:browser", "browser"),
        ("keyword:api", "api"),
        ("keyword:filesystem", "filesystem"),
        ("keyword:docker", "docker"),
        ("keyword:execute", "python"),
    ])
}

fn signal_weights() -> HashMap<&'static str, i32> {
    HashMap::from([
        ("credential_exposure_signal", 25),
        ("json_config:credential_connection_string", 20),
        ("json_config:credential_value", 15),
        ("json_config:metadata_url", 25),
        ("json_config:internal_url", 15),
        ("json_config:c2_url", 35),
        ("source:dynamic_import", 20),
        ("source:nonliteral_require", 20),
        ("source:nonliteral_spawn", 30),
        ("source:ssrf_private_ip", 25),
        ("source:ssrf_internal_host", 20),
        ("source:sensitive_path_access", 25),
        ("mcp_server_declared", 20),
        ("extensions_directory_present", 5),
        ("dangerous_combo:shell+network+fs", 30),
        ("dangerous_keyword:exfiltrate", 35),
        ("dangerous_keyword:wipe", 30),
        ("dangerous_keyword:rm", 25),
        ("dangerous_keyword:steal", 35),
        ("dangerous_keyword:upload", 20),
        ("dangerous_keyword:reverse", 35),
        ("dangerous_keyword:disable", 25),
        ("dangerous_keyword:bypass", 25),
    ])
}

fn secret_signal_weight(signal: &str) -> Option<i32> {
    match signal {
        "secret:aws:access_key"
        | "secret:aws:secret_access_key"
        | "secret:aws:session_token"
        | "secret:github:pat"
        | "secret:github:oauth_token"
        | "secret:github:fine_grained_pat"
        | "secret:github:app_token"
        | "secret:github:refresh_token"
        | "secret:gitlab:pat"
        | "secret:gitlab:project_token"
        | "secret:gitlab:oauth_token"
        | "secret:stripe:live_secret_key"
        | "secret:stripe:restricted_key"
        | "secret:npm:token"
        | "secret:pypi:token" => Some(25),
        "secret:gcp:api_key"
        | "secret:gcp:client_secret"
        | "secret:azure:account_key"
        | "secret:azure:connection_string"
        | "secret:azure:secret_value"
        | "secret:azure:sas_token"
        | "secret:slack:bot_token"
        | "secret:slack:user_token"
        | "secret:slack:webhook"
        | "secret:twilio:auth_token"
        | "secret:twilio:api_key"
        | "secret:sendgrid:api_key"
        | "secret:mailgun:api_key"
        | "secret:auth:basic_header"
        | "secret:auth:bearer_header" => Some(20),
        "secret:stripe:test_secret_key" | "secret:auth:jwt" => Some(15),
        _ if signal.starts_with("secret:crypto:") => Some(25),
        _ => None,
    }
}

fn ssrf_signal_weight(signal: &str) -> Option<i32> {
    match signal {
        "ssrf:metadata:aws"
        | "ssrf:metadata:gcp"
        | "ssrf:metadata:azure"
        | "ssrf:metadata:alibaba"
        | "ssrf:scheme:gopher" => Some(45),
        "ssrf:scheme:file"
        | "ssrf:scheme:dict"
        | "ssrf:encoding:octal_ipv4"
        | "ssrf:encoding:hex_ipv4"
        | "ssrf:encoding:decimal_host" => Some(25),
        "ssrf:private_network:10"
        | "ssrf:private_network:172"
        | "ssrf:private_network:192"
        | "ssrf:private_network:localhost" => Some(20),
        _ => None,
    }
}

fn cognitive_signal_weight(signal: &str) -> Option<i32> {
    match signal {
        "cognitive_tampering:role_override" | "cognitive_tampering:delimiter_framing" => Some(45),
        "cognitive_tampering:instruction_injection"
        | "cognitive_tampering:unicode_steganography" => Some(35),
        "cognitive_tampering:file_write" => Some(35),
        "cognitive_tampering:file_target" => Some(25),
        "cognitive_tampering:base64_encoded" => Some(25),
        _ => None,
    }
}

fn type_base_score() -> HashMap<&'static str, i32> {
    HashMap::from([
        ("cursor_rules", 10),
        ("agents_md", 8),
        ("source_risk_surface", 4),
        ("container_config", 12),
        ("container_candidate", 3),
        ("browser_footprint", 5),
        ("mcp_config", 20),
    ])
}

fn declared_tools_from_metadata(artifact: &ArtifactReport) -> Vec<String> {
    artifact
        .metadata
        .get("declared_tools")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn is_declared(signal: &str, declared_tools: &[String], ktd: &HashMap<&str, &str>) -> bool {
    ktd.get(signal)
        .map(|tool_name| declared_tools.iter().any(|t| t == tool_name))
        .unwrap_or(false)
}

fn parse_count_signal(signal: &str, prefix: &str) -> Option<i32> {
    signal
        .strip_prefix(prefix)
        .and_then(|n| n.parse::<i32>().ok())
}

pub fn score_artifact(artifact: &mut ArtifactReport) -> i32 {
    let cap_risk = capability_base_risk();
    let ktd = keyword_to_declared();
    let sig_weights = signal_weights();
    let type_base = type_base_score();

    let base = type_base
        .get(artifact.artifact_type.as_str())
        .copied()
        .unwrap_or(5);

    let declared_tools = declared_tools_from_metadata(artifact);
    let has_structured_secret = artifact.signals.iter().any(|s| s.starts_with("secret:"));
    let mut score = base;
    let mut contributions: Vec<(i32, String)> = Vec::new();

    for signal in &artifact.signals {
        let sig = signal.as_str();

        if sig == "credential_exposure_signal" && has_structured_secret {
            continue;
        }

        if let Some(&weight) = cap_risk.get(sig) {
            let effective = if is_declared(sig, &declared_tools, &ktd) {
                (weight as f64 * DECLARED_DISCOUNT) as i32
            } else {
                weight
            };
            score += effective;
            contributions.push((effective, signal.clone()));
        } else if let Some(weight) = secret_signal_weight(sig) {
            score += weight;
            contributions.push((weight, signal.clone()));
        } else if let Some(weight) = ssrf_signal_weight(sig) {
            score += weight;
            contributions.push((weight, signal.clone()));
        } else if let Some(weight) = cognitive_signal_weight(sig) {
            score += weight;
            contributions.push((weight, signal.clone()));
        } else if let Some(&weight) = sig_weights.get(sig) {
            score += weight;
            contributions.push((weight, signal.clone()));
        } else if let Some(n) = parse_count_signal(sig, "extension_count:") {
            let w = n.min(10);
            score += w;
            contributions.push((w, signal.clone()));
        } else if let Some(n) = parse_count_signal(sig, "mcp_server_count:") {
            let w = (n * 5).min(20);
            score += w;
            contributions.push((w, signal.clone()));
        }
    }

    score = score.min(100);

    contributions.sort_by(|a, b| b.0.cmp(&a.0));
    artifact.risk_reasons = contributions
        .iter()
        .take(2)
        .map(|(w, s)| format!("{s} (+{w})"))
        .collect();

    artifact.risk_score = score;
    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_artifact(artifact_type: &str, signals: Vec<&str>) -> ArtifactReport {
        let mut a = ArtifactReport::new(artifact_type, 1.0);
        a.signals = signals.into_iter().map(String::from).collect();
        a
    }

    #[test]
    fn test_base_score_only() {
        let mut a = make_artifact("mcp_config", vec![]);
        let score = score_artifact(&mut a);
        assert_eq!(score, 20);
    }

    #[test]
    fn test_capability_risk_no_discount() {
        let mut a = make_artifact("cursor_rules", vec!["keyword:shell"]);
        let score = score_artifact(&mut a);
        assert_eq!(score, 25); // 10 + 15
    }

    #[test]
    fn test_capability_risk_with_discount() {
        let mut a = make_artifact("cursor_rules", vec!["keyword:shell"]);
        a.metadata
            .insert("declared_tools".to_string(), json!(["shell"]));
        let score = score_artifact(&mut a);
        assert_eq!(score, 17); // 10 + 7 (15*0.5 truncated)
    }

    #[test]
    fn test_signal_weight() {
        let mut a = make_artifact("agents_md", vec!["dangerous_keyword:steal"]);
        let score = score_artifact(&mut a);
        assert_eq!(score, 43); // 8 + 35
    }

    #[test]
    fn test_json_config_c2_signal_weight() {
        let mut a = make_artifact("source_risk_surface", vec!["json_config:c2_url"]);
        let score = score_artifact(&mut a);
        assert_eq!(score, 39); // 4 + 35
    }

    #[test]
    fn test_source_dynamic_spawn_weight() {
        let mut a = make_artifact("source_risk_surface", vec!["source:nonliteral_spawn"]);
        let score = score_artifact(&mut a);
        assert_eq!(score, 34); // 4 + 30
    }

    #[test]
    fn test_cognitive_file_write_weight() {
        let mut a = make_artifact(
            "source_risk_surface",
            vec!["cognitive_tampering:file_write"],
        );
        let score = score_artifact(&mut a);
        assert_eq!(score, 39); // 4 + 35
    }

    #[test]
    fn test_source_risk_surface_base_score() {
        let mut a = make_artifact("source_risk_surface", vec![]);
        let score = score_artifact(&mut a);
        assert_eq!(score, 4);
    }

    #[test]
    fn test_structured_secret_signal_weight_replaces_generic_credential_weight() {
        let mut a = make_artifact(
            "agents_md",
            vec!["credential_exposure_signal", "secret:github:pat"],
        );
        let score = score_artifact(&mut a);
        assert_eq!(score, 33); // 8 + 25, without double counting the generic signal
        assert!(a.risk_reasons[0].contains("secret:github:pat"));
    }

    #[test]
    fn test_ssrf_metadata_signal_weight() {
        let mut a = make_artifact("prompt_config", vec!["ssrf:metadata:aws"]);
        let score = score_artifact(&mut a);
        assert_eq!(score, 50); // unknown type base 5 + 45
    }

    #[test]
    fn test_cognitive_tampering_signal_weight() {
        let mut a = make_artifact("prompt_config", vec!["cognitive_tampering:role_override"]);
        let score = score_artifact(&mut a);
        assert_eq!(score, 50); // unknown type base 5 + 45
    }

    #[test]
    fn test_extension_count() {
        let mut a = make_artifact("agents_md", vec!["extension_count:15"]);
        let score = score_artifact(&mut a);
        assert_eq!(score, 18); // 8 + min(15,10)
    }

    #[test]
    fn test_mcp_server_count() {
        let mut a = make_artifact("agents_md", vec!["mcp_server_count:6"]);
        let score = score_artifact(&mut a);
        assert_eq!(score, 28); // 8 + min(30,20)
    }

    #[test]
    fn test_cap_at_100() {
        let mut a = make_artifact(
            "mcp_config",
            vec![
                "dangerous_keyword:steal",
                "dangerous_keyword:exfiltrate",
                "dangerous_combo:shell+network+fs",
                "keyword:shell",
            ],
        );
        let score = score_artifact(&mut a);
        assert_eq!(score, 100);
    }

    #[test]
    fn test_risk_reasons_top_2() {
        let mut a = make_artifact(
            "agents_md",
            vec![
                "keyword:instructions",
                "keyword:shell",
                "dangerous_keyword:steal",
            ],
        );
        score_artifact(&mut a);
        assert_eq!(a.risk_reasons.len(), 2);
        assert!(a.risk_reasons[0].contains("steal"));
        assert!(a.risk_reasons[1].contains("shell"));
    }

    #[test]
    fn test_unknown_type_default_base() {
        let mut a = make_artifact("unknown_type", vec![]);
        let score = score_artifact(&mut a);
        assert_eq!(score, 5);
    }
}
