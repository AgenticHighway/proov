use std::collections::HashMap;

use crate::models::{ArtifactReport, ScanReport};

pub const LITE_MODE_VISIBLE_RESULTS: usize = 3;

fn local_policy_signal_weights() -> HashMap<&'static str, i32> {
    HashMap::from([
        ("credential_exposure_signal", 25),
        ("dangerous_combo:shell+network+fs", 30),
        ("dangerous_keyword:exfiltrate", 35),
        ("dangerous_keyword:reverse", 35),
        ("dangerous_keyword:steal", 35),
        ("dangerous_keyword:wipe", 30),
        ("dangerous_keyword:bypass", 25),
        ("keyword:shell", 15),
        ("keyword:browser", 10),
        ("keyword:api", 10),
        ("keyword:execute", 12),
        ("keyword:network", 10),
        ("keyword:filesystem", 5),
    ])
}

fn local_policy_type_base() -> HashMap<&'static str, i32> {
    HashMap::from([
        ("cursor_rules", 4),
        ("agents_md", 4),
        ("prompt_config", 3),
    ])
}

pub fn local_policy_score(artifact: &ArtifactReport) -> i32 {
    let type_base = local_policy_type_base();
    let signal_weights = local_policy_signal_weights();
    let mut score = *type_base.get(artifact.artifact_type.as_str()).unwrap_or(&1);
    for signal in &artifact.signals {
        score += signal_weights.get(signal.as_str()).unwrap_or(&0);
    }
    score.min(100)
}

pub fn limit_lite_mode_report(
    report: &ScanReport,
    top_n: usize,
) -> (ScanReport, usize, Vec<ArtifactReport>) {
    let mut scored: Vec<(i32, i32, i64, ArtifactReport)> = report
        .artifacts
        .iter()
        .map(|a| {
            (
                local_policy_score(a),
                a.risk_score,
                (a.confidence * 1000.0) as i64,
                a.clone(),
            )
        })
        .collect();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then(b.1.cmp(&a.1))
            .then(b.2.cmp(&a.2))
    });

    let visible: Vec<ArtifactReport> = scored.iter().take(top_n).map(|t| t.3.clone()).collect();
    let hidden: Vec<ArtifactReport> = scored.iter().skip(top_n).map(|t| t.3.clone()).collect();
    let hidden_count = hidden.len();

    let visible_report = ScanReport {
        scanned_path: report.scanned_path.clone(),
        run_id: report.run_id.clone(),
        timestamp: report.timestamp.clone(),
        artifacts: visible,
    };
    (visible_report, hidden_count, hidden)
}

pub fn locked_summary_counts(artifacts: &[ArtifactReport]) -> serde_json::Value {
    let mut by_type: HashMap<&str, usize> = HashMap::new();
    let mut by_status: HashMap<&str, usize> = HashMap::new();
    let mut by_origin: HashMap<String, usize> = HashMap::new();

    for a in artifacts {
        *by_type.entry(a.artifact_type.as_str()).or_default() += 1;
        *by_status.entry(a.verification_status.as_str()).or_default() += 1;
        let origin = a
            .metadata
            .get("analysis_origin")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        *by_origin.entry(origin).or_default() += 1;
    }

    serde_json::json!({
        "count": artifacts.len(),
        "by_type": by_type,
        "by_status": by_status,
        "by_origin": by_origin,
    })
}

pub fn print_locked_summary(artifacts: &[ArtifactReport]) {
    if artifacts.is_empty() {
        return;
    }
    let summary = locked_summary_counts(artifacts);
    println!("Locked findings summary (lite mode):");
    println!("  Locked findings: {}", summary["count"]);

    if let Some(obj) = summary["by_origin"].as_object() {
        println!("  Analysis handoff:");
        for (k, v) in obj {
            println!("    {}: {}", k, v);
        }
    }
    if let Some(obj) = summary["by_status"].as_object() {
        println!("  Status distribution:");
        for status in &["fail", "conditional_pass", "pass", "pending"] {
            if let Some(v) = obj.get(*status) {
                println!("    {}: {}", status, v);
            }
        }
    }
    if let Some(obj) = summary["by_type"].as_object() {
        println!("  Locked artifact types:");
        for (k, v) in obj {
            println!("    {}: {}", k, v);
        }
    }
    println!();
}
