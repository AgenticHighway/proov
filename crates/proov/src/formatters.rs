//! Human-readable output formatters for scan reports.
//!
//! Provides overview, full detail, and summary views of scan results.
//! All output uses ANSI escape codes for terminal coloring.

use std::collections::HashMap;

use crate::capabilities::derive_capabilities;
use crate::models::{ArtifactReport, ScanReport};

// ── ANSI helpers ────────────────────────────────────────────────────────

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";

pub fn severity(score: i32) -> (&'static str, &'static str) {
    if score >= 90 {
        ("CRITICAL", "\x1b[1;35m")
    } else if score >= 70 {
        ("HIGH    ", "\x1b[31m")
    } else if score >= 40 {
        ("MEDIUM  ", "\x1b[33m")
    } else if score >= 10 {
        ("LOW     ", "\x1b[36m")
    } else {
        ("INFO    ", "\x1b[2m")
    }
}

// ── Counting helpers (pure logic) ───────────────────────────────────────

fn count_by<F>(artifacts: &[ArtifactReport], key_fn: F) -> Vec<(String, usize)>
where
    F: Fn(&ArtifactReport) -> &str,
{
    let mut counts: HashMap<String, usize> = HashMap::new();
    for a in artifacts {
        *counts.entry(key_fn(a).to_string()).or_default() += 1;
    }
    let mut pairs: Vec<_> = counts.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    pairs
}

fn count_strings(items: &[String]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in items {
        *counts.entry(item.clone()).or_default() += 1;
    }
    let mut pairs: Vec<_> = counts.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    pairs
}

fn artifact_location(a: &ArtifactReport) -> &str {
    a.metadata
        .get("paths")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
}

fn top_risk_reasons(a: &ArtifactReport) -> &[String] {
    let len = a.risk_reasons.len().min(2);
    &a.risk_reasons[..len]
}

// ── print_overview ──────────────────────────────────────────────────────

pub fn print_overview(report: &ScanReport) {
    let line = format!("{DIM}{}{RESET}", "─".repeat(52));
    println!();
    println!("{line}");
    println!("  {BOLD}Scanned:{RESET} {CYAN}{}{RESET}", report.scanned_path);
    println!("{line}");
    println!();

    if report.artifacts.is_empty() {
        println!("  {DIM}No AI execution artifacts detected.{RESET}");
        println!();
        return;
    }

    println!("  {BOLD}Found {} artifact(s):{RESET}", report.artifacts.len());
    println!();

    let mut sorted: Vec<&ArtifactReport> = report.artifacts.iter().collect();
    sorted.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

    for a in sorted {
        print_overview_line(a);
    }
    println!();
}

fn print_overview_line(a: &ArtifactReport) {
    let loc = artifact_location(a);
    let (label, color) = severity(a.risk_score);
    let kind = a.artifact_type.replace('_', " ");
    let filled = (a.risk_score / 10) as usize;
    let empty = 10 - filled;
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));

    println!(
        "  {color}{label}{RESET}  {BOLD}{kind:<22}{RESET} \
         {color}{bar}{RESET} {DIM}{:>3}{RESET}  {DIM}{loc}{RESET}",
        a.risk_score
    );
}

// ── print_human ─────────────────────────────────────────────────────────

pub fn print_human(report: &ScanReport) {
    println!();
    println!("AI Execution Inventory");
    println!("{}", "=".repeat(40));
    println!("Run ID:  {}", report.run_id);
    println!("Scanned: {}", report.scanned_path);
    println!("Time:    {}", report.timestamp);
    println!();

    if report.artifacts.is_empty() {
        println!("No AI execution artifacts detected.");
        return;
    }

    print_type_counts(report);
    print_verification_policy();
    print_status_legend();
    print_artifact_details(report);
}

fn print_type_counts(report: &ScanReport) {
    let type_counts = count_by(&report.artifacts, |a| &a.artifact_type);
    let eligible: usize = report.artifacts.iter().filter(|a| a.registry_eligible).count();
    let info = report.artifacts.len() - eligible;

    println!("Detected {} artifact(s):", report.artifacts.len());
    println!("  Verified candidates:     {eligible}");
    println!("  Informational artifacts: {info}");
    for (atype, count) in &type_counts {
        println!("  {atype}: {count}");
    }
    println!();
}

fn print_verification_policy() {
    println!("Verification policy:");
    println!("  pass:             score < 20");
    println!("  conditional_pass: score 20\u{2013}49 (or dangerous combo \u{2192} manual review)");
    println!("  fail:             score \u{2265} 50 (or credential exposure / ungoverned dangerous keyword)");
    println!();
}

fn print_status_legend() {
    println!("Status definitions:");
    println!("  pass = low risk, matches declared/expected patterns");
    println!("  conditional_pass = usable but needs review or limited permissions");
    println!("  fail = high risk / unsafe patterns / likely malicious");
    println!();
}

fn print_artifact_details(report: &ScanReport) {
    for (i, a) in report.artifacts.iter().enumerate() {
        let location = artifact_location(a);
        let hash_short = if a.artifact_hash.len() >= 12 {
            &a.artifact_hash[..12]
        } else if a.artifact_hash.is_empty() {
            "n/a"
        } else {
            &a.artifact_hash
        };
        let eligible = if a.registry_eligible {
            "yes"
        } else {
            "no (informational)"
        };

        println!("  {}. {}", i + 1, a.artifact_type);
        println!("     Location:      {location}");
        println!("     Artifact hash: {hash_short}");
        println!("     Kind:          {}", a.artifact_type);
        println!("     Scope:         {}", a.artifact_scope);
        println!("     Registry:      {eligible}");
        println!("     Schema:        v1");
        println!("     Confidence:    {:.0}%", a.confidence * 100.0);
        println!("     Risk score:    {}", a.risk_score);
        println!("     Status:        {}", a.verification_status);

        let reasons = top_risk_reasons(a);
        if !reasons.is_empty() {
            println!("     Risk reasons: {}", reasons.join(", "));
        }

        let caps = derive_capabilities(a);
        if !caps.is_empty() {
            println!("     Capabilities:");
            for cap in &caps {
                println!("       {cap}");
            }
        }

        if !a.signals.is_empty() {
            println!("     Signals:");
            for sig in &a.signals {
                println!("       {sig}");
            }
        }
        println!();
    }
}

// ── print_summary ───────────────────────────────────────────────────────

pub fn print_summary(report: &ScanReport) {
    println!();
    println!("AI Execution Inventory Summary");
    println!("{}", "-".repeat(40));

    let eligible: Vec<&ArtifactReport> =
        report.artifacts.iter().filter(|a| a.registry_eligible).collect();
    let info_count = report.artifacts.len() - eligible.len();

    println!("Verified candidates:    {}", eligible.len());
    println!("Informational artifacts: {info_count}");
    println!();

    if report.artifacts.is_empty() {
        return;
    }

    print_status_distribution(&eligible);
    print_scope_breakdown(report);
    print_top_capabilities(report);
    print_type_breakdown(report);
    print_risk_drivers(report);
    print_next_actions(&eligible);
}

fn print_status_distribution(eligible: &[&ArtifactReport]) {
    if eligible.is_empty() {
        return;
    }
    let counts = count_by_status(eligible);
    println!("Status distribution (verified):");
    for status in &["pass", "conditional_pass", "fail"] {
        println!("  {status}: {}", counts.get(*status).copied().unwrap_or(0));
    }
    println!();
}

fn count_by_status(artifacts: &[&ArtifactReport]) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for a in artifacts {
        *counts.entry(a.verification_status.clone()).or_default() += 1;
    }
    counts
}

fn print_scope_breakdown(report: &ScanReport) {
    let scope_counts = count_by(&report.artifacts, |a| &a.artifact_scope);
    println!("Artifact scopes:");
    for (scope, count) in &scope_counts {
        println!("  {scope}: {count}");
    }
    println!();
}

fn print_top_capabilities(report: &ScanReport) {
    let mut all_caps: Vec<String> = Vec::new();
    for a in &report.artifacts {
        all_caps.extend(derive_capabilities(a));
    }
    if all_caps.is_empty() {
        return;
    }
    let cap_counts = count_strings(&all_caps);
    println!("Top capabilities detected:");
    for (cap, count) in cap_counts.iter().take(8) {
        println!("  {cap}: {count}");
    }
    println!();
}

fn print_type_breakdown(report: &ScanReport) {
    let type_counts = count_by(&report.artifacts, |a| &a.artifact_type);
    println!("Artifact types:");
    for (atype, count) in &type_counts {
        println!("  {atype}: {count}");
    }
    println!();
}

fn print_risk_drivers(report: &ScanReport) {
    let all_reasons: Vec<String> = report
        .artifacts
        .iter()
        .flat_map(|a| a.risk_reasons.clone())
        .collect();
    if all_reasons.is_empty() {
        return;
    }
    let reason_counts = count_strings(&all_reasons);
    println!("Top risk drivers:");
    for (reason, count) in reason_counts.iter().take(5) {
        println!("  {reason}: {count}");
    }
    println!();
}

fn print_next_actions(eligible: &[&ArtifactReport]) {
    let counts = count_by_status(eligible);
    let actions = [
        ("pass", "allow"),
        ("conditional_pass", "restrict + review"),
        ("fail", "block + investigate"),
    ];

    let present: Vec<_> = actions
        .iter()
        .filter(|(s, _)| counts.get(*s).copied().unwrap_or(0) > 0)
        .collect();

    if present.is_empty() {
        return;
    }

    println!("Recommended next actions:");
    for (status, action) in &present {
        let n = counts[*status];
        println!("  {status} ({n}): {action}");
    }
    println!();
}
