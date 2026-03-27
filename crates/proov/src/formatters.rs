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

// ── Shared helpers ──────────────────────────────────────────────────────

fn shorten_path(path: &str) -> String {
    if let Some(home) = std::env::var_os("HOME") {
        let home = home.to_string_lossy();
        if let Some(rest) = path.strip_prefix(home.as_ref()) {
            return format!("~{rest}");
        }
    }
    path.to_string()
}

fn pretty_type(raw: &str) -> &str {
    match raw {
        "agents_md" => "AGENTS.md",
        "cursor_rules" => "Cursor rules",
        "prompt_config" => "prompt config",
        "mcp_config" => "MCP server config",
        "container_config" => "container config",
        "container_candidate" => "container candidate",
        "browser_footprint" => "browser footprint",
        other => other,
    }
}

fn status_icon(status: &str) -> (&'static str, &'static str) {
    match status {
        "fail" => ("\x1b[31m✗\x1b[0m", "\x1b[31m"),
        "conditional_pass" => ("\x1b[33m⚠\x1b[0m", "\x1b[33m"),
        _ => ("\x1b[32m✓\x1b[0m", "\x1b[32m"),
    }
}

// ── print_overview ──────────────────────────────────────────────────────

pub fn print_overview(report: &ScanReport) {
    let w = 58;
    let line = format!("{DIM}{}{RESET}", "─".repeat(w));

    println!();
    println!("{line}");
    println!("  {BOLD}proov{RESET} · AI Execution Inventory");
    println!("  Scanned: {CYAN}{}{RESET}", report.scanned_path);
    println!("{line}");

    if report.artifacts.is_empty() {
        println!();
        println!("  {DIM}No AI execution artifacts detected.{RESET}");
        println!();
        return;
    }

    // ── Section 1: What was found ───────────────────────────────────
    println!();
    println!(
        "  {BOLD}INVENTORY{RESET}{DIM}{:>width$} artifact(s){RESET}",
        report.artifacts.len(),
        width = w - 21
    );
    println!("  {DIM}{}{RESET}", "─".repeat(w - 2));

    let type_counts = count_by(&report.artifacts, |a| &a.artifact_type);
    for (atype, count) in &type_counts {
        let label = pretty_type(atype);
        println!("  {BOLD}{count:>4}{RESET}  {label}");
    }

    // ── Section 2: What is risky and why ────────────────────────────
    let fail_count = report
        .artifacts
        .iter()
        .filter(|a| a.verification_status == "fail")
        .count();
    let review_count = report
        .artifacts
        .iter()
        .filter(|a| a.verification_status == "conditional_pass")
        .count();
    let pass_count = report
        .artifacts
        .iter()
        .filter(|a| a.verification_status == "pass")
        .count();

    println!();
    let mut status_parts: Vec<String> = Vec::new();
    if fail_count > 0 {
        status_parts.push(format!("\x1b[31m{fail_count} fail\x1b[0m"));
    }
    if review_count > 0 {
        status_parts.push(format!("\x1b[33m{review_count} review\x1b[0m"));
    }
    if pass_count > 0 {
        status_parts.push(format!("\x1b[32m{pass_count} pass\x1b[0m"));
    }
    println!(
        "  {BOLD}RISK{RESET}  {}",
        status_parts.join(&format!(" {DIM}·{RESET} "))
    );
    println!("  {DIM}{}{RESET}", "─".repeat(w - 2));

    let mut sorted: Vec<&ArtifactReport> = report.artifacts.iter().collect();
    sorted.sort_by(|a, b| {
        let rank = |s: &str| match s {
            "fail" => 2,
            "conditional_pass" => 1,
            _ => 0,
        };
        rank(&b.verification_status)
            .cmp(&rank(&a.verification_status))
            .then(b.risk_score.cmp(&a.risk_score))
    });

    // Show all fail + conditional_pass, then up to a few pass items
    let actionable: Vec<&&ArtifactReport> = sorted
        .iter()
        .filter(|a| a.verification_status != "pass")
        .collect();
    let passing: Vec<&&ArtifactReport> = sorted
        .iter()
        .filter(|a| a.verification_status == "pass")
        .collect();

    const MAX_PASS_SHOWN: usize = 3;

    if actionable.is_empty() && passing.is_empty() {
        println!("  {DIM}No artifacts to display.{RESET}");
    }

    for a in &actionable {
        print_risk_card(a);
    }

    if !passing.is_empty() {
        if !actionable.is_empty() {
            println!();
        }
        for a in passing.iter().take(MAX_PASS_SHOWN) {
            print_pass_line(a);
        }
        if passing.len() > MAX_PASS_SHOWN {
            println!(
                "  {DIM}  … and {} more passing artifact(s){RESET}",
                passing.len() - MAX_PASS_SHOWN
            );
        }
    }

    // ── Section 3: Save & share ─────────────────────────────────────
    println!();
    println!("  {BOLD}SAVE & SHARE{RESET}");
    println!("  {DIM}{}{RESET}", "─".repeat(w - 2));
    println!(
        "  {DIM}proov scan --json{RESET}          {DIM}→{RESET} JSON to stdout"
    );
    println!(
        "  {DIM}proov scan --out{RESET}           {DIM}→{RESET} write proov-report.json"
    );
    println!(
        "  {DIM}proov scan --submit{RESET}        {DIM}→{RESET} send to Vettd"
    );
    println!();
}

fn print_risk_card(a: &ArtifactReport) {
    let loc = shorten_path(artifact_location(a));
    let (icon, color) = status_icon(&a.verification_status);
    let label = if a.verification_status == "fail" {
        "FAIL"
    } else {
        "REVIEW"
    };
    let kind = pretty_type(&a.artifact_type);

    println!();
    println!(
        "  {icon} {color}{BOLD}{label}{RESET}  {BOLD}{kind}{RESET}{DIM}{:>width$}{RESET}",
        format!("risk {}", a.risk_score),
        width = 50 - label.len() - kind.len()
    );
    println!("    {DIM}{loc}{RESET}");

    let reasons = top_risk_reasons(a);
    if !reasons.is_empty() {
        println!("    Reason: {}", reasons.join(", "));
    }

    let caps = derive_capabilities(a);
    if !caps.is_empty() {
        println!(
            "    Capabilities: {CYAN}{}{RESET}",
            caps.join(", ")
        );
    }
}

fn print_pass_line(a: &ArtifactReport) {
    let loc = shorten_path(artifact_location(a));
    let (icon, _color) = status_icon(&a.verification_status);
    let kind = pretty_type(&a.artifact_type);
    println!(
        "  {icon} {DIM}PASS{RESET}  {kind:<24} {DIM}{loc}{RESET}"
    );
}

// ── print_human ─────────────────────────────────────────────────────────

pub fn print_human(report: &ScanReport) {
    let w = 58;
    let line = format!("{DIM}{}{RESET}", "─".repeat(w));

    println!();
    println!("{line}");
    println!("  {BOLD}proov{RESET} · AI Execution Inventory  {DIM}(full detail){RESET}");
    println!("  Run ID:  {DIM}{}{RESET}", report.run_id);
    println!("  Scanned: {CYAN}{}{RESET}", report.scanned_path);
    println!("  Time:    {DIM}{}{RESET}", report.timestamp);
    println!("{line}");

    if report.artifacts.is_empty() {
        println!();
        println!("  {DIM}No AI execution artifacts detected.{RESET}");
        println!();
        return;
    }

    print_type_counts(report);
    print_artifact_details(report);
}

fn print_type_counts(report: &ScanReport) {
    let type_counts = count_by(&report.artifacts, |a| &a.artifact_type);

    println!();
    println!(
        "  {BOLD}INVENTORY{RESET}{DIM}{:>width$} artifact(s){RESET}",
        report.artifacts.len(),
        width = 36
    );
    println!("  {DIM}{}{RESET}", "─".repeat(56));
    for (atype, count) in &type_counts {
        let label = pretty_type(atype);
        println!("  {BOLD}{count:>4}{RESET}  {label}");
    }
    println!();
}

fn print_artifact_details(report: &ScanReport) {
    let mut sorted: Vec<&ArtifactReport> = report.artifacts.iter().collect();
    sorted.sort_by(|a, b| {
        let rank = |s: &str| match s {
            "fail" => 2,
            "conditional_pass" => 1,
            _ => 0,
        };
        rank(&b.verification_status)
            .cmp(&rank(&a.verification_status))
            .then(b.risk_score.cmp(&a.risk_score))
    });

    for (i, a) in sorted.iter().enumerate() {
        let loc = shorten_path(artifact_location(a));
        let (icon, color) = status_icon(&a.verification_status);
        let kind = pretty_type(&a.artifact_type);
        let hash_short = if a.artifact_hash.len() >= 12 {
            &a.artifact_hash[..12]
        } else if a.artifact_hash.is_empty() {
            "n/a"
        } else {
            &a.artifact_hash
        };
        let status_label = match a.verification_status.as_str() {
            "fail" => "FAIL",
            "conditional_pass" => "REVIEW",
            _ => "PASS",
        };

        println!(
            "  {icon} {color}{BOLD}{}{RESET}. {BOLD}{kind}{RESET}  {color}{status_label}{RESET}  risk {}{RESET}",
            i + 1,
            a.risk_score
        );
        println!("    {DIM}{loc}{RESET}");
        println!(
            "    {DIM}hash:{RESET} {hash_short}  \
{DIM}scope:{RESET} {}  \
{DIM}confidence:{RESET} {:.0}%",
            a.artifact_scope,
            a.confidence * 100.0
        );

        let reasons = top_risk_reasons(a);
        if !reasons.is_empty() {
            println!("    {DIM}Reason:{RESET} {}", reasons.join(", "));
        }

        let caps = derive_capabilities(a);
        if !caps.is_empty() {
            println!(
                "    {DIM}Capabilities:{RESET} {CYAN}{}{RESET}",
                caps.join(", ")
            );
        }

        if !a.signals.is_empty() {
            println!(
                "    {DIM}Signals:{RESET} {}",
                a.signals.join(", ")
            );
        }
        println!();
    }
}

// ── print_summary ───────────────────────────────────────────────────────

pub fn print_summary(report: &ScanReport) {
    let w = 58;
    let line = format!("{DIM}{}{RESET}", "─".repeat(w));

    println!();
    println!("{line}");
    println!("  {BOLD}proov{RESET} · Summary");
    println!("{line}");

    if report.artifacts.is_empty() {
        println!();
        println!("  {DIM}No AI execution artifacts detected.{RESET}");
        println!();
        return;
    }

    let eligible: Vec<&ArtifactReport> =
        report.artifacts.iter().filter(|a| a.registry_eligible).collect();

    // Counts by type
    let type_counts = count_by(&report.artifacts, |a| &a.artifact_type);
    println!();
    println!(
        "  {BOLD}INVENTORY{RESET}{DIM}{:>width$} artifact(s){RESET}",
        report.artifacts.len(),
        width = w - 21
    );
    for (atype, count) in &type_counts {
        let label = pretty_type(atype);
        println!("  {BOLD}{count:>4}{RESET}  {label}");
    }

    // Status distribution
    println!();
    print_status_distribution(&eligible);
    print_top_capabilities(report);
    print_risk_drivers(report);
    print_next_actions(&eligible);
}

fn print_status_distribution(eligible: &[&ArtifactReport]) {
    if eligible.is_empty() {
        return;
    }
    let counts = count_by_status(eligible);
    let fail = counts.get("fail").copied().unwrap_or(0);
    let review = counts.get("conditional_pass").copied().unwrap_or(0);
    let pass = counts.get("pass").copied().unwrap_or(0);

    let mut parts: Vec<String> = Vec::new();
    if fail > 0 {
        parts.push(format!("\x1b[31m{fail} fail\x1b[0m"));
    }
    if review > 0 {
        parts.push(format!("\x1b[33m{review} review\x1b[0m"));
    }
    if pass > 0 {
        parts.push(format!("\x1b[32m{pass} pass\x1b[0m"));
    }
    println!(
        "  {BOLD}STATUS{RESET}  {}",
        parts.join(&format!(" {DIM}·{RESET} "))
    );
    println!();
}

fn count_by_status(artifacts: &[&ArtifactReport]) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for a in artifacts {
        *counts.entry(a.verification_status.clone()).or_default() += 1;
    }
    counts
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
    println!("  {BOLD}CAPABILITIES{RESET}");
    for (cap, count) in cap_counts.iter().take(8) {
        println!("  {BOLD}{count:>4}{RESET}  {cap}");
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
    println!("  {BOLD}TOP RISK DRIVERS{RESET}");
    for (reason, count) in reason_counts.iter().take(5) {
        println!("  {BOLD}{count:>4}{RESET}  {reason}");
    }
    println!();
}

fn print_next_actions(eligible: &[&ArtifactReport]) {
    let counts = count_by_status(eligible);
    let actions: &[(&str, &str, &str)] = &[
        ("fail", "\x1b[31m", "block + investigate"),
        ("conditional_pass", "\x1b[33m", "restrict + review"),
        ("pass", "\x1b[32m", "allow"),
    ];

    let present: Vec<_> = actions
        .iter()
        .filter(|(s, _, _)| counts.get(*s).copied().unwrap_or(0) > 0)
        .collect();

    if present.is_empty() {
        return;
    }

    println!("  {BOLD}NEXT ACTIONS{RESET}");
    for (status, color, action) in &present {
        let n = counts[*status];
        println!("  {color}{n:>4}{RESET}  {status} → {action}");
    }
    println!();
}
