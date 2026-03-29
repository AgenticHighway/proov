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

// ── Human-readable signal/reason labels ─────────────────────────────────

fn humanize_reason(raw: &str) -> &str {
    // Strip the "(+N)" weight suffix to match the signal key
    let key = raw.split(" (+").next().unwrap_or(raw);
    match key {
        "keyword:api" => "Makes external API calls",
        "keyword:shell" => "Runs shell commands",
        "keyword:browser" => "Controls a browser",
        "keyword:execute" => "Executes code at runtime",
        "keyword:network" => "Accesses the network",
        "keyword:filesystem" => "Reads/writes the filesystem",
        "keyword:docker" => "Uses container runtimes",
        "keyword:system" => "Sets or overrides the system prompt",
        "keyword:permissions" => "Requests elevated permissions",
        "keyword:tools" => "Declares callable tools",
        "keyword:dependencies" => "Installs or runs dependencies",
        "keyword:secrets" => "References secrets or credentials",
        "keyword:instructions" => "Contains instruction directives",
        "credential_exposure_signal" => "Credential / secret exposure",
        "mcp_server_declared" => "Declares an MCP server",
        "dangerous_combo:shell+network+fs" => "Shell + network + filesystem combined",
        "dangerous_keyword:exfiltrate" => "References data exfiltration",
        "dangerous_keyword:wipe" => "References destructive wiping",
        "dangerous_keyword:rm" => "References file deletion",
        "dangerous_keyword:steal" => "References data theft",
        "dangerous_keyword:upload" => "References data upload",
        "dangerous_keyword:reverse" => "References reverse connection",
        "dangerous_keyword:disable" => "References disabling protections",
        "dangerous_keyword:bypass" => "References bypassing controls",
        "extensions_directory_present" => "Browser extensions directory found",
        _ if key.starts_with("extension_count:") => "Browser extensions installed",
        _ if key.starts_with("mcp_server_count:") => "Multiple MCP servers declared",
        _ => raw,
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
    let counts = count_by_status(&eligible);
    let fail_n = counts.get("fail").copied().unwrap_or(0);
    let review_n = counts.get("conditional_pass").copied().unwrap_or(0);
    let pass_n = counts.get("pass").copied().unwrap_or(0);

    // ── Posture headline ────────────────────────────────────────────
    println!();
    let mut parts: Vec<String> = Vec::new();
    if fail_n > 0 {
        parts.push(format!("\x1b[31m{fail_n} blocked\x1b[0m"));
    }
    if review_n > 0 {
        parts.push(format!("\x1b[33m{review_n} need review\x1b[0m"));
    }
    if pass_n > 0 {
        parts.push(format!("\x1b[32m{pass_n} clear\x1b[0m"));
    }
    println!(
        "  {}",
        parts.join(&format!("  {DIM}·{RESET}  "))
    );

    // ── Blocked items (listed individually — usually few) ───────────
    let mut sorted: Vec<&ArtifactReport> = eligible.to_vec();
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

    let blocked: Vec<&&ArtifactReport> = sorted
        .iter()
        .filter(|a| a.verification_status == "fail")
        .collect();

    if !blocked.is_empty() {
        println!();
        println!(
            "  \x1b[31m{BOLD}BLOCKED{RESET} {DIM}── investigate before use{RESET}"
        );
        println!("  {DIM}{}{RESET}", "─".repeat(w - 2));
        for a in &blocked {
            print_summary_card(a);
        }
    }

    // ── Review items (grouped by top risk reason) ───────────────────
    let review: Vec<&&ArtifactReport> = sorted
        .iter()
        .filter(|a| a.verification_status == "conditional_pass")
        .collect();

    if !review.is_empty() {
        println!();
        println!(
            "  \x1b[33m{BOLD}NEEDS REVIEW{RESET} {DIM}── restrict until reviewed{RESET}"
        );
        println!("  {DIM}{}{RESET}", "─".repeat(w - 2));
        print_review_groups(&review, w);
    }

    // ── Clear items (compact one-liner) ─────────────────────────────
    if pass_n > 0 {
        println!();
        println!(
            "  \x1b[32m{BOLD}CLEAR{RESET} {DIM}── {pass_n} artifact(s) passed all checks{RESET}"
        );
    }

    // ── Compact inventory ───────────────────────────────────────────
    let type_counts = count_by(&report.artifacts, |a| &a.artifact_type);
    let inventory_parts: Vec<String> = type_counts
        .iter()
        .map(|(t, c)| format!("{c} {}", pretty_type(t)))
        .collect();
    println!();
    println!(
        "  {DIM}Scanned {total} artifact(s): {list}{RESET}",
        total = report.artifacts.len(),
        list = inventory_parts.join(", ")
    );
    println!();
}

fn print_summary_card(a: &ArtifactReport) {
    let loc = shorten_path(artifact_location(a));
    let (icon, _) = status_icon(&a.verification_status);
    let kind = pretty_type(&a.artifact_type);

    println!(
        "  {icon}  {BOLD}{kind}{RESET}  {DIM}risk {}{RESET}",
        a.risk_score
    );
    println!("     {DIM}{loc}{RESET}");

    let reasons = top_risk_reasons(a);
    if !reasons.is_empty() {
        let human: Vec<&str> = reasons.iter().map(|r| humanize_reason(r)).collect();
        println!("     {CYAN}{}{RESET}", human.join(", "));
    }
}

/// Group review artifacts by their top risk reason and show counts.
fn print_review_groups(items: &[&&ArtifactReport], _w: usize) {
    // Build groups keyed by the first (highest-weight) risk reason.
    let mut groups: Vec<(String, Vec<&ArtifactReport>)> = Vec::new();
    let mut group_map: HashMap<String, usize> = HashMap::new();

    for a in items {
        let key = a
            .risk_reasons
            .first()
            .map(|r| humanize_reason(r).to_string())
            .unwrap_or_else(|| "Other".to_string());

        if let Some(&idx) = group_map.get(&key) {
            groups[idx].1.push(a);
        } else {
            group_map.insert(key.clone(), groups.len());
            groups.push((key, vec![a]));
        }
    }

    // Sort groups by count descending
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    const MAX_EXAMPLES: usize = 2;

    for (reason, members) in &groups {
        let n = members.len();
        let plural = if n == 1 { "" } else { "s" };
        println!(
            "  \x1b[33m⚠{RESET}  {BOLD}{reason}{RESET}  {DIM}({n} artifact{plural}){RESET}"
        );

        // Show a couple of example paths
        for a in members.iter().take(MAX_EXAMPLES) {
            let loc = shorten_path(artifact_location(a));
            let kind = pretty_type(&a.artifact_type);
            println!(
                "     {DIM}{kind} · {loc}{RESET}"
            );
        }
        if n > MAX_EXAMPLES {
            println!(
                "     {DIM}… and {} more{RESET}",
                n - MAX_EXAMPLES
            );
        }
    }
}

fn count_by_status(artifacts: &[&ArtifactReport]) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for a in artifacts {
        *counts.entry(a.verification_status.clone()).or_default() += 1;
    }
    counts
}
