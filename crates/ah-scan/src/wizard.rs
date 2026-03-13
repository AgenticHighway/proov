//! Interactive wizard for ah-scan.
//!
//! Presents a guided menu for scanning, viewing results, and choosing output
//! formats.  Uses crossterm for raw key input when running in a TTY; falls
//! back to numbered text menus otherwise.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    terminal,
};

use crate::formatters::{print_human, print_overview, print_summary, severity};
use crate::models::ScanReport;
use crate::progress::ScanProgress;
use crate::scan::run_scan;

// ── ANSI constants ──────────────────────────────────────────────────────

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const INV: &str = "\x1b[7m";

// ── Low-level key reading ───────────────────────────────────────────────

fn is_tty() -> bool {
    io::stdin().is_terminal()
}

fn read_key() -> String {
    loop {
        if let Ok(Event::Key(KeyEvent { code, modifiers, .. })) = event::read() {
            if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
                return "ctrl-c".to_string();
            }
            return match code {
                KeyCode::Up => "up".to_string(),
                KeyCode::Down => "down".to_string(),
                KeyCode::Left => "left".to_string(),
                KeyCode::Right => "right".to_string(),
                KeyCode::Enter => "enter".to_string(),
                KeyCode::Esc => "esc".to_string(),
                KeyCode::Char(c) => c.to_string(),
                _ => continue,
            };
        }
    }
}

// ── Prompt helpers ──────────────────────────────────────────────────────

fn ask(prompt: &str, default: &str) -> String {
    if default.is_empty() {
        eprint!("  {prompt}: ");
    } else {
        eprint!("  {prompt} [{default}]: ");
    }
    let _ = io::stderr().flush();

    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line).is_err() {
        return default.to_string();
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

fn confirm(prompt: &str, default: bool) -> bool {
    if !is_tty() {
        let hint = if default { "Y/n" } else { "y/N" };
        let ans = ask(&format!("{prompt} ({hint})"), "");
        return match ans.to_lowercase().as_str() {
            "y" | "yes" => true,
            "n" | "no" => false,
            _ => default,
        };
    }

    let mut value = default;
    terminal::enable_raw_mode().ok();

    loop {
        let yes_style = if value { format!("{INV} Yes {RESET}") } else { " Yes ".to_string() };
        let no_style = if !value { format!("{INV} No {RESET}") } else { " No ".to_string() };
        eprint!("\r\x1b[K  {prompt}  {yes_style}  {no_style}");
        let _ = io::stderr().flush();

        match read_key().as_str() {
            "left" | "right" | "y" | "n" => value = !value,
            "enter" => break,
            "ctrl-c" | "esc" => {
                terminal::disable_raw_mode().ok();
                graceful_exit();
            }
            _ => {}
        }
    }
    terminal::disable_raw_mode().ok();
    eprintln!();
    value
}

fn pick(prompt: &str, options: &[&str], default: usize) -> usize {
    if !is_tty() {
        return pick_fallback(prompt, options, default);
    }

    let mut idx = default;
    terminal::enable_raw_mode().ok();

    loop {
        render_pick_menu(prompt, options, idx);
        match read_key().as_str() {
            "up" | "k" if idx > 0 => idx -= 1,
            "down" | "j" if idx + 1 < options.len() => idx += 1,
            "enter" => break,
            "ctrl-c" | "esc" => {
                terminal::disable_raw_mode().ok();
                graceful_exit();
            }
            _ => {}
        }
    }
    terminal::disable_raw_mode().ok();
    clear_pick_menu(options.len());
    eprintln!("  {prompt}: {CYAN}{}{RESET}", options[idx]);
    idx
}

fn render_pick_menu(prompt: &str, options: &[&str], selected: usize) {
    eprint!("\r\x1b[K  {BOLD}{prompt}{RESET}\r\n");
    for (i, opt) in options.iter().enumerate() {
        if i == selected {
            eprint!("\r\x1b[K    {CYAN}❯{RESET} {INV} {opt} {RESET}\r\n");
        } else {
            eprint!("\r\x1b[K      {DIM}{opt}{RESET}\r\n");
        }
    }
    // Move cursor back up
    let up = options.len() + 1;
    eprint!("\x1b[{up}A");
    let _ = io::stderr().flush();
}

fn clear_pick_menu(option_count: usize) {
    for _ in 0..=option_count {
        eprint!("\r\x1b[K\r\n");
    }
    let up = option_count + 1;
    eprint!("\x1b[{up}A");
    let _ = io::stderr().flush();
}

fn pick_fallback(prompt: &str, options: &[&str], default: usize) -> usize {
    eprintln!("  {prompt}:");
    for (i, opt) in options.iter().enumerate() {
        let marker = if i == default { " (default)" } else { "" };
        eprintln!("    {}: {opt}{marker}", i + 1);
    }
    let ans = ask("Choice", &(default + 1).to_string());
    ans.parse::<usize>()
        .ok()
        .filter(|&v| v >= 1 && v <= options.len())
        .map(|v| v - 1)
        .unwrap_or(default)
}

fn graceful_exit() -> ! {
    eprintln!("\r\x1b[K");
    eprintln!("  {DIM}Cancelled.{RESET}");
    std::process::exit(0);
}

// ── Banner ──────────────────────────────────────────────────────────────

fn print_banner() {
    eprintln!();
    eprintln!("  {DIM}┌──────────────────────────────────────────┐{RESET}");
    eprintln!("  {DIM}│{RESET}  {BOLD}{CYAN}ah-scan{RESET}  —  AI Execution Inventory       {DIM}│{RESET}");
    eprintln!("  {DIM}└──────────────────────────────────────────┘{RESET}");
    eprintln!();
}

// ── Wizard steps ────────────────────────────────────────────────────────

fn step_choose_mode() -> (String, Option<PathBuf>) {
    let modes = &[
        "Quick scan  (host config areas)",
        "Full scan   (entire filesystem)",
        "Folder scan (specific directory)",
        "Repo scan   (deep git repo scan)",
        "File scan   (single file)",
    ];
    let idx = pick("Scan mode", modes, 0);

    match idx {
        0 => ("host".to_string(), None),
        1 => ("filesystem".to_string(), None),
        2 => {
            let dir = ask("Directory path", ".");
            (
                "workdir".to_string(),
                Some(PathBuf::from(dir)),
            )
        }
        3 => {
            let dir = ask("Repo path", ".");
            (
                "workdir_deep".to_string(),
                Some(PathBuf::from(dir)),
            )
        }
        4 => {
            let path = ask("File path", "");
            ("file".to_string(), Some(PathBuf::from(path)))
        }
        _ => ("host".to_string(), None),
    }
}

fn step_run_scan(mode: &str, workdir: Option<&PathBuf>) -> ScanReport {
    eprintln!();
    let mut progress = ScanProgress::new(false);
    progress.phase("Scanning");

    let deep = mode == "workdir_deep";
    let scan_mode = if mode == "workdir_deep" { "workdir" } else { mode };

    let report = run_scan(
        scan_mode,
        workdir.map(|p| p.as_path()),
        workdir.filter(|_| scan_mode == "file").map(|p| p.as_path()),
        deep,
        Some(&|detail: &str| {
            // Progress tick writes directly — ScanProgress is not accessible
            // from the closure without interior mutability, so we write inline.
            eprint!(
                "\r\x1b[K  {CYAN}⠿{RESET} Scanning  {}  ",
                detail
            );
            let _ = io::stderr().flush();
        }),
    );

    progress.done(Some(&format!(
        "Found {} artifact(s)",
        report.artifacts.len()
    )));
    eprintln!();

    print_severity_bars(&report);
    report
}

fn print_severity_bars(report: &ScanReport) {
    if report.artifacts.is_empty() {
        eprintln!("  {DIM}No artifacts found.{RESET}");
        eprintln!();
        return;
    }

    let mut sorted: Vec<_> = report.artifacts.iter().collect();
    sorted.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

    for a in sorted.iter().take(12) {
        let (label, color) = severity(a.risk_score);
        let kind = a.artifact_type.replace('_', " ");
        let filled = (a.risk_score / 10) as usize;
        let empty = 10 - filled;
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));
        eprintln!(
            "  {color}{label}{RESET}  {BOLD}{kind:<22}{RESET} {color}{bar}{RESET} {DIM}{:>3}{RESET}",
            a.risk_score
        );
    }
    if sorted.len() > 12 {
        eprintln!("  {DIM}… and {} more{RESET}", sorted.len() - 12);
    }
    eprintln!();
}

// ── Output step ─────────────────────────────────────────────────────────

fn step_choose_output(report: &ScanReport) {
    let formats = &["Overview (default)", "Full detail", "Summary", "JSON"];
    let idx = pick("Output format", formats, 0);

    match idx {
        0 => print_overview(report),
        1 => print_human(report),
        2 => print_summary(report),
        3 => println!("{}", report.to_json(true)),
        _ => print_overview(report),
    }
}

fn offer_save(report: &ScanReport) {
    if !confirm("Save JSON report to file?", false) {
        return;
    }
    let dest = ask("Output path", "ahscan-report.json");
    let json = report.to_json(true);
    match std::fs::write(&dest, &json) {
        Ok(()) => eprintln!("  {DIM}Saved to {dest}{RESET}"),
        Err(e) => eprintln!("  Error: {e}"),
    }
}

// ── Menu loop ───────────────────────────────────────────────────────────

fn menu_loop(report: &ScanReport) {
    loop {
        let actions = &[
            "View output (change format)",
            "Save JSON to file",
            "Run another scan",
            "Exit",
        ];
        let idx = pick("What next?", actions, 0);

        match idx {
            0 => step_choose_output(report),
            1 => offer_save(report),
            2 => {
                let (mode, workdir) = step_choose_mode();
                let new_report = step_run_scan(&mode, workdir.as_ref());
                step_choose_output(&new_report);
                menu_loop(&new_report);
                return;
            }
            3 => {
                eprintln!("  {DIM}Goodbye.{RESET}");
                return;
            }
            _ => return,
        }
    }
}

// ── Public entry point ──────────────────────────────────────────────────

pub fn run_wizard() {
    print_banner();

    let (mode, workdir) = step_choose_mode();
    let report = step_run_scan(&mode, workdir.as_ref());

    step_choose_output(&report);
    menu_loop(&report);
}
