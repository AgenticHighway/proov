use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

use crate::formatters::{print_human, print_overview, print_summary};
use crate::lite_mode::{limit_lite_mode_report, print_locked_summary, LITE_MODE_VISIBLE_RESULTS};
use crate::models::ScanReport;
use crate::plugins;
use crate::scan::run_scan;
use crate::submit::load_submission_config;

// ---------------------------------------------------------------------------
// CLI argument definitions
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "ah-scan",
    about = "AI Execution Inventory — detect, analyze, and report AI execution artifacts."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan critical user config areas
    Quick {
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Full system scan
    Full {
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Scan a single file
    File {
        path: PathBuf,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Scan a folder
    Folder {
        path: PathBuf,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Deep-scan a local git repo
    Repo {
        path: PathBuf,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Manage detector plugins
    Plugins {
        #[command(subcommand)]
        action: PluginAction,
    },
}

#[derive(Subcommand)]
pub enum PluginAction {
    /// List installed detector plugins
    List,
    /// Install a .wasm detector plugin
    Install {
        /// Path to the .wasm file to install
        path: PathBuf,
    },
    /// Remove an installed detector plugin
    Remove {
        /// Name of the plugin to remove (without .wasm extension)
        name: String,
    },
    /// Show details about an installed plugin
    Info {
        /// Name of the plugin
        name: String,
    },
}

#[derive(clap::Args)]
pub struct OutputArgs {
    /// Full per-artifact detail output
    #[arg(long)]
    pub full: bool,
    /// Output JSON to stdout
    #[arg(long)]
    pub json: bool,
    /// Print compact summary only
    #[arg(long)]
    pub summary: bool,
    /// Write JSON report to file
    #[arg(long, value_name = "FILE")]
    pub out: Option<Option<PathBuf>>,
    /// Minimum severity: critical|high|medium|low|info
    #[arg(long, default_value = "info")]
    pub min_severity: String,
}

// ---------------------------------------------------------------------------
// Access configuration
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct AccessConfig {
    mode: String,
    license_key: Option<String>,
    endpoint: Option<String>,
    license_timeout_seconds: f64,
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            mode: "licensed".into(),
            license_key: None,
            endpoint: None,
            license_timeout_seconds: 5.0,
        }
    }
}

fn load_access_config() -> AccessConfig {
    let path = Path::new(".ahscan.toml");
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return AccessConfig::default(),
    };

    let table: toml::Table = match content.parse() {
        Ok(t) => t,
        Err(_) => return AccessConfig::default(),
    };

    let access = match table.get("access") {
        Some(toml::Value::Table(t)) => t,
        _ => return AccessConfig::default(),
    };

    let mut cfg = AccessConfig::default();

    if let Some(toml::Value::String(v)) = access.get("mode") {
        cfg.mode = v.clone();
    }
    if let Some(toml::Value::String(v)) = access.get("license_key") {
        cfg.license_key = Some(v.clone());
    }
    if let Some(toml::Value::String(v)) = access.get("endpoint") {
        cfg.endpoint = Some(v.clone());
    }
    if let Some(toml::Value::Float(v)) = access.get("license_timeout_seconds") {
        cfg.license_timeout_seconds = *v;
    }

    cfg
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

fn min_severity_score(level: &str) -> i32 {
    match level {
        "critical" => 90,
        "high" => 70,
        "medium" => 40,
        "low" => 10,
        _ => 0,
    }
}

fn filter_by_severity(report: &mut ScanReport, min_score: i32) {
    report.artifacts.retain(|a| a.risk_score >= min_score);
}

// ---------------------------------------------------------------------------
// Scan dispatch
// ---------------------------------------------------------------------------

struct ScanParams<'a> {
    mode: &'a str,
    workdir: Option<&'a Path>,
    file: Option<&'a Path>,
    deep: bool,
}

fn resolve_scan_params(cmd: &Commands) -> ScanParams<'_> {
    match cmd {
        Commands::Quick { .. } => ScanParams {
            mode: "host",
            workdir: None,
            file: None,
            deep: false,
        },
        Commands::Full { .. } => ScanParams {
            mode: "filesystem",
            workdir: None,
            file: None,
            deep: false,
        },
        Commands::File { path, .. } => ScanParams {
            mode: "file",
            workdir: None,
            file: Some(path.as_path()),
            deep: false,
        },
        Commands::Folder { path, .. } => ScanParams {
            mode: "workdir",
            workdir: Some(path.as_path()),
            file: None,
            deep: false,
        },
        Commands::Repo { path, .. } => ScanParams {
            mode: "workdir",
            workdir: Some(path.as_path()),
            file: None,
            deep: true,
        },
        Commands::Plugins { .. } => unreachable!("handled before scan dispatch"),
    }
}

fn output_args(cmd: &Commands) -> &OutputArgs {
    match cmd {
        Commands::Quick { output, .. }
        | Commands::Full { output, .. }
        | Commands::File { output, .. }
        | Commands::Folder { output, .. }
        | Commands::Repo { output, .. } => output,
        Commands::Plugins { .. } => unreachable!("handled before output dispatch"),
    }
}

// ---------------------------------------------------------------------------
// Output emission
// ---------------------------------------------------------------------------

fn emit(
    report: &ScanReport,
    json_output: bool,
    out: &Option<Option<PathBuf>>,
    summary: bool,
    full: bool,
) {
    if json_output {
        println!("{}", report.to_json(true));
    } else if summary {
        print_summary(report);
    } else if full {
        print_human(report);
    } else {
        print_overview(report);
    }

    if let Some(maybe_path) = out {
        let dest = match maybe_path {
            Some(p) => p.clone(),
            None => PathBuf::from("ahscan-report.json"),
        };
        let json = report.to_json(true);
        if let Err(e) = fs::write(&dest, &json) {
            eprintln!("Error writing report to {}: {}", dest.display(), e);
        } else {
            eprintln!("Report written to {}", dest.display());
        }
    }
}

// ---------------------------------------------------------------------------
// Access gate
// ---------------------------------------------------------------------------

fn apply_access_gate(report: ScanReport, access: &AccessConfig) -> ScanReport {
    if access.mode == "lite" {
        let (limited, _hidden_count, hidden_artifacts) =
            limit_lite_mode_report(&report, LITE_MODE_VISIBLE_RESULTS);
        if !hidden_artifacts.is_empty() {
            print_locked_summary(&hidden_artifacts);
        }
        limited
    } else {
        report
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run() {
    let cli = Cli::parse();

    let cmd = match cli.command {
        Some(c) => c,
        None => {
            println!("Interactive wizard — run with a subcommand");
            return;
        }
    };

    // Handle plugin management separately
    if let Commands::Plugins { action } = cmd {
        plugins::handle_plugin_action(&action);
        return;
    }

    let access = load_access_config();
    let _submission = load_submission_config(None);

    let params = resolve_scan_params(&cmd);
    let out = output_args(&cmd);
    let min_score = min_severity_score(&out.min_severity);

    let mut report = run_scan(params.mode, params.workdir, params.file, params.deep, None);

    report = apply_access_gate(report, &access);
    filter_by_severity(&mut report, min_score);

    emit(&report, out.json, &out.out, out.summary, out.full);
}
