use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

use crate::contract::build_contract_payload;
use crate::formatters::{print_human, print_overview, print_summary};
use crate::lite_mode::{limit_lite_mode_report, print_locked_summary, LITE_MODE_VISIBLE_RESULTS};
use crate::models::ScanReport;
use crate::plugins;
use crate::scan::run_scan;
use crate::submit::{load_auth_config, load_submission_config, save_auth_config, submit_contract_payload, AuthConfig, DEFAULT_PRODUCTION_ENDPOINT};

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
    /// Configure API credentials for scan submission
    Auth {
        /// API key (e.g. ah_xxxx)
        #[arg(long)]
        key: String,
        /// Ingest endpoint URL (defaults to production)
        #[arg(long)]
        endpoint: Option<String>,
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
    /// Output JSON conforming to the AH-Verify data contract
    #[arg(long)]
    pub contract: bool,
    /// Submit scan results to the given URL (or the configured default)
    #[arg(long, value_name = "URL")]
    pub submit: Option<Option<String>>,
    /// API key for submission (overrides config file)
    #[arg(long, value_name = "KEY")]
    pub api_key: Option<String>,
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
        Commands::Plugins { .. } | Commands::Auth { .. } => {
            unreachable!("handled before scan dispatch")
        }
    }
}

fn output_args(cmd: &Commands) -> &OutputArgs {
    match cmd {
        Commands::Quick { output, .. }
        | Commands::Full { output, .. }
        | Commands::File { output, .. }
        | Commands::Folder { output, .. }
        | Commands::Repo { output, .. } => output,
        Commands::Plugins { .. } | Commands::Auth { .. } => {
            unreachable!("handled before output dispatch")
        }
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
            crate::wizard::run_wizard();
            return;
        }
    };

    // Handle plugin management separately
    if let Commands::Plugins { action } = cmd {
        plugins::handle_plugin_action(&action);
        return;
    }

    // Handle auth command
    if let Commands::Auth { key, endpoint } = &cmd {
        let config = AuthConfig {
            endpoint: endpoint
                .clone()
                .unwrap_or_else(|| DEFAULT_PRODUCTION_ENDPOINT.to_string()),
            api_key: key.clone(),
        };
        match save_auth_config(&config) {
            Ok(()) => {
                eprintln!("Credentials saved.");
                eprintln!("  Endpoint: {}", config.endpoint);
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    let access = load_access_config();
    let _submission = load_submission_config(None);

    let params = resolve_scan_params(&cmd);
    let out = output_args(&cmd);
    let min_score = min_severity_score(&out.min_severity);

    let scan_start = std::time::Instant::now();
    let mut report = run_scan(params.mode, params.workdir, params.file, params.deep, None);
    let scan_duration_ms = scan_start.elapsed().as_millis() as u64;

    report = apply_access_gate(report, &access);
    filter_by_severity(&mut report, min_score);

    let wants_submit = out.submit.is_some();

    if out.contract {
        let payload = build_contract_payload(&report, scan_duration_ms);
        let json = serde_json::to_string_pretty(&payload)
            .expect("contract payload serialization");

        if !wants_submit {
            println!("{json}");
        }

        if let Some(maybe_path) = &out.out {
            let dest = match maybe_path {
                Some(p) => p.clone(),
                None => PathBuf::from("ahscan-contract.json"),
            };
            if let Err(e) = fs::write(&dest, &json) {
                eprintln!("Error writing contract to {}: {}", dest.display(), e);
            } else {
                eprintln!("Contract written to {}", dest.display());
            }
        }

        if wants_submit {
            do_submit(&json, &out.submit, out.api_key.as_deref());
        }
    } else if wants_submit {
        // --submit without --contract: build contract payload automatically
        let payload = build_contract_payload(&report, scan_duration_ms);
        let json = serde_json::to_string_pretty(&payload)
            .expect("contract payload serialization");

        // Write to file
        let dest = match &out.out {
            Some(Some(p)) => p.clone(),
            _ => PathBuf::from("ahscan-contract.json"),
        };
        if let Err(e) = fs::write(&dest, &json) {
            eprintln!("Error writing contract to {}: {}", dest.display(), e);
        } else {
            eprintln!("Contract written to {}", dest.display());
        }

        do_submit(&json, &out.submit, out.api_key.as_deref());
    } else {
        emit(&report, out.json, &out.out, out.summary, out.full);
    }
}

/// Resolve auth (from flags + config file) and POST the payload.
fn do_submit(
    payload_json: &str,
    submit_flag: &Option<Option<String>>,
    api_key_flag: Option<&str>,
) {
    // Load saved config as baseline
    let saved = load_auth_config();

    // Resolve endpoint: --submit <url> > config file > default
    let endpoint = match submit_flag {
        Some(Some(url)) => url.clone(),
        _ => saved
            .as_ref()
            .map(|c| c.endpoint.clone())
            .unwrap_or_else(|| DEFAULT_PRODUCTION_ENDPOINT.to_string()),
    };

    // Resolve API key: --api-key > config file
    let api_key = match api_key_flag {
        Some(k) => k.to_string(),
        None => match saved.as_ref().map(|c| c.api_key.clone()) {
            Some(k) => k,
            None => {
                eprintln!(
                    "No API key provided. Pass --api-key or run `ah-scan auth --key <your-key>`."
                );
                std::process::exit(1);
            }
        },
    };

    let auth = AuthConfig {
        endpoint,
        api_key,
    };

    eprintln!("Submitting scan to {}...", auth.endpoint);
    match submit_contract_payload(payload_json, &auth) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Submission failed: {e}");
            std::process::exit(1);
        }
    }
}
