use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

use crate::contract::build_contract_payload;
use crate::lite_mode::{limit_lite_mode_report, print_locked_summary, LITE_MODE_VISIBLE_RESULTS};
use crate::models::ScanReport;
use crate::output::{do_submit, emit};
use crate::scan::run_scan;
use crate::submit::{load_submission_config, save_auth_config, AuthConfig, DEFAULT_PRODUCTION_ENDPOINT};

// ---------------------------------------------------------------------------
// CLI argument definitions
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "proov",
    about = "AI Execution Inventory — detect, analyze, and report AI execution artifacts.",
    version = env!("CARGO_PKG_VERSION"),
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Default scan — home directory, recursive
    Scan {
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Quick scan — agentic config areas (Cursor, VS Code, Claude, etc.)
    Quick {
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Full scan — entire filesystem from root
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
    /// Configure API credentials for scan submission
    Auth {
        /// API key (e.g. ah_xxxx)
        #[arg(long)]
        key: String,
        /// Ingest endpoint URL (defaults to production)
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Run (or re-run) the interactive setup wizard
    Setup,
    /// Check for updates and self-update the scanner binary
    Update {
        /// Only check for updates — don't download or install
        #[arg(long)]
        check: bool,
        /// Skip the confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Manage custom detection rules
    Rules {
        #[command(subcommand)]
        action: RuleAction,
    },
}

#[derive(Subcommand)]
pub enum RuleAction {
    /// List installed rules
    List,
    /// Install a rule file into ~/.ahscan/rules/
    Add {
        /// Path to the .toml rule file
        path: PathBuf,
    },
    /// Remove an installed rule by name (e.g. terraform-ai or terraform-ai.toml)
    Remove {
        /// Rule name or filename
        name: String,
    },
    /// Validate a rule file without installing it
    Validate {
        /// Path to the .toml rule file
        path: PathBuf,
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
        Commands::Scan { .. } => ScanParams {
            mode: "home",
            workdir: None,
            file: None,
            deep: false,
        },
        Commands::Quick { .. } => ScanParams {
            mode: "host",
            workdir: None,
            file: None,
            deep: false,
        },
        Commands::Full { .. } => ScanParams {
            mode: "root",
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
        Commands::Auth { .. } | Commands::Setup | Commands::Update { .. } | Commands::Rules { .. } => {
            unreachable!("handled before scan dispatch")
        }
    }
}

fn output_args(cmd: &Commands) -> &OutputArgs {
    match cmd {
        Commands::Scan { output, .. }
        | Commands::Quick { output, .. }
        | Commands::Full { output, .. }
        | Commands::File { output, .. }
        | Commands::Folder { output, .. }
        | Commands::Repo { output, .. } => output,
        Commands::Auth { .. } | Commands::Setup | Commands::Update { .. } | Commands::Rules { .. } => {
            unreachable!("handled before output dispatch")
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

    // Handle rules subcommand
    if let Commands::Rules { action } = &cmd {
        match action {
            RuleAction::List => crate::rules::cmd_list(),
            RuleAction::Add { path } => crate::rules::cmd_add(path),
            RuleAction::Remove { name } => crate::rules::cmd_remove(name),
            RuleAction::Validate { path } => crate::rules::cmd_validate(path),
        }
        return;
    }

    // Handle setup command
    if matches!(cmd, Commands::Setup) {
        crate::setup::run_setup(true);
        return;
    }

    // Handle update command
    if let Commands::Update { check, force } = &cmd {
        if *check {
            match crate::updater::check_for_update(10) {
                Ok(result) => {
                    if result.is_newer {
                        eprintln!(
                            "Update available: {} → {}",
                            result.current_version, result.latest_version
                        );
                        eprintln!("Run `proov update` to install.");
                    } else {
                        eprintln!(
                            "You are running the latest version ({}).",
                            result.current_version
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Update check failed: {e}");
                    std::process::exit(1);
                }
            }
        } else if let Err(e) = crate::updater::perform_update(*force) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
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

    // Validate file/folder paths exist before scanning
    match &cmd {
        Commands::File { path, .. } => {
            if !path.exists() {
                eprintln!("Error: file not found: {}", path.display());
                std::process::exit(1);
            }
        }
        Commands::Folder { path, .. } | Commands::Repo { path, .. } => {
            if !path.exists() {
                eprintln!("Error: path not found: {}", path.display());
                std::process::exit(1);
            }
        }
        Commands::Rules { .. } => unreachable!("handled above"),
        _ => {}
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

    if out.contract || wants_submit {
        let payload = build_contract_payload(&report, scan_duration_ms);
        let json = match serde_json::to_string_pretty(&payload) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("Error serializing contract payload: {e}");
                std::process::exit(1);
            }
        };

        if out.contract && !wants_submit {
            println!("{json}");
        }

        // Write to file if --out is specified, or always when submitting
        let write_dest = if let Some(maybe_path) = &out.out {
            Some(match maybe_path {
                Some(p) => p.clone(),
                None => PathBuf::from("ahscan-contract.json"),
            })
        } else if wants_submit {
            Some(PathBuf::from("ahscan-contract.json"))
        } else {
            None
        };

        if let Some(dest) = write_dest {
            if let Err(e) = fs::write(&dest, &json) {
                eprintln!("Error writing contract to {}: {}", dest.display(), e);
            } else {
                eprintln!("Contract written to {}", dest.display());
            }
        }

        if wants_submit {
            do_submit(&json, &out.submit, out.api_key.as_deref());
        }
    } else {
        emit(&report, scan_duration_ms, out.json, &out.out, out.summary, out.full);
    }

    // Passive update check after scan completes
    crate::updater::passive_update_check();
}
