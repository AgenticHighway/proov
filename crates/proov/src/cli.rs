use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

use crate::contract::build_contract_payload;
use crate::lite_mode::{limit_lite_mode_report, print_locked_summary, LITE_MODE_VISIBLE_RESULTS};
use crate::models::ScanReport;
use crate::output::{do_submit, emit};
use crate::scan::run_scan;
use crate::submit::{
    load_submission_config, save_auth_config, AuthConfig, DEFAULT_PRODUCTION_ENDPOINT,
};

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
        Commands::Auth { .. }
        | Commands::Setup
        | Commands::Update { .. }
        | Commands::Rules { .. } => {
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
        Commands::Auth { .. }
        | Commands::Setup
        | Commands::Update { .. }
        | Commands::Rules { .. } => {
            unreachable!("handled before output dispatch")
        }
    }
}

fn command_name(cmd: &Commands) -> &'static str {
    match cmd {
        Commands::Scan { .. } => "scan",
        Commands::Quick { .. } => "quick",
        Commands::Full { .. } => "full",
        Commands::File { .. } => "file",
        Commands::Folder { .. } => "folder",
        Commands::Repo { .. } => "repo",
        Commands::Auth { .. }
        | Commands::Setup
        | Commands::Update { .. }
        | Commands::Rules { .. } => {
            unreachable!("handled before command_name")
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
                None => PathBuf::from("proov-contract.json"),
            })
        } else if wants_submit {
            Some(PathBuf::from("proov-contract.json"))
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
        let cmd_name = command_name(&cmd);
        emit(
            &report,
            scan_duration_ms,
            out.json,
            &out.out,
            out.summary,
            out.full,
            cmd_name,
        );
    }

    // Show Vettd hint for local-only users (not submitting, not JSON)
    if !wants_submit && !out.json {
        print_vettd_cta();
    }

    // Passive update check after scan completes
    crate::updater::passive_update_check();
}

fn print_vettd_cta() {
    use crate::submit::load_auth_config;
    let has_key = load_auth_config()
        .map(|a| !a.api_key.is_empty())
        .unwrap_or(false);
    if has_key {
        return;
    }
    eprintln!("  \x1b[2m┌──────────────────────────────────────────────────────────┐\x1b[0m");
    eprintln!("  \x1b[2m│\x1b[0m  \x1b[1mWant deeper analysis?\x1b[0m  Sync your results to \x1b[36mVettd\x1b[0m       \x1b[2m│\x1b[0m");
    eprintln!(
        "  \x1b[2m│\x1b[0m  for verification scoring, trend tracking, and more.   \x1b[2m│\x1b[0m"
    );
    eprintln!(
        "  \x1b[2m│\x1b[0m                                                        \x1b[2m│\x1b[0m"
    );
    eprintln!("  \x1b[2m│\x1b[0m  Get your API key → \x1b[36mhttps://vettd.agentichighway.ai\x1b[0m    \x1b[2m│\x1b[0m");
    eprintln!("  \x1b[2m│\x1b[0m  Then run:  \x1b[1mproov setup\x1b[0m                                \x1b[2m│\x1b[0m");
    eprintln!("  \x1b[2m└──────────────────────────────────────────────────────────┘\x1b[0m");
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn min_severity_score_critical() {
        assert_eq!(min_severity_score("critical"), 90);
    }

    #[test]
    fn min_severity_score_high() {
        assert_eq!(min_severity_score("high"), 70);
    }

    #[test]
    fn min_severity_score_medium() {
        assert_eq!(min_severity_score("medium"), 40);
    }

    #[test]
    fn min_severity_score_low() {
        assert_eq!(min_severity_score("low"), 10);
    }

    #[test]
    fn min_severity_score_info_default() {
        assert_eq!(min_severity_score("info"), 0);
        assert_eq!(min_severity_score("anything"), 0);
    }

    #[test]
    fn filter_by_severity_removes_below_threshold() {
        let mut report = ScanReport::new("/tmp");
        let mut a1 = crate::models::ArtifactReport::new("prompt_config", 0.8);
        a1.risk_score = 80;
        let mut a2 = crate::models::ArtifactReport::new("prompt_config", 0.8);
        a2.risk_score = 30;
        let mut a3 = crate::models::ArtifactReport::new("prompt_config", 0.8);
        a3.risk_score = 50;
        report.artifacts = vec![a1, a2, a3];

        filter_by_severity(&mut report, 40);
        assert_eq!(report.artifacts.len(), 2);
        assert!(report.artifacts.iter().all(|a| a.risk_score >= 40));
    }

    #[test]
    fn filter_by_severity_zero_keeps_all() {
        let mut report = ScanReport::new("/tmp");
        let mut a = crate::models::ArtifactReport::new("prompt_config", 0.8);
        a.risk_score = 5;
        report.artifacts = vec![a];

        filter_by_severity(&mut report, 0);
        assert_eq!(report.artifacts.len(), 1);
    }

    #[test]
    fn parse_cli_scan() {
        let cli = Cli::parse_from(["proov", "scan"]);
        assert!(matches!(cli.command, Some(Commands::Scan { .. })));
    }

    #[test]
    fn parse_cli_quick() {
        let cli = Cli::parse_from(["proov", "quick"]);
        assert!(matches!(cli.command, Some(Commands::Quick { .. })));
    }

    #[test]
    fn parse_cli_full() {
        let cli = Cli::parse_from(["proov", "full"]);
        assert!(matches!(cli.command, Some(Commands::Full { .. })));
    }

    #[test]
    fn parse_cli_file() {
        let cli = Cli::parse_from(["proov", "file", "/tmp/test.md"]);
        match cli.command {
            Some(Commands::File { path, .. }) => {
                assert_eq!(path, PathBuf::from("/tmp/test.md"));
            }
            _ => panic!("Expected File command"),
        }
    }

    #[test]
    fn parse_cli_folder() {
        let cli = Cli::parse_from(["proov", "folder", "/tmp"]);
        match cli.command {
            Some(Commands::Folder { path, .. }) => {
                assert_eq!(path, PathBuf::from("/tmp"));
            }
            _ => panic!("Expected Folder command"),
        }
    }

    #[test]
    fn parse_cli_repo() {
        let cli = Cli::parse_from(["proov", "repo", "."]);
        match cli.command {
            Some(Commands::Repo { path, .. }) => {
                assert_eq!(path, PathBuf::from("."));
            }
            _ => panic!("Expected Repo command"),
        }
    }

    #[test]
    fn parse_cli_auth() {
        let cli = Cli::parse_from(["proov", "auth", "--key", "ah_test123"]);
        match cli.command {
            Some(Commands::Auth { key, endpoint }) => {
                assert_eq!(key, "ah_test123");
                assert!(endpoint.is_none());
            }
            _ => panic!("Expected Auth command"),
        }
    }

    #[test]
    fn parse_cli_auth_with_endpoint() {
        let cli = Cli::parse_from([
            "proov",
            "auth",
            "--key",
            "ah_test",
            "--endpoint",
            "https://example.com/api",
        ]);
        match cli.command {
            Some(Commands::Auth { key, endpoint }) => {
                assert_eq!(key, "ah_test");
                assert_eq!(endpoint.unwrap(), "https://example.com/api");
            }
            _ => panic!("Expected Auth command"),
        }
    }

    #[test]
    fn parse_cli_update_check() {
        let cli = Cli::parse_from(["proov", "update", "--check"]);
        match cli.command {
            Some(Commands::Update { check, force }) => {
                assert!(check);
                assert!(!force);
            }
            _ => panic!("Expected Update command"),
        }
    }

    #[test]
    fn parse_cli_rules_list() {
        let cli = Cli::parse_from(["proov", "rules", "list"]);
        match cli.command {
            Some(Commands::Rules {
                action: RuleAction::List,
            }) => {}
            _ => panic!("Expected Rules List"),
        }
    }

    #[test]
    fn parse_cli_output_args_json() {
        let cli = Cli::parse_from(["proov", "scan", "--json"]);
        match cli.command {
            Some(Commands::Scan { output, .. }) => {
                assert!(output.json);
                assert!(!output.summary);
                assert!(!output.full);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parse_cli_output_args_summary() {
        let cli = Cli::parse_from(["proov", "scan", "--summary"]);
        match cli.command {
            Some(Commands::Scan { output, .. }) => {
                assert!(output.summary);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parse_cli_output_args_min_severity() {
        let cli = Cli::parse_from(["proov", "scan", "--min-severity", "high"]);
        match cli.command {
            Some(Commands::Scan { output, .. }) => {
                assert_eq!(output.min_severity, "high");
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parse_cli_no_command() {
        let cli = Cli::parse_from(["proov"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn resolve_scan_params_scan() {
        let cmd = Commands::Scan {
            output: OutputArgs {
                full: false,
                json: false,
                summary: false,
                out: None,
                min_severity: "info".to_string(),
                contract: false,
                submit: None,
                api_key: None,
            },
        };
        let params = resolve_scan_params(&cmd);
        assert_eq!(params.mode, "home");
        assert!(params.workdir.is_none());
        assert!(!params.deep);
    }

    #[test]
    fn resolve_scan_params_quick() {
        let cmd = Commands::Quick {
            output: OutputArgs {
                full: false,
                json: false,
                summary: false,
                out: None,
                min_severity: "info".to_string(),
                contract: false,
                submit: None,
                api_key: None,
            },
        };
        let params = resolve_scan_params(&cmd);
        assert_eq!(params.mode, "host");
    }

    #[test]
    fn resolve_scan_params_repo_deep() {
        let cmd = Commands::Repo {
            path: PathBuf::from("/tmp/repo"),
            output: OutputArgs {
                full: false,
                json: false,
                summary: false,
                out: None,
                min_severity: "info".to_string(),
                contract: false,
                submit: None,
                api_key: None,
            },
        };
        let params = resolve_scan_params(&cmd);
        assert_eq!(params.mode, "workdir");
        assert!(params.deep);
        assert_eq!(params.workdir.unwrap(), Path::new("/tmp/repo"));
    }

    #[test]
    fn resolve_scan_params_file() {
        let cmd = Commands::File {
            path: PathBuf::from("/tmp/test.md"),
            output: OutputArgs {
                full: false,
                json: false,
                summary: false,
                out: None,
                min_severity: "info".to_string(),
                contract: false,
                submit: None,
                api_key: None,
            },
        };
        let params = resolve_scan_params(&cmd);
        assert_eq!(params.mode, "file");
        assert_eq!(params.file.unwrap(), Path::new("/tmp/test.md"));
    }

    #[test]
    fn load_access_config_defaults_when_no_file() {
        let cfg = load_access_config();
        assert_eq!(cfg.mode, "licensed");
        assert!(cfg.license_key.is_none());
    }
}
