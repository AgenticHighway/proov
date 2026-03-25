//! Output dispatch — writes scan results as JSON, human-readable, or file,
//! and handles submission orchestration.

use std::fs;
use std::path::PathBuf;

use crate::contract::build_contract_payload;
use crate::formatters::{print_human, print_overview, print_summary};
use crate::models::ScanReport;
use crate::submit::{
    load_auth_config, submit_contract_payload, AuthConfig, DEFAULT_PRODUCTION_ENDPOINT,
};

pub fn emit(
    report: &ScanReport,
    scan_duration_ms: u64,
    json_output: bool,
    out: &Option<Option<PathBuf>>,
    summary: bool,
    full: bool,
) {
    if json_output {
        let payload = build_contract_payload(report, scan_duration_ms);
        match serde_json::to_string_pretty(&payload) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("Error serializing contract payload: {e}"),
        }
    } else if summary {
        print_summary(report);
    } else if full {
        print_human(report);
    } else {
        print_overview(report);
    }

    if let Some(maybe_path) = out {
        write_json_report(report, scan_duration_ms, maybe_path);
    }
}

fn write_json_report(
    report: &ScanReport,
    scan_duration_ms: u64,
    maybe_path: &Option<PathBuf>,
) {
    let dest = match maybe_path {
        Some(p) => p.clone(),
        None => PathBuf::from("proov-report.json"),
    };
    let payload = build_contract_payload(report, scan_duration_ms);
    match serde_json::to_string_pretty(&payload) {
        Ok(json) => {
            if let Err(e) = fs::write(&dest, &json) {
                eprintln!("Error writing report to {}: {}", dest.display(), e);
            } else {
                eprintln!("Report written to {}", dest.display());
            }
        }
        Err(e) => eprintln!("Error serializing contract payload: {e}"),
    }
}

/// Resolve auth (from flags + config file) and POST the payload.
pub fn do_submit(
    payload_json: &str,
    submit_flag: &Option<Option<String>>,
    api_key_flag: Option<&str>,
) {
    let saved = load_auth_config();

    let endpoint = match submit_flag {
        Some(Some(url)) => url.clone(),
        _ => saved
            .as_ref()
            .map(|c| c.endpoint.clone())
            .unwrap_or_else(|| DEFAULT_PRODUCTION_ENDPOINT.to_string()),
    };

    let api_key = match api_key_flag {
        Some(k) => k.to_string(),
        None => match saved.as_ref().map(|c| c.api_key.clone()) {
            Some(k) => k,
            None => {
                eprintln!(
                    "No API key provided. Pass --api-key or run `proov auth --key <your-key>`."
                );
                std::process::exit(1);
            }
        },
    };

    let auth = AuthConfig { endpoint, api_key };

    eprintln!("Submitting scan to {}...", auth.endpoint);
    match submit_contract_payload(payload_json, &auth) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Submission failed: {e}");
            std::process::exit(1);
        }
    }
}
