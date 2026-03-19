//! Submission side-effects — config loading, file I/O, HTTP dispatch.
//!
//! All pure payload-building logic lives in `crate::payload`.  This module
//! handles the parts that touch the outside world: reading config files,
//! resolving identities, writing audit logs, and posting to the ingest API.

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::identity::{is_valid_uuid, resolve_scanner_account_uuid, resolve_scanner_uuid};
use crate::network::ensure_endpoint_allowed;
use crate::payload::build_ingest_payload;

pub const DEFAULT_INGEST_ENDPOINT: &str = "http://localhost:3000/api/ingest";
pub const DEFAULT_PRODUCTION_ENDPOINT: &str = "https://verify.agentichighway.ai/api/scans/ingest";
pub const DEFAULT_TIMEOUT_SECONDS: f64 = 10.0;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SubmissionConfig {
    pub endpoint: String,
    pub token: Option<String>,
    pub scanner_uuid: Option<String>,
    pub scanner_account_uuid: Option<String>,
    pub timeout_seconds: f64,
    pub include_informational: bool,
    pub allow_public_endpoint: bool,
    pub source: String,
    pub audit_log_enabled: bool,
    pub audit_log_path: String,
}

impl Default for SubmissionConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_INGEST_ENDPOINT.to_string(),
            token: None,
            scanner_uuid: None,
            scanner_account_uuid: None,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            include_informational: false,
            allow_public_endpoint: false,
            source: "cli".to_string(),
            audit_log_enabled: false,
            audit_log_path: "ah-scan-audit.jsonl".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

/// Load submission settings from a `.ahscan.toml` file.
///
/// If `config_path` is `None` or the file does not exist, returns defaults.
/// Only the `[submit]` section is read; unknown keys are silently ignored.
pub fn load_submission_config(config_path: Option<&Path>) -> Result<SubmissionConfig, String> {
    let path = match config_path {
        Some(p) if p.exists() => p,
        _ => return Ok(SubmissionConfig::default()),
    };

    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config {}: {e}", path.display()))?;

    let table: toml::Table = content
        .parse()
        .map_err(|e| format!("Invalid TOML in {}: {e}", path.display()))?;

    let submit = match table.get("submit") {
        Some(toml::Value::Table(t)) => t,
        _ => return Ok(SubmissionConfig::default()),
    };

    let mut cfg = SubmissionConfig::default();

    if let Some(toml::Value::String(v)) = submit.get("endpoint") {
        cfg.endpoint = v.clone();
    }
    if let Some(toml::Value::String(v)) = submit.get("token") {
        cfg.token = Some(v.clone());
    }
    if let Some(toml::Value::String(v)) = submit.get("scanner_uuid") {
        cfg.scanner_uuid = Some(v.clone());
    }
    if let Some(toml::Value::String(v)) = submit.get("scanner_account_uuid") {
        cfg.scanner_account_uuid = Some(v.clone());
    }
    if let Some(toml::Value::Float(v)) = submit.get("timeout_seconds") {
        cfg.timeout_seconds = *v;
    }
    if let Some(toml::Value::Boolean(v)) = submit.get("include_informational") {
        cfg.include_informational = *v;
    }
    if let Some(toml::Value::Boolean(v)) = submit.get("allow_public_endpoint") {
        cfg.allow_public_endpoint = *v;
    }
    if let Some(toml::Value::String(v)) = submit.get("source") {
        cfg.source = v.clone();
    }
    if let Some(toml::Value::Boolean(v)) = submit.get("audit_log_enabled") {
        cfg.audit_log_enabled = *v;
    }
    if let Some(toml::Value::String(v)) = submit.get("audit_log_path") {
        cfg.audit_log_path = v.clone();
    }

    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

/// Append `event` to an audit log file.
///
/// - `.json`  → reads an existing JSON array, appends, writes back.
/// - anything else (`.jsonl` default) → appends a single line.
pub fn append_submission_audit(audit_path: &Path, event: &Value) {
    let line = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string());

    let is_json_array = audit_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e == "json")
        .unwrap_or(false);

    if is_json_array {
        let mut entries: Vec<Value> = if audit_path.exists() {
            fs::read_to_string(audit_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        entries.push(event.clone());
        let _ = fs::write(
            audit_path,
            serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string()),
        );
    } else {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(audit_path)
            .unwrap_or_else(|e| {
                eprintln!("Warning: cannot open audit log {}: {e}", audit_path.display());
                // Fall back to /dev/null so caller doesn't panic.
                fs::OpenOptions::new()
                    .write(true)
                    .open(if cfg!(windows) { "NUL" } else { "/dev/null" })
                    .expect("open /dev/null")
            });
        let _ = writeln!(file, "{line}");
    }
}

// ---------------------------------------------------------------------------
// Global auth config (~/.config/ahscan/config.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub endpoint: String,
    #[serde(rename = "apiKey")]
    pub api_key: String,
}

/// Return the path to `~/.config/ahscan/config.json`.
pub fn auth_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("ahscan").join("config.json"))
}

/// Load the global auth config. Returns `None` if the file doesn't exist.
pub fn load_auth_config() -> Option<AuthConfig> {
    let path = auth_config_path()?;
    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Save the global auth config to `~/.config/ahscan/config.json`.
pub fn save_auth_config(config: &AuthConfig) -> Result<(), String> {
    let path = auth_config_path()
        .ok_or_else(|| "Could not determine config directory".to_string())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {e}"))?;
    }
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {e}"))?;
    fs::write(&path, json)
        .map_err(|e| format!("Failed to write config to {}: {e}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP submission with retry
// ---------------------------------------------------------------------------

/// Backoff schedule in seconds for transient failures.
const BACKOFF_SECONDS: [u64; 3] = [5, 30, 120];
const MAX_ATTEMPTS: usize = 3;

/// HTTP status codes considered transient (retryable).
fn is_retryable(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
}

/// Submit the contract payload to the ingest endpoint.
///
/// Uses the global `AuthConfig` for the endpoint and bearer token.
/// Retries transient failures with exponential backoff.
pub fn submit_contract_payload(
    payload_json: &str,
    auth: &AuthConfig,
) -> Result<(), String> {
    let mut last_err = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            eprintln!("  Attempt {}/{MAX_ATTEMPTS}...", attempt + 1);
        }

        let result = ureq::post(&auth.endpoint)
            .set("Content-Type", "application/json")
            .set("Authorization", &format!("Bearer {}", auth.api_key))
            .send_string(payload_json);

        match result {
            Ok(response) => {
                let status = response.status();
                match status {
                    201 => {
                        let body: Value = response.into_json().unwrap_or(json!({}));
                        let scan_id = body.get("scanId")
                            .or_else(|| body.get("scan_id"))
                            .or_else(|| body.get("id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        eprintln!("Scan accepted: {scan_id}");
                        return Ok(());
                    }
                    _ => {
                        // Any other 2xx — treat as success
                        return Ok(());
                    }
                }
            }
            Err(ureq::Error::Status(status, response)) => {
                match status {
                    409 => {
                        eprintln!("Scan already submitted (duplicate).");
                        return Ok(());
                    }
                    400 => {
                        let body = response.into_string().unwrap_or_default();
                        return Err(format!(
                            "Server rejected payload (400): {body}\n\
                             This is likely a scanner bug — the payload doesn't match the contract."
                        ));
                    }
                    401 => {
                        return Err(
                            "Authentication failed (401). Run `ahscan auth --key <your-key>` to configure credentials."
                                .into(),
                        );
                    }
                    413 => {
                        let size_kb = payload_json.len() / 1024;
                        return Err(format!(
                            "Payload too large (413): ~{size_kb} KB. Try reducing scan scope."
                        ));
                    }
                    s if is_retryable(s) => {
                        let wait = if s == 429 {
                            // Respect Retry-After header if present
                            response
                                .header("Retry-After")
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(BACKOFF_SECONDS[attempt])
                        } else {
                            BACKOFF_SECONDS[attempt]
                        };
                        last_err = format!("Server returned {s}");
                        eprintln!("  {last_err}, retrying in {wait}s...");
                        thread::sleep(Duration::from_secs(wait));
                        continue;
                    }
                    _ => {
                        let body = response.into_string().unwrap_or_default();
                        return Err(format!("Server error ({status}): {body}"));
                    }
                }
            }
            Err(ureq::Error::Transport(e)) => {
                last_err = format!("Connection error: {e}");
                if attempt < MAX_ATTEMPTS - 1 {
                    let wait = BACKOFF_SECONDS[attempt];
                    eprintln!("  {last_err}, retrying in {wait}s...");
                    thread::sleep(Duration::from_secs(wait));
                    continue;
                }
            }
        }
    }

    Err(format!("Failed after {MAX_ATTEMPTS} attempts: {last_err}"))
}

// ---------------------------------------------------------------------------
// Legacy HTTP submission (stub, kept for old submit flow)
// ---------------------------------------------------------------------------

/// Submit the pre-built payload to the configured ingest endpoint.
pub fn submit_payload(
    payload: &Value,
    config: &SubmissionConfig,
) -> Result<Value, String> {
    ensure_endpoint_allowed(&config.endpoint, config.allow_public_endpoint)?;

    let _ = payload;
    Err(
        "Legacy submission path — use --submit with auth config instead"
            .into(),
    )
}

// ---------------------------------------------------------------------------
// Convenience: resolve identities + build + submit
// ---------------------------------------------------------------------------

/// Resolve scanner identities, build the ingest payload, and attempt
/// submission.  Returns the assembled payload regardless of submission
/// outcome so callers can fall back to writing JSON to disk.
pub fn prepare_and_submit(
    report: &crate::models::ScanReport,
    config: &SubmissionConfig,
    client_emitted_at: Option<&str>,
    lite_mode_locked_summary: Option<&Value>,
) -> (Value, Result<Value, String>) {
    let scanner_uuid = resolve_scanner_uuid(config.scanner_uuid.as_deref())
        .unwrap_or_else(|_| "unknown".to_string());
    let scanner_account_uuid =
        resolve_scanner_account_uuid(config.scanner_account_uuid.as_deref())
            .unwrap_or_else(|_| "unknown".to_string());

    let payload = build_ingest_payload(
        report,
        config.include_informational,
        Some(&config.endpoint),
        &config.source,
        &scanner_uuid,
        &scanner_account_uuid,
        client_emitted_at,
        lite_mode_locked_summary,
    );

    let result = submit_payload(&payload, config);

    if config.audit_log_enabled {
        let audit_path = PathBuf::from(&config.audit_log_path);
        let audit_event = json!({
            "action": "submit",
            "run_id": report.run_id,
            "endpoint": config.endpoint,
            "success": result.is_ok(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        append_submission_audit(&audit_path, &audit_event);
    }

    (payload, result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = SubmissionConfig::default();
        assert_eq!(cfg.endpoint, DEFAULT_INGEST_ENDPOINT);
        assert_eq!(cfg.timeout_seconds, DEFAULT_TIMEOUT_SECONDS);
        assert!(!cfg.include_informational);
        assert!(!cfg.allow_public_endpoint);
        assert_eq!(cfg.source, "cli");
    }

    #[test]
    fn load_config_missing_file_returns_defaults() {
        let cfg = load_submission_config(Some(Path::new("/nonexistent/.ahscan.toml")));
        assert!(cfg.is_ok());
        assert_eq!(cfg.unwrap().endpoint, DEFAULT_INGEST_ENDPOINT);
    }

    #[test]
    fn load_config_none_returns_defaults() {
        let cfg = load_submission_config(None).unwrap();
        assert_eq!(cfg.endpoint, DEFAULT_INGEST_ENDPOINT);
    }

    #[test]
    fn submit_payload_rejects_public_by_default() {
        let cfg = SubmissionConfig {
            endpoint: "https://api.example.com/ingest".to_string(),
            ..Default::default()
        };
        let result = submit_payload(&json!({}), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn submit_payload_stub_returns_legacy_message() {
        let cfg = SubmissionConfig::default();
        let result = submit_payload(&json!({}), &cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Legacy"));
    }

    #[test]
    fn append_audit_jsonl() {
        let dir = std::env::temp_dir().join(format!(
            "ah_audit_test_{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");

        append_submission_audit(&path, &json!({"a": 1}));
        append_submission_audit(&path, &json!({"b": 2}));

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_audit_json_array() {
        let dir = std::env::temp_dir().join(format!(
            "ah_audit_test_{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.json");

        append_submission_audit(&path, &json!({"a": 1}));
        append_submission_audit(&path, &json!({"b": 2}));

        let content = fs::read_to_string(&path).unwrap();
        let arr: Vec<Value> = serde_json::from_str(&content).unwrap();
        assert_eq!(arr.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }
}
