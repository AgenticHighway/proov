//! Submission side-effects — config persistence and HTTP dispatch.
//!
//! Handles the parts that touch the outside world: reading/writing config
//! files and posting contract payloads to the ingest API.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const DEFAULT_PRODUCTION_ENDPOINT: &str = "https://vettd.agentichighway.ai/api/scans/ingest";

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
                eprintln!(
                    "Warning: cannot open audit log {}: {e}",
                    audit_path.display()
                );
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

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub endpoint: String,
    #[serde(rename = "apiKey")]
    pub api_key: String,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field("endpoint", &self.endpoint)
            .field("api_key", &"<redacted>")
            .finish()
    }
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
    let path =
        auth_config_path().ok_or_else(|| "Could not determine config directory".to_string())?;
    save_auth_config_to_path(&path, config)
}

fn save_auth_config_to_path(path: &Path, config: &AuthConfig) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("Failed to secure config directory: {e}"))?;
        }
    }
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {e}"))?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("Failed to open config file {}: {e}", path.display()))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write config to {}: {e}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to secure config file {}: {e}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, json)
            .map_err(|e| format!("Failed to write config to {}: {e}", path.display()))?;
    }

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
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// Submit the contract payload to the ingest endpoint.
///
/// Uses the global `AuthConfig` for the endpoint and bearer token.
/// Retries transient failures with exponential backoff.
pub fn submit_contract_payload(payload_json: &str, auth: &AuthConfig) -> Result<(), String> {
    let mut last_err = String::new();

    for (attempt, &backoff) in BACKOFF_SECONDS.iter().enumerate().take(MAX_ATTEMPTS) {
        if attempt > 0 {
            eprintln!("  Attempt {}/{MAX_ATTEMPTS}...", attempt + 1);
        }

        let result = ureq::post(&auth.endpoint)
            .set("Content-Type", "application/json")
            .set("Authorization", &format!("Bearer {}", auth.api_key))
            .set("User-Agent", &crate::updater::user_agent_string())
            .send_string(payload_json);

        match result {
            Ok(response) => {
                let status = response.status();
                match status {
                    201 => {
                        let body: Value = response.into_json().unwrap_or(json!({}));
                        let scan_id = body
                            .get("scanId")
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
                                .unwrap_or(backoff)
                        } else {
                            backoff
                        };
                        let body = response.into_string().unwrap_or_default();
                        let detail = if body.trim().is_empty() {
                            "no details provided".to_string()
                        } else {
                            body
                        };
                        last_err = format!("Server returned {s}: {detail}");
                        if attempt < MAX_ATTEMPTS - 1 {
                            eprintln!("  Server returned {s}, retrying in {wait}s...");
                            thread::sleep(Duration::from_secs(wait));
                            continue;
                        }
                    }
                    _ => {
                        let body = response.into_string().unwrap_or_default();
                        let detail = if body.trim().is_empty() {
                            "no details provided".to_string()
                        } else {
                            body
                        };
                        return Err(format!("Server error ({status}): {detail}"));
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_audit_jsonl() {
        let dir = std::env::temp_dir().join(format!("ah_audit_test_{}", uuid::Uuid::new_v4()));
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
        let dir = std::env::temp_dir().join(format!("ah_audit_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.json");

        append_submission_audit(&path, &json!({"a": 1}));
        append_submission_audit(&path, &json!({"b": 2}));

        let content = fs::read_to_string(&path).unwrap();
        let arr: Vec<Value> = serde_json::from_str(&content).unwrap();
        assert_eq!(arr.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn auth_config_debug_redacts_api_key() {
        let auth = AuthConfig {
            endpoint: "https://example.com/api".to_string(),
            api_key: "super-secret-key".to_string(),
        };

        let debug = format!("{auth:?}");
        assert!(debug.contains("https://example.com/api"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("super-secret-key"));
    }

    #[test]
    fn save_auth_config_to_custom_path_writes_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let path = config_dir.join("config.json");
        let auth = AuthConfig {
            endpoint: "https://example.com/api".to_string(),
            api_key: "ah_test".to_string(),
        };

        save_auth_config_to_path(&path, &auth).unwrap();

        let saved = fs::read_to_string(&path).unwrap();
        let loaded: AuthConfig = serde_json::from_str(&saved).unwrap();
        assert_eq!(loaded.endpoint, auth.endpoint);
        assert_eq!(loaded.api_key, auth.api_key);
    }

    #[cfg(unix)]
    #[test]
    fn save_auth_config_to_custom_path_secures_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let path = config_dir.join("config.json");
        let auth = AuthConfig {
            endpoint: "https://example.com/api".to_string(),
            api_key: "ah_test".to_string(),
        };

        save_auth_config_to_path(&path, &auth).unwrap();

        let dir_mode = fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }
}
