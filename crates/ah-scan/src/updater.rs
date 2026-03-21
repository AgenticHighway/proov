//! Self-update mechanism — check for new versions and replace the binary.
//!
//! Architecture:
//!   1. `check_for_update()` — GET latest.json, compare semver, return result
//!   2. `passive_update_check()` — cached TTY-only hint after scans
//!   3. `perform_update()` — download, verify SHA-256, backup, replace
//!
//! All downloads are over HTTPS.  The binary is never executed during the
//! update — only extracted, verified, and placed.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// S3 bucket URL for release manifests and artifacts.
const MANIFEST_URL: &str =
    "https://ah-scanner-releases.s3.amazonaws.com/latest.json";

/// How long to cache a "no update" result before checking again.
const CHECK_CACHE_TTL_SECS: u64 = 24 * 60 * 60; // 24 hours

/// HTTP timeout for the passive (background) check — keep it short.
const PASSIVE_CHECK_TIMEOUT_SECS: u64 = 3;

/// HTTP timeout for the active download.
const DOWNLOAD_TIMEOUT_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// The expanded `latest.json` manifest served from S3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub date: String,
    #[serde(default)]
    pub artifacts: std::collections::HashMap<String, ArtifactInfo>,
}

/// One platform's downloadable artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub url: String,
    pub sha256: String,
}

/// Result of comparing the manifest version to the running binary.
#[derive(Debug)]
pub struct UpdateCheckResult {
    pub current_version: String,
    pub latest_version: String,
    pub is_newer: bool,
    pub artifact: Option<ArtifactInfo>,
}

/// On-disk cache written after a successful check.
#[derive(Debug, Serialize, Deserialize)]
struct CheckCache {
    checked_at_epoch: u64,
    latest_version: String,
    is_newer: bool,
}

// ---------------------------------------------------------------------------
// Platform key
// ---------------------------------------------------------------------------

/// Map the running OS + arch to the artifact key in `latest.json`.
pub fn platform_key() -> Result<&'static str, String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("darwin-arm64"),
        ("macos", "x86_64") => Ok("darwin-amd64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("linux", "x86_64") => Ok("linux-amd64"),
        ("windows", "x86_64") => Ok("windows-amd64"),
        (os, arch) => Err(format!("Unsupported platform: {os}/{arch}")),
    }
}

// ---------------------------------------------------------------------------
// Version comparison (simple semver: major.minor.patch)
// ---------------------------------------------------------------------------

fn parse_semver(v: &str) -> Option<(u32, u32, u32)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

fn is_version_newer(current: &str, latest: &str) -> bool {
    match (parse_semver(current), parse_semver(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn ahscan_dir() -> Result<PathBuf, String> {
    dirs::home_dir()
        .map(|h| h.join(".ahscan"))
        .ok_or_else(|| "Cannot determine home directory".to_string())
}

fn check_cache_path() -> Result<PathBuf, String> {
    Ok(ahscan_dir()?.join("last_update_check.json"))
}

fn downloads_dir() -> Result<PathBuf, String> {
    Ok(ahscan_dir()?.join("downloads"))
}

fn backup_path() -> Result<PathBuf, String> {
    Ok(ahscan_dir()?.join("ah-scan.backup"))
}

// ---------------------------------------------------------------------------
// Check cache
// ---------------------------------------------------------------------------

fn read_check_cache() -> Option<CheckCache> {
    let path = check_cache_path().ok()?;
    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

fn write_check_cache(result: &UpdateCheckResult) {
    let epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let cache = CheckCache {
        checked_at_epoch: epoch,
        latest_version: result.latest_version.clone(),
        is_newer: result.is_newer,
    };

    if let Ok(path) = check_cache_path() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&path, serde_json::to_string_pretty(&cache).unwrap_or_default());
    }
}

fn is_cache_fresh() -> bool {
    let cache = match read_check_cache() {
        Some(c) => c,
        None => return false,
    };
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(cache.checked_at_epoch) < CHECK_CACHE_TTL_SECS
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn fetch_manifest(timeout_secs: u64) -> Result<UpdateManifest, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs))
        .build();

    let response = agent
        .get(MANIFEST_URL)
        .set("User-Agent", &user_agent_string())
        .call()
        .map_err(|e| format!("Failed to fetch update manifest: {e}"))?;

    response
        .into_json::<UpdateManifest>()
        .map_err(|e| format!("Failed to parse update manifest: {e}"))
}

fn download_to_file(url: &str, dest: &Path) -> Result<u64, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .build();

    let response = agent
        .get(url)
        .set("User-Agent", &user_agent_string())
        .call()
        .map_err(|e| format!("Download failed: {e}"))?;

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create download directory: {e}"))?;
    }

    let mut file = fs::File::create(dest)
        .map_err(|e| format!("Failed to create download file: {e}"))?;

    let mut reader = response.into_reader();
    let mut buf = [0u8; 8192];
    let mut total: u64 = 0;

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("Read error during download: {e}"))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .map_err(|e| format!("Write error during download: {e}"))?;
        total += n as u64;
    }

    Ok(total)
}

// ---------------------------------------------------------------------------
// SHA-256 verification
// ---------------------------------------------------------------------------

fn verify_sha256(path: &Path, expected: &str) -> Result<(), String> {
    let mut file = fs::File::open(path)
        .map_err(|e| format!("Cannot open file for verification: {e}"))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("Read error during verification: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let actual = format!("{:x}", hasher.finalize());
    let expected_lower = expected.to_lowercase();

    if actual != expected_lower {
        return Err(format!(
            "SHA-256 mismatch!\n  Expected: {expected_lower}\n  Got:      {actual}\n\
             The downloaded file may be corrupted or tampered with."
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// User-Agent string
// ---------------------------------------------------------------------------

pub fn user_agent_string() -> String {
    format!(
        "ah-scan/{} ({}/{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

// ---------------------------------------------------------------------------
// Public API: check
// ---------------------------------------------------------------------------

/// Fetch the update manifest and compare against the running version.
pub fn check_for_update(timeout_secs: u64) -> Result<UpdateCheckResult, String> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let manifest = fetch_manifest(timeout_secs)?;
    let platform = platform_key()?;

    let is_newer = is_version_newer(&current, &manifest.version);
    let artifact = manifest.artifacts.get(platform).cloned();

    let result = UpdateCheckResult {
        current_version: current,
        latest_version: manifest.version,
        is_newer,
        artifact,
    };

    write_check_cache(&result);
    Ok(result)
}

/// Called after a scan completes.  Only prints a hint if:
///   - stdout is a TTY
///   - the cache is stale (>24h since last check)
///   - a newer version exists
pub fn passive_update_check() {
    // Only when interactive
    if !atty_stdout() {
        return;
    }

    // Check cache first — avoid network entirely if fresh
    if is_cache_fresh() {
        if let Some(cache) = read_check_cache() {
            // Re-evaluate against the running version: the binary may have been
            // upgraded since the cache was written, so trusting the cached
            // `is_newer` flag alone would produce a false positive.
            let still_newer = is_version_newer(env!("CARGO_PKG_VERSION"), &cache.latest_version);
            if still_newer {
                eprintln!(
                    "\n  A newer version of ah-scan is available ({}).",
                    cache.latest_version
                );
                eprintln!("  Run `ah-scan update` to upgrade.\n");
            }
        }
        return;
    }

    // Stale or no cache — do a quick network check
    match check_for_update(PASSIVE_CHECK_TIMEOUT_SECS) {
        Ok(result) if result.is_newer => {
            eprintln!(
                "\n  ah-scan {} is available (you have {}).",
                result.latest_version, result.current_version
            );
            eprintln!("  Run `ah-scan update` to upgrade.\n");
        }
        _ => {} // silently ignore errors and up-to-date
    }
}

// ---------------------------------------------------------------------------
// Public API: update
// ---------------------------------------------------------------------------

/// Download, verify, backup, and replace the running binary.
pub fn perform_update(force: bool) -> Result<(), String> {
    let result = check_for_update(PASSIVE_CHECK_TIMEOUT_SECS)?;

    if !result.is_newer {
        eprintln!(
            "You are already running the latest version ({}). Nothing to do.",
            result.current_version
        );
        return Ok(());
    }

    let artifact = result.artifact.ok_or_else(|| {
        let plat = platform_key().unwrap_or("unknown");
        format!(
            "No artifact available for your platform ({plat}) in version {}.\n\
             Please download manually from the GitHub Releases page.",
            result.latest_version
        )
    })?;

    eprintln!(
        "Update available: {} → {}",
        result.current_version, result.latest_version
    );

    if !force {
        eprint!("Proceed with update? [Y/n] ");
        let _ = io::stderr().flush();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("Failed to read input: {e}"))?;
        let input = input.trim().to_lowercase();
        if input == "n" || input == "no" {
            eprintln!("Update cancelled.");
            return Ok(());
        }
    }

    // 1. Determine paths
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Cannot determine current binary path: {e}"))?;
    let dl_dir = downloads_dir()?;
    let dl_path = dl_dir.join(format!(
        "ah-scan-{}.tmp",
        result.latest_version.replace('/', "-")
    ));
    let backup = backup_path()?;

    // 2. Download
    eprintln!("Downloading {}...", artifact.url);
    let bytes = download_to_file(&artifact.url, &dl_path)?;
    eprintln!("  Downloaded {} bytes.", bytes);

    // 3. Verify SHA-256
    eprintln!("Verifying integrity (SHA-256)...");
    if let Err(e) = verify_sha256(&dl_path, &artifact.sha256) {
        // Clean up tainted download
        let _ = fs::remove_file(&dl_path);
        return Err(e);
    }
    eprintln!("  Checksum verified.");

    // 4. Backup current binary
    if let Some(parent) = backup.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::copy(&current_exe, &backup).map_err(|e| {
        format!(
            "Failed to backup current binary to {}: {e}",
            backup.display()
        )
    })?;
    eprintln!("  Backed up current binary to {}", backup.display());

    // 5. Extract and replace
    match extract_and_replace(&dl_path, &current_exe) {
        Ok(()) => {
            // Clean up download
            let _ = fs::remove_file(&dl_path);
            eprintln!(
                "Updated ah-scan {} → {}.",
                result.current_version, result.latest_version
            );

            // macOS quarantine notice
            if cfg!(target_os = "macos") {
                eprintln!();
                eprintln!("  Note: macOS may quarantine the new binary.");
                eprintln!("  If you see a \"cannot be opened\" warning, run:");
                eprintln!(
                    "    xattr -d com.apple.quarantine {}",
                    current_exe.display()
                );
                eprintln!();
            }
            Ok(())
        }
        Err(e) => {
            // Restore from backup
            eprintln!("Update failed: {e}");
            eprintln!("Restoring previous version from backup...");
            if let Err(restore_err) = fs::copy(&backup, &current_exe) {
                eprintln!(
                    "CRITICAL: Failed to restore backup: {restore_err}\n\
                     Your backup is at: {}\n\
                     Manually copy it to: {}",
                    backup.display(),
                    current_exe.display()
                );
            } else {
                eprintln!("  Restored previous version successfully.");
            }
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Extract + replace
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
fn extract_and_replace(archive_path: &Path, dest: &Path) -> Result<(), String> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let file = fs::File::open(archive_path)
        .map_err(|e| format!("Cannot open downloaded archive: {e}"))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    // Find the binary inside the tar (expect a single file named "ah-scanner")
    let mut found = false;
    for entry in archive
        .entries()
        .map_err(|e| format!("Failed to read tar entries: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("Bad tar entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("Bad path in tar: {e}"))?
            .to_path_buf();

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        if name == "ah-scanner" || name == "ah-scan" {
            // Extract to a temp file next to dest, then atomic rename
            let tmp = dest.with_extension("new");
            let mut out = fs::File::create(&tmp)
                .map_err(|e| format!("Cannot create temp file: {e}"))?;
            io::copy(&mut entry, &mut out)
                .map_err(|e| format!("Failed to extract binary: {e}"))?;
            drop(out);

            // Set executable permission
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))
                    .map_err(|e| format!("Failed to set permissions: {e}"))?;
            }

            // Atomic rename
            fs::rename(&tmp, dest).map_err(|e| {
                format!(
                    "Failed to replace binary (rename {} → {}): {e}",
                    tmp.display(),
                    dest.display()
                )
            })?;
            found = true;
            break;
        }
    }

    if !found {
        return Err("Downloaded archive does not contain the ah-scan binary.".into());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn extract_and_replace(downloaded: &Path, dest: &Path) -> Result<(), String> {
    // On Windows: rename current → .old, copy new → current, schedule .old delete
    let old = dest.with_extension("old.exe");
    let _ = fs::remove_file(&old); // clean up any previous leftover

    fs::rename(dest, &old)
        .map_err(|e| format!("Cannot rename current binary: {e}"))?;
    fs::copy(downloaded, dest)
        .map_err(|e| format!("Cannot place new binary: {e}"))?;

    // Best-effort cleanup of .old
    let _ = fs::remove_file(&old);
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API: print version
// ---------------------------------------------------------------------------

pub fn print_version() {
    println!("ah-scan {}", env!("CARGO_PKG_VERSION"));
}

// ---------------------------------------------------------------------------
// TTY detection (simple, no extra deps)
// ---------------------------------------------------------------------------

fn atty_stdout() -> bool {
    // crossterm is already a dependency; use it for TTY detection
    crossterm::tty::IsTty::is_tty(&io::stderr())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semver_basic() {
        assert_eq!(parse_semver("0.3.0"), Some((0, 3, 0)));
        assert_eq!(parse_semver("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_semver("10.20.30"), Some((10, 20, 30)));
    }

    #[test]
    fn test_parse_semver_invalid() {
        assert_eq!(parse_semver(""), None);
        assert_eq!(parse_semver("1.2"), None);
        assert_eq!(parse_semver("not-a-version"), None);
        assert_eq!(parse_semver("1.2.x"), None);
    }

    #[test]
    fn test_is_version_newer_true() {
        assert!(is_version_newer("0.3.0", "0.4.0"));
        assert!(is_version_newer("0.3.0", "1.0.0"));
        assert!(is_version_newer("0.3.0", "v0.3.1"));
        assert!(is_version_newer("1.0.0", "1.0.1"));
    }

    #[test]
    fn test_is_version_newer_false() {
        assert!(!is_version_newer("0.3.0", "0.3.0")); // same
        assert!(!is_version_newer("0.4.0", "0.3.0")); // older
        assert!(!is_version_newer("1.0.0", "0.9.9")); // older
    }

    #[test]
    fn test_is_version_newer_with_v_prefix() {
        assert!(is_version_newer("v0.3.0", "v0.4.0"));
        assert!(is_version_newer("0.3.0", "v0.4.0"));
        assert!(is_version_newer("v0.3.0", "0.4.0"));
    }

    #[test]
    fn test_is_version_newer_invalid_returns_false() {
        assert!(!is_version_newer("bad", "0.4.0"));
        assert!(!is_version_newer("0.3.0", "bad"));
        assert!(!is_version_newer("bad", "bad"));
    }

    #[test]
    fn test_platform_key_returns_ok() {
        // Should not error on any CI/dev platform
        let result = platform_key();
        assert!(result.is_ok(), "platform_key() failed: {:?}", result);
        let key = result.unwrap();
        assert!(
            ["darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64", "windows-amd64"]
                .contains(&key),
            "Unexpected platform key: {key}"
        );
    }

    #[test]
    fn test_user_agent_string_format() {
        let ua = user_agent_string();
        assert!(ua.starts_with("ah-scan/"), "UA should start with ah-scan/: {ua}");
        assert!(ua.contains('/'), "UA should contain OS/ARCH: {ua}");
        assert!(ua.contains('('), "UA should contain parens: {ua}");
    }

    #[test]
    fn test_verify_sha256_correct() {
        let dir = std::env::temp_dir().join("ah-scan-test-sha256");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test-verify.bin");
        fs::write(&path, b"hello world").unwrap();

        // SHA-256 of "hello world"
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(verify_sha256(&path, expected).is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_verify_sha256_mismatch() {
        let dir = std::env::temp_dir().join("ah-scan-test-sha256-bad");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test-verify-bad.bin");
        fs::write(&path, b"hello world").unwrap();

        let bad_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = verify_sha256(&path, bad_hash);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SHA-256 mismatch"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_verify_sha256_case_insensitive() {
        let dir = std::env::temp_dir().join("ah-scan-test-sha256-case");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test-verify-case.bin");
        fs::write(&path, b"hello world").unwrap();

        let expected = "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
        assert!(verify_sha256(&path, expected).is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_manifest_deserialization() {
        let json = r#"{
            "version": "v0.4.0",
            "date": "2026-03-21T00:00:00Z",
            "artifacts": {
                "darwin-arm64": {
                    "url": "https://example.com/ah-scanner-darwin-arm64.tar.gz",
                    "sha256": "abcdef1234567890"
                }
            }
        }"#;
        let manifest: UpdateManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.version, "v0.4.0");
        assert_eq!(manifest.artifacts.len(), 1);
        assert!(manifest.artifacts.contains_key("darwin-arm64"));
        assert_eq!(
            manifest.artifacts["darwin-arm64"].sha256,
            "abcdef1234567890"
        );
    }

    #[test]
    fn test_manifest_deserialization_no_artifacts() {
        // Backwards-compatible with old latest.json format
        let json = r#"{"version":"v0.3.0","date":"2026-03-20T00:00:00Z"}"#;
        let manifest: UpdateManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.version, "v0.3.0");
        assert!(manifest.artifacts.is_empty());
    }

    #[test]
    fn test_check_cache_roundtrip() {
        let result = UpdateCheckResult {
            current_version: "0.3.0".into(),
            latest_version: "v0.4.0".into(),
            is_newer: true,
            artifact: None,
        };
        // write_check_cache writes to ~/.ahscan/ — just verify it doesn't panic
        write_check_cache(&result);
        // And reading should return something (or None if dir doesn't exist)
        let _ = read_check_cache();
    }

    #[test]
    fn test_print_version_does_not_panic() {
        // Just ensure it doesn't panic; output goes to stdout
        print_version();
    }

    #[test]
    fn test_is_version_newer_same_version_is_false() {
        // Regression: after upgrading the binary the cached is_newer flag
        // would still be true. The fix re-evaluates against the current
        // binary version, so equal versions must return false.
        let current = env!("CARGO_PKG_VERSION");
        assert!(
            !is_version_newer(current, current),
            "same version should not be considered newer (got true for {current})"
        );
    }
}
