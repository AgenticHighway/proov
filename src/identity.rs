use std::fs;
use std::path::{Path, PathBuf};

use uuid::Uuid;

/// Returns `true` when `value` is a valid v4-style UUID string.
pub fn is_valid_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok()
}

/// `~/.ahscan/scanner_uuid`
pub fn default_scanner_uuid_path() -> PathBuf {
    ahscan_dir().join("scanner_uuid")
}

/// `~/.ahscan/scanner_account_uuid`
pub fn default_scanner_account_uuid_path() -> PathBuf {
    ahscan_dir().join("scanner_account_uuid")
}

fn ahscan_dir() -> PathBuf {
    dirs::home_dir()
        .expect("unable to determine home directory")
        .join(".ahscan")
}

/// Resolve a UUID through the following cascade:
///
/// 1. `explicit` — use if provided (must be valid UUID).
/// 2. Environment variable `env_var`.
/// 3. Read from `id_path` on disk.
/// 4. Generate a new v4 UUID and persist it to `id_path`.
///
/// `field_name` is used in error messages (e.g. "scanner_uuid").
pub fn resolve_persisted_uuid(
    explicit: Option<&str>,
    env_var: &str,
    id_path: &Path,
    field_name: &str,
) -> Result<String, String> {
    // 1. Explicit value
    if let Some(val) = explicit {
        let val = val.trim();
        if !is_valid_uuid(val) {
            return Err(format!("Explicit {field_name} is not a valid UUID: {val}"));
        }
        return Ok(val.to_string());
    }

    // 2. Environment variable
    if let Ok(val) = std::env::var(env_var) {
        let val = val.trim().to_string();
        if !val.is_empty() {
            if !is_valid_uuid(&val) {
                return Err(format!(
                    "Environment variable {env_var} is not a valid UUID: {val}"
                ));
            }
            return Ok(val);
        }
    }

    // 3. Read from file
    if id_path.exists() {
        let content = fs::read_to_string(id_path)
            .map_err(|e| format!("Failed to read {field_name} from {}: {e}", id_path.display()))?;
        let val = content.trim().to_string();
        if !val.is_empty() {
            if !is_valid_uuid(&val) {
                return Err(format!(
                    "Persisted {field_name} in {} is not a valid UUID: {val}",
                    id_path.display()
                ));
            }
            return Ok(val);
        }
    }

    // 4. Generate and persist
    let new_uuid = Uuid::new_v4().to_string();
    if let Some(parent) = id_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create directory {} for {field_name}: {e}",
                parent.display()
            )
        })?;
    }
    fs::write(id_path, &new_uuid).map_err(|e| {
        format!(
            "Failed to persist {field_name} to {}: {e}",
            id_path.display()
        )
    })?;

    Ok(new_uuid)
}

/// Resolve the scanner UUID (convenience wrapper).
pub fn resolve_scanner_uuid(explicit: Option<&str>) -> Result<String, String> {
    resolve_persisted_uuid(
        explicit,
        "AH_SCANNER_UUID",
        &default_scanner_uuid_path(),
        "scanner_uuid",
    )
}

/// Resolve the scanner account UUID (convenience wrapper).
pub fn resolve_scanner_account_uuid(explicit: Option<&str>) -> Result<String, String> {
    resolve_persisted_uuid(
        explicit,
        "AH_SCANNER_ACCOUNT_UUID",
        &default_scanner_account_uuid_path(),
        "scanner_account_uuid",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn valid_uuid_check() {
        assert!(is_valid_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_valid_uuid("not-a-uuid"));
        assert!(!is_valid_uuid(""));
    }

    #[test]
    fn default_paths_end_correctly() {
        let p = default_scanner_uuid_path();
        assert!(p.ends_with("scanner_uuid"));
        let p = default_scanner_account_uuid_path();
        assert!(p.ends_with("scanner_account_uuid"));
    }

    #[test]
    fn explicit_value_wins() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let tmp = tempdir();
        let path = tmp.join("id");
        let result = resolve_persisted_uuid(Some(uuid), "UNUSED_VAR_1234", &path, "test");
        assert_eq!(result.unwrap(), uuid);
    }

    #[test]
    fn invalid_explicit_is_rejected() {
        let tmp = tempdir();
        let path = tmp.join("id");
        let result = resolve_persisted_uuid(Some("bad"), "UNUSED_VAR_1234", &path, "test");
        assert!(result.is_err());
    }

    #[test]
    fn env_var_fallback() {
        let uuid = "660e8400-e29b-41d4-a716-446655440000";
        let var_name = "AH_TEST_UUID_ENV_FALLBACK";
        env::set_var(var_name, uuid);
        let tmp = tempdir();
        let path = tmp.join("id");
        let result = resolve_persisted_uuid(None, var_name, &path, "test");
        env::remove_var(var_name);
        assert_eq!(result.unwrap(), uuid);
    }

    #[test]
    fn file_fallback() {
        let uuid = "770e8400-e29b-41d4-a716-446655440000";
        let tmp = tempdir();
        let path = tmp.join("id");
        fs::write(&path, uuid).unwrap();
        let result =
            resolve_persisted_uuid(None, "UNUSED_VAR_5678", &path, "test");
        assert_eq!(result.unwrap(), uuid);
    }

    #[test]
    fn generates_and_persists_when_nothing_exists() {
        let tmp = tempdir();
        let path = tmp.join("sub").join("id");
        let result =
            resolve_persisted_uuid(None, "UNUSED_VAR_9012", &path, "test");
        let uuid = result.unwrap();
        assert!(is_valid_uuid(&uuid));
        assert_eq!(fs::read_to_string(&path).unwrap(), uuid);
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ah_test_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
