//! Host and workdir surface discovery.
//!
//! Enumerates candidate files/directories from bounded host roots
//! or an explicit workspace path. Each candidate is tagged with its
//! origin ("host", "workdir", or "filesystem") so downstream detectors
//! and reports can distinguish them.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Guardrails – directory depth limit for bounded walks
// ---------------------------------------------------------------------------

pub const MAX_DEPTH: usize = 5;

// ---------------------------------------------------------------------------
// Excluded directory sets
// ---------------------------------------------------------------------------

const NON_FORENSIC_EXCLUDED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".idea",
    ".vscode",
    ".next",
    "target",
    ".cache",
    "cache",
    "Caches",
    ".cargo",
    ".rustup",
    ".npm",
    ".pnpm-store",
    ".yarn",
    ".gradle",
    ".m2",
    ".terraform",
    ".bundle",
    ".gem",
    ".nuget",
    ".swiftpm",
    ".build",
    "DerivedData",
    "vendor",
];

const FILESYSTEM_EXTRA_EXCLUDED: &[&str] = &[
    "proc",
    "sys",
    "dev",
    "run",
    "snap",
    "boot",
    "tmp",
    "private",
    "cores",
    "Volumes",
    "Network",
    "automount",
    "System",
    "Library",
];

const AI_CLI_CONFIG_DIRS: &[&str] = &[
    ".claude",
    ".cursor",
    ".aider",
    ".ollama",
    ".continue",
    ".vscode",
    ".vscode-insiders",
];

const FILESYSTEM_EXTRA_ROOTS: &[&str] = &["/Applications", "/opt/homebrew", "/usr/local"];

// ---------------------------------------------------------------------------
// Candidate model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Candidate {
    pub path: PathBuf,
    pub origin: String,
}

// ---------------------------------------------------------------------------
// Excluded-dir helpers
// ---------------------------------------------------------------------------

fn nonforensic_excluded_set() -> HashSet<&'static str> {
    NON_FORENSIC_EXCLUDED_DIRS.iter().copied().collect()
}

fn filesystem_excluded_set() -> HashSet<&'static str> {
    let mut set = nonforensic_excluded_set();
    for d in FILESYSTEM_EXTRA_EXCLUDED {
        set.insert(d);
    }
    set
}

fn is_excluded_dir(entry: &walkdir::DirEntry, excluded: &HashSet<&str>) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    entry
        .file_name()
        .to_str()
        .is_some_and(|name| excluded.contains(name))
}

fn should_descend(entry: &walkdir::DirEntry, excluded: &HashSet<&str>) -> bool {
    entry.depth() == 0 || !is_excluded_dir(entry, excluded)
}

// ---------------------------------------------------------------------------
// Platform-aware roots
// ---------------------------------------------------------------------------

fn home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

pub fn host_roots() -> Vec<PathBuf> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let mut roots = vec![home.join(".config"), home.join(".local").join("share")];

    // Agentic tool config directories
    for dir in AI_CLI_CONFIG_DIRS {
        roots.push(home.join(dir));
    }

    // VS Code / Cursor settings per platform
    if std::env::consts::OS == "macos" {
        let app_support = home.join("Library").join("Application Support");
        roots.push(app_support.clone());
        roots.push(app_support.join("Code").join("User"));
        roots.push(app_support.join("Code - Insiders").join("User"));
        roots.push(app_support.join("Cursor").join("User"));
    } else {
        roots.push(home.join(".config").join("Code").join("User"));
        roots.push(home.join(".config").join("Code - Insiders").join("User"));
        roots.push(home.join(".config").join("Cursor").join("User"));
    }

    roots.into_iter().filter(|r| r.exists()).collect()
}

pub fn browser_profile_roots() -> Vec<PathBuf> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let roots = match std::env::consts::OS {
        "macos" => {
            let app_support = home.join("Library").join("Application Support");
            vec![
                app_support.join("Google").join("Chrome"),
                app_support.join("Microsoft Edge"),
                app_support.join("BraveSoftware").join("Brave-Browser"),
                app_support.join("Arc").join("User Data"),
            ]
        }
        "linux" => {
            let config = home.join(".config");
            vec![
                config.join("google-chrome"),
                config.join("microsoft-edge"),
                config.join("BraveSoftware").join("Brave-Browser"),
            ]
        }
        _ => Vec::new(),
    };
    roots.into_iter().filter(|r| r.exists()).collect()
}

pub fn ai_cli_config_roots() -> Vec<PathBuf> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    AI_CLI_CONFIG_DIRS
        .iter()
        .map(|d| home.join(d))
        .filter(|p| p.exists())
        .collect()
}

// ---------------------------------------------------------------------------
// Walking functions
// ---------------------------------------------------------------------------

pub fn walk_bounded(root: &Path, origin: &str, on_tick: Option<&dyn Fn(&str)>) -> Vec<Candidate> {
    let excluded = nonforensic_excluded_set();
    let mut candidates = Vec::new();
    let mut count: usize = 0;

    let walker = WalkDir::new(root).max_depth(MAX_DEPTH).follow_links(false);
    let filtered = walker
        .into_iter()
        .filter_entry(|e| should_descend(e, &excluded));

    for entry in filtered.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        candidates.push(Candidate {
            path: entry.into_path(),
            origin: origin.to_string(),
        });
        count += 1;
        if let Some(tick) = on_tick {
            if count % 5000 == 0 {
                tick(&format!("{count} files"));
            }
        }
    }
    candidates
}

pub fn walk_deep_workdir(
    root: &Path,
    origin: &str,
    on_tick: Option<&dyn Fn(&str)>,
) -> Vec<Candidate> {
    let excluded = nonforensic_excluded_set();
    let mut candidates = Vec::new();
    let mut count: usize = 0;

    let walker = WalkDir::new(root).follow_links(false);
    let filtered = walker
        .into_iter()
        .filter_entry(|e| should_descend(e, &excluded));

    for entry in filtered.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        candidates.push(Candidate {
            path: entry.into_path(),
            origin: origin.to_string(),
        });
        count += 1;
        if let Some(tick) = on_tick {
            if count % 5000 == 0 {
                tick(&format!("{count} files"));
            }
        }
    }
    candidates
}

// ---------------------------------------------------------------------------
// High-level discovery entry points
// ---------------------------------------------------------------------------

pub fn discover_host_surfaces(on_tick: Option<&dyn Fn(&str)>) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for root in host_roots() {
        candidates.extend(walk_bounded(&root, "host", on_tick));
    }
    candidates
}

pub fn discover_workdir_surfaces(
    path: &Path,
    deep: bool,
    on_tick: Option<&dyn Fn(&str)>,
) -> Vec<Candidate> {
    let resolved = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    if !resolved.is_dir() {
        return Vec::new();
    }
    if deep {
        walk_deep_workdir(&resolved, "workdir", on_tick)
    } else {
        walk_bounded(&resolved, "workdir", on_tick)
    }
}

pub fn discover_filesystem_surfaces(on_tick: Option<&dyn Fn(&str)>) -> Vec<Candidate> {
    let excluded = filesystem_excluded_set();
    let mut candidates = Vec::new();
    let mut count: usize = 0;

    let mut scan_roots: Vec<PathBuf> = Vec::new();
    if let Some(home) = home_dir() {
        scan_roots.push(home);
    }
    for extra in FILESYSTEM_EXTRA_ROOTS {
        let p = PathBuf::from(extra);
        if p.exists() {
            scan_roots.push(p);
        }
    }

    for root in &scan_roots {
        let walker = WalkDir::new(root).follow_links(false);
        let filtered = walker
            .into_iter()
            .filter_entry(|e| should_descend(e, &excluded));

        for entry in filtered.filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            candidates.push(Candidate {
                path: entry.into_path(),
                origin: "filesystem".to_string(),
            });
            count += 1;
            if let Some(tick) = on_tick {
                if count % 10_000 == 0 {
                    tick(&format!("{count} files"));
                }
            }
        }
    }
    candidates
}

pub fn discover_home_surfaces(on_tick: Option<&dyn Fn(&str)>) -> Vec<Candidate> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    walk_deep_workdir(&home, "home", on_tick)
}

pub fn discover_root_surfaces(on_tick: Option<&dyn Fn(&str)>) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut count: usize = 0;

    let root = if cfg!(windows) {
        PathBuf::from("C:\\")
    } else {
        PathBuf::from("/")
    };

    // Full scan: no directory exclusions — enumerate everything.
    let walker = WalkDir::new(&root).follow_links(false);

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        candidates.push(Candidate {
            path: entry.into_path(),
            origin: "root".to_string(),
        });
        count += 1;
        if let Some(tick) = on_tick {
            if count % 10_000 == 0 {
                tick(&format!("{count} files"));
            }
        }
    }
    candidates
}

pub fn discover_file_surface(path: &Path) -> Vec<Candidate> {
    let resolved = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    if !resolved.is_file() {
        return Vec::new();
    }
    vec![Candidate {
        path: resolved,
        origin: "workdir".to_string(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn nonforensic_excluded_set_contains_expected_dirs() {
        let set = nonforensic_excluded_set();
        assert!(set.contains(".git"));
        assert!(set.contains("node_modules"));
        assert!(set.contains("target"));
        assert!(set.contains("__pycache__"));
        assert!(set.contains(".cargo"));
        assert!(set.contains("vendor"));
    }

    #[test]
    fn filesystem_excluded_set_extends_nonforensic_set() {
        let deep = nonforensic_excluded_set();
        let fs_set = filesystem_excluded_set();
        for item in &deep {
            assert!(fs_set.contains(item));
        }
        assert!(fs_set.contains("proc"));
        assert!(fs_set.contains("sys"));
        assert!(fs_set.contains("Library"));
    }

    #[test]
    fn walk_bounded_finds_files() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("test.txt"), "hello").unwrap();
        fs::create_dir(tmp.path().join("sub")).unwrap();
        fs::write(tmp.path().join("sub").join("nested.txt"), "world").unwrap();

        let candidates = walk_bounded(tmp.path(), "test", None);
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().all(|c| c.origin == "test"));
    }

    #[test]
    fn walk_bounded_skips_dirs() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("sub")).unwrap();
        let candidates = walk_bounded(tmp.path(), "test", None);
        assert!(candidates.is_empty());
    }

    #[test]
    fn walk_bounded_excludes_low_value_dirs() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("target")).unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("target").join("generated.txt"), "noise").unwrap();
        fs::write(tmp.path().join("src").join("main.rs"), "fn main() {}\n").unwrap();

        let candidates = walk_bounded(tmp.path(), "test", None);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].path.ends_with("src/main.rs"));
    }

    #[test]
    fn walk_bounded_preserves_explicit_root_even_if_name_is_excluded() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join(".vscode");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("settings.json"), "{}\n").unwrap();

        let candidates = walk_bounded(&root, "host", None);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].path.ends_with(".vscode/settings.json"));
    }

    #[test]
    fn walk_deep_workdir_excludes_git() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        fs::write(tmp.path().join(".git").join("config"), "git data").unwrap();
        fs::write(tmp.path().join("real.txt"), "real file").unwrap();

        let candidates = walk_deep_workdir(tmp.path(), "workdir", None);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].path.ends_with("real.txt"));
    }

    #[test]
    fn walk_deep_workdir_excludes_node_modules() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("node_modules")).unwrap();
        fs::write(tmp.path().join("node_modules").join("package.json"), "{}").unwrap();
        fs::write(tmp.path().join("index.js"), "code").unwrap();

        let candidates = walk_deep_workdir(tmp.path(), "workdir", None);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].path.ends_with("index.js"));
    }

    #[test]
    fn walk_deep_workdir_excludes_dependency_cache_dirs() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join(".cargo").join("registry").join("src")).unwrap();
        fs::write(
            tmp.path()
                .join(".cargo")
                .join("registry")
                .join("src")
                .join("agents.md"),
            "cached dependency file",
        )
        .unwrap();
        fs::write(tmp.path().join("AGENTS.md"), "real file").unwrap();

        let candidates = walk_deep_workdir(tmp.path(), "test", None);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].path.ends_with("AGENTS.md"));
    }

    #[test]
    fn discover_file_surface_single_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("agents.md");
        fs::write(&file, "# Agents").unwrap();

        let candidates = discover_file_surface(&file);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].origin, "workdir");
    }

    #[test]
    fn discover_file_surface_nonexistent() {
        let candidates = discover_file_surface(Path::new("/nonexistent/file.txt"));
        assert!(candidates.is_empty());
    }

    #[test]
    fn discover_file_surface_directory_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let candidates = discover_file_surface(tmp.path());
        assert!(candidates.is_empty());
    }

    #[test]
    fn discover_workdir_surfaces_nonexistent() {
        let candidates = discover_workdir_surfaces(Path::new("/nonexistent/path"), false, None);
        assert!(candidates.is_empty());
    }

    #[test]
    fn discover_workdir_surfaces_finds_files() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("test.md"), "hello").unwrap();

        let candidates = discover_workdir_surfaces(tmp.path(), false, None);
        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn discover_workdir_deep_excludes_git() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        fs::write(tmp.path().join(".git").join("HEAD"), "ref").unwrap();
        fs::write(tmp.path().join("code.rs"), "fn main() {}").unwrap();

        let candidates = discover_workdir_surfaces(tmp.path(), true, None);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].path.ends_with("code.rs"));
    }

    #[test]
    fn host_roots_returns_existing_paths() {
        let roots = host_roots();
        for root in &roots {
            assert!(root.exists(), "{:?} should exist", root);
        }
    }

    #[test]
    fn ai_cli_config_roots_returns_existing_paths() {
        let roots = ai_cli_config_roots();
        for root in &roots {
            assert!(root.exists(), "{:?} should exist", root);
        }
    }
}
