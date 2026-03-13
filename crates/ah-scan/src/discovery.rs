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
// Guardrails – prevent runaway scans
// ---------------------------------------------------------------------------

pub const MAX_DEPTH: usize = 5;
pub const MAX_FILES: usize = 50_000;
pub const MAX_FILES_DEEP: usize = 500_000;

// ---------------------------------------------------------------------------
// Excluded directory sets
// ---------------------------------------------------------------------------

const DEEP_EXCLUDED_DIRS: &[&str] = &[
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
];

const AI_CLI_CONFIG_DIRS: &[&str] = &[".claude", ".cursor", ".aider", ".ollama", ".continue"];

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

fn deep_excluded_set() -> HashSet<&'static str> {
    DEEP_EXCLUDED_DIRS.iter().copied().collect()
}

fn filesystem_excluded_set() -> HashSet<&'static str> {
    let mut set = deep_excluded_set();
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
        .map_or(false, |name| excluded.contains(name))
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
    if std::env::consts::OS == "macos" {
        roots.push(home.join("Library").join("Application Support"));
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

pub fn walk_bounded(
    root: &Path,
    origin: &str,
    on_tick: Option<&dyn Fn(&str)>,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut count: usize = 0;

    let walker = WalkDir::new(root)
        .max_depth(MAX_DEPTH)
        .follow_links(false);

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
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
        if count >= MAX_FILES {
            break;
        }
    }
    candidates
}

pub fn walk_deep_workdir(
    root: &Path,
    origin: &str,
    on_tick: Option<&dyn Fn(&str)>,
) -> Vec<Candidate> {
    let excluded = deep_excluded_set();
    let mut candidates = Vec::new();
    let mut count: usize = 0;

    let walker = WalkDir::new(root).follow_links(false);
    let filtered = walker.into_iter().filter_entry(|e| !is_excluded_dir(e, &excluded));

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
        if count >= MAX_FILES_DEEP {
            break;
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
            .filter_entry(|e| !is_excluded_dir(e, &excluded));

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
