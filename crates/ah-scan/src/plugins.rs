//! Plugin management commands — list, install, remove, info.

use std::fs;
use std::path::PathBuf;

use crate::engine::PluginRegistry;
use ah_scan_sdk::DetectorManifest;

use crate::cli::PluginAction;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";

// ---------------------------------------------------------------------------
// Plugin directory
// ---------------------------------------------------------------------------

fn plugin_dir() -> PathBuf {
    dirs::home_dir()
        .expect("unable to determine home directory")
        .join(".ahscan")
        .join("plugins")
}

fn ensure_plugin_dir() -> PathBuf {
    let dir = plugin_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir).expect("failed to create plugin directory");
    }
    dir
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub fn handle_plugin_action(action: &PluginAction) {
    match action {
        PluginAction::List => cmd_list(),
        PluginAction::Install { path } => cmd_install(path),
        PluginAction::Remove { name } => cmd_remove(name),
        PluginAction::Info { name } => cmd_info(name),
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn cmd_list() {
    let dir = plugin_dir();
    if !dir.is_dir() {
        println!("{DIM}No plugins installed. Directory: {}{RESET}", dir.display());
        println!();
        println!("Install a plugin:");
        println!("  ah-scan plugins install <path-to-plugin.wasm>");
        return;
    }

    let mut registry = PluginRegistry::new();
    match registry.load_from_dir(&dir) {
        Ok(0) => {
            println!("{DIM}No plugins found in {}{RESET}", dir.display());
            return;
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("{RED}Error loading plugins: {e}{RESET}");
            return;
        }
    }

    println!();
    println!("  {BOLD}Installed detector plugins{RESET}");
    println!("  {DIM}{}{RESET}", "─".repeat(50));

    for (name, source) in registry.list() {
        let location = match source {
            crate::engine::PluginSource::File(p) => p.display().to_string(),
            crate::engine::PluginSource::Bundled(n) => format!("(bundled: {n})"),
        };
        println!("  {CYAN}{name:<24}{RESET} {DIM}{location}{RESET}");
    }
    println!();
    println!("  {DIM}Plugin directory: {}{RESET}", dir.display());
    println!();
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

fn cmd_install(path: &PathBuf) {
    if !path.exists() {
        eprintln!("{RED}File not found: {}{RESET}", path.display());
        std::process::exit(1);
    }

    let ext = path.extension().and_then(|e| e.to_str());
    if ext != Some("wasm") {
        eprintln!("{RED}Expected a .wasm file, got: {}{RESET}", path.display());
        std::process::exit(1);
    }

    let dir = ensure_plugin_dir();
    let file_name = path
        .file_name()
        .expect("file must have a name");
    let dest = dir.join(file_name);

    if dest.exists() {
        eprintln!(
            "{BOLD}Replacing{RESET} existing plugin: {}",
            file_name.to_string_lossy()
        );
    }

    fs::copy(path, &dest).unwrap_or_else(|e| {
        eprintln!("{RED}Failed to install plugin: {e}{RESET}");
        std::process::exit(1);
    });

    // Also copy sidecar manifest if it exists next to the .wasm
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let manifest_src = path
        .parent()
        .map(|p| p.join(format!("{stem}.manifest.json")));
    if let Some(ref src) = manifest_src {
        if src.exists() {
            let manifest_dest = dir.join(format!("{stem}.manifest.json"));
            let _ = fs::copy(src, &manifest_dest);
        }
    }

    println!(
        "{GREEN}✓{RESET} Installed plugin: {BOLD}{}{RESET}",
        file_name.to_string_lossy()
    );
    println!("  {DIM}Location: {}{RESET}", dest.display());
}

// ---------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------

fn cmd_remove(name: &str) {
    let dir = plugin_dir();
    let wasm_path = dir.join(format!("{name}.wasm"));
    let manifest_path = dir.join(format!("{name}.manifest.json"));

    if !wasm_path.exists() {
        eprintln!("{RED}Plugin not found: {name}{RESET}");
        eprintln!("{DIM}Expected: {}{RESET}", wasm_path.display());
        std::process::exit(1);
    }

    fs::remove_file(&wasm_path).unwrap_or_else(|e| {
        eprintln!("{RED}Failed to remove plugin: {e}{RESET}");
        std::process::exit(1);
    });

    if manifest_path.exists() {
        let _ = fs::remove_file(&manifest_path);
    }

    println!("{GREEN}✓{RESET} Removed plugin: {BOLD}{name}{RESET}");
}

// ---------------------------------------------------------------------------
// info
// ---------------------------------------------------------------------------

fn cmd_info(name: &str) {
    let dir = plugin_dir();
    let wasm_path = dir.join(format!("{name}.wasm"));
    let manifest_path = dir.join(format!("{name}.manifest.json"));

    if !wasm_path.exists() {
        eprintln!("{RED}Plugin not found: {name}{RESET}");
        std::process::exit(1);
    }

    let file_size = fs::metadata(&wasm_path)
        .map(|m| m.len())
        .unwrap_or(0);

    println!();
    println!("  {BOLD}Plugin: {CYAN}{name}{RESET}");
    println!("  {DIM}{}{RESET}", "─".repeat(40));
    println!("  File:     {}", wasm_path.display());
    println!("  Size:     {}", format_bytes(file_size));

    if manifest_path.exists() {
        if let Ok(content) = fs::read_to_string(&manifest_path) {
            if let Ok(manifest) = serde_json::from_str::<DetectorManifest>(&content) {
                println!("  Version:  {}", manifest.version);
                println!("  SDK:      {}", manifest.sdk_version);
                println!("  Desc:     {}", manifest.description);
                println!(
                    "  Types:    {}",
                    manifest.artifact_types.join(", ")
                );

                // SDK compatibility check
                let compatible = check_sdk_compatibility(&manifest.sdk_version);
                if compatible {
                    println!("  Compat:   {GREEN}✓ compatible{RESET}");
                } else {
                    println!(
                        "  Compat:   {RED}✗ sdk_version {} ≠ host {}{RESET}",
                        manifest.sdk_version,
                        ah_scan_sdk::SDK_VERSION
                    );
                }
            }
        }
    } else {
        println!("  {DIM}No manifest file found{RESET}");
    }
    println!();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Check if a plugin's SDK version is compatible with the host.
/// Currently requires an exact major.minor match.
fn check_sdk_compatibility(plugin_sdk_version: &str) -> bool {
    let host = ah_scan_sdk::SDK_VERSION;
    let host_parts: Vec<&str> = host.split('.').collect();
    let plugin_parts: Vec<&str> = plugin_sdk_version.split('.').collect();

    if host_parts.len() < 2 || plugin_parts.len() < 2 {
        return false;
    }

    // Major and minor must match
    host_parts[0] == plugin_parts[0] && host_parts[1] == plugin_parts[1]
}
