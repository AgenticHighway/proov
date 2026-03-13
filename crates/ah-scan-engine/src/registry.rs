//! Plugin registry — discovers and loads WASM detector plugins.
//!
//! Scans a directory for `.wasm` files and optional sidecar manifests,
//! loads them as `DetectorPlugin` instances, and provides iteration.
//! Validates SDK version compatibility when a manifest is present.

use std::path::{Path, PathBuf};

use ah_scan_sdk::{DetectorManifest, SDK_VERSION};

use crate::plugin::DetectorPlugin;

/// Where a plugin was loaded from.
#[derive(Debug, Clone)]
pub enum PluginSource {
    /// Loaded from a `.wasm` file on disk.
    File(PathBuf),
    /// Loaded from in-memory bytes (e.g. bundled).
    Bundled(String),
}

/// Registry of loaded detector plugins.
pub struct PluginRegistry {
    plugins: Vec<(DetectorPlugin, PluginSource)>,
}

impl PluginRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Discover and load all `.wasm` plugins from a directory.
    ///
    /// For each `.wasm` file, looks for a sidecar `<name>.manifest.json`
    /// file containing a [`DetectorManifest`].
    pub fn load_from_dir(&mut self, dir: &Path) -> Result<usize, String> {
        if !dir.is_dir() {
            return Ok(0);
        }

        let entries = std::fs::read_dir(dir)
            .map_err(|e| format!("Failed to read plugin directory {}: {e}", dir.display()))?;

        let mut count = 0;
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
                continue;
            }

            match DetectorPlugin::from_file(&path) {
                Ok(mut plugin) => {
                    if let Some(manifest) = load_sidecar_manifest(&path) {
                        if !is_sdk_compatible(&manifest.sdk_version) {
                            eprintln!(
                                "Warning: plugin {} targets SDK {} (host is {}), skipping",
                                path.display(),
                                manifest.sdk_version,
                                SDK_VERSION,
                            );
                            continue;
                        }
                        plugin.set_manifest(manifest);
                    }
                    self.plugins.push((plugin, PluginSource::File(path)));
                    count += 1;
                }
                Err(e) => {
                    eprintln!("Warning: skipping plugin {}: {e}", path.display());
                }
            }
        }

        Ok(count)
    }

    /// Register a plugin loaded from in-memory bytes.
    pub fn register_bundled(
        &mut self,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), String> {
        let plugin = DetectorPlugin::from_bytes(name, bytes)?;
        self.plugins
            .push((plugin, PluginSource::Bundled(name.to_string())));
        Ok(())
    }

    /// Number of loaded plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Iterate over loaded plugins mutably (needed for calling `detect`).
    pub fn plugins_mut(&mut self) -> impl Iterator<Item = (&mut DetectorPlugin, &PluginSource)> {
        self.plugins
            .iter_mut()
            .map(|(plugin, source)| (plugin, source as &PluginSource))
    }

    /// List plugin names and sources.
    pub fn list(&self) -> Vec<(&str, &PluginSource)> {
        self.plugins
            .iter()
            .map(|(p, s)| (p.name(), s))
            .collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Try to load a sidecar manifest file for a `.wasm` plugin.
///
/// For `detectors/foo.wasm`, looks for `detectors/foo.manifest.json`.
fn load_sidecar_manifest(wasm_path: &Path) -> Option<DetectorManifest> {
    let stem = wasm_path.file_stem()?.to_str()?;
    let manifest_path = wasm_path
        .parent()?
        .join(format!("{stem}.manifest.json"));

    if !manifest_path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(&manifest_path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Check if a plugin's SDK version is compatible with the host.
///
/// Requires matching major and minor version. Patch differences are allowed.
fn is_sdk_compatible(plugin_sdk_version: &str) -> bool {
    let host_parts: Vec<&str> = SDK_VERSION.split('.').collect();
    let plugin_parts: Vec<&str> = plugin_sdk_version.split('.').collect();

    if host_parts.len() < 2 || plugin_parts.len() < 2 {
        return false;
    }

    host_parts[0] == plugin_parts[0] && host_parts[1] == plugin_parts[1]
}
