//! Single WASM detector plugin wrapper.
//!
//! Manages an Extism plugin instance, handles serialization of the
//! `DetectRequest`/`DetectResponse` protocol, and provides error context.

use ah_scan_sdk::{DetectRequest, DetectResponse, DetectorManifest, DETECT_FUNCTION};
use extism::{Manifest as ExtismManifest, Plugin, Wasm};
use std::path::Path;

/// A loaded WASM detector plugin ready to execute.
pub struct DetectorPlugin {
    name: String,
    manifest: Option<DetectorManifest>,
    plugin: Plugin,
}

impl DetectorPlugin {
    /// Load a detector plugin from a `.wasm` file on disk.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let file_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let wasm = Wasm::file(path);
        let extism_manifest = ExtismManifest::new([wasm]);
        let plugin = Plugin::new(extism_manifest, [], true)
            .map_err(|e| format!("Failed to load plugin '{}': {e}", file_name))?;

        Ok(Self {
            name: file_name,
            manifest: None,
            plugin,
        })
    }

    /// Load a detector plugin from in-memory WASM bytes.
    pub fn from_bytes(name: &str, bytes: &[u8]) -> Result<Self, String> {
        let wasm = Wasm::data(bytes.to_vec());
        let extism_manifest = ExtismManifest::new([wasm]);
        let plugin = Plugin::new(extism_manifest, [], true)
            .map_err(|e| format!("Failed to load plugin '{name}': {e}"))?;

        Ok(Self {
            name: name.to_string(),
            manifest: None,
            plugin,
        })
    }

    /// The plugin name (derived from filename or explicitly set).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The plugin manifest, if loaded.
    pub fn manifest(&self) -> Option<&DetectorManifest> {
        self.manifest.as_ref()
    }

    /// Set the manifest for this plugin.
    pub fn set_manifest(&mut self, manifest: DetectorManifest) {
        self.name = manifest.name.clone();
        self.manifest = Some(manifest);
    }

    /// Run detection on the given request.
    ///
    /// Serializes the request to JSON, calls the plugin's `detect` export,
    /// and deserializes the response.
    pub fn detect(&mut self, request: &DetectRequest) -> Result<DetectResponse, String> {
        let input = serde_json::to_vec(request)
            .map_err(|e| format!("Failed to serialize DetectRequest for '{}': {e}", self.name))?;

        let output = self
            .plugin
            .call::<&[u8], Vec<u8>>(DETECT_FUNCTION, &input)
            .map_err(|e| format!("Plugin '{}' failed during detect: {e}", self.name))?;

        serde_json::from_slice(&output)
            .map_err(|e| format!("Plugin '{}' returned invalid DetectResponse: {e}", self.name))
    }
}
