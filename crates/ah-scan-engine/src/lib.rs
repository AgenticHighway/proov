//! # ah-scan-engine
//!
//! WASM plugin host engine for ah-scan detectors.
//!
//! This crate loads `.wasm` detector plugins via [Extism](https://extism.org),
//! feeds them `DetectRequest` payloads, and collects `DetectResponse` results.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐    JSON     ┌──────────────┐
//! │  Scanner     │ ─────────► │  WASM Plugin  │
//! │  (host)      │ ◄───────── │  (guest)      │
//! └─────────────┘  Findings   └──────────────┘
//! ```
//!
//! The host reads files from disk and passes content to plugins as base64.
//! Plugins never have direct filesystem access — they only see what the
//! host provides in the `ScanCandidate` payloads.

mod plugin;
mod registry;

pub use plugin::DetectorPlugin;
pub use registry::{PluginRegistry, PluginSource};
