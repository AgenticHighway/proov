//! # ah-scan-sdk
//!
//! SDK types and detector interface for ah-scan WASM plugins.
//!
//! This crate defines the contract between the scanner host and detector
//! plugins compiled to WebAssembly. Plugin authors depend on this crate
//! to implement the [`detect`] function that the host calls.
//!
//! ## For plugin authors
//!
//! ```ignore
//! use ah_scan_sdk::{DetectRequest, DetectResponse, ScanCandidate, Finding};
//!
//! #[no_mangle]
//! pub extern "C" fn detect() -> i32 {
//!     ah_scan_sdk::guest::handle_detect(|req: DetectRequest| {
//!         let mut findings = Vec::new();
//!         for candidate in &req.candidates {
//!             // ... your detection logic ...
//!         }
//!         DetectResponse { findings }
//!     })
//! }
//! ```

mod types;

pub mod guest;

pub use types::{
    DetectRequest, DetectResponse, DetectorManifest, Finding, FindingMetadata, ScanCandidate,
};

/// Current SDK protocol version. The host checks this to ensure compatibility.
pub const SDK_VERSION: &str = "0.1.0";

/// The expected WASM export function name that the host calls.
pub const DETECT_FUNCTION: &str = "detect";
