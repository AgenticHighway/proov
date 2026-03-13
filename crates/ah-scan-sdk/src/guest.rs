//! Guest-side helpers for WASM detector plugins.
//!
//! Provides the `handle_detect` function that WASM detector authors call
//! from their `#[no_mangle] pub extern "C" fn detect()` export.
//!
//! This module uses Extism PDK conventions:
//! - Input is read from Extism host memory as a JSON-encoded `DetectRequest`.
//! - Output is written back as a JSON-encoded `DetectResponse`.

use crate::{DetectRequest, DetectResponse};

/// Decode a `DetectRequest` from raw JSON bytes.
///
/// Plugin authors can use this when manually reading Extism input.
pub fn decode_request(input: &[u8]) -> Result<DetectRequest, String> {
    serde_json::from_slice(input).map_err(|e| format!("Failed to decode DetectRequest: {e}"))
}

/// Encode a `DetectResponse` to JSON bytes for returning to the host.
pub fn encode_response(response: &DetectResponse) -> Result<Vec<u8>, String> {
    serde_json::to_vec(response).map_err(|e| format!("Failed to encode DetectResponse: {e}"))
}

/// Decode base64 content from a `ScanCandidate.content_b64` field.
///
/// Returns `None` if the input is `None` or decoding fails.
pub fn decode_content(content_b64: Option<&str>) -> Option<String> {
    let encoded = content_b64?;
    let bytes = base64_decode(encoded)?;
    String::from_utf8(bytes).ok()
}

/// Minimal base64 decoder (standard alphabet, no padding required).
/// Avoids adding a dependency on a base64 crate for the guest SDK.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn val(c: u8) -> Option<u8> {
        TABLE.iter().position(|&b| b == c).map(|p| p as u8)
    }

    let input: Vec<u8> = input.bytes().filter(|&b| b != b'=' && b != b'\n' && b != b'\r').collect();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let chunks = input.chunks(4);

    for chunk in chunks {
        let mut buf: u32 = 0;
        let len = chunk.len();
        for (i, &b) in chunk.iter().enumerate() {
            buf |= (val(b)? as u32) << (6 * (3 - i));
        }
        out.push((buf >> 16) as u8);
        if len > 2 {
            out.push((buf >> 8) as u8);
        }
        if len > 3 {
            out.push(buf as u8);
        }
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finding, ScanCandidate};

    #[test]
    fn round_trip_request() {
        let req = DetectRequest {
            deep: true,
            mode: "workdir".to_string(),
            candidates: vec![ScanCandidate {
                path: "src/.cursorrules".to_string(),
                origin: "workdir".to_string(),
                file_name: ".cursorrules".to_string(),
                content_b64: Some("SGVsbG8gd29ybGQ=".to_string()),
                file_size: 11,
            }],
        };

        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded = decode_request(&bytes).unwrap();
        assert_eq!(decoded.candidates.len(), 1);
        assert_eq!(decoded.candidates[0].file_name, ".cursorrules");
    }

    #[test]
    fn round_trip_response() {
        let resp = DetectResponse {
            findings: vec![Finding::new("cursor_rules", 0.9, "src/.cursorrules")],
        };

        let bytes = encode_response(&resp).unwrap();
        let decoded: DetectResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.findings.len(), 1);
        assert_eq!(decoded.findings[0].artifact_type, "cursor_rules");
    }

    #[test]
    fn decode_base64_content() {
        let text = decode_content(Some("SGVsbG8gd29ybGQ="));
        assert_eq!(text.unwrap(), "Hello world");
    }

    #[test]
    fn decode_none_content() {
        assert!(decode_content(None).is_none());
    }
}
