//! Pure-logic verification module.
//!
//! Applies governance rules to an `ArtifactReport` and sets its
//! `verification_status` to one of `"pass"`, `"conditional_pass"`, or `"fail"`.

use crate::models::ArtifactReport;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the higher-severity status of `a` and `b`.
fn rank_max<'a>(a: &'a str, b: &'a str) -> &'a str {
    let rank = |s: &str| match s {
        "pass" => 0,
        "conditional_pass" => 1,
        "fail" => 2,
        _ => 0,
    };
    if rank(a) >= rank(b) { a } else { b }
}

/// True when the artifact declares tools, permissions, or API endpoints.
fn has_governance_constraints(artifact: &ArtifactReport) -> bool {
    let meta = &artifact.metadata;
    for key in &["declared_tools", "permissions", "api_endpoints"] {
        if let Some(v) = meta.get(*key) {
            if let Some(arr) = v.as_array() {
                if !arr.is_empty() {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply verification rules and return the resulting status string.
///
/// Rules (in priority order):
///   1. `credential_exposure_signal` → always **fail**.
///   2. Score bands: ≥50 → fail, ≥20 → conditional_pass, else pass.
///   3. `dangerous_keyword:*` escalates to fail unless governance
///      constraints are present (then conditional_pass).
///   4. `dangerous_combo:*` escalates to at least conditional_pass.
pub fn verify(artifact: &mut ArtifactReport) -> String {
    // Rule 1: credential exposure is an automatic failure.
    if artifact.signals.contains(&"credential_exposure_signal".to_string()) {
        artifact.verification_status = "fail".to_string();
        return artifact.verification_status.clone();
    }

    // Rule 2: score-based bands.
    let score = artifact.risk_score;
    let mut status = if score >= 50 {
        "fail"
    } else if score >= 20 {
        "conditional_pass"
    } else {
        "pass"
    };

    // Rule 3-4: dangerous signal escalation.
    let has_dangerous_keyword = artifact.signals.iter().any(|s| s.starts_with("dangerous_keyword:"));
    let has_dangerous_combo = artifact.signals.iter().any(|s| s.starts_with("dangerous_combo:"));

    if has_dangerous_keyword && status != "fail" {
        status = if has_governance_constraints(artifact) {
            rank_max(status, "conditional_pass")
        } else {
            "fail"
        };
    } else if has_dangerous_combo && status != "fail" {
        status = rank_max(status, "conditional_pass");
    }

    artifact.verification_status = status.to_string();
    artifact.verification_status.clone()
}
