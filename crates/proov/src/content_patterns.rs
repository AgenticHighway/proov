use regex::Regex;
use std::sync::LazyLock;

// Secret patterns in this module are adapted from Cisco DefenseClaw
// (Apache-2.0). See THIRD_PARTY_NOTICES for attribution details.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PatternDefinition {
    pub(crate) id: &'static str,
    pub(crate) signal: &'static str,
    pub(crate) expression: &'static str,
}

#[derive(Debug)]
pub(crate) struct CompiledContentPattern {
    pub(crate) id: &'static str,
    pub(crate) signal: &'static str,
    regex: Regex,
}

impl CompiledContentPattern {
    fn is_match(&self, content: &str) -> bool {
        self.regex.is_match(content)
    }
}

const LEGACY_SECRET_PATTERN_DEFS: &[PatternDefinition] = &[
    PatternDefinition {
        id: "legacy_sk_prefix",
        signal: "credential_exposure_signal",
        expression: r"sk-",
    },
    PatternDefinition {
        id: "legacy_ghp_prefix",
        signal: "credential_exposure_signal",
        expression: r"ghp_",
    },
    PatternDefinition {
        id: "legacy_gho_prefix",
        signal: "credential_exposure_signal",
        expression: r"gho_",
    },
    PatternDefinition {
        id: "legacy_github_pat_prefix",
        signal: "credential_exposure_signal",
        expression: r"github_pat_",
    },
    PatternDefinition {
        id: "legacy_aws_access_key_prefix",
        signal: "credential_exposure_signal",
        expression: r"AKIA",
    },
    PatternDefinition {
        id: "legacy_jwt_prefix",
        signal: "credential_exposure_signal",
        expression: r"eyJ",
    },
];

const STRUCTURED_SECRET_PATTERN_DEFS: &[PatternDefinition] = &[
    PatternDefinition {
        id: "dc_aws_access_key",
        signal: "secret:aws:access_key",
        expression: r"\bAKIA[0-9A-Z]{16}\b",
    },
    PatternDefinition {
        id: "dc_aws_secret_access_key",
        signal: "secret:aws:secret_access_key",
        expression: r#"(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key['":\s=]+[A-Za-z0-9/+=]{40}"#,
    },
    PatternDefinition {
        id: "dc_aws_session_token",
        signal: "secret:aws:session_token",
        expression: r#"(?i)aws_session_token['":\s=]+[A-Za-z0-9/+=]{100,}"#,
    },
    PatternDefinition {
        id: "dc_gcp_api_key",
        signal: "secret:gcp:api_key",
        expression: r"\bAIza[0-9A-Za-z\-_]{35}\b",
    },
    PatternDefinition {
        id: "dc_gcp_client_secret",
        signal: "secret:gcp:client_secret",
        expression: r#"(?i)client_secret['":\s=]+[A-Za-z0-9\-_]{24,}"#,
    },
    PatternDefinition {
        id: "dc_azure_account_key",
        signal: "secret:azure:account_key",
        expression: r"(?i)AccountKey\s*=\s*[A-Za-z0-9+/=]{44,}",
    },
    PatternDefinition {
        id: "dc_azure_connection_string",
        signal: "secret:azure:connection_string",
        expression: r"(?i)(?:Server|Data Source)\s*=\s*[^;]+;\s*(?:User ID|Password)\s*=\s*[^;]+",
    },
    PatternDefinition {
        id: "dc_azure_secret_value",
        signal: "secret:azure:secret_value",
        expression: r#"(?i)azure[\w_]*(?:secret|key|password)['":\s=]+[A-Za-z0-9\-_.~]{30,}"#,
    },
    PatternDefinition {
        id: "dc_azure_sas_token",
        signal: "secret:azure:sas_token",
        expression: r"(?i)\bsig=[A-Za-z0-9%+/=]{30,}(?:&|$)",
    },
    PatternDefinition {
        id: "dc_github_pat",
        signal: "secret:github:pat",
        expression: r"\bghp_[A-Za-z0-9]{36}\b",
    },
    PatternDefinition {
        id: "dc_github_oauth_token",
        signal: "secret:github:oauth_token",
        expression: r"\bgho_[A-Za-z0-9]{36}\b",
    },
    PatternDefinition {
        id: "dc_github_fine_grained_pat",
        signal: "secret:github:fine_grained_pat",
        expression: r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b",
    },
    PatternDefinition {
        id: "dc_github_app_token",
        signal: "secret:github:app_token",
        expression: r"\bghs_[A-Za-z0-9]{36}\b",
    },
    PatternDefinition {
        id: "dc_github_refresh_token",
        signal: "secret:github:refresh_token",
        expression: r"\bghr_[A-Za-z0-9]{36}\b",
    },
    PatternDefinition {
        id: "dc_gitlab_pat",
        signal: "secret:gitlab:pat",
        expression: r"\bglpat-[A-Za-z0-9\-_]{20,}\b",
    },
    PatternDefinition {
        id: "dc_gitlab_project_token",
        signal: "secret:gitlab:project_token",
        expression: r"\bglptt-[A-Za-z0-9\-_]{20,}\b",
    },
    PatternDefinition {
        id: "dc_gitlab_oauth_token",
        signal: "secret:gitlab:oauth_token",
        expression: r"\bglsoat-[A-Za-z0-9\-_]{20,}\b",
    },
    PatternDefinition {
        id: "dc_slack_bot_token",
        signal: "secret:slack:bot_token",
        expression: r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}\b",
    },
    PatternDefinition {
        id: "dc_slack_user_token",
        signal: "secret:slack:user_token",
        expression: r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}\b",
    },
    PatternDefinition {
        id: "dc_slack_webhook",
        signal: "secret:slack:webhook",
        expression: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    },
    PatternDefinition {
        id: "dc_stripe_live_secret_key",
        signal: "secret:stripe:live_secret_key",
        expression: r"\bsk_live_[A-Za-z0-9]{24,}\b",
    },
    PatternDefinition {
        id: "dc_stripe_test_secret_key",
        signal: "secret:stripe:test_secret_key",
        expression: r"\bsk_test_[A-Za-z0-9]{24,}\b",
    },
    PatternDefinition {
        id: "dc_stripe_restricted_key",
        signal: "secret:stripe:restricted_key",
        expression: r"\brk_live_[A-Za-z0-9]{24,}\b",
    },
    PatternDefinition {
        id: "dc_twilio_auth_token",
        signal: "secret:twilio:auth_token",
        expression: r#"(?i)twilio[\w_]*(?:auth|token)['":\s=]+[0-9a-f]{32}"#,
    },
    PatternDefinition {
        id: "dc_twilio_api_key",
        signal: "secret:twilio:api_key",
        expression: r"\bSK[0-9a-fA-F]{32}\b",
    },
    PatternDefinition {
        id: "dc_sendgrid_api_key",
        signal: "secret:sendgrid:api_key",
        expression: r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b",
    },
    PatternDefinition {
        id: "dc_mailgun_api_key",
        signal: "secret:mailgun:api_key",
        expression: r"\bkey-[A-Za-z0-9]{32}\b",
    },
    PatternDefinition {
        id: "dc_npm_token",
        signal: "secret:npm:token",
        expression: r"\bnpm_[A-Za-z0-9]{36}\b",
    },
    PatternDefinition {
        id: "dc_pypi_token",
        signal: "secret:pypi:token",
        expression: r"\bpypi-[A-Za-z0-9\-_]{50,}\b",
    },
    PatternDefinition {
        id: "dc_rsa_private_key",
        signal: "secret:crypto:rsa_private_key",
        expression: r"-----BEGIN RSA PRIVATE KEY-----",
    },
    PatternDefinition {
        id: "dc_ec_private_key",
        signal: "secret:crypto:ec_private_key",
        expression: r"-----BEGIN EC PRIVATE KEY-----",
    },
    PatternDefinition {
        id: "dc_dsa_private_key",
        signal: "secret:crypto:dsa_private_key",
        expression: r"-----BEGIN DSA PRIVATE KEY-----",
    },
    PatternDefinition {
        id: "dc_private_key",
        signal: "secret:crypto:private_key",
        expression: r"-----BEGIN PRIVATE KEY-----",
    },
    PatternDefinition {
        id: "dc_openssh_private_key",
        signal: "secret:crypto:openssh_private_key",
        expression: r"-----BEGIN OPENSSH PRIVATE KEY-----",
    },
    PatternDefinition {
        id: "dc_jwt",
        signal: "secret:auth:jwt",
        expression: r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+\b",
    },
    PatternDefinition {
        id: "dc_basic_auth_header",
        signal: "secret:auth:basic_header",
        expression: r"(?i)(?:authorization|auth)\s*[:=]\s*basic\s+[A-Za-z0-9+/=]{10,}",
    },
    PatternDefinition {
        id: "dc_bearer_auth_header",
        signal: "secret:auth:bearer_header",
        expression: r"(?i)(?:authorization|auth)\s*[:=]\s*bearer\s+[A-Za-z0-9\-_.+/=]{20,}",
    },
];

const DANGEROUS_PATTERN_DEFS: &[PatternDefinition] = &[
    PatternDefinition {
        id: "dangerous_exfiltrate",
        signal: "dangerous_keyword:exfiltrate",
        expression: r"(?i)exfiltrate",
    },
    PatternDefinition {
        id: "dangerous_wipe",
        signal: "dangerous_keyword:wipe",
        expression: r"(?i)wipe",
    },
    PatternDefinition {
        id: "dangerous_rm_rf",
        signal: "dangerous_keyword:rm",
        expression: r"(?i)rm\s+-rf",
    },
    PatternDefinition {
        id: "dangerous_steal",
        signal: "dangerous_keyword:steal",
        expression: r"(?i)steal",
    },
    PatternDefinition {
        id: "dangerous_upload_credentials",
        signal: "dangerous_keyword:upload",
        expression: r"(?i)upload\s+credentials",
    },
    PatternDefinition {
        id: "dangerous_reverse_shell",
        signal: "dangerous_keyword:reverse",
        expression: r"(?i)reverse\s+shell",
    },
    PatternDefinition {
        id: "dangerous_disable_security",
        signal: "dangerous_keyword:disable",
        expression: r"(?i)disable\s+security",
    },
    PatternDefinition {
        id: "dangerous_bypass_auth",
        signal: "dangerous_keyword:bypass",
        expression: r"(?i)bypass\s+auth",
    },
];

const SHELL_PATTERN_DEFS: &[PatternDefinition] = &[
    PatternDefinition {
        id: "combo_shell",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)shell",
    },
    PatternDefinition {
        id: "combo_bash",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)bash",
    },
    PatternDefinition {
        id: "combo_exec",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)exec",
    },
    PatternDefinition {
        id: "combo_subprocess",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)subprocess",
    },
];

const NETWORK_PATTERN_DEFS: &[PatternDefinition] = &[
    PatternDefinition {
        id: "combo_http",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)http",
    },
    PatternDefinition {
        id: "combo_fetch",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)fetch",
    },
    PatternDefinition {
        id: "combo_curl",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)curl",
    },
    PatternDefinition {
        id: "combo_requests",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)requests",
    },
    PatternDefinition {
        id: "combo_network",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)network",
    },
    PatternDefinition {
        id: "combo_api",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)api",
    },
];

const FS_PATTERN_DEFS: &[PatternDefinition] = &[
    PatternDefinition {
        id: "combo_filesystem",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)filesystem",
    },
    PatternDefinition {
        id: "combo_write_file",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)write_file",
    },
    PatternDefinition {
        id: "combo_read_file",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)read_file",
    },
    PatternDefinition {
        id: "combo_os_remove",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)os\.remove",
    },
    PatternDefinition {
        id: "combo_shutil",
        signal: "dangerous_combo:shell+network+fs",
        expression: r"(?i)shutil",
    },
];

static LEGACY_SECRET_PATTERNS: LazyLock<Vec<CompiledContentPattern>> = LazyLock::new(|| {
    compile_pattern_set(LEGACY_SECRET_PATTERN_DEFS).expect("valid legacy secret patterns")
});

static STRUCTURED_SECRET_PATTERNS: LazyLock<Vec<CompiledContentPattern>> = LazyLock::new(|| {
    compile_pattern_set(STRUCTURED_SECRET_PATTERN_DEFS).expect("valid structured secret patterns")
});

static DANGEROUS_PATTERNS: LazyLock<Vec<CompiledContentPattern>> = LazyLock::new(|| {
    compile_pattern_set(DANGEROUS_PATTERN_DEFS).expect("valid dangerous patterns")
});

static SHELL_PATTERNS: LazyLock<Vec<CompiledContentPattern>> =
    LazyLock::new(|| compile_pattern_set(SHELL_PATTERN_DEFS).expect("valid shell patterns"));

static NETWORK_PATTERNS: LazyLock<Vec<CompiledContentPattern>> =
    LazyLock::new(|| compile_pattern_set(NETWORK_PATTERN_DEFS).expect("valid network patterns"));

static FS_PATTERNS: LazyLock<Vec<CompiledContentPattern>> =
    LazyLock::new(|| compile_pattern_set(FS_PATTERN_DEFS).expect("valid filesystem patterns"));

pub(crate) fn compile_pattern_set(
    defs: &[PatternDefinition],
) -> Result<Vec<CompiledContentPattern>, regex::Error> {
    defs.iter()
        .map(|def| {
            Ok(CompiledContentPattern {
                id: def.id,
                signal: def.signal,
                regex: Regex::new(def.expression)?,
            })
        })
        .collect()
}

pub(crate) fn scan_secret_signals(content: &str) -> Vec<String> {
    let mut signals = scan_pattern_signals(content, &STRUCTURED_SECRET_PATTERNS);

    if any_pattern_matches(content, &LEGACY_SECRET_PATTERNS) || !signals.is_empty() {
        insert_unique_signal(&mut signals, "credential_exposure_signal");
    }

    signals
}

pub(crate) fn scan_dangerous_signals(content: &str) -> Vec<String> {
    let mut signals = scan_pattern_signals(content, &DANGEROUS_PATTERNS);

    if any_pattern_matches(content, &SHELL_PATTERNS)
        && any_pattern_matches(content, &NETWORK_PATTERNS)
        && any_pattern_matches(content, &FS_PATTERNS)
    {
        push_unique_signal(&mut signals, "dangerous_combo:shell+network+fs");
    }

    signals
}

fn scan_pattern_signals(content: &str, patterns: &[CompiledContentPattern]) -> Vec<String> {
    let mut signals = Vec::new();
    for pattern in patterns {
        if pattern.is_match(content) {
            debug_assert!(!pattern.id.is_empty());
            push_unique_signal(&mut signals, pattern.signal);
        }
    }
    signals
}

fn any_pattern_matches(content: &str, patterns: &[CompiledContentPattern]) -> bool {
    patterns.iter().any(|pattern| pattern.is_match(content))
}

fn push_unique_signal(signals: &mut Vec<String>, signal: &str) {
    if !signals.iter().any(|existing| existing == signal) {
        signals.push(signal.to_string());
    }
}

fn insert_unique_signal(signals: &mut Vec<String>, signal: &str) {
    if !signals.iter().any(|existing| existing == signal) {
        signals.insert(0, signal.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_pattern_set_rejects_invalid_regex() {
        let defs = [PatternDefinition {
            id: "broken",
            signal: "broken",
            expression: r"(",
        }];

        assert!(compile_pattern_set(&defs).is_err());
    }

    #[test]
    fn scan_secret_signals_matches_legacy_patterns() {
        assert_eq!(
            scan_secret_signals("token sk-abc123"),
            vec!["credential_exposure_signal"]
        );
        assert_eq!(
            scan_secret_signals("ghp_xxxx"),
            vec!["credential_exposure_signal"]
        );
    }

    #[test]
    fn scan_secret_signals_adds_structured_aws_detection() {
        let access_key = ["AKIA", "1234567890ABCDEF"].concat();
        let signals = scan_secret_signals(&access_key);
        assert_eq!(signals[0], "credential_exposure_signal");
        assert!(signals
            .iter()
            .any(|signal| signal == "secret:aws:access_key"));
    }

    #[test]
    fn scan_secret_signals_adds_structured_slack_detection() {
        let slack_token = [
            "xox",
            "b-1234567890-1234567890-abcdefghijklmnopqrstuvwx",
        ]
        .concat();
        let signals = scan_secret_signals(&slack_token);
        assert!(signals
            .iter()
            .any(|signal| signal == "secret:slack:bot_token"));
    }

    #[test]
    fn scan_secret_signals_adds_structured_private_key_detection() {
        let signals = scan_secret_signals("-----BEGIN RSA PRIVATE KEY-----");
        assert!(signals
            .iter()
            .any(|signal| signal == "secret:crypto:rsa_private_key"));
    }

    #[test]
    fn scan_pattern_signals_deduplicates_shared_signal_output() {
        let defs = [
            PatternDefinition {
                id: "one",
                signal: "same_signal",
                expression: r"abc",
            },
            PatternDefinition {
                id: "two",
                signal: "same_signal",
                expression: r"def",
            },
        ];

        let compiled = compile_pattern_set(&defs).unwrap();
        assert_eq!(
            scan_pattern_signals("abcdef", &compiled),
            vec!["same_signal"]
        );
    }

    #[test]
    fn scan_dangerous_signals_adds_combo_signal() {
        let signals = scan_dangerous_signals("use shell to fetch http and write_file");
        assert!(signals
            .iter()
            .any(|signal| signal == "dangerous_combo:shell+network+fs"));
    }
}
