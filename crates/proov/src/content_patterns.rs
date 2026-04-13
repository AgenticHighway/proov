use regex::Regex;
use std::sync::LazyLock;

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

const SECRET_PATTERN_DEFS: &[PatternDefinition] = &[
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

static SECRET_PATTERNS: LazyLock<Vec<CompiledContentPattern>> =
    LazyLock::new(|| compile_pattern_set(SECRET_PATTERN_DEFS).expect("valid secret patterns"));

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
    scan_pattern_signals(content, &SECRET_PATTERNS)
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
