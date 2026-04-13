use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

// Pattern definitions in this module are adapted from Cisco DefenseClaw's
// plugin scanner JSON config rules (Apache-2.0). See THIRD_PARTY_NOTICES for
// the exact upstream files and pattern families incorporated here.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PatternDefinition {
    pub(crate) id: &'static str,
    pub(crate) signal: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) expression: &'static str,
}

#[derive(Debug)]
pub(crate) struct CompiledSourcePattern {
    pub(crate) id: &'static str,
    pub(crate) signal: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) regex: Regex,
}

pub(crate) const MAX_JSON_CONFIG_BYTES: usize = 256 * 1024;

const JSON_SKIP_BASENAMES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "openclaw.plugin.json",
];

const JSON_SECRET_PATTERN_DEFS: &[PatternDefinition] = &[
    PatternDefinition {
        id: "dc_json_connection_string",
        signal: "json_config:credential_connection_string",
        summary: "JSON config embeds credentials in a connection string",
        expression: r"(?:mongodb|postgres|mysql|redis)://[^:]+:[^@]+@",
    },
    PatternDefinition {
        id: "dc_json_generic_credential_value",
        signal: "json_config:credential_value",
        summary: "JSON config contains a likely credential key/value pair",
        expression: r#"["'](?:password|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']\s*:\s*["'][^"']{8,}["']"#,
    },
];

const JSON_URL_PATTERN_DEFS: &[PatternDefinition] = &[
    PatternDefinition {
        id: "dc_json_metadata_or_localhost_url",
        signal: "json_config:metadata_url",
        summary: "JSON config references a metadata or localhost URL",
        expression: r#"["']https?://(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|localhost|127\.0\.0\.1)"#,
    },
    PatternDefinition {
        id: "dc_json_internal_url",
        signal: "json_config:internal_url",
        summary: "JSON config references an internal-only URL",
        expression: r#"["']https?://[^"']*(?:internal|corp|local|intranet|private)(?:[./:"']|$)"#,
    },
    PatternDefinition {
        id: "dc_json_c2_url",
        signal: "json_config:c2_url",
        summary: "JSON config references a known collector or C2 URL",
        expression: r#"["']https?://[^"']*(?:webhook\.site|ngrok\.io|pipedream\.net|requestbin\.com|interact\.sh|oast\.fun|burpcollaborator\.net)"#,
    },
];

static JSON_SECRET_PATTERNS: LazyLock<Vec<CompiledSourcePattern>> =
    LazyLock::new(|| compile_patterns(JSON_SECRET_PATTERN_DEFS));

static JSON_URL_PATTERNS: LazyLock<Vec<CompiledSourcePattern>> =
    LazyLock::new(|| compile_patterns(JSON_URL_PATTERN_DEFS));

pub(crate) fn json_secret_patterns() -> &'static [CompiledSourcePattern] {
    &JSON_SECRET_PATTERNS
}

pub(crate) fn json_url_patterns() -> &'static [CompiledSourcePattern] {
    &JSON_URL_PATTERNS
}

pub(crate) fn should_skip_json_config(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            JSON_SKIP_BASENAMES
                .iter()
                .any(|candidate| name.eq_ignore_ascii_case(candidate))
        })
        .unwrap_or(false)
}

fn compile_patterns(definitions: &[PatternDefinition]) -> Vec<CompiledSourcePattern> {
    definitions
        .iter()
        .map(|definition| CompiledSourcePattern {
            id: definition.id,
            signal: definition.signal,
            summary: definition.summary,
            regex: Regex::new(definition.expression)
                .unwrap_or_else(|err| panic!("invalid source pattern {}: {err}", definition.id)),
        })
        .collect()
}
