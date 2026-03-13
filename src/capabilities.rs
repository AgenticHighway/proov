use crate::models::ArtifactReport;

const CAPABILITY_MAP: &[(&str, &str)] = &[
    ("keyword:shell", "shell_execution"),
    ("keyword:browser", "browser_access"),
    ("keyword:api", "external_api_calls"),
    ("keyword:filesystem", "filesystem_access"),
    ("keyword:network", "network_access"),
    ("keyword:execute", "code_execution"),
    ("keyword:docker", "container_runtime"),
    ("keyword:system", "system_prompt"),
    ("keyword:permissions", "permission_scope"),
    ("keyword:dependencies", "dependency_execution"),
    ("keyword:tools", "tool_declarations"),
    ("keyword:secrets", "secret_references"),
];

pub fn derive_capabilities(artifact: &ArtifactReport) -> Vec<String> {
    let mut caps: Vec<String> = Vec::new();
    for signal in &artifact.signals {
        for &(key, capability) in CAPABILITY_MAP {
            if signal == key {
                caps.push(capability.to_string());
            }
        }
    }
    caps.sort();
    caps.dedup();
    caps
}
