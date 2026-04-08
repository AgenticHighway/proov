# C4 Level 2 — Container Diagram

Shows the major runtime containers and data stores within the **proov** system boundary.

```mermaid
flowchart TD
    subgraph ProovCLI["proov CLI Binary (Rust)"]
        CLI["CLI Layer\n(clap argument parsing,\nwizard, setup)"]
        ScanEngine["Scan Engine\n(discovery, detection,\nrisk scoring, verification)"]
        ContractBuilder["Contract Builder\n(transforms raw artifacts\ninto v2 contract payload)"]
        Submission["Submission Module\n(HTTP POST with retry,\naudit logging)"]
        Updater["Self-Updater\n(version check, download,\nSHA-256 verify, replace)"]
        RuleEngine["Rule Engine\n(loads and validates\ncustom TOML rules)"]
    end

    subgraph LocalStorage["Local Filesystem (~/.ahscan/)"]
        AuthConfig["config.json\n(API key + endpoint)"]
        ScannerUUID["scanner_uuid\n(persistent identity)"]
        RulesDir["rules/*.toml\n(custom detection rules)"]
        ContractCache["contract/\n(cached schema + version)"]
    end

    subgraph ExternalSystems["External Systems"]
        Vettd["Vettd Server\n(ingest API + dashboard)"]
        S3["S3 Release Bucket\n(update manifests + binaries)"]
    end

    FS["Target Filesystem\n(scanned files and directories)"]

    CLI -->|"dispatches scan mode"| ScanEngine
    CLI -->|"manages"| RuleEngine
    ScanEngine -->|"reads candidates"| FS
    ScanEngine -->|"loads rules"| RulesDir
    ScanEngine -->|"produces ScanReport"| ContractBuilder
    ContractBuilder -->|"produces ContractPayload"| Submission
    Submission -->|"reads credentials"| AuthConfig
    Submission -->|"POST /api/scans/ingest"| Vettd
    CLI -->|"triggers"| Updater
    Updater -->|"GET latest.json"| S3
    CLI -->|"persists credentials"| AuthConfig
    CLI -->|"reads/writes"| ScannerUUID
    ContractBuilder -->|"checks version"| ContractCache
```

## Container Responsibilities

| Container         | Technology           | Purpose                                                           |
| ----------------- | -------------------- | ----------------------------------------------------------------- |
| CLI Layer         | clap + crossterm     | Parse commands, interactive wizard, setup flow                    |
| Scan Engine       | walkdir + detectors  | Discover filesystem candidates, run detectors, score risk, verify |
| Contract Builder  | serde + custom logic | Transform `ScanReport` into versioned `ContractPayload`           |
| Submission Module | ureq (HTTP)          | Auth config I/O, HTTP dispatch with retry, audit logging          |
| Self-Updater      | ureq + flate2/tar    | Check S3 manifest, download, verify SHA-256, swap binary          |
| Rule Engine       | toml + validation    | Load, validate, install custom `.toml` detection rules            |
| Local Storage     | Filesystem           | Persist identity, auth, rules, and contract cache                 |
