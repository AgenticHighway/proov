# C4 Level 4 — Code Diagrams

Zooms into key data flows and type relationships at the code level.

## Scan Pipeline Sequence

The core scan execution from CLI invocation through to output.

```mermaid
sequenceDiagram
    participant User
    participant CLI as cli::run()
    participant Scan as scan::run_scan()
    participant Disc as discovery
    participant Det as detectors
    participant Risk as risk_engine
    participant Ver as verifier
    participant Con as contract::build_contract_payload()
    participant Out as output::emit()

    User->>CLI: proov scan --json
    CLI->>Scan: run_scan("home", None, None, false)
    Scan->>Disc: discover_home_surfaces()
    Disc-->>Scan: Vec<Candidate>
    loop for each Detector
        Scan->>Det: detector.detect(candidates, deep)
        Det-->>Scan: Vec<ArtifactReport>
    end
    loop for each ArtifactReport
        Scan->>Risk: score_artifact(artifact)
        Risk-->>Scan: scored artifact
        Scan->>Ver: verify(artifact)
        Ver-->>Scan: verified artifact
    end
    Scan-->>CLI: ScanReport
    CLI->>Con: build_contract_payload(report, duration_ms)
    Con-->>CLI: ContractPayload
    CLI->>Out: emit(report, ...)
    Out-->>User: JSON / human output
```

## Submission Flow Sequence

The HTTP submission path when `--submit` is used.

```mermaid
sequenceDiagram
    participant CLI as cli::run()
    participant Out as output::do_submit()
    participant Auth as submit::load_auth_config()
    participant Sync as contract_sync::sync_contract()
    participant Con as contract::build_contract_payload()
    participant HTTP as submit::submit_contract_payload()
    participant Server as Vettd Server

    CLI->>Out: do_submit(report, duration, flags)
    Out->>Auth: load_auth_config()
    Auth-->>Out: AuthConfig (key + endpoint)
    Out->>Sync: sync_contract(endpoint)
    Sync->>Server: GET /api/contract?version=true
    Server-->>Sync: version response
    Sync-->>Out: ok / warn / exit
    Out->>Con: build_contract_payload(report, duration)
    Con-->>Out: ContractPayload
    Out->>HTTP: submit_contract_payload(payload, key, endpoint)
    loop up to 3 retries (5s / 30s / 120s)
        HTTP->>Server: POST /api/scans/ingest (Bearer token)
        Server-->>HTTP: 200 OK / 429 / 5xx
    end
    HTTP-->>Out: Result
```

## Self-Update Flow Sequence

Binary update check, download, and replacement.

```mermaid
sequenceDiagram
    participant User
    participant CLI as cli::run()
    participant Upd as updater
    participant S3 as S3 Release Bucket

    User->>CLI: proov update
    CLI->>Upd: check_for_update()
    Upd->>S3: GET /api/scanner/latest (latest.json)
    S3-->>Upd: UpdateManifest (version, artifacts, sha256)
    Upd->>Upd: compare semver (current vs latest)
    Upd-->>CLI: UpdateCheckResult (is_newer)
    alt is_newer = true
        CLI->>Upd: perform_update(manifest)
        Upd->>S3: GET artifact URL (tar.gz)
        S3-->>Upd: binary archive
        Upd->>Upd: SHA-256 verify
        Upd->>Upd: backup current binary
        Upd->>Upd: extract and replace
        Upd-->>CLI: success
    else is_newer = false
        CLI-->>User: already up to date
    end
```

## Core Data Types

```mermaid
flowchart LR
    subgraph models.rs["models.rs — Core Types"]
        AR["ArtifactReport\n─────────────\nartifact_type: String\nconfidence: f64\nsignals: Vec of String\nmetadata: Map\nrisk_score: i32\nrisk_reasons: Vec of String\nverification_status: String\nartifact_id: String\nartifact_hash: String\nregistry_eligible: bool\nartifact_scope: String"]
        SR["ScanReport\n─────────────\nscanner_version: String\ntimestamp: String\nscanned_path: String\nartifacts: Vec of ArtifactReport\ntotal_artifacts: usize\nscan_mode: String"]
    end

    subgraph contract_types["contract/types.rs — Contract Types"]
        CP["ContractPayload\n─────────────\nscan_meta: ScanMeta\nprompts: Vec of Prompt\nskills: Vec of Skill\nmcp_servers: Vec of McpServer\nagents: Vec of Agent\nagentic_apps: Vec of AgenticApp"]
        SM["ScanMeta\n─────────────\nscan_id: String\nendpoint_hostname: String\nscanned_at: String\nscanner_version: String\nscan_duration_ms: u64\nscan_roots: Vec of String\nhost_network: HostNetworkInfo"]
    end

    SR -->|"contains many"| AR
    SR -->|"transformed into"| CP
    CP -->|"contains"| SM
```

## Detector Trait and Implementations

```mermaid
flowchart TD
    Trait["trait Detector\n─────────────\nname() -> &str\ndetect(candidates, deep)\n  -> Vec of ArtifactReport"]

    CRD["CustomRulesDetector\n(loads TOML rules from\n~/.ahscan/rules/)"]
    CD["ContainerDetector\n(Dockerfile, docker-compose,\ncontainer_kind metadata)"]
    MCD["MCPConfigDetector\n(VS Code, Cursor, Claude\nMCP server configs)"]
    BFD["BrowserFootprintDetector\n(Chrome/Edge/Firefox\nextension artifacts)"]

    Trait -.->|"implemented by"| CRD
    Trait -.->|"implemented by"| CD
    Trait -.->|"implemented by"| MCD
    Trait -.->|"implemented by"| BFD

    RE["rule_engine.rs\n(DetectionRule, MatchConfig,\nKeywordConfig)"]
    CRD -->|"loads rules via"| RE
```

## Discovery Modes

```mermaid
flowchart TD
    RunScan["run_scan(mode)"]

    RunScan -->|"mode = host"| Host["discover_host_surfaces()\nBounded AI config dirs\n(Cursor, VS Code, Claude, etc.)"]
    RunScan -->|"mode = home"| Home["discover_home_surfaces()\nRecursive ~ walk\n(MAX_DEPTH = 5)"]
    RunScan -->|"mode = root"| Root["discover_root_surfaces()\nEntire filesystem from /"]
    RunScan -->|"mode = workdir"| Workdir["discover_workdir_surfaces()\nExplicit project directory\n(deep mode optional)"]
    RunScan -->|"mode = file"| File["discover_file_surface()\nSingle file analysis"]
    RunScan -->|"mode = filesystem"| FS["discover_filesystem_surfaces()\nHome + system app paths"]

    Host -->|"Vec of Candidate"| Detectors["Detector Pipeline"]
    Home -->|"Vec of Candidate"| Detectors
    Root -->|"Vec of Candidate"| Detectors
    Workdir -->|"Vec of Candidate"| Detectors
    File -->|"Vec of Candidate"| Detectors
    FS -->|"Vec of Candidate"| Detectors
```
