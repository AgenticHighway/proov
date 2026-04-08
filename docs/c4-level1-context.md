# C4 Level 1 — System Context

Shows how the **proov** scanner relates to external actors and systems.

```mermaid
flowchart TD
    User["👤 Security Engineer / DevOps\n(runs scans on target machines)"]
    Proov["🔍 proov Scanner\n(Rust CLI — detects, analyzes,\nand reports AI execution artifacts)"]
    Vettd["🌐 Vettd Server\n(Next.js + PostgreSQL — ingests\nscans, renders verification dashboard)"]
    S3["☁️ S3 Release Bucket\n(hosts binary releases\nand update manifests)"]
    FS["💻 Target Machine Filesystem\n(AI config files, prompts,\nMCP configs, containers, rules)"]
    Contract["📄 Contract Endpoint\n(/api/contract — schema\nversion negotiation)"]

    User -->|"runs scan commands"| Proov
    Proov -->|"reads files & directories"| FS
    Proov -->|"POST /api/scans/ingest\n(Bearer token auth)"| Vettd
    Proov -->|"GET /api/contract\n(version check)"| Contract
    Contract -.->|"hosted by"| Vettd
    Proov -->|"GET latest.json\n(self-update check)"| S3
    User -->|"reviews scan results"| Vettd
```

## Key Relationships

| From  | To           | Protocol           | Purpose                                 |
| ----- | ------------ | ------------------ | --------------------------------------- |
| User  | proov        | CLI (stdin/stdout) | Run scans, manage rules, configure auth |
| proov | Filesystem   | OS read            | Discover and analyze AI artifacts       |
| proov | Vettd Server | HTTPS POST         | Submit scan contract payloads           |
| proov | Vettd Server | HTTPS GET          | Contract version negotiation            |
| proov | S3 Bucket    | HTTPS GET          | Check for binary updates                |
| User  | Vettd Server | Browser            | Review verification dashboard           |
