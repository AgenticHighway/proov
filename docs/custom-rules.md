# Writing Custom Detection Rules

This guide explains how to extend proov with custom detection rules. Rules are declarative TOML files — no code, no build pipeline required.

## Why write a custom rule?

Custom rules let you detect artifacts specific to your environment:

- **Proprietary config formats** — internal AI tools with custom config files
- **Organization-specific patterns** — custom naming conventions or risk keywords
- **Emerging tools** — new AI frameworks the built-in detectors don't cover yet
- **Compliance checks** — flag specific patterns your security team cares about

## Quick start

1. **Create the rules directory:**

    ```bash
    mkdir -p ~/.ahscan/rules
    ```

2. **Drop in a `.toml` rule file:**

    ```bash
    cp examples/rules/terraform-ai.toml ~/.ahscan/rules/
    ```

3. **Run a scan** — custom rules are loaded automatically:

    ```bash
    proov quick
    ```

    You'll see `Loaded 1 custom rule(s) from ~/.ahscan/rules` in the output.

## Rule file format

Each `.toml` file defines one detection rule:

```toml
[detector]
name = "terraform_ai"
description = "Detect Terraform files provisioning AI services"
artifact_type = "terraform_config"

[match]
filenames = ["main.tf", "providers.tf"]
suffixes = [".tf"]
confidence = 0.6

[keywords]
keywords = ["openai", "anthropic", "langchain", "bedrock"]
signals_prefix = "keyword"
boost_confidence = 0.85
boost_threshold = 1

[deep_keywords]
keywords = ["api_key", "secret", "token"]
signals_prefix = "deep_keyword"
boost_confidence = 0.9
boost_threshold = 1
```

### Sections

#### `[detector]` (required)

| Field           | Type   | Description                            |
| --------------- | ------ | -------------------------------------- |
| `name`          | string | Unique rule name (used in metadata)    |
| `description`   | string | Human-readable description             |
| `artifact_type` | string | The artifact type reported in findings |

#### `[match]` (required)

| Field        | Type     | Description                                               |
| ------------ | -------- | --------------------------------------------------------- |
| `filenames`  | string[] | Exact filenames or glob patterns to match (e.g. `"*.tf"`) |
| `suffixes`   | string[] | File suffixes to match (e.g. `".tf"`)                     |
| `confidence` | float    | Base confidence score (0.0–1.0) when a file matches       |

At least one of `filenames` or `suffixes` must be non-empty.

Filename matching is **case-insensitive**. Glob patterns (using `*`) are supported in the `filenames` list.

#### `[keywords]` (optional)

| Field              | Type     | Description                                        |
| ------------------ | -------- | -------------------------------------------------- |
| `keywords`         | string[] | Keywords to search for in file content             |
| `signals_prefix`   | string   | Signal prefix (default: `"keyword"`)               |
| `boost_confidence` | float    | Confidence to boost to when threshold is met       |
| `boost_threshold`  | int      | Minimum keyword hits to trigger boost (default: 1) |

#### `[deep_keywords]` (optional)

Same format as `[keywords]`, but only applied in deep scan mode (`proov repo`, `proov full`).

## How it works

When the scanner runs:

1. Rule files are loaded from `~/.ahscan/rules/` at startup
2. Each candidate file is checked against all rules
3. If a filename matches, the rule fires with the base confidence
4. If content reading is allowed for that file type, keywords are scanned
5. Keyword matches boost confidence and add signals
6. The resulting artifact gets scored and verified like any built-in finding

Rules produce the same `ArtifactReport` structures as built-in detectors. Risk scoring, verification, and output formatting all apply normally.

## Content reading

The scanner only reads content from files on the [content-read allowlist](detectors.md). If your rule targets a file type not on the allowlist, it will still match by filename — but keyword scanning won't run. This is a deliberate privacy guardrail.

To check if a file type is on the allowlist, look at `CONTENT_READ_ALLOWLIST` and `CONTENT_READ_GLOB_PATTERNS` in `models.rs`.

## Signal naming

Rules generate signals in the format `{prefix}:{keyword}`:

- `keyword:openai` — from the `[keywords]` section
- `deep_keyword:api_key` — from the `[deep_keywords]` section
- `filename_match:main.tf` — auto-generated on match

These signals feed into the risk engine and verifier. Use the same signal patterns as built-in detectors when possible (see [detectors.md](detectors.md) for conventions).

## Tips

- **Start simple.** Match filenames first, add keywords after testing.
- **Use glob patterns** for broad matching (`"*.ai.yaml"`) and exact names for precision.
- **Set confidence conservatively.** Let keyword boosts raise it.
- **Check the examples** in `examples/rules/` for working patterns.
- **Test with `proov file <path>`** to verify a rule fires on a specific file.

## Examples

See the `examples/rules/` directory:

- `terraform-ai.toml` — Detect Terraform files with AI provider references
- `internal-tool.toml` — Template for internal/proprietary tool configs
