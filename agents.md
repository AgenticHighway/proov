# agents.md

## Project relationship

This is the **client/scanner side** of a two-repo client/server system:

| Role                   | Repo                             | Description                                                                                                                     |
| ---------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **Client (this repo)** | `AgenticHighway/ah-scanner-poc`  | System-level scanner that runs on target machines, produces scan reports, and submits them to the server ingest API.            |
| **Server**             | `AgenticHighway/ah-verified-poc` | Next.js app + PostgreSQL (via Prisma). Exposes `POST /api/ingest`, stores scan results, and renders the verification dashboard. |

The scanner is the data producer. The server is the data consumer, store, and reviewer. They communicate over HTTP.

This repository is a minimal `uv`-managed Python project.

## Expectations for coding agents

- Use `uv run` for running Python commands and scripts.
- Keep changes small and focused.
- Prefer adding tests for non-trivial behavior changes.
- Preserve existing project structure unless restructuring is required.
- Update this file when introducing agent-specific workflows.

Below is a tight, AI-optimized AGENTS.md designed specifically for agentic coding environments (Cursor, Claude Code, OpenAI agents, etc.).

It focuses on things that AI coding systems consistently struggle with:
• unclear structure
• hidden side effects
• inconsistent patterns
• giant files
• ambiguous interfaces

This version enforces deterministic structure, which dramatically improves AI-generated code quality.

⸻

AGENTS.md

Agentic Highway Engineering Guidelines

This repository is designed to be worked on by humans and AI agents.

Code must be:
• predictable
• modular
• easy to reason about
• safe to modify automatically

The goal is fast iteration with minimal breakage.

⸻

Core Principles

Priorities in order: 1. Deterministic structure 2. Small composable modules 3. Explicit interfaces 4. Minimal hidden behavior 5. Safe automated refactoring

Readable, boring code is preferred over clever code.

⸻

Rules:
• core must be pure logic
• tools contain all external effects
• agents coordinate behavior
• workflows orchestrate systems

This separation allows AI agents to modify components safely.

Make sure that Verbs, Nouns, Actions, etc are properly grammatically named and consistent across the codebase.

⸻

File Size Rules

Large files degrade AI performance.

Limits:
• files: ≤ 400 lines
• functions: ≤ 50 lines
• classes: ≤ 200 lines

If a file grows too large:

split it.

⸻

Function Design

Functions must:
• do one thing
• have clear inputs
• have predictable outputs

Avoid hidden dependencies.

Bad:

def process_task():
user = get_current_user()
data = requests.get(API).json()

Good:

def process_task(user, external_data):

Pass dependencies explicitly.

⸻

Pure Logic vs Side Effects

All side effects must be isolated.

Side effects include:
• LLM calls
• HTTP requests
• database operations
• filesystem access
• environment variables

Pure logic should never directly call external services.

⸻

Typed Data Contracts

All shared data structures should use typed models.

Prefer:
• Pydantic models
• dataclasses
• typed dictionaries

Example:

class AgentTask(BaseModel):
id: str
prompt: str
tools_allowed: list[str]

Avoid passing raw dictionaries between modules.

Typed contracts reduce AI-generated bugs.

⸻

Error Handling

Errors must include context.

Rules:
• never swallow exceptions
• always add debugging context
• propagate meaningful errors upward

Bad:

except Exception:
pass

Good:

except Exception as e:
raise WorkflowExecutionError(
f"Step {step_id} failed"
) from e

Logs should contain enough information to reproduce failures.

⸻

Logging

Every agent execution should log:
• task ID
• tools invoked
• model calls
• latency
• errors

Example:

logger.info("agent_step_start", step_id=step_id)

Logs should be structured.

⸻

Tool Integration Pattern

External systems must be wrapped in tool adapters.

Example:

tools/
openai_client.py
slack_client.py
github_client.py

Agents must not call external APIs directly.

Adapters improve:
• testability
• mocking
• debugging
• observability

⸻

Testing Expectations

Focus tests on logic that could break.

Test:
• reasoning logic
• data transformations
• workflow orchestration

Avoid heavy testing of:
• thin wrappers
• temporary experiments

Minimum test types:

tests/
unit/
workflows/

⸻

Performance Guidelines

Prioritize major improvements:
• fewer LLM calls
• caching
• batching
• smaller prompts

Ignore premature micro-optimizations.

Measure before optimizing.

⸻

Security Rules

Always:
• validate inputs
• avoid unsafe deserialization
• never commit secrets
• use environment variables for credentials
• sanitize external data

Security issues must be treated as bugs.
.env files should never be committed, but `.env.example` with placeholder values is encouraged.
and `.env` should be in `.gitignore`.

⸻

Pull Request Guidelines

Changes should be easy to review.

Preferred:
• small PRs
• focused changes
• clear commit messages

Separate:
• refactors
• feature additions
• bug fixes

⸻

Refactoring Rules for AI Agents

AI-generated refactors must:
• maintain test coverage
• avoid large multi-file rewrites unless requested

Prefer incremental improvements.

⸻

Avoid Over-Engineering

Do not build:
• generic frameworks
• premature abstractions
• complex plugin systems

Duplicate small patterns until real reuse emerges.

⸻

Ownership Mindset

Write code assuming:

you will debug this system during production incidents.

Code should make failures easy to understand and fix.

⸻

Summary

The system should always be:
• readable
• modular
• observable
• easy to test
• safe to refactor

Fast iteration is the goal.

Not theoretical perfection.

⸻
