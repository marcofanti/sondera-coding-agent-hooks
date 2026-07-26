# Agent Instructions

## Global Codex Instructions

### Gemini API - SDK and Model Notes

#### Use `google-genai`, not `google-generativeai`

The `google-generativeai` package is deprecated and end-of-life. Always use the new SDK:

```bash
pip install google-genai
```

```python
from google import genai
from google.genai import types

client = genai.Client(api_key=api_key)
```

#### Generation

```python
response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents=prompt,
    config=types.GenerateContentConfig(response_mime_type="application/json"),
)
text = response.text
```

#### Embeddings

```python
response = client.models.embed_content(
    model="gemini-embedding-001",
    contents=["text1", "text2"],  # batch up to 100
    config=types.EmbedContentConfig(task_type="RETRIEVAL_DOCUMENT"),  # or RETRIEVAL_QUERY
)
vectors = [emb.values for emb in response.embeddings]  # list[list[float]], dim=3072
```

#### Confirmed working models as of 2026-05-04

| Model | Use | Notes |
| --- | --- | --- |
| `gemini-2.5-flash` | Generation | Fast, cheap, good JSON output |
| `gemini-embedding-001` | Embeddings | 3072-dim vectors, batch up to 100 |

#### Confirmed broken or unavailable models

| Model | Error |
| --- | --- |
| `gemini-1.5-flash` | Deprecated, returns 404 for new users |
| `gemini-2.0-flash` | No longer available to new users |
| `text-embedding-004` | Only on v1 API; not available via `google-generativeai` v1beta |
| `models/embedding-001` | Not found on v1beta API |
| `models/text-embedding-004` | Not found on v1beta API |

`google-generativeai` uses the v1beta API endpoint. Several newer models are only available on v1, which is why they 404. The new `google-genai` SDK uses v1 and has access to all current models.

## Repository Overview

This repository is a Rust workspace for Sondera coding-agent hooks: a reference monitor for Claude Code, Cursor, GitHub Copilot, and Gemini CLI. Hook adapter binaries normalize agent-specific JSON events and forward them to a central harness server that evaluates Cedar policies and returns allow, deny, or escalate decisions.

The top-level Rust workspace includes:

- `crates/harness`: core policy harness and `sondera-harness-server`
- `crates/guardrails/signature`: YARA-X signature scanning
- `crates/guardrails/ifc`: optional Ollama-based information-flow classification
- `crates/guardrails/policy`: optional Ollama-based secure-code policy classification
- `crates/common`: shared hook-binary helpers
- `crates/mcp`: MCP/Cedar policy tooling
- `apps/claude`, `apps/cursor`, `apps/copilot`, `apps/gemini`: agent hook binaries
- `sondera-python`: Python SDK and tests, outside the Rust workspace

## Core Commands

Run these from the repository root unless noted otherwise.

```bash
# Build all Rust crates
cargo build --workspace

# Test all Rust crates
cargo test --workspace

# Run one Rust integration test
cargo test -p sondera-harness --test cedarling_shell_gate allows_clean_git_status

# Format and lint Rust
cargo fmt --all -- --check
cargo clippy --all-features -- -D warnings

# Start the harness server with the default Cedar policy engine
cargo run --bin sondera-harness-server -- -v

# Start with the allow-all engine for hook testing without policy enforcement
cargo run --bin sondera-harness-server -- --policy-engine allow-all -v

# Start with Cedarling
cargo run --bin sondera-harness-server -- --policy-engine cedarling -v
```

Python SDK commands:

```bash
cd sondera-python
python -m pytest
```

Example RAG agent commands:

```bash
cd examples/rag_test_agent
python -m pytest
```

## Hook Installation Commands

Claude is the reference adapter. Other adapter binaries follow the same install/uninstall pattern.

```bash
# Local Claude Code hooks; writes .claude/settings.local.json
cargo run -p sondera-claude -- install

# Project Claude Code hooks; writes .claude/settings.json
cargo run -p sondera-claude -- install --project

# User Claude Code hooks
cargo run -p sondera-claude -- install --user

# Uninstall from the same scope
cargo run -p sondera-claude -- uninstall --user
```

## Architecture Notes

The request path is:

```text
Agent hook JSON
  -> apps/{claude,cursor,copilot,gemini}
  -> tarpc RPC over Unix socket
  -> PolicyHarness<CedarlingPolicyEngine or CedarPolicyEngine>
  -> guardrails, Cedar request transform, authorization
  -> Allow, Deny, or Escalate response
```

Current production policy work should target the `CedarlingPolicyEngine` and the `Jans::` entity namespace. The legacy `CedarPolicyEngine` with flat entity names remains for compatibility.

Keep trajectory state in `context.trajectory.{label, step_count, taints}`. Do not move trajectory label or taint state onto resource entities.

Hook `event.raw` fields take precedence over guardrail-computed fields. Guardrails fill missing context only.

## Policies

Policies live in `policies/`. Cedar `forbid` overrides `permit`.

- `schema.json`: Cedar JSON schema for the `Jans::` model
- `base.cedar`: default permit and common forbids
- `destructive.cedar`: irreversible shell and infrastructure operations
- `file.cedar`: file, secret, Bell-LaPadula, OWASP/CWE policy checks
- `ifc.cedar`: trajectory label and taint gates
- `supply_chain_risk.cedar`: dependency and build-script risk checks
- `communication.cedar`: email and calendar actions
- `browser.cedar`: browser navigation, forms, screenshots, and script evaluation
- `ifc.toml`, `policies.toml`: optional LLM classifier prompts

Use `@id("policy-name")` annotations for structured deny messages. `@taint("name")` propagates taints onto the trajectory. `@decision("escalate")` converts a soft deny into an escalation unless another matched forbid is a hard deny.

## Development Guidance

- Prefer the existing Cedarling/Jans path for new policy-engine behavior.
- Treat `apps/claude` as the reference adapter when updating Cursor, Copilot, or Gemini support.
- Keep adapter JSON normalization logic small and push shared semantics into `crates/harness` or `crates/common` when reasonable.
- Add focused integration tests in `crates/harness/tests/` for policy-engine and transform behavior.
- Avoid relying on Ollama in ordinary unit tests unless the test is explicitly marked or scoped as an integration check for LLM behavior.
- Do not commit local hook settings, local sockets, or generated runtime stores.
- Be careful around destructive-operation tests. Prefer allow/deny assertions against policy evaluation over running real destructive commands.

## Dirty Worktree Policy

This repository may contain user or generated changes. Before editing, check `git status --short`. Do not revert unrelated modifications. If a task requires touching a file that already has unrelated changes, inspect it and preserve the existing work.

## Reference Docs

- `CLAUDE.md`: existing command and architecture notes
- `HANDOFF.md`: project status, completed areas, and remaining work
- `DESIGN.md`: Cedar/Jans design details
- `README.md`: end-user setup and usage
