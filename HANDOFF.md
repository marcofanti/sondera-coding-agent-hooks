# Sondera Coding Agent Hooks — Handoff Document

**Last updated:** 2026-06-21  
**Branch:** main  
**Fork:** https://github.com/marcofanti/sondera-coding-agent-hooks  
**Upstream:** https://github.com/sondera-ai/sondera-coding-agent-hooks  

---

## Fork Workflow

This repo is a fork of `sondera-ai/sondera-coding-agent-hooks`. The fork lives at
`marcofanti/sondera-coding-agent-hooks`. To keep it in sync with upstream:

```bash
# One-time setup
git remote add upstream https://github.com/sondera-ai/sondera-coding-agent-hooks.git

# Pull in upstream changes
git fetch upstream && git merge upstream/main

# Push to fork
git push origin main
```

---

## Project Status: Production-Ready Core

The `CedarlingPolicyEngine` (Jans:: namespace) is fully implemented, wired, and green.
All four layers — Cedar authorization, guardrail scanning, taint propagation, and IFC label
propagation — are live. The Python SDK, escalation CLI, and multi-scenario Cedar policies are
also complete.

---

## Architecture

```
Agent (Claude/Cursor/Copilot/Gemini)
  │  stdin/stdout JSON hook
  ▼
apps/{claude,cursor,copilot,gemini}   — normalize agent-specific JSON → Event
  │  tarpc RPC over Unix socket
  ▼
PolicyHarness<CedarlingPolicyEngine>
  │
  ├─ Guardrails::compute(scannable_text)
  │   ├─ sondera_signature::scan()      — YARA-X: exfil, credential_access, injection …
  │   ├─ DataModel::classify()          — Ollama IFC label (Public…HighlyConfidential)
  │   └─ PolicyModel::evaluate_content()— Ollama policy compliance
  │
  ├─ transform::build_request_with_raw()— Event → (principal, action, resource, ctx, entities)
  │   raw field merge: hook pre-computed wins, guardrail fills gaps only
  │
  ├─ CedarlingPolicyEngine::authorize_full() — cedar_policy::Authorizer
  │
  ├─ Taint propagation — @taint("name") annotations → Trajectory.taints in EntityStore
  └─ IFC label propagation — new_label.level() > current → elevate Trajectory.label
```

---

## Cedar Entity Model (Jans:: namespace)

| Principal | Action | Resource |
|-----------|--------|----------|
| `Jans::Workload::"<agent-id>"` | `exec_command` | `Jans::Shell::"<binary>"` |
| | `call_api` | `Jans::API::"<domain>"` |
| | `read_file` / `write_file` / `edit_file` / `delete_file` | `Jans::File::"<path>"` |
| | `call_tool` | `Jans::Tool::"<tool>"` |
| | `observe_prompt` / `observe_think` | `Jans::Message::"<event-id>"` |
| | `observe_exec_output` | `Jans::Shell::"<binary>"` |
| | `observe_api_output` | `Jans::API::"<domain>"` |
| | `observe_file_result` | `Jans::File::"<path>"` |
| | `observe_tool_output` | `Jans::Tool::"<tool>"` |
| | `send_email` / `read_email` / `list_emails` | `Jans::API::"mail.google.com"` |
| | `read_calendar` / `create_event` / `update_event` / `delete_event` | `Jans::API::"calendar.google.com"` |
| | `navigate` / `fill_form` / `submit_form` / `evaluate_script` / `take_screenshot` | `Jans::API::"<domain>"` |

Trajectory state is in **context.trajectory.{label, step_count, taints}** — never on the resource.

---

## Policy Files

| File | Scope |
|------|-------|
| `policies/schema.json` | Cedar JSON schema — all Jans:: entity types and actions |
| `policies/base.cedar` | Default-permit + forbids: injection, exfil, credential access, shell/web gates |
| `policies/destructive.cedar` | rm -rf, git force-push, terraform destroy, DROP DATABASE, kill -9 |
| `policies/file.cedar` | Bell-LaPadula IFC, private keys, secrets in source, OWASP violations |
| `policies/ifc.cedar` | Outbound blocking by trajectory label, taint guards, step-count limits |
| `policies/supply_chain_risk.cedar` | Typosquatting, dependency confusion, build script injection |
| `policies/communication.cedar` | Email/calendar: exfil guards, IFC label blocks, escalation for `delete_event` |
| `policies/browser.cedar` | Browser navigation: `submit_form` always escalates, JS eval severity gate |

Annotating a forbid with `@taint("name")` causes `PolicyHarness` to add that string to
`Trajectory.taints` in the entity store. Annotating with `@decision("escalate")` promotes
Deny → Escalate unless another co-fired forbid is a hard deny.

---

## Key Design Decisions

### Guardrail merge order

The hook binary may pre-compute signature/label/policy fields and inject them via `event.raw`.
The harness also runs YARA-X (and optionally Ollama) live. Merge strategy: **hook's `event.raw`
wins for any field present there; guardrail fills gaps only.** This preserves the hook's
closer-to-content scan while ensuring fields missing from the hook are never left empty.

### `@decision("escalate")` semantics

If every matched forbid policy carries `@decision("escalate")`, the harness returns
`Decision::Escalate` (not Deny). If any matched forbid lacks the annotation, Deny wins.
This lets operators distinguish "ask first" from "hard no."

### Two-layer authorization (mandate engine)

`MandatePolicyEngine<CedarlingPolicyEngine>` wraps the ceiling with a per-agent Ed25519-signed
JWT. Both layers must allow. Mandate is a Cedar policy subset — cannot grant more than the ceiling.

---

## What Is Complete

### Policy Engine
- [x] `CedarlingPolicyEngine` — `from_policy_dir()`, `evaluate()`, `is_authorized()`
- [x] `CedarlingStore` — schema.json parse, *.cedar glob merge
- [x] `transform::build_request_with_raw()` — all 13 event types → Jans:: Cedar request
- [x] `Guardrails` struct — YARA-X + optional Ollama IFC + optional Ollama policy
- [x] Guardrail merge: hook.raw wins, guardrail fills gaps
- [x] Taint propagation — `@taint()` annotations → `Trajectory.taints` deduplicated
- [x] IFC label propagation — classified label elevates `Trajectory.label` if higher
- [x] `@decision("escalate")` annotation support — soft Deny with hard-deny override
- [x] `EscalationStore` — Turso/libsql table, TTL, approve/deny, Slack webhook
- [x] `MandatePolicyEngine` — Ed25519 JWT, subset proof, two-layer adjudication
- [x] `PolicyHarness` — taint propagation post-evaluation wired in
- [x] `AllowAllPolicyEngine` — no-op for dry-runs and isolated tests

### Cedar Policies
- [x] `base.cedar`, `destructive.cedar`, `file.cedar`, `ifc.cedar`, `supply_chain_risk.cedar`
- [x] `communication.cedar` — email/calendar action rules
- [x] `browser.cedar` — navigation/form/script rules
- [x] @taint annotations on credential_access and exfiltration policies
- [x] `schema.json` — all actions including communication and browser groups

### Server
- [x] `--policy-engine cedarling | cedar | allow-all | mandate`
- [x] `--admin-port 9090` — axum HTTP admin API for escalation approve/deny/list + SSE stream
- [x] EscalationStore wired into `AdminState` + SSE broadcaster + Slack webhook

### CLI (`apps/claude`)
- [x] `sondera-claude escalations list/show/approve/deny`
- [x] `sondera-claude mandate sign --signing-key --agent-id --policy --exp`

### Python SDK (`sondera-python/`)
- [x] `PolicyGate` — sync (requests) and async (aiohttp) variants
- [x] `Trajectory.adjudicate(action)` — gate any action
- [x] `Trajectory.observe(observation)` — send tool outputs back
- [x] `Observation` factory — shell_output, file_result, web_fetch_output, tool_output, prompt, think
- [x] `AsyncTrajectory.observe()` — async variant
- [x] LangChain `PolicyGateTool` wrapper

### Tests (all passing)
- [x] `cedarling_schema.rs` — schema parses, Jans:: types present
- [x] `cedarling_policy_loading.rs` — all *.cedar load, policy IDs present
- [x] `cedarling_shell_gate.rs` — exec_command allow/deny
- [x] `cedarling_api_gate.rs` — call_api allow/deny
- [x] `cedarling_file_gate.rs` — file operations allow/deny
- [x] `cedarling_ifc.rs` — HighlyConfidential trajectory blocks outbound
- [x] `escalation_store.rs` — create, approve, deny, TTL expiry
- [x] `escalation_annotation.rs` — @decision("escalate") fires correctly
- [x] `taint_propagation.rs` — 4 tests: exfil, credential, allow=no-taint, dedup
- [x] `guardrail_wiring.rs` — 3 tests: YARA fires without raw, clean allows, hook.raw wins
- [x] `transform_action_mapping.rs` — 9 action mapping tests
- [x] `scenario_email.rs` — email/calendar policy scenarios
- [x] `scenario_browser.rs` — browser action policy scenarios
- [x] `policy_engine_configuration.rs` — engine variants and configuration
- [x] `trajectory_label_persistence.rs` — label survives across events

---

## What Remains

### MCP proxy server (`crates/mcp/src/gate.rs`)

A stub is in place but the MCP tool-call proxy that intercepts LangChain MCP tool invocations
and gates them through the harness is not yet implemented. The existing `crates/mcp` crate
provides the Cedar policy authoring server; the gate layer is separate.

### Other agent adapters

`apps/cursor`, `apps/copilot`, `apps/gemini` have hook binaries but may be missing some of the
newer hook event types (Prompt/Think observations, escalation return path). Audit against
`apps/claude` as the reference.

### Async `observe()` coverage

The Python SDK's `AsyncTrajectory.observe()` is implemented and unit-tested with mocks but has
no integration test against a live harness. Add one to `sondera-python/tests/test_async_gate.py`.

---

## Resuming

```bash
# Build
cargo build --workspace

# Test (all should pass)
cargo test --workspace

# Start harness (cedarling engine, verbose)
cargo run --bin sondera-harness-server -- --policy-engine cedarling -v

# Start with admin API on port 9090
cargo run --bin sondera-harness-server -- --policy-engine cedarling --admin-port 9090 -v

# Install Claude Code hooks
cargo run -p sondera-claude -- install

# Sign a mandate JWT
cargo run -p sondera-claude -- mandate sign \
  --signing-key /etc/sondera/mandate.pem \
  --agent-id my-agent \
  --policy policies/base.cedar \
  --exp 3600

# Python SDK (sync)
cd sondera-python && pip install -e . && pytest

# List pending escalations
cargo run -p sondera-claude -- escalations list
```

---

## File Map

| Path | What it does |
|------|-------------|
| `crates/harness/src/cedarling/mod.rs` | `CedarlingPolicyEngine` + `Guardrails` + label/taint propagation |
| `crates/harness/src/cedarling/transform.rs` | Event → Jans:: Cedar request (13 event types) |
| `crates/harness/src/cedarling/store.rs` | Load schema.json + *.cedar into `CedarlingStore` |
| `crates/harness/src/policy_harness.rs` | `PolicyHarness<E>` — taint propagation post-eval |
| `crates/harness/src/policy_engine.rs` | `PolicyEngine` trait definition |
| `crates/harness/src/escalation/` | `EscalationStore` + axum HTTP admin API + SSE |
| `crates/harness/src/bin/server.rs` | tarpc server + `--admin-port` axum sidecar |
| `crates/harness/src/types.rs` | All event types |
| `policies/schema.json` | Cedar JSON schema — single source of truth for entity types |
| `policies/*.cedar` | Policy files — one per threat domain |
| `apps/claude/src/app/escalations.rs` | `sondera-claude escalations` CLI |
| `apps/claude/src/app/mandate.rs` | `sondera-claude mandate sign` CLI |
| `sondera-python/sondera/` | Python SDK — gate, trajectory, observations, langchain |
| `design/` | Architecture decision records and scenario analysis |
