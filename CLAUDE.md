# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
cargo build --workspace

# Test all
cargo test --workspace

# Run a single test
cargo test -p sondera-harness --test cedarling_shell_gate allows_clean_git_status

# Lint
cargo fmt --all -- --check
cargo clippy --all-features -- -D warnings

# Start the harness server (Cedar engine, verbose)
cargo run --bin sondera-harness-server -- -v

# Start with allow-all engine (no policy checks, useful for testing hooks in isolation)
cargo run --bin sondera-harness-server -- --policy-engine allow-all -v

# Install Claude Code hooks (local scope, not committed)
cargo run -p sondera-claude -- install

# Install project-scoped hooks (committed to git, shared)
cargo run -p sondera-claude -- install --project

# Uninstall
cargo run -p sondera-claude -- uninstall
```

## Architecture

The system is a **reference monitor for AI coding agents**. Hook adapter binaries intercept every tool call and forward events to a central harness server that evaluates Cedar policies and returns Allow/Deny.

### Request flow

```
Agent (Claude/Cursor/Copilot/Gemini)
  │  stdin/stdout JSON hook
  ▼
apps/{claude,cursor,copilot,gemini}   — normalize agent-specific JSON → Event
  │  tarpc RPC over Unix socket
  ▼
crates/harness/src/bin/server.rs      — PolicyHarness<CedarPolicyEngine>
  │
  ├─ crates/guardrails/signature      — YARA-X scan → signature context
  ├─ crates/guardrails/ifc            — Ollama LLM → sensitivity label (Bell-LaPadula)
  ├─ crates/guardrails/policy         — Ollama LLM → secure code policy classification
  │
  ▼
CedarPolicyEngine / CedarlingPolicyEngine
  │  cedar_policy::Authorizer
  ▼
Adjudicated { Allow | Deny | Escalate }
  │
  └─ EntityStore (Fjall KV) + TrajectoryStore (libsql/Turso)
```

### Event model

Every hook event is normalized into one of four `TrajectoryEvent` categories (defined in `crates/harness/src/types.rs`):

| Category | When | Examples |
|----------|------|---------|
| `Action` | Before execution | `ShellCommand`, `FileOperation`, `WebFetch`, `ToolCall` |
| `Observation` | After execution | `ShellCommandOutput`, `FileOperationResult`, `WebFetchOutput` |
| `Control` | Lifecycle | `Started`, `Completed`, `Failed`, `Adjudicated` |
| `State` | Snapshots | `Snapshot` (cwd, git branch, open files) |

### Cedar entity model (in-flight migration)

The codebase is mid-migration from a flat namespace to `Jans::` (aligned with jans-cedarling/carapace). See `DESIGN.md` for full spec.

**Current (green tests):** `Agent`, `Trajectory`, `Tool`, `File`, `Label`, `Message` — used by `CedarPolicyEngine` in `crates/harness/src/cedar/`

**Target (red tests):** `Jans::Workload`, `Jans::Shell`, `Jans::API`, `Jans::File`, `Jans::Tool`, `Jans::Message`, `Jans::Label`, `Jans::Trajectory` — used by `CedarlingPolicyEngine` (not yet implemented)

### Cedar request mapping (Jans:: target model)

| Event | Action | Resource |
|-------|--------|----------|
| `ShellCommand` | `Jans::Action::"exec_command"` | `Jans::Shell::"<binary>"` |
| `WebFetch` | `Jans::Action::"call_api"` | `Jans::API::"<domain>"` |
| `FileOperation{Read}` | `Jans::Action::"read_file"` | `Jans::File::"<path>"` |
| `FileOperation{Write}` | `Jans::Action::"write_file"` | `Jans::File::"<path>"` |
| `ToolCall` | `Jans::Action::"call_tool"` | `Jans::Tool::"<tool>"` |
| `Prompt` | `Jans::Action::"observe_prompt"` | `Jans::Message::"<event_id>"` |

Every Cedar context includes `workspace`, `signature`, `policy`, `label`, and `trajectory` fields. Trajectory state (step_count, label, taints) is always in `context.trajectory.*` — never on the resource entity.

### Policy files

All policies live in `policies/`. Cedar's `forbid` always beats `permit`.

| File | Scope |
|------|-------|
| `base.cedar` | Default permit + universal forbids (injection, severity, credential access, exfiltration) |
| `destructive.cedar` | `rm -rf`, git force-push, terraform destroy, DROP DATABASE, kill -9 |
| `file.cedar` | Bell-LaPadula no-write-down, private keys, secrets in source, OWASP violations |
| `ifc.cedar` | Outbound blocking by trajectory sensitivity label, runaway step limits |
| `supply_chain_risk.cedar` | Typosquatting, dependency confusion, build script injection |

Policies use `@id("policy-name")` annotations — the harness extracts these to populate `Adjudicated.annotations` for structured deny messages.

### PolicyEngine trait

`crates/harness/src/policy_engine.rs` defines the `PolicyEngine` trait. Implement it to plug in a custom authorization backend. `AllowAllPolicyEngine` is the no-op implementation for dry-runs and tests. `CedarPolicyEngine` is the current production backend; `CedarlingPolicyEngine` is the migration target.

### Storage

- **EntityStore** (`crates/harness/src/storage/entity.rs`): Fjall KV, persists Cedar entities (agents, trajectories, files, labels). Lives at `~/.sondera/entities/` or `/var/run/sondera/entities/`.
- **TrajectoryStore** (`crates/harness/src/storage/turso.rs`): libsql/Turso, append-only log of all trajectory events. Tests use `open_in_memory()`.

### Tests

All integration tests are in `crates/harness/tests/`. Two classes:

- `cedar_*` — test the existing `CedarPolicyEngine` (pass today)
- `cedarling_*` — test the target `CedarlingPolicyEngine` (RED: do not compile until `CedarlingPolicyEngine` is implemented)

Test harnesses use `CedarPolicyHarness::from_policy_dir_isolated()` / `CedarlingPolicyEngine::from_policy_dir()` with the real `policies/` directory pointed at by `CARGO_MANIFEST_DIR/../../policies`.

### Workspace crates

| Crate | Binary / lib |
|-------|-------------|
| `crates/harness` | lib + `sondera-harness-server` binary |
| `crates/guardrails/signature` | lib (YARA-X) |
| `crates/guardrails/ifc` | lib (LLM IFC classifier) |
| `crates/guardrails/policy` | lib (LLM policy classifier) |
| `crates/common` | lib (stdin/stdout JSON, tracing helpers for hook binaries) |
| `crates/mcp` | MCP server for interactive Cedar policy authoring |
| `apps/claude` | `sondera-claude` binary |
| `apps/cursor` | `sondera-cursor` binary |
| `apps/copilot` | `sondera-copilot` binary |
| `apps/gemini` | `sondera-gemini` binary |
