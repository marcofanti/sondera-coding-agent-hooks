# Cedarling Migration — Handoff Document

**Last updated:** 2026-06-21  
**Branch:** main  
**Working dir:** `/Users/mfanti/AgenticAIEngineering/sondera-coding-agent-hooks`

---

## What This Is

A full replacement of the embedded Cedar policy engine with a `CedarlingPolicyEngine`
modelled after jans-cedarling / carapace. Two authorization layers:

1. **CedarlingPolicyEngine** — static deployment-ceiling policies (Jans:: namespace)
2. **MandatePolicyEngine** — per-agent Ed25519-signed JWT carrying a Cedar policy
   subset (must be a subset of the ceiling)

We use `cedar-policy = "4"` directly (cedarling crate is at v0.0.0, not on
crates.io; we replicate its architecture natively).

---

## Key Design Decisions

### Entity Namespace

All Cedar entities use `Jans::` prefix (matching jans-cedarling / carapace):

- Principal: `Jans::Workload` (the AI agent)
- Resource: `Jans::Shell`, `Jans::API`, `Jans::Tool`, `Jans::File`, `Jans::Message`
- Labels: `Jans::Label`
- Taints: `Jans::Taint`
- Trajectory: `Jans::Trajectory` (entity in store, NOT the Cedar resource)

### Resource Type Shift (CRITICAL)

In the new model, **resource = the thing being acted on**, not the trajectory:

| Action | Resource |
|--------|----------|
| `exec_command` | `Jans::Shell::"git"` |
| `call_api` | `Jans::API::"api.github.com"` |
| `call_tool` | `Jans::Tool::"read"` |
| `read_file` / `write_file` / `edit_file` / `delete_file` | `Jans::File::"path"` |
| `observe_prompt` | `Jans::Message::"msg-id"` |

### Trajectory State in Context (CRITICAL)

Trajectory label/step_count/taints are in **context.trajectory**, not on resource:

```cedar
// WRONG (old pattern — resource was Jans::Trajectory):
resource.label == Label::"HighlyConfidential"
resource.step_count > 100
resource.taints.contains(Taint::"exfiltration")

// CORRECT (new pattern — resource is Jans::Shell / Jans::API etc.):
context.trajectory.label == Jans::Label::"HighlyConfidential"
context.trajectory.step_count > 100
context.trajectory.taints.contains(Jans::Taint::"exfiltration")
```

Exception: `Jans::File` has a `label` attribute on the entity itself, so
`resource.label` remains valid for `read_file`/`write_file`/`edit_file`/`delete_file`.

### Action Name Mapping

| Old name | New name |
|----------|----------|
| `ShellCommand` | `exec_command` |
| `ShellCommandOutput` | `observe_exec_output` |
| `WebFetch` | `call_api` |
| `WebFetchOutput` | `observe_api_output` |
| `FileRead` | `read_file` |
| `FileWrite` | `write_file` |
| `FileEdit` | `edit_file` |
| `FileDelete` | `delete_file` |
| `FileOperationResult` | `observe_file_result` |
| `Prompt` | `observe_prompt` |
| `ToolOutput` | `observe_tool_output` |

### Schema Format

Cedar JSON schema (`policies/schema.json`), not `.cedarschema` human-readable format.
Key format details:

- String attribute: `{ "required": false, "type": "String" }`
- Entity ref attribute: `{ "required": false, "type": "Entity", "name": "Jans::Label" }`
- Set of entities: `{ "required": false, "type": "Set", "element": { "type": "Entity", "name": "Jans::Taint" } }`

### CedarlingPolicyEngine Public API (designed, not yet implemented)

```rust
pub struct CedarlingPolicyEngine { schema, policy_set }

impl CedarlingPolicyEngine {
    pub fn from_policy_dir(path: impl AsRef<Path>) -> Result<Self>;
    pub fn schema(&self) -> &cedar_policy::Schema;
    pub fn policy_set(&self) -> &cedar_policy::PolicySet;
    pub fn is_authorized(
        &self,
        principal: cedar_policy::EntityUid,
        action:    cedar_policy::EntityUid,
        resource:  cedar_policy::EntityUid,
        context:   cedar_policy::Context,
        entities:  cedar_policy::Entities,
    ) -> cedar_policy::Decision;
}

impl PolicyEngine for CedarlingPolicyEngine { ... }

pub type CedarlingPolicyHarness = PolicyHarness<CedarlingPolicyEngine>;
```

### Dependencies Added to Cargo.toml

```toml
base64 = "0.22"
ed25519-dalek = { version = "2", features = ["rand_core"] }
jsonwebtoken = "9"
cedar-policy = "4"   # was already present
```

---

## Task List

### COMPLETED

- [x] Verify cedarling crate availability → use `cedar-policy = "4"` directly
- [x] Update `crates/harness/Cargo.toml` — add base64, ed25519-dalek, jsonwebtoken
- [x] Write `policies/schema.json` — Cedar JSON schema in Jans:: namespace
- [x] Rewrite `policies/base.cedar` — Jans:: namespace, new action names
- [x] Rewrite `policies/destructive.cedar` — Jans:: namespace
- [x] Rewrite `policies/file.cedar` — Jans:: namespace + trajectory-in-context
- [x] Rewrite `policies/ifc.cedar` — Jans:: namespace + trajectory-in-context
- [x] Rewrite `policies/supply_chain_risk.cedar` — Jans:: namespace
- [x] Delete `policies/base.cedarschema` (replaced by schema.json)
- [x] RED test: `tests/cedarling_schema.rs` — schema parses, all Jans:: types present
- [x] RED test: `tests/cedarling_policy_loading.rs` — .cedar files load, policy IDs present
- [x] RED test: `tests/cedarling_shell_gate.rs` — exec_command allow/deny
- [x] RED test: `tests/cedarling_api_gate.rs` — call_api allow/deny
- [x] RED test: `tests/cedarling_file_gate.rs` — file operations allow/deny
- [x] RED test: `tests/cedarling_ifc.rs` — HighlyConfidential trajectory blocks outbound
- [x] RED test: `tests/cedarling_destructive.rs` — rm -rf, git force push, DROP TABLE
- [x] RED test: `tests/cedarling_prompt_injection.rs` — observe_prompt injection blocks

### COMPLETED — GREEN phase

- [x] `crates/harness/src/cedarling/store.rs` — `CedarlingStore::load()`: reads schema.json + globs *.cedar
- [x] `crates/harness/src/cedarling/transform.rs` — `build_request()`: all 11 event types → Jans:: Cedar request
- [x] `crates/harness/src/cedarling/mod.rs` — `CedarlingPolicyEngine` + `impl PolicyEngine`
- [x] `crates/harness/src/lib.rs` — `pub mod cedarling`, `pub use cedarling::CedarlingPolicyEngine`, `pub type CedarlingPolicyHarness`
- [x] `crates/harness/src/bin/server.rs` — `--policy-engine cedarling` CLI variant added
- [x] `policies/base.cedarschema` — restored (legacy schema for CedarPolicyEngine tests)
- [x] `policies/file.cedar` — added `forbid-private-key-delete` policy
- [x] `cargo test --workspace` — all tests green (0 failures)
- [x] `cargo clippy --all-features -- -D warnings` — 0 warnings

### NEXT — Mandate layer (TDD RED then GREEN)

**`crates/harness/src/cedarling/store.rs`**
- `cedar_policy::Schema::from_json_value()` parsing `policies/schema.json`
- Glob `policies/*.cedar`, parse each, merge into `cedar_policy::PolicySet`
- Return `Err` if dir doesn't exist or schema.json missing

**`crates/harness/src/cedarling/transform.rs`**
- `event_to_request(event, entity_store) -> cedar_policy::Request`
- Map `Action::ShellCommand` → principal=Workload, action=exec_command, resource=Shell
- Map `Action::WebFetch` → call_api, resource=API
- Map `Action::FileOperation(Read)` → read_file, resource=File
- Map `Action::FileOperation(Write)` → write_file, resource=File
- Map `Action::FileOperation(Edit)` → edit_file, resource=File
- Map `Action::FileOperation(Delete)` → delete_file, resource=File
- Map `Action::ToolCall` → call_tool, resource=Tool
- Map `Observation::Prompt` → observe_prompt, resource=Message
- Map `Observation::ToolOutput` → observe_tool_output, resource=Tool
- Map `Observation::ShellCommandOutput` → observe_exec_output, resource=Shell
- Map `Observation::WebFetchOutput` → observe_api_output, resource=API
- Map `Observation::FileOperationResult` → observe_file_result, resource=File
- Build context from event + trajectory lookup in entity_store

**`crates/harness/src/cedarling/mod.rs`**
- `CedarlingPolicyEngine` struct with `store: CedarlingStore`
- `from_policy_dir()` → calls `CedarlingStore::load(path)`
- `is_authorized()` → calls `cedar_policy::Authorizer::is_authorized()`
- `impl PolicyEngine` → async `evaluate()` calls transform.rs + is_authorized()

**`crates/harness/src/lib.rs` updates**
```rust
mod cedarling;
pub use cedarling::CedarlingPolicyEngine;
pub type CedarlingPolicyHarness = PolicyHarness<CedarlingPolicyEngine>;
```

**`crates/harness/src/bin/server.rs` updates**
- Add `--policy-engine cedarling` CLI variant (alongside existing `cedar`)

### PENDING — Confirm GREEN

- [ ] `cargo test` — all cedarling_* tests pass

### PENDING — Mandate layer (TDD RED then GREEN)

**RED tests:**
- `tests/mandate_jwt.rs` — Ed25519 key gen, sign JWT, verify JWT, tampered JWT rejected
- `tests/mandate_subset.rs` — policy A ⊆ ceiling passes; policy with extra permit rejected
- `tests/mandate_policy_engine.rs` — ceiling Allow + mandate Allow = Allow; ceiling Deny = Deny

**GREEN implementation:**
- `crates/harness/src/mandate/jwt.rs` — Ed25519 key gen (ed25519-dalek), JWT sign/verify (jsonwebtoken)
- `crates/harness/src/mandate/subset.rs` — Cedar policy subset proof (compare permit sets)
- `crates/harness/src/mandate/mod.rs` — `MandatePolicyEngine<E: PolicyEngine>`
- Update lib.rs + server.rs

### PENDING — Final checks

- [ ] `cargo test --workspace` — all tests green
- [ ] `cargo clippy --all-features -- -D warnings` — zero warnings

---

## Files Changed or Created

| File | Status | Notes |
|------|--------|-------|
| `policies/schema.json` | NEW | Cedar JSON schema, Jans:: namespace |
| `policies/base.cedar` | REWRITTEN | 34 policies, Jans:: namespace |
| `policies/destructive.cedar` | REWRITTEN | 35 policies, Jans:: namespace |
| `policies/file.cedar` | REWRITTEN | Jans:: + trajectory-in-context |
| `policies/ifc.cedar` | REWRITTEN | Jans:: + trajectory-in-context |
| `policies/supply_chain_risk.cedar` | REWRITTEN | Jans:: namespace |
| `policies/base.cedarschema` | DELETED | Replaced by schema.json |
| `crates/harness/Cargo.toml` | MODIFIED | +base64, +ed25519-dalek, +jsonwebtoken |
| `crates/harness/tests/cedarling_schema.rs` | NEW | RED test |
| `crates/harness/tests/cedarling_policy_loading.rs` | NEW | RED test |
| `crates/harness/tests/cedarling_shell_gate.rs` | NEW | RED test |
| `crates/harness/tests/cedarling_api_gate.rs` | NEW | RED test |
| `crates/harness/tests/cedarling_file_gate.rs` | NEW | RED test |
| `crates/harness/tests/cedarling_ifc.rs` | INCOMPLETE | Write rejected |
| `crates/harness/src/cedarling/` | NOT CREATED | GREEN phase |
| `crates/harness/src/mandate/` | NOT CREATED | Mandate layer |

---

## Key Source Files (read before implementing)

| File | Why |
|------|-----|
| `crates/harness/src/policy_engine.rs` | `PolicyEngine` trait definition |
| `crates/harness/src/policy_harness.rs` | `PolicyHarness<E>` — wraps PolicyEngine |
| `crates/harness/src/cedar/mod.rs` | Existing `CedarPolicyEngine` — mirror this pattern |
| `crates/harness/src/cedar/transform.rs` | Existing event→Cedar mapping — replace with Jans:: version |
| `crates/harness/src/types.rs` | All event types: `ShellCommand`, `WebFetch`, `FileOperation`, etc. |
| `crates/harness/src/storage/entity.rs` | `EntityStore` API — used in transform for trajectory context |
| `crates/harness/tests/cedar_policy_loading.rs` | Test pattern to follow |
| `policies/schema.json` | Source of truth for Jans:: entity types and actions |

---

## Resuming This Session

```bash
# 1. Check ifc test file
cat crates/harness/tests/cedarling_ifc.rs

# 2. Write it if empty (see design above for test cases)

# 3. Write cedarling_destructive.rs and cedarling_prompt_injection.rs

# 4. Confirm RED
cargo test --no-run 2>&1 | grep "cedarling_"

# 5. Begin GREEN implementation
# Start with: crates/harness/src/cedarling/store.rs
```
