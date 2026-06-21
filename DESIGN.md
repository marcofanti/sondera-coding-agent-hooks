# Cedarling Policy Engine — Design Document

**Status:** In progress  
**Last updated:** 2026-06-20

---

## Problem

The existing `CedarPolicyEngine` uses a flat, non-standard Cedar entity model
(`Agent`, `Trajectory`, `Tool`, etc.) with the trajectory as the Cedar *resource*.
This diverges from the jans-cedarling / carapace architecture and makes per-agent
mandate delegation impossible.

Goals:
1. Align with carapace / jans-cedarling entity model (`Jans::` namespace)
2. Enable deployment-level policy ceiling enforcement
3. Enable per-agent mandate delegation via Ed25519-signed JWTs

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   PolicyHarness<E>                       │
│  (trajectory persistence, entity bookkeeping, RPC)       │
└────────────────────────┬────────────────────────────────┘
                         │ delegate non-control events
              ┌──────────▼──────────────┐
              │  MandatePolicyEngine<E>  │  Layer 2 (per-agent)
              │  Ed25519 JWT mandate     │  mandate ⊆ ceiling
              └──────────┬──────────────┘
                         │ ceiling check first
              ┌──────────▼──────────────┐
              │  CedarlingPolicyEngine   │  Layer 1 (deployment)
              │  cedar-policy = "4"      │  static .cedar files
              └─────────────────────────┘
```

Both layers implement `PolicyEngine`. Cedar's `forbid always wins` semantics apply
at each layer independently. A request must be `Allow` at *both* layers to proceed.

---

## Layer 1 — CedarlingPolicyEngine

### Responsibility

Static deployment ceiling. Loaded once at startup from `policies/`. The operator
controls what agents are permitted to do at the infrastructure level. Agents cannot
escalate beyond this ceiling regardless of their mandate.

### Module layout

```
crates/harness/src/cedarling/
├── mod.rs        — CedarlingPolicyEngine struct + PolicyEngine impl
├── store.rs      — load schema.json + *.cedar files into cedar-policy types
└── transform.rs  — Event → Cedar (principal, action, resource, context, entities)
```

### store.rs

```rust
pub struct CedarlingStore {
    schema:     cedar_policy::Schema,
    policy_set: cedar_policy::PolicySet,
}

impl CedarlingStore {
    pub fn load(dir: impl AsRef<Path>) -> Result<Self>;
    pub fn schema(&self) -> &cedar_policy::Schema;
    pub fn policy_set(&self) -> &cedar_policy::PolicySet;
}
```

Loading sequence:
1. Read `{dir}/schema.json` → `cedar_policy::Schema::from_json_value()`
2. Glob `{dir}/*.cedar` → parse each with `cedar_policy::PolicySet::from_str()`
3. Merge into single `PolicySet` (Cedar supports additive merging)
4. Return `Err` if dir missing, schema.json missing, or any .cedar fails to parse

### transform.rs

Maps `Event` (harness type) → Cedar authorization request.

```
Event::Action(ShellCommand { command, .. })
  principal = Jans::Workload::"<agent.id>"
  action    = Jans::Action::"exec_command"
  resource  = Jans::Shell::"<binary>"       ← first token of command
  context   = { command, working_dir, workspace, signature, policy, label, trajectory }

Event::Action(WebFetch { url, prompt, .. })
  action    = Jans::Action::"call_api"
  resource  = Jans::API::"<domain>"         ← parsed from url

Event::Action(FileOperation { op: Read, path })
  action    = Jans::Action::"read_file"
  resource  = Jans::File::"<path>"

Event::Action(FileOperation { op: Write, path })
  action    = Jans::Action::"write_file"
  resource  = Jans::File::"<path>"

Event::Action(FileOperation { op: Edit, path })
  action    = Jans::Action::"edit_file"
  resource  = Jans::File::"<path>"

Event::Action(FileOperation { op: Delete, path })
  action    = Jans::Action::"delete_file"
  resource  = Jans::File::"<path>"

Event::Action(ToolCall { tool, .. })
  action    = Jans::Action::"call_tool"
  resource  = Jans::Tool::"<tool>"

Event::Observation(Prompt { content, role })
  action    = Jans::Action::"observe_prompt"
  resource  = Jans::Message::"<event_id>"

Event::Observation(ToolOutput { .. })
  action    = Jans::Action::"observe_tool_output"
  resource  = Jans::Tool::"<tool_name>"

Event::Observation(ShellCommandOutput { .. })
  action    = Jans::Action::"observe_exec_output"
  resource  = Jans::Shell::"<binary>"

Event::Observation(WebFetchOutput { url, .. })
  action    = Jans::Action::"observe_api_output"
  resource  = Jans::API::"<domain>"

Event::Observation(FileOperationResult { .. })
  action    = Jans::Action::"observe_file_result"
  resource  = Jans::File::"<path>"
```

Context structure (same for all actions — Cedar ignores unknown attributes):
```json
{
  "workspace":  { "cwd": "...", "permission_mode": "...", "transcript_path": "..." },
  "signature":  { "matches": 0, "categories": [], "severity": 0 },
  "policy":     { "compliant": true, "violations": [] },
  "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
  "trajectory": {
    "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
    "step_count": 1,
    "taints":     []
  },
  // action-specific fields:
  "command":    "git status",      // exec_command / observe_exec_output
  "url":        "https://...",     // call_api / observe_api_output
  "prompt":     "...",             // call_api / observe_prompt
  "path":       "src/main.rs",     // read_file / write_file / edit_file / ...
  "content":    "...",             // observe_file_result / observe_prompt
  "role":       "user"             // observe_prompt
}
```

Signature and policy fields come from the harness-level YARA scan and IFC classifier
that runs *before* calling `evaluate()`. The transform reads them from `event.raw`.
Trajectory state is looked up from `EntityStore` by `trajectory_id`.

### mod.rs

```rust
pub struct CedarlingPolicyEngine {
    store: CedarlingStore,
}

impl CedarlingPolicyEngine {
    pub fn from_policy_dir(path: impl AsRef<Path>) -> Result<Self>;
    pub fn schema(&self) -> &cedar_policy::Schema;
    pub fn policy_set(&self) -> &cedar_policy::PolicySet;

    // Direct Cedar authorization — used by tests
    pub fn is_authorized(
        &self,
        principal: cedar_policy::EntityUid,
        action:    cedar_policy::EntityUid,
        resource:  cedar_policy::EntityUid,
        context:   cedar_policy::Context,
        entities:  cedar_policy::Entities,
    ) -> cedar_policy::Decision;
}

impl PolicyEngine for CedarlingPolicyEngine {
    fn name(&self) -> &'static str { "cedarling" }

    async fn evaluate(&self, event: &Event, entity_store: &EntityStore)
        -> Result<PolicyEvaluation>
    {
        let (principal, action, resource, context, entities) =
            transform::event_to_request(event, entity_store)?;
        let decision = self.is_authorized(principal, action, resource, context, entities);
        // map cedar_policy::Decision → Adjudicated, collect denying policy annotations
    }
}
```

### lib.rs exports

```rust
mod cedarling;
pub use cedarling::CedarlingPolicyEngine;
pub type CedarlingPolicyHarness = PolicyHarness<CedarlingPolicyEngine>;
```

---

## Layer 2 — MandatePolicyEngine

### Responsibility

Per-agent mandate delegation. An operator signs a JWT containing a Cedar policy
subset. The agent presents this JWT on startup. Every request must satisfy *both*
the ceiling (Layer 1) and the mandate (Layer 2). Cedar's `forbid always wins`
semantics mean a deny at either layer denies the request.

### JWT structure

```json
{
  "iss": "operator@example.com",
  "sub": "agent-id-xyz",
  "iat": 1718832000,
  "exp": 1718918400,
  "jti": "mandate-uuid",
  "cedar_policies": "permit (principal, action == Jans::Action::\"exec_command\", resource);"
}
```

Signed with Ed25519 (EdDSA). The operator's public key is provisioned in the
deployment config. The agent cannot forge or modify the mandate.

### Subset proof

Before accepting a mandate JWT, the engine verifies:

```
mandate_permits ⊆ ceiling_permits
```

Concretely: for every `permit` statement in the mandate policy, there must exist
a corresponding `permit` (or broader `permit`) in the ceiling that covers it.
Any `forbid` in the ceiling always wins regardless.

Implementation approach: evaluate each mandate permit against the ceiling as an
authorizer. If the ceiling would `Deny` any action that the mandate `Permit`s,
reject the mandate at startup.

### Module layout

```
crates/harness/src/mandate/
├── mod.rs       — MandatePolicyEngine<E: PolicyEngine>
├── jwt.rs       — Ed25519 key gen, JWT sign/verify (ed25519-dalek + jsonwebtoken)
└── subset.rs    — Cedar policy subset proof
```

### MandatePolicyEngine

```rust
pub struct MandatePolicyEngine<E: PolicyEngine> {
    ceiling:  E,
    mandate:  cedar_policy::PolicySet,   // parsed from JWT cedar_policies claim
    verifier: MandateVerifier,           // holds operator Ed25519 public key
}

impl<E: PolicyEngine> PolicyEngine for MandatePolicyEngine<E> {
    async fn evaluate(&self, event, entity_store) -> Result<PolicyEvaluation> {
        // 1. Check ceiling
        let ceiling_result = self.ceiling.evaluate(event, entity_store).await?;
        if ceiling_result.adjudicated.decision == Decision::Deny {
            return Ok(ceiling_result);   // ceiling deny wins immediately
        }
        // 2. Check mandate
        let mandate_decision = self.evaluate_mandate(event, entity_store)?;
        if mandate_decision == cedar_policy::Decision::Deny {
            return Ok(PolicyEvaluation::new(Adjudicated::deny(), ...));
        }
        Ok(ceiling_result)   // both Allow
    }
}
```

---

## Entity Model (Jans:: namespace)

### schema.json commonTypes

| Type | Fields |
|------|--------|
| `WorkspaceContext` | `cwd: String`, `permission_mode: String`, `transcript_path: String` |
| `SignatureContext` | `matches: Long`, `categories: Set<String>`, `severity: Long` |
| `PolicyContext` | `compliant: Bool`, `violations: Set<String>` |
| `TrajectoryContext` | `label?: Jans::Label`, `step_count: Long`, `taints: Set<Jans::Taint>` |

### entityTypes

| Entity | Attributes | MemberOf |
|--------|-----------|----------|
| `Workload` | `provider_id?: String` | — |
| `User` | — | — |
| `Label` | — | — |
| `Taint` | — | — |
| `Trajectory` | `step_count: Long`, `label?: Jans::Label`, `taints: Set<Jans::Taint>` | — |
| `Message` | `content: String`, `role: String` | `Trajectory` |
| `File` | `label?: Jans::Label` | — |
| `Shell` | — | — |
| `API` | — | — |
| `Tool` | — | — |

### Actions (principal → resource)

| Action | Principal | Resource |
|--------|-----------|----------|
| `observe_prompt` | `Workload` | `Message` |
| `exec_command` | `Workload` | `Shell` |
| `observe_exec_output` | `Workload` | `Shell` |
| `call_api` | `Workload` | `API` |
| `observe_api_output` | `Workload` | `API` |
| `call_tool` | `Workload` | `Tool` |
| `observe_tool_output` | `Workload` | `Tool` |
| `read_file` | `Workload` | `File` |
| `write_file` | `Workload` | `File` |
| `edit_file` | `Workload` | `File` |
| `delete_file` | `Workload` | `File` |
| `observe_file_result` | `Workload` | `File` |

---

## Policy File Structure

All policy files are in `policies/`. All use the `Jans::` namespace.

| File | Scope | Count |
|------|-------|-------|
| `schema.json` | Cedar schema | 1 |
| `base.cedar` | Default permit + universal forbids (severity, injection, policy violation) | 34 |
| `destructive.cedar` | rm -rf, git force push, DROP TABLE, terraform destroy, etc. | 35 |
| `file.cedar` | IFC label guards, secret files, OWASP SC2–SC7, post-read injection | ~80 |
| `ifc.cedar` | Bell-LaPadula outbound blocking by trajectory sensitivity | ~20 |
| `supply_chain_risk.cedar` | Package manager attack detection, build script injection | 12 |

---

## Information Flow Control Model

Simplified Bell-LaPadula "no write down" for agent trajectories:

```
Jans::Label::"HighlyConfidential"   (level 3)  ← unconditional outbound lockdown
Jans::Label::"Confidential"         (level 2)  ← outbound blocked when tainted
Jans::Label::"Internal"             (level 1)  ← restricted write-down
Jans::Label::"Public"               (level 0)  ← no restrictions
```

Once a trajectory ingests data at level N, its label is raised to N (high-water
mark). The IFC policies in `ifc.cedar` then restrict `call_api` and `exec_command`
based on `context.trajectory.label`.

---

## Test Strategy

All tests are integration tests in `crates/harness/tests/`.

### RED phase (all use `CedarlingPolicyEngine` which doesn't exist yet)

| File | What it tests |
|------|--------------|
| `cedarling_schema.rs` | schema.json parses; all Jans:: entity types and actions present |
| `cedarling_policy_loading.rs` | all .cedar files load; named policy IDs present |
| `cedarling_shell_gate.rs` | exec_command: git status allowed; rm -rf denied; policy violation denied |
| `cedarling_api_gate.rs` | call_api: docs.rs allowed; exfiltration sig denied; critical severity denied |
| `cedarling_file_gate.rs` | read_file .pem denied; write secrets to .env denied; SC2/SC3 violations denied |
| `cedarling_ifc.rs` | HC trajectory blocks call_api + curl; Public trajectory allows; step_count runaway denied |
| `cedarling_destructive.rs` | rm -rf, git push --force, DROP TABLE denied; git status allowed |
| `cedarling_prompt_injection.rs` | observe_prompt + prompt_injection sig denied; clean prompt allowed |

### GREEN phase (mandate layer)

| File | What it tests |
|------|--------------|
| `mandate_jwt.rs` | Ed25519 keygen; sign→verify round-trip; tampered JWT rejected |
| `mandate_subset.rs` | valid subset mandate accepted; over-privileged mandate rejected at startup |
| `mandate_policy_engine.rs` | ceiling allow + mandate allow = Allow; ceiling deny = Deny |

---

## Sequence: Request Evaluation

```
Hook process
  │
  │ tarpc IPC (Unix socket)
  ▼
HarnessServer::adjudicate(event)
  │
  ├─ YARA scan → signature context
  ├─ IFC classifier → label context
  ├─ EntityStore lookup → trajectory context
  │
  ▼
PolicyHarness::adjudicate(enriched_event)
  │
  ▼
MandatePolicyEngine::evaluate(event, entity_store)
  │
  ├─ CedarlingPolicyEngine::evaluate()   ← ceiling check
  │    └─ transform::event_to_request()
  │    └─ cedar_policy::Authorizer::is_authorized()
  │
  └─ mandate PolicySet eval              ← mandate check
       └─ cedar_policy::Authorizer::is_authorized()
  │
  ▼
PolicyEvaluation { adjudicated: Adjudicated { decision, reason, annotations }, raw }
  │
  ▼
EntityStore::persist_adjudication()
  │
  ▼
tarpc response → hook process → block or allow tool call
```
