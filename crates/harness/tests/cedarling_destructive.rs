//! RED — fails to compile until CedarlingPolicyEngine is implemented.
//!
//! Destructive command gate tests. Verifies that the destructive.cedar policies
//! block rm -rf, git force push, DROP TABLE, terraform destroy, etc.

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

fn workload(id: &str) -> EntityUid  { uid("Jans::Workload", id) }
fn action(name: &str) -> EntityUid  { uid("Jans::Action", name) }
fn shell(binary: &str) -> EntityUid { uid("Jans::Shell", binary) }
fn file(path: &str) -> EntityUid    { uid("Jans::File", path) }

fn basic_entities() -> Entities {
    Entities::from_json_value(
        serde_json::json!([
            { "uid": {"type": "Jans::Workload", "id": "claude"}, "attrs": {"provider_id": "test"}, "parents": [] },
            { "uid": {"type": "Jans::Label", "id": "Public"}, "attrs": {}, "parents": [] }
        ]),
        None,
    )
    .expect("entities must parse")
}

fn clean_shell_ctx(command: &str) -> Context {
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

fn clean_file_ctx(path: &str) -> Context {
    Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "policy":     { "compliant": true, "violations": [] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "path":       path,
            "operation":  "delete",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .expect("context must parse")
}

// ─── DENY: filesystem destruction ────────────────────────────────────────────

#[test]
fn denies_rm_rf() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("exec_command"), shell("rm"),
        clean_shell_ctx("rm -rf /tmp/build"), basic_entities(),
    );
    assert_eq!(d, Decision::Deny, "rm -rf must be denied");
}

#[test]
fn denies_rm_rf_root() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("exec_command"), shell("rm"),
        clean_shell_ctx("rm -rf /"), basic_entities(),
    );
    assert_eq!(d, Decision::Deny, "rm -rf / must be denied");
}

// ─── DENY: git destructive ops ───────────────────────────────────────────────

#[test]
fn denies_git_force_push() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("exec_command"), shell("git"),
        clean_shell_ctx("git push --force origin main"), basic_entities(),
    );
    assert_eq!(d, Decision::Deny, "git push --force must be denied");
}

#[test]
fn denies_git_push_force_shorthand() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("exec_command"), shell("git"),
        clean_shell_ctx("git push -f origin main"), basic_entities(),
    );
    assert_eq!(d, Decision::Deny, "git push -f must be denied");
}

#[test]
fn denies_git_reset_hard() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("exec_command"), shell("git"),
        clean_shell_ctx("git reset --hard HEAD~5"), basic_entities(),
    );
    assert_eq!(d, Decision::Deny, "git reset --hard must be denied");
}

// ─── DENY: database destruction ──────────────────────────────────────────────

#[test]
fn denies_drop_database() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("exec_command"), shell("psql"),
        clean_shell_ctx("psql -c 'DROP DATABASE production'"), basic_entities(),
    );
    assert_eq!(d, Decision::Deny, "DROP DATABASE must be denied");
}

#[test]
fn denies_drop_table() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("exec_command"), shell("psql"),
        clean_shell_ctx("psql -c 'DROP TABLE users CASCADE'"), basic_entities(),
    );
    assert_eq!(d, Decision::Deny, "DROP TABLE must be denied");
}

// ─── DENY: terraform destroy ──────────────────────────────────────────────────

#[test]
fn denies_terraform_destroy() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("exec_command"), shell("terraform"),
        clean_shell_ctx("terraform destroy -auto-approve"), basic_entities(),
    );
    assert_eq!(d, Decision::Deny, "terraform destroy must be denied");
}

// ─── DENY: process kill ──────────────────────────────────────────────────────

#[test]
fn denies_kill_9() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("exec_command"), shell("kill"),
        clean_shell_ctx("kill -9 1"), basic_entities(),
    );
    assert_eq!(d, Decision::Deny, "kill -9 must be denied");
}

// ─── DENY: delete_file on key material ───────────────────────────────────────

#[test]
fn denies_delete_pem_file() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("delete_file"), file("certs/server.pem"),
        clean_file_ctx("certs/server.pem"), basic_entities(),
    );
    assert_eq!(d, Decision::Deny, "delete_file on .pem must be denied");
}

// ─── ALLOW: safe commands ────────────────────────────────────────────────────

#[test]
fn allows_git_status() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("exec_command"), shell("git"),
        clean_shell_ctx("git status"), basic_entities(),
    );
    assert_eq!(d, Decision::Allow, "git status must be allowed");
}

#[test]
fn allows_cargo_test() {
    let e = engine();
    let d = e.is_authorized(
        workload("claude"), action("exec_command"), shell("cargo"),
        clean_shell_ctx("cargo test --workspace"), basic_entities(),
    );
    assert_eq!(d, Decision::Allow, "cargo test must be allowed");
}
