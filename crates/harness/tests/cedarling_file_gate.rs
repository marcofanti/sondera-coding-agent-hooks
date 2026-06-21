//! RED — fails to compile until CedarlingPolicyEngine is implemented.
//!
//! Gate tests for file operations: read_file, write_file, edit_file,
//! delete_file, observe_file_result.

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
fn file(path: &str) -> EntityUid   { uid("Jans::File", path) }

fn basic_entities(agent_id: &str) -> Entities {
    let json = serde_json::json!([
        { "uid": {"type": "Jans::Workload", "id": agent_id},
          "attrs": {"provider_id": "test"}, "parents": [] },
        { "uid": {"type": "Jans::Label", "id": "Public"}, "attrs": {}, "parents": [] },
        { "uid": {"type": "Jans::Label", "id": "Internal"}, "attrs": {}, "parents": [] }
    ]);
    Entities::from_json_value(json, None).expect("entities must parse")
}

fn clean_read_context(path: &str) -> Context {
    Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "policy":     { "compliant": true, "violations": [] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Internal" } },
            "path":       path,
            "operation":  "read",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .expect("context must parse")
}

fn clean_write_context(path: &str) -> Context {
    Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "policy":     { "compliant": true, "violations": [] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "path":       path,
            "operation":  "write",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .expect("context must parse")
}

// ─── ALLOW ───────────────────────────────────────────────────────────────────

#[test]
fn allows_read_rust_source() {
    let e = engine();
    let decision = e.is_authorized(
        workload("claude"),
        action("read_file"),
        file("src/main.rs"),
        clean_read_context("src/main.rs"),
        basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Allow, "reading .rs file must be allowed");
}

#[test]
fn allows_write_normal_file() {
    let e = engine();
    let decision = e.is_authorized(
        workload("claude"),
        action("write_file"),
        file("src/lib.rs"),
        clean_write_context("src/lib.rs"),
        basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Allow, "writing .rs file must be allowed");
}

// ─── DENY: private key reads ─────────────────────────────────────────────────

#[test]
fn denies_read_pem_key() {
    let e = engine();
    let decision = e.is_authorized(
        workload("claude"),
        action("read_file"),
        file("certs/server.pem"),
        clean_read_context("certs/server.pem"),
        basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "reading .pem file must be denied");
}

#[test]
fn denies_read_key_file() {
    let e = engine();
    let decision = e.is_authorized(
        workload("claude"),
        action("read_file"),
        file("secrets/server.key"),
        clean_read_context("secrets/server.key"),
        basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "reading .key file must be denied");
}

// ─── DENY: writing secrets into .env ─────────────────────────────────────────

#[test]
fn denies_write_secrets_into_env() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 1, "categories": ["secrets_detection"], "severity": 2 },
            "policy":     { "compliant": true, "violations": [] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "path":       ".env",
            "operation":  "write",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .unwrap();
    let decision = e.is_authorized(
        workload("claude"), action("write_file"), file(".env"), ctx, basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "writing secrets to .env must be denied");
}

// ─── DENY: SC2 injection in source files ─────────────────────────────────────

#[test]
fn denies_write_sql_injection() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "policy":     { "compliant": false, "violations": ["SC2"] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "path":       "db/queries.sql",
            "operation":  "write",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .unwrap();
    let decision = e.is_authorized(
        workload("claude"), action("write_file"), file("db/queries.sql"), ctx, basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "writing SQL injection must be denied");
}

// ─── DENY: SC3 secrets exposure ───────────────────────────────────────────────

#[test]
fn denies_hardcoded_secret_in_python() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "policy":     { "compliant": false, "violations": ["SC3"] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "path":       "auth/config.py",
            "operation":  "write",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .unwrap();
    let decision = e.is_authorized(
        workload("claude"), action("write_file"), file("auth/config.py"), ctx, basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "hardcoded secrets in Python must be denied");
}

// ─── DENY: file policy violation ─────────────────────────────────────────────

#[test]
fn denies_policy_violation_on_file_write() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "policy":     { "compliant": false, "violations": ["data_exfiltration"] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "path":       "output/report.csv",
            "operation":  "write",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .unwrap();
    let decision = e.is_authorized(
        workload("claude"), action("write_file"), file("output/report.csv"), ctx, basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "non-compliant file write must be denied");
}
