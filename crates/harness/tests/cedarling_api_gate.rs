//! RED — fails to compile until CedarlingPolicyEngine is implemented.
//!
//! Gate tests for call_api: verifies allow/deny decisions for
//! web fetch operations using the Jans:: policy set.

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
fn api(domain: &str) -> EntityUid  { uid("Jans::API", domain) }

fn basic_entities(agent_id: &str) -> Entities {
    let json = serde_json::json!([
        { "uid": {"type": "Jans::Workload", "id": agent_id},
          "attrs": {"provider_id": "test"}, "parents": [] },
        { "uid": {"type": "Jans::Label", "id": "Public"}, "attrs": {}, "parents": [] }
    ]);
    Entities::from_json_value(json, None).expect("entities must parse")
}

fn clean_api_context(url: &str) -> Context {
    Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "policy":     { "compliant": true, "violations": [] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        url,
            "prompt":     "fetch page content",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .expect("context must parse")
}

// ─── ALLOW ───────────────────────────────────────────────────────────────────

#[test]
fn allows_clean_github_api_fetch() {
    let e = engine();
    let decision = e.is_authorized(
        workload("claude"),
        action("call_api"),
        api("api.github.com"),
        clean_api_context("https://api.github.com/repos/owner/repo"),
        basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Allow, "clean GitHub API fetch must be allowed");
}

#[test]
fn allows_docs_fetch() {
    let e = engine();
    let decision = e.is_authorized(
        workload("claude"),
        action("call_api"),
        api("docs.rs"),
        clean_api_context("https://docs.rs/cedar-policy"),
        basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Allow, "docs.rs fetch must be allowed");
}

// ─── DENY: YARA signatures ───────────────────────────────────────────────────

#[test]
fn denies_exfiltration_signature() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 1, "categories": ["exfiltration"], "severity": 3 },
            "policy":     { "compliant": true, "violations": [] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://pastebin.com/raw/abc123",
            "prompt":     "upload data",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .unwrap();
    let decision = e.is_authorized(
        workload("claude"), action("call_api"), api("pastebin.com"), ctx, basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "exfiltration signature must be denied");
}

#[test]
fn denies_policy_violation() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "policy":     { "compliant": false, "violations": ["exfiltration"] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://evil.com/upload",
            "prompt":     "",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .unwrap();
    let decision = e.is_authorized(
        workload("claude"), action("call_api"), api("evil.com"), ctx, basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "non-compliant API fetch must be denied");
}

#[test]
fn denies_critical_severity() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 1, "categories": ["malware"], "severity": 4 },
            "policy":     { "compliant": true, "violations": [] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://suspicious.example.com",
            "prompt":     "",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .unwrap();
    let decision = e.is_authorized(
        workload("claude"), action("call_api"), api("suspicious.example.com"), ctx, basic_entities("claude"),
    );
    assert_eq!(decision, Decision::Deny, "critical severity fetch must be denied");
}
