//! RED — fails to compile until mandate module is implemented.
//!
//! Tests the two-layer authorization behavior of MandatePolicyEngine:
//!   - Ceiling DENY always wins regardless of mandate.
//!   - When ceiling allows, mandate has the final word.
//!   - Invalid or missing mandate JWT causes denial.

use cedar_policy::{Context, Decision, Entities, EntityId, EntityTypeName, EntityUid};
use sondera_harness::mandate::{MandatePolicyEngine, jwt}; // → RED
use sondera_harness::{AllowAllPolicyEngine, CedarlingPolicyEngine};
use std::path::PathBuf;
use std::str::FromStr;

const POLICIES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies");

fn uid(entity_type: &str, id: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(entity_type).unwrap(),
        EntityId::new(id),
    )
}

fn basic_entities() -> Entities {
    Entities::from_json_value(
        serde_json::json!([
            { "uid": {"type": "Jans::Workload", "id": "agent-1"}, "attrs": {"provider_id": "test"}, "parents": [] },
            { "uid": {"type": "Jans::Label", "id": "Public"}, "attrs": {}, "parents": [] },
            { "uid": {"type": "Jans::Shell", "id": "git"}, "attrs": {}, "parents": [] },
        ]),
        None,
    ).unwrap()
}

fn clean_exec_ctx(command: &str) -> Context {
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
    ).unwrap()
}

// ─── Ceiling allow + mandate allow → Allow ───────────────────────────────────

#[test]
fn ceiling_allow_and_mandate_allow_gives_allow() {
    let (signing_key, verifying_key) = jwt::generate_keypair();

    // Mandate that permits exec_command on git
    let mandate_policy = r#"
        @id("mandate-git-ok")
        permit (
            principal,
            action == Jans::Action::"exec_command",
            resource == Jans::Shell::"git"
        );
    "#.to_string();

    let claims = jwt::MandateClaims {
        sub: "agent-1".to_string(),
        iss: "test-deployment".to_string(),
        iat: 0,
        exp: u64::MAX,
        policy: mandate_policy,
    };
    let token = jwt::sign_mandate(&signing_key, &claims).unwrap();

    let ceiling = AllowAllPolicyEngine;
    let engine = MandatePolicyEngine::new(ceiling, verifying_key);

    let d = engine.is_authorized(
        uid("Jans::Workload", "agent-1"),
        uid("Jans::Action", "exec_command"),
        uid("Jans::Shell", "git"),
        clean_exec_ctx("git status"),
        basic_entities(),
        Some(&token),
    );
    assert_eq!(d, Decision::Allow, "ceiling+mandate allow must give Allow");
}

// ─── Ceiling deny → Deny regardless of mandate ───────────────────────────────

#[test]
fn ceiling_deny_overrides_mandate_allow() {
    let (signing_key, verifying_key) = jwt::generate_keypair();

    // Mandate that would permit rm -rf
    let claims = jwt::MandateClaims {
        sub: "agent-1".to_string(),
        iss: "test-deployment".to_string(),
        iat: 0,
        exp: u64::MAX,
        policy: r#"permit (principal, action, resource);"#.to_string(),
    };
    let token = jwt::sign_mandate(&signing_key, &claims).unwrap();

    // Ceiling = CedarlingPolicyEngine, which forbids rm -rf
    let ceiling = CedarlingPolicyEngine::from_policy_dir(PathBuf::from(POLICIES_DIR)).unwrap();
    let engine = MandatePolicyEngine::new(ceiling, verifying_key);

    let d = engine.is_authorized(
        uid("Jans::Workload", "agent-1"),
        uid("Jans::Action", "exec_command"),
        uid("Jans::Shell", "rm"),
        Context::from_json_value(
            serde_json::json!({
                "workspace":   { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
                "signature":   { "matches": 0, "categories": [], "severity": 0 },
                "policy":      { "compliant": true, "violations": [] },
                "label":       { "__entity": { "type": "Jans::Label", "id": "Public" } },
                "command":     "rm -rf /tmp/build",
                "working_dir": "/workspace",
                "trajectory":  { "step_count": 1 }
            }),
            None,
        ).unwrap(),
        Entities::from_json_value(
            serde_json::json!([
                { "uid": {"type": "Jans::Workload", "id": "agent-1"}, "attrs": {"provider_id": "test"}, "parents": [] },
                { "uid": {"type": "Jans::Label", "id": "Public"}, "attrs": {}, "parents": [] },
                { "uid": {"type": "Jans::Shell", "id": "rm"}, "attrs": {}, "parents": [] },
            ]),
            None,
        ).unwrap(),
        Some(&token),
    );
    assert_eq!(d, Decision::Deny, "ceiling deny must override mandate allow");
}

// ─── Ceiling allow + mandate deny → Deny ────────────────────────────────────

#[test]
fn mandate_deny_overrides_ceiling_allow() {
    let (signing_key, verifying_key) = jwt::generate_keypair();

    // Mandate that ONLY permits cargo (not git)
    let claims = jwt::MandateClaims {
        sub: "agent-1".to_string(),
        iss: "test-deployment".to_string(),
        iat: 0,
        exp: u64::MAX,
        policy: r#"
            @id("mandate-cargo-only")
            permit (
                principal,
                action == Jans::Action::"exec_command",
                resource == Jans::Shell::"cargo"
            );
        "#.to_string(),
    };
    let token = jwt::sign_mandate(&signing_key, &claims).unwrap();

    let ceiling = AllowAllPolicyEngine;
    let engine = MandatePolicyEngine::new(ceiling, verifying_key);

    // Try to run git — mandate doesn't permit it
    let d = engine.is_authorized(
        uid("Jans::Workload", "agent-1"),
        uid("Jans::Action", "exec_command"),
        uid("Jans::Shell", "git"),
        clean_exec_ctx("git status"),
        basic_entities(),
        Some(&token),
    );
    assert_eq!(d, Decision::Deny, "mandate deny must override ceiling allow");
}

// ─── Invalid or absent mandate JWT → Deny when mandate is required ───────────

#[test]
fn invalid_jwt_returns_deny() {
    let (_, verifying_key) = jwt::generate_keypair();
    let ceiling = AllowAllPolicyEngine;
    let engine = MandatePolicyEngine::new(ceiling, verifying_key);

    let d = engine.is_authorized(
        uid("Jans::Workload", "agent-1"),
        uid("Jans::Action", "exec_command"),
        uid("Jans::Shell", "git"),
        clean_exec_ctx("git status"),
        basic_entities(),
        Some("not.a.valid.jwt"),
    );
    assert_eq!(d, Decision::Deny, "invalid JWT must be denied");
}

#[test]
fn missing_mandate_is_denied_when_required() {
    let (_, verifying_key) = jwt::generate_keypair();
    let ceiling = AllowAllPolicyEngine;
    let engine = MandatePolicyEngine::new(ceiling, verifying_key);

    // Pass None — no mandate presented
    let d = engine.is_authorized(
        uid("Jans::Workload", "agent-1"),
        uid("Jans::Action", "exec_command"),
        uid("Jans::Shell", "git"),
        clean_exec_ctx("git status"),
        basic_entities(),
        None, // no mandate
    );
    assert_eq!(d, Decision::Deny, "absent mandate must be denied when mandate is required");
}
