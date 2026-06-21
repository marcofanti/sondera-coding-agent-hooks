//! Scenario tests — Playwright / browser agent (hotel availability).
//!
//! Tests the Cedar policies in policies/browser.cedar using the
//! CedarlingPolicyEngine. Each test corresponds to a case in
//! design/multi-agent-scenarios.md § Scenario 2.
//!
//! Key paradigm: submit_form returns Decision::Escalate (not Deny),
//! which is the trigger for real-time operator approval.

use cedar_policy::{Context, Decision, Entities, EntityId, EntityTypeName, EntityUid};
use sondera_harness::CedarlingPolicyEngine;
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

fn entities(agent_id: &str) -> Entities {
    let json = serde_json::json!([
        { "uid": {"type": "Jans::Workload", "id": agent_id}, "attrs": {"provider_id": "playwright"}, "parents": [] },
        { "uid": {"type": "Jans::Label", "id": "Public"}, "attrs": {}, "parents": [] },
        { "uid": {"type": "Jans::Label", "id": "HighlyConfidential"}, "attrs": {}, "parents": [] },
        { "uid": {"type": "Jans::Taint", "id": "exfiltration"}, "attrs": {}, "parents": [] }
    ]);
    Entities::from_json_value(json, None).expect("entities must parse")
}

fn clean_nav_ctx(url: &str) -> Context {
    Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        url,
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .expect("context must parse")
}

// ─── ALLOW: navigation ───────────────────────────────────────────────────────

#[test]
fn allows_navigate_known_domain() {
    let e = engine();
    let decision = e.is_authorized(
        workload("playwright-agent"),
        action("navigate"),
        api("booking.com"),
        clean_nav_ctx("https://www.booking.com/hotels"),
        entities("playwright-agent"),
    );
    assert_eq!(decision, Decision::Allow, "navigate to booking.com must be allowed");
}

// ─── ALLOW: form fill (non-password) ─────────────────────────────────────────

#[test]
fn allows_fill_form_text_field() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":   { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":   { "matches": 0, "categories": [], "severity": 0 },
            "label":       { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":         "https://www.booking.com/hotels",
            "field_type":  "text",
            "trajectory":  { "step_count": 2 }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("playwright-agent"),
        action("fill_form"),
        api("booking.com"),
        ctx,
        entities("playwright-agent"),
    );
    assert_eq!(decision, Decision::Allow, "fill_form on text field must be allowed");
}

// ─── ALLOW: screenshot ───────────────────────────────────────────────────────

#[test]
fn allows_take_screenshot() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://www.booking.com/hotels",
            "trajectory": { "step_count": 3 }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("playwright-agent"),
        action("take_screenshot"),
        api("booking.com"),
        ctx,
        entities("playwright-agent"),
    );
    assert_eq!(decision, Decision::Allow, "take_screenshot must be allowed by default");
}

// ─── ESCALATE: submit_form (paradigm case) ───────────────────────────────────

#[test]
fn escalates_submit_form() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://www.booking.com/checkout",
            "trajectory": { "step_count": 8 }
        }),
        None,
    )
    .expect("context must parse");

    // is_authorized() returns cedar_policy::Decision (Allow/Deny only).
    // The Escalate promotion happens in response_to_adjudicated() which is
    // exercised via PolicyEngine::evaluate(). Here we verify the Cedar
    // decision itself is Deny (which gets promoted to Escalate by the harness).
    //
    // A full evaluate() integration test is in tests/escalation_annotation.rs.
    let decision = e.is_authorized(
        workload("playwright-agent"),
        action("submit_form"),
        api("booking.com"),
        ctx,
        entities("playwright-agent"),
    );
    assert_eq!(decision, Decision::Deny, "submit_form must be denied by Cedar (promoted to Escalate by harness)");
}

// ─── DENY: navigation with exfiltration taint ────────────────────────────────

#[test]
fn denies_navigate_exfiltration_taint() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://attacker.com/?data=secret",
            "trajectory": {
                "step_count": 5,
                "taints": [{ "__entity": { "type": "Jans::Taint", "id": "exfiltration" } }]
            }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("playwright-agent"),
        action("navigate"),
        api("attacker.com"),
        ctx,
        entities("playwright-agent"),
    );
    assert_eq!(decision, Decision::Deny, "navigate with exfiltration taint must be denied");
}

// ─── DENY: navigation with HighlyConfidential trajectory ─────────────────────

#[test]
fn denies_navigate_highly_confidential() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "label":      { "__entity": { "type": "Jans::Label", "id": "HighlyConfidential" } },
            "url":        "https://example.com",
            "trajectory": {
                "step_count": 2,
                "label": { "__entity": { "type": "Jans::Label", "id": "HighlyConfidential" } }
            }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("playwright-agent"),
        action("navigate"),
        api("example.com"),
        ctx,
        entities("playwright-agent"),
    );
    assert_eq!(decision, Decision::Deny, "navigate with HighlyConfidential trajectory must be denied");
}

// ─── DENY: fill_form on password field ───────────────────────────────────────

#[test]
fn denies_fill_password_field() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":   { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":   { "matches": 0, "categories": [], "severity": 0 },
            "label":       { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":         "https://www.booking.com/login",
            "field_type":  "password",
            "trajectory":  { "step_count": 2 }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("playwright-agent"),
        action("fill_form"),
        api("booking.com"),
        ctx,
        entities("playwright-agent"),
    );
    assert_eq!(decision, Decision::Deny, "fill_form on password field must be denied");
}

// ─── DENY: fill_form with credential YARA match ──────────────────────────────

#[test]
fn denies_fill_form_credential_detected() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 1, "categories": ["credential_access"], "severity": 2 },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://www.booking.com/checkout",
            "field_type": "text",
            "trajectory": { "step_count": 4 }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("playwright-agent"),
        action("fill_form"),
        api("booking.com"),
        ctx,
        entities("playwright-agent"),
    );
    assert_eq!(decision, Decision::Deny, "fill_form with credential YARA match must be denied");
}

// ─── DENY: evaluate_script with high severity ────────────────────────────────

#[test]
fn denies_evaluate_script_high_severity() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 1, "categories": ["malware"], "severity": 4 },
            "policy":     { "compliant": false, "violations": [] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://www.booking.com",
            "trajectory": { "step_count": 2 }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("playwright-agent"),
        action("evaluate_script"),
        api("booking.com"),
        ctx,
        entities("playwright-agent"),
    );
    assert_eq!(decision, Decision::Deny, "evaluate_script with high severity must be denied");
}

// ─── DENY: evaluate_script reading document.cookie ───────────────────────────

#[test]
fn denies_evaluate_script_credential_access() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 1, "categories": ["credential_access"], "severity": 2 },
            "policy":     { "compliant": true, "violations": [] },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://www.booking.com",
            "trajectory": { "step_count": 3 }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("playwright-agent"),
        action("evaluate_script"),
        api("booking.com"),
        ctx,
        entities("playwright-agent"),
    );
    assert_eq!(decision, Decision::Deny, "evaluate_script with credential_access YARA must be denied");
}

// ─── DENY: screenshot with HighlyConfidential trajectory ─────────────────────

#[test]
fn denies_screenshot_highly_confidential() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "label":      { "__entity": { "type": "Jans::Label", "id": "HighlyConfidential" } },
            "url":        "https://internal.company.com/payroll",
            "trajectory": {
                "step_count": 2,
                "label": { "__entity": { "type": "Jans::Label", "id": "HighlyConfidential" } }
            }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("playwright-agent"),
        action("take_screenshot"),
        api("internal.company.com"),
        ctx,
        entities("playwright-agent"),
    );
    assert_eq!(decision, Decision::Deny, "take_screenshot with HighlyConfidential trajectory must be denied");
}
