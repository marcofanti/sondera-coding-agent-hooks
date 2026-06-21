//! Scenario tests — LangChain / LangGraph email + calendar agent.
//!
//! Tests the Cedar policies in policies/communication.cedar using the
//! CedarlingPolicyEngine. Each test corresponds to a case in
//! design/multi-agent-scenarios.md § Scenario 1.

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
        { "uid": {"type": "Jans::Workload", "id": agent_id}, "attrs": {"provider_id": "langchain"}, "parents": [] },
        { "uid": {"type": "Jans::Label", "id": "Public"}, "attrs": {}, "parents": [] },
        { "uid": {"type": "Jans::Label", "id": "HighlyConfidential"}, "attrs": {}, "parents": [] }
    ]);
    Entities::from_json_value(json, None).expect("entities must parse")
}

fn clean_email_ctx() -> Context {
    Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://mail.google.com/gmail/v1",
            "trajectory": { "step_count": 3 }
        }),
        None,
    )
    .expect("context must parse")
}

// ─── ALLOW: read-only operations ─────────────────────────────────────────────

#[test]
fn allows_read_email() {
    let e = engine();
    let decision = e.is_authorized(
        workload("langchain-agent"),
        action("read_email"),
        api("mail.google.com"),
        clean_email_ctx(),
        entities("langchain-agent"),
    );
    assert_eq!(decision, Decision::Allow, "read_email must be allowed by default");
}

#[test]
fn allows_list_emails() {
    let e = engine();
    let decision = e.is_authorized(
        workload("langchain-agent"),
        action("list_emails"),
        api("mail.google.com"),
        clean_email_ctx(),
        entities("langchain-agent"),
    );
    assert_eq!(decision, Decision::Allow, "list_emails must be allowed by default");
}

#[test]
fn allows_read_calendar() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://calendar.google.com/calendar/v3",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("langchain-agent"),
        action("read_calendar"),
        api("calendar.google.com"),
        ctx,
        entities("langchain-agent"),
    );
    assert_eq!(decision, Decision::Allow, "read_calendar must be allowed by default");
}

// ─── ESCALATE: send_email by default ─────────────────────────────────────────
//
// `is_authorized()` returns Cedar-native Deny (the @decision("escalate") forbid fires).
// `evaluate()` promotes this to Decision::Escalate via response_to_adjudicated().
// The harness then posts to the escalation channel for operator approval.

#[test]
fn escalates_send_email_by_default() {
    let e = engine();
    let decision = e.is_authorized(
        workload("langchain-agent"),
        action("send_email"),
        api("mail.google.com"),
        clean_email_ctx(),
        entities("langchain-agent"),
    );
    // Cedar-native level: Deny. Harness level (evaluate()): Escalate.
    assert_eq!(decision, Decision::Deny, "send_email must be Cedar-Deny (→ Escalate) by default");
}

// ─── DENY: IFC — send_email with HighlyConfidential trajectory ───────────────

#[test]
fn denies_send_email_highly_confidential_trajectory() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "label":      { "__entity": { "type": "Jans::Label", "id": "HighlyConfidential" } },
            "url":        "https://mail.google.com/gmail/v1",
            "trajectory": {
                "step_count": 5,
                "label": { "__entity": { "type": "Jans::Label", "id": "HighlyConfidential" } }
            }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("langchain-agent"),
        action("send_email"),
        api("mail.google.com"),
        ctx,
        entities("langchain-agent"),
    );
    assert_eq!(decision, Decision::Deny, "send_email must be denied when trajectory is HighlyConfidential");
}

// ─── DENY: send_email with exfiltration taint ────────────────────────────────

#[test]
fn denies_send_email_exfiltration_taint() {
    let e = engine();
    let entities_with_taint = {
        let json = serde_json::json!([
            { "uid": {"type": "Jans::Workload", "id": "langchain-agent"}, "attrs": {"provider_id": "langchain"}, "parents": [] },
            { "uid": {"type": "Jans::Label", "id": "Public"}, "attrs": {}, "parents": [] },
            { "uid": {"type": "Jans::Taint", "id": "exfiltration"}, "attrs": {}, "parents": [] }
        ]);
        Entities::from_json_value(json, None).expect("entities must parse")
    };
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 0, "categories": [], "severity": 0 },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://mail.google.com/gmail/v1",
            "trajectory": {
                "step_count": 5,
                "taints": [{ "__entity": { "type": "Jans::Taint", "id": "exfiltration" } }]
            }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("langchain-agent"),
        action("send_email"),
        api("mail.google.com"),
        ctx,
        entities_with_taint,
    );
    assert_eq!(decision, Decision::Deny, "send_email must be denied when trajectory has exfiltration taint");
}

// ─── DENY: send_email with credential YARA match ─────────────────────────────

#[test]
fn denies_send_email_credential_in_body() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "signature":  { "matches": 1, "categories": ["credential_access"], "severity": 3 },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://mail.google.com/gmail/v1",
            "trajectory": { "step_count": 2 }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("langchain-agent"),
        action("send_email"),
        api("mail.google.com"),
        ctx,
        entities("langchain-agent"),
    );
    assert_eq!(decision, Decision::Deny, "send_email must be denied when YARA detects credential material");
}

// ─── ESCALATE: delete_event by default ───────────────────────────────────────

#[test]
fn escalates_delete_event_by_default() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "label":      { "__entity": { "type": "Jans::Label", "id": "Public" } },
            "url":        "https://calendar.google.com/calendar/v3",
            "trajectory": { "step_count": 1 }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("langchain-agent"),
        action("delete_event"),
        api("calendar.google.com"),
        ctx,
        entities("langchain-agent"),
    );
    // Cedar-native: Deny. Harness level (evaluate()): Escalate.
    assert_eq!(decision, Decision::Deny, "delete_event must be Cedar-Deny (→ Escalate) by default");
}

// ─── DENY: delete_event with HighlyConfidential trajectory ───────────────────

#[test]
fn denies_delete_event_highly_confidential() {
    let e = engine();
    let ctx = Context::from_json_value(
        serde_json::json!({
            "workspace":  { "cwd": "/workspace", "permission_mode": "default", "transcript_path": "" },
            "label":      { "__entity": { "type": "Jans::Label", "id": "HighlyConfidential" } },
            "url":        "https://calendar.google.com/calendar/v3",
            "trajectory": {
                "step_count": 3,
                "label": { "__entity": { "type": "Jans::Label", "id": "HighlyConfidential" } }
            }
        }),
        None,
    )
    .expect("context must parse");
    let decision = e.is_authorized(
        workload("langchain-agent"),
        action("delete_event"),
        api("calendar.google.com"),
        ctx,
        entities("langchain-agent"),
    );
    assert_eq!(decision, Decision::Deny, "delete_event must be denied when trajectory is HighlyConfidential");
}
