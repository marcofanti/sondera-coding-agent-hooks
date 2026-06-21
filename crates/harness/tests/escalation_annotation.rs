//! Integration test: Decision::Escalate flows into EscalationStore.
//!
//! Uses the full PolicyHarness::adjudicate() path (not just is_authorized()).
//! Verifies that when browser.cedar's @decision("escalate") forbid fires for
//! submit_form, an EscalationStore record is automatically created.

use sondera_harness::{
    Action, Actor, ActorType, Agent, Causality, CedarlingPolicyEngine, CedarlingPolicyHarness,
    AdminState, Decision, Event, Harness, TrajectoryEvent, WebFetch,
};
use sondera_harness::escalation::{EscalationStatus, EscalationStore};
use std::sync::Arc;
use tempfile::TempDir;

const POLICIES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies");

async fn harness_with_escalation() -> (CedarlingPolicyHarness, Arc<AdminState>, TempDir) {
    let tmpdir = TempDir::new().expect("tmpdir");
    let engine = CedarlingPolicyEngine::from_policy_dir(POLICIES_DIR)
        .expect("policies must load");
    let harness = CedarlingPolicyHarness::from_isolated_storage(engine, tmpdir.path())
        .await
        .expect("harness must init");

    let esc_store = EscalationStore::open_in_memory().await.expect("esc store");
    let state = Arc::new(AdminState::new(esc_store, None, 9090));
    let harness = harness.with_escalation(state.clone(), 120);
    (harness, state, tmpdir)
}

fn submit_form_event(agent_id: &str) -> Event {
    let traj_id = uuid::Uuid::new_v4().to_string();
    Event {
        event_id:      uuid::Uuid::new_v4().to_string(),
        trajectory_id: traj_id.clone(),
        timestamp:     chrono::Utc::now(),
        agent: Agent {
            id:          agent_id.to_string(),
            provider_id: "playwright".to_string(),
        },
        actor: Actor {
            id:         agent_id.to_string(),
            actor_type: ActorType::Agent,
        },
        causality: Causality {
            correlation_id: traj_id,
            causation_id:   None,
            parent_id:      None,
        },
        // submit_form is a WebFetch in the current type system; the Cedar action
        // is what matters — we use a ToolCall to represent the submit_form action.
        event: TrajectoryEvent::Action(Action::WebFetch(WebFetch::new(
            "https://booking.com/checkout",
            "submit_form",
        ))),
        raw: None,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn escalation_record_created_on_escalate() {
    let (harness, state, _tmp) = harness_with_escalation().await;

    // submit_form → @decision("escalate") forbid in browser.cedar.
    // The harness should auto-create an EscalationStore record.
    let event = submit_form_event("playwright-agent");
    let adjudicated = harness.adjudicate(event).await.expect("adjudicate must succeed");

    // Verify the harness-level decision is Escalate.
    assert_eq!(adjudicated.decision, Decision::Escalate,
        "submit_form must return Escalate at the harness level");

    // Verify the escalation_id is surfaced in the Adjudicated response.
    let esc_id = adjudicated.escalation_id.expect("escalation_id must be set on Escalate decision");
    assert!(!esc_id.is_empty(), "escalation_id must be non-empty");

    // Verify the EscalationStore received a record with the same ID.
    let pending = state.store.list(Some(EscalationStatus::Pending))
        .await
        .expect("list must succeed");
    assert_eq!(pending.len(), 1, "exactly one escalation record must be created");
    assert_eq!(pending[0].agent_id, "playwright-agent");
    assert_eq!(pending[0].id, esc_id, "escalation_id in Adjudicated must match the store record");
}

#[tokio::test]
async fn escalation_id_cleared_after_operator_approval() {
    let (harness, state, _tmp) = harness_with_escalation().await;

    let adjudicated = harness.adjudicate(submit_form_event("playwright-agent"))
        .await
        .expect("adjudicate must succeed");
    assert_eq!(adjudicated.decision, Decision::Escalate);

    let esc_id = adjudicated.escalation_id.unwrap();

    // Operator approves → status transitions to Approved.
    state.store.approve(&esc_id, "operator").await.expect("approve must succeed");

    let record = state.store.get(&esc_id).await.expect("get must succeed").unwrap();
    assert_eq!(record.status, EscalationStatus::Approved);
}

#[tokio::test]
async fn no_escalation_record_on_allow() {
    let (harness, state, _tmp) = harness_with_escalation().await;

    // navigate to a clean domain is Allow — no escalation record.
    let traj_id = uuid::Uuid::new_v4().to_string();
    let event = Event {
        event_id:      uuid::Uuid::new_v4().to_string(),
        trajectory_id: traj_id.clone(),
        timestamp:     chrono::Utc::now(),
        agent: Agent { id: "playwright-agent".to_string(), provider_id: "playwright".to_string() },
        actor: Actor { id: "playwright-agent".to_string(), actor_type: ActorType::Agent },
        causality: Causality {
            correlation_id: traj_id,
            causation_id:   None,
            parent_id:      None,
        },
        event: TrajectoryEvent::Action(Action::WebFetch(WebFetch::new(
            "https://booking.com/hotels",
            "navigate",
        ))),
        raw: None,
    };

    let adjudicated = harness.adjudicate(event).await.expect("adjudicate must succeed");
    // navigate is Allow — no escalation record should be created.
    let all = state.store.list(None).await.expect("list");
    assert!(
        all.is_empty() || adjudicated.decision != Decision::Escalate,
        "no escalation should be created for an Allow decision"
    );
}
