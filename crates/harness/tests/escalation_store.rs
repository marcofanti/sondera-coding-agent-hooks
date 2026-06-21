//! Integration tests for EscalationStore.
//!
//! These tests verify create / get / approve / deny / expire_stale
//! using an in-memory Turso database so they run without touching disk.

use sondera_harness::{
    Agent, Actor, ActorType, Causality, Control, Event, Started, TrajectoryEvent,
    escalation::{EscalationStatus, EscalationStore},
};

fn dummy_event(id: &str) -> Event {
    Event {
        event_id:      id.to_string(),
        trajectory_id: "traj-1".to_string(),
        timestamp:     chrono::Utc::now(),
        agent: Agent {
            id:          "agent-1".to_string(),
            provider_id: "cursor".to_string(),
        },
        actor: Actor {
            id:         "agent-1".to_string(),
            actor_type: ActorType::Agent,
        },
        causality: Causality {
            correlation_id: id.to_string(),
            causation_id:   None,
            parent_id:      None,
        },
        event: TrajectoryEvent::Control(Control::Started(Started {
            agent_id: "agent-1".to_string(),
            task:     None,
        })),
        raw:   None,
    }
}

async fn store() -> EscalationStore {
    EscalationStore::open_in_memory().await.expect("in-memory store")
}

// ─── create ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_returns_id() {
    let s = store().await;
    let ev = dummy_event("evt-1");
    let id = s.create(&ev, &["escalate-send-email-default".to_string()], 120)
        .await
        .expect("create must succeed");
    assert!(!id.is_empty(), "id must be non-empty");
}

#[tokio::test]
async fn created_record_is_pending() {
    let s = store().await;
    let ev = dummy_event("evt-2");
    let id = s.create(&ev, &[], 120).await.expect("create");
    let record = s.get(&id).await.expect("get").expect("record must exist");
    assert_eq!(record.status, EscalationStatus::Pending);
    assert_eq!(record.trajectory_id, "traj-1");
    assert_eq!(record.agent_id, "agent-1");
}

// ─── get ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_unknown_id_returns_none() {
    let s = store().await;
    let result = s.get("does-not-exist").await.expect("get must not error");
    assert!(result.is_none());
}

// ─── list ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_all_returns_all_records() {
    let s = store().await;
    s.create(&dummy_event("e1"), &[], 120).await.expect("create");
    s.create(&dummy_event("e2"), &[], 120).await.expect("create");
    let all = s.list(None).await.expect("list");
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn list_pending_filters_correctly() {
    let s = store().await;
    let id1 = s.create(&dummy_event("e3"), &[], 120).await.expect("c1");
    let _id2 = s.create(&dummy_event("e4"), &[], 120).await.expect("c2");
    s.approve(&id1, "operator").await.expect("approve");

    let pending = s.list(Some(EscalationStatus::Pending)).await.expect("list pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, EscalationStatus::Pending);
}

// ─── approve ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn approve_transitions_to_approved() {
    let s = store().await;
    let id = s.create(&dummy_event("e5"), &[], 120).await.expect("create");
    let changed = s.approve(&id, "marco").await.expect("approve");
    assert!(changed, "approve must return true");

    let record = s.get(&id).await.expect("get").expect("exists");
    assert_eq!(record.status, EscalationStatus::Approved);
    assert_eq!(record.decided_by.as_deref(), Some("marco"));
    assert!(record.decided_at.is_some());
}

#[tokio::test]
async fn approve_already_approved_returns_false() {
    let s = store().await;
    let id = s.create(&dummy_event("e6"), &[], 120).await.expect("create");
    s.approve(&id, "op").await.expect("first approve");
    let second = s.approve(&id, "op").await.expect("second approve");
    assert!(!second, "double-approve must return false");
}

// ─── deny ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn deny_transitions_to_denied() {
    let s = store().await;
    let id = s.create(&dummy_event("e7"), &[], 120).await.expect("create");
    let changed = s.deny(&id, "security-team").await.expect("deny");
    assert!(changed);

    let record = s.get(&id).await.expect("get").expect("exists");
    assert_eq!(record.status, EscalationStatus::Denied);
}

// ─── expire_stale ────────────────────────────────────────────────────────────

#[tokio::test]
async fn expire_stale_marks_timed_out() {
    let s = store().await;
    // TTL = -1 so it expires immediately.
    let id = s.create(&dummy_event("e8"), &[], -1).await.expect("create");
    let expired = s.expire_stale().await.expect("expire");
    assert!(expired >= 1, "at least one record must be expired");

    let record = s.get(&id).await.expect("get").expect("exists");
    assert_eq!(record.status, EscalationStatus::TimedOut);
}

#[tokio::test]
async fn expire_stale_leaves_future_records_untouched() {
    let s = store().await;
    let id = s.create(&dummy_event("e9"), &[], 9999).await.expect("create");
    let expired = s.expire_stale().await.expect("expire");
    assert_eq!(expired, 0);

    let record = s.get(&id).await.expect("get").expect("exists");
    assert_eq!(record.status, EscalationStatus::Pending);
}
