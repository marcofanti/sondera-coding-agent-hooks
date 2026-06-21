//! Runtime transform tests — verifies that WebFetch.prompt is correctly mapped
//! to the Cedar action name in the full adjudicate() path.
//!
//! These complement scenario_email.rs / scenario_browser.rs which call
//! is_authorized() directly. Here we go through PolicyHarness::adjudicate()
//! to prove the transform.rs mapping fires for each action group.

use sondera_harness::{
    Agent, CedarlingPolicyEngine, CedarlingPolicyHarness, Decision,
    Event, Harness, Observation, Prompt, Think, TrajectoryEvent, WebFetch,
    Actor, ActorType, Causality,
};
use tempfile::TempDir;

const POLICIES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies");

async fn harness() -> (CedarlingPolicyHarness, TempDir) {
    let tmp = TempDir::new().unwrap();
    let engine = CedarlingPolicyEngine::from_policy_dir(POLICIES_DIR).unwrap();
    let h = CedarlingPolicyHarness::from_isolated_storage(engine, tmp.path())
        .await
        .unwrap();
    (h, tmp)
}

fn web_event(agent_id: &str, url: &str, prompt: &str) -> Event {
    let traj = uuid::Uuid::new_v4().to_string();
    Event {
        event_id:      uuid::Uuid::new_v4().to_string(),
        trajectory_id: traj.clone(),
        timestamp:     chrono::Utc::now(),
        agent: Agent { id: agent_id.to_string(), provider_id: "test".to_string() },
        actor: Actor { id: agent_id.to_string(), actor_type: ActorType::Agent },
        causality: Causality { correlation_id: traj, causation_id: None, parent_id: None },
        event: TrajectoryEvent::Action(sondera_harness::Action::WebFetch(
            WebFetch::new(url, prompt),
        )),
        raw: None,
    }
}

// ─── Browser actions ──────────────────────────────────────────────────────────

#[tokio::test]
async fn transform_navigate_allows() {
    let (h, _tmp) = harness().await;
    let ev = web_event("agent", "https://booking.com/hotels", "navigate");
    let adj = h.adjudicate(ev).await.unwrap();
    assert_eq!(adj.decision, Decision::Allow, "navigate to known domain must Allow");
}

#[tokio::test]
async fn transform_submit_form_escalates() {
    let (h, _tmp) = harness().await;
    let ev = web_event("agent", "https://booking.com/checkout", "submit_form");
    let adj = h.adjudicate(ev).await.unwrap();
    assert_eq!(adj.decision, Decision::Escalate, "submit_form must Escalate via transform path");
}

// ─── Email / calendar actions ─────────────────────────────────────────────────

#[tokio::test]
async fn transform_read_email_allows() {
    let (h, _tmp) = harness().await;
    let ev = web_event("agent", "https://mail.google.com", "read_email");
    let adj = h.adjudicate(ev).await.unwrap();
    assert_eq!(adj.decision, Decision::Allow, "read_email must Allow via transform path");
}

#[tokio::test]
async fn transform_send_email_escalates() {
    let (h, _tmp) = harness().await;
    let ev = web_event("agent", "https://mail.google.com", "send_email");
    let adj = h.adjudicate(ev).await.unwrap();
    assert_eq!(adj.decision, Decision::Escalate, "send_email must Escalate via transform path");
}

#[tokio::test]
async fn transform_delete_event_escalates() {
    let (h, _tmp) = harness().await;
    let ev = web_event("agent", "https://calendar.google.com", "delete_event");
    let adj = h.adjudicate(ev).await.unwrap();
    assert_eq!(adj.decision, Decision::Escalate, "delete_event must Escalate via transform path");
}

#[tokio::test]
async fn transform_list_emails_allows() {
    let (h, _tmp) = harness().await;
    let ev = web_event("agent", "https://mail.google.com", "list_emails");
    let adj = h.adjudicate(ev).await.unwrap();
    assert_eq!(adj.decision, Decision::Allow, "list_emails must Allow via transform path");
}

#[tokio::test]
async fn transform_unknown_prompt_falls_back_to_call_api() {
    let (h, _tmp) = harness().await;
    // Unknown prompt → "call_api" → should Allow (base.cedar default permit)
    let ev = web_event("agent", "https://api.github.com/repos/foo", "some_custom_op");
    let adj = h.adjudicate(ev).await.unwrap();
    assert_eq!(adj.decision, Decision::Allow, "unknown prompt falls back to call_api and should Allow");
}

// ─── Observation variants (previously would bail) ─────────────────────────────

fn obs_event(agent_id: &str, obs: Observation) -> Event {
    let traj = uuid::Uuid::new_v4().to_string();
    Event {
        event_id:      uuid::Uuid::new_v4().to_string(),
        trajectory_id: traj.clone(),
        timestamp:     chrono::Utc::now(),
        agent: Agent { id: agent_id.to_string(), provider_id: "test".to_string() },
        actor: Actor { id: agent_id.to_string(), actor_type: ActorType::Agent },
        causality: Causality { correlation_id: traj, causation_id: None, parent_id: None },
        event: TrajectoryEvent::Observation(obs),
        raw: None,
    }
}

#[tokio::test]
async fn transform_prompt_observation_does_not_bail() {
    let (h, _tmp) = harness().await;
    let ev = obs_event("agent", Observation::Prompt(Prompt::user("what files are in /tmp?")));
    // Should not error — base.cedar permits by default.
    let result = h.adjudicate(ev).await;
    assert!(result.is_ok(), "Prompt observation must not bail: {:?}", result.err());
    assert_eq!(result.unwrap().decision, Decision::Allow);
}

#[tokio::test]
async fn transform_think_observation_does_not_bail() {
    let (h, _tmp) = harness().await;
    let ev = obs_event("agent", Observation::Think(Think::new("I should list the files first")));
    let result = h.adjudicate(ev).await;
    assert!(result.is_ok(), "Think observation must not bail: {:?}", result.err());
    assert_eq!(result.unwrap().decision, Decision::Allow);
}
