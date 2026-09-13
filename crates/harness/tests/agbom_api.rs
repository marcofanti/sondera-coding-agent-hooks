use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::Value;
use sondera_harness::{
    Action, Agent, Event, ToolCall, TrajectoryEvent,
    escalation::{
        EscalationStore,
        api::{AdminState, router},
    },
    storage::turso::TrajectoryStore,
};
use tower::ServiceExt;

fn test_event(trajectory_id: &str, agent_id: &str, tool: &str) -> Event {
    Event::new(
        Agent {
            id: agent_id.to_string(),
            provider_id: "cursor".to_string(),
        },
        trajectory_id,
        TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
            tool,
            serde_json::json!({"secret": "do-not-emit"}),
        ))),
    )
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn aggregate_agbom_endpoint_returns_components_from_trajectory_store() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("trajectories.db");
    let store = TrajectoryStore::open(&db_path).await.unwrap();
    store
        .insert_event(&test_event("traj-a", "agent-a", "read_file"))
        .await
        .unwrap();

    let state = AdminState::new(EscalationStore::open_in_memory().await.unwrap(), None, 9090)
        .with_trajectory_db_path(db_path);
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri("/api/agbom?agent_id=agent-a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["bomFormat"], "CycloneDX");
    assert!(
        json["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|component| component["bom-ref"] == "tool:read_file")
    );
    assert!(!json.to_string().contains("do-not-emit"));
}

#[tokio::test]
async fn trajectory_agbom_endpoint_limits_inventory_to_requested_trajectory() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("trajectories.db");
    let store = TrajectoryStore::open(&db_path).await.unwrap();
    store
        .insert_event(&test_event("traj-a", "agent-a", "read_file"))
        .await
        .unwrap();
    store
        .insert_event(&test_event("traj-b", "agent-b", "send_email"))
        .await
        .unwrap();

    let state = AdminState::new(EscalationStore::open_in_memory().await.unwrap(), None, 9090)
        .with_trajectory_db_path(db_path);
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri("/api/trajectories/traj-a/agbom")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await.to_string();
    assert!(body.contains("tool:read_file"));
    assert!(!body.contains("tool:send_email"));
}
