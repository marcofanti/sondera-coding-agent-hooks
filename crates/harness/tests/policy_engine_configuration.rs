//! Integration tests for configurable harness policy engines.

use sondera_harness::{
    Action, Agent, AllowAllPolicyEngine, Decision, Event, Harness, PolicyHarness, ToolCall,
    TrajectoryEvent,
};

fn test_agent() -> Agent {
    Agent {
        id: "test-agent".to_string(),
        provider_id: "test-provider".to_string(),
    }
}

#[tokio::test]
async fn allow_all_policy_engine_allows_non_control_events() {
    let temp_dir = tempfile::tempdir().expect("should create temp dir for storage");
    let harness = PolicyHarness::from_isolated_storage(AllowAllPolicyEngine, temp_dir.path())
        .await
        .expect("should build allow-all harness");

    let event = Event::new(
        test_agent(),
        format!("test-allow-all-{}", uuid::Uuid::new_v4()),
        TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
            "test_tool",
            serde_json::json!({"arg": "value"}),
        ))),
    );

    let result = harness.adjudicate(event).await.unwrap();
    assert_eq!(result.decision, Decision::Allow);
}
