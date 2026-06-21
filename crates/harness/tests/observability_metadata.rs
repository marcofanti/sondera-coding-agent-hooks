use sondera_harness::observability::{
    AdjudicationMetricLabels, EventTelemetry, HTTP_ADJUDICATE_ROUTE,
    HTTP_APPROVE_ESCALATION_ROUTE, HTTP_DENY_ESCALATION_ROUTE, HTTP_GET_ESCALATION_ROUTE,
    HTTP_LIST_ESCALATIONS_ROUTE, HTTP_STREAM_ESCALATIONS_ROUTE,
};
use sondera_harness::{
    Action, Adjudicated, Agent, Annotation, Decision, Event, FileOperation, ShellCommand, ToolCall,
    TrajectoryEvent,
};

fn agent() -> Agent {
    Agent {
        id: "agent-secret-id".to_string(),
        provider_id: "claude".to_string(),
    }
}

#[test]
fn event_telemetry_contains_safe_action_metadata() {
    let event = Event::new(
        agent(),
        "trajectory-1",
        TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new(
            "cat /tmp/secret.txt",
        ))),
    );

    let telemetry = EventTelemetry::from_event(&event);

    assert_eq!(telemetry.category, "Action");
    assert_eq!(telemetry.event_type, "ShellCommand");
    assert_eq!(telemetry.agent_provider, "claude");
    assert!(!format!("{telemetry:?}").contains("cat /tmp/secret.txt"));
}

#[test]
fn event_telemetry_does_not_export_file_content_or_path() {
    let event = Event::new(
        agent(),
        "trajectory-1",
        TrajectoryEvent::Action(Action::FileOperation(FileOperation::write(
            "/tmp/private-plan.md",
            "top secret content",
        ))),
    );

    let telemetry = EventTelemetry::from_event(&event);
    let debug = format!("{telemetry:?}");

    assert_eq!(telemetry.category, "Action");
    assert_eq!(telemetry.event_type, "FileOperation");
    assert!(!debug.contains("/tmp/private-plan.md"));
    assert!(!debug.contains("top secret content"));
}

#[test]
fn event_telemetry_does_not_export_tool_arguments() {
    let event = Event::new(
        agent(),
        "trajectory-1",
        TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
            "send_email",
            serde_json::json!({"body": "do not export me"}),
        ))),
    );

    let telemetry = EventTelemetry::from_event(&event);

    assert_eq!(telemetry.event_type, "ToolCall");
    assert!(!format!("{telemetry:?}").contains("do not export me"));
}

#[test]
fn metric_labels_exclude_high_cardinality_identifiers() {
    let event = Event::new(
        agent(),
        "trajectory-1",
        TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
            "send_email",
            serde_json::json!({"body": "do not export me"}),
        ))),
    );
    let labels = AdjudicationMetricLabels::new("cedarling", Decision::Deny, &event);

    assert_eq!(labels.engine, "cedarling");
    assert_eq!(labels.decision, "Deny");
    assert_eq!(labels.agent_provider, "claude");
    assert_eq!(labels.event_category, "Action");
    assert_eq!(labels.event_type, "ToolCall");

    let debug = format!("{labels:?}");
    assert!(!debug.contains(&event.event_id));
    assert!(!debug.contains(&event.trajectory_id));
    assert!(!debug.contains(&event.agent.id));
}

#[test]
fn policy_ids_are_exported_without_descriptions() {
    let adjudicated = Adjudicated::new(Decision::Deny).with_annotation(
        Annotation::new()
            .with_id("deny-secret".to_string())
            .with_description("sensitive rule description".to_string()),
    );

    let ids = EventTelemetry::policy_ids(&adjudicated);

    assert_eq!(ids, vec!["deny-secret"]);
    assert!(!ids.join(",").contains("sensitive rule description"));
}

#[test]
fn http_route_telemetry_uses_stable_route_templates() {
    assert_eq!(HTTP_ADJUDICATE_ROUTE.method, "POST");
    assert_eq!(HTTP_ADJUDICATE_ROUTE.route, "/api/adjudicate");
    assert_eq!(HTTP_LIST_ESCALATIONS_ROUTE.route, "/api/escalations");
    assert_eq!(HTTP_STREAM_ESCALATIONS_ROUTE.route, "/api/escalations/stream");
    assert_eq!(HTTP_GET_ESCALATION_ROUTE.route, "/api/escalations/{id}");
    assert_eq!(
        HTTP_APPROVE_ESCALATION_ROUTE.route,
        "/api/escalations/{id}/approve"
    );
    assert_eq!(
        HTTP_DENY_ESCALATION_ROUTE.route,
        "/api/escalations/{id}/deny"
    );
}

#[test]
fn http_route_telemetry_does_not_include_escalation_ids() {
    for route in [
        HTTP_ADJUDICATE_ROUTE,
        HTTP_LIST_ESCALATIONS_ROUTE,
        HTTP_STREAM_ESCALATIONS_ROUTE,
        HTTP_GET_ESCALATION_ROUTE,
        HTTP_APPROVE_ESCALATION_ROUTE,
        HTTP_DENY_ESCALATION_ROUTE,
    ] {
        let debug = format!("{route:?}");
        assert!(!debug.contains("esc_123456"));
        assert!(!route.route.contains("esc_123456"));
    }
}
