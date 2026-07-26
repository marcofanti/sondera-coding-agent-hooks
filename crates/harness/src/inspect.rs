//! InspectPolicyEngine — a passthrough policy engine for audit and review modes.
//!
//! Wraps `CedarlingPolicyEngine` to run Cedar evaluation and emit full
//! observability data (OTel + agentmemory), then overrides the final
//! decision based on `InspectMode`:
//!
//! - `Allow`  — always allows (shadow/audit mode; log and pass through)
//! - `Prompt` — always escalates (review mode; every action awaits operator approval)
//!
//! The original Cedar decision is preserved in `eval.raw["would_be_decision"]`
//! so OTel consumers can see what Cedar *would* have done.

use crate::cedarling::extract_scannable;
use crate::cedarling::CedarlingPolicyEngine;
use crate::policy_engine::{PolicyEngine, PolicyEvaluation};
use crate::storage::entity::EntityStore;
use crate::types::{Adjudicated, Decision, Event};
use anyhow::Result;
use tracing::{info_span, warn, Instrument};

/// How the inspect engine overrides Cedar's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectMode {
    /// Always allow — log what Cedar would have decided, then pass through.
    Allow,
    /// Always escalate — log what Cedar would have decided, then require operator approval.
    Prompt,
}

/// Configuration for the optional agentmemory HTTP integration.
#[derive(Debug, Clone)]
pub struct AgentMemoryConfig {
    /// Base URL of the agentmemory REST API, e.g. `http://localhost:3111`.
    pub url: String,
    /// Optional Bearer token for `Authorization: Bearer <secret>`.
    pub secret: Option<String>,
}

/// Policy engine that runs Cedar evaluation, emits inspection telemetry, and
/// overrides the final decision based on `InspectMode`.
pub struct InspectPolicyEngine {
    inner: CedarlingPolicyEngine,
    mode: InspectMode,
    agentmemory: Option<AgentMemoryConfig>,
}

impl InspectPolicyEngine {
    /// Create a new inspect engine.
    ///
    /// - `inner` — the Cedar engine that performs the real policy evaluation.
    /// - `mode` — whether to always Allow or always Escalate.
    /// - `agentmemory` — optional agentmemory integration; `None` disables the HTTP POST.
    pub fn new(
        inner: CedarlingPolicyEngine,
        mode: InspectMode,
        agentmemory: Option<AgentMemoryConfig>,
    ) -> Self {
        Self {
            inner,
            mode,
            agentmemory,
        }
    }
}

impl PolicyEngine for InspectPolicyEngine {
    fn name(&self) -> &'static str {
        "inspect"
    }

    async fn evaluate(
        &self,
        event: &Event,
        entity_store: &EntityStore,
    ) -> Result<PolicyEvaluation> {
        // Run the inner Cedar engine to get the real policy decision.
        let inner_eval = self.inner.evaluate(event, entity_store).await?;
        let would_be = inner_eval.adjudicated.decision;
        let would_be_str = decision_str(&would_be);

        // Collect matched policy IDs and guardrail metadata from the inner result.
        let matched_policy_ids: Vec<&str> = inner_eval
            .adjudicated
            .annotations
            .iter()
            .filter_map(|a| a.policy_id.as_deref())
            .collect();
        let policy_ids_csv = matched_policy_ids.join(",");

        let (guardrail_cats, guardrail_label) = extract_guardrail_meta(&inner_eval.raw);
        let event_content = extract_scannable(event).unwrap_or_default();

        // Emit an inspect span visible to OTel exporters.
        {
            let span = info_span!(
                "harness.inspect",
                inspect.mode = mode_str(self.mode),
                inspect.would_be_decision = would_be_str,
                inspect.matched_policy_ids = %policy_ids_csv,
                inspect.guardrail_categories = %guardrail_cats,
                inspect.guardrail_label = %guardrail_label,
                inspect.event_content = %event_content,
            );
            // Enter and immediately exit — we only need the span attributes recorded.
            let _guard = span.enter();
        }

        // Override the decision based on InspectMode.
        let overridden_decision = match self.mode {
            InspectMode::Allow => Decision::Allow,
            InspectMode::Prompt => Decision::Escalate,
        };

        let adjudicated = Adjudicated {
            decision: overridden_decision,
            // Preserve the original reason text and annotations for caller visibility.
            reason: inner_eval.adjudicated.reason.clone(),
            annotations: inner_eval.adjudicated.annotations.clone(),
            escalation_id: None,
        };

        // Augment the raw JSON with inspect-mode metadata.
        let raw = serde_json::json!({
            "engine": self.name(),
            "event_id": event.event_id,
            "inspect_mode": mode_str(self.mode),
            "decision": decision_str(&overridden_decision),
            "would_be_decision": would_be_str,
            "matched_policy_ids": matched_policy_ids,
            "guardrail_categories": guardrail_cats,
            "guardrail_label": guardrail_label,
            "event_content": event_content,
        });

        // Fire-and-forget POST to agentmemory (if configured).
        if let Some(ref cfg) = self.agentmemory {
            post_to_agentmemory(cfg.clone(), event, &event_content, would_be_str, &policy_ids_csv, mode_str(self.mode));
        }

        Ok(PolicyEvaluation::new(adjudicated, raw))
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn decision_str(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "Allow",
        Decision::Deny => "Deny",
        Decision::Escalate => "Escalate",
    }
}

fn mode_str(m: InspectMode) -> &'static str {
    match m {
        InspectMode::Allow => "allow",
        InspectMode::Prompt => "prompt",
    }
}

/// Pull guardrail metadata out of the CedarlingPolicyEngine's raw JSON.
fn extract_guardrail_meta(raw: &serde_json::Value) -> (String, String) {
    let cats = raw
        .pointer("/signature/categories")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();

    let label = raw
        .pointer("/guardrail_label")
        .and_then(|v| v.as_str())
        .or_else(|| {
            raw.pointer("/label/__entity/id")
                .and_then(|v| v.as_str())
        })
        .unwrap_or("Public")
        .to_string();

    (cats, label)
}

/// Map a `TrajectoryEvent` category to an agentmemory `hookType` string.
fn hook_type_for_event(event: &Event) -> &'static str {
    use crate::types::{Control, TrajectoryEvent};
    match &event.event {
        TrajectoryEvent::Action(_) => "pre_tool_use",
        TrajectoryEvent::Observation(_) => "post_tool_use",
        TrajectoryEvent::Control(Control::Started(_)) => "session_start",
        TrajectoryEvent::Control(Control::Completed(_))
        | TrajectoryEvent::Control(Control::Failed(_))
        | TrajectoryEvent::Control(Control::Terminated(_)) => "stop",
        TrajectoryEvent::Control(_) | TrajectoryEvent::State(_) => "notification",
    }
}

/// Fire-and-forget POST to agentmemory's `/agentmemory/observe` endpoint.
fn post_to_agentmemory(
    cfg: AgentMemoryConfig,
    event: &Event,
    event_content: &str,
    would_be: &'static str,
    policy_ids_csv: &str,
    mode: &'static str,
) {
    let hook_type = hook_type_for_event(event);
    let payload = serde_json::json!({
        "hookType": hook_type,
        "sessionId": event.trajectory_id,
        "project": "",
        "cwd": "",
        "timestamp": event.timestamp.to_rfc3339(),
        "data": {
            "event_type": event_type_name(event),
            "event_content": event_content,
            "would_be_decision": would_be,
            "matched_policies": policy_ids_csv,
            "inspect_mode": mode,
        }
    });

    let url = format!("{}/agentmemory/observe", cfg.url);
    let secret = cfg.secret.clone();
    let span_url = url.clone();

    tokio::spawn(
        async move {
            let client = reqwest::Client::new();
            let mut req = client.post(&url).json(&payload);
            if let Some(s) = secret {
                req = req.bearer_auth(s);
            }
            if let Err(e) = req.send().await {
                warn!("agentmemory POST failed (inspect mode): {e}");
            }
        }
        .instrument(info_span!("inspect.agentmemory_post", url = %span_url)),
    );
}

fn event_type_name(event: &Event) -> &'static str {
    use crate::types::{Action, Control, Observation, TrajectoryEvent};
    match &event.event {
        TrajectoryEvent::Action(Action::ShellCommand(_)) => "ShellCommand",
        TrajectoryEvent::Action(Action::WebFetch(_)) => "WebFetch",
        TrajectoryEvent::Action(Action::FileOperation(_)) => "FileOperation",
        TrajectoryEvent::Action(Action::ToolCall(_)) => "ToolCall",
        TrajectoryEvent::Observation(Observation::Prompt(_)) => "Prompt",
        TrajectoryEvent::Observation(Observation::Think(_)) => "Think",
        TrajectoryEvent::Observation(Observation::ShellCommandOutput(_)) => "ShellCommandOutput",
        TrajectoryEvent::Observation(Observation::FileOperationResult(_)) => "FileOperationResult",
        TrajectoryEvent::Observation(Observation::WebFetchOutput(_)) => "WebFetchOutput",
        TrajectoryEvent::Observation(Observation::ToolOutput(_)) => "ToolOutput",
        TrajectoryEvent::Control(Control::Started(_)) => "Started",
        TrajectoryEvent::Control(Control::Completed(_)) => "Completed",
        TrajectoryEvent::Control(Control::Failed(_)) => "Failed",
        TrajectoryEvent::Control(Control::Adjudicated(_)) => "Adjudicated",
        TrajectoryEvent::Control(Control::Terminated(_)) => "Terminated",
        TrajectoryEvent::Control(Control::Suspended(_)) => "Suspended",
        TrajectoryEvent::Control(Control::Resumed(_)) => "Resumed",
        TrajectoryEvent::State(_) => "State",
    }
}
