use crate::cedar::entity::{Trajectory, euid as old_euid};
use crate::storage::entity::EntityStore;
use crate::{Action, Event, FileOpType, Observation, TrajectoryEvent};
use anyhow::{Context as _, Result};
use cedar_policy::{Context, Entities, EntityId, EntityTypeName, EntityUid};
use std::str::FromStr;

// ─── Helper constructors ─────────────────────────────────────────────────────

pub fn jans_uid(entity_type: &str, id: &str) -> Result<EntityUid> {
    let type_name = EntityTypeName::from_str(entity_type)
        .with_context(|| format!("Invalid entity type name: {entity_type}"))?;
    Ok(EntityUid::from_type_name_and_id(type_name, EntityId::new(id)))
}

// ─── Trajectory context ───────────────────────────────────────────────────────

struct TrajectoryCtx {
    label_id: String,
    step_count: i64,
    taints: Vec<String>,
}

fn load_trajectory(trajectory_id: &str, entity_store: &EntityStore) -> TrajectoryCtx {
    let traj = old_euid("Trajectory", trajectory_id)
        .ok()
        .and_then(|uid| entity_store.get(&uid).ok().flatten())
        .and_then(|e| Trajectory::try_from(e).ok())
        .unwrap_or_else(|| Trajectory::new(trajectory_id));

    TrajectoryCtx {
        label_id: traj.label.to_string(),
        step_count: traj.step_count,
        taints: traj.taints,
    }
}

fn trajectory_context_value(tctx: &TrajectoryCtx) -> serde_json::Value {
    let taints: Vec<serde_json::Value> = tctx
        .taints
        .iter()
        .map(|t| serde_json::json!({"__entity": {"type": "Jans::Taint", "id": t}}))
        .collect();
    serde_json::json!({
        "label":      { "__entity": { "type": "Jans::Label", "id": tctx.label_id } },
        "step_count": tctx.step_count,
        "taints":     taints
    })
}

// ─── Entity set ──────────────────────────────────────────────────────────────

/// Build the minimal entity set needed for a Jans:: authorization request.
fn build_entities(
    agent_id: &str,
    provider_id: &str,
    tctx: &TrajectoryCtx,
    extra: Vec<serde_json::Value>,
) -> Result<Entities> {
    let taint_entities: Vec<serde_json::Value> = tctx
        .taints
        .iter()
        .map(|t| {
            serde_json::json!({
                "uid": {"type": "Jans::Taint", "id": t},
                "attrs": {}, "parents": []
            })
        })
        .collect();

    let mut all: Vec<serde_json::Value> = vec![
        serde_json::json!({
            "uid": {"type": "Jans::Workload", "id": agent_id},
            "attrs": {"provider_id": provider_id},
            "parents": []
        }),
        serde_json::json!({"uid": {"type": "Jans::Label", "id": "Public"},             "attrs": {}, "parents": []}),
        serde_json::json!({"uid": {"type": "Jans::Label", "id": "Internal"},           "attrs": {}, "parents": []}),
        serde_json::json!({"uid": {"type": "Jans::Label", "id": "Confidential"},       "attrs": {}, "parents": []}),
        serde_json::json!({"uid": {"type": "Jans::Label", "id": "HighlyConfidential"}, "attrs": {}, "parents": []}),
    ];
    all.extend(taint_entities);
    all.extend(extra);

    Entities::from_json_value(serde_json::Value::Array(all), None)
        .context("Failed to build Cedar entities")
}

// ─── Signature / policy / label helpers ──────────────────────────────────────

fn sig_from_raw(raw: Option<&serde_json::Value>) -> serde_json::Value {
    raw.and_then(|r| r.get("signature")).cloned().unwrap_or_else(|| {
        serde_json::json!({"matches": 0, "categories": [], "severity": 0})
    })
}

fn policy_from_raw(raw: Option<&serde_json::Value>) -> serde_json::Value {
    raw.and_then(|r| r.get("policy")).cloned().unwrap_or_else(|| {
        serde_json::json!({"compliant": true, "violations": []})
    })
}

fn label_from_raw(raw: Option<&serde_json::Value>) -> serde_json::Value {
    raw.and_then(|r| r.get("label"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({"__entity": {"type": "Jans::Label", "id": "Public"}}))
}

fn workspace_from_raw(raw: Option<&serde_json::Value>) -> serde_json::Value {
    raw.and_then(|r| r.get("workspace")).cloned().unwrap_or_else(|| {
        serde_json::json!({"cwd": "", "permission_mode": "default", "transcript_path": ""})
    })
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/// Translate an Event into the five components needed for a Cedar is_authorized call.
///
/// `raw_override`, when provided, takes priority over `event.raw` for
/// `signature`, `label`, and `policy` fields.  This allows the caller to inject
/// pre-computed guardrail results (YARA-X, IFC, policy classifier) without
/// mutating the original event.
pub fn build_request_with_raw(
    event: &Event,
    entity_store: &EntityStore,
    raw_override: Option<&serde_json::Value>,
) -> Result<(EntityUid, EntityUid, EntityUid, Context, Entities)> {
    // raw_override wins for guardrail fields; event.raw wins for workspace etc.
    let raw = raw_override.or(event.raw.as_ref());
    let tctx = load_trajectory(&event.trajectory_id, entity_store);

    let principal = jans_uid("Jans::Workload", &event.agent.id)?;
    let sig = sig_from_raw(raw);
    let policy = policy_from_raw(raw);
    let label = label_from_raw(raw);
    let workspace = workspace_from_raw(event.raw.as_ref());
    let trajectory_val = trajectory_context_value(&tctx);

    let (action, resource, context, extra_entities) = match &event.event {
        TrajectoryEvent::Observation(Observation::Prompt(p)) => {
            let action = jans_uid("Jans::Action", "observe_prompt")?;
            let resource = jans_uid("Jans::Message", &event.event_id)?;
            let ctx = Context::from_json_value(
                serde_json::json!({
                    "workspace": workspace, "signature": sig, "policy": policy,
                    "label": label, "trajectory": trajectory_val,
                    "content": p.content, "role": p.role.to_string().to_lowercase()
                }),
                None,
            )
            .context("Failed to build observe_prompt context")?;
            let message_entity = serde_json::json!({
                "uid": {"type": "Jans::Message", "id": event.event_id},
                "attrs": {"content": p.content, "role": p.role.to_string().to_lowercase()},
                "parents": []
            });
            (action, resource, ctx, vec![message_entity])
        }

        TrajectoryEvent::Action(Action::ShellCommand(sc)) => {
            let binary = sc.command.split_whitespace().next().unwrap_or("sh");
            let action = jans_uid("Jans::Action", "exec_command")?;
            let resource = jans_uid("Jans::Shell", binary)?;
            let working_dir = sc.working_dir.as_deref().unwrap_or("");
            let ctx = Context::from_json_value(
                serde_json::json!({
                    "workspace": workspace, "signature": sig, "policy": policy,
                    "label": label, "trajectory": trajectory_val,
                    "command": sc.command, "working_dir": working_dir
                }),
                None,
            )
            .context("Failed to build exec_command context")?;
            let shell_entity = serde_json::json!({
                "uid": {"type": "Jans::Shell", "id": binary},
                "attrs": {}, "parents": []
            });
            (action, resource, ctx, vec![shell_entity])
        }

        TrajectoryEvent::Action(Action::WebFetch(wf)) => {
            let domain = extract_domain(&wf.url);
            // Browser and communication sub-actions use the prompt field as the Cedar action name.
            let cedar_action = match wf.prompt.as_str() {
                "navigate" | "fill_form" | "submit_form" | "evaluate_script"
                | "take_screenshot"
                | "send_email" | "read_email" | "list_emails"
                | "read_calendar" | "create_event" | "update_event" | "delete_event" => {
                    wf.prompt.as_str()
                }
                _ => "call_api",
            };
            let action = jans_uid("Jans::Action", cedar_action)?;
            let resource = jans_uid("Jans::API", &domain)?;
            let ctx = Context::from_json_value(
                serde_json::json!({
                    "workspace": workspace, "signature": sig, "policy": policy,
                    "label": label, "trajectory": trajectory_val,
                    "url": wf.url, "prompt": wf.prompt
                }),
                None,
            )
            .context("Failed to build call_api context")?;
            let api_entity = serde_json::json!({
                "uid": {"type": "Jans::API", "id": domain},
                "attrs": {}, "parents": []
            });
            (action, resource, ctx, vec![api_entity])
        }

        TrajectoryEvent::Action(Action::FileOperation(fo)) => {
            let action_name = match fo.operation {
                FileOpType::Read   => "read_file",
                FileOpType::Write  => "write_file",
                FileOpType::Edit   => "edit_file",
                FileOpType::Delete => "delete_file",
            };
            let action = jans_uid("Jans::Action", action_name)?;
            let resource = jans_uid("Jans::File", &fo.path)?;
            let ctx = Context::from_json_value(
                serde_json::json!({
                    "workspace": workspace, "signature": sig, "policy": policy,
                    "label": label, "trajectory": trajectory_val,
                    "path": fo.path, "operation": fo.operation.to_string()
                }),
                None,
            )
            .context("Failed to build file context")?;
            let file_entity = serde_json::json!({
                "uid": {"type": "Jans::File", "id": fo.path},
                "attrs": {}, "parents": []
            });
            (action, resource, ctx, vec![file_entity])
        }

        TrajectoryEvent::Action(Action::ToolCall(tc)) => {
            let action = jans_uid("Jans::Action", "call_tool")?;
            let resource = jans_uid("Jans::Tool", &tc.tool)?;
            let ctx = Context::from_json_value(
                serde_json::json!({
                    "workspace": workspace, "signature": sig, "policy": policy,
                    "label": label, "trajectory": trajectory_val
                }),
                None,
            )
            .context("Failed to build call_tool context")?;
            let tool_entity = serde_json::json!({
                "uid": {"type": "Jans::Tool", "id": tc.tool},
                "attrs": {}, "parents": []
            });
            (action, resource, ctx, vec![tool_entity])
        }

        TrajectoryEvent::Observation(Observation::ShellCommandOutput(sco)) => {
            let binary = raw
                .and_then(|r| r.get("binary"))
                .and_then(|v| v.as_str())
                .unwrap_or("sh");
            let action = jans_uid("Jans::Action", "observe_exec_output")?;
            let resource = jans_uid("Jans::Shell", binary)?;
            let ctx = Context::from_json_value(
                serde_json::json!({
                    "workspace": workspace, "signature": sig, "policy": policy,
                    "label": label, "trajectory": trajectory_val,
                    "exit_code": sco.exit_code as i64,
                    "stdout": sco.stdout, "stderr": sco.stderr
                }),
                None,
            )
            .context("Failed to build observe_exec_output context")?;
            let shell_entity = serde_json::json!({
                "uid": {"type": "Jans::Shell", "id": binary},
                "attrs": {}, "parents": []
            });
            (action, resource, ctx, vec![shell_entity])
        }

        TrajectoryEvent::Observation(Observation::WebFetchOutput(wfo)) => {
            let domain = extract_domain(&wfo.url);
            let action = jans_uid("Jans::Action", "observe_api_output")?;
            let resource = jans_uid("Jans::API", &domain)?;
            let ctx = Context::from_json_value(
                serde_json::json!({
                    "workspace": workspace, "signature": sig, "policy": policy,
                    "label": label, "trajectory": trajectory_val,
                    "url": wfo.url, "code": wfo.code as i64, "result": wfo.result
                }),
                None,
            )
            .context("Failed to build observe_api_output context")?;
            let api_entity = serde_json::json!({
                "uid": {"type": "Jans::API", "id": domain},
                "attrs": {}, "parents": []
            });
            (action, resource, ctx, vec![api_entity])
        }

        TrajectoryEvent::Observation(Observation::ToolOutput(_to)) => {
            let tool = raw
                .and_then(|r| r.get("tool"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let action = jans_uid("Jans::Action", "observe_tool_output")?;
            let resource = jans_uid("Jans::Tool", tool)?;
            let ctx = Context::from_json_value(
                serde_json::json!({
                    "workspace": workspace, "signature": sig, "policy": policy,
                    "label": label, "trajectory": trajectory_val
                }),
                None,
            )
            .context("Failed to build observe_tool_output context")?;
            let tool_entity = serde_json::json!({
                "uid": {"type": "Jans::Tool", "id": tool},
                "attrs": {}, "parents": []
            });
            (action, resource, ctx, vec![tool_entity])
        }

        TrajectoryEvent::Observation(Observation::FileOperationResult(fo)) => {
            // FileOperationResult has no path field — use the call_id as the resource ID,
            // supplemented by the path from raw metadata when the hook provides it.
            let path = raw
                .and_then(|r| r.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or(&fo.call_id);
            let content = fo.content.as_deref().unwrap_or("");
            let action = jans_uid("Jans::Action", "observe_file_result")?;
            let resource = jans_uid("Jans::File", path)?;
            let ctx = Context::from_json_value(
                serde_json::json!({
                    "workspace": workspace, "signature": sig, "policy": policy,
                    "label": label, "trajectory": trajectory_val,
                    "path": path, "content": content
                }),
                None,
            )
            .context("Failed to build observe_file_result context")?;
            let file_entity = serde_json::json!({
                "uid": {"type": "Jans::File", "id": path},
                "attrs": {}, "parents": []
            });
            (action, resource, ctx, vec![file_entity])
        }

        TrajectoryEvent::Observation(Observation::Think(t)) => {
            let msg_id = &event.event_id;
            let action = jans_uid("Jans::Action", "observe_think")?;
            let resource = jans_uid("Jans::Message", msg_id)?;
            let ctx = Context::from_json_value(
                serde_json::json!({
                    "workspace": workspace, "signature": sig,
                    "label": label, "trajectory": trajectory_val,
                    "thought": t.thought
                }),
                None,
            )
            .context("Failed to build observe_think context")?;
            let msg_entity = serde_json::json!({
                "uid": {"type": "Jans::Message", "id": msg_id},
                "attrs": {}, "parents": []
            });
            (action, resource, ctx, vec![msg_entity])
        }

        other => {
            anyhow::bail!(
                "CedarlingPolicyEngine: unsupported event type: {:?}",
                other
            )
        }
    };

    let entities = build_entities(&event.agent.id, &event.agent.provider_id, &tctx, extra_entities)?;
    Ok((principal, action, resource, context, entities))
}

fn extract_domain(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

/// Convenience wrapper that uses `event.raw` as the only guardrail source.
#[allow(dead_code)]
pub fn build_request(
    event: &Event,
    entity_store: &EntityStore,
) -> Result<(EntityUid, EntityUid, EntityUid, Context, Entities)> {
    build_request_with_raw(event, entity_store, None)
}
