pub mod store;
mod transform;

use crate::cedar::entity::{Trajectory, euid as old_euid};
use crate::policy_engine::{PolicyEngine, PolicyEvaluation, SyncAuthorize};
use crate::storage::entity::EntityStore;
use crate::{Adjudicated, Annotation, Decision, Event, TrajectoryEvent, Action, Observation};
use anyhow::{Context as _, Result};
use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityUid, PolicySet, Request,
    Schema,
};
use sondera_information_flow_control::{DataModel, Label};
use sondera_policy::PolicyModel;
use std::path::Path;
use tracing::{debug, warn};

/// Lazily-initialized optional guardrails (YARA-X + LLM IFC + LLM policy).
/// Fields are `None` when the config files are absent from the policy directory.
struct Guardrails {
    ifc: Option<DataModel>,
    policy: Option<PolicyModel>,
}

impl Guardrails {
    fn load(policy_dir: &Path) -> Self {
        let ifc = DataModel::from_toml(policy_dir.join("ifc.toml")).ok();
        let policy = PolicyModel::from_toml(policy_dir.join("policies.toml")).ok();
        if ifc.is_none() {
            warn!("ifc.toml not found or invalid — IFC label classification disabled");
        }
        if policy.is_none() {
            warn!("policies.toml not found or invalid — LLM policy classification disabled");
        }
        Self { ifc, policy }
    }

    /// Build guardrail context JSON for a piece of text content.
    ///
    /// On Ollama unavailability the classifiers fall back to safe defaults
    /// (`Public` label, `compliant: true`) rather than failing the request.
    async fn compute(&self, content: &str) -> serde_json::Value {
        let sig = sondera_signature::scan(content);
        let severity: i64 = sig.severity.into();
        let categories: Vec<serde_json::Value> =
            sig.categories.iter().map(|c| serde_json::json!(c)).collect();
        let matches: i64 = sig.matches.len() as i64;

        let label_str = if let Some(ref dm) = self.ifc {
            match dm.classify(content).await {
                Ok(result) => result.max_label().to_string(),
                Err(e) => {
                    warn!("IFC classify failed: {e}; defaulting to Public");
                    "Public".to_string()
                }
            }
        } else {
            "Public".to_string()
        };

        let (policy_compliant, policy_violations): (bool, Vec<serde_json::Value>) =
            if let Some(ref pm) = self.policy {
                match pm.evaluate_content(content).await {
                    Ok(result) => {
                        let cats: Vec<serde_json::Value> = result
                            .categories()
                            .into_iter()
                            .map(|c| serde_json::json!(c))
                            .collect();
                        (result.compliant, cats)
                    }
                    Err(e) => {
                        warn!("Policy classify failed: {e}; defaulting to compliant");
                        (true, vec![])
                    }
                }
            } else {
                (true, vec![])
            };

        serde_json::json!({
            "signature": {
                "severity": severity,
                "categories": categories,
                "matches": matches,
            },
            "label": {
                "__entity": { "type": "Jans::Label", "id": label_str }
            },
            "policy": {
                "compliant": policy_compliant,
                "violations": policy_violations,
            }
        })
    }
}

pub struct CedarlingPolicyEngine {
    authorizer: Authorizer,
    store: store::CedarlingStore,
    guardrails: Guardrails,
}

impl CedarlingPolicyEngine {
    /// Load a `CedarlingPolicyEngine` from a directory containing `schema.json`
    /// and one or more `*.cedar` policy files.
    ///
    /// If `ifc.toml` and `policies.toml` are present alongside the Cedar files,
    /// the IFC label classifier and the LLM policy classifier are also loaded and
    /// wired into every `evaluate()` call.  Missing config files are silently
    /// tolerated — the corresponding guardrail falls back to a safe default.
    pub fn from_policy_dir(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let store = store::CedarlingStore::load(path)?;
        let guardrails = Guardrails::load(path);
        Ok(Self {
            authorizer: Authorizer::new(),
            store,
            guardrails,
        })
    }

    /// The Cedar schema loaded from `schema.json`.
    pub fn schema(&self) -> &Schema {
        self.store.schema()
    }

    /// The merged Cedar policy set loaded from all `*.cedar` files.
    pub fn policy_set(&self) -> &PolicySet {
        self.store.policy_set()
    }

    /// Perform a Cedar authorization check directly.
    ///
    /// Used by integration tests to verify policy decisions without going through
    /// the full `PolicyEngine::evaluate()` harness path.
    pub fn is_authorized(
        &self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
        entities: Entities,
    ) -> CedarDecision {
        match Request::new(principal, action, resource, context, None) {
            Ok(req) => self
                .authorizer
                .is_authorized(&req, self.store.policy_set(), &entities)
                .decision(),
            Err(_) => CedarDecision::Deny,
        }
    }

    /// Perform a Cedar authorization check and return the full response with
    /// policy annotations (used by the `PolicyEngine::evaluate()` impl).
    fn authorize_full(
        &self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
        entities: Entities,
    ) -> Result<cedar_policy::Response> {
        let req = Request::new(principal, action, resource, context, None)
            .context("Failed to construct Cedar request")?;
        Ok(self
            .authorizer
            .is_authorized(&req, self.store.policy_set(), &entities))
    }

    fn response_to_adjudicated(&self, response: &cedar_policy::Response) -> Adjudicated {
        // Collect annotations from every matched policy (the "reason" set).
        // While iterating, check for @decision("escalate") — if any matched
        // forbid policy carries this annotation, promote Deny → Escalate.
        let mut escalate = false;

        let annotations: Vec<Annotation> = response
            .diagnostics()
            .reason()
            .map(|policy_id| {
                let mut annotation = Annotation::new().with_id(policy_id.to_string());
                if let Some(policy) = self.store.policy_set().policy(policy_id) {
                    for (key, value) in policy.annotations() {
                        match key.to_string().as_str() {
                            "id" => {}
                            "decision" => {
                                if value == "escalate" {
                                    escalate = true;
                                }
                                annotation =
                                    annotation.with("decision".to_string(), value.to_string());
                            }
                            "description" => {
                                annotation = annotation.with_description(value.to_string());
                            }
                            other => {
                                annotation = annotation.with(other.to_string(), value.to_string());
                            }
                        }
                    }
                }
                annotation
            })
            .collect();

        // Escalate only when ALL matched forbid policies carry @decision("escalate").
        // If any matched forbid is a hard-deny (no annotation), Deny wins — this
        // prevents escalation from "softening" a hard rule like deny-send-email-highly-confidential
        // when it co-fires with escalate-send-email-default.
        let hard_deny = response.decision() == CedarDecision::Deny
            && response.diagnostics().reason().any(|policy_id| {
                self.store
                    .policy_set()
                    .policy(policy_id)
                    .and_then(|p| p.annotation("decision"))
                    .map(|v| v != "escalate")
                    .unwrap_or(true) // missing annotation → hard deny
            });

        let decision = match response.decision() {
            CedarDecision::Allow => Decision::Allow,
            CedarDecision::Deny if escalate && !hard_deny => Decision::Escalate,
            CedarDecision::Deny => Decision::Deny,
        };

        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        Adjudicated {
            decision,
            reason: if errors.is_empty() { None } else { Some(errors.join("; ")) },
            annotations,
            escalation_id: None,
        }
    }
}

impl SyncAuthorize for CedarlingPolicyEngine {
    fn authorize(
        &self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
        entities: Entities,
    ) -> CedarDecision {
        self.is_authorized(principal, action, resource, context, entities)
    }
}

impl PolicyEngine for CedarlingPolicyEngine {
    fn name(&self) -> &'static str {
        "cedarling"
    }

    async fn evaluate(
        &self,
        event: &Event,
        entity_store: &EntityStore,
    ) -> Result<PolicyEvaluation> {
        // Extract scannable text from the event to feed the guardrails.
        // Control events have no content to scan; skip guardrail computation.
        let guardrail_ctx = if let Some(text) = extract_scannable(event) {
            // Merge pre-computed guardrail fields from raw (if the hook already ran them)
            // with freshly computed results. Freshly computed wins for signature, label, policy.
            Some(self.guardrails.compute(&text).await)
        } else {
            None
        };

        // Build effective raw: guardrail fills gaps only — event.raw wins for
        // any field already present there (the hook ran closer to the content).
        let effective_raw: Option<serde_json::Value> = match (guardrail_ctx.as_ref(), event.raw.as_ref()) {
            (Some(g), Some(r)) => {
                // Start from guardrail defaults, then overwrite with the hook's values.
                let mut merged = g.clone();
                if let (Some(obj), Some(r_obj)) = (merged.as_object_mut(), r.as_object()) {
                    for (k, v) in r_obj {
                        obj.insert(k.clone(), v.clone());
                    }
                }
                Some(merged)
            }
            (Some(g), None) => Some(g.clone()),
            (None, raw) => raw.cloned(),
        };

        let (principal, action, resource, context, entities) =
            transform::build_request_with_raw(event, entity_store, effective_raw.as_ref())?;

        let response = self.authorize_full(principal, action, resource, context, entities)?;
        let adjudicated = self.response_to_adjudicated(&response);

        // IFC label propagation: if the guardrail classified a label higher than
        // the trajectory's current label, elevate and persist the trajectory entity.
        if let Some(ref gctx) = guardrail_ctx
            && let Some(label_str) = gctx
                .get("label")
                .and_then(|l| l.get("__entity"))
                .and_then(|e| e.get("id"))
                .and_then(|id| id.as_str())
            && let Ok(new_label) = label_str.parse::<Label>()
            && new_label != Label::default()
        {
            propagate_label(new_label, &event.trajectory_id, entity_store);
        }

        let reason_policies: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        let raw = serde_json::json!({
            "engine": self.name(),
            "event_id": event.event_id,
            "decision": format!("{:?}", response.decision()),
            "reason": reason_policies,
            "errors": errors,
        });

        Ok(PolicyEvaluation::new(adjudicated, raw))
    }
}

/// Extract the text content to run through the guardrails for a given event.
/// Returns `None` for Control events (no content to scan).
fn extract_scannable(event: &Event) -> Option<String> {
    match &event.event {
        TrajectoryEvent::Action(Action::ShellCommand(sc)) => Some(sc.command.clone()),
        TrajectoryEvent::Action(Action::WebFetch(wf)) => {
            Some(format!("{} {}", wf.url, wf.prompt))
        }
        TrajectoryEvent::Action(Action::FileOperation(fo)) => {
            let mut s = fo.path.clone();
            if let Some(ref content) = fo.content {
                s.push(' ');
                s.push_str(content);
            }
            Some(s)
        }
        TrajectoryEvent::Action(Action::ToolCall(tc)) => {
            Some(format!("{} {}", tc.tool, tc.arguments))
        }
        TrajectoryEvent::Observation(Observation::Prompt(p)) => Some(p.content.clone()),
        TrajectoryEvent::Observation(Observation::Think(t)) => Some(t.thought.clone()),
        TrajectoryEvent::Observation(Observation::ShellCommandOutput(sco)) => {
            Some(format!("{} {}", sco.stdout, sco.stderr))
        }
        TrajectoryEvent::Observation(Observation::FileOperationResult(fo)) => {
            fo.content.clone()
        }
        TrajectoryEvent::Observation(Observation::WebFetchOutput(wfo)) => Some(wfo.result.clone()),
        TrajectoryEvent::Observation(Observation::ToolOutput(to)) => {
            Some(to.output.to_string())
        }
        TrajectoryEvent::Control(_) | TrajectoryEvent::State(_) => None,
    }
}

/// If `new_label` is more sensitive than the trajectory's current label, update the entity.
fn propagate_label(new_label: Label, trajectory_id: &str, entity_store: &EntityStore) {
    let uid = match old_euid("Trajectory", trajectory_id) {
        Ok(u) => u,
        Err(_) => return,
    };
    let current_label = entity_store
        .get(&uid)
        .ok()
        .flatten()
        .and_then(|e| Trajectory::try_from(e).ok())
        .map(|t| t.label)
        .unwrap_or_default();

    // Label ordering: Public < Internal < Confidential < HighlyConfidential
    if new_label.level() > current_label.level() {
        debug!(
            "IFC label elevated on trajectory {}: {} → {}",
            trajectory_id, current_label, new_label
        );
        let updated = match entity_store.get(&uid).ok().flatten() {
            Some(entity) => {
                let mut traj = Trajectory::try_from(entity).unwrap_or_else(|_| Trajectory::new(trajectory_id));
                traj.label = new_label;
                traj
            }
            None => {
                let mut traj = Trajectory::new(trajectory_id);
                traj.label = new_label;
                traj
            }
        };
        if let Ok(entity) = updated.into_entity()
            && let Err(e) = entity_store.upsert(&entity)
        {
            warn!("Failed to persist IFC label elevation: {e}");
        }
    }
}
