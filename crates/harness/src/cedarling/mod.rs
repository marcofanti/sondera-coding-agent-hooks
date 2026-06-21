pub mod store;
mod transform;

use crate::policy_engine::{PolicyEngine, PolicyEvaluation, SyncAuthorize};
use crate::storage::entity::EntityStore;
use crate::{Adjudicated, Annotation, Decision, Event};
use anyhow::{Context as _, Result};
use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityUid, PolicySet, Request,
    Schema,
};
use std::path::Path;

pub struct CedarlingPolicyEngine {
    authorizer: Authorizer,
    store: store::CedarlingStore,
}

impl CedarlingPolicyEngine {
    /// Load a `CedarlingPolicyEngine` from a directory containing `schema.json`
    /// and one or more `*.cedar` policy files.
    pub fn from_policy_dir(path: impl AsRef<Path>) -> Result<Self> {
        let store = store::CedarlingStore::load(path)?;
        Ok(Self {
            authorizer: Authorizer::new(),
            store,
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
        let decision = match response.decision() {
            CedarDecision::Allow => Decision::Allow,
            CedarDecision::Deny => Decision::Deny,
        };

        let annotations: Vec<Annotation> = response
            .diagnostics()
            .reason()
            .map(|policy_id| {
                let mut annotation = Annotation::new().with_id(policy_id.to_string());
                if let Some(policy) = self.store.policy_set().policy(policy_id) {
                    for (key, value) in policy.annotations() {
                        match key.to_string().as_str() {
                            "id" => {}
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

        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        Adjudicated {
            decision,
            reason: if errors.is_empty() { None } else { Some(errors.join("; ")) },
            annotations,
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
        let (principal, action, resource, context, entities) =
            transform::build_request(event, entity_store)?;

        let response = self.authorize_full(principal, action, resource, context, entities)?;
        let adjudicated = self.response_to_adjudicated(&response);

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
