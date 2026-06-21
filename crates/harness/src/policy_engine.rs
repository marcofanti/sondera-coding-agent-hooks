use crate::storage::entity::EntityStore;
use crate::types::{Adjudicated, Event};
use anyhow::Result;
use cedar_policy::{Context, Decision, Entities, EntityUid};

/// Result returned by a pluggable policy engine.
#[derive(Debug, Clone)]
pub struct PolicyEvaluation {
    /// The engine's decision in the harness-neutral adjudication format.
    pub adjudicated: Adjudicated,
    /// Engine-specific request/response details to persist in the trajectory log.
    pub raw: serde_json::Value,
}

impl PolicyEvaluation {
    pub fn new(adjudicated: Adjudicated, raw: serde_json::Value) -> Self {
        Self { adjudicated, raw }
    }
}

/// Pluggable authorization boundary for the harness.
///
/// Implementations own policy loading and evaluation. The surrounding
/// [`crate::PolicyHarness`] owns common trajectory persistence and entity
/// bookkeeping, then delegates non-control events to this trait.
pub trait PolicyEngine: Send + Sync {
    /// Stable name written as the actor for adjudication events.
    fn name(&self) -> &'static str;

    /// Evaluate a trajectory event against the engine's policies.
    fn evaluate(
        &self,
        event: &Event,
        entity_store: &EntityStore,
    ) -> impl std::future::Future<Output = Result<PolicyEvaluation>> + Send;
}

/// Synchronous authorization check for engines that support it.
///
/// Implemented by `CedarlingPolicyEngine` and `AllowAllPolicyEngine`. Used by
/// `MandatePolicyEngine::is_authorized()` to check the ceiling without async.
pub trait SyncAuthorize {
    fn authorize(
        &self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
        entities: Entities,
    ) -> Decision;
}

impl SyncAuthorize for AllowAllPolicyEngine {
    fn authorize(
        &self,
        _principal: EntityUid,
        _action: EntityUid,
        _resource: EntityUid,
        _context: Context,
        _entities: Entities,
    ) -> Decision {
        Decision::Allow
    }
}

/// Built-in policy engine useful for tests, dry-runs, and custom deployments
/// that want the harness persistence/RPC layer without authorization.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllPolicyEngine;

impl PolicyEngine for AllowAllPolicyEngine {
    fn name(&self) -> &'static str {
        "allow-all"
    }

    async fn evaluate(
        &self,
        event: &Event,
        _entity_store: &EntityStore,
    ) -> Result<PolicyEvaluation> {
        Ok(PolicyEvaluation::new(
            Adjudicated::allow(),
            serde_json::json!({
                "engine": self.name(),
                "event_id": event.event_id,
                "decision": "Allow",
            }),
        ))
    }
}
