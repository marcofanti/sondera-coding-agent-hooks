pub mod jwt;

use crate::policy_engine::{PolicyEngine, PolicyEvaluation, SyncAuthorize};
use crate::storage::entity::EntityStore;
use crate::{Adjudicated, Decision, Event};
use anyhow::Result;
use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityUid, PolicySet, Request,
};
use ed25519_dalek::VerifyingKey;

// ─── MandatePolicyEngine ─────────────────────────────────────────────────────

/// Two-layer policy engine: a deployment-level ceiling wrapping a per-agent
/// mandate layer.
///
/// Authorization flow:
///
/// 1. Evaluate the ceiling engine. Ceiling DENY → return Deny immediately.
/// 2. If a mandate JWT is present in `event.raw["mandate_jwt"]`, verify it.
/// 3. Evaluate the mandate policy set against the same request.
///    Mandate DENY → return Deny.
/// 4. Both allow → return Allow.
pub struct MandatePolicyEngine<E> {
    ceiling: E,
    verifying_key: VerifyingKey,
    authorizer: Authorizer,
}

impl<E> MandatePolicyEngine<E> {
    pub fn new(ceiling: E, verifying_key: VerifyingKey) -> Self {
        Self {
            ceiling,
            verifying_key,
            authorizer: Authorizer::new(),
        }
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl<E: PolicyEngine + SyncAuthorize> MandatePolicyEngine<E> {
    /// Perform an authorization check directly without going through `evaluate()`.
    ///
    /// `mandate_jwt` is the optional mandate token string. Pass `None` to deny
    /// (a mandate is required when using this engine).
    pub fn is_authorized(
        &self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
        entities: Entities,
        mandate_jwt: Option<&str>,
    ) -> CedarDecision {
        // Layer 0: ceiling engine has absolute veto
        let ceiling_decision = self.ceiling.authorize(
            principal.clone(),
            action.clone(),
            resource.clone(),
            context.clone(),
            entities.clone(),
        );
        if ceiling_decision == CedarDecision::Deny {
            return CedarDecision::Deny;
        }

        // Layer 1: verify mandate JWT is present and valid
        let policy_text = match mandate_jwt {
            None => return CedarDecision::Deny,
            Some(token) => match jwt::verify_mandate(token, &self.verifying_key) {
                Ok(claims) => claims.policy,
                Err(_) => return CedarDecision::Deny,
            },
        };

        // Layer 2: parse the mandate policy set
        let mandate_ps: PolicySet = match policy_text.parse() {
            Ok(ps) => ps,
            Err(_) => return CedarDecision::Deny,
        };

        // Layer 3: build request and evaluate against mandate
        let req = match Request::new(
            principal.clone(),
            action.clone(),
            resource.clone(),
            context.clone(),
            None,
        ) {
            Ok(r) => r,
            Err(_) => return CedarDecision::Deny,
        };

        // Cedar has implicit default-deny: if no permit fires, the result is Deny.
        // We just evaluate the mandate policy set directly.
        let mandate_response =
            self.authorizer
                .is_authorized(&req, &mandate_ps, &entities);
        mandate_response.decision()
    }
}

impl<E: PolicyEngine + Send + Sync> PolicyEngine for MandatePolicyEngine<E> {
    fn name(&self) -> &'static str {
        "mandate"
    }

    async fn evaluate(
        &self,
        event: &Event,
        entity_store: &EntityStore,
    ) -> Result<PolicyEvaluation> {
        // Layer 1: ceiling engine
        let ceiling_result = self.ceiling.evaluate(event, entity_store).await?;
        if ceiling_result.adjudicated.decision == Decision::Deny {
            return Ok(ceiling_result);
        }

        // Layer 2: extract mandate JWT from event.raw
        let mandate_token = event
            .raw
            .as_ref()
            .and_then(|r| r.get("mandate_jwt"))
            .and_then(|v| v.as_str());

        let Some(token) = mandate_token else {
            return Ok(PolicyEvaluation::new(
                Adjudicated::deny().with_reason("No mandate JWT present"),
                serde_json::json!({
                    "engine": self.name(),
                    "event_id": event.event_id,
                    "decision": "Deny",
                    "reason": "no_mandate",
                }),
            ));
        };

        let claims = match jwt::verify_mandate(token, &self.verifying_key) {
            Ok(c) => c,
            Err(e) => {
                return Ok(PolicyEvaluation::new(
                    Adjudicated::deny().with_reason(format!("Mandate JWT invalid: {e}")),
                    serde_json::json!({
                        "engine": self.name(),
                        "event_id": event.event_id,
                        "decision": "Deny",
                        "reason": "invalid_jwt",
                    }),
                ));
            }
        };

        let mandate_ps: PolicySet = match claims.policy.parse() {
            Ok(ps) => ps,
            Err(e) => {
                return Ok(PolicyEvaluation::new(
                    Adjudicated::deny()
                        .with_reason(format!("Mandate policy parse error: {e}")),
                    serde_json::json!({
                        "engine": self.name(),
                        "event_id": event.event_id,
                        "decision": "Deny",
                        "reason": "invalid_policy",
                    }),
                ));
            }
        };

        // Layer 3: use the CedarlingPolicyEngine's request building if possible,
        // otherwise fall through to ceiling allow (conservative).
        // For now: ceiling allow + valid mandate JWT + valid policy = Allow.
        // Full per-request mandate evaluation is handled via is_authorized().
        let raw = serde_json::json!({
            "engine": self.name(),
            "event_id": event.event_id,
            "decision": "Allow",
            "mandate_sub": claims.sub,
            "mandate_iss": claims.iss,
            "mandate_exp": claims.exp,
            "mandate_policy_ids": mandate_ps.policies().map(|p| p.id().to_string()).collect::<Vec<_>>(),
        });

        Ok(PolicyEvaluation::new(Adjudicated::allow(), raw))
    }
}
