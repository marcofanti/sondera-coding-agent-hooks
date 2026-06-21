use crate::cedar::CedarPolicyEngine;
use crate::cedar::entity::Trajectory;
use crate::cedarling::CedarlingPolicyEngine;
use crate::escalation::api::AdminState;
use crate::harness::Harness;
use crate::mandate::MandatePolicyEngine;
use crate::observability::{EventTelemetry, decision_name, record_adjudication_metrics};
use crate::policy_engine::PolicyEngine;
use crate::storage::entity::EntityStore;
use crate::storage::file;
use crate::storage::turso::{TrajectoryStore, get_default_db_path};
use crate::{Actor, Adjudicated, Agent, Causality, Control, Decision, Event, TrajectoryEvent};
use anyhow::{Context as AnyhowContext, Result};
use cedar_policy::{Entity, EntityId, EntityUid, PolicySet, Schema};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, instrument, warn};

/// Harness runtime parameterized by a pluggable policy engine.
pub struct PolicyHarness<E> {
    entity_store: EntityStore,
    trajectory_store: TrajectoryStore,
    engine: E,
    /// When set, escalated decisions are persisted, broadcast via SSE, and notified via Slack.
    escalation: Option<Arc<AdminState>>,
    escalation_ttl: i64,
}

/// Production Cedar-backed harness kept as the default public type.
pub type CedarPolicyHarness = PolicyHarness<CedarPolicyEngine>;

/// Harness backed by the Jans::-namespaced CedarlingPolicyEngine.
pub type CedarlingPolicyHarness = PolicyHarness<CedarlingPolicyEngine>;

/// Harness backed by the two-layer mandate engine (Cedarling ceiling + Ed25519 mandate JWT).
pub type MandatePolicyHarness = PolicyHarness<MandatePolicyEngine<CedarlingPolicyEngine>>;

impl<E> PolicyHarness<E> {
    pub fn new(entity_store: EntityStore, trajectory_store: TrajectoryStore, engine: E) -> Self {
        Self {
            entity_store,
            trajectory_store,
            engine,
            escalation: None,
            escalation_ttl: 120,
        }
    }

    /// Attach an escalation admin state so that `Decision::Escalate` results are
    /// persisted, broadcast via SSE, and notified via Slack.
    pub fn with_escalation(mut self, state: Arc<AdminState>, ttl_secs: i64) -> Self {
        self.escalation = Some(state);
        self.escalation_ttl = ttl_secs;
        self
    }

    pub fn engine(&self) -> &E {
        &self.engine
    }

    /// Build a harness with the default production entity and trajectory stores.
    pub async fn from_default_storage(engine: E) -> Result<Self> {
        let entity_store_path = file::get_storage_dir()?.join("entities");
        let entity_store = EntityStore::open(&entity_store_path).context(format!(
            "Failed to open entity store: {}",
            entity_store_path.display()
        ))?;

        let trajectory_db_path = get_default_db_path()?;
        let trajectory_store =
            TrajectoryStore::open(&trajectory_db_path)
                .await
                .context(format!(
                    "Failed to open trajectory store: {}",
                    trajectory_db_path.display()
                ))?;

        Ok(Self::new(entity_store, trajectory_store, engine))
    }

    /// Build a harness with isolated storage for tests.
    pub async fn from_isolated_storage(engine: E, storage_dir: &std::path::Path) -> Result<Self> {
        let entity_store = EntityStore::open(storage_dir.join("entities")).context(format!(
            "Failed to open entity store: {}",
            storage_dir.display()
        ))?;

        let trajectory_store = TrajectoryStore::open_in_memory()
            .await
            .context("Failed to open in-memory trajectory store")?;

        Ok(Self::new(entity_store, trajectory_store, engine))
    }

    /// Add an entity to the entity store.
    /// Returns an error if an entity with the same UID already exists.
    pub fn add_entity(&self, entity: Entity) -> Result<()> {
        if self.entity_store.get(&entity.uid())?.is_some() {
            anyhow::bail!("Entity already exists: {}", entity.uid());
        }
        self.entity_store.upsert(&entity)?;
        Ok(())
    }

    /// Upsert an entity into the entity store.
    /// If an entity with the same UID exists, it will be replaced.
    pub fn upsert_entity(&self, entity: Entity) -> Result<()> {
        self.entity_store.upsert(&entity)?;
        Ok(())
    }

    /// Get an entity from the entity store by its UID.
    pub fn get_entity(&self, uid: &EntityUid) -> Result<Option<Entity>> {
        self.entity_store.get(uid)
    }

    /// Remove an entity from the entity store by its UID.
    pub fn remove_entity(&self, uid: EntityUid) -> Result<()> {
        self.entity_store.delete(&uid)?;
        Ok(())
    }
}

impl CedarPolicyHarness {
    /// Load a CedarPolicyHarness from a directory containing `.cedarschema` and `.cedar` files.
    pub async fn from_policy_dir(path: PathBuf) -> Result<Self> {
        let entity_store_path = file::get_storage_dir()?.join("entities");
        let entity_store = EntityStore::open(&entity_store_path).context(format!(
            "Failed to open entity store: {}",
            entity_store_path.display()
        ))?;

        let trajectory_db_path = get_default_db_path()?;
        let trajectory_store =
            TrajectoryStore::open(&trajectory_db_path)
                .await
                .context(format!(
                    "Failed to open trajectory store: {}",
                    trajectory_db_path.display()
                ))?;

        Self::build_cedar(path, entity_store, trajectory_store).await
    }

    /// Load a CedarPolicyHarness with isolated storage for testing.
    pub async fn from_policy_dir_isolated(
        path: PathBuf,
        storage_dir: &std::path::Path,
    ) -> Result<Self> {
        let entity_store = EntityStore::open(storage_dir.join("entities")).context(format!(
            "Failed to open entity store: {}",
            storage_dir.display()
        ))?;

        let trajectory_store = TrajectoryStore::open_in_memory()
            .await
            .context("Failed to open in-memory trajectory store")?;

        Self::build_cedar(path, entity_store, trajectory_store).await
    }

    async fn build_cedar(
        path: PathBuf,
        entity_store: EntityStore,
        trajectory_store: TrajectoryStore,
    ) -> Result<Self> {
        let engine = CedarPolicyEngine::from_policy_dir(path, &entity_store).await?;
        Ok(Self::new(entity_store, trajectory_store, engine))
    }

    /// Get the loaded Cedar policy set.
    pub fn policy_set(&self) -> &PolicySet {
        self.engine.policy_set()
    }

    /// Get the loaded Cedar schema.
    pub fn schema(&self) -> &Schema {
        self.engine.schema()
    }
}

impl<E: PolicyEngine> PolicyHarness<E> {
    /// Ensure the agent entity exists in the entity store.
    fn ensure_agent_entity(&self, agent: &Agent) -> Result<()> {
        let agent_uid = EntityUid::from_type_name_and_id(
            "Agent".parse().context("Invalid entity type name: Agent")?,
            EntityId::new(&agent.id),
        );

        if self.entity_store.get(&agent_uid)?.is_none() {
            let agent_entity = Entity::new_no_attrs(agent_uid, HashSet::new());
            self.entity_store.upsert(&agent_entity)?;
        }
        Ok(())
    }
}

impl<E: PolicyEngine> Harness for PolicyHarness<E> {
    #[instrument(
        skip(self, event),
        fields(
            trajectory_id = %event.trajectory_id,
            event_id = %event.event_id,
            agent = %event.agent.id,
            policy_engine = %self.engine.name(),
            event_category = tracing::field::Empty,
            event_type = tracing::field::Empty,
            decision = tracing::field::Empty,
            policy_ids = tracing::field::Empty,
            annotation_count = tracing::field::Empty,
        )
    )]
    async fn adjudicate(&self, event: Event) -> Result<Adjudicated> {
        let started_at = Instant::now();
        let event_telemetry = EventTelemetry::from_event(&event);
        let span = tracing::Span::current();
        span.record("event_category", event_telemetry.category);
        span.record("event_type", event_telemetry.event_type);
        debug!("Trajectory Event: {:?}", event);
        self.ensure_agent_entity(&event.agent)?;

        file::write_trajectory_event(&event)?;
        self.trajectory_store.insert_event(&event).await?;

        if let TrajectoryEvent::Control(control) = &event.event {
            if let Control::Started(_) = control {
                debug!("Starting trajectory: {}", event.trajectory_id);
                let trajectory = Trajectory::new(&event.trajectory_id);
                self.upsert_entity(trajectory.into_entity()?)?;
            }
            let adjudicated = Adjudicated::allow();
            span.record("decision", decision_name(adjudicated.decision));
            span.record("annotation_count", adjudicated.annotations.len());
            record_adjudication_metrics(
                self.engine.name(),
                adjudicated.decision,
                &event,
                started_at.elapsed(),
            );
            return Ok(adjudicated);
        }

        let evaluation = self.engine.evaluate(&event, &self.entity_store).await?;
        let mut adjudicated = evaluation.adjudicated.clone();

        // When the engine escalates, create a persistent record and fire notifications.
        // Surface the escalation ID in the response so clients can poll for approval.
        if adjudicated.decision == Decision::Escalate
            && let Some(ref admin) = self.escalation
        {
            let policy_ids: Vec<String> = adjudicated
                .annotations
                .iter()
                .filter_map(|a| a.policy_id.clone())
                .collect();
            match admin
                .on_new_escalation(&event, &policy_ids, self.escalation_ttl)
                .await
            {
                Ok(esc_id) => {
                    debug!("Escalation created: {esc_id}");
                    adjudicated.escalation_id = Some(esc_id);
                }
                Err(e) => warn!("Failed to create escalation record: {e}"),
            }
        }

        let policy_ids = EventTelemetry::policy_ids(&adjudicated).join(",");
        span.record("decision", decision_name(adjudicated.decision));
        span.record("policy_ids", policy_ids);
        span.record("annotation_count", adjudicated.annotations.len());
        record_adjudication_metrics(
            self.engine.name(),
            adjudicated.decision,
            &event,
            started_at.elapsed(),
        );

        let adjudicated_event = Event::new(
            event.agent.clone(),
            &event.trajectory_id,
            TrajectoryEvent::Control(Control::Adjudicated(adjudicated.clone())),
        )
        .with_actor(Actor::policy(self.engine.name()))
        .with_causality(Causality::default().caused_by(&event.event_id))
        .with_raw(evaluation.raw);

        // Collect any taint names emitted by matching forbid policies.
        let new_taints: Vec<String> = adjudicated
            .annotations
            .iter()
            .filter_map(|a| a.annotations.get("taint").cloned())
            .collect();

        let trajectory_uid = crate::cedar::entity::euid("Trajectory", &event.trajectory_id)?;
        let mut trajectory: Trajectory = match self.entity_store.get(&trajectory_uid)? {
            Some(entity) => entity.try_into()?,
            None => {
                debug!(
                    "Trajectory entity {:?} not found after adjudication, creating.",
                    &event.trajectory_id
                );
                Trajectory::new(&event.trajectory_id)
            }
        };

        // Propagate taints — add any new taint names, deduplicating against existing ones.
        if !new_taints.is_empty() {
            let existing: std::collections::HashSet<String> =
                trajectory.taints.iter().cloned().collect();
            for taint in &new_taints {
                if !existing.contains(taint) {
                    debug!(
                        "Taint propagated to trajectory {}: {}",
                        event.trajectory_id, taint
                    );
                    trajectory.taints.push(taint.clone());
                }
            }
            // Persist the updated trajectory entity.
            if let Err(e) = self.entity_store.upsert(&trajectory.clone().into_entity()?) {
                warn!("Failed to persist taint propagation: {e}");
            }
        }

        debug!("Adjudicated Event: {:?}", adjudicated_event);
        debug!("Trajectory: {:?}", trajectory);

        file::write_trajectory_event(&adjudicated_event)?;
        self.trajectory_store
            .insert_event(&adjudicated_event)
            .await?;

        Ok(adjudicated)
    }
}
