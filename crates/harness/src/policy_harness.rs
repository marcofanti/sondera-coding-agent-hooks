use crate::cedar::CedarPolicyEngine;
use crate::cedarling::CedarlingPolicyEngine;
use crate::mandate::MandatePolicyEngine;
use crate::cedar::entity::Trajectory;
use crate::harness::Harness;
use crate::policy_engine::PolicyEngine;
use crate::storage::entity::EntityStore;
use crate::storage::file;
use crate::storage::turso::{TrajectoryStore, get_default_db_path};
use crate::{Actor, Adjudicated, Agent, Causality, Control, Event, TrajectoryEvent};
use anyhow::{Context as AnyhowContext, Result};
use cedar_policy::{Entity, EntityId, EntityUid, PolicySet, Schema};
use std::collections::HashSet;
use std::path::PathBuf;
use tracing::{debug, instrument};

/// Harness runtime parameterized by a pluggable policy engine.
pub struct PolicyHarness<E> {
    entity_store: EntityStore,
    trajectory_store: TrajectoryStore,
    engine: E,
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
        }
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
        )
    )]
    async fn adjudicate(&self, event: Event) -> Result<Adjudicated> {
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
            return Ok(Adjudicated::allow());
        }

        let evaluation = self.engine.evaluate(&event, &self.entity_store).await?;
        let adjudicated = evaluation.adjudicated;

        let adjudicated_event = Event::new(
            event.agent.clone(),
            &event.trajectory_id,
            TrajectoryEvent::Control(Control::Adjudicated(adjudicated.clone())),
        )
        .with_actor(Actor::policy(self.engine.name()))
        .with_causality(Causality::default().caused_by(&event.event_id))
        .with_raw(evaluation.raw);

        let trajectory: Trajectory = match self.entity_store.get(&crate::cedar::entity::euid(
            "Trajectory",
            &event.trajectory_id,
        )?)? {
            Some(entity) => entity.try_into()?,
            None => {
                debug!(
                    "Trajectory entity {:?} not found after adjudication, creating.",
                    &event.trajectory_id
                );
                Trajectory::new(&event.trajectory_id)
            }
        };

        debug!("Adjudicated Event: {:?}", adjudicated_event);
        debug!("Trajectory: {:?}", trajectory);

        file::write_trajectory_event(&adjudicated_event)?;
        self.trajectory_store
            .insert_event(&adjudicated_event)
            .await?;

        Ok(adjudicated)
    }
}
