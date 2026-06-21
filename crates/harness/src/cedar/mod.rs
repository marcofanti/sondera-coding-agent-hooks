pub mod entity;
mod transform;

use crate::storage::entity::EntityStore;
use crate::{EntityBuilder, euid};
use anyhow::{Context as AnyhowContext, Result};
use cedar_policy::{
    Authorizer, Context, EntityUid, PolicyId, PolicySet, Request, Response, Schema, SchemaFragment,
};
use sondera_information_flow_control::DataModel;
use sondera_policy::PolicyModel;
use std::path::PathBuf;
use tracing::{debug, warn};

pub struct CedarPolicyEngine {
    authorizer: Authorizer,
    schema: Schema,
    policy_set: PolicySet,
    data_model: DataModel,
    policy_model: PolicyModel,
}

impl CedarPolicyEngine {
    /// Load a CedarPolicyEngine from a directory containing `.cedarschema` and `.cedar` files.
    ///
    /// Expects exactly one `.cedarschema` file and zero or more `.cedar` policy files.
    /// Agent entities are created dynamically based on the agent field in each Event.
    pub async fn from_policy_dir(path: PathBuf, entity_store: &EntityStore) -> Result<Self> {
        anyhow::ensure!(
            path.is_dir(),
            "Policy directory does not exist: {}",
            path.display()
        );

        let mut schema_fragments: Vec<SchemaFragment> = Vec::new();
        let mut policy_set = PolicySet::new();

        for entry in std::fs::read_dir(&path).context(format!(
            "Failed to read policy directory: {}",
            path.display()
        ))? {
            let entry = entry?;
            let file_path = entry.path();

            match file_path.extension().and_then(|e| e.to_str()) {
                Some("cedarschema") => {
                    let content = std::fs::read_to_string(&file_path)
                        .context(format!("Failed to read schema: {}", file_path.display()))?;
                    let (fragment, warnings) = SchemaFragment::from_cedarschema_str(&content)
                        .context(format!(
                            "Failed to parse schema fragment: {}",
                            file_path.display()
                        ))?;
                    for warning in warnings {
                        warn!(
                            "Cedar Schema Warning in {}: {}",
                            file_path.display(),
                            warning
                        );
                    }
                    schema_fragments.push(fragment);
                }
                Some("cedar") => {
                    let content = std::fs::read_to_string(&file_path)
                        .context(format!("Failed to read policy: {}", file_path.display()))?;
                    // Parse all policies in the file, then re-add with @id annotation as ID
                    let file_policies: PolicySet = content.parse().context(format!(
                        "Failed to parse Cedar policies: {}",
                        file_path.display()
                    ))?;
                    for policy in file_policies.policies() {
                        let id_str = policy
                            .annotation("id")
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| policy.id().as_ref());
                        let named = policy.new_id(PolicyId::new(id_str));
                        debug!(
                            "Adding policy {:?} from {}",
                            named.id().to_string(),
                            file_path.display()
                        );
                        policy_set.add(named).context(format!(
                            "Duplicate policy id {:?} in {}",
                            id_str,
                            file_path.display()
                        ))?;
                    }
                }
                _ => {}
            }
        }

        anyhow::ensure!(
            !schema_fragments.is_empty(),
            "No .cedarschema files found in {}",
            path.display()
        );

        let schema = Schema::from_schema_fragments(schema_fragments)
            .context("Failed to merge schema fragments")?;

        // Add Label entity types matching the sensitivity lattice.
        // Names must match Label enum's Display impl and ifc.cedar policy references.
        let highly_confidential_label =
            EntityBuilder::new(euid("Label", "HighlyConfidential")?).build()?;
        let confidential_label = EntityBuilder::new(euid("Label", "Confidential")?)
            .parent_uid(highly_confidential_label.uid())
            .build()?;
        let internal_label = EntityBuilder::new(euid("Label", "Internal")?)
            .parent_uid(confidential_label.uid())
            .build()?;
        let public_label = EntityBuilder::new(euid("Label", "Public")?)
            .parent_uid(internal_label.uid())
            .build()?;

        entity_store.upsert(&highly_confidential_label)?;
        entity_store.upsert(&confidential_label)?;
        entity_store.upsert(&internal_label)?;
        entity_store.upsert(&public_label)?;

        let data_model_path = path.join("ifc.toml");
        let data_model = DataModel::from_toml(data_model_path)?;

        let policy_model_path = path.join("policies.toml");
        let policy_model = PolicyModel::from_toml(policy_model_path)?;

        Ok(Self {
            authorizer: Authorizer::new(),
            schema,
            policy_set,
            data_model,
            policy_model,
        })
    }

    /// Get the loaded policy set.
    pub fn policy_set(&self) -> &PolicySet {
        &self.policy_set
    }

    /// Get the loaded schema.
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    pub fn is_authorized(&self, request: &Request, entity_store: &EntityStore) -> Result<Response> {
        let entities = entity_store.entities()?;
        Ok(self
            .authorizer
            .is_authorized(request, &self.policy_set, &entities))
    }

    pub fn validate_request(
        &self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Option<Context>,
    ) -> Result<Request> {
        let ctx = context.unwrap_or_else(Context::empty);
        let request = Request::new(principal, action, resource, ctx, Some(&self.schema))?;
        Ok(request)
    }
}
