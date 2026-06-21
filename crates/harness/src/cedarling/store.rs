use anyhow::{Context as _, Result};
use cedar_policy::{PolicyId, PolicySet, Schema};
use std::path::Path;
use tracing::debug;

pub struct CedarlingStore {
    schema: Schema,
    policy_set: PolicySet,
}

impl CedarlingStore {
    /// Load a `CedarlingStore` from a directory containing `schema.json` and `*.cedar` files.
    pub fn load(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        anyhow::ensure!(
            dir.is_dir(),
            "Policy directory does not exist: {}",
            dir.display()
        );

        // --- Schema ---
        let schema_path = dir.join("schema.json");
        anyhow::ensure!(
            schema_path.exists(),
            "schema.json not found in {}",
            dir.display()
        );
        let schema_str = std::fs::read_to_string(&schema_path)
            .with_context(|| format!("Failed to read {}", schema_path.display()))?;
        let schema_value: serde_json::Value = serde_json::from_str(&schema_str)
            .with_context(|| format!("Failed to parse {} as JSON", schema_path.display()))?;
        let schema = Schema::from_json_value(schema_value)
            .with_context(|| format!("Failed to build Cedar schema from {}", schema_path.display()))?;

        // --- Policies ---
        let mut policy_set = PolicySet::new();
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read directory {}", dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    == Some("cedar")
            })
            .collect();
        // Sort for deterministic loading order
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let file_path = entry.path();
            let content = std::fs::read_to_string(&file_path)
                .with_context(|| format!("Failed to read {}", file_path.display()))?;
            let file_policies: PolicySet = content.parse().with_context(|| {
                format!("Failed to parse Cedar policies in {}", file_path.display())
            })?;
            for policy in file_policies.policies() {
                let id_str = policy
                    .annotation("id")
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| policy.id().as_ref());
                let named = policy.new_id(PolicyId::new(id_str));
                debug!(
                    "Loading policy {:?} from {}",
                    named.id().to_string(),
                    file_path.display()
                );
                policy_set.add(named).with_context(|| {
                    format!(
                        "Duplicate policy id {:?} in {}",
                        id_str,
                        file_path.display()
                    )
                })?;
            }
        }

        Ok(Self { schema, policy_set })
    }

    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    pub fn policy_set(&self) -> &PolicySet {
        &self.policy_set
    }
}
