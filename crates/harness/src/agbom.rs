use crate::{Action, Event, FileOpType, Observation, TrajectoryEvent, TrajectoryStore};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentBom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: AgentBomMetadata,
    pub components: Vec<AgentBomComponent>,
    pub dependencies: Vec<AgentBomDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentBomMetadata {
    pub timestamp: DateTime<Utc>,
    pub component: AgentBomComponent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentBomComponent {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub properties: Vec<AgentBomProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentBomProperty {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentBomDependency {
    #[serde(rename = "ref")]
    pub bom_ref: String,
    #[serde(rename = "dependsOn")]
    pub depends_on: Vec<String>,
}

impl AgentBom {
    pub fn from_events(events: &[Event]) -> Self {
        let mut projection = Projection::default();
        for event in events {
            projection.observe(event);
        }
        projection.finish()
    }
}

#[derive(Default)]
struct Projection {
    components: BTreeMap<String, ComponentAccumulator>,
    dependencies: BTreeMap<String, BTreeSet<String>>,
}

struct ComponentAccumulator {
    bom_ref: String,
    component_type: String,
    name: String,
    properties: BTreeMap<String, String>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    event_count: u64,
}

impl Projection {
    fn observe(&mut self, event: &Event) {
        let agent_ref = format!("agent:{}:{}", event.agent.provider_id, event.agent.id);
        self.add_component(
            &agent_ref,
            "application",
            &event.agent.id,
            event.timestamp,
            [
                ("sondera:component_kind", "agent".to_string()),
                ("sondera:agent_id", event.agent.id.clone()),
                ("sondera:provider", event.agent.provider_id.clone()),
                ("sondera:trajectory_id", event.trajectory_id.clone()),
            ],
        );

        self.observe_raw_metadata(event, &agent_ref);

        match &event.event {
            TrajectoryEvent::Action(Action::ToolCall(tool)) => {
                let tool_ref = format!("tool:{}", tool.tool);
                self.add_component(
                    &tool_ref,
                    "application",
                    &tool.tool,
                    event.timestamp,
                    [
                        ("sondera:component_kind", "tool".to_string()),
                        ("sondera:tool_name", tool.tool.clone()),
                        ("sondera:agent_id", event.agent.id.clone()),
                        ("sondera:provider", event.agent.provider_id.clone()),
                        ("sondera:trajectory_id", event.trajectory_id.clone()),
                    ],
                );
                self.add_dependency(&agent_ref, &tool_ref);

                if let Some(mcp_ref) = self.observe_mcp_server(event, &agent_ref) {
                    self.add_dependency(&mcp_ref, &tool_ref);
                }
            }
            TrajectoryEvent::Action(Action::ShellCommand(shell)) => {
                if let Some(binary) = shell_binary(&shell.command) {
                    let capability_ref = format!("capability:shell:{binary}");
                    self.add_component(
                        &capability_ref,
                        "application",
                        &binary,
                        event.timestamp,
                        [
                            ("sondera:component_kind", "capability".to_string()),
                            ("sondera:shell_binary", binary.clone()),
                            ("sondera:agent_id", event.agent.id.clone()),
                            ("sondera:provider", event.agent.provider_id.clone()),
                            ("sondera:trajectory_id", event.trajectory_id.clone()),
                        ],
                    );
                    self.add_dependency(&agent_ref, &capability_ref);
                }

                if let Some((manager, action)) = package_command(&shell.command) {
                    let dependency_ref = format!("dependency:command:{manager}:{action}");
                    self.add_component(
                        &dependency_ref,
                        "application",
                        &format!("{manager} {action}"),
                        event.timestamp,
                        [
                            ("sondera:component_kind", "dependency".to_string()),
                            ("sondera:package_command", format!("{manager} {action}")),
                            ("sondera:agent_id", event.agent.id.clone()),
                            ("sondera:provider", event.agent.provider_id.clone()),
                            ("sondera:trajectory_id", event.trajectory_id.clone()),
                        ],
                    );
                    self.add_dependency(&agent_ref, &dependency_ref);
                }
            }
            TrajectoryEvent::Action(Action::WebFetch(fetch)) => {
                if let Some(host) = url_host(&fetch.url) {
                    let api_ref = format!("api:{host}");
                    self.add_component(
                        &api_ref,
                        "application",
                        &host,
                        event.timestamp,
                        [
                            ("sondera:component_kind", "api".to_string()),
                            ("sondera:api_host", host.clone()),
                            ("sondera:agent_id", event.agent.id.clone()),
                            ("sondera:provider", event.agent.provider_id.clone()),
                            ("sondera:trajectory_id", event.trajectory_id.clone()),
                        ],
                    );
                    self.add_dependency(&agent_ref, &api_ref);
                }
            }
            TrajectoryEvent::Action(Action::FileOperation(file)) => {
                let (kind, prefix) = match file.operation {
                    FileOpType::Read => ("knowledge_source", "knowledge:file"),
                    FileOpType::Write | FileOpType::Edit | FileOpType::Delete => ("file", "file"),
                };
                let file_ref = format!("{prefix}:{}", file.path);
                self.add_component(
                    &file_ref,
                    "application",
                    &file.path,
                    event.timestamp,
                    [
                        ("sondera:component_kind", kind.to_string()),
                        ("sondera:file_path", file.path.clone()),
                        ("sondera:agent_id", event.agent.id.clone()),
                        ("sondera:provider", event.agent.provider_id.clone()),
                        ("sondera:trajectory_id", event.trajectory_id.clone()),
                    ],
                );
                self.add_dependency(&agent_ref, &file_ref);

                if is_dependency_manifest(&file.path) {
                    let manifest_ref = format!("dependency:manifest:{}", file.path);
                    self.add_component(
                        &manifest_ref,
                        "application",
                        &file.path,
                        event.timestamp,
                        [
                            ("sondera:component_kind", "dependency".to_string()),
                            ("sondera:manifest_path", file.path.clone()),
                            ("sondera:agent_id", event.agent.id.clone()),
                            ("sondera:provider", event.agent.provider_id.clone()),
                            ("sondera:trajectory_id", event.trajectory_id.clone()),
                        ],
                    );
                    self.add_dependency(&agent_ref, &manifest_ref);
                }
            }
            TrajectoryEvent::Observation(Observation::WebFetchOutput(output)) => {
                if let Some(host) = url_host(&output.url) {
                    let api_ref = format!("api:{host}");
                    self.add_component(
                        &api_ref,
                        "application",
                        &host,
                        event.timestamp,
                        [
                            ("sondera:component_kind", "api".to_string()),
                            ("sondera:api_host", host.clone()),
                            ("sondera:agent_id", event.agent.id.clone()),
                            ("sondera:provider", event.agent.provider_id.clone()),
                            ("sondera:trajectory_id", event.trajectory_id.clone()),
                        ],
                    );
                    self.add_dependency(&agent_ref, &api_ref);
                }
            }
            _ => {}
        }
    }

    fn observe_raw_metadata(&mut self, event: &Event, agent_ref: &str) {
        let Some(raw) = event.raw.as_ref() else {
            return;
        };

        if let Some(model) = raw_string(raw, "model") {
            let model_ref = format!("model:{}:{model}", event.agent.provider_id);
            self.add_component(
                &model_ref,
                "application",
                &model,
                event.timestamp,
                [
                    ("sondera:component_kind", "model".to_string()),
                    ("sondera:model_name", model.clone()),
                    ("sondera:agent_id", event.agent.id.clone()),
                    ("sondera:provider", event.agent.provider_id.clone()),
                    ("sondera:trajectory_id", event.trajectory_id.clone()),
                ],
            );
            self.add_dependency(agent_ref, &model_ref);
        }

        if let Some(transcript_path) = raw_string(raw, "transcript_path") {
            self.add_knowledge_source(event, agent_ref, "transcript", &transcript_path);
        }

        if let Some(roots) = raw.get("workspace_roots").and_then(|v| v.as_array()) {
            for root in roots.iter().filter_map(|v| v.as_str()) {
                if !root.trim().is_empty() {
                    self.add_knowledge_source(event, agent_ref, "workspace", root);
                }
            }
        }

        if let Some(attachments) = raw.get("attachments").and_then(|v| v.as_array()) {
            for attachment in attachments {
                let path = raw_string(attachment, "filePath")
                    .or_else(|| raw_string(attachment, "file_path"));
                if let Some(path) = path {
                    self.add_knowledge_source(event, agent_ref, "attachment", &path);
                }
            }
        }
    }

    fn observe_mcp_server(&mut self, event: &Event, agent_ref: &str) -> Option<String> {
        let raw = event.raw.as_ref()?;
        if let Some(url) = raw_string(raw, "url") {
            let mcp_ref = format!("mcp:{url}");
            self.add_component(
                &mcp_ref,
                "application",
                &url,
                event.timestamp,
                [
                    ("sondera:component_kind", "mcp_server".to_string()),
                    ("sondera:mcp_url", url.clone()),
                    ("sondera:agent_id", event.agent.id.clone()),
                    ("sondera:provider", event.agent.provider_id.clone()),
                    ("sondera:trajectory_id", event.trajectory_id.clone()),
                ],
            );
            self.add_dependency(agent_ref, &mcp_ref);
            return Some(mcp_ref);
        }

        if let Some(command) = raw_string(raw, "command") {
            let safe_name = command
                .split_whitespace()
                .next()
                .filter(|v| !v.is_empty())
                .unwrap_or("command")
                .to_string();
            let mcp_ref = format!("mcp:command:{safe_name}");
            self.add_component(
                &mcp_ref,
                "application",
                &safe_name,
                event.timestamp,
                [
                    ("sondera:component_kind", "mcp_server".to_string()),
                    ("sondera:mcp_command", safe_name.clone()),
                    ("sondera:agent_id", event.agent.id.clone()),
                    ("sondera:provider", event.agent.provider_id.clone()),
                    ("sondera:trajectory_id", event.trajectory_id.clone()),
                ],
            );
            self.add_dependency(agent_ref, &mcp_ref);
            return Some(mcp_ref);
        }

        None
    }

    fn add_knowledge_source(
        &mut self,
        event: &Event,
        agent_ref: &str,
        source_type: &str,
        path: &str,
    ) {
        let source_ref = format!("knowledge:{source_type}:{path}");
        self.add_component(
            &source_ref,
            "application",
            path,
            event.timestamp,
            [
                ("sondera:component_kind", "knowledge_source".to_string()),
                ("sondera:file_path", path.to_string()),
                ("sondera:source_type", source_type.to_string()),
                ("sondera:agent_id", event.agent.id.clone()),
                ("sondera:provider", event.agent.provider_id.clone()),
                ("sondera:trajectory_id", event.trajectory_id.clone()),
            ],
        );
        self.add_dependency(agent_ref, &source_ref);
    }

    fn add_component<I>(
        &mut self,
        bom_ref: &str,
        component_type: &str,
        name: &str,
        seen_at: DateTime<Utc>,
        properties: I,
    ) where
        I: IntoIterator<Item = (&'static str, String)>,
    {
        let entry = self
            .components
            .entry(bom_ref.to_string())
            .or_insert_with(|| ComponentAccumulator {
                bom_ref: bom_ref.to_string(),
                component_type: component_type.to_string(),
                name: name.to_string(),
                properties: BTreeMap::new(),
                first_seen: seen_at,
                last_seen: seen_at,
                event_count: 0,
            });

        entry.first_seen = entry.first_seen.min(seen_at);
        entry.last_seen = entry.last_seen.max(seen_at);
        entry.event_count += 1;
        for (key, value) in properties {
            if !value.trim().is_empty() {
                entry.properties.entry(key.to_string()).or_insert(value);
            }
        }
    }

    fn add_dependency(&mut self, from: &str, to: &str) {
        if from != to {
            self.dependencies
                .entry(from.to_string())
                .or_default()
                .insert(to.to_string());
        }
    }

    fn finish(self) -> AgentBom {
        let timestamp = self
            .components
            .values()
            .map(|component| component.last_seen)
            .max()
            .unwrap_or_else(Utc::now);
        let serial_number = stable_serial_number(self.components.keys());
        let components: Vec<AgentBomComponent> = self
            .components
            .into_values()
            .map(ComponentAccumulator::finish)
            .collect();
        let dependencies: Vec<AgentBomDependency> = self
            .dependencies
            .into_iter()
            .filter(|(_, depends_on)| !depends_on.is_empty())
            .map(|(bom_ref, depends_on)| AgentBomDependency {
                bom_ref,
                depends_on: depends_on.into_iter().collect(),
            })
            .collect();

        AgentBom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            serial_number,
            version: 1,
            metadata: AgentBomMetadata {
                timestamp,
                component: AgentBomComponent {
                    bom_ref: "sondera:agbom".to_string(),
                    component_type: "application".to_string(),
                    name: "Sondera Agent Bill of Materials".to_string(),
                    properties: Vec::new(),
                },
            },
            components,
            dependencies,
        }
    }
}

impl ComponentAccumulator {
    fn finish(mut self) -> AgentBomComponent {
        self.properties.insert(
            "sondera:first_seen".to_string(),
            self.first_seen.to_rfc3339(),
        );
        self.properties
            .insert("sondera:last_seen".to_string(), self.last_seen.to_rfc3339());
        self.properties.insert(
            "sondera:event_count".to_string(),
            self.event_count.to_string(),
        );

        AgentBomComponent {
            bom_ref: self.bom_ref,
            component_type: self.component_type,
            name: self.name,
            properties: self
                .properties
                .into_iter()
                .map(|(name, value)| AgentBomProperty { name, value })
                .collect(),
        }
    }
}

pub async fn build_agbom(
    store: &TrajectoryStore,
    agent_id: Option<&str>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<AgentBom> {
    let mut events = Vec::new();
    for stats in store
        .list_trajectories_filtered(agent_id, limit, offset)
        .await?
    {
        events.extend(store.get_trajectory(&stats.trajectory_id).await?);
    }
    Ok(AgentBom::from_events(&events))
}

pub async fn build_agbom_for_trajectory(
    store: &TrajectoryStore,
    trajectory_id: &str,
) -> Result<AgentBom> {
    let events = store.get_trajectory(trajectory_id).await?;
    Ok(AgentBom::from_events(&events))
}

fn stable_serial_number<'a>(refs: impl Iterator<Item = &'a String>) -> String {
    let mut hasher = DefaultHasher::new();
    for bom_ref in refs {
        bom_ref.hash(&mut hasher);
    }
    format!("urn:sondera:agbom:{:016x}", hasher.finish())
}

fn raw_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
}

fn shell_binary(command: &str) -> Option<String> {
    shlex::split(command)
        .and_then(|parts| parts.into_iter().next())
        .or_else(|| command.split_whitespace().next().map(ToString::to_string))
}

fn package_command(command: &str) -> Option<(String, String)> {
    let parts = shlex::split(command)?;
    let manager = parts.first()?.as_str();
    let action = parts.get(1).map(String::as_str).unwrap_or("run");
    let supported = matches!(
        manager,
        "cargo" | "npm" | "pnpm" | "yarn" | "bun" | "pip" | "pip3" | "poetry" | "go"
    );
    supported.then(|| (manager.to_string(), action.to_string()))
}

fn url_host(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(ToString::to_string))
}

fn is_dependency_manifest(path: &str) -> bool {
    let file_name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        file_name,
        "Cargo.toml"
            | "Cargo.lock"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "bun.lockb"
            | "requirements.txt"
            | "pyproject.toml"
            | "poetry.lock"
            | "go.mod"
            | "go.sum"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Action, Agent, Event, FileOperation, ShellCommand, ToolCall, TrajectoryEvent, WebFetch,
    };
    use chrono::TimeZone;
    use serde_json::json;

    fn event_at(
        id: &str,
        trajectory_id: &str,
        provider: &str,
        event: TrajectoryEvent,
        raw: Option<serde_json::Value>,
        second: u32,
    ) -> Event {
        let mut ev = Event::new(
            Agent {
                id: "agent-1".to_string(),
                provider_id: provider.to_string(),
            },
            trajectory_id,
            event,
        );
        ev.event_id = id.to_string();
        ev.timestamp = Utc.with_ymd_and_hms(2026, 6, 23, 12, 0, second).unwrap();
        ev.raw = raw;
        ev
    }

    fn prop<'a>(component: &'a AgentBomComponent, name: &str) -> Option<&'a str> {
        component
            .properties
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.value.as_str())
    }

    fn component<'a>(bom: &'a AgentBom, bom_ref: &str) -> &'a AgentBomComponent {
        bom.components
            .iter()
            .find(|c| c.bom_ref == bom_ref)
            .unwrap_or_else(|| panic!("missing component {bom_ref}"))
    }

    #[test]
    fn extracts_tool_shell_web_file_mcp_prompt_attachment_and_model_components() {
        let events = vec![
            event_at(
                "evt-1",
                "traj-1",
                "cursor",
                TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
                    "gmail_send",
                    json!({"to": "alice@example.com", "body": "secret"}),
                ))),
                Some(json!({
                    "model": "gpt-5-codex",
                    "tool_name": "gmail_send",
                    "url": "https://mcp.example.com/sse",
                    "tool_input": "{\"body\":\"secret\"}",
                    "workspace_roots": ["/workspace/project"],
                    "transcript_path": "/tmp/transcript.jsonl"
                })),
                1,
            ),
            event_at(
                "evt-2",
                "traj-1",
                "cursor",
                TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new("cargo add serde"))),
                None,
                2,
            ),
            event_at(
                "evt-3",
                "traj-1",
                "cursor",
                TrajectoryEvent::Action(Action::WebFetch(WebFetch::new(
                    "https://api.github.com/repos/sondera-ai/project",
                    "do not leak this prompt",
                ))),
                None,
                3,
            ),
            event_at(
                "evt-4",
                "traj-1",
                "cursor",
                TrajectoryEvent::Action(Action::FileOperation(FileOperation::read("Cargo.toml"))),
                Some(json!({
                    "attachments": [{"type": "file", "filePath": "/workspace/project/README.md"}]
                })),
                4,
            ),
        ];

        let bom = AgentBom::from_events(&events);

        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.6");
        assert_eq!(
            prop(
                component(&bom, "agent:cursor:agent-1"),
                "sondera:component_kind"
            ),
            Some("agent")
        );
        assert_eq!(
            prop(component(&bom, "tool:gmail_send"), "sondera:component_kind"),
            Some("tool")
        );
        assert_eq!(
            prop(
                component(&bom, "model:cursor:gpt-5-codex"),
                "sondera:model_name"
            ),
            Some("gpt-5-codex")
        );
        assert_eq!(
            prop(
                component(&bom, "mcp:https://mcp.example.com/sse"),
                "sondera:mcp_url"
            ),
            Some("https://mcp.example.com/sse")
        );
        assert_eq!(
            prop(
                component(&bom, "capability:shell:cargo"),
                "sondera:shell_binary"
            ),
            Some("cargo")
        );
        assert_eq!(
            prop(component(&bom, "api:api.github.com"), "sondera:api_host"),
            Some("api.github.com")
        );
        assert_eq!(
            prop(
                component(&bom, "knowledge:file:Cargo.toml"),
                "sondera:file_path"
            ),
            Some("Cargo.toml")
        );
        assert_eq!(
            prop(
                component(&bom, "knowledge:attachment:/workspace/project/README.md"),
                "sondera:file_path"
            ),
            Some("/workspace/project/README.md")
        );
        assert_eq!(
            prop(
                component(&bom, "dependency:manifest:Cargo.toml"),
                "sondera:manifest_path"
            ),
            Some("Cargo.toml")
        );
        assert_eq!(
            prop(
                component(&bom, "dependency:command:cargo:add"),
                "sondera:package_command"
            ),
            Some("cargo add")
        );
    }

    #[test]
    fn deduplicates_components_tracks_temporal_properties_and_relationships() {
        let events = vec![
            event_at(
                "evt-1",
                "traj-1",
                "claude",
                TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
                    "Read",
                    json!({"file_path": "README.md"}),
                ))),
                None,
                1,
            ),
            event_at(
                "evt-2",
                "traj-1",
                "claude",
                TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
                    "Read",
                    json!({"file_path": "secrets.txt"}),
                ))),
                None,
                9,
            ),
        ];

        let bom = AgentBom::from_events(&events);
        let tool = component(&bom, "tool:Read");
        assert_eq!(prop(tool, "sondera:event_count"), Some("2"));
        assert_eq!(
            prop(tool, "sondera:first_seen"),
            Some("2026-06-23T12:00:01+00:00")
        );
        assert_eq!(
            prop(tool, "sondera:last_seen"),
            Some("2026-06-23T12:00:09+00:00")
        );

        let agent_dep = bom
            .dependencies
            .iter()
            .find(|d| d.bom_ref == "agent:claude:agent-1")
            .expect("missing agent dependency");
        assert!(agent_dep.depends_on.contains(&"tool:Read".to_string()));
    }

    #[test]
    fn redacts_prompts_arguments_and_outputs_from_properties() {
        let events = vec![event_at(
            "evt-1",
            "traj-1",
            "cursor",
            TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
                "dangerous_tool",
                json!({"token": "sk-secret", "prompt": "leak this"}),
            ))),
            Some(json!({
                "tool_input": "{\"token\":\"sk-secret\"}",
                "prompt": "leak this",
                "output": "secret stdout"
            })),
            1,
        )];

        let serialized = serde_json::to_string(&AgentBom::from_events(&events)).unwrap();
        assert!(!serialized.contains("sk-secret"));
        assert!(!serialized.contains("leak this"));
        assert!(!serialized.contains("secret stdout"));
    }
}
