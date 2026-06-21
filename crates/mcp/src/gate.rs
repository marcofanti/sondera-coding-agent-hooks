//! Sondera MCP Gate — policy-gating proxy for LangChain and other MCP-native agents.
//!
//! Exposes common tools (read_file, write_file, run_shell, fetch_url) as MCP tools.
//! Every call is adjudicated through the harness before execution.
//! Deny → MCP error. Escalate → error with escalation hint. Allow → execute.

use anyhow::{Context as _, Result};
use clap::Parser;
use sondera_harness::{
    Action, Actor, ActorType, Agent, Causality, Decision, Event, FileOperation,
    Harness, HarnessClient, ShellCommand, TrajectoryEvent, WebFetch,
};
use std::path::PathBuf;
use turbomcp::prelude::*;

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "sondera-mcp-gate")]
#[command(about = "Policy-gating MCP proxy — adjudicates tool calls via the harness")]
struct Args {
    /// Harness Unix socket path. Defaults to the standard sondera socket.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Agent ID to use for harness adjudication.
    #[arg(long, default_value = "mcp-gate-agent")]
    agent_id: String,

    /// Agent provider to report to the harness.
    #[arg(long, default_value = "langchain")]
    provider: String,
}

// ─── Gate server ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct GateServer {
    harness: HarnessClient,
    agent_id: String,
    provider: String,
    trajectory_id: String,
}

impl GateServer {
    fn new(harness: HarnessClient, agent_id: String, provider: String) -> Self {
        Self {
            harness,
            agent_id: agent_id.clone(),
            provider,
            trajectory_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    fn make_event(&self, id: &str, action: Action) -> Event {
        Event {
            event_id:      id.to_string(),
            trajectory_id: self.trajectory_id.clone(),
            timestamp:     chrono::Utc::now(),
            agent: Agent {
                id:          self.agent_id.clone(),
                provider_id: self.provider.clone(),
            },
            actor: Actor {
                id:         self.agent_id.clone(),
                actor_type: ActorType::Agent,
            },
            causality: Causality {
                correlation_id: self.trajectory_id.clone(),
                causation_id:   Some(id.to_string()),
                parent_id:      None,
            },
            event: TrajectoryEvent::Action(action),
            raw:   None,
        }
    }

    async fn gate(&self, event: Event) -> Result<Decision> {
        Ok(self.harness.adjudicate(event).await?.decision)
    }
}

// ─── MCP tools ───────────────────────────────────────────────────────────────

#[server(name = "sondera-mcp-gate", version = "1.0.0")]
impl GateServer {
    #[tool("Read the contents of a file at a given path")]
    async fn read_file(
        &self,
        ctx: Context,
        path: String,
    ) -> McpResult<String> {
        ctx.info(&format!("Adjudicating read_file({path})")).await?;
        let id = uuid::Uuid::new_v4().to_string();
        let event = self.make_event(
            &id,
            Action::FileOperation(FileOperation::read(&path)),
        );
        match self.gate(event).await.map_err(|e| McpError::internal(e.to_string()))? {
            Decision::Allow => {
                std::fs::read_to_string(&path)
                    .with_context(|| format!("read {path}"))
                    .map_err(|e| McpError::internal(e.to_string()))
            }
            Decision::Deny => Err(McpError::invalid_request(
                format!("Harness denied read_file({path})")
            )),
            Decision::Escalate => Err(McpError::invalid_request(
                format!("Harness escalated read_file({path}): awaiting operator approval")
            )),
        }
    }

    #[tool("Write content to a file at a given path")]
    async fn write_file(
        &self,
        ctx: Context,
        path: String,
        content: String,
    ) -> McpResult<String> {
        ctx.info(&format!("Adjudicating write_file({path})")).await?;
        let id = uuid::Uuid::new_v4().to_string();
        let event = self.make_event(
            &id,
            Action::FileOperation(FileOperation::write(&path, &content)),
        );
        match self.gate(event).await.map_err(|e| McpError::internal(e.to_string()))? {
            Decision::Allow => {
                std::fs::write(&path, &content)
                    .with_context(|| format!("write {path}"))
                    .map_err(|e| McpError::internal(e.to_string()))?;
                Ok(format!("Wrote {} bytes to {path}", content.len()))
            }
            Decision::Deny => Err(McpError::invalid_request(
                format!("Harness denied write_file({path})")
            )),
            Decision::Escalate => Err(McpError::invalid_request(
                format!("Harness escalated write_file({path}): awaiting operator approval")
            )),
        }
    }

    #[tool("Run a shell command and return stdout. Adjudicated by the harness.")]
    async fn run_shell(
        &self,
        ctx: Context,
        command: String,
    ) -> McpResult<String> {
        ctx.info(&format!("Adjudicating run_shell({command})")).await?;
        let binary = command.split_whitespace().next().unwrap_or("sh").to_string();
        let id = uuid::Uuid::new_v4().to_string();
        let event = self.make_event(
            &id,
            Action::ShellCommand(ShellCommand::new(&command)),
        );
        match self.gate(event).await.map_err(|e| McpError::internal(e.to_string()))? {
            Decision::Allow => {
                let out = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&command)
                    .output()
                    .map_err(|e| McpError::internal(e.to_string()))?;
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if out.status.success() {
                    Ok(stdout)
                } else {
                    Err(McpError::internal(format!("Command failed:\n{stderr}")))
                }
            }
            Decision::Deny => Err(McpError::invalid_request(
                format!("Harness denied run_shell({binary})")
            )),
            Decision::Escalate => Err(McpError::invalid_request(
                format!("Harness escalated run_shell({binary}): awaiting operator approval")
            )),
        }
    }

    #[tool("Fetch a URL via HTTP GET. Adjudicated by the harness.")]
    async fn fetch_url(
        &self,
        ctx: Context,
        url: String,
    ) -> McpResult<String> {
        ctx.info(&format!("Adjudicating fetch_url({url})")).await?;
        let id = uuid::Uuid::new_v4().to_string();
        let event = self.make_event(
            &id,
            Action::WebFetch(WebFetch::new(&url, "fetch url")),
        );
        match self.gate(event).await.map_err(|e| McpError::internal(e.to_string()))? {
            Decision::Allow => {
                reqwest::get(&url)
                    .await
                    .map_err(|e| McpError::internal(e.to_string()))?
                    .text()
                    .await
                    .map_err(|e| McpError::internal(e.to_string()))
            }
            Decision::Deny => Err(McpError::invalid_request(
                format!("Harness denied fetch_url({url})")
            )),
            Decision::Escalate => Err(McpError::invalid_request(
                format!("Harness escalated fetch_url({url}): awaiting operator approval")
            )),
        }
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let harness = match args.socket {
        Some(ref path) => HarnessClient::connect(path).await?,
        None           => HarnessClient::connect_default().await?,
    };

    tracing::info!(
        agent_id = %args.agent_id,
        provider = %args.provider,
        "MCP gate connected to harness"
    );

    let server = GateServer::new(harness, args.agent_id, args.provider);
    tracing::info!("Starting Sondera MCP Gate on stdio");
    server.run_stdio().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}
