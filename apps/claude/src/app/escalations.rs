use anyhow::{Context as _, Result};
use clap::Subcommand;
use serde::Deserialize;

const DEFAULT_ADMIN_URL: &str = "http://localhost:9090";

/// An escalation record returned by the admin HTTP API.
#[derive(Debug, Deserialize)]
struct EscalationRecord {
    id: String,
    trajectory_id: String,
    agent_id: String,
    status: String,
    annotations: Vec<serde_json::Value>,
    expires_at: Option<i64>,
}

#[derive(Subcommand, Debug)]
pub enum EscalationAction {
    /// List pending escalations (requires running admin server).
    List {
        /// Admin HTTP server base URL.
        #[arg(long, default_value = DEFAULT_ADMIN_URL)]
        admin_url: String,
        /// Show all statuses, not just pending.
        #[arg(long)]
        all: bool,
    },
    /// Show the details of a specific escalation by ID.
    Show {
        /// Escalation ID.
        id: String,
        /// Admin HTTP server base URL.
        #[arg(long, default_value = DEFAULT_ADMIN_URL)]
        admin_url: String,
    },
    /// Approve a pending escalation (allows the blocked action to proceed).
    Approve {
        /// Escalation ID.
        id: String,
        /// Admin HTTP server base URL.
        #[arg(long, default_value = DEFAULT_ADMIN_URL)]
        admin_url: String,
        /// Name/identity of the operator making the decision.
        #[arg(long, default_value = "cli")]
        decided_by: String,
    },
    /// Deny a pending escalation (keeps the action blocked).
    Deny {
        /// Escalation ID.
        id: String,
        /// Admin HTTP server base URL.
        #[arg(long, default_value = DEFAULT_ADMIN_URL)]
        admin_url: String,
        /// Name/identity of the operator making the decision.
        #[arg(long, default_value = "cli")]
        decided_by: String,
    },
}

pub async fn handle_escalations(action: &EscalationAction) -> Result<()> {
    match action {
        EscalationAction::List { admin_url, all } => cmd_list(admin_url, *all).await,
        EscalationAction::Show { id, admin_url } => cmd_show(admin_url, id).await,
        EscalationAction::Approve {
            id,
            admin_url,
            decided_by,
        } => cmd_decide(admin_url, id, "approve", decided_by).await,
        EscalationAction::Deny {
            id,
            admin_url,
            decided_by,
        } => cmd_decide(admin_url, id, "deny", decided_by).await,
    }
}

async fn cmd_list(admin_url: &str, all: bool) -> Result<()> {
    let url = format!("{}/api/escalations", admin_url.trim_end_matches('/'));
    let records: Vec<EscalationRecord> = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| "Admin server returned an error")?
        .json()
        .await
        .context("Failed to parse escalation list")?;

    let filtered: Vec<&EscalationRecord> = if all {
        records.iter().collect()
    } else {
        records.iter().filter(|r| r.status == "pending").collect()
    };

    if filtered.is_empty() {
        println!("No pending escalations.");
        return Ok(());
    }

    for r in filtered {
        println!(
            "[{}] {} | agent={} traj={} expires={:?}",
            r.status.to_uppercase(),
            r.id,
            r.agent_id,
            r.trajectory_id,
            r.expires_at
        );
        for ann in &r.annotations {
            if let Some(policy_id) = ann.get("policy_id").and_then(|v| v.as_str()) {
                println!("      policy: {policy_id}");
            }
        }
    }
    Ok(())
}

async fn cmd_show(admin_url: &str, id: &str) -> Result<()> {
    let url = format!("{}/api/escalations/{id}", admin_url.trim_end_matches('/'));
    let record: serde_json::Value = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("Escalation {id} not found"))?
        .json()
        .await
        .context("Failed to parse escalation record")?;

    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

async fn cmd_decide(admin_url: &str, id: &str, action: &str, decided_by: &str) -> Result<()> {
    let url = format!(
        "{}/api/escalations/{id}/{action}",
        admin_url.trim_end_matches('/')
    );
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"decided_by": decided_by}))
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    if resp.status().is_success() {
        println!("Escalation {id} {action}d by {decided_by}.");
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Admin server returned {status}: {body}");
    }
    Ok(())
}
