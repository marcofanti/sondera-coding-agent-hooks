use anyhow::{Context as _, Result};
use clap::{Subcommand, ValueEnum};
use reqwest::Url;

const DEFAULT_ADMIN_URL: &str = "http://localhost:9090";

#[derive(Subcommand, Debug)]
pub enum AgbomAction {
    /// Show the live Agent Bill of Materials from the admin HTTP server.
    Show {
        /// Admin HTTP server base URL.
        #[arg(long, default_value = DEFAULT_ADMIN_URL)]
        admin_url: String,
        /// Limit the AgBOM to one trajectory.
        #[arg(long)]
        trajectory_id: Option<String>,
        /// Limit aggregate AgBOM to trajectories for one agent.
        #[arg(long)]
        agent_id: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = AgbomOutput::Json)]
        output: AgbomOutput,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AgbomOutput {
    Json,
}

pub fn handle_agbom(action: &AgbomAction) -> Result<()> {
    match action {
        AgbomAction::Show {
            admin_url,
            trajectory_id,
            agent_id,
            output: _,
        } => {
            let url = build_agbom_url(admin_url, trajectory_id.as_deref(), agent_id.as_deref());
            let value: serde_json::Value = reqwest::blocking::get(&url)
                .with_context(|| format!("GET {url}"))?
                .error_for_status()
                .with_context(|| "Admin server returned an error")?
                .json()
                .context("Failed to parse AgBOM response")?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
    }
}

fn build_agbom_url(admin_url: &str, trajectory_id: Option<&str>, agent_id: Option<&str>) -> String {
    let mut url = Url::parse(admin_url.trim_end_matches('/'))
        .or_else(|_| Url::parse(DEFAULT_ADMIN_URL))
        .expect("default admin URL is valid");

    if let Some(trajectory_id) = trajectory_id.filter(|v| !v.trim().is_empty()) {
        url.path_segments_mut()
            .expect("admin URL can be a base")
            .clear()
            .extend(["api", "trajectories", trajectory_id, "agbom"]);
        return url.to_string();
    }

    url.set_path("/api/agbom");
    if let Some(agent_id) = agent_id.filter(|v| !v.trim().is_empty()) {
        url.query_pairs_mut().append_pair("agent_id", agent_id);
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_aggregate_agbom_url_with_agent_filter() {
        assert_eq!(
            build_agbom_url("http://localhost:9090/", None, Some("agent 1")),
            "http://localhost:9090/api/agbom?agent_id=agent+1"
        );
    }

    #[test]
    fn builds_trajectory_agbom_url_and_ignores_agent_filter() {
        assert_eq!(
            build_agbom_url("http://localhost:9090/", Some("traj/1"), Some("agent-a")),
            "http://localhost:9090/api/trajectories/traj%2F1/agbom"
        );
    }
}
