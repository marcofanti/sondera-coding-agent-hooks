pub mod api;
mod slack;

use crate::Event;
use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;
use turso::{Builder, Connection, Database};

// ─── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationStatus {
    Pending,
    Approved,
    Denied,
    TimedOut,
}

impl EscalationStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Pending  => "pending",
            Self::Approved => "approved",
            Self::Denied   => "denied",
            Self::TimedOut => "timed_out",
        }
    }
}

impl std::fmt::Display for EscalationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for EscalationStatus {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "pending"   => Ok(Self::Pending),
            "approved"  => Ok(Self::Approved),
            "denied"    => Ok(Self::Denied),
            "timed_out" => Ok(Self::TimedOut),
            other => Err(anyhow::anyhow!("Unknown escalation status: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRecord {
    pub id: String,
    pub trajectory_id: String,
    pub agent_id: String,
    /// Full event JSON for operator display.
    pub event_json: String,
    /// Comma-separated Cedar policy IDs that triggered the escalation.
    pub policy_ids: String,
    pub status: EscalationStatus,
    pub created_at: i64,
    pub expires_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
}

impl EscalationRecord {
    pub fn is_expired(&self) -> bool {
        now_secs() > self.expires_at
    }
}

// ─── Store ───────────────────────────────────────────────────────────────────

pub struct EscalationStore {
    _db: Database,
    conn: Connection,
}

impl EscalationStore {
    pub async fn open_at(db_path: &std::path::Path) -> Result<Self> {
        let db = Builder::new_local(&db_path.to_string_lossy())
            .build()
            .await
            .context("Failed to open escalation DB")?;
        let conn = db.connect().context("Failed to connect to escalation DB")?;
        Self::init_schema(&conn).await?;
        Ok(Self { _db: db, conn })
    }

    pub async fn open_in_memory() -> Result<Self> {
        let db = Builder::new_local(":memory:")
            .build()
            .await
            .context("Failed to create in-memory escalation DB")?;
        let conn = db.connect().context("Failed to connect")?;
        Self::init_schema(&conn).await?;
        Ok(Self { _db: db, conn })
    }

    async fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS escalations (
                id            TEXT PRIMARY KEY,
                trajectory_id TEXT NOT NULL,
                agent_id      TEXT NOT NULL,
                event_json    TEXT NOT NULL,
                policy_ids    TEXT NOT NULL DEFAULT '',
                status        TEXT NOT NULL DEFAULT 'pending',
                created_at    TEXT NOT NULL,
                expires_at    TEXT NOT NULL,
                decided_at    TEXT,
                decided_by    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_esc_status     ON escalations(status);
            CREATE INDEX IF NOT EXISTS idx_esc_trajectory ON escalations(trajectory_id);
            "#,
        )
        .await
        .context("Failed to initialize escalation schema")?;
        Ok(())
    }

    /// Persist a new escalation. Returns the record ID.
    pub async fn create(
        &self,
        event: &Event,
        policy_ids: &[String],
        ttl_secs: i64,
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_secs();
        let event_json = serde_json::to_string(event).context("serialize event")?;
        let policy_ids_str = policy_ids.join(",");
        let now_str = now.to_string();
        let expires_str = (now + ttl_secs).to_string();

        self.conn
            .execute(
                "INSERT INTO escalations (id, trajectory_id, agent_id, event_json, policy_ids, status, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7)",
                [
                    id.as_str(),
                    event.trajectory_id.as_str(),
                    event.agent.id.as_str(),
                    event_json.as_str(),
                    policy_ids_str.as_str(),
                    now_str.as_str(),
                    expires_str.as_str(),
                ],
            )
            .await
            .context("Failed to insert escalation")?;

        debug!("Escalation created: {id}");
        Ok(id)
    }

    pub async fn get(&self, id: &str) -> Result<Option<EscalationRecord>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, trajectory_id, agent_id, event_json, policy_ids, status,
                        created_at, expires_at, decided_at, decided_by
                 FROM escalations WHERE id = ?1",
                [id],
            )
            .await
            .context("Failed to query escalation")?;

        if let Some(row) = rows.next().await.context("row read")? {
            Ok(Some(row_to_record(&row)?))
        } else {
            Ok(None)
        }
    }

    pub async fn list(&self, status: Option<EscalationStatus>) -> Result<Vec<EscalationRecord>> {
        let sql = match &status {
            Some(_) => "SELECT id, trajectory_id, agent_id, event_json, policy_ids, status,
                               created_at, expires_at, decided_at, decided_by
                        FROM escalations WHERE status = ?1 ORDER BY created_at DESC",
            None => "SELECT id, trajectory_id, agent_id, event_json, policy_ids, status,
                            created_at, expires_at, decided_at, decided_by
                     FROM escalations ORDER BY created_at DESC",
        };

        let mut rows = if let Some(ref s) = status {
            self.conn.query(sql, [s.as_str()]).await
        } else {
            self.conn.query(sql, ()).await
        }
        .context("Failed to list escalations")?;

        let mut records = Vec::new();
        while let Some(row) = rows.next().await.context("row read")? {
            records.push(row_to_record(&row)?);
        }
        Ok(records)
    }

    pub async fn approve(&self, id: &str, decided_by: &str) -> Result<bool> {
        self.set_decision(id, EscalationStatus::Approved, decided_by).await
    }

    pub async fn deny(&self, id: &str, decided_by: &str) -> Result<bool> {
        self.set_decision(id, EscalationStatus::Denied, decided_by).await
    }

    async fn set_decision(
        &self,
        id: &str,
        status: EscalationStatus,
        decided_by: &str,
    ) -> Result<bool> {
        let now_str = now_secs().to_string();
        let affected = self
            .conn
            .execute(
                "UPDATE escalations SET status = ?1, decided_at = ?2, decided_by = ?3
                 WHERE id = ?4 AND status = 'pending'",
                [status.as_str(), now_str.as_str(), decided_by, id],
            )
            .await
            .context("Failed to update escalation")?;
        Ok(affected > 0)
    }

    /// Expire all pending records past their TTL.
    pub async fn expire_stale(&self) -> Result<u64> {
        let now_str = now_secs().to_string();
        let affected = self
            .conn
            .execute(
                "UPDATE escalations SET status = 'timed_out'
                 WHERE status = 'pending' AND expires_at < ?1",
                [now_str.as_str()],
            )
            .await
            .context("Failed to expire escalations")?;
        if affected > 0 {
            debug!("Expired {affected} stale escalations");
        }
        Ok(affected)
    }
}

// ─── Slack ────────────────────────────────────────────────────────────────────

/// Post an escalation notification to a Slack incoming webhook URL.
///
/// No-op if `webhook_url` is `None`.
pub async fn notify_slack(
    webhook_url: Option<&str>,
    record: &EscalationRecord,
    admin_port: u16,
) -> Result<()> {
    let Some(url) = webhook_url else { return Ok(()) };
    slack::post(url, record, admin_port).await
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn row_to_record(row: &turso::Row) -> Result<EscalationRecord> {
    let status_str: String = row.get(5).context("status")?;
    let created_at: String = row.get(6).context("created_at")?;
    let expires_at: String = row.get(7).context("expires_at")?;
    let decided_at: Option<String> = row.get(8).context("decided_at")?;
    Ok(EscalationRecord {
        id:            row.get(0).context("id")?,
        trajectory_id: row.get(1).context("trajectory_id")?,
        agent_id:      row.get(2).context("agent_id")?,
        event_json:    row.get(3).context("event_json")?,
        policy_ids:    row.get(4).context("policy_ids")?,
        status:        status_str.parse()?,
        created_at:    created_at.parse().unwrap_or(0),
        expires_at:    expires_at.parse().unwrap_or(0),
        decided_at:    decided_at.and_then(|s| s.parse().ok()),
        decided_by:    row.get(9).context("decided_by")?,
    })
}
