use super::{EscalationRecord, EscalationStore, notify_slack};
use crate::harness::Harness;
use crate::rpc::HarnessClient;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
};
use serde::Deserialize;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;

// ─── App state ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AdminState {
    pub store: Arc<EscalationStore>,
    /// Broadcast channel — each new escalation or decision posts a JSON string.
    pub events_tx: broadcast::Sender<String>,
    pub slack_webhook: Option<String>,
    pub admin_port: u16,
    /// Path to the harness tarpc Unix socket for the /api/adjudicate proxy endpoint.
    pub harness_socket: Option<PathBuf>,
    /// Lazily initialized tarpc client shared across handler instances.
    harness_client: Arc<tokio::sync::OnceCell<HarnessClient>>,
}

impl AdminState {
    pub fn new(
        store: EscalationStore,
        slack_webhook: Option<String>,
        admin_port: u16,
    ) -> Self {
        let (events_tx, _) = broadcast::channel(256);
        Self {
            store: Arc::new(store),
            events_tx,
            slack_webhook,
            admin_port,
            harness_socket: None,
            harness_client: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Wire a harness socket path for the /api/adjudicate proxy endpoint.
    pub fn with_harness_socket(mut self, socket: PathBuf) -> Self {
        self.harness_socket = Some(socket);
        self
    }

    async fn get_harness_client(&self) -> anyhow::Result<&HarnessClient> {
        let socket = self
            .harness_socket
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("harness socket not configured"))?;
        self.harness_client
            .get_or_try_init(|| HarnessClient::connect(socket))
            .await
    }

    /// Publish a record to the SSE stream.
    fn broadcast(&self, record: &EscalationRecord) {
        if let Ok(json) = serde_json::to_string(record) {
            let _ = self.events_tx.send(json);
        }
    }

    /// Called by PolicyHarness when an event is escalated.
    /// Creates the EscalationStore record, broadcasts to SSE, and fires the Slack webhook.
    pub async fn on_new_escalation(
        &self,
        event: &crate::Event,
        policy_ids: &[String],
        ttl_secs: i64,
    ) -> anyhow::Result<String> {
        let id = self.store.create(event, policy_ids, ttl_secs).await?;
        if let Some(record) = self.store.get(&id).await? {
            self.broadcast(&record);
            let _ = notify_slack(self.slack_webhook.as_deref(), &record, self.admin_port).await;
        }
        Ok(id)
    }
}

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/api/adjudicate",                post(http_adjudicate))
        .route("/api/escalations",               get(list_escalations))
        .route("/api/escalations/stream",        get(sse_stream))
        .route("/api/escalations/:id",           get(get_escalation))
        .route("/api/escalations/:id/approve",   post(approve_escalation))
        .route("/api/escalations/:id/deny",      post(deny_escalation))
        .with_state(state)
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// Proxy an `Event` to the harness tarpc server and return the `Adjudicated` result.
/// Used by the Python SDK and other non-tarpc clients.
async fn http_adjudicate(
    State(s): State<AdminState>,
    Json(event): Json<crate::Event>,
) -> Response {
    match s.get_harness_client().await {
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
        Ok(client) => match client.adjudicate(event).await {
            Ok(adj) => Json(adj).into_response(),
            Err(e)  => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
    }
}

#[derive(Deserialize)]
struct ListQuery {
    status: Option<String>,
}

async fn list_escalations(
    State(s): State<AdminState>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<EscalationRecord>>, (StatusCode, String)> {
    let filter = q.status.as_deref().and_then(|v| v.parse().ok());
    s.store.list(filter).await.map(Json).map_err(internal)
}

async fn get_escalation(
    State(s): State<AdminState>,
    Path(id): Path<String>,
) -> Result<Json<EscalationRecord>, (StatusCode, String)> {
    match s.store.get(&id).await {
        Ok(Some(r)) => Ok(Json(r)),
        Ok(None)    => Err((StatusCode::NOT_FOUND, format!("escalation {id} not found"))),
        Err(e)      => Err(internal(e)),
    }
}

#[derive(Deserialize)]
struct DecisionBody {
    decided_by: Option<String>,
}

async fn approve_escalation(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Result<Json<EscalationRecord>, (StatusCode, String)> {
    let who = body.as_ref().and_then(|b| b.decided_by.as_deref()).unwrap_or("operator");
    let updated = s.store.approve(&id, who).await.map_err(internal)?;
    if !updated {
        return Err((StatusCode::CONFLICT, format!("escalation {id} is no longer pending")));
    }
    fetch_and_broadcast(&s, &id).await
}

async fn deny_escalation(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Result<Json<EscalationRecord>, (StatusCode, String)> {
    let who = body.as_ref().and_then(|b| b.decided_by.as_deref()).unwrap_or("operator");
    let updated = s.store.deny(&id, who).await.map_err(internal)?;
    if !updated {
        return Err((StatusCode::CONFLICT, format!("escalation {id} is no longer pending")));
    }
    fetch_and_broadcast(&s, &id).await
}

async fn sse_stream(
    State(s): State<AdminState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = s.events_tx.subscribe();
    let stream = BroadcastStream::new(rx)
        .filter_map(|res| res.ok())
        .map(|json| Ok(Event::default().data(json)));
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async fn fetch_and_broadcast(
    s: &AdminState,
    id: &str,
) -> Result<Json<EscalationRecord>, (StatusCode, String)> {
    let record = s
        .store
        .get(id)
        .await
        .map_err(internal)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("escalation {id} not found")))?;
    s.broadcast(&record);
    Ok(Json(record))
}

/// Notify Slack when a new escalation is created.
///
/// Call this from PolicyHarness after `EscalationStore::create()`.
pub async fn on_escalation_created(state: &AdminState, record: &EscalationRecord) {
    state.broadcast(record);
    let _ = notify_slack(state.slack_webhook.as_deref(), record, state.admin_port).await;
}

fn internal(e: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// ─── Background TTL sweeper ───────────────────────────────────────────────────

/// Spawn a background task that expires stale escalations every `interval`.
pub fn spawn_ttl_sweeper(state: AdminState, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(e) = state.store.expire_stale().await {
                tracing::warn!("TTL sweep error: {e}");
            }
        }
    })
}
