//! Sondera Harness Server
//!
//! A tarpc-based IPC server that provides policy adjudication services
//! via Unix domain sockets.

use anyhow::{Context as _, Result};
use axum::serve;
use clap::{Parser, ValueEnum};
use sondera_harness::{
    AllowAllPolicyEngine, CedarPolicyHarness, CedarlingPolicyEngine, CedarlingPolicyHarness,
    MandatePolicyEngine, MandatePolicyHarness, PolicyHarness,
    escalation::{
        EscalationStore,
        api::{AdminState, router, spawn_ttl_sweeper},
    },
    mandate::jwt::load_verifying_key,
    observability::{ObservabilityConfig, ObservabilityOptions, OtelProtocol, ProcessEnv},
    rpc,
};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, ValueEnum)]
enum PolicyEngineKind {
    /// Evaluate policies with the legacy Cedar policy engine (old namespace).
    Cedar,
    /// Evaluate policies with the Jans::-namespaced CedarlingPolicyEngine (new default).
    Cedarling,
    /// Two-layer: Cedarling ceiling + per-agent Ed25519 mandate JWT (requires --mandate-pub-key).
    Mandate,
    /// Persist events and allow every non-control event without policy checks.
    AllowAll,
}

#[derive(Parser, Debug)]
#[command(name = "sondera-harness-server")]
#[command(about = "Sondera Harness IPC Server")]
#[command(version)]
struct Args {
    /// Path to Unix socket for IPC
    #[arg(short, long)]
    socket: Option<PathBuf>,

    /// Path to Cedar policy directory
    #[arg(short, long, default_value = "policies")]
    policy_path: PathBuf,

    /// Policy engine implementation to use
    #[arg(long, value_enum, default_value_t = PolicyEngineKind::Cedar)]
    policy_engine: PolicyEngineKind,

    /// Path to the Ed25519 verifying key file (32 raw bytes). Required when --policy-engine mandate.
    #[arg(long)]
    mandate_pub_key: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Port for the HTTP admin API (escalation approve/deny + SSE stream). 0 disables it.
    #[arg(long, default_value_t = 9090)]
    admin_port: u16,

    /// Slack incoming webhook URL for escalation notifications.
    #[arg(long)]
    slack_webhook: Option<String>,

    /// Default escalation TTL in seconds (auto-deny after this period).
    #[arg(long, default_value_t = 120)]
    escalation_ttl: u64,

    /// Enable OpenTelemetry trace export.
    #[arg(long)]
    otel: bool,

    /// OTLP endpoint. Defaults to OTEL_EXPORTER_OTLP_TRACES_ENDPOINT or OTEL_EXPORTER_OTLP_ENDPOINT.
    #[arg(long)]
    otel_endpoint: Option<String>,

    /// OTLP transport protocol.
    #[arg(long, value_enum, default_value_t = OtelProtocol::Grpc)]
    otel_protocol: OtelProtocol,

    /// OpenTelemetry service name. Defaults to OTEL_SERVICE_NAME or sondera-harness.
    #[arg(long)]
    otel_service_name: Option<String>,

    /// Enable OpenTelemetry metric export.
    #[arg(long)]
    otel_metrics: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let otel_config = ObservabilityConfig::from_options_and_env(
        ObservabilityOptions {
            enabled: args.otel,
            endpoint: args.otel_endpoint.clone(),
            protocol: args.otel_protocol,
            service_name: args.otel_service_name.clone(),
            metrics_enabled: args.otel_metrics,
        },
        &ProcessEnv,
    );
    let _observability = sondera_harness::observability::init(&otel_config, args.verbose)?;

    let socket_path = args.socket.unwrap_or_else(rpc::default_socket_path);

    // Escalation admin HTTP server (optional — disabled when admin_port == 0).
    // Returns an Arc<AdminState> so each harness variant can attach it.
    let escalation: Option<std::sync::Arc<AdminState>> = if args.admin_port > 0 {
        let esc_store = EscalationStore::open_in_memory().await?;
        let state = AdminState::new(esc_store, args.slack_webhook.clone(), args.admin_port)
            .with_harness_socket(socket_path.clone());
        let state = std::sync::Arc::new(state);
        let app = router((*state).clone());
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], args.admin_port).into();
        tracing::info!("Admin HTTP API listening on http://{addr}");
        spawn_ttl_sweeper((*state).clone(), Duration::from_secs(30));
        let state_clone = state.clone();
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .expect("admin bind");
            serve(listener, app).await.expect("admin serve");
            drop(state_clone);
        });
        Some(state)
    } else {
        None
    };
    let esc_ttl = args.escalation_ttl as i64;

    match args.policy_engine {
        PolicyEngineKind::Cedar => {
            tracing::info!("Loading Cedar policies from {:?}", args.policy_path);
            let mut harness = CedarPolicyHarness::from_policy_dir(args.policy_path).await?;
            if let Some(esc) = escalation {
                harness = harness.with_escalation(esc, esc_ttl);
            }
            tracing::info!("Starting Cedar-backed harness server on {:?}", socket_path);
            rpc::serve(harness, &socket_path).await?;
        }
        PolicyEngineKind::Cedarling => {
            tracing::info!("Loading Jans:: policies from {:?}", args.policy_path);
            let engine = CedarlingPolicyEngine::from_policy_dir(&args.policy_path)?;
            let mut harness = CedarlingPolicyHarness::from_default_storage(engine).await?;
            if let Some(esc) = escalation {
                harness = harness.with_escalation(esc, esc_ttl);
            }
            tracing::info!(
                "Starting Cedarling-backed harness server on {:?}",
                socket_path
            );
            rpc::serve(harness, &socket_path).await?;
        }
        PolicyEngineKind::Mandate => {
            let key_path = args
                .mandate_pub_key
                .context("--mandate-pub-key <path> is required when --policy-engine mandate")?;
            let verifying_key = load_verifying_key(&key_path)?;

            tracing::info!(
                "Loading Jans:: ceiling policies from {:?}",
                args.policy_path
            );
            let ceiling = CedarlingPolicyEngine::from_policy_dir(&args.policy_path)?;
            let engine = MandatePolicyEngine::new(ceiling, verifying_key);
            let mut harness = MandatePolicyHarness::from_default_storage(engine).await?;
            if let Some(esc) = escalation {
                harness = harness.with_escalation(esc, esc_ttl);
            }
            tracing::info!(
                "Starting mandate-backed harness server on {:?}",
                socket_path
            );
            rpc::serve(harness, &socket_path).await?;
        }
        PolicyEngineKind::AllowAll => {
            tracing::warn!("Starting harness with allow-all policy engine");
            let harness = PolicyHarness::from_default_storage(AllowAllPolicyEngine).await?;
            tracing::info!("Starting allow-all harness server on {:?}", socket_path);
            rpc::serve(harness, &socket_path).await?;
        }
    }

    Ok(())
}
