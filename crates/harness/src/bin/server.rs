//! Sondera Harness Server
//!
//! A tarpc-based IPC server that provides policy adjudication services
//! via Unix domain sockets.

use anyhow::{Context as _, Result};
use clap::{Parser, ValueEnum};
use sondera_harness::{
    AllowAllPolicyEngine, CedarPolicyHarness, CedarlingPolicyEngine, CedarlingPolicyHarness,
    MandatePolicyEngine, MandatePolicyHarness, PolicyHarness,
    mandate::jwt::load_verifying_key,
    rpc,
};
use std::path::PathBuf;
use tracing_subscriber::fmt::format::FmtSpan;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging.
    let filter = if args.verbose {
        tracing_subscriber::EnvFilter::new("info,tarpc=warn,sondera=debug")
    } else {
        tracing_subscriber::EnvFilter::new("warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let socket_path = args.socket.unwrap_or_else(rpc::default_socket_path);

    match args.policy_engine {
        PolicyEngineKind::Cedar => {
            tracing::info!("Loading Cedar policies from {:?}", args.policy_path);
            let harness = CedarPolicyHarness::from_policy_dir(args.policy_path).await?;

            tracing::info!("Starting Cedar-backed harness server on {:?}", socket_path);
            rpc::serve(harness, &socket_path).await?;
        }
        PolicyEngineKind::Cedarling => {
            tracing::info!("Loading Jans:: policies from {:?}", args.policy_path);
            let engine = CedarlingPolicyEngine::from_policy_dir(&args.policy_path)?;
            let harness = CedarlingPolicyHarness::from_default_storage(engine).await?;

            tracing::info!("Starting Cedarling-backed harness server on {:?}", socket_path);
            rpc::serve(harness, &socket_path).await?;
        }
        PolicyEngineKind::Mandate => {
            let key_path = args
                .mandate_pub_key
                .context("--mandate-pub-key <path> is required when --policy-engine mandate")?;
            let verifying_key = load_verifying_key(&key_path)?;

            tracing::info!("Loading Jans:: ceiling policies from {:?}", args.policy_path);
            let ceiling = CedarlingPolicyEngine::from_policy_dir(&args.policy_path)?;
            let engine = MandatePolicyEngine::new(ceiling, verifying_key);
            let harness = MandatePolicyHarness::from_default_storage(engine).await?;

            tracing::info!("Starting mandate-backed harness server on {:?}", socket_path);
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
