//! Sondera Harness — policy adjudication engine for AI coding agents.
//!
//! This crate is the core runtime for the Sondera governance platform. It
//! evaluates Cedar authorization policies against trajectory events produced
//! by AI agents (Claude, Cursor, Copilot, Gemini) and returns Allow / Deny /
//! Escalate decisions.
//!
//! # Architecture
//!
//! - [`Harness`] trait: the adjudication interface (implement for custom backends).
//! - [`PolicyEngine`]: pluggable authorization boundary for Cedar or custom
//!   policy engines.
//! - [`CedarPolicyHarness`]: default production harness backed by Cedar, YARA-X
//!   signature scanning, Ollama-based data classification, and policy evaluation.
//! - [`rpc`]: tarpc IPC layer — the harness server exposes adjudication over
//!   Unix domain sockets so hook processes can call it without linking the
//!   full engine.
//! - [`storage`]: persistence via Fjall (entity store) and Turso/libsql
//!   (trajectory events).
//!
//! # License
//!
//! MIT — see LICENSE in the repository root.

mod cedar;
pub mod cedarling;
pub mod escalation;
mod harness;
pub mod mandate;
pub mod observability;
mod policy_engine;
mod policy_harness;
pub mod rpc;
pub mod storage;
mod types;

// Re-export commonly used types for convenience
pub use types::*;

// Public exports for Harness API.
pub use cedar::CedarPolicyEngine;
pub use cedar::entity::{EntityBuilder, Trajectory, euid, json_to_restricted_expr};
pub use cedarling::CedarlingPolicyEngine;
pub use harness::Harness;
pub use mandate::MandatePolicyEngine;
pub use policy_engine::{AllowAllPolicyEngine, PolicyEngine, PolicyEvaluation, SyncAuthorize};
pub use policy_harness::{
    CedarPolicyHarness, CedarlingPolicyHarness, MandatePolicyHarness, PolicyHarness,
};
pub use rpc::HarnessClient;
pub use sondera_information_flow_control::Label;

// Re-export Turso storage types
pub use storage::turso::{TrajectoryStats, TrajectoryStore, get_default_db_path};

// Re-export escalation API state for server wiring
pub use escalation::api::AdminState;
