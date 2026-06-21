//! RED — fails to compile until CedarlingPolicyEngine is implemented.
//!
//! Verifies that schema.json loads cleanly and contains the expected
//! Jans:: entity types and actions.

use cedar_policy::Decision;
use sondera_harness::CedarlingPolicyEngine; // does not exist yet → RED
use std::path::PathBuf;

const POLICIES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies");

fn engine() -> CedarlingPolicyEngine {
    CedarlingPolicyEngine::from_policy_dir(PathBuf::from(POLICIES_DIR))
        .expect("policies dir must load")
}

#[test]
fn schema_loads_without_error() {
    let _ = engine();
}

#[test]
fn schema_contains_jans_workload() {
    let e = engine();
    let names: Vec<String> = e.schema().entity_types().map(|t| t.to_string()).collect();
    assert!(
        names.iter().any(|n| n.contains("Workload")),
        "schema must contain Jans::Workload, got: {names:?}"
    );
}

#[test]
fn schema_contains_jans_shell_api_tool() {
    let e = engine();
    let names: Vec<String> = e.schema().entity_types().map(|t| t.to_string()).collect();
    for expected in ["Shell", "API", "Tool"] {
        assert!(
            names.iter().any(|n| n.contains(expected)),
            "schema must contain Jans::{expected}, got: {names:?}"
        );
    }
}

#[test]
fn schema_contains_jans_trajectory_file_message() {
    let e = engine();
    let names: Vec<String> = e.schema().entity_types().map(|t| t.to_string()).collect();
    for expected in ["Trajectory", "File", "Message"] {
        assert!(
            names.iter().any(|n| n.contains(expected)),
            "schema must contain Jans::{expected}, got: {names:?}"
        );
    }
}

#[test]
fn schema_contains_jans_label_taint() {
    let e = engine();
    let names: Vec<String> = e.schema().entity_types().map(|t| t.to_string()).collect();
    for expected in ["Label", "Taint"] {
        assert!(
            names.iter().any(|n| n.contains(expected)),
            "schema must contain Jans::{expected}, got: {names:?}"
        );
    }
}

#[test]
fn schema_contains_exec_command_and_call_api() {
    let e = engine();
    let actions: Vec<String> = e.schema().actions().map(|a| a.to_string()).collect();
    for expected in ["exec_command", "call_api", "call_tool"] {
        assert!(
            actions.iter().any(|a| a.contains(expected)),
            "schema must contain action {expected:?}, got: {actions:?}"
        );
    }
}

#[test]
fn schema_contains_all_file_actions() {
    let e = engine();
    let actions: Vec<String> = e.schema().actions().map(|a| a.to_string()).collect();
    for expected in ["read_file", "write_file", "edit_file", "delete_file", "observe_file_result"] {
        assert!(
            actions.iter().any(|a| a.contains(expected)),
            "schema must contain action {expected:?}, got: {actions:?}"
        );
    }
}

#[test]
fn schema_contains_observe_actions() {
    let e = engine();
    let actions: Vec<String> = e.schema().actions().map(|a| a.to_string()).collect();
    for expected in ["observe_prompt", "observe_exec_output", "observe_api_output", "observe_tool_output"] {
        assert!(
            actions.iter().any(|a| a.contains(expected)),
            "schema must contain action {expected:?}, got: {actions:?}"
        );
    }
}

// Confirm engine is Send + Sync (required for PolicyEngine trait)
fn _assert_send_sync<T: Send + Sync>() {}
#[test]
fn engine_is_send_sync() {
    _assert_send_sync::<CedarlingPolicyEngine>();
    // Just ensure it compiles — Decision is used to suppress the import warning
    let _ = Decision::Allow;
}
