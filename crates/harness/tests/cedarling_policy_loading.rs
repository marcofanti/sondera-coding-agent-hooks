//! RED — fails to compile until CedarlingPolicyEngine / CedarlingPolicyHarness are implemented.
//!
//! Verifies that all .cedar policy files load without errors and that
//! the expected policy IDs are present in the policy set.

use sondera_harness::CedarlingPolicyEngine; // does not exist yet → RED
use std::path::PathBuf;

const POLICIES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies");

fn engine() -> CedarlingPolicyEngine {
    CedarlingPolicyEngine::from_policy_dir(PathBuf::from(POLICIES_DIR))
        .expect("policies dir must load")
}

#[test]
fn loads_all_cedar_files() {
    // If any .cedar file has a syntax error the constructor returns Err
    let _ = engine();
}

#[test]
fn default_permit_policy_is_present() {
    let e = engine();
    let policy = e
        .policy_set()
        .policy(&"default-permit".parse().unwrap());
    assert!(
        policy.is_some(),
        "policy set must contain @id(\"default-permit\")"
    );
}

#[test]
fn base_forbid_policies_are_present() {
    let e = engine();
    let ps = e.policy_set();
    for id in [
        "forbid-critical-severity",
        "forbid-prompt-injection",
        "forbid-shell-policy-violation",
        "forbid-webfetch-policy-violation",
        "forbid-file-policy-violation",
    ] {
        assert!(
            ps.policy(&id.parse().unwrap()).is_some(),
            "policy set must contain @id({id:?})"
        );
    }
}

#[test]
fn destructive_policies_are_present() {
    let e = engine();
    let ps = e.policy_set();
    for id in [
        "forbid-rm-rf",
        "forbid-git-force-push",
        "forbid-terraform-destroy",
        "forbid-drop-database",
    ] {
        assert!(
            ps.policy(&id.parse().unwrap()).is_some(),
            "policy set must contain @id({id:?})"
        );
    }
}

#[test]
fn ifc_policies_are_present() {
    let e = engine();
    let ps = e.policy_set();
    for id in [
        "ifc-forbid-webfetch-highly-confidential",
        "ifc-forbid-shell-network-highly-confidential",
        "ifc-forbid-confidential-trajectory-runaway",
    ] {
        assert!(
            ps.policy(&id.parse().unwrap()).is_some(),
            "policy set must contain @id({id:?})"
        );
    }
}

#[test]
fn supply_chain_policies_are_present() {
    let e = engine();
    let ps = e.policy_set();
    for id in [
        "forbid-suspicious-package-install-obfuscated",
        "forbid-dependency-file-injection-attack",
        "forbid-suspicious-registry-fetch-exfiltration",
    ] {
        assert!(
            ps.policy(&id.parse().unwrap()).is_some(),
            "policy set must contain @id({id:?})"
        );
    }
}

#[test]
fn rejects_nonexistent_directory() {
    let result = CedarlingPolicyEngine::from_policy_dir("/nonexistent/policies/dir");
    assert!(result.is_err(), "must fail for nonexistent directory");
}
