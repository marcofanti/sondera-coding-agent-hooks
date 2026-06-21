//! RED — fails to compile until mandate/jwt.rs is implemented.
//!
//! Tests Ed25519 key generation, mandate JWT sign/verify round-trip, and
//! rejection of tampered or expired tokens.

use sondera_harness::mandate::jwt::{MandateClaims, generate_keypair, sign_mandate, verify_mandate}; // → RED

// ─── Key generation ──────────────────────────────────────────────────────────

#[test]
fn keygen_produces_usable_keypair() {
    let (signing_key, verifying_key) = generate_keypair();
    // Signing with the key and verifying with the corresponding key must round-trip.
    let claims = MandateClaims {
        sub: "test-agent".to_string(),
        iss: "sondera-test".to_string(),
        iat: 0,
        exp: u64::MAX,
        policy: "permit (principal, action, resource);".to_string(),
    };
    let token = sign_mandate(&signing_key, &claims).expect("should sign");
    let _ = verify_mandate(&token, &verifying_key).expect("should verify");
}

// ─── Sign / verify round-trip ────────────────────────────────────────────────

#[test]
fn sign_and_verify_round_trip() {
    let (signing_key, verifying_key) = generate_keypair();
    let original = MandateClaims {
        sub: "agent-abc".to_string(),
        iss: "deployment-1".to_string(),
        iat: 1_000_000,
        exp: 9_999_999_999,
        policy: r#"
            @id("mandate-read-only")
            permit (
                principal,
                action in [Jans::Action::"read_file", Jans::Action::"exec_command"],
                resource
            );
        "#.to_string(),
    };

    let token = sign_mandate(&signing_key, &original).expect("sign must succeed");
    let decoded = verify_mandate(&token, &verifying_key).expect("verify must succeed");

    assert_eq!(decoded.sub, original.sub);
    assert_eq!(decoded.iss, original.iss);
    assert_eq!(decoded.exp, original.exp);
    assert_eq!(decoded.policy.trim(), original.policy.trim());
}

// ─── Tampered token rejection ────────────────────────────────────────────────

#[test]
fn tampered_signature_is_rejected() {
    let (signing_key, verifying_key) = generate_keypair();
    let claims = MandateClaims {
        sub: "agent-x".to_string(),
        iss: "deployment-1".to_string(),
        iat: 0,
        exp: u64::MAX,
        policy: "permit (principal, action, resource);".to_string(),
    };

    let mut token = sign_mandate(&signing_key, &claims).expect("sign");
    // Corrupt the last few characters of the token (signature portion)
    let len = token.len();
    token.replace_range(len - 4.., "XXXX");

    let result = verify_mandate(&token, &verifying_key);
    assert!(result.is_err(), "tampered token must be rejected");
}

#[test]
fn wrong_key_is_rejected() {
    let (signing_key, _) = generate_keypair();
    let (_, wrong_verifying_key) = generate_keypair(); // different keypair
    let claims = MandateClaims {
        sub: "agent-x".to_string(),
        iss: "deployment-1".to_string(),
        iat: 0,
        exp: u64::MAX,
        policy: "permit (principal, action, resource);".to_string(),
    };

    let token = sign_mandate(&signing_key, &claims).expect("sign");
    let result = verify_mandate(&token, &wrong_verifying_key);
    assert!(result.is_err(), "token signed by different key must be rejected");
}

// ─── Expired token rejection ─────────────────────────────────────────────────

#[test]
fn expired_token_is_rejected() {
    let (signing_key, verifying_key) = generate_keypair();
    let claims = MandateClaims {
        sub: "agent-x".to_string(),
        iss: "deployment-1".to_string(),
        iat: 0,
        exp: 1, // already expired (Unix epoch + 1 second)
        policy: "permit (principal, action, resource);".to_string(),
    };

    let token = sign_mandate(&signing_key, &claims).expect("sign");
    let result = verify_mandate(&token, &verifying_key);
    assert!(result.is_err(), "expired token must be rejected");
}
