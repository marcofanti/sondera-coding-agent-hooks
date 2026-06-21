use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MandateClaims {
    /// Agent identifier (JWT `sub`).
    pub sub: String,
    /// Deployment issuer (JWT `iss`).
    pub iss: String,
    /// Issued-at timestamp (Unix seconds).
    pub iat: u64,
    /// Expiry timestamp (Unix seconds).
    pub exp: u64,
    /// Cedar policy text authorizing this agent's actions.
    pub policy: String,
}

// ─── Key generation ──────────────────────────────────────────────────────────

/// Load an Ed25519 verifying key from a file containing 32 raw bytes.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read mandate public key from {:?}", path))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Mandate public key file must contain exactly 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).context("Invalid Ed25519 verifying key bytes")
}

/// Write the raw 32-byte verifying key to a file (used by key management tooling).
pub fn save_verifying_key(key: &VerifyingKey, path: &Path) -> Result<()> {
    std::fs::write(path, key.as_bytes())
        .with_context(|| format!("Failed to write mandate public key to {:?}", path))
}

/// Generate a new Ed25519 keypair for mandate signing.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

// ─── Sign ─────────────────────────────────────────────────────────────────────

/// Sign `claims` and return a compact mandate token: `<b64url_payload>.<b64url_sig>`.
///
/// The signature covers the exact bytes of the base64url-encoded payload,
/// so any modification to either part invalidates the token.
pub fn sign_mandate(signing_key: &SigningKey, claims: &MandateClaims) -> Result<String> {
    let payload_json =
        serde_json::to_vec(claims).context("Failed to serialize mandate claims")?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let sig = signing_key.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(format!("{payload_b64}.{sig_b64}"))
}

// ─── Verify ──────────────────────────────────────────────────────────────────

/// Verify a mandate token and return the decoded claims.
///
/// Returns `Err` if:
/// - The token format is malformed.
/// - The Ed25519 signature is invalid.
/// - The token has expired (`exp < now`).
pub fn verify_mandate(token: &str, verifying_key: &VerifyingKey) -> Result<MandateClaims> {
    let (payload_b64, sig_b64) = token
        .split_once('.')
        .context("Mandate token must contain exactly one '.'")?;

    // Verify signature over the payload portion
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .context("Failed to base64-decode mandate signature")?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Mandate signature must be 64 bytes"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
    verifying_key
        .verify(payload_b64.as_bytes(), &sig)
        .context("Mandate signature verification failed")?;

    // Decode and deserialize payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .context("Failed to base64-decode mandate payload")?;
    let claims: MandateClaims =
        serde_json::from_slice(&payload_bytes).context("Failed to deserialize mandate claims")?;

    // Check expiry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    anyhow::ensure!(claims.exp > now, "Mandate token has expired");

    Ok(claims)
}
