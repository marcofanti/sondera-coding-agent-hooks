use anyhow::{Context as _, Result};
use clap::Subcommand;
use sondera_harness::mandate::jwt::{
    generate_keypair, load_verifying_key, save_verifying_key, sign_mandate, verify_mandate,
    MandateClaims,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Subcommand, Debug)]
pub enum MandateAction {
    /// Generate a new Ed25519 keypair for mandate signing.
    Keygen {
        /// Write the signing key (private, 32 bytes) to this path.
        #[arg(long)]
        signing_key: std::path::PathBuf,
        /// Write the verifying key (public, 32 bytes) to this path.
        #[arg(long)]
        verifying_key: std::path::PathBuf,
    },
    /// Sign a Cedar policy file and print a compact mandate JWT to stdout.
    Sign {
        /// Path to the Ed25519 signing key file (32 raw bytes).
        #[arg(long)]
        signing_key: std::path::PathBuf,
        /// Agent ID to embed in the mandate JWT (`sub` claim).
        #[arg(long)]
        agent_id: String,
        /// Path to the Cedar policy file to embed in the mandate.
        #[arg(long)]
        policy: std::path::PathBuf,
        /// Issuer string to embed in the mandate JWT (`iss` claim).
        #[arg(long, default_value = "sondera")]
        issuer: String,
        /// Token lifetime in seconds.
        #[arg(long, default_value_t = 3600)]
        exp_secs: u64,
    },
    /// Verify a mandate JWT read from stdin and print the decoded claims as JSON.
    Verify {
        /// Path to the Ed25519 verifying key file (32 raw bytes).
        #[arg(long)]
        verifying_key: std::path::PathBuf,
    },
}

pub fn handle_mandate(action: &MandateAction) -> Result<()> {
    match action {
        MandateAction::Keygen { signing_key, verifying_key } => {
            let (sk, vk) = generate_keypair();
            std::fs::write(signing_key, sk.as_bytes())
                .with_context(|| format!("write signing key to {:?}", signing_key))?;
            save_verifying_key(&vk, verifying_key)?;
            eprintln!("Signing key:    {:?}", signing_key);
            eprintln!("Verifying key:  {:?}", verifying_key);
            println!("Keypair generated.");
            Ok(())
        }

        MandateAction::Sign { signing_key, agent_id, policy, issuer, exp_secs } => {
            let sk_bytes = std::fs::read(signing_key)
                .with_context(|| format!("read signing key {:?}", signing_key))?;
            let sk_arr: [u8; 32] = sk_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Signing key must be exactly 32 bytes"))?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&sk_arr);

            let policy_text = std::fs::read_to_string(policy)
                .with_context(|| format!("read policy file {:?}", policy))?;

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let claims = MandateClaims {
                sub:    agent_id.clone(),
                iss:    issuer.clone(),
                iat:    now,
                exp:    now + exp_secs,
                policy: policy_text,
            };

            let token = sign_mandate(&sk, &claims)?;
            println!("{token}");
            Ok(())
        }

        MandateAction::Verify { verifying_key } => {
            let vk = load_verifying_key(verifying_key)?;
            let token = {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf).context("read token from stdin")?;
                buf.trim().to_string()
            };
            let claims = verify_mandate(&token, &vk)?;
            println!("{}", serde_json::to_string_pretty(&claims)?);
            Ok(())
        }
    }
}
