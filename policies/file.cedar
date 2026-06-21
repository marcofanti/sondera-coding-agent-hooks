// ═══════════════════════════════════════════════════════
// Sondera – File-Specific Governance Policies
// ═══════════════════════════════════════════════════════
//
// Extension-aware policies that combine information flow
// control (IFC), YARA signature detection, and secure code
// generation policy categories (OWASP/CWE) to enforce
// fine-grained governance on file operations.
//
// Namespace: Jans:: (aligned with jans-cedarling / carapace)
//
// ─── Available Context ──────────────────────────────────
//
//   read_file / write_file / edit_file / delete_file (pre-exec):
//     resource  = Jans::File { label: Jans::Label }
//     context   = { workspace, signature, policy, label,
//                   path, operation, trajectory }
//
//   observe_file_result (post-exec):
//     resource  = Jans::File { label: Jans::Label }
//     context   = { workspace, signature, policy, label,
//                   path, content, trajectory }
//     trajectory = { label, step_count, taints }  ← use for taint checks
//
//   policy.violations contains Secure Code Generation (SC) codes:
//     SC2 = Injection        (CWE-78/89/79, OWASP A03:2021)
//     SC3 = Secrets Exposure (CWE-798/200,  OWASP A02:2021)
//     SC4 = Path Traversal   (CWE-22,       OWASP A01:2021)
//     SC5 = Insecure Deser.  (CWE-502,      OWASP A08:2021)
//     SC6 = Weak Crypto      (CWE-327/330,  OWASP A02:2021)
//     SC7 = Broken AuthZ     (CWE-284/862,  OWASP A01:2021)

// ═══════════════════════════════════════════════════════
// §1  Information Flow Control – Label-Based Guards
// ═══════════════════════════════════════════════════════
//
// Bell-LaPadula "no write down": content at a higher
// sensitivity label must not flow into a file at a lower
// label. resource.label is the File entity's label;
// context.label is the sensitivity of the content being
// written (from IFC classifier).

@id("forbid-file-write-hc-to-public")
@description("IFC: block writing highly confidential content to a Public-labeled file — prevents data spillage.")
@taint("exfiltration")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.label == Jans::Label::"HighlyConfidential" &&
    resource.label == Jans::Label::"Public"
};

@id("forbid-file-write-hc-to-internal")
@description("IFC: block writing highly confidential content to an Internal-labeled file — prevents data spillage.")
@taint("exfiltration")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.label == Jans::Label::"HighlyConfidential" &&
    resource.label == Jans::Label::"Internal"
};

@id("forbid-file-write-confidential-to-public")
@description("IFC: block writing confidential content to a Public-labeled file — prevents data spillage.")
@taint("exfiltration")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.label == Jans::Label::"Confidential" &&
    resource.label == Jans::Label::"Public"
};

// ─── IFC: taint-aware post-read guards ───
//
// After a file read the trajectory inherits the file's label.
// Block further processing when the trajectory is already
// tainted — limits blast radius. Taint state is in
// context.trajectory (resource is Jans::File, not Trajectory).

@id("forbid-file-result-hc-on-exfil-tainted-trajectory")
@description("IFC: block highly confidential file results when trajectory is tainted with exfiltration — limits blast radius.")
forbid (
    principal,
    action == Jans::Action::"observe_file_result",
    resource
) when {
    context.label == Jans::Label::"HighlyConfidential" &&
    context.trajectory.taints.contains(Jans::Taint::"exfiltration")
};

@id("forbid-file-result-confidential-on-exfil-tainted-trajectory")
@description("IFC: block confidential file results when trajectory is tainted with exfiltration.")
forbid (
    principal,
    action == Jans::Action::"observe_file_result",
    resource
) when {
    context.label == Jans::Label::"Confidential" &&
    context.trajectory.taints.contains(Jans::Taint::"exfiltration")
};

// ═══════════════════════════════════════════════════════
// §2  Credential & Secret File Guards
// ═══════════════════════════════════════════════════════

// ─── Private keys & keystores ───

@id("forbid-private-key-read")
@description("Block reading private key files — agent should never access raw key material.")
@taint("credential_access")
forbid (
    principal,
    action == Jans::Action::"read_file",
    resource
) when {
    context.path like "*.pem" ||
    context.path like "*.key" ||
    context.path like "*.p12" ||
    context.path like "*.pfx" ||
    context.path like "*.jks"
};

@id("forbid-private-key-write")
@description("Block writing private key files — agent should not generate or overwrite key material.")
@taint("credential_access")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.pem" ||
    context.path like "*.key" ||
    context.path like "*.p12" ||
    context.path like "*.pfx" ||
    context.path like "*.jks"
};

@id("forbid-private-key-delete")
@description("Block deleting private key files — key material must not be destroyed by the agent.")
forbid (
    principal,
    action == Jans::Action::"delete_file",
    resource
) when {
    context.path like "*.pem" ||
    context.path like "*.key" ||
    context.path like "*.p12" ||
    context.path like "*.pfx" ||
    context.path like "*.jks"
};

// ─── Environment & config files with secrets ───

@id("forbid-env-file-write-with-secrets")
@description("Block writing secrets into .env files — detected by YARA secrets_detection rules.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.env" &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-env-file-write-with-credentials")
@description("Block writing credentials into .env files — detected by YARA credential_access rules.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.env" &&
    context.signature.categories.contains("credential_access")
};

// ─── Secrets in source code ───

@id("forbid-source-write-secrets-python")
@description("Block writing secrets into Python source files.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.py" &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-source-write-secrets-javascript")
@description("Block writing secrets into JavaScript/TypeScript source files.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts" ||
     context.path like "*.jsx" || context.path like "*.tsx") &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-source-write-secrets-go")
@description("Block writing secrets into Go source files.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.go" &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-source-write-secrets-rust")
@description("Block writing secrets into Rust source files.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.rs" &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-source-write-secrets-java")
@description("Block writing secrets into Java source files.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.java" &&
    context.signature.categories.contains("secrets_detection")
};

// ─── Secrets in config serialization formats ───

@id("forbid-config-write-secrets-yaml")
@description("Block writing secrets into YAML config files.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.yaml" || context.path like "*.yml") &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-config-write-secrets-json")
@description("Block writing secrets into JSON config files.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.json" &&
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-config-write-secrets-toml")
@description("Block writing secrets into TOML config files.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.toml" &&
    context.signature.categories.contains("secrets_detection")
};

// ═══════════════════════════════════════════════════════
// §3  Obfuscation Detection – Script & Shell Files
// ═══════════════════════════════════════════════════════

@id("forbid-script-write-obfuscation")
@description("Block writing obfuscated content into shell scripts.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.sh" || context.path like "*.bash" ||
     context.path like "*.zsh") &&
    context.signature.categories.contains("obfuscation")
};

@id("forbid-python-write-obfuscation")
@description("Block writing obfuscated content into Python files.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.py" &&
    context.signature.categories.contains("obfuscation")
};

@id("forbid-js-write-obfuscation")
@description("Block writing obfuscated content into JavaScript/TypeScript files.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts" ||
     context.path like "*.jsx" || context.path like "*.tsx") &&
    context.signature.categories.contains("obfuscation")
};

@id("forbid-php-write-obfuscation")
@description("Block writing obfuscated content into PHP files.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.php" &&
    context.signature.categories.contains("obfuscation")
};

// ═══════════════════════════════════════════════════════
// §4  SC2 – Injection (CWE-78/89/79, OWASP A03:2021)
// ═══════════════════════════════════════════════════════

@id("forbid-injection-sql")
@description("SC2: block writing SQL files with injection vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.sql" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-python")
@description("SC2: block writing Python files with injection vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.py" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-javascript")
@description("SC2: block writing JavaScript/TypeScript files with injection vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts" ||
     context.path like "*.jsx" || context.path like "*.tsx") &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-php")
@description("SC2: block writing PHP files with injection vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.php" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-go")
@description("SC2: block writing Go files with injection vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.go" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-ruby")
@description("SC2: block writing Ruby files with injection vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.rb" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-rust")
@description("SC2: block writing Rust files with injection vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.rs" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-java")
@description("SC2: block writing Java files with injection vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.java" &&
    context.policy.violations.contains("SC2")
};

@id("forbid-injection-html-templates")
@description("SC2: block writing HTML template files with XSS vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.html" || context.path like "*.svelte" ||
     context.path like "*.vue"  || context.path like "*.ejs" ||
     context.path like "*.hbs") &&
    context.policy.violations.contains("SC2")
};

// ═══════════════════════════════════════════════════════
// §5  SC3 – Secrets Exposure (CWE-798/200, OWASP A02:2021)
// ═══════════════════════════════════════════════════════

@id("forbid-secrets-exposure-env")
@description("SC3: block writing .env files with hardcoded secrets.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.env" &&
    context.policy.violations.contains("SC3")
};

@id("forbid-secrets-exposure-yaml-config")
@description("SC3: block writing YAML config files with hardcoded secrets.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.yaml" || context.path like "*.yml") &&
    context.policy.violations.contains("SC3")
};

@id("forbid-secrets-exposure-docker")
@description("SC3: block writing Dockerfiles with hardcoded secrets (ARG/ENV with credentials).")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*Dockerfile"           ||
     context.path like "*.dockerfile"          ||
     context.path like "*docker-compose*.yml"  ||
     context.path like "*docker-compose*.yaml") &&
    context.policy.violations.contains("SC3")
};

@id("forbid-secrets-exposure-terraform")
@description("SC3: block writing Terraform/IaC files with hardcoded secrets.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.tf" || context.path like "*.tfvars") &&
    context.policy.violations.contains("SC3")
};

@id("forbid-secrets-exposure-ci-config")
@description("SC3: block writing CI/CD config files with hardcoded secrets.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.github/workflows/*.yml"  ||
     context.path like "*.github/workflows/*.yaml" ||
     context.path like "*.gitlab-ci.yml"           ||
     context.path like "*Jenkinsfile") &&
    context.policy.violations.contains("SC3")
};

// ═══════════════════════════════════════════════════════
// §6  SC5 – Insecure Deserialization (CWE-502, OWASP A08)
// ═══════════════════════════════════════════════════════

@id("forbid-insecure-deser-python")
@description("SC5: block writing Python files with insecure deserialization (pickle.load, yaml.load).")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.py" &&
    context.policy.violations.contains("SC5")
};

@id("forbid-insecure-deser-yaml")
@description("SC5: block writing YAML files with unsafe loader directives.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.yaml" || context.path like "*.yml") &&
    context.policy.violations.contains("SC5")
};

@id("forbid-insecure-deser-ruby")
@description("SC5: block writing Ruby files with insecure deserialization (Marshal.load).")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.rb" &&
    context.policy.violations.contains("SC5")
};

@id("forbid-insecure-deser-java")
@description("SC5: block writing Java files with insecure deserialization (ObjectInputStream).")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.java" &&
    context.policy.violations.contains("SC5")
};

@id("forbid-insecure-deser-php")
@description("SC5: block writing PHP files with insecure deserialization (unserialize on user input).")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.php" &&
    context.policy.violations.contains("SC5")
};

// ═══════════════════════════════════════════════════════
// §7  SC6 – Weak Cryptography (CWE-327/330, OWASP A02)
// ═══════════════════════════════════════════════════════

@id("forbid-weak-crypto-python")
@description("SC6: block writing Python files with weak cryptography (md5, sha1, random for tokens).")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.py" &&
    context.policy.violations.contains("SC6")
};

@id("forbid-weak-crypto-javascript")
@description("SC6: block writing JavaScript/TypeScript files with weak cryptography.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts") &&
    context.policy.violations.contains("SC6")
};

@id("forbid-weak-crypto-go")
@description("SC6: block writing Go files with weak cryptography (crypto/md5, math/rand for tokens).")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.go" &&
    context.policy.violations.contains("SC6")
};

@id("forbid-weak-crypto-rust")
@description("SC6: block writing Rust files with weak cryptography (md5 crate for auth).")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.rs" &&
    context.policy.violations.contains("SC6")
};

@id("forbid-weak-crypto-java")
@description("SC6: block writing Java files with weak cryptography (MessageDigest MD5/SHA1, DES, ECB mode).")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.java" &&
    context.policy.violations.contains("SC6")
};

// ═══════════════════════════════════════════════════════
// §8  SC7 – Broken Access Control (CWE-284/862, OWASP A01)
// ═══════════════════════════════════════════════════════

@id("forbid-broken-authz-python")
@description("SC7: block writing Python API files with broken access control.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.py" &&
    context.policy.violations.contains("SC7")
};

@id("forbid-broken-authz-javascript")
@description("SC7: block writing JavaScript/TypeScript API files with broken access control.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts") &&
    context.policy.violations.contains("SC7")
};

@id("forbid-broken-authz-go")
@description("SC7: block writing Go API files with broken access control.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.go" &&
    context.policy.violations.contains("SC7")
};

@id("forbid-broken-authz-java")
@description("SC7: block writing Java API files with broken access control.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.java" &&
    context.policy.violations.contains("SC7")
};

@id("forbid-broken-authz-rust")
@description("SC7: block writing Rust API files with broken access control.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.rs" &&
    context.policy.violations.contains("SC7")
};

// ═══════════════════════════════════════════════════════
// §9  SC4 – Path Traversal (CWE-22, OWASP A01:2021)
// ═══════════════════════════════════════════════════════

@id("forbid-path-traversal-python")
@description("SC4: block writing Python files with path traversal vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.py" &&
    context.policy.violations.contains("SC4")
};

@id("forbid-path-traversal-javascript")
@description("SC4: block writing JavaScript/TypeScript files with path traversal vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*.js" || context.path like "*.ts") &&
    context.policy.violations.contains("SC4")
};

@id("forbid-path-traversal-go")
@description("SC4: block writing Go files with path traversal vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.go" &&
    context.policy.violations.contains("SC4")
};

@id("forbid-path-traversal-java")
@description("SC4: block writing Java files with path traversal vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.java" &&
    context.policy.violations.contains("SC4")
};

@id("forbid-path-traversal-rust")
@description("SC4: block writing Rust files with path traversal vulnerabilities.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*.rs" &&
    context.policy.violations.contains("SC4")
};

// ═══════════════════════════════════════════════════════
// §10  Post-Read Guards – Indirect Injection via Files
// ═══════════════════════════════════════════════════════

@id("forbid-file-result-injection-yaml")
@description("Block YAML file content containing prompt injection — prevents indirect injection via config files.")
forbid (
    principal,
    action == Jans::Action::"observe_file_result",
    resource
) when {
    (context.path like "*.yaml" || context.path like "*.yml") &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};

@id("forbid-file-result-injection-json")
@description("Block JSON file content containing prompt injection — prevents indirect injection via data files.")
forbid (
    principal,
    action == Jans::Action::"observe_file_result",
    resource
) when {
    context.path like "*.json" &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};

@id("forbid-file-result-injection-markdown")
@description("Block Markdown file content containing prompt injection — prevents indirect injection via documentation.")
forbid (
    principal,
    action == Jans::Action::"observe_file_result",
    resource
) when {
    (context.path like "*.md" || context.path like "*.mdx") &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};

@id("forbid-file-result-injection-csv")
@description("Block CSV/TSV file content containing prompt injection — prevents indirect injection via data imports.")
forbid (
    principal,
    action == Jans::Action::"observe_file_result",
    resource
) when {
    (context.path like "*.csv" || context.path like "*.tsv") &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};
