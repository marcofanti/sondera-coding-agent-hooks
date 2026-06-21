// ═══════════════════════════════════════════════════════
// Sondera – Base Governance Policies for Coding Agents
// ═══════════════════════════════════════════════════════
//
// Applies to all coding agents (Claude Code, Cursor, Copilot, etc.).
//
// Strategy: default-permit with targeted forbid overrides.
// Cedar evaluates all policies; a single matching forbid wins.
//
// Namespace: Jans:: (aligned with jans-cedarling / carapace)
//
// ─── Actions & Context ────────────────────────────────
//
//   Jans::Action::"observe_prompt"
//     principal = Jans::Workload | Jans::User
//     resource  = Jans::Message (in Jans::Trajectory)
//     context   = { workspace, signature, label }
//
//   Jans::Action::"exec_command"
//     principal = Jans::Workload | Jans::User
//     resource  = Jans::Shell   (e.g. Shell::"git")
//     context   = { workspace, signature, policy, label,
//                   command, working_dir, trajectory }
//
//   Jans::Action::"observe_exec_output"
//     resource  = Jans::Shell
//     context   = { workspace, signature, policy, label,
//                   command, exit_code, stdout, stderr,
//                   working_dir, trajectory }
//
//   Jans::Action::"call_api"
//     resource  = Jans::API    (e.g. API::"api.github.com")
//     context   = { workspace, signature, policy, label,
//                   url, prompt, trajectory }
//
//   Jans::Action::"observe_api_output"
//     resource  = Jans::API
//     context   = { workspace, signature, policy, label,
//                   url, code, result, trajectory }
//
//   Jans::Action::"call_tool"
//     resource  = Jans::Tool   (e.g. Tool::"read_file")
//     context   = { workspace, trajectory }
//
//   Jans::Action::"observe_tool_output"
//     resource  = Jans::Tool
//     context   = { workspace, signature, policy, label,
//                   content, trajectory }
//
//   Jans::Action::"read_file" / "write_file" / "edit_file" / "delete_file"
//     resource  = Jans::File
//     context   = { workspace, signature, policy, label,
//                   path, operation, trajectory }
//
//   Jans::Action::"observe_file_result"
//     resource  = Jans::File
//     context   = { workspace, signature, policy, label,
//                   path, content, trajectory }
//
// ─── Shared Context Types ─────────────────────────────
//
//   workspace  = { cwd, permission_mode, transcript_path }
//   signature  = { matches: Long, categories: Set<String>,
//                  severity: Long }
//                  Severity: 0=None 1=Low 2=Medium 3=High 4=Critical
//   policy     = { compliant: Bool, violations: Set<String> }
//   label      = Jans::Label entity (e.g. Jans::Label::"HighlyConfidential")
//   trajectory = { label: Jans::Label, step_count: Long,
//                  taints: Set<Jans::Taint> }

// ─── Baseline ───────────────────────────────────────

@id("default-permit")
@description("Permit all actions unless a forbid below fires.")
permit (principal, action, resource);

// ═══════════════════════════════════════════════════════
// §1  Prompt – Signature-Based Threat Detection
// ═══════════════════════════════════════════════════════

@id("forbid-critical-severity")
@description("Block any prompt where YARA signatures flagged critical severity (4).")
forbid (
    principal,
    action == Jans::Action::"observe_prompt",
    resource
) when {
    context.signature.severity >= 4
};

@id("forbid-prompt-injection")
@description("Block prompts containing prompt injection patterns (role manipulation, system override, ignore instructions).")
forbid (
    principal,
    action == Jans::Action::"observe_prompt",
    resource
) when {
    context.signature.categories.contains("prompt_injection")
};

@id("forbid-indirect-injection")
@description("Block prompts containing indirect injection via embedded document instructions.")
forbid (
    principal,
    action == Jans::Action::"observe_prompt",
    resource
) when {
    context.signature.categories.contains("indirect_injection")
};

@id("forbid-credential-access-prompt")
@description("Block prompts that attempt to access or extract credentials.")
@taint("credential_access")
forbid (
    principal,
    action == Jans::Action::"observe_prompt",
    resource
) when {
    context.signature.categories.contains("credential_access")
};

@id("forbid-data-exfiltration-prompt")
@description("Block prompts with data exfiltration patterns.")
@taint("exfiltration")
forbid (
    principal,
    action == Jans::Action::"observe_prompt",
    resource
) when {
    context.signature.categories.contains("exfiltration")
};

@id("forbid-command-injection-prompt")
@description("Block prompts containing command injection patterns.")
forbid (
    principal,
    action == Jans::Action::"observe_prompt",
    resource
) when {
    context.signature.categories.contains("command_injection")
};

@id("forbid-defense-evasion-prompt")
@description("Block prompts using obfuscation to evade detection (base64, HTML entities, homoglyphs).")
forbid (
    principal,
    action == Jans::Action::"observe_prompt",
    resource
) when {
    context.signature.categories.contains("defense_evasion")
};

@id("forbid-tool-abuse-prompt")
@description("Block prompts attempting to abuse agent tools via injection.")
forbid (
    principal,
    action == Jans::Action::"observe_prompt",
    resource
) when {
    context.signature.categories.contains("tool_abuse")
};

// ═══════════════════════════════════════════════════════
// §2  Prompt – Sensitivity-Gated Controls
// ═══════════════════════════════════════════════════════

@id("forbid-highly-confidential-with-threats")
@description("Block prompts on highly confidential data when any YARA signature matched.")
forbid (
    principal,
    action == Jans::Action::"observe_prompt",
    resource
) when {
    context.label == Jans::Label::"HighlyConfidential" &&
    context.signature.matches > 0
};

@id("forbid-confidential-high-severity")
@description("Block prompts on confidential data when YARA severity is high or above.")
forbid (
    principal,
    action == Jans::Action::"observe_prompt",
    resource
) when {
    context.label == Jans::Label::"Confidential" &&
    context.signature.severity >= 3
};

// ═══════════════════════════════════════════════════════
// §3  Shell Command – Pre-Execution Gates
// ═══════════════════════════════════════════════════════

@id("forbid-shell-policy-violation")
@description("Block shell commands that violate the policy model (destructive, unsafe, etc.).")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    !context.policy.compliant
};

@id("forbid-shell-command-injection")
@description("Block shell commands containing injection patterns (chaining, reverse shells, cron manipulation).")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    context.signature.categories.contains("command_injection")
};

@id("forbid-shell-obfuscation")
@description("Block shell commands using obfuscation to hide intent (base64, hex, concatenation).")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    context.signature.categories.contains("obfuscation")
};

@id("forbid-shell-exfiltration")
@description("Block shell commands with data exfiltration patterns (curl to paste sites, DNS tunneling).")
@taint("exfiltration")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    context.signature.categories.contains("exfiltration")
};

@id("forbid-shell-credential-access")
@description("Block shell commands accessing sensitive credential files or cloud configs.")
@taint("credential_access")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    context.signature.categories.contains("credential_access")
};

@id("forbid-shell-critical-severity")
@description("Block shell commands that trigger critical-severity YARA rules.")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    context.signature.severity >= 4
};

// ─── IFC: prevent exfiltration of sensitive data via shell ───

@id("forbid-shell-highly-confidential")
@description("Block shell commands when trajectory carries highly confidential data — prevents exfiltration via shell.")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    context.label == Jans::Label::"HighlyConfidential" &&
    context.signature.categories.contains("exfiltration")
};

// ═══════════════════════════════════════════════════════
// §4  Shell Command Output – Post-Execution Guards
// ═══════════════════════════════════════════════════════

@id("forbid-shell-output-secrets")
@description("Block when command output contains detected secrets (API keys, tokens, private keys).")
forbid (
    principal,
    action == Jans::Action::"observe_exec_output",
    resource
) when {
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-shell-output-credential-leak")
@description("Block when command output exposes credentials (memory dumps, cloud creds).")
forbid (
    principal,
    action == Jans::Action::"observe_exec_output",
    resource
) when {
    context.signature.categories.contains("credential_access")
};

@id("forbid-shell-output-policy-violation")
@description("Block when command output violates the policy model.")
forbid (
    principal,
    action == Jans::Action::"observe_exec_output",
    resource
) when {
    !context.policy.compliant
};

@id("forbid-shell-output-exfiltration-evidence")
@description("Block when command output shows evidence of data exfiltration (network sends, paste site responses).")
forbid (
    principal,
    action == Jans::Action::"observe_exec_output",
    resource
) when {
    context.signature.categories.contains("exfiltration")
};

// ═══════════════════════════════════════════════════════
// §5  Web / API Fetch – Pre-Execution Gates
// ═══════════════════════════════════════════════════════

@id("forbid-webfetch-policy-violation")
@description("Block web fetches that violate the policy model.")
forbid (
    principal,
    action == Jans::Action::"call_api",
    resource
) when {
    !context.policy.compliant
};

@id("forbid-webfetch-exfiltration")
@description("Block web fetches to exfiltration targets (paste sites, suspicious external domains).")
forbid (
    principal,
    action == Jans::Action::"call_api",
    resource
) when {
    context.signature.categories.contains("exfiltration")
};

@id("forbid-webfetch-obfuscation")
@description("Block web fetches using obfuscated URLs or prompts to evade detection.")
forbid (
    principal,
    action == Jans::Action::"call_api",
    resource
) when {
    context.signature.categories.contains("obfuscation")
};

@id("forbid-webfetch-critical-severity")
@description("Block web fetches that trigger critical-severity YARA rules.")
forbid (
    principal,
    action == Jans::Action::"call_api",
    resource
) when {
    context.signature.severity >= 4
};

// ─── IFC: prevent data leakage via web requests ───

@id("forbid-webfetch-highly-confidential")
@description("Block all web fetches when trajectory is tainted with highly confidential data — prevents HTTP exfiltration.")
forbid (
    principal,
    action == Jans::Action::"call_api",
    resource
) when {
    context.trajectory.label == Jans::Label::"HighlyConfidential" &&
    context.signature.matches > 0
};

// ═══════════════════════════════════════════════════════
// §6  Web / API Fetch Output – Post-Execution Guards
// ═══════════════════════════════════════════════════════

@id("forbid-webfetch-output-injection")
@description("Block web fetch results containing prompt injection — prevents indirect injection via web content.")
forbid (
    principal,
    action == Jans::Action::"observe_api_output",
    resource
) when {
    context.signature.categories.contains("prompt_injection") ||
    context.signature.categories.contains("indirect_injection")
};

@id("forbid-webfetch-output-secrets")
@description("Block web fetch results that contain detected secrets.")
forbid (
    principal,
    action == Jans::Action::"observe_api_output",
    resource
) when {
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-webfetch-output-critical")
@description("Block web fetch results with critical-severity YARA matches.")
forbid (
    principal,
    action == Jans::Action::"observe_api_output",
    resource
) when {
    context.signature.severity >= 4
};

// ═══════════════════════════════════════════════════════
// §7  File Operations – Pre-Execution Gates
// ═══════════════════════════════════════════════════════

@id("forbid-file-policy-violation")
@description("Block file operations that violate the policy model.")
forbid (
    principal,
    action in [Jans::Action::"read_file",  Jans::Action::"write_file",
               Jans::Action::"edit_file",  Jans::Action::"delete_file"],
    resource
) when {
    !context.policy.compliant
};

@id("forbid-file-credential-access")
@description("Block file operations on sensitive credential and config files (.env, private keys, cloud creds).")
forbid (
    principal,
    action in [Jans::Action::"read_file",  Jans::Action::"write_file",
               Jans::Action::"edit_file",  Jans::Action::"delete_file"],
    resource
) when {
    context.signature.categories.contains("credential_access")
};

@id("forbid-file-write-secrets")
@description("Block file writes or edits that would embed secrets into source code.")
forbid (
    principal,
    action in [Jans::Action::"write_file", Jans::Action::"edit_file"],
    resource
) when {
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-file-path-traversal")
@description("Block file operations with path traversal patterns in the file path.")
forbid (
    principal,
    action in [Jans::Action::"read_file",  Jans::Action::"write_file",
               Jans::Action::"edit_file",  Jans::Action::"delete_file"],
    resource
) when {
    context.signature.categories.contains("command_injection")
};

@id("forbid-file-delete-highly-confidential")
@description("Block deletion of files classified as highly confidential — prevents evidence destruction.")
forbid (
    principal,
    action == Jans::Action::"delete_file",
    resource
) when {
    resource.label == Jans::Label::"HighlyConfidential"
};

@id("forbid-file-critical-severity")
@description("Block file operations that trigger critical-severity YARA rules.")
forbid (
    principal,
    action in [Jans::Action::"read_file",  Jans::Action::"write_file",
               Jans::Action::"edit_file",  Jans::Action::"delete_file"],
    resource
) when {
    context.signature.severity >= 4
};

// ═══════════════════════════════════════════════════════
// §8  File Operation Result – Post-Execution Guards
// ═══════════════════════════════════════════════════════

@id("forbid-file-result-secrets")
@description("Block when file content reveals secrets — prevents the agent from using exposed credentials.")
forbid (
    principal,
    action == Jans::Action::"observe_file_result",
    resource
) when {
    context.signature.categories.contains("secrets_detection") &&
    context.signature.severity >= 3
};

@id("forbid-file-result-injection")
@description("Block when file content contains prompt injection — prevents indirect injection via file reads.")
forbid (
    principal,
    action == Jans::Action::"observe_file_result",
    resource
) when {
    context.signature.categories.contains("prompt_injection") ||
    context.signature.categories.contains("indirect_injection")
};

@id("forbid-file-result-policy-violation")
@description("Block when file operation results violate the policy model.")
forbid (
    principal,
    action == Jans::Action::"observe_file_result",
    resource
) when {
    !context.policy.compliant
};

// ═══════════════════════════════════════════════════════
// §9  Trajectory-Level Controls – Runaway Agent Protection
// ═══════════════════════════════════════════════════════
//
// Trajectory state lives in context.trajectory (not resource)
// because Shell/API/Tool are now the resource types.

@id("forbid-tainted-trajectory-runaway")
@description("Limit highly confidential trajectories to 50 steps — prevents unbounded processing of sensitive data.")
forbid (
    principal,
    action in [Jans::Action::"exec_command", Jans::Action::"call_api"],
    resource
) when {
    context.trajectory.label == Jans::Label::"HighlyConfidential" &&
    context.trajectory.step_count > 50
};

@id("forbid-tainted-trajectory-with-threats")
@description("Block further actions on tainted trajectories when signatures detect active threats.")
forbid (
    principal,
    action in [Jans::Action::"exec_command",        Jans::Action::"observe_exec_output",
               Jans::Action::"call_api",             Jans::Action::"observe_api_output",
               Jans::Action::"observe_file_result"],
    resource
) when {
    context.trajectory.taints.contains(Jans::Taint::"exfiltration") &&
    context.signature.matches > 0
};
