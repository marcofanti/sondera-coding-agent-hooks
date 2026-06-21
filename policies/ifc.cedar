// ═══════════════════════════════════════════════════════
// Sondera – Information Flow Control (IFC) Policies
// ═══════════════════════════════════════════════════════
//
// Enforces lattice-based information flow control to prevent
// sensitive data from leaking through outbound channels.
//
// Namespace: Jans:: (aligned with jans-cedarling / carapace)
//
// Model: simplified Bell-LaPadula "no write down" / "no read up"
// adapted for AI agent trajectories. Once a trajectory ingests
// data at a given sensitivity level, its label is raised to
// the max level seen (high-water mark). These policies then
// restrict which outbound actions the trajectory may perform.
//
// ─── Sensitivity Lattice ────────────────────────────────
//
//   Jans::Label::"HighlyConfidential"   (level 3)
//   Jans::Label::"Confidential"         (level 2)
//   Jans::Label::"Internal"             (level 1)
//   Jans::Label::"Public"               (level 0)
//
// ─── Resource / Context mapping ─────────────────────────
//
//   exec_command / observe_exec_output → resource = Jans::Shell
//   call_api / observe_api_output      → resource = Jans::API
//   observe_tool_output                → resource = Jans::Tool
//   Trajectory state (label, step_count, taints) → context.trajectory
//   (resource is no longer Jans::Trajectory — use context.trajectory.*)
//
// ─── Outbound Channels Controlled ───────────────────────
//
//   call_api / observe_api_output   — HTTP requests to external URLs
//   exec_command                    — network tools (curl, wget, nc, etc.)
//   observe_exec_output             — output from network commands

// ═══════════════════════════════════════════════════════
// §1  call_api – Sensitivity-Gated Outbound Blocking
// ═══════════════════════════════════════════════════════

@id("ifc-forbid-webfetch-highly-confidential")
@description("IFC: block all web/API fetches when trajectory carries highly confidential data — unconditional outbound lockdown.")
forbid (
    principal,
    action == Jans::Action::"call_api",
    resource
) when {
    context.trajectory.label == Jans::Label::"HighlyConfidential"
};

@id("ifc-forbid-webfetch-confidential-with-signatures")
@description("IFC: block API fetches on confidential trajectories when YARA signatures detected.")
forbid (
    principal,
    action == Jans::Action::"call_api",
    resource
) when {
    context.trajectory.label == Jans::Label::"Confidential" &&
    context.signature.matches > 0
};

@id("ifc-forbid-webfetch-confidential-with-exfil-taint")
@description("IFC: block API fetches on confidential trajectories tainted with exfiltration.")
forbid (
    principal,
    action == Jans::Action::"call_api",
    resource
) when {
    context.trajectory.label == Jans::Label::"Confidential" &&
    context.trajectory.taints.contains(Jans::Taint::"exfiltration")
};

@id("ifc-forbid-webfetch-confidential-with-cred-taint")
@description("IFC: block API fetches on confidential trajectories tainted with credential access.")
forbid (
    principal,
    action == Jans::Action::"call_api",
    resource
) when {
    context.trajectory.label == Jans::Label::"Confidential" &&
    context.trajectory.taints.contains(Jans::Taint::"credential_access")
};

// ═══════════════════════════════════════════════════════
// §2  observe_api_output – Taint Propagation Guards
// ═══════════════════════════════════════════════════════

@id("ifc-forbid-webfetch-output-raises-to-highly-confidential")
@description("IFC: block API fetch results classified as highly confidential — prevents taint escalation via external content.")
forbid (
    principal,
    action == Jans::Action::"observe_api_output",
    resource
) when {
    context.label == Jans::Label::"HighlyConfidential"
};

@id("ifc-forbid-webfetch-output-on-tainted-trajectory")
@description("IFC: block API fetch results when trajectory is already tainted with exfiltration.")
forbid (
    principal,
    action == Jans::Action::"observe_api_output",
    resource
) when {
    context.trajectory.taints.contains(Jans::Taint::"exfiltration") &&
    context.signature.severity >= 2
};

@id("ifc-forbid-webfetch-output-confidential-with-secrets")
@description("IFC: block API fetch results containing secrets on confidential trajectories.")
forbid (
    principal,
    action == Jans::Action::"observe_api_output",
    resource
) when {
    context.trajectory.label == Jans::Label::"Confidential" &&
    context.signature.categories.contains("secrets_detection")
};

// ═══════════════════════════════════════════════════════
// §3  exec_command – Network Tool Blocking
// ═══════════════════════════════════════════════════════

@id("ifc-forbid-shell-network-highly-confidential")
@description("IFC: block network shell commands (curl, wget, ssh, scp, nc, rsync, ftp) when trajectory is highly confidential.")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    context.trajectory.label == Jans::Label::"HighlyConfidential" &&
    (context.command like "*curl *"    ||
     context.command like "*wget *"    ||
     context.command like "*ssh *"     ||
     context.command like "*scp *"     ||
     context.command like "*sftp *"    ||
     context.command like "*rsync *"   ||
     context.command like "*nc *"      ||
     context.command like "*ncat *"    ||
     context.command like "*netcat *"  ||
     context.command like "*ftp *"     ||
     context.command like "*telnet *"  ||
     context.command like "*socat *")
};

@id("ifc-forbid-shell-network-confidential-with-taint")
@description("IFC: block network shell commands on confidential trajectories tainted with exfiltration.")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    context.trajectory.label == Jans::Label::"Confidential" &&
    context.trajectory.taints.contains(Jans::Taint::"exfiltration") &&
    (context.command like "*curl *"   ||
     context.command like "*wget *"   ||
     context.command like "*ssh *"    ||
     context.command like "*scp *"    ||
     context.command like "*sftp *"   ||
     context.command like "*rsync *"  ||
     context.command like "*nc *"     ||
     context.command like "*ncat *"   ||
     context.command like "*netcat *" ||
     context.command like "*ftp *")
};

@id("ifc-forbid-shell-pipe-network-highly-confidential")
@description("IFC: block shell commands piping to network tools when trajectory is highly confidential.")
forbid (
    principal,
    action == Jans::Action::"exec_command",
    resource
) when {
    context.trajectory.label == Jans::Label::"HighlyConfidential" &&
    (context.command like "*| curl *"  ||
     context.command like "*| wget *"  ||
     context.command like "*| nc *"    ||
     context.command like "*| ssh *"   ||
     context.command like "*| socat *")
};

// ═══════════════════════════════════════════════════════
// §4  observe_exec_output – Network Output Guards
// ═══════════════════════════════════════════════════════

@id("ifc-forbid-shell-output-secrets-on-sensitive-trajectory")
@description("IFC: block shell output containing secrets when trajectory carries confidential or higher data.")
forbid (
    principal,
    action == Jans::Action::"observe_exec_output",
    resource
) when {
    (context.trajectory.label == Jans::Label::"Confidential" ||
     context.trajectory.label == Jans::Label::"HighlyConfidential") &&
    context.signature.categories.contains("secrets_detection")
};

@id("ifc-forbid-shell-output-raises-to-highly-confidential")
@description("IFC: block shell output classified as highly confidential when trajectory is not already at that level — prevents taint escalation.")
forbid (
    principal,
    action == Jans::Action::"observe_exec_output",
    resource
) when {
    context.label == Jans::Label::"HighlyConfidential" &&
    context.trajectory.label != Jans::Label::"HighlyConfidential"
};

// ═══════════════════════════════════════════════════════
// §5  Trajectory Step Limits – Sensitivity-Scaled
// ═══════════════════════════════════════════════════════
//
// context.trajectory.step_count replaces resource.step_count
// because the resource is now Jans::Shell / Jans::API.

@id("ifc-forbid-confidential-trajectory-runaway")
@description("IFC: limit confidential trajectories to 100 outbound steps — bounds blast radius.")
forbid (
    principal,
    action in [Jans::Action::"exec_command", Jans::Action::"call_api"],
    resource
) when {
    context.trajectory.label == Jans::Label::"Confidential" &&
    context.trajectory.step_count > 100
};

@id("ifc-forbid-highly-confidential-trajectory-strict-limit")
@description("IFC: limit highly confidential trajectories to 25 outbound steps — strict bound on highest-sensitivity processing.")
forbid (
    principal,
    action in [Jans::Action::"exec_command", Jans::Action::"call_api"],
    resource
) when {
    context.trajectory.label == Jans::Label::"HighlyConfidential" &&
    context.trajectory.step_count > 25
};

// ═══════════════════════════════════════════════════════
// §6  Cross-Channel Compound Guards
// ═══════════════════════════════════════════════════════

@id("ifc-forbid-sensitive-trajectory-with-obfuscation")
@description("IFC: block outbound actions on sensitive trajectories when obfuscation detected.")
forbid (
    principal,
    action in [Jans::Action::"exec_command", Jans::Action::"call_api"],
    resource
) when {
    (context.trajectory.label == Jans::Label::"Confidential" ||
     context.trajectory.label == Jans::Label::"HighlyConfidential") &&
    context.signature.categories.contains("obfuscation")
};

@id("ifc-forbid-sensitive-trajectory-defense-evasion")
@description("IFC: block outbound actions on sensitive trajectories using defense evasion techniques.")
forbid (
    principal,
    action in [Jans::Action::"exec_command", Jans::Action::"call_api"],
    resource
) when {
    (context.trajectory.label == Jans::Label::"Confidential" ||
     context.trajectory.label == Jans::Label::"HighlyConfidential") &&
    context.signature.categories.contains("defense_evasion")
};

@id("ifc-forbid-tool-output-on-highly-confidential-trajectory")
@description("IFC: block tool output processing on highly confidential trajectories when threats detected.")
forbid (
    principal,
    action == Jans::Action::"observe_tool_output",
    resource
) when {
    context.trajectory.label == Jans::Label::"HighlyConfidential" &&
    context.signature.matches > 0
};
