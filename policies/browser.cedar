// Browser policy — Playwright / browser agent actions
//
// Resource for all rules: Jans::API (the domain being interacted with)
// Trajectory state is always in context.trajectory.*, not on the resource.

// ─── Navigation ───────────────────────────────────────────────────────────────

@id("permit-navigate-default")
@description("Allow navigation by default; specific forbids apply below")
permit (
    principal is Jans::Workload,
    action == Jans::Action::"navigate",
    resource is Jans::API
);

@id("deny-navigate-exfiltration-taint")
@description("Deny navigation when trajectory is tainted — prevents data exfiltration via URL params")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"navigate",
    resource is Jans::API
)
when {
    context has trajectory &&
    context.trajectory has taints &&
    context.trajectory.taints.contains(Jans::Taint::"exfiltration")
};

@id("deny-navigate-highly-confidential")
@description("Deny navigation when trajectory carries HighlyConfidential data (IFC no-read-up boundary)")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"navigate",
    resource is Jans::API
)
when {
    context has trajectory &&
    context.trajectory has label &&
    context.trajectory.label == Jans::Label::"HighlyConfidential"
};

// ─── Form interaction ─────────────────────────────────────────────────────────

@id("permit-fill-form-default")
@description("Allow form fill by default; password and sensitive field types are blocked below")
permit (
    principal is Jans::Workload,
    action == Jans::Action::"fill_form",
    resource is Jans::API
);

@id("deny-fill-password-field")
@description("Deny filling password fields — agents should not handle credentials")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"fill_form",
    resource is Jans::API
)
when {
    context has field_type &&
    context.field_type == "password"
};

@id("deny-fill-form-credential-signature")
@description("Deny form fill when YARA detects credential material in the value")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"fill_form",
    resource is Jans::API
)
when {
    context has signature &&
    context.signature has categories &&
    context.signature.categories.contains("credential_access")
};

// submit_form has NO permit → Cedar default-deny.
// Operator must add a permit via mandate JWT for specific domains.
// This implements the "always escalate / require approval" pattern:
// the agent gets Deny, the harness wraps it as Escalate when
// @decision("escalate") is set on the forbid or the mandate is absent.

@id("deny-submit-form-default")
@description("Block form submission by default — irreversible real-world side effects require explicit operator permit")
@decision("escalate")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"submit_form",
    resource is Jans::API
);

// ─── Script evaluation ────────────────────────────────────────────────────────

@id("deny-evaluate-script-high-severity")
@description("Deny JS evaluation when YARA detects high-severity payload (mirrors exec_command gate)")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"evaluate_script",
    resource is Jans::API
)
when {
    context has signature &&
    context.signature has severity &&
    context.signature.severity >= 3
};

@id("deny-evaluate-script-credential-access")
@description("Deny JS evaluation when YARA detects credential access pattern (e.g. document.cookie)")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"evaluate_script",
    resource is Jans::API
)
when {
    context has signature &&
    context.signature has categories &&
    context.signature.categories.contains("credential_access")
};

@id("deny-evaluate-script-injection")
@description("Deny JS evaluation when YARA detects prompt injection pattern")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"evaluate_script",
    resource is Jans::API
)
when {
    context has signature &&
    context.signature has categories &&
    context.signature.categories.contains("prompt_injection")
};

// ─── Screenshot ───────────────────────────────────────────────────────────────

@id("permit-take-screenshot-default")
@description("Allow screenshots by default")
permit (
    principal is Jans::Workload,
    action == Jans::Action::"take_screenshot",
    resource is Jans::API
);

@id("deny-screenshot-highly-confidential")
@description("Deny screenshots when trajectory carries HighlyConfidential data (no-read-up)")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"take_screenshot",
    resource is Jans::API
)
when {
    context has trajectory &&
    context.trajectory has label &&
    context.trajectory.label == Jans::Label::"HighlyConfidential"
};
