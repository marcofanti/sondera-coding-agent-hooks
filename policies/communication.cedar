// Communication policy — email and calendar actions
//
// Resource for all rules: Jans::API (the communication service endpoint)
// Trajectory state is always in context.trajectory.*, not on the resource.

// ─── Default permit for read-only communication actions ───────────────────────

@id("permit-read-email")
@description("Allow agents to read email by default")
permit (
    principal is Jans::Workload,
    action == Jans::Action::"read_email",
    resource is Jans::API
);

@id("permit-list-emails")
@description("Allow agents to list emails by default")
permit (
    principal is Jans::Workload,
    action == Jans::Action::"list_emails",
    resource is Jans::API
);

@id("permit-read-calendar")
@description("Allow agents to read calendar by default")
permit (
    principal is Jans::Workload,
    action == Jans::Action::"read_calendar",
    resource is Jans::API
);

// ─── Email write — gated by IFC label ─────────────────────────────────────────

@id("deny-send-email-highly-confidential")
@description("Deny outbound email when trajectory carries HighlyConfidential data (IFC no-write-up)")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"send_email",
    resource is Jans::API
)
when {
    context has trajectory &&
    context.trajectory has label &&
    context.trajectory.label == Jans::Label::"HighlyConfidential"
};

@id("deny-send-email-exfiltration-taint")
@description("Deny outbound email when trajectory is tainted with exfiltration")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"send_email",
    resource is Jans::API
)
when {
    context has trajectory &&
    context.trajectory has taints &&
    context.trajectory.taints.contains(Jans::Taint::"exfiltration")
};

@id("deny-send-email-credential-signature")
@description("Deny email send when YARA detects credential or key material in body")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"send_email",
    resource is Jans::API
)
when {
    context has signature &&
    context.signature has categories &&
    context.signature.categories.contains("credential_access")
};

// send_email always requires real-time operator approval (Escalate).
// The @decision("escalate") annotation promotes Cedar Deny → Escalate in the harness.
// Hard forbids (HighlyConfidential, exfil taint, YARA) remain Deny even when this fires.
@id("escalate-send-email-default")
@decision("escalate")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"send_email",
    resource is Jans::API
);

// ─── Calendar write ───────────────────────────────────────────────────────────

@id("deny-delete-event-highly-confidential")
@description("Deny calendar delete when trajectory carries HighlyConfidential data")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"delete_event",
    resource is Jans::API
)
when {
    context has trajectory &&
    context.trajectory has label &&
    context.trajectory.label == Jans::Label::"HighlyConfidential"
};

// Calendar write actions require real-time approval by default.
@id("escalate-create-event-default")
@decision("escalate")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"create_event",
    resource is Jans::API
);

@id("escalate-update-event-default")
@decision("escalate")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"update_event",
    resource is Jans::API
);

@id("escalate-delete-event-default")
@decision("escalate")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"delete_event",
    resource is Jans::API
);
