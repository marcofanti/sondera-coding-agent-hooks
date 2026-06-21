# Real-Time Escalation Design

**Status:** In progress  
**Last updated:** 2026-06-21

This document describes the architecture for real-time human-in-the-loop approval when the harness returns `Decision::Escalate`.

---

## Problem

Cedar `forbid` rules return `Decision::Deny` — the operation is blocked immediately. For certain actions (e.g., submitting a booking form, sending an outbound email, deleting a calendar event), the right behavior is **"ask first, then allow or deny"** rather than a hard block.

The existing `Decision::Escalate` variant exists in the type system but has no infrastructure:
- IDE hook adapters (Claude, Cursor) translate it to a local UI prompt
- Gemini treats it as Deny
- Non-IDE agents (LangChain, browser, Hermes, OpenClaw) block indefinitely

---

## Cedar Trigger: `@decision("escalate")` Annotation

A new Cedar policy annotation on `forbid` rules changes the return value from `Deny` to `Escalate`:

```cedar
@id("deny-submit-form-default")
@decision("escalate")
forbid (
    principal is Jans::Workload,
    action == Jans::Action::"submit_form",
    resource is Jans::API
);
```

The `CedarlingPolicyEngine` checks the annotation on every matched `forbid` policy. If any matched policy has `@decision("escalate")`, the engine returns `Decision::Escalate` instead of `Decision::Deny`.

**Implementation:** In `crates/harness/src/cedarling/mod.rs`, `response_to_adjudicated()` inspects `response.diagnostics().reason()` — the set of policy IDs that caused the decision. For each, look up `policy.annotation("decision")`. If any equals `"escalate"`, return `Decision::Escalate`.

---

## Escalation Flow (end-to-end)

```
┌──────────────┐         ┌─────────────────┐        ┌──────────────────┐
│  Agent / SDK │         │  Harness Server  │        │   Operator       │
│  (any type)  │         │                  │        │  (CLI / Slack)   │
└──────┬───────┘         └────────┬─────────┘        └────────┬─────────┘
       │                          │                            │
       │  adjudicate(event)       │                            │
       │─────────────────────────►│                            │
       │                          │                            │
       │                          │ CedarlingEngine returns    │
       │                          │ Decision::Escalate         │
       │                          │                            │
       │                          │ EscalationStore.create()   │
       │                          │ (Turso, TTL=120s)          │
       │                          │                            │
       │                          │ POST Slack webhook          │
       │                          │──────────────────────────────────────►│
       │                          │                            │ Slack msg │
       │  Response: Escalate      │                            │ with      │
       │  + escalation_id         │                            │ approve/  │
       │◄─────────────────────────│                            │ deny cmds │
       │                          │                            │           │
       │  poll /api/escalations/  │                            │           │
       │  {id} every 2s           │                            │           │
       │─────────────────────────►│                            │           │
       │  status: pending         │                            │           │
       │◄─────────────────────────│                            │           │
       │                          │                            │           │
       │  (waiting...)            │                            │           │
       │                          │                            │           │
       │                          │◄───────────────────────────────────────│
       │                          │ POST /api/escalations/{id}/approve     │
       │                          │                            │           │
       │                          │ EscalationStore: status→approved       │
       │                          │                            │           │
       │  poll: status: approved  │                            │           │
       │◄─────────────────────────│                            │           │
       │                          │                            │           │
       │  execute tool            │                            │           │
       ▼                          │                            │           │
```

---

## EscalationStore

Stored in the existing Turso/libsql trajectory database (new table, same connection).

```sql
CREATE TABLE IF NOT EXISTS escalations (
    id            TEXT PRIMARY KEY,
    trajectory_id TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    event_json    TEXT NOT NULL,       -- full Event as JSON for operator display
    policy_ids    TEXT NOT NULL,       -- comma-separated matched Cedar policy IDs
    annotations   TEXT NOT NULL,       -- JSON map of annotation key→value
    status        TEXT NOT NULL DEFAULT 'pending',
    created_at    INTEGER NOT NULL,    -- Unix seconds
    expires_at    INTEGER NOT NULL,    -- Unix seconds (TTL = created_at + 120)
    decided_at    INTEGER,
    decided_by    TEXT                 -- operator identity (from admin API auth)
);
```

**Status transitions:** `pending` → `approved` | `denied` | `timed_out`

**TTL enforcement:** A background task in the server checks every 10 seconds and moves `pending` records past `expires_at` to `timed_out`.

---

## HTTP Admin API

New `axum` HTTP server on `--admin-port 9090` (default). Runs alongside the existing tarpc RPC server.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/escalations` | List all escalations (query: `?status=pending`) |
| `GET` | `/api/escalations/:id` | Get detail + full event JSON |
| `POST` | `/api/escalations/:id/approve` | Operator approves; body: `{"decided_by": "marco"}` |
| `POST` | `/api/escalations/:id/deny` | Operator denies; body: `{"decided_by": "marco", "reason": "..."}` |
| `GET` | `/api/escalations/stream` | Server-Sent Events: `data: <escalation_json>` on each new escalation |

### Authentication

Simple bearer token: `--admin-token <token>` CLI arg. Admin API checks `Authorization: Bearer <token>` on all state-changing endpoints. Read endpoints (`GET`) are unauthenticated by default (localhost-only bind).

---

## Slack Notification

When `Decision::Escalate` is returned and `--slack-webhook-url` is set, the harness POSTs to the Slack incoming webhook URL:

```json
{
  "text": "🔔 *Sondera Escalation Request*",
  "attachments": [{
    "color": "warning",
    "fields": [
      { "title": "Agent",       "value": "langchain-agent-1", "short": true },
      { "title": "Action",      "value": "submit_form",       "short": true },
      { "title": "Resource",    "value": "booking.com",       "short": true },
      { "title": "Policy",      "value": "deny-submit-form-default", "short": true },
      { "title": "Expires in",  "value": "120s",              "short": true },
      { "title": "Approve",     "value": "`sondera escalations approve abc123`", "short": false },
      { "title": "Deny",        "value": "`sondera escalations deny abc123`",    "short": false }
    ]
  }]
}
```

The operator copies the `approve`/`deny` command and runs it in their terminal (or pastes into a remote shell). This avoids requiring a public-facing Slack interactive endpoint.

For future Slack interactivity (button clicks), see the `design/` folder for Slack app design.

---

## Agent-Side Behavior

### Python SDK / Playwright gate

```python
decision = gate.adjudicate(event)
if decision.is_escalate:
    escalation_id = decision.escalation_id
    # poll until decided or timed out
    for _ in range(60):  # 120s / 2s per poll
        time.sleep(2)
        status = gate.escalation_status(escalation_id)
        if status == "approved":
            # proceed with the tool call
            break
        if status in ("denied", "timed_out"):
            raise EscalationDenied(f"Escalation {escalation_id} was {status}")
    else:
        raise EscalationTimeout(f"Escalation {escalation_id} timed out")
```

### Hook binaries (Claude, Cursor, Copilot, Gemini)

IDE hooks continue to use the local UI prompt for `Escalate`. The admin API is a fallback channel for non-interactive agents only. Both paths write to the same EscalationStore.

---

## Server Changes

**`crates/harness/src/bin/server.rs`** — new CLI args:
```
--admin-port <port>           HTTP admin API port (default: 9090, 0 = disabled)
--admin-token <token>         Bearer token for state-changing admin endpoints
--slack-webhook-url <url>     Slack incoming webhook URL for escalation notifications
--escalation-ttl <seconds>    Escalation TTL before auto-deny (default: 120)
```

The `tokio::main` spawns two tasks: `rpc::serve()` (existing) + `escalation::api::serve()` (new).

---

## Files

| File | Purpose |
|------|---------|
| `crates/harness/src/escalation/mod.rs` | `EscalationStore` — Turso table, CRUD, TTL sweep |
| `crates/harness/src/escalation/api.rs` | `axum` HTTP routes + SSE stream |
| `crates/harness/src/escalation/slack.rs` | Slack webhook POST helper |
| `crates/harness/src/cedarling/mod.rs` | `@decision("escalate")` annotation check in `response_to_adjudicated()` |
| `crates/harness/src/bin/server.rs` | New CLI args, spawn escalation server task |
| `crates/harness/src/lib.rs` | `pub mod escalation` |
| `crates/harness/tests/escalation_store.rs` | RED tests: create, approve, deny, TTL |
| `crates/harness/tests/escalation_annotation.rs` | RED tests: @decision("escalate") in Cedar |
