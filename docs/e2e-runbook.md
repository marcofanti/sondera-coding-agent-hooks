# Sondera End-to-End Test Runbook

This runbook exercises the whole reference monitor as a running system: a real
agent making tool calls through real hooks/MCP against a live harness, with
Cedar policy adjudication and OpenTelemetry you can see in Grafana. It doubles
as the setup documentation for hook configuration, policy configuration, and
agent identity creation.

Everything here has been run end-to-end on macOS with Docker, Rust, and Python
3.13. No Ollama is required for the main run (LLM guardrails degrade to
permissive defaults; see [§7](#7-optional-ollama-llm-guardrails)).

## Contents

1. [Prerequisites & one-command run](#1-prerequisites--one-command-run)
2. [Telemetry stack (Grafana LGTM)](#2-telemetry-stack-grafana-lgtm)
3. [Hook configuration](#3-hook-configuration)
4. [Policy configuration](#4-policy-configuration)
5. [Agent identity creation](#5-agent-identity-creation)
6. [The gated file agent (MCP read/write + adjudication)](#6-the-gated-file-agent)
7. [Optional: Ollama LLM guardrails](#7-optional-ollama-llm-guardrails)
8. [cedar-mcp policy authoring](#8-cedar-mcp-policy-authoring)
9. [Inspect / shadow mode](#9-inspect--shadow-mode)
10. [Agent Bill of Materials (AgBOM)](#10-agent-bill-of-materials-agbom)
11. [Findings](#11-findings)

---

## 1. Prerequisites & one-command run

| Need | Why |
|------|-----|
| Rust (stable) | build the harness + adapter binaries |
| Docker | Grafana LGTM telemetry container |
| Python 3.10+ and `uv` | the gated file agent + SDK |
| `jq`, `curl` | fixture smokes and admin API calls |

Build once and create the agent venv:

```bash
cargo build --workspace
cd examples/gated_file_agent
uv venv --python 3.13 .venv
uv pip install --python .venv -e . -e ../../sondera-python -e '.[dev]'
cd ../..
```

Run the whole campaign:

```bash
bash scripts/e2e/run_all.sh
```

Phases: build & unit tests → start LGTM → start harness (cedarling + OTel) →
gated agent scenarios → adapter smokes → mandate → escalation → telemetry
assertions → failure modes. Env toggles: `SKIP_BUILD=1`, `SKIP_LGTM=1`,
`OTEL_ENDPOINT=...`.

Individual phases (each requires the harness for its scope; the scripts manage
harness start/stop by process name):

```bash
bash scripts/e2e/smoke_adapters.sh     # claude/cursor/gemini fixtures
bash scripts/e2e/mandate_phase.sh      # provisioned identities
bash scripts/e2e/escalation_phase.sh   # approve / deny / timeout
bash scripts/e2e/inspect_phase.sh      # shadow (allow) + approve-everything (prompt)
bash scripts/e2e/agbom_phase.sh        # CycloneDX bill of materials
bash scripts/e2e/failure_modes.sh      # harness DOWN posture per adapter
```

---

## 2. Telemetry stack (Grafana LGTM)

```bash
cd deploy/otel-lgtm && docker compose up -d
```

`grafana/otel-lgtm` bundles Grafana + Tempo (traces) + Prometheus (metrics) and
listens for OTLP on `:4317` (gRPC) and `:4318` (HTTP). Grafana UI:
<http://localhost:3000>.

Start the harness so it exports:

```bash
cargo run --bin sondera-harness-server -- \
  --policy-engine cedarling --admin-port 9090 \
  --otel --otel-metrics --otel-endpoint http://localhost:4317 -v
```

Telemetry auto-enables if `OTEL_EXPORTER_OTLP_ENDPOINT` (or the traces-specific
variant) is set, even without `--otel`.

**What to look for.** Query the datasources directly (UIDs `prometheus`,
`tempo`) or use Grafana Explore:

```bash
# metrics
curl -s -G 'http://localhost:3000/api/datasources/proxy/uid/prometheus/api/v1/query' \
  --data-urlencode 'query=sondera_adjudications_total'
# traces
curl -s -G 'http://localhost:3000/api/datasources/proxy/uid/tempo/api/search' \
  --data-urlencode 'tags=service.name=sondera-harness'
```

- Metrics: `sondera_adjudications_total` and `sondera_adjudication_duration_ms`,
  labelled `engine`, `decision`, `agent_provider`, `event_category`,
  `event_type`. Watch `sondera_adjudications_total{decision="Deny"}` climb
  during the forbidden scenarios.
- Traces: service `sondera-harness`, spans `harness.rpc.adjudicate`,
  `PolicyHarness::adjudicate` (carries `decision`, `policy_ids`), and
  `harness.http.request` (templated `http.route`). Span attributes deliberately
  exclude file contents, prompt text, and shell command text.

---

## 3. Hook configuration

Hook adapters normalize each agent's tool-call JSON into a harness `Event`,
send it over a tarpc Unix socket, and translate the `Allow | Deny | Escalate`
verdict back into that agent's hook response dialect.

Install / uninstall (each backs up the existing settings file first):

```bash
cargo run -p sondera-claude  -- install            # local:  .claude/settings.local.json
cargo run -p sondera-claude  -- install --project  # shared: .claude/settings.json
cargo run -p sondera-cursor  -- install            # ~/.cursor/hooks.json  (or --project)
cargo run -p sondera-gemini  -- install            # ~/.gemini/settings.json
cargo run -p sondera-claude  -- uninstall
```

| Agent | Settings file | Events | Response dialect | Deny exit |
|-------|---------------|--------|------------------|-----------|
| Claude Code | `.claude/settings.local.json` (default), `.claude/settings.json` (`--project`), `~/.claude/settings.json` (`--user`) | 14 | `hookSpecificOutput.permissionDecision` = `deny`/`ask`; **allow = `{}`** | 0 |
| Cursor | `~/.cursor/hooks.json` or `<proj>/.cursor/hooks.json` | 20 | `{"permission":"allow"\|"deny"}` | 2 |
| Gemini CLI | `~/.gemini/settings.json`, `.gemini/settings.json`, `.gemini/settings.local.json` | 11 | `{"decision":"allow"\|"deny"}` | 2 on pipeline error |
| Copilot CLI | `.github/hooks/hooks.json` | 6 | dual bash/pwsh commands | — |

Each generated hook entry runs `<abs-path-to-binary> --verbose <event>`. The
binary reads the agent's hook JSON on stdin and writes one JSON line to stdout
(logs go to stderr to keep stdout clean).

**Critical invariant — Claude allow must serialize to `{}`.** Emitting an
`hookSpecificOutput` with `permissionDecision:"allow"` would make Claude Code
skip its own permission prompt and silently auto-approve. The adapter and a
regression test guard this; the smoke script asserts it:

```bash
echo '{"session_id":"s","transcript_path":"/tmp/t","cwd":"/tmp","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}' \
  | ./target/debug/sondera-claude pre-tool-use     # → {}
```

Fixtures for driving each adapter without a live agent live in
`examples/claude_code_hooks/fixtures/`, `examples/cursor_hooks/fixtures/`,
`examples/gemini_cli_hooks/fixtures/` (placeholders `__SID__`/`__CWD__` are
substituted by the smoke script). Copilot ships its own fixture smoke at
`examples/github_copilot_cli_hooks/scripts/run_fixture_smoke.sh`.

Hooks connect to the harness at `/var/run/sondera/sondera-harness.sock`, falling
back to `~/.sondera/sondera-harness.sock`. They load `~/.sondera/env` if present.

---

## 4. Policy configuration

All policies live in `policies/` and load together; a Cedar `forbid` always
beats a `permit`.

| File | Scope |
|------|-------|
| `schema.json` | authoritative `Jans::` Cedar schema (entities, 25 actions) |
| `base.cedar` | default permit + universal forbids (injection, severity, credentials, exfiltration) |
| `destructive.cedar` | `rm -rf`, git force-push, terraform destroy, DROP DATABASE, kill -9 |
| `file.cedar` | Bell-LaPadula no-write-down, private keys, secrets, OWASP/CWE gates |
| `ifc.cedar` | outbound blocking by trajectory label, runaway step limits |
| `supply_chain_risk.cedar` | typosquatting, dependency confusion, build-script injection |
| `communication.cedar` | email/calendar; escalates send/create/update/delete by default |
| `browser.cedar` | navigation/forms; escalates form submit |
| `ifc.toml`, `policies.toml` | Ollama IFC + secure-code classifier config |

**Annotation semantics** (all three are used by the campaign):

- `@id("name")` — surfaced as `policy_id` in the deny message and telemetry.
  You see these in every denied scenario, e.g. `forbid-private-key-read`.
- `@taint("name")` — after a matching forbid fires, the harness appends the
  taint to the trajectory entity (deduplicated). Later actions on the same
  trajectory can be blocked by taint-conditioned policies (e.g. an outbound
  fetch after a `credential_access` taint).
- `@decision("escalate")` — promotes a `Deny` to `Escalate` **only if no other
  co-firing forbid is a hard deny** (a forbid with no `@decision` is always a
  hard deny). This is why `deny-send-email-highly-confidential` (hard) beats
  `escalate-send-email-default` when both match.

Editing policies: change a `.cedar` file and restart the harness (or point it at
a directory with `-p <dir>`). To validate before loading, use cedar-mcp
([§8](#8-cedar-mcp-policy-authoring)).

---

## 5. Agent identity creation

There are three tiers of identity, from weakest to strongest.

### Tier 1 — derived identities (default)

Each adapter derives its id as `"<provider>-<username>"` (e.g. `claude-mfanti`)
and hardcodes its `provider_id`. On the first event, the harness lazily upserts
an `Agent`/`Jans::Workload` entity into the Fjall entity store
(`~/.sondera/entities/`) — no enrollment, no key. The Claude `session_id` is the
trajectory id; subagents get their own Agent entity but share the parent
trajectory. Control events (session start/stop) are never policy-evaluated.

### Tier 2 — SDK identities

Python agents choose their identity explicitly:

```python
from sondera import PolicyGate, Action
gate = PolicyGate(admin_url="http://localhost:9090",
                  default_agent_id="gated-file-agent",
                  default_provider_id="python")
with gate.trajectory(trajectory_id="…") as traj:
    decision = traj.check(Action.read_file("notes.md"))
```

The SDK talks HTTP to the admin API (`--admin-port`), not the Unix socket.

### Tier 3 — provisioned identities (mandate JWT)

An operator issues a per-agent Ed25519-signed mandate carrying a Cedar policy
subset. The agent presents it on every request; both the deployment ceiling and
the mandate must allow.

```bash
# 1. operator generates a keypair (32 raw bytes each)
sondera-claude mandate keygen \
  --signing-key ops.sign.key --verifying-key ops.verify.key

# 2. issue a narrow mandate (here: read only) to a named agent
printf 'permit ( principal, action == Jans::Action::"read_file", resource );\n' > readonly.cedar
sondera-claude mandate sign \
  --signing-key ops.sign.key --agent-id gated-file-agent \
  --policy readonly.cedar --exp-secs 3600 > agent.jwt

# 3. inspect the decoded claims
sondera-claude mandate verify --verifying-key ops.verify.key < agent.jwt

# 4. run the harness with the mandate engine
sondera-harness-server --policy-engine mandate \
  --mandate-pub-key ops.verify.key --admin-port 9090 -v
```

The agent attaches the JWT via `PolicyGate(mandate_jwt=<token>)`, which the SDK
places at `event.raw["mandate_jwt"]`.

Verified behavior: **no JWT → Deny**, **valid JWT + permitted action → Allow**.
The per-request *subset* is not yet enforced over the async/HTTP path — see
[§9 Findings](#9-findings).

---

## 6. The gated file agent

`examples/gated_file_agent/` is a self-contained agent whose stdio MCP server
reads and writes files in a sandbox and adjudicates **every** tool call through
the SDK before touching disk. It is the phase-1 "simple agent with its own MCP"
target.

```bash
cd examples/gated_file_agent
.venv/bin/python -m gated_agent.agent --scenario all      # needs harness on :9090
```

The driver prints a PASS/FAIL table and exits non-zero on any mismatch. Scenario
matrix (default, YARA-only run):

| Scenario | Tool | Expected | Policy |
|----------|------|----------|--------|
| write + read `notes.md`, list, `ls` | write/read/list/shell | Allow | `default-permit` |
| read `server.pem` | read_file | Deny | `forbid-private-key-read` |
| write `.env` with AWS key | write_file | Deny | `forbid-env-file-write-with-secrets` |
| write `app.py` with hardcoded secret | write_file | Deny | `forbid-source-write-secrets-python` |
| `rm -rf /` | run_command | Deny | `forbid-rm-rf` |
| `send_email` | send_email | Escalate | `escalate-send-email-default` |
| write `query.sql` (SQL injection) | write_file | Deny (Ollama only) | `forbid-injection-sql` |

The SQL-injection row depends on the Ollama secure-code classifier and is
skipped unless `--with-ollama` is passed (without Ollama the classifier reports
compliant and the write is allowed).

Unit tests (no harness needed):

```bash
cd examples/gated_file_agent && .venv/bin/python -m pytest -q
```

---

## 7. Optional: Ollama LLM guardrails

Two guardrails are LLM-backed and enabled purely by the presence of their config
in the policy dir (`ifc.toml`, `policies.toml`). Without Ollama they fail safe:
IFC label → `Public`, secure-code → compliant. To exercise them for real:

```bash
ollama serve &
ollama pull gpt-oss-safeguard:20b        # ~12 GB
```

Then:

```bash
# guardrail crate integration tests (ignored by default)
cargo test -p guardrails-ifc    -- --ignored
cargo test -p guardrails-policy -- --ignored
cargo test -p sondera-harness --test trajectory_label_persistence -- --ignored

# gated agent including the SQL-injection scenario
cd examples/gated_file_agent && .venv/bin/python -m gated_agent.agent --scenario all --with-ollama
```

Live IFC demo: read a file the model labels Confidential, then attempt an
outbound `curl` on the same trajectory — `ifc.cedar` blocks it.

---

## 8. cedar-mcp policy authoring

`crates/mcp` ships a stdio MCP server (`cedar-mcp`) with 20 tools for authoring
and validating Cedar policies against the real schema. Register it with an MCP
client by copying the example config:

```bash
cp .mcp.json.example .mcp.json        # gitignored; runs `cargo run -p sondera-mcp --bin cedar-mcp`
```

Authoring loop (validated during this campaign):

1. `load_schema` with `policies/schema.json`, then `load_policies`.
2. Author a new forbid and `validate_policy` / `validate_policy_against_schema`.
   Example that returns `{"valid": true}`:
   ```cedar
   @id("forbid-delete-markdown")
   forbid ( principal, action == Jans::Action::"delete_file", resource )
   when { context.path like "*.md" };
   ```
3. Optionally `is_authorized` for a dry-run request.
4. Drop the policy into `policies/`, restart the harness, and confirm: the gated
   agent's `delete_file notes.md` now returns `Deny [forbid-delete-markdown]`.

---

## 9. Inspect / shadow mode

`--policy-engine inspect` wraps the cedarling engine: it runs the real Cedar
evaluation and emits telemetry, then **overrides** the decision. Use it to roll
out policies without blocking, or to force human review of everything.

```bash
# shadow / audit: never blocks, but records what WOULD have been denied
sondera-harness-server --policy-engine inspect --inspect-mode allow \
  --admin-port 9090 --otel --otel-metrics --otel-endpoint http://localhost:4317 -v

# approve-everything: every action escalates for operator approval
sondera-harness-server --policy-engine inspect --inspect-mode prompt --admin-port 9090 -v
```

Verified (`scripts/e2e/inspect_phase.sh`):

- `--inspect-mode allow`: a `read_file server.pem` that cedarling would **Deny**
  comes back **Allow**, but the response annotations still carry
  `forbid-private-key-read` (+ the other matched forbids) — so the audit trail
  shows the would-be denial. Clean reads stay Allow.
- `--inspect-mode prompt`: even a clean `ls /tmp` returns **Escalate**.

The real verdict is also written to the `harness.inspect` span as
`inspect.would_be_decision` and `inspect.matched_policy_ids`. Optional
`--agentmemory-url` / `--agentmemory-secret` mirror each observation to an
agentmemory endpoint.

> **Privacy caveat.** The `harness.inspect` span attribute `inspect.event_content`
> and the agentmemory POST carry the raw scannable content (command text, prompt
> text, file contents), which the OTel design's allowlist otherwise forbids. Do
> not point inspect mode at an untrusted collector.

## 10. Agent Bill of Materials (AgBOM)

The harness projects a trajectory's durable event stream into a CycloneDX
document — the agent plus every tool, shell capability, package dependency, API
host, model, MCP server, and knowledge source it touched.

```bash
# per-trajectory
curl -s http://localhost:9090/api/trajectories/<trajectory-id>/agbom
# aggregate for an agent
curl -s 'http://localhost:9090/api/agbom?agent_id=<agent-id>&limit=100'
# operator CLI
sondera-claude agbom show --trajectory-id <trajectory-id> --output json
```

Verified (`scripts/e2e/agbom_phase.sh`) — a trajectory doing `git status`,
`pip install requests`, a file read, a WebFetch, and a tool call yields a
`bomFormat: "CycloneDX"` document whose `sondera:component_kind` properties
include `agent`, `capability` (git/pip), `dependency` (pip install), `api`
(api.github.com), `tool` (search_docs), and `knowledge_source` (the read file),
plus dependency edges from the agent. The CLI returns the same document with a
deterministic `urn:sondera:agbom:<hash>` serial number.

## 11. Findings

These surfaced while building the campaign and are worth tracking.

1. **SDK wire shape was wrong (fixed).** `sondera-python` emitted externally
   tagged events (`{"Action":{"ShellCommand":…}}`) and wrong field names, which
   the harness (adjacent tagging `{"category","payload":{"type","data"}}`)
   rejected with HTTP 422. The mocked SDK tests never hit the real deserializer,
   so it had never worked against a live harness. Fixed in `actions.py`,
   `observations.py`, `gate.py`, `aiogate.py`, `trajectory.py`; the mandate JWT
   is now nested at `raw["mandate_jwt"]`. All 39 SDK tests updated and green.
2. **Mandate subset not enforced (open).** `MandatePolicyEngine::evaluate`
   (async/HTTP path used by the admin API and all hooks) checks only that a
   valid mandate JWT is present, not that the mandate's Cedar policy permits the
   request. A read-only mandate still allows `write_file`. Real subset logic
   exists only in the unused sync `is_authorized()`. See
   `crates/harness/src/mandate/mod.rs:169-183`.
3. **Fail-open vs fail-closed is not uniform (open).** With the harness down,
   claude/cursor exit 1 (non-blocking → fail-open) while gemini exits 2
   (fail-closed). A deployment that assumes the harness is up runs unmonitored
   under claude/cursor if it isn't. Reproduce: `scripts/e2e/failure_modes.sh`.
4. **TTL sweeper cadence is fixed at 30s (minor).** `spawn_ttl_sweeper` is
   hardcoded to 30s regardless of `--escalation-ttl`, so an escalation record's
   status flips to `timed_out` up to 30s after it expires. The agent-observable
   behavior (client `wait()` returns Deny at its own deadline) is correct.
5. **`--policy-engine` default is still `cedar` (minor).** The legacy flat-
   namespace engine remains the CLI default even though DESIGN.md/README call
   cedarling the recommended engine. Pass `--policy-engine cedarling` explicitly.
6. **Design-doc metrics partially implemented (minor).** Only
   `sondera_adjudications_total` and `sondera_adjudication_duration_ms` are
   emitted; `sondera_policy_denies_total`, `sondera_escalations_total`,
   `sondera_guardrail_duration_ms`, etc. from the OTel design are not.
7. **Hook binaries cannot target a non-default socket (minor).** The server and
   `sondera-mcp-gate` accept `--socket`; the hook adapters always use
   `connect_default()`.
8. **Admin CLIs panicked (fixed).** `sondera-claude agbom show` and
   `sondera-claude escalations …` called `reqwest::blocking` from inside
   `#[tokio::main]`, which panics ("Cannot drop a runtime in a context where
   blocking is not allowed"). Both handlers are now `async` and use non-blocking
   reqwest (`apps/claude/src/app/{agbom,escalations}.rs`, `main.rs`).
9. **Inspect mode leaks raw content into telemetry (open).** The `harness.inspect`
   span's `inspect.event_content` attribute and the agentmemory POST carry raw
   command/prompt/file content, contradicting the OTel design's positive
   allowlist. See `crates/harness/src/inspect.rs`.
