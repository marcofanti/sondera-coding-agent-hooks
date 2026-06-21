# OpenTelemetry Observability Design

**Status:** Proposed  
**Last updated:** 2026-06-21  
**Methodology:** Test-driven design

This document proposes an observability design for the Sondera harness and hook
ecosystem. The first implementation target is the long-running harness server.
Hook binaries remain lightweight and continue to write diagnostics to stderr so
their stdout JSON contracts stay intact.

---

## Problem

Sondera already records durable trajectory events and uses `tracing` spans in
several hot paths, but operators do not yet have a distributed observability
surface for:

- adjudication latency by policy engine
- allow, deny, and escalate rates
- policy IDs responsible for denials
- guardrail and LLM classifier latency
- escalation throughput and TTL behavior
- correlation between a hook response and backend evaluation work

The system is a security reference monitor, so the observability design must
also prevent telemetry from becoming an exfiltration path. Raw prompts, command
output, file contents, request bodies, policy raw payloads, and mandate JWTs must
not be exported as span attributes, metric labels, or logs by default.

---

## Goals

1. Export OpenTelemetry traces from `sondera-harness-server`.
2. Export OpenTelemetry metrics for adjudication, policy, guardrail, storage,
   and escalation behavior.
3. Preserve existing local `tracing_subscriber::fmt` output.
4. Keep hook binaries safe for JSON-over-stdout agent protocols.
5. Make telemetry opt-in by configuration and safe to enable in production.
6. Use tests to define the public behavior before implementation.

---

## Non-Goals

- Do not export full trajectory events to OpenTelemetry.
- Do not require an OpenTelemetry Collector for normal local development.
- Do not instrument every short-lived hook binary in the first phase.
- Do not replace the Turso trajectory store. Durable audit history remains the
  source of truth for event replay.
- Do not add vendor-specific SDKs. Export OTLP and let collectors route data to
  Jaeger, Tempo, Prometheus, Honeycomb, Datadog, or another backend.

---

## Current Entry Points

| Area | File | Role |
|------|------|------|
| Server tracing initialization | `crates/harness/src/bin/server.rs` | Builds the current fmt subscriber |
| Core request boundary | `crates/harness/src/policy_harness.rs` | `PolicyHarness::adjudicate` handles every normalized event |
| tarpc service boundary | `crates/harness/src/rpc.rs` | Accepts hook adapter RPC calls |
| HTTP admin boundary | `crates/harness/src/escalation/api.rs` | Serves `/api/adjudicate` and escalation endpoints |
| Hook logging | `crates/common/src/lib.rs` | Initializes stderr-only hook tracing |
| Guardrail spans | `crates/guardrails/*/src/lib.rs` | Signature, IFC, and policy classifiers already use `#[instrument]` |

The central trace should start at the tarpc or HTTP boundary and include the
`PolicyHarness::adjudicate` span, policy engine evaluation, guardrail calls,
storage writes, and escalation creation.

---

## Proposed Architecture

Add a small observability module inside `crates/harness`:

```text
crates/harness/src/observability.rs
```

Responsibilities:

1. Parse observability configuration from CLI args and environment variables.
2. Build a `tracing_subscriber` registry with:
   - fmt layer for local stderr/stdout diagnostics
   - optional OpenTelemetry trace layer
   - optional OpenTelemetry log bridge in a later phase
3. Build an OpenTelemetry meter provider for metrics.
4. Provide helper functions for recording metric events.
5. Provide a shutdown guard so batch exporters flush on server exit.

The server owns initialization. Library crates keep using plain `tracing` and
OpenTelemetry API calls where needed.

---

## Configuration

### CLI

Add these arguments to `sondera-harness-server`:

```text
--otel                         Enable OpenTelemetry export
--otel-endpoint <url>           OTLP endpoint, default from OTEL_EXPORTER_OTLP_ENDPOINT
--otel-protocol <grpc|http>     Default: grpc
--otel-service-name <name>      Default: sondera-harness
--otel-metrics                  Enable OTLP metrics export
```

### Environment Variables

Support the standard OpenTelemetry environment variables where practical:

| Variable | Purpose |
|----------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector endpoint |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Trace-specific endpoint |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Metrics-specific endpoint |
| `OTEL_SERVICE_NAME` | Service name |
| `OTEL_RESOURCE_ATTRIBUTES` | Deployment, host, version, environment |

OpenTelemetry should be enabled when either `--otel` is set or an OTLP endpoint
environment variable exists. Metrics should be separately gated by
`--otel-metrics` for the first implementation so traces can be shipped without
introducing metric-cardinality risk.

---

## Trace Model

### Root Span: RPC or HTTP Request

`crates/harness/src/rpc.rs`

Span name:

```text
harness.rpc.adjudicate
```

Attributes:

| Attribute | Source |
|-----------|--------|
| `otel.kind = "server"` | static |
| `rpc.system = "tarpc"` | static |
| `sondera.trajectory_id` | `event.trajectory_id` |
| `sondera.event_id` | `event.event_id` |
| `sondera.agent_id` | `event.agent.id` |
| `sondera.agent_provider` | `event.agent.provider_id` |
| `sondera.event_category` | `Action`, `Observation`, `Control`, or `State` |
| `sondera.event_type` | Safe enum variant name |

Do not include raw command strings, file paths, prompt text, URL query strings,
file contents, or JSON arguments.

### Core Span: Adjudication

`crates/harness/src/policy_harness.rs`

Span name:

```text
harness.adjudicate
```

Existing fields are useful and should remain:

- `trajectory_id`
- `event_id`
- `agent`
- `policy_engine`

Add safe result fields when the decision is known:

- `sondera.decision`
- `sondera.policy_ids`
- `sondera.annotation_count`
- `sondera.escalation_id` only when present

### Child Spans

| Span | Location | Notes |
|------|----------|-------|
| `harness.storage.write_event` | trajectory store writes | record success/failure and duration |
| `harness.policy.evaluate` | policy engine trait call | record engine name and decision |
| `guardrail.signature.scan` | signature crate | existing span can be renamed or enriched |
| `guardrail.ifc.classify` | IFC crate | existing span can record model name and label count |
| `guardrail.policy.evaluate_content` | policy crate | existing span can record model name and policy count |
| `harness.escalation.create` | escalation store/API | record TTL and policy count |
| `harness.slack.notify` | Slack webhook helper | record HTTP status class only |

---

## Metrics Model

Initial instruments:

| Metric | Type | Labels |
|--------|------|--------|
| `sondera_adjudications_total` | counter | `decision`, `engine`, `agent_provider`, `event_category`, `event_type` |
| `sondera_adjudication_duration_ms` | histogram | `engine`, `decision`, `event_category`, `event_type` |
| `sondera_policy_denies_total` | counter | `engine`, `policy_id` |
| `sondera_escalations_total` | counter | `status`, `engine` |
| `sondera_guardrail_duration_ms` | histogram | `guardrail`, `result` |
| `sondera_storage_write_duration_ms` | histogram | `store`, `result` |
| `sondera_rpc_errors_total` | counter | `boundary`, `error_kind` |

Metric labels must remain low cardinality. `event_id`, `trajectory_id`,
`agent_id`, file paths, URLs, commands, and policy descriptions are not metric
labels.

---

## Privacy and Redaction

Telemetry must use a positive allowlist. A field is exported only when this
document explicitly permits it.

Allowed examples:

- event ID
- trajectory ID
- agent provider
- event category and enum type
- policy engine name
- decision
- policy ID
- signature category
- signature severity
- content length
- model name
- status code class

Forbidden examples:

- prompt text
- shell command text
- command stdout or stderr
- file contents
- file paths by default
- URL query strings
- HTTP request or response bodies
- tool JSON arguments
- mandate JWTs
- raw Cedar evaluation payloads

Existing verbose debug logs such as full `Event` dumps should be reviewed during
implementation. If they can include sensitive content, replace them with a
redacted summary before enabling OpenTelemetry log export.

---

## Test-Driven Design

Implementation proceeds by writing failing tests first, making them pass with
the smallest implementation, then refactoring the internals while preserving the
test suite.

### Phase 1: RED Tests for Configuration

File:

```text
crates/harness/tests/observability_config.rs
```

Tests:

```text
observability_disabled_without_flag_or_env
observability_enabled_by_cli_flag
observability_enabled_by_otlp_endpoint_env
service_name_defaults_to_sondera_harness
service_name_can_be_overridden_by_cli
metrics_are_disabled_until_explicitly_enabled
```

Expected behavior:

- config parsing is deterministic
- CLI values override environment values
- no exporter is created when observability is disabled

### Phase 2: RED Tests for Safe Span Fields

File:

```text
crates/harness/tests/observability_spans.rs
```

Tests:

```text
adjudication_span_contains_safe_correlation_fields
adjudication_span_records_final_decision
adjudication_span_records_policy_ids_without_descriptions
adjudication_span_does_not_export_shell_command_text
adjudication_span_does_not_export_file_content
adjudication_span_does_not_export_tool_arguments
http_adjudicate_span_uses_server_kind
rpc_adjudicate_span_uses_server_kind
```

Test strategy:

- install a test `tracing_subscriber` layer that captures span fields in memory
- build representative shell, file, web, and tool events
- assert the allowlisted fields exist
- assert sensitive strings from fixtures never appear in captured fields

### Phase 3: RED Tests for Metrics

File:

```text
crates/harness/tests/observability_metrics.rs
```

Tests:

```text
adjudication_counter_increments_for_allow
adjudication_counter_increments_for_deny
adjudication_counter_increments_for_escalate
adjudication_duration_histogram_records_once_per_event
policy_deny_counter_uses_policy_id_label
metrics_do_not_use_event_id_or_trajectory_id_labels
```

Test strategy:

- use an in-memory metric reader or a small test recorder abstraction
- run isolated `PolicyHarness` evaluations
- assert metric names, counts, and label keys

### Phase 4: RED Tests for Exporter Lifecycle

File:

```text
crates/harness/tests/observability_shutdown.rs
```

Tests:

```text
shutdown_flushes_trace_provider
shutdown_flushes_meter_provider_when_metrics_enabled
shutdown_is_noop_when_observability_disabled
```

Expected behavior:

- server can hold an `ObservabilityGuard`
- dropping or explicitly shutting down the guard flushes exporters
- tests do not require a live collector

### Phase 5: GREEN Implementation

Implement only enough code to pass the tests:

1. Add `crates/harness/src/observability.rs`.
2. Add dependency declarations in `crates/harness/Cargo.toml`.
3. Replace inline tracing initialization in `server.rs` with
   `observability::init(&args)`.
4. Add safe span fields at tarpc and HTTP request boundaries.
5. Record metrics in `PolicyHarness::adjudicate`.
6. Add shutdown flushing at the end of `main`.

### Phase 6: REFACTOR

After the tests pass:

1. Move metric recording helpers behind narrow functions.
2. Replace duplicated event category/type extraction with a shared helper.
3. Review existing debug logs for raw event leakage.
4. Document local collector setup in `README.md`.
5. Add example commands for Jaeger and Prometheus.

---

## Implementation File Map

| File | Change |
|------|--------|
| `crates/harness/src/observability.rs` | New config, subscriber, metrics, shutdown guard |
| `crates/harness/src/bin/server.rs` | Add CLI args, call observability init, hold shutdown guard |
| `crates/harness/src/rpc.rs` | Add RPC boundary span fields |
| `crates/harness/src/escalation/api.rs` | Add HTTP boundary span fields |
| `crates/harness/src/policy_harness.rs` | Record decision fields and metrics |
| `crates/harness/src/types.rs` | Add safe helpers for event category/type names if needed |
| `crates/guardrails/signature/src/lib.rs` | Enrich scan span with result metadata |
| `crates/guardrails/ifc/src/lib.rs` | Enrich classifier span with model and finding count |
| `crates/guardrails/policy/src/lib.rs` | Enrich policy model span with model and violation count |
| `README.md` | Add local collector and usage examples |

---

## Cargo Dependencies

Add to `crates/harness/Cargo.toml`:

```toml
opentelemetry = "0.32"
opentelemetry_sdk = { version = "0.32", features = ["rt-tokio"] }
opentelemetry-otlp = { version = "0.32", features = ["grpc-tonic", "http-proto", "reqwest-client"] }
tracing-opentelemetry = "0.33"
```

OpenTelemetry logs can be added in a later phase:

```toml
opentelemetry-appender-tracing = "0.32"
```

Exact versions should be pinned during implementation using `cargo update` and
verified with `cargo test --workspace`.

---

## Local Development

Trace collector with Jaeger:

```bash
docker run --rm \
  -p 16686:16686 \
  -p 4317:4317 \
  -e COLLECTOR_OTLP_ENABLED=true \
  jaegertracing/all-in-one:latest
```

Run the harness:

```bash
cargo run --bin sondera-harness-server -- \
  --policy-engine cedarling \
  --otel \
  --otel-endpoint http://localhost:4317 \
  -v
```

Open Jaeger:

```text
http://localhost:16686
```

---

## Rollout Plan

1. Implement config and subscriber tests.
2. Add server trace export.
3. Add safe span fields and privacy tests.
4. Add metrics behind `--otel-metrics`.
5. Add README usage examples.
6. Add optional Python SDK instrumentation as a separate design or follow-up.
7. Consider OpenTelemetry log export only after raw debug logging has been
   redacted.

---

## Open Questions

1. Should telemetry be enabled automatically when `OTEL_EXPORTER_OTLP_ENDPOINT`
   is present, or should `--otel` always be required?
2. Should `Adjudicated` responses include a `trace_id` field for CLI/operator
   correlation?
3. Should file path export be allowed when explicitly enabled, or should paths
   remain audit-store-only?
4. Should metrics use OTLP only, or should the admin API expose a Prometheus
   scrape endpoint too?
5. Should hook binaries ever export spans directly, or should they only pass
   correlation identifiers into the harness?

