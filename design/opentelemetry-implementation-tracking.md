# OpenTelemetry Implementation Tracking

**Branch:** `feature/otel-observability`  
**Worktree:** `/Users/mfanti/AgenticAIEngineering/sondera-coding-agent-hooks-otel`  
**Started:** 2026-06-21  
**Tracking fallback:** Beads `br` is not installed in this environment, so this
file tracks work items for the branch.

## Scope

Implement the first server-side phase of `design/opentelemetry-observability.md`:

- OpenTelemetry configuration parsing
- optional OTLP trace export from `sondera-harness-server`
- optional OTLP metrics export
- safe event classification helpers
- low-cardinality adjudication metrics
- safe RPC and adjudication span fields

The committed base branch does not include the uncommitted escalation admin API
currently present in the primary worktree, so HTTP admin endpoint
instrumentation remains a follow-up.

## Work Items

| ID | Status | Item |
|----|--------|------|
| OTel-1 | In progress | Add tests for observability configuration and safe event metadata |
| OTel-2 | Pending | Add `observability` module with config, subscriber, metrics, and shutdown guard |
| OTel-3 | Pending | Wire server CLI args and replace inline subscriber initialization |
| OTel-4 | Pending | Add safe RPC/adjudication span fields |
| OTel-5 | Pending | Record adjudication counters and duration histograms |
| OTel-6 | Pending | Run focused tests and cargo checks |

## Notes

- Telemetry must not export prompts, shell commands, file contents, tool
  arguments, raw event JSON, or mandate JWTs.
- Metric labels must not include `event_id`, `trajectory_id`, `agent_id`, file
  paths, URLs, commands, or raw policy descriptions.

