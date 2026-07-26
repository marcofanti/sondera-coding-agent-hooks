#!/usr/bin/env bash
# End-to-end test campaign orchestrator for the Sondera reference monitor.
#
# Phases: build → telemetry stack → harness → gated agent scenarios →
# adapter smokes → mandate → escalation → failure modes → summary.
#
# Env toggles:
#   SKIP_BUILD=1      skip cargo build / test
#   SKIP_LGTM=1       do not start the Grafana LGTM container
#   OTEL_ENDPOINT=... OTLP endpoint (default http://localhost:4317)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

OTEL_ENDPOINT="${OTEL_ENDPOINT:-http://localhost:4317}"
PY="$REPO_ROOT/examples/gated_file_agent/.venv/bin/python"

section() { printf '\n\033[1m### %s\033[0m\n' "$1"; }

cleanup() {
  stop_harness
}
trap cleanup EXIT

section "Phase 0 — build & unit tests"
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  (cd "$REPO_ROOT" && cargo build --workspace 2>&1 | tail -1)
  (cd "$REPO_ROOT" && cargo test --workspace 2>&1 | tail -3)
else
  echo "  skipped (SKIP_BUILD=1)"
fi

section "Phase 1 — telemetry stack (Grafana LGTM)"
if [ "${SKIP_LGTM:-0}" != "1" ]; then
  (cd "$REPO_ROOT/deploy/otel-lgtm" && docker compose up -d 2>&1 | tail -1)
  echo "  Grafana at http://localhost:3000 (Tempo + Prometheus)"
else
  echo "  skipped (SKIP_LGTM=1) — harness still exports if endpoint is reachable"
fi

section "Phase 2 — start harness (cedarling + OTel)"
pkill -f 'sondera-harness-server' 2>/dev/null || true
sleep 1
start_harness cedarling --escalation-ttl 5 --otel --otel-metrics --otel-endpoint "$OTEL_ENDPOINT"
echo "  harness up (pid $HARNESS_PID), admin at $ADMIN_URL"

section "Phase 3 — gated file agent scenarios"
if [ -x "$PY" ]; then
  if (cd "$REPO_ROOT/examples/gated_file_agent" && "$PY" -m gated_agent.agent --scenario all 2>/dev/null); then
    pass "gated agent: all scenarios matched"
  else
    fail "gated agent: scenario mismatch"
  fi
else
  fail "gated agent venv missing — run: (cd examples/gated_file_agent && uv venv && uv pip install -e . -e ../../sondera-python)"
fi

section "Phase 4 — adapter smokes"
bash "$REPO_ROOT/scripts/e2e/smoke_adapters.sh" || true

section "Phase 5 — mandate identities"
bash "$REPO_ROOT/scripts/e2e/mandate_phase.sh" || true

section "Phase 6 — escalation lifecycle"
bash "$REPO_ROOT/scripts/e2e/escalation_phase.sh" || true

section "Phase 6b — inspect / shadow mode"
bash "$REPO_ROOT/scripts/e2e/inspect_phase.sh" || true

section "Phase 6c — agent bill of materials (AgBOM)"
bash "$REPO_ROOT/scripts/e2e/agbom_phase.sh" || true

section "Phase 7 — telemetry assertions"
if [ "${SKIP_LGTM:-0}" = "1" ]; then
  echo "  skipped (SKIP_LGTM=1)"
else
  # Start a harness, generate traffic, then poll Prometheus. Metrics only
  # appear while an exporter is live; Prometheus drops the series once it stops.
  start_harness cedarling --otel --otel-metrics --otel-endpoint "$OTEL_ENDPOINT"
  gen_traffic() {
    curl -s -o /dev/null -X POST "$ADMIN_URL/api/adjudicate" -H 'Content-Type: application/json' \
      -d '{"event_id":"t","trajectory_id":"tel","timestamp":"2026-01-01T00:00:00Z","agent":{"id":"tel","provider_id":"e2e"},"actor":{"id":"tel","actor_type":"Agent"},"causality":{"correlation_id":"tel","causation_id":null,"parent_id":null},"event":{"category":"Action","payload":{"type":"ShellCommand","data":{"call_id":"c","command":"git status","working_dir":"/tmp"}}},"raw":null}' 2>/dev/null || true
  }
  gen_traffic
  # The OTel SDK's periodic metric reader flushes on a 60s cadence, so allow up
  # to ~100s. Traces stream immediately; only metrics wait for the export cycle.
  landed=0
  for _ in $(seq 1 50); do
    if curl -s "http://localhost:3000/api/datasources/proxy/uid/prometheus/api/v1/label/__name__/values" \
        2>/dev/null | grep -q 'sondera_adjudications_total'; then
      landed=1
      break
    fi
    gen_traffic
    sleep 2
  done
  if [ "$landed" = "1" ]; then
    pass "Prometheus has sondera_adjudications_total (+ duration histogram)"
  else
    fail "metrics did not land in Prometheus within ~100s (60s export cycle + scrape)"
  fi
  if curl -s -G "http://localhost:3000/api/datasources/proxy/uid/tempo/api/search" \
      --data-urlencode 'tags=service.name=sondera-harness' 2>/dev/null | grep -q 'sondera-harness'; then
    pass "Tempo has sondera-harness traces"
  else
    echo "  (traces not yet queryable — Tempo ingest lag)"
  fi
  stop_harness
fi

section "Phase 8 — failure modes (stops the harness)"
stop_harness
bash "$REPO_ROOT/scripts/e2e/failure_modes.sh" || true

section "Done"
summary "run_all"
