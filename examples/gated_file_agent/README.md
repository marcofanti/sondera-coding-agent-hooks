# Gated File Agent

A minimal sample agent whose stdio MCP server reads and writes files in a
sandbox folder, adjudicating **every** tool call through the Sondera harness
before touching disk. Unlike `rag_test_agent` (whose internal file reads are not
intercepted), this agent gates its own MCP tools via the `sondera-python`
`PolicyGate` → harness admin HTTP API (`http://localhost:9090/api/adjudicate`).

It is the phase-1 target of the end-to-end campaign — see
[`docs/e2e-runbook.md`](../../docs/e2e-runbook.md).

## Layout

- `gated_agent/mcp_file_server.py` — FastMCP stdio server. Tools: `list_files`,
  `read_file`, `write_file`, `delete_file`, `run_command`, `send_email` (mock).
  Each tool adjudicates first; Allow executes, Deny returns the policy ids,
  Escalate can block-poll for operator approval.
- `gated_agent/agent.py` — driver that runs the scenario matrix and prints a
  PASS/FAIL table (`--scenario permitted|forbidden|escalation|all`).
- `gated_agent/scenarios.py` — the expected decision per tool call.
- `gated_agent/setup_sandbox.py` — seeds `notes.md`, a fake `server.pem`, `config/`.

## Setup

```bash
uv venv --python 3.13 .venv
uv pip install --python .venv -e . -e ../../sondera-python -e '.[dev]'
```

## Run

Start the harness first:

```bash
cargo run --bin sondera-harness-server -- --policy-engine cedarling --admin-port 9090 -v
```

Then drive the scenarios (exits non-zero on any decision mismatch):

```bash
.venv/bin/python -m gated_agent.agent --scenario all
```

`--with-ollama` adds scenarios whose deny depends on the Ollama secure-code
classifier (skipped by default).

## Tests

```bash
.venv/bin/python -m pytest -q      # sandbox escape + decision mapping, no harness needed
```
