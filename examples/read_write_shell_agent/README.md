# Read / Write / Shell Agent — governed by Sondera

A small [PydanticAI](https://ai.pydantic.dev/) agent (`claude-haiku-4-5`) with
three tools — `read_file`, `write_file`, `run_command` — scoped to a
`scratch_space/` workspace. It runs with `uv` for the environment and
[1Password `op`](https://developer.1password.com/docs/cli/) for the API key, and
it is governed by the Sondera harness at **two clearly separated layers**.

The agent code is the demo from the *"Build Your Own Agent — Escaping the
Harness"* talk; this example wraps it in the Sondera governance story.

## Files

| File | Role |
|------|------|
| `pydantic-ai-read-write-edit.py` | the original **ungated** agent (talk demo) |
| `gated-read-write-edit.py` | the **gated** agent — every tool call is adjudicated by the harness (Layer 2) |
| `event_logging.py` | vendored ANSI trace printer the agents import |
| `run.sh` | run the ungated agent live (`op` + `uv`) |
| `run_gated.sh` | run the gated agent live (`op` + `uv`, needs the harness) |
| `smoke.sh` | deterministic test — no model call, no tokens; proves both layers |
| `pyproject.toml` / `.env.example` | uv project + 1Password reference template |

## Two governance layers

```
┌─ Layer 1: Claude Code hooks (project scope) ────────────────────────┐
│  A hooked Claude Code session runs the launch command. sondera-claude │
│  PreToolUse adjudicates THAT Bash command — not what the agent does.  │
│     op run … uv run python …-read-write-edit.py   ← adjudicated       │
└──────────────────────────────────────────────────────────────────────┘
┌─ Layer 2: PolicyGate on the agent's own tools ──────────────────────┐
│  gated-read-write-edit.py sends each read/write/shell action to the  │
│  harness admin API before executing it. Governs what the agent DOES.  │
│     read_file("secrets.pem")  → Deny [forbid-private-key-read]        │
└──────────────────────────────────────────────────────────────────────┘
```

Layer 1 governs *launching* the agent; Layer 2 governs the agent's *actions*.
They are independent — you can use either or both.

## Prerequisites

- `uv` and the 1Password CLI `op` (with the desktop app's *Settings → Developer
  → Integrate with 1Password CLI* enabled).
- Rust workspace built: `cargo build --workspace` (for `sondera-harness-server`
  and `sondera-claude`).
- For Layer 2 / live gated runs, a running harness:
  ```bash
  cargo run --bin sondera-harness-server -- --policy-engine cedarling --admin-port 9090 -v
  ```

## Setup

```bash
cd examples/read_write_shell_agent
cp .env.example .env            # then edit .env
uv sync                         # build the environment
```

Put your own 1Password reference in `.env` (never a raw key):

```bash
ANTHROPIC_API_KEY=op://<vault>/<item>/credential
```

`op run --env-file=.env -- …` resolves the reference into a real environment
variable before Python starts; the in-script `load_dotenv()` then finds it
already set. `.env` is gitignored.

## Layer 1 — Claude Code project hooks

Install the hooks in **project scope** (committed `.claude/settings.json`, shared
with everyone who clones the repo):

```bash
cargo run -p sondera-claude -- install --project
```

Now, from a Claude Code session in this repo, ask it to run the agent. The Bash
command it issues is adjudicated by `sondera-claude pre-tool-use` before it runs.

Two real outcomes worth knowing (both asserted by `smoke.sh`):

- A plain launch with the key already in the environment is **Allowed**:
  ```bash
  uv run --project . python pydantic-ai-read-write-edit.py
  ```
- Resolving the key inline with `op run --env-file=.env` references a credential
  file, so the harness flags it **Deny** (`forbid-shell-credential-access`).
  This is a genuine governance signal: under project hooks, resolve the secret
  out-of-band rather than reading a credential file inside the tool command.

> Uninstall with `sondera-claude uninstall`. Installing project hooks routes
> every Claude Code tool call in this repo through the harness, so keep the
> harness running (Claude Code fails open if it is down — see the e2e runbook's
> Findings).

## Layer 2 — PolicyGate on the agent's tools

`gated-read-write-edit.py` calls `PolicyGate.check()` on each tool before it
touches disk or the shell. Start the harness, then:

```bash
./run_gated.sh "read the file secrets.pem"     # → blocked, model is told why
./run_gated.sh "write hello.txt saying hi"     # → allowed
```

A denied action returns `BLOCKED by Sondera (Deny): ['forbid-private-key-read']`
to the model instead of executing — the agent sees the policy verdict and can
adapt.

## Running the tests

### Deterministic smoke (no model call, no tokens)

Requires only a running harness on `:9090`:

```bash
./smoke.sh
```

It asserts (11 checks): `install --project` produces a valid project hook
config; the launch command is adjudicated (plain → Allow, `op --env-file` →
credential-access Deny, `rm -rf` tamper → Deny); and the agent's own tools are
adjudicated (clean write → Allow, private-key read → Deny, `rm -rf` → Deny).

### Live run (spends tokens; needs `op` signed in)

```bash
./run.sh        "list the files here and summarize them"   # ungated
./run_gated.sh  "read /etc/passwd"                          # gated, watch it block
```

These call `claude-haiku-4-5` for real, so they need a valid `.env`, an active
`op` session, and network access.
