# RAG Test Agent

Local prototype: a web UI starts an agent that indexes a folder through a
filesystem MCP server, stores document chunks in SQLite, and retrieves relevant
chunks for questions.

## Shape

```
Browser UI
  -> FastAPI app
    -> RagAgent
      -> stdio MCP client
        -> rag-filesystem MCP server
          -> allowed local folder only
      -> SQLite RAG index
      -> optional Gemini answer generation
```

The MCP server is launched per indexing job with `RAG_AGENT_ALLOWED_ROOT` set to
the selected folder. Tools only accept relative paths under that root.

## Run Locally

From this directory:

```bash
cd examples/rag_test_agent
python3 -m pip install -e ".[documents]"
python3 -m rag_agent.web --port 8787
```

Open http://127.0.0.1:8787.

For a throwaway run that does not write the SQLite index into the repo:

```bash
python3 -m rag_agent.web \
  --host 127.0.0.1 \
  --port 8787 \
  --embedding-provider hash \
  --db /tmp/rag-test-agent.sqlite
```

With `uv`, the same isolated test run is:

```bash
uv run --with-editable . --with mcp --with fastapi --with uvicorn \
  python -m rag_agent.web --port 8787 --embedding-provider hash
```

Gemini is optional. Set `GEMINI_API_KEY` or `GOOGLE_API_KEY` to use
`gemini-embedding-001` for embeddings and `gemini-2.5-flash` for answer
generation. Without a key, the agent uses deterministic local hash embeddings
and returns retrieved sources without generated prose.

## Cache / Index Location

The RAG index is a local SQLite database.

- Default: `.rag-test-agent/rag.sqlite` under the current working directory.
- Override: pass `--db /path/to/rag.sqlite`.
- Reset: stop the server and delete the SQLite file.

Re-indexing skips unchanged files by SHA-256. Removed files are not pruned yet;
delete the SQLite file for an exact rebuild.

## Add Sondera Hooks To Catch Agent Activity

The hooks catch tool calls made by Claude Code, Cursor, Copilot, or Gemini CLI.
They do not automatically intercept arbitrary Python file reads made by a web
server that you start manually from a terminal.

Use this path when you want the coding agent that launches or operates this test
agent to be monitored by the Sondera harness.

### 1. Start the harness

From the repository root:

```bash
cargo run --bin sondera-harness-server -- \
  --policy-engine cedarling \
  --admin-port 9090 \
  -v
```

Keep this process running. Hook binaries send events to this harness over the
standard Sondera Unix socket.

### 2. Install the Claude Code hook

Development install, local to this repo:

```bash
cargo run -p sondera-claude -- install
```

Binary install, better for daily use:

```bash
cargo install --path apps/claude
sondera-claude install
```

Scope options:

```bash
sondera-claude install           # .claude/settings.local.json, local only
sondera-claude install --project # .claude/settings.json, committed/shared
sondera-claude install --user    # ~/.claude/settings.json, all projects
```

Restart Claude Code after installing the hook.

### 3. Run the test agent from a hooked Claude session

Ask Claude Code to run:

```bash
cd examples/rag_test_agent
python3 -m rag_agent.web --port 8787 --embedding-provider hash
```

Then open http://127.0.0.1:8787 and index a folder.

What the hook catches in this setup:

- The Claude Code `Bash` call that starts the web app.
- Claude Code shell/file/web actions used to operate or test the app.
- Prompt, lifecycle, permission, pre-tool-use, and post-tool-use events.

What it does not catch yet:

- The internal `read_document` calls made by this Python MCP filesystem server
  after the web server is running.

To catch every document read, wire harness adjudication directly into
`rag_agent/mcp_filesystem_server.py` before `read_document` reads a file. The
existing `sondera-python` SDK exposes `PolicyGate` and `Action.read_file(...)`
for that next step.

### 4. Verify the hook is active

Check the installed settings:

```bash
cat .claude/settings.local.json
```

You should see `PreToolUse`, `PostToolUse`, `SessionStart`, and related events
calling `sondera-claude`.

In the harness terminal, run a simple Claude Code command like:

```bash
pwd
```

The harness should log the corresponding hook event. If it does not:

1. Confirm the harness process is still running.
2. Confirm `sondera-claude --help` works.
3. Restart Claude Code after installing hooks.
4. Check whether hooks were installed at local, project, or user scope.

Other agent hook installers live beside the Claude one:

```bash
cargo run -p sondera-cursor -- install
cargo run -p sondera-gemini -- install
cargo run -p sondera-copilot -- install
```

## MCP Tools

- `describe_root`: returns the allowed root and supported extensions.
- `list_directory`: lists one relative directory and marks supported documents.
- `read_document`: extracts text from one supported document.
- `scan_documents`: bounded recursive manifest for previews.

## Supported Documents

Text-like files are supported directly: Markdown, text, source code, JSON, YAML,
TOML, CSV, HTML, XML, SQL, logs, and common script files.

PDF and DOCX require the `documents` extra.

## Design Review Pressure Points

1. Should folder access be per-job, per-session, or persisted as a long-lived
   allowlist? Per-job is safer but slower.
2. Is a local stdio MCP server enough, or should this become MCPB so non-Python
   users can run it without managing dependencies?
3. What is the intended corpus size? This prototype linearly scans SQLite
   embeddings, which is fine for tests and bad for large corpora.
4. Do you want exact re-indexing semantics? Current behavior skips unchanged
   files by SHA-256 but does not delete index rows for files removed from disk.
5. Should the RAG index store raw text? That makes source inspection easy but
   creates a local data-retention and secrets problem.
6. Are binary enterprise docs first-class? If yes, PDF/DOCX extraction needs
   quality scoring, OCR fallback, and extraction failure visibility.
7. Should answer generation be allowed to call a hosted model with retrieved
   local content? If not, use local generation or retrieval-only mode.
