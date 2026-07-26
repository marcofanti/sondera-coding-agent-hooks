# sondera-coding-agent-hooks

**Source:** https://github.com/marcofanti/sondera-coding-agent-hooks.git
**Stack:** Rust (Cargo workspace) + Cedar policies + YARA signatures; Python SDK

A reference monitor / guardrail system for AI coding agents. Rust hook binaries and [Cedar](https://docs.cedarpolicy.com/) policies intercept every shell command, file operation, and web request to block exfiltration and destructive behaviors and to enforce information-flow control. YARA signatures and Cedar evaluation are deterministic; optional LLM-based classifiers (data sensitivity, secure-code policy) run on Ollama. Works with Claude Code, Cursor, GitHub Copilot, and Gemini CLI. This repo is a personal fork of `sondera-ai/sondera-coding-agent-hooks` extended with live guardrail wiring into Cedar context, taint/IFC label propagation, real-time escalation infrastructure, communication/browser policies, and a Python SDK for LangChain/agent frameworks. Released alongside the "Hooking Coding Agents with the Cedar Policy Language" talk at Unprompted 2026.

## Running it

```bash
# Prereqs: Rust + Cargo (rustup). Optional LLM classifiers need Ollama + gpt-oss-safeguard-20b (~12 GB)
cargo build --release
```

The workspace builds per-agent hook binaries under `apps/` (claude, copilot, cursor, gemini). See `README.md`, `DESIGN.md`, and `HANDOFF.md` for wiring hooks into each coding agent and the Cedar policies in `policies/`.
