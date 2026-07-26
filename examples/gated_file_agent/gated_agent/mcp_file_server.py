"""Policy-gated filesystem MCP server.

Every tool call is adjudicated by the Sondera harness (admin HTTP API) BEFORE
it touches the filesystem. The requested path/command — exactly as supplied by
the calling agent — is what gets adjudicated, so Cedar sees traversal attempts
and suspicious content before any local sanitization.

Environment:
    GATED_AGENT_ROOT        sandbox directory (required)
    SONDERA_ADMIN_URL       harness admin API (default http://localhost:9090)
    SONDERA_AGENT_ID        agent identity (default gated-file-agent)
    SONDERA_TRAJECTORY_ID   trajectory shared with the driver (default: fresh UUID)
    SONDERA_MANDATE_JWT     optional Ed25519 mandate JWT
"""

from __future__ import annotations

import os
import shlex
import subprocess
import uuid
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from sondera.actions import Action
from sondera.gate import PolicyGate

mcp = FastMCP("gated-filesystem")

COMMAND_TIMEOUT_SECS = 10
ESCALATION_POLL_SECS = 2.0


def sandbox_root() -> Path:
    root = os.environ.get("GATED_AGENT_ROOT")
    if not root:
        raise RuntimeError("GATED_AGENT_ROOT must be set to the sandbox directory")
    path = Path(root).expanduser().resolve()
    if not path.is_dir():
        raise RuntimeError(f"GATED_AGENT_ROOT is not a directory: {path}")
    return path


def build_gate() -> tuple[PolicyGate, str]:
    gate = PolicyGate(
        admin_url=os.environ.get("SONDERA_ADMIN_URL", "http://localhost:9090"),
        mandate_jwt=os.environ.get("SONDERA_MANDATE_JWT"),
        default_agent_id=os.environ.get("SONDERA_AGENT_ID", "gated-file-agent"),
        default_provider_id="python",
    )
    trajectory_id = os.environ.get("SONDERA_TRAJECTORY_ID", str(uuid.uuid4()))
    return gate, trajectory_id


GATE, TRAJECTORY_ID = build_gate()


def adjudicate(action: Any, wait_for_operator: bool = False, timeout: float = 60.0) -> dict:
    """Adjudicate an action; return a decision dict shared by every tool.

    Keys: decision (Allow|Deny|Escalate), reason, policy_ids, escalation_id.
    With wait_for_operator=True an Escalate blocks-polls until the operator
    approves/denies or the escalation times out, and the final decision is
    returned instead.
    """
    with GATE.trajectory(trajectory_id=TRAJECTORY_ID) as traj:
        decision = traj.check(action)

    if decision.escalate and wait_for_operator:
        handle = GATE.escalation_handle(decision)
        if handle is not None:
            resolved = handle.wait(poll_interval=ESCALATION_POLL_SECS, timeout=timeout)
            return {
                "decision": resolved.decision,
                "reason": resolved.reason,
                "policy_ids": _policy_ids(decision),
                "escalation_id": decision.escalation_id,
            }

    return {
        "decision": decision.decision,
        "reason": decision.reason,
        "policy_ids": _policy_ids(decision),
        "escalation_id": decision.escalation_id,
    }


def _policy_ids(decision: Any) -> list[str]:
    annotations = decision.annotations or []
    return [a["policy_id"] for a in annotations if isinstance(a, dict) and a.get("policy_id")]


def resolve_in_sandbox(root: Path, relative: str) -> Path:
    """Second line of defense: resolve under the sandbox root, refuse escapes."""
    if Path(relative).is_absolute():
        raise ValueError(f"absolute paths are not allowed: {relative}")
    resolved = (root / relative).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"path escapes the sandbox: {relative}")
    return resolved


def denied(verdict: dict) -> dict:
    return {"status": "denied", **verdict}


@mcp.tool()
def list_files(subdir: str = ".") -> dict:
    """List files in the sandbox (optionally under a subdirectory)."""
    verdict = adjudicate(Action.tool_call("list_files", subdir=subdir))
    if verdict["decision"] != "Allow":
        return denied(verdict)
    root = sandbox_root()
    base = resolve_in_sandbox(root, subdir) if subdir != "." else root
    entries = sorted(
        str(p.relative_to(root)) for p in base.rglob("*") if p.is_file()
    )
    return {"status": "ok", "files": entries, **verdict}


@mcp.tool()
def read_file(path: str) -> dict:
    """Read a text file from the sandbox. `path` is relative to the sandbox root."""
    verdict = adjudicate(Action.read_file(path))
    if verdict["decision"] != "Allow":
        return denied(verdict)
    root = sandbox_root()
    resolved = resolve_in_sandbox(root, path)
    content = resolved.read_text(encoding="utf-8", errors="replace")
    return {"status": "ok", "path": path, "content": content, **verdict}


@mcp.tool()
def write_file(path: str, content: str) -> dict:
    """Write a text file into the sandbox. `path` is relative to the sandbox root."""
    verdict = adjudicate(Action.write_file(path, content))
    if verdict["decision"] != "Allow":
        return denied(verdict)
    root = sandbox_root()
    resolved = resolve_in_sandbox(root, path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(content, encoding="utf-8")
    return {"status": "ok", "path": path, "bytes": len(content), **verdict}


@mcp.tool()
def delete_file(path: str) -> dict:
    """Delete a file from the sandbox. `path` is relative to the sandbox root."""
    verdict = adjudicate(Action.delete_file(path))
    if verdict["decision"] != "Allow":
        return denied(verdict)
    root = sandbox_root()
    resolved = resolve_in_sandbox(root, path)
    resolved.unlink(missing_ok=False)
    return {"status": "ok", "path": path, **verdict}


@mcp.tool()
def run_command(command: str) -> dict:
    """Run a shell command inside the sandbox. Denied commands never execute."""
    parts = shlex.split(command)
    if not parts:
        return {"status": "error", "error": "empty command"}
    verdict = adjudicate(Action.shell(parts[0], *parts[1:]))
    if verdict["decision"] != "Allow":
        return denied(verdict)
    root = sandbox_root()
    result = subprocess.run(
        parts,
        cwd=root,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECS,
        check=False,
    )
    return {
        "status": "ok",
        "exit_code": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        **verdict,
    }


@mcp.tool()
def send_email(to: str, subject: str, wait_for_operator: bool = False) -> dict:
    """Mock email send — exercises the escalate-send-email-default Cedar policy.

    No email is ever sent; on Allow the tool just reports what would have
    happened. With wait_for_operator=True the call blocks until a human
    approves or denies the escalation via the Sondera admin API.
    """
    verdict = adjudicate(Action.send_email(), wait_for_operator=wait_for_operator)
    if verdict["decision"] != "Allow":
        if verdict["decision"] == "Escalate":
            return {"status": "pending_approval", **verdict}
        return denied(verdict)
    return {"status": "ok", "note": f"mock email to {to}: {subject}", **verdict}


def main() -> None:
    sandbox_root()  # fail fast before serving
    mcp.run()


if __name__ == "__main__":
    main()
