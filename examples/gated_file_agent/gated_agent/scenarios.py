"""Scenario matrix: each row is an MCP tool call and the decision Cedar should return.

`expect_policy` is the `@id` of the policy that should appear in the decision's
annotations. It is asserted only when the harness surfaces annotations (it always
does for forbid matches), and skipped for Allow rows where no forbid fires.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

AWS_KEY_LINE = 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
PY_SECRET = 'API_TOKEN = "sk-live-abcdef0123456789abcdef0123456789"\n'
SQL_INJECTION = 'query = "SELECT * FROM users WHERE id = %s" % user_input\n'


@dataclass(frozen=True)
class Scenario:
    name: str
    group: str  # permitted | forbidden | escalation
    tool: str
    args: dict[str, Any]
    expect: str  # Allow | Deny | Escalate
    expect_policy: str | None = None
    # True when the deny relies on the Ollama secure-code / IFC classifier.
    # These are skipped in the default YARA-only run because the classifier
    # degrades to permissive defaults (compliant=true) without Ollama.
    requires_ollama: bool = False


def matrix() -> list[Scenario]:
    return [
        # ── permitted ──────────────────────────────────────────────────────
        Scenario(
            "write_notes", "permitted", "write_file",
            {"path": "scratch.md", "content": "# scratch\nhello\n"}, "Allow",
        ),
        Scenario("read_notes", "permitted", "read_file", {"path": "notes.md"}, "Allow"),
        Scenario("list_all", "permitted", "list_files", {"subdir": "."}, "Allow"),
        Scenario(
            "run_ls", "permitted", "run_command", {"command": "ls -la"}, "Allow",
        ),
        # ── forbidden ──────────────────────────────────────────────────────
        Scenario(
            "read_private_key", "forbidden", "read_file", {"path": "server.pem"},
            "Deny", "forbid-private-key-read",
        ),
        Scenario(
            "write_env_secret", "forbidden", "write_file",
            {"path": ".env", "content": AWS_KEY_LINE}, "Deny",
            "forbid-env-file-write-with-secrets",
        ),
        Scenario(
            "write_py_secret", "forbidden", "write_file",
            {"path": "app.py", "content": PY_SECRET}, "Deny",
            "forbid-source-write-secrets-python",
        ),
        Scenario(
            "sql_injection", "forbidden", "write_file",
            {"path": "query.sql", "content": SQL_INJECTION}, "Deny",
            # SC2 (injection) is classified by the Ollama secure-code model; the
            # forbid-injection-sql policy keys on policy.violations.contains("SC2").
            # Without Ollama the classifier reports compliant=true and this allows.
            "forbid-injection-sql", requires_ollama=True,
        ),
        Scenario(
            "destructive_rm", "forbidden", "run_command",
            {"command": "rm -rf /"}, "Deny", "forbid-rm-rf",
        ),
        # ── escalation ─────────────────────────────────────────────────────
        Scenario(
            "send_email", "escalation", "send_email",
            {"to": "ops@example.com", "subject": "status"}, "Escalate",
            "escalate-send-email-default",
        ),
    ]
