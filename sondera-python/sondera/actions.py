"""Action constructors that produce JSON-serialisable event payloads.

The harness `TrajectoryEvent` enum is adjacently tagged as
`{"category": <variant>, "payload": {...}}`, and the inner `Action` enum as
`{"type": <variant>, "data": {...}}`. Every action struct also carries a
`call_id`. Helpers below emit exactly that shape so the harness deserializer
accepts the event.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


def _call_id() -> str:
    return f"call-{uuid.uuid4()}"


def _action_event(variant: str, data: dict) -> dict:
    return {"category": "Action", "payload": {"type": variant, "data": data}}


@dataclass
class ShellAction:
    command: str
    args: list[str] = field(default_factory=list)

    def to_event(self) -> dict:
        # The Rust ShellCommand struct has a single `command` string plus an
        # optional working_dir; args fold into the command line so guardrails
        # scan the full invocation, not just the binary name.
        full_command = " ".join([self.command, *self.args]) if self.args else self.command
        return _action_event(
            "ShellCommand",
            {"call_id": _call_id(), "command": full_command, "working_dir": None},
        )


@dataclass
class FileReadAction:
    path: str

    def to_event(self) -> dict:
        return _action_event(
            "FileOperation",
            {"call_id": _call_id(), "operation": "Read", "path": self.path, "content": None},
        )


@dataclass
class FileWriteAction:
    path: str
    content: str

    def to_event(self) -> dict:
        return _action_event(
            "FileOperation",
            {
                "call_id": _call_id(),
                "operation": "Write",
                "path": self.path,
                "content": self.content,
            },
        )


@dataclass
class FileDeleteAction:
    path: str

    def to_event(self) -> dict:
        return _action_event(
            "FileOperation",
            {"call_id": _call_id(), "operation": "Delete", "path": self.path, "content": None},
        )


@dataclass
class WebFetchAction:
    url: str
    prompt: str = "fetch"

    def to_event(self) -> dict:
        return _action_event(
            "WebFetch",
            {"call_id": _call_id(), "url": self.url, "prompt": self.prompt},
        )


@dataclass
class ToolCallAction:
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)

    def to_event(self) -> dict:
        return _action_event(
            "ToolCall",
            {"call_id": _call_id(), "tool": self.tool, "arguments": self.arguments},
        )


class Action:
    """Factory for common action types."""

    @staticmethod
    def shell(command: str, *args: str) -> ShellAction:
        return ShellAction(command=command, args=list(args))

    @staticmethod
    def read_file(path: str) -> FileReadAction:
        return FileReadAction(path=path)

    @staticmethod
    def write_file(path: str, content: str) -> FileWriteAction:
        return FileWriteAction(path=path, content=content)

    @staticmethod
    def delete_file(path: str) -> FileDeleteAction:
        return FileDeleteAction(path=path)

    @staticmethod
    def fetch(url: str, prompt: str = "fetch") -> WebFetchAction:
        return WebFetchAction(url=url, prompt=prompt)

    @staticmethod
    def navigate(url: str) -> WebFetchAction:
        return WebFetchAction(url=url, prompt="navigate")

    @staticmethod
    def submit_form(url: str) -> WebFetchAction:
        return WebFetchAction(url=url, prompt="submit_form")

    @staticmethod
    def tool_call(tool: str, **kwargs: Any) -> ToolCallAction:
        return ToolCallAction(tool=tool, arguments=kwargs)

    @staticmethod
    def send_email(api: str = "mail.google.com") -> WebFetchAction:
        return WebFetchAction(url=f"https://{api}", prompt="send_email")

    @staticmethod
    def read_email(api: str = "mail.google.com") -> WebFetchAction:
        return WebFetchAction(url=f"https://{api}", prompt="read_email")

    @staticmethod
    def create_event(api: str = "calendar.google.com") -> WebFetchAction:
        return WebFetchAction(url=f"https://{api}", prompt="create_event")

    @staticmethod
    def delete_event(api: str = "calendar.google.com") -> WebFetchAction:
        return WebFetchAction(url=f"https://{api}", prompt="delete_event")
