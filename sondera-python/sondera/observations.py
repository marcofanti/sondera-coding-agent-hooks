"""Observation constructors that produce JSON-serialisable event payloads.

Observations are sent AFTER a tool executes so the harness can classify
output sensitivity and propagate taints onto the trajectory.

Like actions, the harness `TrajectoryEvent` enum is adjacently tagged as
`{"category": "Observation", "payload": {"type": <variant>, "data": {...}}}`.
The `data` field names match the Rust structs exactly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Optional


def _obs_event(variant: str, data: dict) -> dict:
    return {"category": "Observation", "payload": {"type": variant, "data": data}}


@dataclass
class ShellOutputObservation:
    call_id: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0

    def to_event(self) -> dict:
        return _obs_event(
            "ShellCommandOutput",
            {
                "call_id": self.call_id,
                "exit_code": self.exit_code,
                "stdout": self.stdout,
                "stderr": self.stderr,
            },
        )


@dataclass
class FileResultObservation:
    call_id: str
    content: Optional[str] = None
    error: Optional[str] = None

    def to_event(self) -> dict:
        return _obs_event(
            "FileOperationResult",
            {
                "call_id": self.call_id,
                "success": self.error is None,
                "content": self.content,
                "error": self.error,
            },
        )


@dataclass
class WebFetchOutputObservation:
    call_id: str
    url: str = ""
    result: str = ""
    code: int = 200

    def to_event(self) -> dict:
        return _obs_event(
            "WebFetchOutput",
            {
                "call_id": self.call_id,
                "url": self.url,
                "code": self.code,
                "result": self.result,
            },
        )


@dataclass
class ToolOutputObservation:
    call_id: str
    output: Any = None
    error: Optional[str] = None

    def to_event(self) -> dict:
        return _obs_event(
            "ToolOutput",
            {
                "call_id": self.call_id,
                "success": self.error is None,
                "output": self.output,
                "error": self.error,
            },
        )


@dataclass
class PromptObservation:
    content: str
    role: str = "User"

    def to_event(self) -> dict:
        return _obs_event(
            "Prompt",
            {"content": self.content, "role": self.role},
        )


@dataclass
class ThinkObservation:
    thought: str

    def to_event(self) -> dict:
        return _obs_event("Think", {"thought": self.thought})


class Observation:
    """Factory for common observation types."""

    @staticmethod
    def shell_output(
        stdout: str,
        stderr: str = "",
        exit_code: int = 0,
        call_id: Optional[str] = None,
    ) -> ShellOutputObservation:
        return ShellOutputObservation(
            call_id=call_id or str(uuid.uuid4()),
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
        )

    @staticmethod
    def file_result(
        content: Optional[str] = None,
        error: Optional[str] = None,
        call_id: Optional[str] = None,
    ) -> FileResultObservation:
        return FileResultObservation(
            call_id=call_id or str(uuid.uuid4()),
            content=content,
            error=error,
        )

    @staticmethod
    def web_fetch_output(
        result: str,
        url: str = "",
        code: int = 200,
        call_id: Optional[str] = None,
    ) -> WebFetchOutputObservation:
        return WebFetchOutputObservation(
            call_id=call_id or str(uuid.uuid4()),
            url=url,
            result=result,
            code=code,
        )

    @staticmethod
    def tool_output(
        output: Any = None,
        error: Optional[str] = None,
        call_id: Optional[str] = None,
    ) -> ToolOutputObservation:
        return ToolOutputObservation(
            call_id=call_id or str(uuid.uuid4()),
            output=output,
            error=error,
        )

    @staticmethod
    def prompt(content: str, role: str = "User") -> PromptObservation:
        return PromptObservation(content=content, role=role)

    @staticmethod
    def think(thought: str) -> ThinkObservation:
        return ThinkObservation(thought=thought)
