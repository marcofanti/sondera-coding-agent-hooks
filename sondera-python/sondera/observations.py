"""Observation constructors that produce JSON-serialisable event payloads.

Observations are sent AFTER a tool executes so the harness can classify
output sensitivity and propagate taints onto the trajectory.

Each helper returns a dict matching the Rust `TrajectoryEvent::Observation(…)`
enum variants.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ShellOutputObservation:
    call_id: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0

    def to_event(self) -> dict:
        return {
            "Observation": {
                "ShellCommandOutput": {
                    "call_id": self.call_id,
                    "stdout": self.stdout,
                    "stderr": self.stderr,
                    "exit_code": self.exit_code,
                }
            }
        }


@dataclass
class FileResultObservation:
    call_id: str
    content: Optional[str] = None
    error: Optional[str] = None

    def to_event(self) -> dict:
        return {
            "Observation": {
                "FileOperationResult": {
                    "call_id": self.call_id,
                    "content": self.content,
                    "error": self.error,
                }
            }
        }


@dataclass
class WebFetchOutputObservation:
    call_id: str
    body: str = ""
    status_code: int = 200

    def to_event(self) -> dict:
        return {
            "Observation": {
                "WebFetchOutput": {
                    "call_id": self.call_id,
                    "body": self.body,
                    "status_code": self.status_code,
                }
            }
        }


@dataclass
class ToolOutputObservation:
    call_id: str
    output: Any = None
    error: Optional[str] = None

    def to_event(self) -> dict:
        return {
            "Observation": {
                "ToolOutput": {
                    "call_id": self.call_id,
                    "output": self.output,
                    "error": self.error,
                }
            }
        }


@dataclass
class PromptObservation:
    content: str
    role: str = "user"

    def to_event(self) -> dict:
        return {
            "Observation": {
                "Prompt": {
                    "content": self.content,
                    "role": self.role,
                }
            }
        }


@dataclass
class ThinkObservation:
    thought: str

    def to_event(self) -> dict:
        return {
            "Observation": {
                "Think": {
                    "thought": self.thought,
                }
            }
        }


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
        body: str,
        status_code: int = 200,
        call_id: Optional[str] = None,
    ) -> WebFetchOutputObservation:
        return WebFetchOutputObservation(
            call_id=call_id or str(uuid.uuid4()),
            body=body,
            status_code=status_code,
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
    def prompt(content: str, role: str = "user") -> PromptObservation:
        return PromptObservation(content=content, role=role)

    @staticmethod
    def think(thought: str) -> ThinkObservation:
        return ThinkObservation(thought=thought)
