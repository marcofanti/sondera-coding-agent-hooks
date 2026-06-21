"""Action constructors that produce JSON-serialisable event payloads.

Each helper returns a dict matching the Rust `TrajectoryEvent::Action(…)` enum
variants that the harness understands.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ShellAction:
    command: str
    args: list[str] = field(default_factory=list)

    def to_event(self) -> dict:
        return {
            "Action": {
                "ShellCommand": {
                    "command": self.command,
                    "args": self.args,
                }
            }
        }


@dataclass
class FileReadAction:
    path: str

    def to_event(self) -> dict:
        return {
            "Action": {
                "FileOperation": {
                    "path": self.path,
                    "operation": "Read",
                    "content": None,
                }
            }
        }


@dataclass
class FileWriteAction:
    path: str
    content: str

    def to_event(self) -> dict:
        return {
            "Action": {
                "FileOperation": {
                    "path": self.path,
                    "operation": "Write",
                    "content": self.content,
                }
            }
        }


@dataclass
class WebFetchAction:
    url: str
    prompt: str = "fetch"

    def to_event(self) -> dict:
        return {
            "Action": {
                "WebFetch": {
                    "url": self.url,
                    "prompt": self.prompt,
                }
            }
        }


@dataclass
class ToolCallAction:
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)

    def to_event(self) -> dict:
        return {
            "Action": {
                "ToolCall": {
                    "tool": self.tool,
                    "arguments": self.arguments,
                }
            }
        }


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
