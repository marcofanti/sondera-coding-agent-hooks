"""Unit tests that need no running harness."""

from __future__ import annotations

from pathlib import Path

import pytest

from gated_agent.mcp_file_server import resolve_in_sandbox
from gated_agent.setup_sandbox import build


def test_resolve_rejects_absolute(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        resolve_in_sandbox(tmp_path, "/etc/passwd")


def test_resolve_rejects_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        resolve_in_sandbox(tmp_path, "../../etc/passwd")


def test_resolve_allows_relative(tmp_path: Path) -> None:
    resolved = resolve_in_sandbox(tmp_path, "sub/file.txt")
    assert str(resolved).startswith(str(tmp_path))


def test_build_sandbox_seeds_fixtures(tmp_path: Path) -> None:
    build(tmp_path)
    assert (tmp_path / "notes.md").is_file()
    assert (tmp_path / "server.pem").is_file()
    assert "PRIVATE KEY" in (tmp_path / "server.pem").read_text()
    assert (tmp_path / "config" / "app.toml").is_file()
