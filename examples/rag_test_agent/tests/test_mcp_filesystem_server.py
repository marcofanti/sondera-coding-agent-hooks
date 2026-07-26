from pathlib import Path

import pytest

from rag_agent.mcp_filesystem_server import read_document_text, resolve_relative


def test_resolve_relative_blocks_absolute_path(tmp_path):
    with pytest.raises(ValueError):
        resolve_relative(tmp_path, str(Path("/etc/passwd")))


def test_resolve_relative_blocks_parent_escape(tmp_path):
    with pytest.raises(ValueError):
        resolve_relative(tmp_path, "../outside.txt")


def test_read_document_text_reads_utf8_with_replacement(tmp_path):
    path = tmp_path / "note.md"
    path.write_bytes(b"hello\xffworld")

    text, extraction = read_document_text(path)

    assert "hello" in text
    assert "world" in text
    assert extraction == "text"
