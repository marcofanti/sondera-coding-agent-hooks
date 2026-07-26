"""Local filesystem MCP server for the RAG test agent.

The server is launched with RAG_AGENT_ALLOWED_ROOT. Every tool accepts relative
paths only, then resolves them under that root to make traversal mistakes
unrepresentable to the calling agent.
"""

from __future__ import annotations

import hashlib
import html
import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP


TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cfg",
    ".cpp",
    ".cs",
    ".css",
    ".csv",
    ".go",
    ".h",
    ".hpp",
    ".htm",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".log",
    ".md",
    ".mdx",
    ".py",
    ".rb",
    ".rs",
    ".rst",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

OPTIONAL_DOCUMENT_EXTENSIONS = {".pdf", ".docx"}
IGNORED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "dist",
    "node_modules",
    "target",
}
DEFAULT_MAX_BYTES = 2_000_000


def _error(
    error_type: str,
    message: str,
    *,
    recoverable: bool = True,
    **data: Any,
) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "type": error_type,
            "message": message,
            "recoverable": recoverable,
            "data": data,
        },
    }


def _ok(**data: Any) -> dict[str, Any]:
    return {"ok": True, **data}


def allowed_root() -> Path:
    raw = os.environ.get("RAG_AGENT_ALLOWED_ROOT")
    if not raw:
        raise RuntimeError("RAG_AGENT_ALLOWED_ROOT must point at the folder to index")
    root = Path(raw).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise RuntimeError(f"RAG_AGENT_ALLOWED_ROOT is not a directory: {root}")
    return root


def resolve_relative(root: Path, relative_path: str | None) -> Path:
    rel = (relative_path or ".").strip() or "."
    rel_path = Path(rel)
    if rel_path.is_absolute():
        raise ValueError("Use a relative path inside the allowed root, not an absolute path")

    candidate = (root / rel_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("Path escapes the allowed root")
    return candidate


def relative_to_root(root: Path, path: Path) -> str:
    rel = path.resolve().relative_to(root)
    text = rel.as_posix()
    return "." if text == "" else text


def is_supported_document(path: Path) -> bool:
    suffix = path.suffix.lower()
    return suffix in TEXT_EXTENSIONS or suffix in OPTIONAL_DOCUMENT_EXTENSIONS


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_text_file(path: Path, max_bytes: int) -> tuple[str, str]:
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError(f"Document is {len(raw)} bytes, over the {max_bytes} byte limit")
    return raw.decode("utf-8", errors="replace"), "text"


def _read_pdf(path: Path, max_bytes: int) -> tuple[str, str]:
    if path.stat().st_size > max_bytes:
        raise ValueError(f"Document is {path.stat().st_size} bytes, over the {max_bytes} byte limit")
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise RuntimeError("Install rag-test-agent[documents] to read PDF files") from exc

    reader = PdfReader(str(path))
    pages = [(page.extract_text() or "") for page in reader.pages]
    return "\n\n".join(pages), "pdf"


def _read_docx(path: Path, max_bytes: int) -> tuple[str, str]:
    if path.stat().st_size > max_bytes:
        raise ValueError(f"Document is {path.stat().st_size} bytes, over the {max_bytes} byte limit")
    try:
        import docx
    except ImportError as exc:
        raise RuntimeError("Install rag-test-agent[documents] to read DOCX files") from exc

    document = docx.Document(str(path))
    paragraphs = [paragraph.text for paragraph in document.paragraphs]
    return "\n".join(paragraphs), "docx"


def read_document_text(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[str, str]:
    suffix = path.suffix.lower()
    if suffix in TEXT_EXTENSIONS:
        if suffix in {".htm", ".html"}:
            text, kind = _read_text_file(path, max_bytes)
            return html.unescape(text), kind
        return _read_text_file(path, max_bytes)
    if suffix == ".pdf":
        return _read_pdf(path, max_bytes)
    if suffix == ".docx":
        return _read_docx(path, max_bytes)
    raise ValueError(f"Unsupported document extension: {suffix or '<none>'}")


def entry_payload(root: Path, path: Path) -> dict[str, Any]:
    stat = path.stat()
    suffix = path.suffix.lower()
    kind = "directory" if path.is_dir() else "file"
    ignored = path.is_dir() and path.name in IGNORED_DIR_NAMES
    return {
        "name": path.name,
        "relative_path": relative_to_root(root, path),
        "kind": kind,
        "size_bytes": stat.st_size if path.is_file() else 0,
        "modified": stat.st_mtime,
        "extension": suffix,
        "ignored": ignored,
        "supported_document": path.is_file() and is_supported_document(path),
    }


mcp = FastMCP(
    "rag-filesystem",
    instructions=(
        "Use list_directory to recursively discover files under the allowed root. "
        "Use read_document only on supported_document entries returned by list_directory. "
        "All paths must be relative to the allowed root."
    ),
)


@mcp.tool(
    description=(
        "Describe the single filesystem root this MCP server is allowed to expose. "
        "Use this first to confirm the indexing scope."
    )
)
def describe_root() -> dict[str, Any]:
    root = allowed_root()
    stat = root.stat()
    return _ok(
        root=str(root),
        name=root.name,
        modified=stat.st_mtime,
        ignored_directory_names=sorted(IGNORED_DIR_NAMES),
        supported_extensions=sorted(TEXT_EXTENSIONS | OPTIONAL_DOCUMENT_EXTENSIONS),
        next_actions=["Call list_directory with relative_path='.'"],
    )


@mcp.tool(
    description=(
        "List one directory below the allowed root. Do not pass absolute paths. "
        "The result marks directories to skip and files that read_document can ingest."
    )
)
def list_directory(relative_path: str = ".") -> dict[str, Any]:
    root = allowed_root()
    try:
        directory = resolve_relative(root, relative_path)
    except ValueError as exc:
        return _error("PATH_OUTSIDE_ROOT", str(exc), relative_path=relative_path)

    if not directory.exists():
        return _error("NOT_FOUND", "Directory does not exist", relative_path=relative_path)
    if not directory.is_dir():
        return _error("NOT_A_DIRECTORY", "Path is not a directory", relative_path=relative_path)

    try:
        entries = [
            entry_payload(root, child)
            for child in sorted(directory.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        ]
    except PermissionError as exc:
        return _error("PERMISSION_DENIED", str(exc), relative_path=relative_path)

    return _ok(
        root=str(root),
        relative_path=relative_to_root(root, directory),
        entries=entries,
        next_actions=[
            "Recurse into entries where kind='directory' and ignored=false",
            "Call read_document for entries where supported_document=true",
        ],
    )


@mcp.tool(
    description=(
        "Read a supported document below the allowed root and return extracted text. "
        "Use paths exactly as returned by list_directory."
    )
)
def read_document(relative_path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    root = allowed_root()
    try:
        path = resolve_relative(root, relative_path)
    except ValueError as exc:
        return _error("PATH_OUTSIDE_ROOT", str(exc), relative_path=relative_path)

    if not path.exists():
        return _error("NOT_FOUND", "Document does not exist", relative_path=relative_path)
    if not path.is_file():
        return _error("NOT_A_FILE", "Path is not a file", relative_path=relative_path)
    if not is_supported_document(path):
        return _error(
            "UNSUPPORTED_DOCUMENT",
            "The extension is not in the supported document set",
            relative_path=relative_path,
            extension=path.suffix.lower(),
            supported_extensions=sorted(TEXT_EXTENSIONS | OPTIONAL_DOCUMENT_EXTENSIONS),
        )

    try:
        text, extraction = read_document_text(path, max_bytes=max_bytes)
    except PermissionError as exc:
        return _error("PERMISSION_DENIED", str(exc), relative_path=relative_path)
    except (RuntimeError, ValueError, OSError) as exc:
        return _error("READ_FAILED", str(exc), relative_path=relative_path)

    stat = path.stat()
    return _ok(
        relative_path=relative_to_root(root, path),
        extension=path.suffix.lower(),
        size_bytes=stat.st_size,
        modified=stat.st_mtime,
        sha256=_file_sha256(path),
        extraction=extraction,
        text=text,
        next_actions=["Chunk and embed this text before reading another document"],
    )


@mcp.tool(
    description=(
        "Return a bounded recursive manifest of supported documents. Prefer the "
        "list_directory/read_document workflow for full indexing; this is for previews."
    )
)
def scan_documents(max_files: int = 500) -> dict[str, Any]:
    root = allowed_root()
    documents: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for current, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in IGNORED_DIR_NAMES]
        current_path = Path(current)
        for filename in sorted(files):
            path = current_path / filename
            if not is_supported_document(path):
                continue
            if len(documents) >= max_files:
                skipped.append({"reason": "max_files_reached", "remaining_from": str(current_path)})
                return _ok(root=str(root), documents=documents, skipped=skipped)
            documents.append(entry_payload(root, path))

    return _ok(root=str(root), documents=documents, skipped=skipped)


def main() -> None:
    mcp.run("stdio")


if __name__ == "__main__":
    main()
