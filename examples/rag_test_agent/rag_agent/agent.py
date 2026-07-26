"""RAG test agent orchestration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from .index import RagIndex
from .llm import generate_answer
from .mcp_client import FilesystemMcpClient


ProgressCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


@dataclass
class IndexStats:
    root: str
    directories_seen: int = 0
    documents_seen: int = 0
    documents_indexed: int = 0
    chunks_indexed: int = 0
    skipped: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "directories_seen": self.directories_seen,
            "documents_seen": self.documents_seen,
            "documents_indexed": self.documents_indexed,
            "chunks_indexed": self.chunks_indexed,
            "skipped": self.skipped[-100:],
        }


class RagAgent:
    def __init__(self, db_path: str | Path, *, embedding_provider: str = "auto") -> None:
        from .embeddings import build_embedding_provider

        self.index = RagIndex(db_path, embedding_provider=build_embedding_provider(embedding_provider))

    async def index_folder(
        self,
        folder_path: str | Path,
        *,
        progress: ProgressCallback | None = None,
        max_document_bytes: int = 2_000_000,
    ) -> dict[str, Any]:
        root = Path(folder_path).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Folder does not exist or is not a directory: {root}")

        stats = IndexStats(root=str(root))
        async with FilesystemMcpClient(root) as fs:
            await self._emit(progress, {"phase": "connected", "tools": await fs.list_tools()})
            await self._walk_directory(
                fs,
                relative_path=".",
                stats=stats,
                progress=progress,
                max_document_bytes=max_document_bytes,
            )

        summary = stats.as_dict()
        summary["index"] = self.index.stats(root=str(root))
        await self._emit(progress, {"phase": "complete", **summary})
        return summary

    async def _walk_directory(
        self,
        fs: FilesystemMcpClient,
        *,
        relative_path: str,
        stats: IndexStats,
        progress: ProgressCallback | None,
        max_document_bytes: int,
    ) -> None:
        response = await fs.call_json("list_directory", {"relative_path": relative_path})
        if not response.get("ok"):
            stats.skipped.append({"relative_path": relative_path, "error": response.get("error")})
            await self._emit(progress, {"phase": "skip_directory", "relative_path": relative_path})
            return

        stats.directories_seen += 1
        await self._emit(
            progress,
            {
                "phase": "scan_directory",
                "relative_path": relative_path,
                "directories_seen": stats.directories_seen,
            },
        )

        for entry in response.get("entries", []):
            if entry.get("kind") == "directory":
                if entry.get("ignored"):
                    stats.skipped.append({"relative_path": entry["relative_path"], "reason": "ignored_directory"})
                    continue
                await self._walk_directory(
                    fs,
                    relative_path=entry["relative_path"],
                    stats=stats,
                    progress=progress,
                    max_document_bytes=max_document_bytes,
                )
            elif entry.get("supported_document"):
                await self._index_document(
                    fs,
                    entry["relative_path"],
                    stats=stats,
                    progress=progress,
                    max_document_bytes=max_document_bytes,
                )

    async def _index_document(
        self,
        fs: FilesystemMcpClient,
        relative_path: str,
        *,
        stats: IndexStats,
        progress: ProgressCallback | None,
        max_document_bytes: int,
    ) -> None:
        stats.documents_seen += 1
        response = await fs.call_json(
            "read_document",
            {"relative_path": relative_path, "max_bytes": max_document_bytes},
        )
        if not response.get("ok"):
            stats.skipped.append({"relative_path": relative_path, "error": response.get("error")})
            await self._emit(progress, {"phase": "skip_document", "relative_path": relative_path})
            return

        chunks = await asyncio.to_thread(
            self.index.upsert_document,
            root=stats.root,
            relative_path=response["relative_path"],
            text=response["text"],
            size_bytes=int(response["size_bytes"]),
            modified=float(response["modified"]),
            sha256=response["sha256"],
            extraction=response["extraction"],
        )
        if chunks:
            stats.documents_indexed += 1
            stats.chunks_indexed += chunks
        await self._emit(
            progress,
            {
                "phase": "index_document",
                "relative_path": relative_path,
                "chunks": chunks,
                "documents_seen": stats.documents_seen,
                "documents_indexed": stats.documents_indexed,
            },
        )

    def ask(self, question: str, *, root: str | None = None, top_k: int = 6) -> dict[str, Any]:
        normalized_root = str(Path(root).expanduser().resolve()) if root else None
        results = self.index.search(question, root=normalized_root, top_k=top_k)
        answer = generate_answer(question, results)
        return {
            **answer,
            "sources": [
                {
                    "score": result.score,
                    "root": result.root,
                    "relative_path": result.relative_path,
                    "chunk_index": result.chunk_index,
                    "content": result.content,
                }
                for result in results
            ],
        }

    def stats(self, *, root: str | None = None) -> dict[str, Any]:
        normalized_root = str(Path(root).expanduser().resolve()) if root else None
        return self.index.stats(root=normalized_root)

    async def _emit(self, progress: ProgressCallback | None, event: dict[str, Any]) -> None:
        if progress is None:
            return
        maybe = progress(event)
        if hasattr(maybe, "__await__"):
            await maybe
