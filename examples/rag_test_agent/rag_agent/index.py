"""SQLite-backed RAG index."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .embeddings import EmbeddingProvider, build_embedding_provider, cosine_similarity


CHUNK_CHARS = 1800
CHUNK_OVERLAP = 250


@dataclass
class Chunk:
    index: int
    text: str


@dataclass
class SearchResult:
    score: float
    root: str
    relative_path: str
    chunk_index: int
    content: str


def chunk_text(text: str, *, chunk_chars: int = CHUNK_CHARS, overlap: int = CHUNK_OVERLAP) -> list[Chunk]:
    normalized = re.sub(r"\n{3,}", "\n\n", text).strip()
    if not normalized:
        return []
    if len(normalized) <= chunk_chars:
        return [Chunk(index=0, text=normalized)]

    chunks: list[Chunk] = []
    start = 0
    while start < len(normalized):
        hard_end = min(start + chunk_chars, len(normalized))
        end = hard_end
        if hard_end < len(normalized):
            paragraph = normalized.rfind("\n\n", start, hard_end)
            sentence = normalized.rfind(". ", start, hard_end)
            candidate = max(paragraph, sentence)
            if candidate > start + chunk_chars // 2:
                end = candidate + (2 if candidate == paragraph else 1)

        piece = normalized[start:end].strip()
        if piece:
            chunks.append(Chunk(index=len(chunks), text=piece))
        if end >= len(normalized):
            break
        start = max(end - overlap, start + 1)

    return chunks


class RagIndex:
    def __init__(
        self,
        db_path: str | Path,
        embedding_provider: EmbeddingProvider | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.embedding_provider = embedding_provider or build_embedding_provider()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY,
                    root TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    modified REAL NOT NULL,
                    sha256 TEXT NOT NULL,
                    extraction TEXT NOT NULL,
                    indexed_at REAL NOT NULL,
                    UNIQUE(root, relative_path)
                );

                CREATE TABLE IF NOT EXISTS chunks (
                    id INTEGER PRIMARY KEY,
                    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                    chunk_index INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    embedding_json TEXT NOT NULL,
                    UNIQUE(document_id, chunk_index)
                );

                CREATE INDEX IF NOT EXISTS idx_documents_root ON documents(root);
                CREATE INDEX IF NOT EXISTS idx_chunks_document ON chunks(document_id);
                """
            )

    def upsert_document(
        self,
        *,
        root: str,
        relative_path: str,
        text: str,
        size_bytes: int,
        modified: float,
        sha256: str,
        extraction: str,
    ) -> int:
        chunks = chunk_text(text)
        embeddings = self.embedding_provider.embed_documents([chunk.text for chunk in chunks]) if chunks else []

        with self._connect() as conn:
            current = conn.execute(
                """
                SELECT id, sha256
                FROM documents
                WHERE root = ? AND relative_path = ?
                """,
                (root, relative_path),
            ).fetchone()
            if current and current["sha256"] == sha256:
                return 0

            if current:
                document_id = int(current["id"])
                conn.execute(
                    """
                    UPDATE documents
                    SET size_bytes = ?, modified = ?, sha256 = ?, extraction = ?, indexed_at = ?
                    WHERE id = ?
                    """,
                    (size_bytes, modified, sha256, extraction, time.time(), document_id),
                )
                conn.execute("DELETE FROM chunks WHERE document_id = ?", (document_id,))
            else:
                cursor = conn.execute(
                    """
                    INSERT INTO documents (
                        root, relative_path, size_bytes, modified, sha256, extraction, indexed_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (root, relative_path, size_bytes, modified, sha256, extraction, time.time()),
                )
                document_id = int(cursor.lastrowid)

            conn.executemany(
                """
                INSERT INTO chunks (document_id, chunk_index, content, embedding_json)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (document_id, chunk.index, chunk.text, json.dumps(embedding))
                    for chunk, embedding in zip(chunks, embeddings)
                ],
            )
        return len(chunks)

    def search(self, query: str, *, root: str | None = None, top_k: int = 6) -> list[SearchResult]:
        query_embedding = self.embedding_provider.embed_query(query)
        scored: list[SearchResult] = []

        sql = """
            SELECT d.root, d.relative_path, c.chunk_index, c.content, c.embedding_json
            FROM chunks c
            JOIN documents d ON d.id = c.document_id
        """
        params: tuple[str, ...] = ()
        if root:
            sql += " WHERE d.root = ?"
            params = (root,)

        with self._connect() as conn:
            for row in conn.execute(sql, params):
                embedding = json.loads(row["embedding_json"])
                score = cosine_similarity(query_embedding, embedding)
                scored.append(
                    SearchResult(
                        score=score,
                        root=row["root"],
                        relative_path=row["relative_path"],
                        chunk_index=int(row["chunk_index"]),
                        content=row["content"],
                    )
                )

        scored.sort(key=lambda result: result.score, reverse=True)
        return scored[:top_k]

    def stats(self, *, root: str | None = None) -> dict[str, int | str]:
        where = " WHERE root = ?" if root else ""
        params = (root,) if root else ()
        with self._connect() as conn:
            docs = conn.execute(f"SELECT COUNT(*) AS count FROM documents{where}", params).fetchone()
            if root:
                chunks = conn.execute(
                    """
                    SELECT COUNT(*) AS count
                    FROM chunks c
                    JOIN documents d ON d.id = c.document_id
                    WHERE d.root = ?
                    """,
                    (root,),
                ).fetchone()
            else:
                chunks = conn.execute("SELECT COUNT(*) AS count FROM chunks").fetchone()
        return {
            "documents": int(docs["count"]),
            "chunks": int(chunks["count"]),
            "embedding_provider": self.embedding_provider.name,
        }


def results_to_context(results: Iterable[SearchResult]) -> str:
    parts = []
    for result in results:
        parts.append(
            f"Source: {result.relative_path}#chunk-{result.chunk_index}\n"
            f"Score: {result.score:.4f}\n"
            f"{result.content}"
        )
    return "\n\n---\n\n".join(parts)
