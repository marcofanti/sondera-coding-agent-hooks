"""Embedding providers for the RAG test agent."""

from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from typing import Protocol


TOKEN_RE = re.compile(r"[A-Za-z0-9_]{2,}")


class EmbeddingProvider(Protocol):
    name: str
    dimensions: int

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        ...

    def embed_query(self, text: str) -> list[float]:
        ...


@dataclass
class HashEmbeddingProvider:
    """Deterministic local fallback for tests and offline demos."""

    dimensions: int = 384
    name: str = "hash-local"

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(text, salt="doc") for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text, salt="doc")

    def _embed(self, text: str, *, salt: str) -> list[float]:
        vector = [0.0] * self.dimensions
        tokens = TOKEN_RE.findall(text.lower())
        if not tokens:
            return vector

        for token in tokens:
            digest = hashlib.blake2b(f"{salt}:{token}".encode("utf-8"), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "little") % self.dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[bucket] += sign

        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0:
            return vector
        return [value / norm for value in vector]


class GeminiEmbeddingProvider:
    """Gemini embeddings via google-genai.

    This intentionally uses google-genai, not the deprecated
    google-generativeai package.
    """

    name = "gemini-embedding-001"
    dimensions = 3072

    def __init__(self, api_key: str | None = None) -> None:
        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:
            raise RuntimeError("Install rag-test-agent[gemini] to use Gemini embeddings") from exc

        key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not key:
            raise RuntimeError("Set GEMINI_API_KEY or GOOGLE_API_KEY to use Gemini embeddings")
        self._client = genai.Client(api_key=key)
        self._types = types

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._embed(texts, task_type="RETRIEVAL_DOCUMENT")

    def embed_query(self, text: str) -> list[float]:
        return self._embed([text], task_type="RETRIEVAL_QUERY")[0]

    def _embed(self, texts: list[str], *, task_type: str) -> list[list[float]]:
        vectors: list[list[float]] = []
        for start in range(0, len(texts), 100):
            batch = texts[start : start + 100]
            response = self._client.models.embed_content(
                model="gemini-embedding-001",
                contents=batch,
                config=self._types.EmbedContentConfig(task_type=task_type),
            )
            vectors.extend([embedding.values for embedding in response.embeddings])
        return vectors


def build_embedding_provider(preferred: str = "auto") -> EmbeddingProvider:
    if preferred == "hash":
        return HashEmbeddingProvider()
    if preferred not in {"auto", "gemini"}:
        raise ValueError("Embedding provider must be one of: auto, gemini, hash")

    has_key = bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    if preferred == "gemini" or has_key:
        try:
            return GeminiEmbeddingProvider()
        except RuntimeError:
            if preferred == "gemini":
                raise

    return HashEmbeddingProvider()


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    return sum(a * b for a, b in zip(left, right))
