"""Optional answer generation over retrieved chunks."""

from __future__ import annotations

import json
import os
from typing import Any

from .index import SearchResult, results_to_context


def generate_answer(question: str, results: list[SearchResult]) -> dict[str, Any]:
    if not results:
        return {
            "answer": "No matching chunks were found in the current index.",
            "generated": False,
            "model": None,
        }

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        return {
            "answer": "Gemini is not configured. The retrieved sources below are the RAG result.",
            "generated": False,
            "model": None,
        }

    try:
        from google import genai
        from google.genai import types
    except ImportError:
        return {
            "answer": "Install rag-test-agent[gemini] to generate answers with Gemini.",
            "generated": False,
            "model": None,
        }

    client = genai.Client(api_key=api_key)
    prompt = {
        "question": question,
        "instructions": (
            "Answer only from the supplied sources. If the sources do not answer the question, "
            "say that the indexed documents do not contain enough information. Return JSON with "
            "keys answer and citations, where citations are source paths from the context."
        ),
        "context": results_to_context(results),
    }
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=json.dumps(prompt),
        config=types.GenerateContentConfig(response_mime_type="application/json"),
    )

    try:
        parsed = json.loads(response.text or "{}")
    except json.JSONDecodeError:
        parsed = {"answer": response.text or "", "citations": []}

    return {
        "answer": parsed.get("answer", ""),
        "citations": parsed.get("citations", []),
        "generated": True,
        "model": "gemini-2.5-flash",
    }
