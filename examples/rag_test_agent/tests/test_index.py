from rag_agent.embeddings import HashEmbeddingProvider
from rag_agent.index import RagIndex, chunk_text


def test_chunk_text_terminates_with_overlap():
    text = ("alpha beta gamma. " * 500).strip()
    chunks = chunk_text(text, chunk_chars=200, overlap=50)
    assert len(chunks) > 1
    assert all(chunk.text for chunk in chunks)
    assert chunks[-1].index == len(chunks) - 1


def test_hash_rag_retrieves_relevant_chunk(tmp_path):
    index = RagIndex(tmp_path / "rag.sqlite", embedding_provider=HashEmbeddingProvider())
    index.upsert_document(
        root="/tmp/corpus",
        relative_path="alpha.md",
        text="The launch checklist requires telemetry, rollback, and a dry run.",
        size_bytes=72,
        modified=1.0,
        sha256="a",
        extraction="text",
    )
    index.upsert_document(
        root="/tmp/corpus",
        relative_path="beta.md",
        text="The lunch menu has noodles, soup, and tea.",
        size_bytes=45,
        modified=1.0,
        sha256="b",
        extraction="text",
    )

    results = index.search("rollback telemetry launch", root="/tmp/corpus", top_k=1)

    assert results
    assert results[0].relative_path == "alpha.md"
