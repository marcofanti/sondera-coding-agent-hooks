import pytest

from rag_agent.agent import RagAgent


@pytest.mark.asyncio
async def test_agent_indexes_folder_through_mcp(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "README.md").write_text("Telemetry rollback launch checklist.", encoding="utf-8")
    (corpus / "nested").mkdir()
    (corpus / "nested" / "notes.txt").write_text("Soup menu and kitchen prep.", encoding="utf-8")

    agent = RagAgent(tmp_path / "rag.sqlite", embedding_provider="hash")
    summary = await agent.index_folder(corpus)
    answer = agent.ask("What mentions telemetry rollback?", root=str(corpus), top_k=1)

    assert summary["documents_seen"] == 2
    assert summary["documents_indexed"] == 2
    assert answer["sources"][0]["relative_path"] == "README.md"
