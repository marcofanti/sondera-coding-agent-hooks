"""FastAPI web UI for the RAG test agent."""

from __future__ import annotations

import argparse
import asyncio
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .agent import RagAgent


PACKAGE_DIR = Path(__file__).resolve().parent
STATIC_DIR = PACKAGE_DIR / "static"
DEFAULT_DB = Path(os.environ.get("RAG_AGENT_DB", Path.cwd() / ".rag-test-agent" / "rag.sqlite"))


class IndexRequest(BaseModel):
    folder_path: str = Field(min_length=1)
    max_document_bytes: int = Field(default=2_000_000, ge=1024, le=50_000_000)


class AskRequest(BaseModel):
    question: str = Field(min_length=1)
    root: str | None = None
    top_k: int = Field(default=6, ge=1, le=20)


@dataclass
class Job:
    id: str
    folder_path: str
    status: str = "queued"
    events: list[dict[str, Any]] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "folder_path": self.folder_path,
            "status": self.status,
            "events": self.events[-200:],
            "result": self.result,
            "error": self.error,
        }


def create_app(db_path: str | Path = DEFAULT_DB, *, embedding_provider: str = "auto") -> FastAPI:
    app = FastAPI(title="RAG Test Agent")
    agent_cache: dict[str, RagAgent] = {}
    jobs: dict[str, Job] = {}

    def get_agent() -> RagAgent:
        agent = agent_cache.get("agent")
        if agent is None:
            agent = RagAgent(db_path, embedding_provider=embedding_provider)
            agent_cache["agent"] = agent
        return agent

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    async def home() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.post("/api/index")
    async def start_index(request: IndexRequest) -> dict[str, str]:
        job_id = str(uuid.uuid4())
        job = Job(id=job_id, folder_path=request.folder_path)
        jobs[job_id] = job

        async def progress(event: dict[str, Any]) -> None:
            job.events.append(event)

        async def run() -> None:
            job.status = "running"
            try:
                job.result = await get_agent().index_folder(
                    request.folder_path,
                    progress=progress,
                    max_document_bytes=request.max_document_bytes,
                )
                job.status = "complete"
            except Exception as exc:
                job.error = str(exc)
                job.status = "failed"

        asyncio.create_task(run())
        return {"job_id": job_id}

    @app.get("/api/jobs/{job_id}")
    async def get_job(job_id: str) -> dict[str, Any]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        return job.snapshot()

    @app.post("/api/ask")
    async def ask(request: AskRequest) -> dict[str, Any]:
        agent = get_agent()
        return await asyncio.to_thread(
            agent.ask,
            request.question,
            root=request.root,
            top_k=request.top_k,
        )

    @app.get("/api/stats")
    async def stats(root: str | None = None) -> dict[str, Any]:
        agent = get_agent()
        return await asyncio.to_thread(agent.stats, root=root)

    return app


app = create_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the RAG test agent web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--embedding-provider", choices=["auto", "gemini", "hash"], default="auto")
    args = parser.parse_args()

    uvicorn.run(
        create_app(args.db, embedding_provider=args.embedding_provider),
        host=args.host,
        port=args.port,
    )


if __name__ == "__main__":
    main()
