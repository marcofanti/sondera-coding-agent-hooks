"""Async MCP client for the local filesystem server."""

from __future__ import annotations

import json
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class FilesystemMcpClient:
    """Launch and call the RAG filesystem MCP server over stdio."""

    def __init__(self, root: str | Path, server_module: str = "rag_agent.mcp_filesystem_server") -> None:
        self.root = Path(root).expanduser().resolve()
        self.server_module = server_module
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "FilesystemMcpClient":
        env = dict(os.environ)
        env["RAG_AGENT_ALLOWED_ROOT"] = str(self.root)
        existing_pythonpath = env.get("PYTHONPATH", "")
        package_root = str(Path(__file__).resolve().parents[1])
        env["PYTHONPATH"] = (
            package_root if not existing_pythonpath else f"{package_root}{os.pathsep}{existing_pythonpath}"
        )

        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", self.server_module],
            env=env,
            cwd=str(package_root),
        )

        stack = AsyncExitStack()
        read_stream, write_stream = await stack.enter_async_context(stdio_client(params))
        session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
        await session.initialize()

        self._stack = stack
        self._session = session
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None
        self._session = None

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("FilesystemMcpClient is not connected")
        return self._session

    async def list_tools(self) -> list[str]:
        result = await self.session.list_tools()
        return [tool.name for tool in result.tools]

    async def call_json(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        result = await self.session.call_tool(name, arguments or {})
        text = _tool_result_text(result)
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"MCP tool {name} returned non-JSON content: {text[:500]}") from exc


def _tool_result_text(result: Any) -> str:
    dump = result.model_dump(by_alias=True) if hasattr(result, "model_dump") else {}
    structured = dump.get("structuredContent") or dump.get("structured_content")
    if structured is not None:
        return json.dumps(structured)

    content = getattr(result, "content", None) or dump.get("content") or []
    parts: list[str] = []
    for item in content:
        if isinstance(item, dict):
            text = item.get("text")
        else:
            text = getattr(item, "text", None)
        if text:
            parts.append(text)

    if not parts:
        raise RuntimeError(f"MCP tool returned no text content: {result!r}")
    return "\n".join(parts)
