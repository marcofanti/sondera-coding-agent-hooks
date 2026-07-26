"""Async stdio MCP client that launches the gated filesystem server."""

from __future__ import annotations

import json
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class GatedFsClient:
    """Launch and call the gated filesystem MCP server over stdio."""

    def __init__(
        self,
        root: str | Path,
        trajectory_id: str,
        admin_url: str = "http://localhost:9090",
        agent_id: str = "gated-file-agent",
        mandate_jwt: Optional[str] = None,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.trajectory_id = trajectory_id
        self.admin_url = admin_url
        self.agent_id = agent_id
        self.mandate_jwt = mandate_jwt
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "GatedFsClient":
        env = dict(os.environ)
        env["GATED_AGENT_ROOT"] = str(self.root)
        env["SONDERA_ADMIN_URL"] = self.admin_url
        env["SONDERA_AGENT_ID"] = self.agent_id
        env["SONDERA_TRAJECTORY_ID"] = self.trajectory_id
        if self.mandate_jwt:
            env["SONDERA_MANDATE_JWT"] = self.mandate_jwt
        package_root = str(Path(__file__).resolve().parents[1])
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = package_root if not existing else f"{package_root}{os.pathsep}{existing}"

        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "gated_agent.mcp_file_server"],
            env=env,
            cwd=package_root,
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

    async def call(self, tool: str, **arguments: Any) -> dict:
        """Call a tool and return its structured JSON result."""
        if self._session is None:
            raise RuntimeError("client not started — use `async with GatedFsClient(...)`")
        result = await self._session.call_tool(tool, arguments=arguments)
        if result.structuredContent is not None:
            content = result.structuredContent
            # FastMCP wraps plain dict returns in {"result": ...}
            return content.get("result", content) if isinstance(content, dict) else content
        for block in result.content:
            if getattr(block, "type", None) == "text":
                return json.loads(block.text)
        raise RuntimeError(f"tool {tool} returned no parsable content")
