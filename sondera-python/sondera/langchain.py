"""LangChain tool wrapper that gates every tool call through Sondera.

Usage::

    from langchain.tools import tool
    from sondera import PolicyGate
    from sondera.langchain import PolicyGateTool

    gate = PolicyGate(admin_url="http://localhost:9090")

    @tool
    def read_file(path: str) -> str:
        \"\"\"Read a file from disk.\"\"\"
        with open(path) as f:
            return f.read()

    safe_read = PolicyGateTool.wrap(read_file, gate, trajectory_id="my-traj")
    result = safe_read.run({"path": "/tmp/data.csv"})
"""

from __future__ import annotations

import json
from typing import Any, Optional, TYPE_CHECKING

from .actions import ToolCallAction
from .gate import PolicyGate

try:
    from langchain_core.tools import BaseTool, ToolException
    HAS_LANGCHAIN = True
except ImportError:  # LangChain not installed — still allow import
    HAS_LANGCHAIN = False
    BaseTool = object
    ToolException = Exception

if TYPE_CHECKING:
    from .trajectory import Trajectory


class PolicyGateTool(BaseTool):
    """Wraps a LangChain `BaseTool` and gates every call through Sondera."""

    name: str
    description: str
    _inner: Any
    _traj: "Trajectory"

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, inner: Any, traj: "Trajectory") -> None:
        if not HAS_LANGCHAIN:
            raise ImportError(
                "langchain-core is required for PolicyGateTool. "
                "Install it with: pip install langchain-core"
            )
        super().__init__(
            name=inner.name,
            description=inner.description,
        )
        self._inner = inner
        self._traj = traj

    @classmethod
    def wrap(
        cls,
        tool: Any,
        gate: PolicyGate,
        agent_id: Optional[str] = None,
        provider_id: str = "langchain",
        trajectory_id: Optional[str] = None,
    ) -> "PolicyGateTool":
        """Wrap an existing LangChain tool with a Sondera policy gate."""
        traj = gate.trajectory(
            agent_id=agent_id,
            provider_id=provider_id,
            trajectory_id=trajectory_id,
        )
        return cls(inner=tool, traj=traj)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        action = ToolCallAction(
            tool=self._inner.name,
            arguments=kwargs or ({"args": args} if args else {}),
        )
        decision = self._traj.check(action)
        if not decision.allow:
            raise ToolException(
                f"Sondera denied tool call '{self._inner.name}': "
                f"{decision.decision} — {decision.reason}"
            )
        return self._inner._run(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)


def gate_toolkit(
    tools: list[Any],
    gate: PolicyGate,
    agent_id: Optional[str] = None,
    provider_id: str = "langchain",
    trajectory_id: Optional[str] = None,
) -> list["PolicyGateTool"]:
    """Gate an entire list of LangChain tools through a shared Sondera trajectory."""
    import uuid
    shared_traj_id = trajectory_id or str(uuid.uuid4())
    return [
        PolicyGateTool.wrap(
            t,
            gate,
            agent_id=agent_id,
            provider_id=provider_id,
            trajectory_id=shared_traj_id,
        )
        for t in tools
    ]
