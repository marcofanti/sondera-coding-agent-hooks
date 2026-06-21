"""Async PolicyGate — uses aiohttp for non-blocking adjudication.

Drop-in async replacement for `gate.PolicyGate`. Useful in LangChain async
agent loops, asyncio-based Hermes/OpenClaw hosts, and any framework where
blocking `requests` would stall the event loop.

Usage::

    from sondera.aiogate import AsyncPolicyGate, AsyncTrajectory
    from sondera import Action

    gate = AsyncPolicyGate(admin_url="http://localhost:9090")

    async with gate.trajectory(agent_id="hermes-1", provider_id="ollama") as traj:
        decision = await traj.check(Action.shell("ls /tmp"))
        if decision.allow:
            ...
        elif decision.escalate:
            handle = gate.escalation_handle(decision)
            decision = await handle.wait()
"""

from __future__ import annotations

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from .gate import PolicyDecision, EscalationHandle, PolicyGate

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


class AsyncEscalationHandle:
    """Async variant of EscalationHandle — polls without blocking the event loop."""

    def __init__(self, escalation_id: str, gate: "AsyncPolicyGate") -> None:
        self.escalation_id = escalation_id
        self.gate = gate

    async def wait(
        self,
        poll_interval: float = 2.0,
        timeout: float = 120.0,
    ) -> PolicyDecision:
        deadline = time.time() + timeout
        async with self.gate._session() as session:
            while time.time() < deadline:
                url = f"{self.gate.admin_url}/api/escalations/{self.escalation_id}"
                async with session.get(url) as resp:
                    if resp.status == 404:
                        return PolicyDecision(decision="Deny", reason="escalation not found")
                    resp.raise_for_status()
                    record = await resp.json()
                status = record.get("status", "pending")
                if status == "approved":
                    return PolicyDecision(decision="Allow", reason="operator approved")
                if status in ("denied", "timed_out"):
                    return PolicyDecision(decision="Deny", reason=f"operator {status}")
                await asyncio.sleep(poll_interval)
        return PolicyDecision(decision="Deny", reason="escalation timed out")

    async def approve(self, decided_by: str = "sdk") -> bool:
        async with self.gate._session() as session:
            url = f"{self.gate.admin_url}/api/escalations/{self.escalation_id}/approve"
            async with session.post(url, json={"decided_by": decided_by}) as resp:
                return resp.ok

    async def deny_action(self, decided_by: str = "sdk") -> bool:
        async with self.gate._session() as session:
            url = f"{self.gate.admin_url}/api/escalations/{self.escalation_id}/deny"
            async with session.post(url, json={"decided_by": decided_by}) as resp:
                return resp.ok


class AsyncPolicyGate:
    """Async policy gate — same interface as `PolicyGate` but all I/O is non-blocking.

    Requires ``aiohttp``::

        pip install sondera[aiohttp]
    """

    def __init__(
        self,
        admin_url: str = "http://localhost:9090",
        mandate_jwt: Optional[str] = None,
        default_agent_id: str = "python-agent",
        default_provider_id: str = "python",
    ) -> None:
        if not HAS_AIOHTTP:
            raise ImportError(
                "aiohttp is required for AsyncPolicyGate. "
                "Install it with: pip install 'sondera[aiohttp]'"
            )
        self.admin_url = admin_url.rstrip("/")
        self.mandate_jwt = mandate_jwt
        self.default_agent_id = default_agent_id
        self.default_provider_id = default_provider_id
        self._shared_session: Optional[aiohttp.ClientSession] = None

    def _session(self):
        """Return a new session for one-off requests (safe for concurrent use)."""
        if not HAS_AIOHTTP:
            raise ImportError("aiohttp required")
        return aiohttp.ClientSession()

    async def close(self) -> None:
        if self._shared_session and not self._shared_session.closed:
            await self._shared_session.close()

    async def __aenter__(self) -> "AsyncPolicyGate":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    def trajectory(
        self,
        agent_id: Optional[str] = None,
        provider_id: Optional[str] = None,
        trajectory_id: Optional[str] = None,
    ) -> "AsyncTrajectory":
        return AsyncTrajectory(
            gate=self,
            agent_id=agent_id or self.default_agent_id,
            provider_id=provider_id or self.default_provider_id,
            trajectory_id=trajectory_id or str(uuid.uuid4()),
        )

    def _build_event(
        self,
        agent_id: str,
        provider_id: str,
        trajectory_id: str,
        action: Any,
    ) -> dict:
        return {
            "event_id": str(uuid.uuid4()),
            "trajectory_id": trajectory_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "agent": {"id": agent_id, "provider_id": provider_id},
            "actor": {"id": agent_id, "actor_type": "Agent"},
            "causality": {
                "correlation_id": trajectory_id,
                "causation_id": None,
                "parent_id": None,
            },
            "event": action.to_event(),
            "raw": self.mandate_jwt,
        }

    async def adjudicate_raw(self, event: dict) -> PolicyDecision:
        async with self._session() as session:
            async with session.post(
                f"{self.admin_url}/api/adjudicate",
                json=event,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                return PolicyDecision._from_response(data)

    def escalation_handle(self, decision: PolicyDecision) -> Optional[AsyncEscalationHandle]:
        if decision.escalate and decision.escalation_id:
            return AsyncEscalationHandle(
                escalation_id=decision.escalation_id,
                gate=self,
            )
        return None


class AsyncTrajectory:
    """Async trajectory context manager."""

    def __init__(
        self,
        gate: AsyncPolicyGate,
        agent_id: str,
        provider_id: str,
        trajectory_id: str,
    ) -> None:
        self.gate = gate
        self.agent_id = agent_id
        self.provider_id = provider_id
        self.trajectory_id = trajectory_id

    async def __aenter__(self) -> "AsyncTrajectory":
        return self

    async def __aexit__(self, *_: Any) -> None:
        pass

    async def check(self, action: Any) -> PolicyDecision:
        event = self.gate._build_event(
            agent_id=self.agent_id,
            provider_id=self.provider_id,
            trajectory_id=self.trajectory_id,
            action=action,
        )
        return await self.gate.adjudicate_raw(event)

    async def check_and_raise(self, action: Any) -> PolicyDecision:
        decision = await self.check(action)
        if not decision.allow:
            raise PermissionError(
                f"Sondera denied {action.__class__.__name__}: "
                f"{decision.decision} — {decision.reason}"
            )
        return decision

    async def observe(self, observation: Any) -> PolicyDecision:
        """Send a tool observation back to the harness for sensitivity classification."""
        event = self.gate._build_event(
            agent_id=self.agent_id,
            provider_id=self.provider_id,
            trajectory_id=self.trajectory_id,
            action=observation,
        )
        return await self.gate.adjudicate_raw(event)
