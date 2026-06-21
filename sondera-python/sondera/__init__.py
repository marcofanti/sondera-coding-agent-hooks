"""Sondera Python SDK — policy gate for autonomous AI agents.

Provides a `PolicyGate` that connects to the Sondera harness and adjudicates
every tool call before execution. Works with LangChain, Hermes, OpenClaw, and
any framework that lets you intercept tool calls.

Quick start::

    from sondera import PolicyGate, Action

    gate = PolicyGate(admin_url="http://localhost:9090")

    with gate.trajectory(agent_id="my-agent", provider_id="hermes") as traj:
        decision = traj.check(Action.shell("ls /tmp"))
        if decision.allow:
            result = subprocess.run(["ls", "/tmp"], capture_output=True)
"""

from .gate import PolicyGate, PolicyDecision, EscalationHandle
from .trajectory import Trajectory
from .actions import Action, ShellAction, FileReadAction, FileWriteAction, WebFetchAction, ToolCallAction
from .observations import (
    Observation,
    ShellOutputObservation,
    FileResultObservation,
    WebFetchOutputObservation,
    ToolOutputObservation,
    PromptObservation,
    ThinkObservation,
)

__all__ = [
    "PolicyGate",
    "PolicyDecision",
    "EscalationHandle",
    "Trajectory",
    "Action",
    "ShellAction",
    "FileReadAction",
    "FileWriteAction",
    "WebFetchAction",
    "ToolCallAction",
    "Observation",
    "ShellOutputObservation",
    "FileResultObservation",
    "WebFetchOutputObservation",
    "ToolOutputObservation",
    "PromptObservation",
    "ThinkObservation",
]
