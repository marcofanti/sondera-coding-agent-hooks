"""Layer-2 governance: the PydanticAI agent, with every tool adjudicated.

Same read/write/shell agent as pydantic-ai-read-write-edit.py, but each tool
first asks the Sondera harness (admin HTTP API) whether the action is allowed.
A Deny/Escalate short-circuits and returns the policy verdict to the model
instead of touching disk or the shell — so the harness governs what the agent
actually *does*, not just the command that launched it.

Run through op + uv so the API key is resolved from 1Password:

    op run --env-file=.env -- uv run python gated-read-write-edit.py

Requires a running harness with the admin API:

    sondera-harness-server --policy-engine cedarling --admin-port 9090 -v
"""

import os
import subprocess
import uuid
from pathlib import Path

from dotenv import load_dotenv
from pydantic_ai import Agent

from event_logging import make_event_stream_printer, print_response
from sondera import Action, PolicyGate

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")

SCRATCH = HERE / "scratch_space"
GATE = PolicyGate(
    admin_url=os.environ.get("SONDERA_ADMIN_URL", "http://localhost:9090"),
    default_agent_id="read-write-shell-agent",
    default_provider_id="pydantic-ai",
)
TRAJECTORY_ID = os.environ.get("SONDERA_TRAJECTORY_ID", str(uuid.uuid4()))


def adjudicate(action: object) -> str | None:
    """Return None if allowed, else a human-readable denial for the model."""
    with GATE.trajectory(trajectory_id=TRAJECTORY_ID) as traj:
        decision = traj.check(action)
    if decision.allow:
        return None
    policy_ids = [
        a["policy_id"]
        for a in (decision.annotations or [])
        if isinstance(a, dict) and a.get("policy_id")
    ]
    return f"BLOCKED by Sondera ({decision.decision}): {policy_ids or decision.reason}"


def main(user_prompt: str) -> None:
    agent = Agent(
        "anthropic:claude-haiku-4-5",
        name="read_write_shell_agent",
        retries=3,
        instructions="You are a helpful assistant. Be concise.",
    )

    @agent.tool_plain(docstring_format="google", require_parameter_descriptions=True)
    def read_file(path: str) -> str:
        """Read a file.

        Args:
            path: The path to the file, relative to the scratch_space directory.
        """
        denial = adjudicate(Action.read_file(path))
        if denial:
            return denial
        try:
            return (SCRATCH / path).read_text()
        except Exception as error:
            return str(error)

    @agent.tool_plain(docstring_format="google", require_parameter_descriptions=True)
    def write_file(path: str, content: str) -> str:
        """Write a file.

        Args:
            path: The path to the file, relative to the scratch_space directory.
            content: The text content to write.
        """
        denial = adjudicate(Action.write_file(path, content))
        if denial:
            return denial
        try:
            full_path = SCRATCH / path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
            return f"Wrote {full_path}"
        except Exception as error:
            return str(error)

    @agent.tool_plain(docstring_format="google", require_parameter_descriptions=True)
    def run_command(command: str) -> str:
        """Run a shell command.

        Args:
            command: The shell command to run inside the scratch_space directory.
        """
        parts = command.split()
        binary, args = (parts[0], parts[1:]) if parts else (command, [])
        denial = adjudicate(Action.shell(binary, *args))
        if denial:
            return denial
        try:
            SCRATCH.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                command,
                shell=True,
                cwd=SCRATCH,
                capture_output=True,
                text=True,
            )
            return f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}"
        except Exception as error:
            return str(error)

    result = agent.run_sync(user_prompt, event_stream_handler=make_event_stream_printer())
    print_response(result.output)


if __name__ == "__main__":
    main(input("Prompt: "))
