"""Driver: run the scenario matrix through the gated MCP server and report PASS/FAIL.

Exit code is non-zero if any scenario's decision does not match expectation, so
the e2e orchestrator can assert on it.
"""

from __future__ import annotations

import argparse
import asyncio
import tempfile
import uuid
from pathlib import Path

from gated_agent import scenarios
from gated_agent.mcp_client import GatedFsClient
from gated_agent.scenarios import Scenario
from gated_agent.setup_sandbox import build as build_sandbox


class Row:
    def __init__(self, scenario: Scenario, decision: str, policy_ids: list[str], reason: str | None):
        self.scenario = scenario
        self.decision = decision
        self.policy_ids = policy_ids
        self.reason = reason

    @property
    def decision_ok(self) -> bool:
        return self.decision == self.scenario.expect

    @property
    def policy_ok(self) -> bool:
        if self.scenario.expect_policy is None:
            return True
        return self.scenario.expect_policy in self.policy_ids


async def run_scenarios(
    selected: list[Scenario],
    admin_url: str,
    agent_id: str,
    mandate_jwt: str | None,
) -> list[Row]:
    trajectory_id = str(uuid.uuid4())
    rows: list[Row] = []
    with tempfile.TemporaryDirectory(prefix="gated-agent-") as tmp:
        root = Path(tmp)
        build_sandbox(root)
        async with GatedFsClient(
            root=root,
            trajectory_id=trajectory_id,
            admin_url=admin_url,
            agent_id=agent_id,
            mandate_jwt=mandate_jwt,
        ) as client:
            for sc in selected:
                result = await client.call(sc.tool, **sc.args)
                rows.append(
                    Row(
                        sc,
                        decision=result.get("decision", "Allow"),
                        policy_ids=result.get("policy_ids", []),
                        reason=result.get("reason"),
                    )
                )
    return rows


def select(group: str, with_ollama: bool) -> list[Scenario]:
    chosen = scenarios.matrix()
    if group != "all":
        chosen = [s for s in chosen if s.group == group]
    if not with_ollama:
        chosen = [s for s in chosen if not s.requires_ollama]
    return chosen


def print_report(rows: list[Row]) -> bool:
    header = f"{'SCENARIO':<20} {'EXPECT':<9} {'ACTUAL':<9} {'POLICY':<8} RESULT"
    print(header)
    print("-" * len(header))
    all_pass = True
    for row in rows:
        sc = row.scenario
        decision_ok = row.decision_ok
        policy_ok = row.policy_ok
        ok = decision_ok and policy_ok
        all_pass = all_pass and ok
        policy_cell = "ok" if policy_ok else "MISS"
        result = "PASS" if ok else "FAIL"
        print(
            f"{sc.name:<20} {sc.expect:<9} {row.decision:<9} {policy_cell:<8} {result}"
        )
        if not policy_ok:
            print(
                f"    expected policy {sc.expect_policy!r}, got {row.policy_ids}"
            )
        if not decision_ok and row.reason:
            print(f"    reason: {row.reason}")
    print("-" * len(header))
    print("ALL PASS" if all_pass else "FAILURES PRESENT")
    return all_pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Run gated-file-agent scenarios.")
    parser.add_argument(
        "--scenario",
        choices=["permitted", "forbidden", "escalation", "all"],
        default="all",
    )
    parser.add_argument("--admin-url", default="http://localhost:9090")
    parser.add_argument("--agent-id", default="gated-file-agent")
    parser.add_argument("--mandate-jwt", default=None)
    parser.add_argument(
        "--with-ollama",
        action="store_true",
        help="include scenarios whose deny depends on the Ollama secure-code/IFC classifier",
    )
    args = parser.parse_args()

    selected = select(args.scenario, args.with_ollama)
    rows = asyncio.run(
        run_scenarios(selected, args.admin_url, args.agent_id, args.mandate_jwt)
    )
    ok = print_report(rows)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
