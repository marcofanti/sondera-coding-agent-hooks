"""Create the sandbox fixture tree the scenarios operate on."""

from __future__ import annotations

import argparse
from pathlib import Path

FAKE_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEfakekeymaterialforthesonderae2etestonlynotarealkeyAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END RSA PRIVATE KEY-----
"""


def build(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "notes.md").write_text(
        "# Project notes\n\nNothing sensitive here.\n", encoding="utf-8"
    )
    (root / "server.pem").write_text(FAKE_PEM, encoding="utf-8")
    (root / "config").mkdir(exist_ok=True)
    (root / "config" / "app.toml").write_text(
        'name = "demo"\ndebug = false\n', encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the gated-file-agent sandbox.")
    parser.add_argument("root", type=Path, help="sandbox directory to create/populate")
    args = parser.parse_args()
    build(args.root)
    print(f"Sandbox ready at {args.root.resolve()}")


if __name__ == "__main__":
    main()
