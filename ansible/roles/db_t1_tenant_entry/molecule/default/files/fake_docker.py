#!/usr/bin/python3
"""A stand-in for docker and the database client, for the role's container test.

It answers the two calls the forced command makes, and nothing else:

  docker ps --quiet --no-trunc --filter ... --filter ... --filter status=running
  docker exec --interactive ID sh -c SCRIPT        (statements on standard input)

It keeps the accounts and databases that exist in a JSON file, applies the create statements
the way the real server does (a second account or database of the same name is an error), and
records every argument list and every statement it was sent, so the scenario can say what reached
the container and what did not. Any other call is an error, which is how a program that runs
something it should not is caught.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RECORD = Path("/var/lib/entry-test")
STATE = RECORD / "db.json"
CONTAINER = (RECORD / "container-id").read_text(encoding="utf-8").strip()


def load() -> dict[str, list[str]]:
    state: dict[str, list[str]] = json.loads(STATE.read_text(encoding="utf-8"))
    return state


def record(name: str, text: str) -> None:
    with (RECORD / name).open("a", encoding="utf-8") as handle:
        handle.write(text)


def main(argv: list[str]) -> int:
    record("argv.log", " ".join(argv) + "\n")
    if argv[:2] == ["ps", "--quiet"]:
        if (RECORD / "no-container").exists():
            return 0
        sys.stdout.write(CONTAINER + "\n")
        return 0
    if argv[:3] == ["exec", "--interactive", CONTAINER] and argv[3:5] == ["sh", "-c"]:
        statements = sys.stdin.read()
        record("sql.log", statements + "\n--\n")
        state = load()
        query = re.search(
            r"WHERE User = '([a-z0-9_]+)'.*SCHEMA_NAME = '([a-z0-9_]+)'", statements, re.DOTALL
        )
        if query is not None:
            users = int(query.group(1) in state["users"])
            databases = int(query.group(2) in state["databases"])
            sys.stdout.write(f"{users}\t{databases}\n")
            return 0
        database = re.search(r"CREATE DATABASE `([a-z0-9_]+)`", statements)
        account = re.search(r"CREATE USER '([a-z0-9_]+)'@'([0-9.]+)'", statements)
        if database is None or account is None:
            sys.stderr.write("ERROR 1064: statements this stand-in does not know\n")
            return 1
        if database.group(1) in state["databases"] or account.group(1) in state["users"]:
            sys.stderr.write("ERROR 1007: exists\n")
            return 1
        state["databases"].append(database.group(1))
        state["users"].append(account.group(1))
        STATE.write_text(json.dumps(state), encoding="utf-8")
        record("creates.log", f"{database.group(1)} {account.group(2)}\n")
        return 0
    sys.stderr.write("the stand-in was called in a way the forced command never does\n")
    return 99


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
