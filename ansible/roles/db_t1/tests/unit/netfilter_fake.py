"""A fake `iptables` and `iptables-restore` that keep the filter table in a file.

Shared by the tests of the database port rule program and by the behaviour tests of the role's
task file. The fakes answer `-S`, `-I` and a restore transaction as the real tools do (an
address prints with its /32 and a TCP port match prints `-m tcp`), refuse any restore line
they do not know, and log every call, so a test can say what was done and what was not. Their
switches are environment variables (FAKE_LIST_EXIT, FAKE_INSERT_EXIT, FAKE_RESTORE_EXIT,
FAKE_RESTORE_NOOP). Nothing here touches a real firewall.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# One script stands in for both tools; the file name it is run under says which.
FAKE = """#!{python}
import json
import os
import sys

state_path = os.environ["FAKE_STATE"]
log_path = os.environ["FAKE_LOG"]
tool = os.path.basename(sys.argv[0])
args = sys.argv[1:]
stdin = sys.stdin.read() if tool == "iptables-restore" else ""
with open(log_path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps({{"tool": tool, "args": args, "stdin": stdin}}) + "\\n")


def load():
    with open(state_path, encoding="utf-8") as handle:
        return json.load(handle)


def save(state):
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)


def canonical(words):
    text = []
    previous = ""
    for word in words:
        if previous in ("-s", "-d") and "/" not in word:
            word = word + "/32"
        text.append(word)
        previous = word
    joined = " ".join(text)
    if "-p tcp --dport" in joined:
        joined = joined.replace("-p tcp --dport", "-p tcp -m tcp --dport")
    return joined


state = load()
chain_name = "BRANCHLEFT-DBT1-IN"
if tool == "iptables":
    if os.environ.get("FAKE_LIST_EXIT"):
        sys.stderr.write("iptables: Permission denied\\n")
        sys.exit(int(os.environ["FAKE_LIST_EXIT"]))
    assert args[:4] == ["-w", "10", "-t", "filter"], args
    action = args[4]
    if action == "-S":
        print("-P INPUT ACCEPT")
        print("-P FORWARD ACCEPT")
        print("-P OUTPUT ACCEPT")
        if state["chain"] is not None:
            print("-N " + chain_name)
        for line in state["input"]:
            print(line)
        for line in state["chain"] or []:
            print(line)
        sys.exit(0)
    if action == "-I":
        if os.environ.get("FAKE_INSERT_EXIT"):
            sys.exit(int(os.environ["FAKE_INSERT_EXIT"]))
        assert args[5:] == ["INPUT", "1", "-j", chain_name], args
        state["input"].insert(0, "-A INPUT -j " + chain_name)
        save(state)
        sys.exit(0)
elif tool == "iptables-restore":
    assert args == ["--noflush", "-w", "10"], args
    if os.environ.get("FAKE_RESTORE_EXIT"):
        sys.stderr.write("iptables-restore: line 5 failed\\n")
        sys.exit(int(os.environ["FAKE_RESTORE_EXIT"]))
    lines = stdin.splitlines()
    assert lines and lines[0] == "*filter" and lines[-1] == "COMMIT", lines
    new = state["chain"]
    for line in lines[1:-1]:
        if line == ":" + chain_name + " - [0:0]":
            new = [] if new is None else new
        elif line == "-F " + chain_name:
            new = []
        elif line.startswith("-A " + chain_name + " "):
            new = new + [canonical(line.split())]
        else:
            sys.stderr.write("fake iptables-restore: line not expected: " + line + "\\n")
            sys.exit(64)
    if not os.environ.get("FAKE_RESTORE_NOOP"):
        state["chain"] = new
        save(state)
    sys.exit(0)
sys.stderr.write("fake: call not expected: " + tool + " " + " ".join(args) + "\\n")
sys.exit(64)
"""


class FakeTable:
    """A scratch directory holding the fakes, the table they keep and the log of their calls."""

    def __init__(
        self, test: unittest.TestCase, *, tools: tuple[str, ...] = ("iptables", "iptables-restore")
    ) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        test.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.bin = root / "bin"
        self.bin.mkdir()
        self.state = root / "state.json"
        self.log = root / "calls.jsonl"
        self.put(input_rules=[], chain=None)
        for tool in tools:
            fake = self.bin / tool
            fake.write_text(FAKE.format(python=sys.executable), encoding="utf-8")
            fake.chmod(0o755)

    def put(self, *, input_rules: list[str], chain: list[str] | None) -> None:
        """Start the table with these INPUT rules and this chain (None: no chain)."""
        self.state.write_text(json.dumps({"input": input_rules, "chain": chain}), encoding="utf-8")

    def table(self) -> dict[str, list[str] | None]:
        """The table now."""
        loaded: dict[str, list[str] | None] = json.loads(self.state.read_text(encoding="utf-8"))
        return loaded

    def calls(self) -> list[dict[str, object]]:
        """Every call the fakes received, in order."""
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def writes(self) -> list[dict[str, object]]:
        """The calls that change the table: a restore or an insert."""
        return [
            c for c in self.calls() if c["tool"] == "iptables-restore" or "-I" in str(c["args"])
        ]

    def environment(self, **switches: str) -> dict[str, str]:
        """An environment with the fakes first on PATH; the keywords are the fakes' switches."""
        return {
            "PATH": f"{self.bin}{os.pathsep}/usr/bin{os.pathsep}/bin",
            "FAKE_STATE": str(self.state),
            "FAKE_LOG": str(self.log),
            **switches,
        }
