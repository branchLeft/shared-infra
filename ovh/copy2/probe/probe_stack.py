"""The Pulumi CLI, driven for the probe stack against a throwaway file backend.

Commands run as an argv list with no shell. A fake `Runner` stands in for the
CLI in the tests. Output that can carry a secret (`stack output --show-secrets`,
`stack export`) is captured and never printed.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STACK = "probe"
PROJECT = "branchleft-ovh-copy2"
SUFFIX_KEY = f"{PROJECT}:nameSuffix"

UP_TIMEOUT = 15 * 60
DESTROY_TIMEOUT = 15 * 60
QUICK_TIMEOUT = 3 * 60


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: str = ""
    stderr: str = ""


# One command: argv, then env, cwd, capture and timeout as keywords.
Runner = Callable[..., Completed]


def run_command(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: Path,
    capture: bool,
    timeout: float,
) -> Completed:
    """The real runner. A timeout is reported as a failed command, not raised."""
    try:
        done = subprocess.run(
            list(argv),
            env=dict(env),
            cwd=cwd,
            capture_output=capture,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return Completed(124, "", f"timed out after {int(timeout)} seconds")
    return Completed(done.returncode, done.stdout or "", done.stderr or "")


@dataclass(frozen=True)
class StackResource:
    kind: str
    name: str
    cloud_name: str


class PulumiError(Exception):
    pass


class ProbeStack:
    def __init__(
        self,
        run: Runner,
        project_dir: Path,
        env: Mapping[str, str],
        stack: str = STACK,
    ) -> None:
        self._run = run
        self._dir = project_dir
        self._env = env
        self._stack = stack

    def _do(self, args: Sequence[str], *, capture: bool, timeout: float) -> Completed:
        argv = ["pulumi", *args, "--non-interactive"]
        return self._run(
            argv, env=self._env, cwd=self._dir, capture=capture, timeout=timeout
        )

    def init(self) -> None:
        done = self._do(
            ["stack", "init", self._stack, "--secrets-provider", "passphrase"],
            capture=True,
            timeout=QUICK_TIMEOUT,
        )
        self._require(done, "stack init")

    def set_suffix(self, suffix: str) -> None:
        done = self._do(
            ["config", "set", SUFFIX_KEY, suffix, "--stack", self._stack],
            capture=True,
            timeout=QUICK_TIMEOUT,
        )
        self._require(done, "config set")

    def up(self) -> None:
        done = self._do(
            [
                "up",
                "--stack",
                self._stack,
                "--yes",
                "--skip-preview",
                "--suppress-outputs",
            ],
            capture=False,
            timeout=UP_TIMEOUT,
        )
        self._require(done, "up")

    def destroy(self) -> bool:
        done = self._do(
            [
                "destroy",
                "--stack",
                self._stack,
                "--yes",
                "--skip-preview",
                "--suppress-outputs",
            ],
            capture=False,
            timeout=DESTROY_TIMEOUT,
        )
        return done.returncode == 0

    def outputs(self) -> dict[str, Any]:
        done = self._do(
            ["stack", "output", "--stack", self._stack, "--json", "--show-secrets"],
            capture=True,
            timeout=QUICK_TIMEOUT,
        )
        self._require(done, "stack output")
        parsed = json.loads(done.stdout or "{}")
        if not isinstance(parsed, dict):
            raise PulumiError("stack output was not a mapping")
        return parsed

    def _deployment(self) -> dict[str, Any]:
        done = self._do(
            ["stack", "export", "--stack", self._stack],
            capture=True,
            timeout=QUICK_TIMEOUT,
        )
        self._require(done, "stack export")
        parsed = json.loads(done.stdout or "{}")
        deployment = parsed.get("deployment") if isinstance(parsed, dict) else None
        if not isinstance(deployment, dict):
            raise PulumiError("stack export held no deployment")
        return deployment

    def resources(self) -> list[StackResource]:
        """Everything the stack still holds, pending operations included."""
        deployment = self._deployment()
        found: list[StackResource] = []
        for item in deployment.get("resources") or []:
            if _is_bookkeeping(str(item.get("type", ""))):
                continue
            found.append(_describe(item))
        for pending in deployment.get("pending_operations") or []:
            item = pending.get("resource") or {}
            if _is_bookkeeping(str(item.get("type", ""))):
                continue
            found.append(_describe(item, pending=True))
        return found

    @staticmethod
    def _require(done: Completed, what: str) -> None:
        if done.returncode != 0:
            tail = (done.stderr or "").strip().splitlines()[-3:]
            raise PulumiError(
                f"pulumi {what} failed ({done.returncode}): {' / '.join(tail)}"
            )


def _is_bookkeeping(kind: str) -> bool:
    return kind == "pulumi:pulumi:Stack" or kind.startswith("pulumi:providers:")


def _describe(item: Mapping[str, Any], pending: bool = False) -> StackResource:
    urn = str(item.get("urn", ""))
    kind = str(item.get("type", "")) or "unknown"
    outputs = item.get("outputs") or {}
    cloud = outputs.get("name") if isinstance(outputs, dict) else None
    return StackResource(
        kind=f"{kind} (pending)" if pending else kind,
        name=urn.rsplit("::", 1)[-1] or urn,
        cloud_name=cloud if isinstance(cloud, str) else "",
    )
