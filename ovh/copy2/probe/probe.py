#!/usr/bin/env python3
"""Drives the OVHcloud lock probe from the dispatch-only workflow.

Subcommands, one per workflow step: `gate`, `up`, `check`, `destroy`. The
rationale, the files this leaves on the runner and the failure directions are in
README.md beside this file. The destroy step runs on every outcome, so it must
leave the job red for any resource it could not remove.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import secrets
import sys
import time
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from probe_checks import TITLES, Probe, Target
from probe_report import (
    EXPECTED_CODES,
    CheckResult,
    Leftover,
    Status,
    all_passed,
    render_cleanup,
    render_table,
    scrub,
)
from probe_s3 import BotoOps, Ops
from probe_stack import STACK, ProbeStack, PulumiError, Runner, run_command

RW_USER = "zz-probe-rw"
ADMIN_USER = "zz-probe-admin"
REGION = "uk"
DESTROY_ATTEMPTS = 3
DESTROY_PAUSE = 20.0
PHASE_STARTED = "started"
PHASE_READY = "stack-ready"

# Everything else in the runner's environment (tokens above all) stays out of
# the Pulumi CLI, the program it runs and the provider plugin.
PULUMI_PASSTHROUGH = (
    "PATH",
    "HOME",
    "TMPDIR",
    "RUNNER_TEMP",
    "LANG",
    "LC_ALL",
    "USER",
    "CI",
    "OVH_ENDPOINT",
    "OVH_CLIENT_ID",
    "OVH_CLIENT_SECRET",
    "OVH_CLOUD_PROJECT_SERVICE",
)

Connect = Callable[[str, str, str, str], Ops]
Fetch = Callable[[str, str], Mapping[str, Any]]


def fetch_json(url: str, token: str) -> Mapping[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as answer:
        parsed = json.load(answer)
    if not isinstance(parsed, dict):
        raise TypeError("the API answer was not an object")
    return parsed


@dataclass
class Context:
    environ: Mapping[str, str]
    workdir: Path
    project_dir: Path
    run: Runner = run_command
    connect: Connect = BotoOps.connect
    fetch: Fetch = fetch_json
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], datetime.datetime] = lambda: datetime.datetime.now(datetime.UTC)

    def out(self, text: str) -> None:
        print(text, flush=True)

    def summary(self, text: str) -> None:
        target = self.environ.get("GITHUB_STEP_SUMMARY")
        if target:
            with open(target, "a", encoding="utf-8") as handle:
                handle.write(text + "\n\n")
        else:
            self.out(text)

    def mask(self, *values: str) -> None:
        """Registers each line of each value with the runner before it is used."""
        for value in values:
            for line in value.splitlines():
                if line.strip():
                    self.out(f"::add-mask::{line}")

    @property
    def run_file(self) -> Path:
        return self.workdir / "run.json"

    @property
    def passphrase_file(self) -> Path:
        return self.workdir / "passphrase"

    @property
    def backend_dir(self) -> Path:
        return self.workdir / "backend"

    def pulumi_env(self) -> dict[str, str]:
        env = {
            key: self.environ[key] for key in PULUMI_PASSTHROUGH if key in self.environ
        }
        env["PULUMI_BACKEND_URL"] = f"file://{self.backend_dir}"
        env["PULUMI_CONFIG_PASSPHRASE_FILE"] = str(self.passphrase_file)
        env["PULUMI_SKIP_UPDATE_CHECK"] = "true"
        return env

    def stack(self) -> ProbeStack:
        return ProbeStack(self.run, self.project_dir, self.pulumi_env(), STACK)


# ---------------------------------------------------------------- gate


def gate(ctx: Context) -> int:
    """Refuses to go on unless the job really was held by the environment's rules."""
    repo = ctx.environ.get("GITHUB_REPOSITORY", "")
    name = ctx.environ.get("PROBE_ENVIRONMENT", "")
    token = ctx.environ.get("GH_TOKEN", "")
    ref = ctx.environ.get("GITHUB_REF", "")
    if (
        not re.fullmatch(r"[\w.-]+/[\w.-]+", repo)
        or not re.fullmatch(r"[\w.-]+", name)
        or not token
    ):
        ctx.out(
            "::error::the gate has no repository, environment name or token to read with"
        )
        return 1
    if ref != "refs/heads/main":
        ctx.out("::error::the probe runs from main only")
        return 1
    try:
        found = ctx.fetch(
            f"https://api.github.com/repos/{repo}/environments/{name}", token
        )
    except Exception as exc:  # noqa: BLE001 - unreadable means unguarded
        ctx.out(
            f"::error::could not read the environment's protection: {type(exc).__name__}"
        )
        return 1
    rules = found.get("protection_rules")
    reviewers = [
        rule
        for rule in (rules if isinstance(rules, list) else [])
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    if not reviewers:
        ctx.out(
            f"::error::the {name} environment has no required-reviewer rule, so nothing held this run"
        )
        return 1
    if not found.get("deployment_branch_policy"):
        ctx.out(f"::error::the {name} environment has no deployment branch policy")
        return 1
    ctx.out(f"The {name} environment has a required-reviewer rule and a branch policy.")
    return 0


# ---------------------------------------------------------------- up


def _suffix(environ: Mapping[str, str]) -> str:
    run_id = environ.get("GITHUB_RUN_ID", "")
    attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"\d{1,12}", run_id) or not re.fullmatch(r"\d{1,3}", attempt):
        raise ValueError("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT must be numbers")
    return f"r{run_id}a{attempt}"


def _write_phase(ctx: Context, suffix: str, phase: str) -> None:
    ctx.run_file.write_text(
        json.dumps({"phase": phase, "suffix": suffix}), encoding="utf-8"
    )


def up(ctx: Context) -> int:
    try:
        suffix = _suffix(ctx.environ)
    except ValueError as exc:
        ctx.out(f"::error::{exc}")
        return 1
    ctx.workdir.mkdir(parents=True, exist_ok=True)
    # The marker goes down before anything can be created, so destroy knows to look.
    _write_phase(ctx, suffix, PHASE_STARTED)
    ctx.backend_dir.mkdir(parents=True, exist_ok=True)
    if not ctx.passphrase_file.exists():
        phrase = secrets.token_urlsafe(32)
        ctx.mask(phrase)
        descriptor = os.open(
            ctx.passphrase_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(phrase)
    stack = ctx.stack()
    try:
        stack.init()
        _write_phase(ctx, suffix, PHASE_READY)
        stack.set_suffix(suffix)
        stack.up()
    except PulumiError as exc:
        ctx.out(f"::error::{exc}")
        return 1
    ctx.out("The probe stack is up.")
    return 0


# ---------------------------------------------------------------- check


def _all_error(reason: str) -> list[CheckResult]:
    return [
        CheckResult(code, TITLES[code], Status.ERROR, reason) for code in EXPECTED_CODES
    ]


def _load_run(ctx: Context) -> tuple[str, str]:
    data = json.loads(ctx.run_file.read_text(encoding="utf-8"))
    return str(data["phase"]), str(data["suffix"])


def _credentials(outputs: Mapping[str, Any], user: str) -> tuple[str, str]:
    return str(outputs["accessKeyIds"][user]), str(outputs["secretAccessKeys"][user])


def check(ctx: Context) -> int:
    known: list[str] = []
    try:
        _, suffix = _load_run(ctx)
        outputs = ctx.stack().outputs()
        rw_id, rw_secret = _credentials(outputs, RW_USER)
        admin_id, admin_secret = _credentials(outputs, ADMIN_USER)
        known = [rw_id, rw_secret, admin_id, admin_secret]
        ctx.mask(*known)
        target = Target(
            endpoint=str(outputs["s3Endpoints"][f"zz-probe-a-{suffix}"]),
            bucket_a=f"zz-probe-a-{suffix}",
            bucket_b=f"zz-probe-b-{suffix}",
            bucket_c=f"zz-probe-c-{suffix}",
        )
        names = set(outputs["bucketNames"])
        if not {target.bucket_a, target.bucket_b, target.bucket_c} <= names:
            raise KeyError("the three probe buckets are not all in the stack outputs")
        rw = ctx.connect(target.endpoint, REGION, rw_id, rw_secret)
        admin = ctx.connect(target.endpoint, REGION, admin_id, admin_secret)
    except Exception as exc:  # noqa: BLE001 - no outputs: all six are errors
        results = _all_error(f"the probe could not start: {type(exc).__name__}")
    else:
        results = Probe(rw, admin, target, clock=ctx.clock, sleep=ctx.sleep).run()
    results = [
        CheckResult(r.code, r.title, r.status, scrub(r.detail, known)) for r in results
    ]
    table = render_table(results)
    ctx.out(table)
    ctx.summary("## OVHcloud lock probe: results\n\n" + table)
    return 0 if all_passed(results) else 1


# ---------------------------------------------------------------- destroy


def _purge(ctx: Context, stack: ProbeStack, suffix: str) -> list[str]:
    """Empties bucket A, which is the only bucket anything is ever written to."""
    notes: list[str] = []
    try:
        outputs = stack.outputs()
        key, secret = _credentials(outputs, RW_USER)
        ctx.mask(key, secret)
        bucket = f"zz-probe-a-{suffix}"
        ops = ctx.connect(str(outputs["s3Endpoints"][bucket]), REGION, key, secret)
        for item in ops.list_versions(bucket):
            try:
                ops.delete_version(bucket, item.key, item.version_id, bypass=True)
            except Exception as exc:  # noqa: BLE001 - noted, then the rest still runs
                notes.append(
                    f"could not remove a version from bucket A: {type(exc).__name__}"
                )
    except Exception as exc:  # noqa: BLE001 - noted; destroy goes on without it
        notes.append(f"bucket A was not emptied first: {type(exc).__name__}")
    return notes


def destroy(ctx: Context) -> int:
    if not ctx.run_file.exists():
        ctx.summary(
            "## OVHcloud lock probe: cleanup\n\nNothing was created: the probe never started."
        )
        return 0
    try:
        phase, suffix = _load_run(ctx)
    except (ValueError, KeyError, OSError):
        phase, suffix = "", ""
    if phase == PHASE_STARTED:
        ctx.summary(
            "## OVHcloud lock probe: cleanup\n\nNothing was created: the run stopped before the stack existed."
        )
        return 0
    if phase != PHASE_READY or not ctx.passphrase_file.exists():
        ctx.out(
            "::error::the probe's run state is unreadable, so nothing can be shown destroyed"
        )
        ctx.summary(
            "## OVHcloud lock probe: cleanup\n\n**Destruction could not be verified: run state unreadable.**"
        )
        return 1

    stack = ctx.stack()
    notes = _purge(ctx, stack, suffix)
    try:
        before = stack.resources()
    except (PulumiError, ValueError):
        before = []
        notes.append("the stack's resources could not be listed before destroying")

    leftovers: list[Leftover] = []
    for attempt in range(DESTROY_ATTEMPTS):
        stack.destroy()
        try:
            left = stack.resources()
        except (PulumiError, ValueError):
            left = None
        if left is not None and not left:
            leftovers = []
            break
        leftovers = (
            [
                Leftover(
                    "state unreadable",
                    "the stack's state could not be read after destroying",
                )
            ]
            if left is None
            else [Leftover(item.kind, item.cloud_name or item.name) for item in left]
        )
        if attempt < DESTROY_ATTEMPTS - 1:
            ctx.sleep(DESTROY_PAUSE)

    remaining = {item.name for item in leftovers}
    destroyed = [
        item.cloud_name or item.name for item in before if item.name not in remaining
    ]
    text = render_cleanup(destroyed, leftovers, "; ".join(notes))
    ctx.out(text)
    ctx.summary("## OVHcloud lock probe: cleanup\n\n" + text)
    if leftovers:
        names = ", ".join(item.name for item in leftovers)
        ctx.out(f"::error::probe resources remain and must be deleted by hand: {names}")
        return 1
    return 0


# ---------------------------------------------------------------- main


def main(argv: list[str], environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("gate", "up", "check", "destroy"))
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    base = env.get("PROBE_WORKDIR") or (
        f"{env['RUNNER_TEMP']}/ovh-copy2-probe" if env.get("RUNNER_TEMP") else ""
    )
    if not base and args.command != "gate":
        print("::error::neither PROBE_WORKDIR nor RUNNER_TEMP is set")
        return 1
    workdir = Path(base or ".")
    ctx = Context(
        environ=env, workdir=workdir, project_dir=Path(__file__).resolve().parent.parent
    )
    handlers = {"gate": gate, "up": up, "check": check, "destroy": destroy}
    return handlers[args.command](ctx)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
