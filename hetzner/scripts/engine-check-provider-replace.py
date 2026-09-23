#!/usr/bin/env python3
"""Ask the Pulumi engine, offline, whether a provider change replaces resources.

    engine-check-provider-replace.py

Everything happens in a temporary directory with a file backend, a throwaway
passphrase and a fake token. `HCLOUD_ENDPOINT` points at a closed loopback
port and `HCLOUD_TOKEN` is removed from the environment, so nothing can reach
Hetzner and no real token is ever read. Each scenario seeds a stack with a
hand-written checkpoint (a firewall and a network that "already exist"), runs
a plain `pulumi preview` over a program that differs in one way, and reads the
planned operations.

    rotation   explicit provider, token A in state, token B in config.
               The operation every new-project stack will need. Asserted:
               no replacement.
    control    the same, but the network's `ipRange` changes, which hcloud
               can only do by replacement. Asserted: a replacement IS seen.
               Without it, "no replacement" above could mean an instrument
               that never reports one.
    adoption   state under the default provider, program on an explicit one.
               Reported, not asserted: it is why the existing mail and org
               stacks stay on the default provider.

Exit 0 when rotation shows no replacement and the control shows one; 1
otherwise; 2 if a scenario could not run.

Seeding a checkpoint is a Pulumi state import. That is on the estate's
never-list for agents, sandbox or not, so this script is run by the platform
owner.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HETZNER = pathlib.Path(__file__).resolve().parent.parent
PROJECT = "engine-check"
REPLACING = {"replace", "create-replacement", "delete-replaced", "delete"}

PROGRAM = """
const hcloud = require('@pulumi/hcloud');
const pulumi = require('@pulumi/pulumi');
const config = new pulumi.Config();
const opts =
  config.require('mode') === 'explicit'
    ? { provider: new hcloud.Provider('hcloud-tenants', {
        token: new pulumi.Config('hcloud-projects').requireSecret('tenantsToken'),
      }) }
    : {};
new hcloud.Firewall('marker', { name: 'project-marker-tenants' }, opts);
new hcloud.Network('net', { name: 'platform', ipRange: config.require('ipRange') }, opts);
"""

FAKE_A = "a" * 64
FAKE_B = "b" * 64


def checkpoint(stack: str, provider: str) -> dict:
    prefix = f"urn:pulumi:{stack}::{PROJECT}::"
    root = f"{prefix}pulumi:pulumi:Stack::{PROJECT}-{stack}"
    if provider == "explicit":
        provider_urn = f"{prefix}pulumi:providers:hcloud::hcloud-tenants"
        provider_inputs = {"token": FAKE_A, "version": "1.41.0"}
    else:
        provider_urn = f"{prefix}pulumi:providers:hcloud::default_1_41_0"
        provider_inputs = {"version": "1.41.0"}
    provider_id = "00000000-0000-4000-8000-000000000001"
    ref = f"{provider_urn}::{provider_id}"
    return {
        "version": 3,
        "deployment": {
            "manifest": {"time": "2026-01-01T00:00:00Z", "magic": "", "version": "v3.255.0"},
            "resources": [
                {"urn": root, "custom": False, "type": "pulumi:pulumi:Stack"},
                {
                    "urn": provider_urn,
                    "custom": True,
                    "id": provider_id,
                    "type": "pulumi:providers:hcloud",
                    "inputs": provider_inputs,
                    "outputs": provider_inputs,
                },
                {
                    "urn": f"{prefix}hcloud:index/firewall:Firewall::marker",
                    "custom": True,
                    "id": "1001",
                    "type": "hcloud:index/firewall:Firewall",
                    "inputs": {"name": "project-marker-tenants"},
                    "outputs": {
                        "id": "1001",
                        "name": "project-marker-tenants",
                        "labels": {},
                        "rules": [],
                        "applyTos": [],
                    },
                    "parent": root,
                    "provider": ref,
                },
                {
                    "urn": f"{prefix}hcloud:index/network:Network::net",
                    "custom": True,
                    "id": "2002",
                    "type": "hcloud:index/network:Network",
                    "inputs": {"name": "platform", "ipRange": "10.20.0.0/16"},
                    "outputs": {
                        "id": "2002",
                        "name": "platform",
                        "ipRange": "10.20.0.0/16",
                        "labels": {},
                        "deleteProtection": False,
                        "exposeRoutesToVswitch": False,
                    },
                    "parent": root,
                    "provider": ref,
                },
            ],
        },
    }


def pulumi(workdir: pathlib.Path, env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["pulumi", *args, "--non-interactive"],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def scenario(workdir: pathlib.Path, env: dict, stack: str, seeded: str, ip_range: str) -> list:
    steps: list = []
    done = pulumi(workdir, env, "stack", "init", stack)
    if done.returncode != 0:
        raise RuntimeError(f"stack init: {done.stderr.strip()}")
    for args in (
        ("mode", "explicit"),
        ("ipRange", ip_range),
        ("--secret", "hcloud-projects:tenantsToken", FAKE_B),
    ):
        done = pulumi(workdir, env, "config", "set", "--stack", stack, *args)
        if done.returncode != 0:
            raise RuntimeError(f"config set {args[0]}: {done.stderr.strip()}")
    seed = workdir / f"{stack}.json"
    seed.write_text(json.dumps(checkpoint(stack, seeded)))
    done = pulumi(workdir, env, "stack", "import", "--stack", stack, "--file", str(seed))
    if done.returncode != 0:
        raise RuntimeError(f"seeding the checkpoint: {done.stderr.strip()}")
    done = pulumi(workdir, env, "preview", "--stack", stack, "--json")
    try:
        plan = json.loads(done.stdout)
    except ValueError:
        raise RuntimeError(f"preview produced no JSON: {done.stderr.strip()}") from None
    errors = [d["message"] for d in plan.get("diagnostics", []) if d.get("severity") == "error"]
    if errors:
        raise RuntimeError(f"preview failed: {errors}")
    for step in plan.get("steps", []):
        steps.append((step["op"], step["urn"].rsplit("::", 1)[-1]))
    return steps


def replacements(steps: list) -> list:
    return [(op, name) for op, name in steps if op in REPLACING]


def main() -> int:
    if shutil.which("pulumi") is None:
        print("ERROR: pulumi is not on PATH")
        return 2
    if not (HETZNER / "node_modules" / "@pulumi" / "hcloud").is_dir():
        print("ERROR: run `npm ci` in hetzner/ first")
        return 2
    with tempfile.TemporaryDirectory(prefix="engine-check-") as tmp:
        workdir = pathlib.Path(tmp)
        (workdir / "Pulumi.yaml").write_text(f"name: {PROJECT}\nruntime: nodejs\nmain: index.js\n")
        (workdir / "index.js").write_text(PROGRAM)
        (workdir / "node_modules").symlink_to(HETZNER / "node_modules")
        (workdir / "state").mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("HCLOUD_", "PULUMI_"))}
        env.update(
            PULUMI_BACKEND_URL=f"file://{workdir / 'state'}",
            PULUMI_CONFIG_PASSPHRASE="sandbox-only",
            PULUMI_SKIP_UPDATE_CHECK="1",
            HCLOUD_ENDPOINT="http://127.0.0.1:9/v1",
        )
        try:
            rotation = scenario(workdir, env, "rotation", "explicit", "10.20.0.0/16")
            control = scenario(workdir, env, "control", "explicit", "10.30.0.0/16")
            adoption = scenario(workdir, env, "adoption", "default", "10.20.0.0/16")
        except RuntimeError as error:
            print(f"ERROR: {error}")
            return 2
    for label, steps in (("rotation", rotation), ("control", control), ("adoption", adoption)):
        print(f"{label}: {steps}")
        print(f"{label} replacements: {replacements(steps) or 'none'}")
    rotation_ok = not replacements(rotation)
    control_ok = bool(replacements(control))
    print(f"rotation plans no replacement: {'PASS' if rotation_ok else 'FAIL'}")
    print(f"control sees the forced replacement: {'PASS' if control_ok else 'FAIL'}")
    return 0 if rotation_ok and control_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
