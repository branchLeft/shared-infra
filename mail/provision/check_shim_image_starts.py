#!/usr/bin/env python3
"""CI-only check: the env rendered for the digest pinned in shim-compose.yml
starts that exact image and answers the compose healthcheck. Why it exists,
how it is bounded and what it cannot show: check_shim_image_starts.md beside
this file. Never run it on a host (docker, no network, a placeholder secret).

    check_shim_image_starts.py                          # must start and be healthy
    check_shim_image_starts.py --expect-smtp-host-missing   # control: must fail,
                                                            # for that reason only
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time

from test_shim_compose_healthcheck import shim_healthcheck_script

PROVISION_DIR = pathlib.Path(__file__).resolve().parent
COMPOSE = PROVISION_DIR / "shim-compose.yml"
RENDERER = PROVISION_DIR / "render_shim_env.py"

IMAGE_LINE = re.compile(
    r"^\s*image:\s*(ghcr\.io/branchleft/mailgun-shim@sha256:[0-9a-f]{64})\s*$", re.MULTILINE
)
PLACEHOLDER_SECRET = "PLACEHOLDER-NOT-A-SECRET"  # noqa: S105 -- never a real value
CREDENTIAL_LABEL = "blog-shim-bulk-submission"
SMTP_HOST_MISSING = "Missing required environment variable SMTP_HOST"
# A mount or permission failure is a different fault from a missing variable, and must not pass
# for it: the control is only worth anything if it fails for the right reason.
MOUNT_OR_PERMISSION = ("SQLITE_CANTOPEN", "EACCES", "EPERM")
START_SECONDS = 30
EXEC_SECONDS = 10


def pinned_image(compose_text: str) -> str:
    """The shim image reference, name and digest, from the compose file's one `image:` line."""
    found = IMAGE_LINE.findall(compose_text)
    if len(found) != 1:
        raise SystemExit(f"check_shim_image_starts: expected one pinned shim image line, found {len(found)}")
    return found[0]


def classify_failure(log: str) -> str:
    """Why a container stopped: smtp-host-missing, mount-or-permission, or other."""
    if any(marker in log for marker in MOUNT_OR_PERMISSION):
        return "mount-or-permission"
    if SMTP_HOST_MISSING in log:
        return "smtp-host-missing"
    return "other"


def docker(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False  # noqa: S607
    )


def pull_with_one_retry(image: str) -> None:
    for attempt in (1, 2):
        done = docker("pull", image, timeout=300)
        if done.returncode == 0:
            return
        print(f"check_shim_image_starts: docker pull attempt {attempt} failed: {done.stderr.strip()}")
    raise SystemExit("check_shim_image_starts: docker pull failed twice")


def render_env(work: pathlib.Path, renderer: str) -> pathlib.Path:
    """Run the renderer exactly as 63 does, against temp paths and a placeholder credential."""
    credentials = work / "credentials"
    credentials.write_text(f"{CREDENTIAL_LABEL}:{PLACEHOLDER_SECRET}\n", encoding="utf-8")
    credentials.chmod(0o600)
    env_file = work / "env"
    done = subprocess.run(  # noqa: S603
        [sys.executable, renderer],
        env={
            **os.environ,
            "SHIM_ENV_PATH": str(env_file),
            "SERVICE_CREDENTIALS_PATH": str(credentials),
            "SHIM_COMPOSE_PATH": str(COMPOSE),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    print(done.stdout.strip())
    if done.returncode != 0:
        print(done.stderr.strip())
        raise SystemExit("check_shim_image_starts: the renderer refused; no env was written")
    return env_file


def render_drain_env(work: pathlib.Path) -> pathlib.Path:
    """The control's environment: the drain contract's output, which is exactly what main
    rendered before the fix and which the pinned image cannot start with.
    """
    import render_shim_env as renderer  # noqa: PLC0415 -- only the control needs it

    env_file = work / "env"
    contract = renderer.load_table()["contracts"]["drain"]
    env_file.write_text(renderer.render_env_file(contract, PLACEHOLDER_SECRET), encoding="utf-8")
    env_file.chmod(0o600)
    return env_file


def wait_for_health(container: str, script: str) -> tuple[bool, str]:
    """Poll the compose healthcheck inside the container; stop at once if it exits."""
    deadline = time.monotonic() + START_SECONDS
    while time.monotonic() < deadline:
        state = docker("inspect", "-f", "{{.State.Running}}", container)
        if state.stdout.strip() != "true":
            return False, "exited"
        probe = docker("exec", container, "node", "-e", script, timeout=EXEC_SECONDS)
        if probe.returncode == 0:
            return True, "healthy"
        time.sleep(1)
    return False, "never healthy"


def run(expect_missing: bool) -> int:
    image = pinned_image(COMPOSE.read_text(encoding="utf-8"))
    script = shim_healthcheck_script(COMPOSE.read_text(encoding="utf-8"))
    renderer = os.environ.get("SHIM_RENDERER", str(RENDERER))
    print(f"check_shim_image_starts: image {image}")
    pull_with_one_retry(image)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        work = pathlib.Path(tmp)
        if expect_missing and "SHIM_RENDERER" not in os.environ:
            env_file = render_drain_env(work)
        else:
            env_file = render_env(work, renderer)
        data = work / "data"
        data.mkdir()
        # The runner is not uid 1000 and the image runs as node (1000): open the directory
        # rather than chown it, the same reason 63 chowns it on the host.
        data.chmod(0o777)
        (data / "throttle.json").write_text("{}\n", encoding="utf-8")
        (data / "throttle.json").chmod(0o644)
        started = docker(
            "run", "-d", "--network", "none", "--env-file", str(env_file), "-v", f"{data}:/data", image
        )
        if started.returncode != 0:
            print(started.stderr.strip())
            return 1
        container = started.stdout.strip()
        try:
            healthy, how = wait_for_health(container, script)
            log = docker("logs", container)
            text = log.stdout + log.stderr
            print(text)
            reason = classify_failure(text)
            if healthy:
                print("CONTROL-REASON: none (container is healthy)")
                if expect_missing:
                    print("check_shim_image_starts: CONTROL BROKEN -- the stale env should not start")
                    return 1
                print("check_shim_image_starts: OK -- the rendered env starts the pinned digest and answers its healthcheck")
                return 0
            print(f"CONTROL-REASON: {reason} ({how})")
            if expect_missing and reason == "smtp-host-missing":
                print("check_shim_image_starts: CONTROL OK -- stopped for the right reason")
                return 0
            return 1
        finally:
            docker("rm", "-f", container)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--expect-smtp-host-missing", action="store_true")
    return run(parser.parse_args().expect_smtp_host_missing)


if __name__ == "__main__":
    sys.exit(main())
