#!/usr/bin/python3
"""Pin a Compose stack to an image digest and restart it.

Installed as /usr/local/sbin/branchleft-deploy and reachable from CI as the
deploy account's single sudo-permitted command. It is the whole of that
account's privilege, so it validates its own arguments rather than relying on
a sudoers pattern to do it -- a wildcard in a sudoers command matches spaces,
which makes any pattern-based restriction argument injection waiting to
happen.

Two rules it exists to enforce:

- **Only digest-pinned references.** A tag is a mutable pointer, so a stack
  deployed by tag has no answer to "what is running", and a restart months
  later can silently change the image. The refusal is here rather than in CI
  because CI is not the only caller.
- **The image file is not the secrets file.** This writes
  /etc/branchleft/<stack>.image.env and nothing else. Stack secrets live in
  /etc/branchleft/<stack>.env, which no automated path may rewrite; both are
  loaded by the systemd unit.

On a failed restart the previous digest is restored and the unit restarted
again, so a bad deploy leaves the host on the last image that worked rather
than on a file describing an image that does not run.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile

CONFIG_DIR = "/etc/branchleft"
STACK_DIR = "/opt/branchleft"

# Deliberately narrower than the character set systemd would accept in an
# instance name: this value is interpolated into a unit name and a filesystem
# path, and every character outside this set is one that would have to be
# reasoned about twice.
STACK_NAME = re.compile(r"\A[a-z][a-z0-9-]{0,31}\Z")

# Registry host and path, an optional tag, and a mandatory sha256 digest.
# `\A`/`\Z` rather than `^`/`$` throughout: `$` also matches immediately
# before a trailing newline, so an argument arriving with one from a shell
# pipeline would validate and then be written into the environment file
# carrying it.
IMAGE_REF = re.compile(
    r"\A[a-z0-9]+(?:[._-][a-z0-9]+)*"         # first path component
    r"(?::[0-9]+)?"                            # optional registry port
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"      # remaining path components
    r"(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?" # optional tag
    r"@sha256:[0-9a-f]{64}\Z"
)


class DeployError(Exception):
    """Raised for anything a caller could have avoided by passing valid input."""


def validate_stack_name(name: str) -> str:
    if not STACK_NAME.match(name):
        raise DeployError(f"invalid stack name: {name!r}")
    return name


def validate_image_ref(ref: str) -> str:
    if not IMAGE_REF.match(ref):
        raise DeployError(
            f"image reference must be digest-pinned (name@sha256:...), got {ref!r}"
        )
    return ref


def image_env_path(stack: str, config_dir: str = CONFIG_DIR) -> str:
    return os.path.join(config_dir, f"{stack}.image.env")


def compose_file_path(stack: str, stack_dir: str = STACK_DIR) -> str:
    return os.path.join(stack_dir, stack, "compose.yml")


def read_current_image(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as handle:
            content = handle.read()
    except FileNotFoundError:
        return None
    for line in content.splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "IMAGE":
            # An empty assignment is not a pin. Returning "" would make the
            # rollback below restore a file the unit then refuses to start
            # from, while reporting that it had recovered.
            return value.strip() or None
    return None


def write_image_env(path: str, image: str) -> None:
    """Replace the file atomically.

    The temporary file is created in the destination's own directory so the
    rename is within one filesystem; a rename across filesystems is not
    atomic and would leave a window in which the unit could load a partial
    file. Permissions are set before the rename for the same reason.
    """
    directory = os.path.dirname(path)
    handle_fd, temporary = tempfile.mkstemp(dir=directory, prefix=".branchleft-deploy-")
    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
            handle.write(f"IMAGE={image}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def deploy(
    stack: str,
    image: str,
    *,
    config_dir: str = CONFIG_DIR,
    stack_dir: str = STACK_DIR,
    run=subprocess.run,
) -> None:
    validate_stack_name(stack)
    validate_image_ref(image)

    compose_file = compose_file_path(stack, stack_dir)
    if not os.path.exists(compose_file):
        raise DeployError(f"no compose file at {compose_file}")

    # A validated digest that the Compose file never reads is a pin in name
    # only: the stack would run whatever tag it hardcodes while this reports
    # success. The digest-pinning property only exists if the substitution is
    # actually wired up, so it is checked rather than assumed.
    with open(compose_file, encoding="utf-8") as handle:
        # Comment lines are stripped first: a `# uses ${IMAGE}` line would
        # otherwise satisfy the check while the services below it run a
        # hardcoded tag, which is precisely the state being guarded against.
        effective = "\n".join(
            line for line in handle.read().splitlines() if not line.lstrip().startswith("#")
        )
    if "${IMAGE}" not in effective:
        raise DeployError(
            f"{compose_file} does not resolve its image from ${{IMAGE}}, "
            "so a pin written here would not take effect"
        )

    env_path = image_env_path(stack, config_dir)
    previous = read_current_image(env_path)
    write_image_env(env_path, image)

    result = run(["systemctl", "restart", f"branchleft-compose@{stack}"], check=False)
    if result.returncode == 0:
        return

    if previous is None:
        # Nothing to roll back to. The unit's EnvironmentFile for the pin
        # carries no leading dash, so it cannot start without one at all --
        # restarting here would fail by construction and turn a first-deploy
        # failure into a misleading report about a stack that was never up.
        os.unlink(env_path)
        raise DeployError(
            f"branchleft-compose@{stack} failed to start on {image}, and there "
            "was no previous pin to fall back to; the stack has never run"
        )

    write_image_env(env_path, previous)

    # The rollback's own outcome decides what this reports. Asserting a
    # recovery that did not happen is worse than reporting the original
    # failure: it tells the caller the host is serving on last-known-good
    # while it is down, which is the state nobody investigates.
    rollback = run(["systemctl", "restart", f"branchleft-compose@{stack}"], check=False)
    if rollback.returncode != 0:
        raise DeployError(
            f"restart of branchleft-compose@{stack} failed AND the rollback to "
            f"{previous} also failed to start; the stack is down and needs "
            "an operator"
        )
    raise DeployError(
        f"restart of branchleft-compose@{stack} failed; rolled back to {previous}"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: branchleft-deploy <stack> <image@sha256:...>", file=sys.stderr)
        return 2
    try:
        deploy(argv[1], argv[2])
    except DeployError as error:
        print(f"branchleft-deploy: {error}", file=sys.stderr)
        return 1
    print(f"branchleft-deploy: {argv[1]} now pinned to {argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
