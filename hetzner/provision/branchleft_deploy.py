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

Two calling conventions, and the difference between them is which principal
chooses the stack:

    branchleft-deploy <stack> <image@sha256:...>

  The unscoped form. The caller names any stack on the host, so possession of
  a key that can reach it is authority over every stack on that host. It is
  what the platform's own repositories use.

    branchleft-deploy --slot <stack>            # image read from stdin

  The scoped form. The stack name is not an argument the caller supplies: it
  is fixed in the `command=` of the authorized_keys entry the presented key
  authenticated against, which only root can write
  (`provision_deploy_slot.py`). The caller supplies the image and nothing
  else, so a key issued for one stack cannot address another, and there is no
  name for this script to cross-check because there is no name from the
  caller to distrust.

  The image arrives on stdin rather than in SSH_ORIGINAL_COMMAND because a
  forced command discards the client's argv, leaving those two as the only
  channels. Carrying it in the environment would need sudo's env_reset opened
  for that variable, which means editing the sudoers grant on every live host
  in order to add a control; stdin needs no change to any privileged file,
  and does not leave a caller-controlled string in a root process's
  environment where a later reader could find it.
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


# `${IMAGE}` and `${IMAGE:?message}` only. Both fail closed: the first
# substitutes empty and Compose rejects the resulting `image:`, the second
# aborts by name. `${IMAGE:-default}` is deliberately absent -- it fails *open*,
# resolving to a hardcoded reference the moment the pin is empty, which is the
# state the mandatory EnvironmentFile exists to make impossible.
IMAGE_PIN_REFERENCE = re.compile(r"\$\{IMAGE(?::\?[^}]*)?\}")

# The fail-open forms, matched so a caller can name them rather than reporting
# the far more confusing "does not resolve its image from ${IMAGE}" about a file
# that visibly mentions IMAGE on the `image:` line.
IMAGE_FALLBACK_REFERENCE = re.compile(r"\$\{IMAGE:[-+=][^}]*\}|\$IMAGE(?![A-Za-z0-9_])")

# YAML begins a comment at a `#` that starts the line or follows whitespace.
_COMMENT = re.compile(r"(?:^|\s)#")


def strip_yaml_comments(compose_text: str) -> str:
    """Drop commented-out text so commentary cannot be read as configuration.

    Trailing comments are cut as well as whole lines: `image: foo@sha256:...
    # was ${IMAGE}` otherwise reads as a live pin reference while the service
    below it runs a hardcoded digest, which is exactly the state being guarded
    against.

    Quoting is not tracked. The only question asked of the result is whether an
    IMAGE reference is live configuration or commentary, and a `#` inside a
    quoted scalar ahead of one would be pathological in a Compose file.
    """
    kept = []
    for line in compose_text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        comment = _COMMENT.search(line)
        kept.append(line[: comment.start()] if comment else line)
    return "\n".join(kept)


def resolves_image_from_env(compose_text: str) -> bool:
    """Whether a Compose file actually substitutes the pin this script writes.

    Module-level rather than inline in `deploy()` because the unit template's
    image-pin contract has a second half this script cannot enforce -- a stack
    that pins inline needs its drop-in to reset `EnvironmentFile=`, or it has no
    writer for a file it cannot start without. The repository-wide test of that
    invariant calls this, so the two halves cannot drift into disagreeing about
    what "resolves its image from ${IMAGE}" means.
    """
    return bool(IMAGE_PIN_REFERENCE.search(strip_yaml_comments(compose_text)))


def has_fail_open_image_reference(compose_text: str) -> bool:
    """Whether a Compose file reaches for IMAGE in a form that survives an empty pin."""
    return bool(IMAGE_FALLBACK_REFERENCE.search(strip_yaml_comments(compose_text)))


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
        compose_text = handle.read()
    if not resolves_image_from_env(compose_text):
        if has_fail_open_image_reference(compose_text):
            raise DeployError(
                f"{compose_file} reaches for IMAGE in a form that survives an empty "
                "pin (${IMAGE:-default} or $IMAGE); use ${IMAGE} or ${IMAGE:?message}, "
                "which fail closed"
            )
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


# Generous next to a reference that cannot exceed a few hundred bytes, and
# small enough that a caller piping something else entirely is refused rather
# than read into memory. The read asks for one byte more so "at the limit" and
# "truncated at the limit" are distinguishable.
SLOT_STDIN_LIMIT = 4096

SLOT_FLAG = "--slot"


def read_slot_image(stream, *, limit: int = SLOT_STDIN_LIMIT) -> str:
    """The one caller-supplied value in slot mode, taken from stdin.

    `splitlines()` rather than a newline split: it also breaks on the vertical
    tab, form feed and separator characters, so a payload that hides a second
    token behind one of them is two lines here and refused, instead of being
    one line that the image pattern would then have to be relied on to reject.
    """
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise DeployError(
            f"image reference on stdin exceeds {limit} bytes; expected one "
            "digest-pinned reference"
        )
    lines = raw.splitlines()
    if not lines:
        raise DeployError("no image reference on stdin")
    if len(lines) != 1:
        raise DeployError(
            f"expected exactly one line on stdin, got {len(lines)}; a slot key "
            "deploys one image to its own stack and nothing else"
        )
    return validate_image_ref(lines[0])


def main(argv: list[str], *, stdin=None, deploy=deploy) -> int:
    usage = (
        "usage: branchleft-deploy <stack> <image@sha256:...>\n"
        f"       branchleft-deploy {SLOT_FLAG} <stack>   (image read from stdin)"
    )
    if len(argv) != 3:
        print(usage, file=sys.stderr)
        return 2

    slot_mode = argv[1] == SLOT_FLAG
    stack = argv[2] if slot_mode else argv[1]
    try:
        if slot_mode:
            # Ahead of the read, which blocks until the caller closes the
            # channel: a rejected stack name should not first wait on input it
            # is never going to use.
            validate_stack_name(stack)
            image = read_slot_image(stdin or sys.stdin)
        else:
            image = argv[2]
        deploy(stack, image)
    except DeployError as error:
        print(f"branchleft-deploy: {error}", file=sys.stderr)
        return 1
    print(f"branchleft-deploy: {stack} now pinned to {image}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
