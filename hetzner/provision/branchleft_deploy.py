#!/usr/bin/python3
"""Pin a Compose stack to an image digest and restart it.

Installed as /usr/local/sbin/branchleft-deploy and reachable from CI as the
deploy account's single sudo-permitted command. It is the whole of that
account's privilege, so it validates its own arguments rather than relying on
a sudoers pattern to do it -- a wildcard in a sudoers command matches spaces,
which makes any pattern-based restriction argument injection waiting to
happen.

Three rules it exists to enforce:

- **Only digest-pinned references.** A tag is a mutable pointer, so a stack
  deployed by tag has no answer to "what is running", and a restart months
  later can silently change the image. The refusal is here rather than in CI
  because CI is not the only caller.
- **The image file is not the secrets file.** This writes
  /etc/branchleft/<stack>.image.env and nothing else. Stack secrets live in
  /etc/branchleft/<stack>.env, which no automated path may rewrite; both are
  loaded by the systemd unit.
- **A restarted service has a health signal.** `docker compose up --wait`
  only reports a rollback-worthy failure for a service that declares a
  healthcheck; without one a crash loop is transiently `running`, so a bad
  deploy is not detected below at all. A gap this script does not already
  know about (`KNOWN_UNHEALTHCHECKED_SERVICES`) refuses the deploy rather
  than restart into a rollback that cannot fire; a known one only warns.

On a failed restart the previous digest is restored and the unit restarted
again, so a bad deploy leaves the host on the last image that worked rather
than on a file describing an image that does not run. The health-signal
refusal above is the one exception: it fires before either happens, so the
stack is left running whatever it already was.

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


class ComposeParseError(AssertionError):
    """A line under `services:` this parser cannot classify.

    The parser below is a regex over indentation, not a YAML parse, so a shape
    it does not recognise -- a YAML anchor on the service header, an inline
    mapping, a different nesting depth -- looks identical to "this service has
    no healthcheck key yet". Raising rather than skipping keeps that ambiguity
    from being read as a clean bill of health; `deploy()` below treats it as
    "could not determine" rather than "found a gap", which is the only choice
    that does not risk refusing a deploy the Compose file itself would start
    without any trouble.
    """


# The three states a service can be in, kept apart because "no healthcheck key"
# and "healthcheck key that turns the probe off" mean opposite things for a
# service whose image ships its own.
ABSENT, DECLARED, DISABLED = "absent", "declared", "disabled"

# A top-level mapping key: column 0, so `services:` is told from a key nested
# under it. Quoted and space-before-colon spellings are matched because YAML
# accepts them and a `services:` this missed would end the section early,
# leaving the rest of the file unread.
_TOP_LEVEL_KEY = re.compile(r"""\A(?P<quote>["']?)(?P<key>[A-Za-z0-9_.-]+)(?P=quote)\s*:""")

# A service name under `services:`, at Compose's two-space nesting. Matched at
# a fixed indent rather than by name so a service added at the wrong depth --
# which Compose would not read as a service at all -- is not silently counted
# as one that has a healthcheck.
_SERVICE_INDENT = 2
_SERVICE_HEADER = re.compile(rf"\A {{{_SERVICE_INDENT}}}([A-Za-z0-9][A-Za-z0-9_.-]*):\s*\Z")

# The healthcheck key of a service, with whatever follows it on the same line:
# `healthcheck: {disable: true}` is a declaration that switches the check off,
# and reads as one that turns it on unless the inline value is looked at.
_HEALTHCHECK_INDENT = 4
_HEALTHCHECK_HEADER = re.compile(rf"\A {{{_HEALTHCHECK_INDENT}}}healthcheck:(?P<inline>.*)\Z")

# The two ways Compose switches a healthcheck off. Both leave the `healthcheck:`
# key in place, so a check for the key alone reads either as a declared probe --
# and for a service whose image supplies one, `disable: true` is what removes
# the only probe it has.
_HEALTHCHECK_DISABLED = re.compile(r"\bdisable:\s*(?:true|yes|on)\b", re.IGNORECASE)
_HEALTHCHECK_TEST_NONE = re.compile(
    r"""\btest:\s*(?:\[\s*)?["']?NONE["']?\s*\]?\s*(?=[,}]|\Z)"""
    r"""|\A\s*-\s*["']?NONE["']?\s*\Z"""
)


def healthcheck_states(compose_text: str) -> dict[str, str]:
    """Every service in `services:`, mapped to `ABSENT`, `DECLARED` or `DISABLED`.

    Regex rather than a YAML parse to keep this module stdlib-only, matching how
    the image-pin half above reads the same files. Module-level, like
    `resolves_image_from_env`, so the repository-wide contract test for the
    stacks this repository commits and the deploy-time check below for whatever
    stack is about to be restarted -- committed here or not -- cannot drift into
    disagreeing about what a health signal is.

    Shapes it cannot classify raise `ComposeParseError`. The one gap it cannot
    raise on is a top-level key it fails to recognise at all, which would end
    the `services:` section early and leave the rest of the file unread.
    """
    states: dict[str, str] = {}
    current: str | None = None
    in_services = False
    healthcheck_block_of: str | None = None
    for raw in strip_yaml_comments(compose_text).splitlines():
        if not raw.strip():
            continue
        top_level = _TOP_LEVEL_KEY.match(raw)
        if top_level:
            in_services = top_level.group("key") == "services"
            current = None
            healthcheck_block_of = None
            continue
        if not in_services:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= _SERVICE_INDENT:
            header = _SERVICE_HEADER.match(raw)
            if header is None:
                raise ComposeParseError(
                    f"cannot read {raw!r} as a service header. Every key directly "
                    "under `services:` must be a bare `  name:` on its own line."
                )
            current = header.group(1)
            states[current] = ABSENT
            healthcheck_block_of = None
            continue
        if current is None:
            raise ComposeParseError(
                f"{raw!r} is nested under `services:` at indent {indent} with no "
                "service header above it. Compose services nest at two spaces; a "
                "different depth means this parser is reading a shape it was not "
                "written for."
            )
        if healthcheck_block_of is not None and indent <= _HEALTHCHECK_INDENT:
            healthcheck_block_of = None
        header = _HEALTHCHECK_HEADER.match(raw)
        if header:
            inline = header.group("inline")
            states[current] = (
                DISABLED
                if _HEALTHCHECK_DISABLED.search(inline) or _HEALTHCHECK_TEST_NONE.search(inline)
                else DECLARED
            )
            healthcheck_block_of = current
            continue
        if healthcheck_block_of is not None and (
            _HEALTHCHECK_DISABLED.search(raw) or _HEALTHCHECK_TEST_NONE.search(raw)
        ):
            states[healthcheck_block_of] = DISABLED
    return states


# Services whose image carries its own HEALTHCHECK instruction, so Compose
# already waits for *healthy* without the Compose file restating one -- Docker
# reports these as `Up (healthy)` exactly as a Compose-declared probe would.
# Listed rather than detected: reading an image's metadata needs a Docker
# daemon and a pulled image, which neither this module nor the deploy-time
# check below has.
IMAGE_PROVIDED_HEALTHCHECK: dict[tuple[str, str], str] = {
    ("monitoring", "cadvisor"): (
        "ghcr.io/google/cadvisor ships HEALTHCHECK CMD-SHELL /usr/bin/healthcheck.sh. "
        "Left to the image rather than restated here: a Compose-level healthcheck "
        "replaces the image's outright, so restating it would swap a probe cAdvisor "
        "maintains for one this repository would have to."
    ),
}

# Services already known to have no health signal at all -- reviewed and
# accepted rather than merely tolerated, so `deploy()` warns for these instead
# of refusing. A stack/service pair absent from both this table and
# `IMAGE_PROVIDED_HEALTHCHECK` is refused below: growing this table is a
# deliberate exemption that costs a diff to shared-infra a reviewer sees, and
# shrinking it (a service gaining a probe) needs no permission at all.
KNOWN_UNHEALTHCHECKED_SERVICES: frozenset[tuple[str, str]] = frozenset(
    {
        # branchLeft/website, deploy/compose.yml.
        ("website", "website-metrics"),
        # branchLeft/ghost-platform, db/stack/compose.yml.
        ("db", "mysqld-exporter"),
    }
)


def health_signal_gaps(stack: str, compose_text: str) -> tuple[list[str], list[str]]:
    """`(refused, warned)` services with no health signal, each `service (state)`.

    `refused` is empty exactly when the deploy should proceed with no gap this
    script does not already know about; anything in it is new since the last
    review of `KNOWN_UNHEALTHCHECKED_SERVICES` and stops the deploy. `warned`
    lists the accepted gaps so a deploy that proceeds still says so, loudly,
    every time.

    Propagates `ComposeParseError` rather than swallowing it: `deploy()` below
    is the one that decides a shape this cannot read is reported as "could not
    determine" rather than as a gap.
    """
    refused, warned = [], []
    for service, state in healthcheck_states(compose_text).items():
        if state == DECLARED or (stack, service) in IMAGE_PROVIDED_HEALTHCHECK:
            continue
        gap = f"{service} ({state})"
        if (stack, service) in KNOWN_UNHEALTHCHECKED_SERVICES:
            warned.append(gap)
        else:
            refused.append(gap)
    return refused, warned


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

    # `docker compose up --wait` is a rollback signal only for a service that
    # declares a healthcheck; without one it waits for *running*, which a
    # crash-looping container transiently is, so the restart below reports
    # success in front of the crash loop and never rolls back. Checked here,
    # ahead of any filesystem or systemd change, for the same reason as the
    # image-pin check above: a refusal must leave the stack running whatever
    # it already was.
    try:
        refused, warned = health_signal_gaps(stack, compose_text)
    except ComposeParseError as error:
        # A parser limitation is not a property of the stack: the regex reads
        # a narrower shape than Compose's own YAML grammar, so a file this
        # cannot classify may still start cleanly. Refusing the deploy over
        # that would be an outage the stack itself never had.
        print(
            f"branchleft-deploy: warning: could not determine {stack}'s health "
            f"signal from {compose_file}: {error}",
            file=sys.stderr,
        )
        refused, warned = [], []

    if refused:
        raise DeployError(
            f"{compose_file} has no health signal for: {', '.join(refused)}. "
            "`docker compose up --wait` cannot report a rollback-worthy failure "
            "without a healthcheck; give the service one, or add its (stack, "
            "service) pair to KNOWN_UNHEALTHCHECKED_SERVICES as a reviewed, "
            "accepted gap"
        )
    for gap in warned:
        print(
            f"branchleft-deploy: warning: {stack}: {gap} has no health signal; "
            "a crash loop after this restart will not roll back "
            "(KNOWN_UNHEALTHCHECKED_SERVICES)",
            file=sys.stderr,
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
        # A failed oneshot restart runs ExecStopPost, never ExecStop, so
        # `docker compose down` does not fire here -- whatever the most
        # recent `up -d --wait` attempt started is still running, healthy or
        # not, whatever this restart's own exit code says about the unit.
        raise DeployError(
            f"restart of branchleft-compose@{stack} failed AND the rollback to "
            f"{previous} also failed to start; branchleft-compose@{stack} is "
            "now `failed` on both pins, which is the unit's state, not the "
            "containers' -- check `docker ps --filter "
            f"label=com.docker.compose.project={stack}` for what is actually "
            "running before assuming an outage"
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
