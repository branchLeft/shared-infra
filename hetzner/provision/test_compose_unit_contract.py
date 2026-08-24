#!/usr/bin/env python3
"""Every committed Compose stack must agree with the unit template's image pin.

`branchleft-compose@.service` loads `/etc/branchleft/%i.image.env` with no
leading dash, so systemd fails the unit start outright when that file is
absent. Only `branchleft-deploy` writes it, and it refuses to write one for a
stack whose Compose file does not resolve `${IMAGE}`.

Those two rules are each correct and together they are a trap: a stack that
pins its images inline has no writer for a file it cannot start without. The
failure is invisible in review, invisible to `docker compose config`, and
invisible to the config-validation jobs, because none of them load the systemd
unit -- it appears for the first time as a failed `systemctl start` on a real
host, which is where it appeared.

The escape is an instance drop-in resetting `EnvironmentFile=`, which drops the
pin for that instance alone. This asserts the two halves stay consistent, in
both directions: an inline-pinned stack has the reset, and an `${IMAGE}` stack
does not -- a stray reset there would silently disable the mandatory pin, which
is the guarantee the no-leading-dash was chosen for.

The same file holds a second contract, for the same reason: `--wait` is only a
deploy signal for a service that declares a `healthcheck:`. Without one Compose
waits for *running*, which a crash-looping container transiently is, so the
stack reports a clean start in front of it and branchleft-deploy's rollback --
which fires on a non-zero `systemctl restart` and nothing else -- never runs.
That is invisible to `docker compose config` and to the config-validation jobs,
because none of them start a container.

Everything here reads the `[Service]` section only, and matches whole stripped
lines. systemd ignores assignments before a section header, so a directive
found anywhere in the file is not a directive systemd applies.
"""

import os
import pathlib
import re
import stat
import subprocess
import tempfile
import unittest

import branchleft_deploy as bd

HETZNER = pathlib.Path(__file__).resolve().parent.parent

# A bare `EnvironmentFile=` clears every prior assignment (systemd.exec(5):
# "If the empty string is assigned to this option, the list of file to read is
# reset, all prior assignments have no effect").
RESET_DIRECTIVE = "EnvironmentFile="

# Compose interpolates `${VAR}`; the stack needs a secrets file if it reads any
# variable other than the image pin. `IMAGE` is excluded by name rather than by
# position so a stack whose only variable is the pin is correctly read as
# needing no secrets.
COMPOSE_VARIABLE = re.compile(r"\$\{(?!IMAGE[}:])([A-Za-z_][A-Za-z0-9_]*)")

# A top-level mapping key: column 0, so `services:` is told from a key nested
# under it.
TOP_LEVEL_KEY = re.compile(r"\A([A-Za-z0-9_.-]+):")

# A service name under `services:`, at Compose's two-space nesting. Matched at
# a fixed indent rather than by name so a service added at the wrong depth --
# which Compose would not read as a service at all -- is not silently counted
# as one that has a healthcheck.
SERVICE_HEADER = re.compile(r"\A {2}([A-Za-z0-9][A-Za-z0-9_.-]*):\s*\Z")

HEALTHCHECK_KEY = "    healthcheck:"

# Services whose image carries its own `HEALTHCHECK` instruction, so Compose
# already waits for *healthy* without the Compose file restating it. Docker
# reports these as `Up (healthy)` exactly as a Compose-declared one does, which
# is why a stack can look uniformly healthy while most of it is not covered.
#
# Listed rather than detected: reading an image's metadata needs a Docker
# daemon and a pulled image, which this suite deliberately has neither of. The
# cost of that is a stale entry here if an image drops its healthcheck, which is
# what `test_every_named_service_still_exists` bounds.
IMAGE_PROVIDED_HEALTHCHECK: dict[tuple[str, str], str] = {
    ("monitoring", "cadvisor"): (
        "ghcr.io/google/cadvisor ships HEALTHCHECK CMD-SHELL /usr/bin/healthcheck.sh. "
        "Left to the image rather than restated here: a Compose-level healthcheck "
        "replaces the image's outright, so restating it would swap a probe cAdvisor "
        "maintains for one this repository would have to."
    ),
}

# Services with no health signal at all. An entry here is a decision to rely on
# the unit template's ExecStartPost instead, which reads the restart state
# directly and so needs nothing of the image -- but only sees a container that is
# looping at the instant it runs. Keep this list short.
HEALTHCHECK_EXEMPT: dict[tuple[str, str], str] = {
    ("edge", "crowdsec"): (
        "docker.io/crowdsecurity/crowdsec carries no HEALTHCHECK, so a probe would "
        "have to be written here -- against a live production-facing host, where a "
        "wrong one fails every future deploy of branchleft.co.uk's edge. CrowdSec "
        "also loads hub collections at start, so the settling time a probe would "
        "have to tolerate is set by network conditions rather than by the image. "
        "The edge stack's rollback signal does not depend on this: `caddy` is the "
        "only service there resolving ${IMAGE}, so it is the only one a deploy can "
        "change, and it has a healthcheck."
    ),
}


EXEC_START_POST = re.compile(r"\AExecStartPost=/bin/sh -c '(?P<body>.*)'\Z")


def crash_loop_assertion_body() -> str:
    """The shell the unit's ExecStartPost actually runs.

    Read out of the committed unit rather than restated in the test, so the
    behaviour asserted below is the behaviour systemd would get.
    """
    unit = HETZNER / "provision" / "branchleft-compose@.service"
    bodies = [
        match.group("body")
        for match in (EXEC_START_POST.match(line) for line in service_lines(unit))
        if match
    ]
    if len(bodies) != 1:
        raise AssertionError(f"expected exactly one `sh -c` ExecStartPost, found {len(bodies)}")
    return bodies[0]


def run_assertion_against(stub: str) -> subprocess.CompletedProcess[str]:
    """Run that shell with `docker` replaced by a stub of known behaviour.

    The point is the exit status the assertion reports for a given `docker
    compose ps`, which is what systemd reads and what branchleft-deploy's
    rollback keys on. A stub is the only way to reach the failure branches --
    a real daemon cannot be made to reject a flag on demand.
    """
    with tempfile.TemporaryDirectory() as directory:
        fake = os.path.join(directory, "docker")
        with open(fake, "w", encoding="utf-8") as handle:
            handle.write(stub)
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
        return subprocess.run(
            ["/bin/sh", "-c", crash_loop_assertion_body().replace("/usr/bin/docker", fake)],
            capture_output=True,
            text=True,
            check=False,
        )


def services_with_healthcheck(compose: pathlib.Path) -> dict[str, bool]:
    """Every service in `services:`, mapped to whether it declares a healthcheck.

    Regex rather than a YAML parse to keep this module stdlib-only, matching how
    the image-pin half above reads the same files. A parser this shallow could
    silently find nothing and pass every assertion, so
    `test_the_parser_still_reads_the_committed_stacks` asserts what it found.
    """
    services: dict[str, bool] = {}
    current: str | None = None
    in_services = False
    for raw in bd.strip_yaml_comments(compose.read_text(encoding="utf-8")).splitlines():
        if TOP_LEVEL_KEY.match(raw):
            in_services = raw.startswith("services:")
            current = None
            continue
        if not in_services:
            continue
        header = SERVICE_HEADER.match(raw)
        if header:
            current = header.group(1)
            services[current] = False
        elif current is not None and raw.startswith(HEALTHCHECK_KEY):
            services[current] = True
    return services


def secrets_directive(stack: str) -> re.Pattern[str]:
    """The stack's own secrets file, in any form systemd resolves to it.

    The leading dash is optional and the `%i` specifier expands to the instance
    name in an instance drop-in, so both are the same directive. Matching the
    literal path alone would fail a correct drop-in and tell its author, wrongly,
    that the stack would start with no secrets.
    """
    return re.compile(rf"\AEnvironmentFile=-?/etc/branchleft/(?:{re.escape(stack)}|%i)\.env\Z")


def stack_compose_files() -> dict[str, pathlib.Path]:
    """Every committed stack, keyed by the systemd instance name it runs as.

    The instance name is the directory holding `stack/`, because the template's
    `WorkingDirectory=/opt/branchleft/%i` is what the deploy rsyncs into.
    """
    return {
        path.parent.parent.name: path for path in sorted(HETZNER.glob("*/stack/compose.yml"))
    }


def drop_in_for(stack: str) -> pathlib.Path | None:
    """The instance drop-in for a stack, wherever in the tree it is committed.

    Searched rather than derived: the drop-ins are committed beside the story
    that introduced them, so `edge.override.conf` lives under `monitoring/`
    rather than under `edge/`.
    """
    matches = sorted(HETZNER.glob(f"*/systemd/{stack}.override.conf"))
    if not matches:
        return None
    if len(matches) > 1:
        raise AssertionError(f"more than one drop-in for {stack}: {matches}")
    return matches[0]


def service_lines(drop_in: pathlib.Path) -> list[str]:
    """Stripped, non-comment lines of the `[Service]` section, in file order.

    Order is preserved because systemd applies directives in it: a reset after a
    re-added file clears it again.
    """
    lines = []
    in_service = False
    for raw in drop_in.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_service = line == "[Service]"
            continue
        if in_service and line and not line.startswith("#"):
            lines.append(line)
    return lines


def classify_stacks() -> tuple[list[tuple[str, pathlib.Path]], list[tuple[str, pathlib.Path]]]:
    """`(inline_pinned, image_env)` stacks, each as `(stack, compose)` pairs."""
    inline_pinned, image_env = [], []
    for stack, compose in stack_compose_files().items():
        text = compose.read_text(encoding="utf-8")
        (image_env if bd.resolves_image_from_env(text) else inline_pinned).append((stack, compose))
    return inline_pinned, image_env


class ComposeUnitContractTests(unittest.TestCase):
    def test_the_repository_actually_has_stacks_of_both_kinds(self):
        """Globs that matched nothing would pass every assertion below."""
        inline_pinned, image_env = classify_stacks()
        self.assertIn("monitoring", [stack for stack, _ in inline_pinned])
        self.assertIn("edge", [stack for stack, _ in image_env])

    def test_no_stack_reaches_for_image_in_a_form_that_survives_an_empty_pin(self):
        """`${IMAGE:-default}` and `$IMAGE` classify as inline-pinned, so the
        assertions below would demand a reset -- which drops the pin file while
        the fallback quietly resolves to a hardcoded reference."""
        for stack, compose in stack_compose_files().items():
            with self.subTest(stack=stack):
                self.assertFalse(
                    bd.has_fail_open_image_reference(compose.read_text(encoding="utf-8")),
                    f"{compose} uses ${{IMAGE:-default}} or $IMAGE; use ${{IMAGE}} or "
                    "${IMAGE:?message}, which fail closed on an empty pin",
                )

    def test_an_inline_pinned_stack_resets_the_mandatory_image_pin(self):
        inline_pinned, _ = classify_stacks()
        for stack, _compose in inline_pinned:
            with self.subTest(stack=stack):
                drop_in = drop_in_for(stack)
                self.assertIsNotNone(
                    drop_in,
                    f"{stack} pins its images inline, so nothing will ever write "
                    f"/etc/branchleft/{stack}.image.env, and the unit cannot start "
                    f"without it. It needs a {stack}.override.conf resetting "
                    "EnvironmentFile= in its [Service] section.",
                )
                self.assertIn(
                    RESET_DIRECTIVE,
                    service_lines(drop_in),
                    f"{drop_in} must contain a bare `EnvironmentFile=` line under "
                    f"[Service]: {stack} pins its images inline, so branchleft-deploy "
                    f"will refuse to write /etc/branchleft/{stack}.image.env and the "
                    "unit will fail to start on a missing EnvironmentFile.",
                )

    def test_an_image_pinned_stack_keeps_the_mandatory_image_pin(self):
        _, image_env = classify_stacks()
        for stack, _compose in image_env:
            with self.subTest(stack=stack):
                drop_in = drop_in_for(stack)
                if drop_in is None:
                    continue
                self.assertNotIn(
                    RESET_DIRECTIVE,
                    service_lines(drop_in),
                    f"{drop_in} resets EnvironmentFile=, which drops the mandatory "
                    f"image pin for a stack that does resolve ${{IMAGE}}. {stack} "
                    "would then start on whatever tag its Compose file happens to "
                    "carry, which is the failure the no-leading-dash prevents.",
                )

    def test_a_reset_re_adds_the_secrets_file_of_a_stack_that_reads_one(self):
        """A reset drops `-/etc/branchleft/%i.env` along with the pin.

        Both are template assignments, so clearing the list clears both. Only
        demanded of a stack that actually interpolates a variable: requiring it
        of a stack with no secrets would force a second EnvironmentFile that
        nothing writes, which is this defect one level down.
        """
        inline_pinned, _ = classify_stacks()
        for stack, compose in inline_pinned:
            with self.subTest(stack=stack):
                variables = set(
                    COMPOSE_VARIABLE.findall(
                        bd.strip_yaml_comments(compose.read_text(encoding="utf-8"))
                    )
                )
                if not variables:
                    continue
                drop_in = drop_in_for(stack)
                self.assertIsNotNone(drop_in, f"{stack} has no drop-in to re-add its secrets file")
                lines = service_lines(drop_in)
                pattern = secrets_directive(stack)
                re_added = [index for index, line in enumerate(lines) if pattern.match(line)]
                self.assertTrue(
                    re_added,
                    f"{drop_in} resets EnvironmentFile= without re-adding "
                    f"/etc/branchleft/{stack}.env, so the stack would start with none "
                    f"of its secrets: {sorted(variables)}.",
                )
                resets = [index for index, line in enumerate(lines) if line == RESET_DIRECTIVE]
                self.assertTrue(resets, f"{drop_in} re-adds a secrets file but never resets")
                self.assertLess(
                    max(resets),
                    max(re_added),
                    f"{drop_in} has an `EnvironmentFile=` reset after the re-added "
                    "secrets file. systemd applies directives in file order, so the "
                    "later reset clears it again and the stack starts with no "
                    "EnvironmentFile at all.",
                )


class WaitSignalContractTests(unittest.TestCase):
    """`docker compose up --wait` is only a deploy signal where healthchecks are."""

    def test_the_parser_still_reads_the_committed_stacks(self):
        """A parser that found nothing would pass every assertion below."""
        found = {
            (stack, service)
            for stack, compose in stack_compose_files().items()
            for service in services_with_healthcheck(compose)
        }
        for expected in [
            ("monitoring", "prometheus"),
            ("monitoring", "alertmanager"),
            ("monitoring", "cadvisor"),
            ("edge", "caddy"),
            ("edge", "crowdsec"),
        ]:
            self.assertIn(expected, found)

    def test_every_service_declares_a_healthcheck_or_is_a_named_exemption(self):
        for stack, compose in stack_compose_files().items():
            for service, has_healthcheck in services_with_healthcheck(compose).items():
                with self.subTest(stack=stack, service=service):
                    if (stack, service) in IMAGE_PROVIDED_HEALTHCHECK:
                        continue
                    if (stack, service) in HEALTHCHECK_EXEMPT:
                        continue
                    self.assertTrue(
                        has_healthcheck,
                        f"{compose}: `{service}` declares no healthcheck, so "
                        "`docker compose up --wait` waits only for it to be running. "
                        "A container that starts and dies is transiently running, so "
                        "the unit start succeeds in front of a crash loop and "
                        "branchleft-deploy never rolls the image back. Give it a "
                        "healthcheck, or name it in IMAGE_PROVIDED_HEALTHCHECK or "
                        "HEALTHCHECK_EXEMPT with the reason.",
                    )

    def test_every_named_service_still_exists(self):
        """A stale entry silently widens the rule for whatever is named next."""
        real = {
            (stack, service)
            for stack, compose in stack_compose_files().items()
            for service in services_with_healthcheck(compose)
        }
        for table, name in (
            (IMAGE_PROVIDED_HEALTHCHECK, "IMAGE_PROVIDED_HEALTHCHECK"),
            (HEALTHCHECK_EXEMPT, "HEALTHCHECK_EXEMPT"),
        ):
            for entry in table:
                with self.subTest(table=name, entry=entry):
                    self.assertIn(
                        entry,
                        real,
                        f"{name} names {entry}, which no committed stack defines. "
                        "Remove it rather than leaving it to match a future service "
                        "of the same name.",
                    )

    def test_nothing_is_excused_without_a_reason(self):
        for table in (IMAGE_PROVIDED_HEALTHCHECK, HEALTHCHECK_EXEMPT):
            for entry, reason in table.items():
                with self.subTest(entry=entry):
                    self.assertTrue(reason.strip(), f"{entry} is excused with no reason")

    def test_a_service_is_not_named_in_both_tables(self):
        """The two are different claims: one is covered, the other is knowingly not."""
        overlap = set(IMAGE_PROVIDED_HEALTHCHECK) & set(HEALTHCHECK_EXEMPT)
        self.assertFalse(overlap, f"named in both tables: {sorted(overlap)}")


class UnitTemplateAssumptionTests(unittest.TestCase):
    """The tests above are only meaningful while the template still reads this way.

    Matched as whole `[Service]` lines, not as substrings of the file: a
    commented-out or relocated directive would satisfy a substring check while
    systemd applied nothing, leaving the contract asserted and unenforced.
    """

    def setUp(self):
        self.lines = service_lines(HETZNER / "provision" / "branchleft-compose@.service")

    def test_the_image_pin_is_still_mandatory(self):
        self.assertIn("EnvironmentFile=/etc/branchleft/%i.image.env", self.lines)

    def test_the_secrets_file_is_still_optional(self):
        self.assertIn("EnvironmentFile=-/etc/branchleft/%i.env", self.lines)

    def test_the_start_still_waits(self):
        """Without `--wait` the healthchecks above are diagnostic and nothing more."""
        self.assertIn(
            "ExecStart=/usr/bin/docker compose up -d --remove-orphans --wait",
            self.lines,
        )

    def test_a_crash_looping_container_still_fails_the_start(self):
        """The backstop for every service HEALTHCHECK_EXEMPT covers."""
        assertions = [line for line in self.lines if line.startswith("ExecStartPost=")]
        self.assertTrue(
            assertions,
            "the unit has no ExecStartPost asserting the post-start restart state, so "
            "a service without a healthcheck can crash-loop behind a successful "
            "`systemctl start`. Every entry in HEALTHCHECK_EXEMPT relies on it.",
        )
        self.assertTrue(
            any("--status restarting" in line for line in assertions),
            f"no ExecStartPost reads the restart state: {assertions}",
        )


class CrashLoopAssertionBehaviourTests(unittest.TestCase):
    """What the ExecStartPost reports back to systemd, run rather than read.

    The text assertions in UnitTemplateAssumptionTests only prove the directive
    is present. Whether it is *sound* is a question about exit statuses, and a
    guard that cannot fail is worth nothing -- which is the whole subject of
    this file.
    """

    NOTHING_RESTARTING = "#!/bin/sh\nexit 0\n"
    ONE_RESTARTING = '#!/bin/sh\necho monitoring-prometheus-1\nexit 0\n'
    # What an older Compose does with a flag it does not have: nothing on
    # stdout, a diagnostic on stderr, non-zero.
    QUERY_FAILS = '#!/bin/sh\necho "unknown flag: --status" >&2\nexit 125\n'

    def test_a_settled_stack_passes(self):
        result = run_assertion_against(self.NOTHING_RESTARTING)
        self.assertEqual(
            result.returncode, 0, f"a settled stack must start: {result.stderr}"
        )

    def test_a_crash_looping_container_fails_the_start(self):
        result = run_assertion_against(self.ONE_RESTARTING)
        self.assertNotEqual(
            result.returncode, 0, "a restarting container must fail the unit start"
        )
        self.assertIn(
            "monitoring-prometheus-1",
            result.stdout,
            "the offending container must be named in the journal",
        )

    def test_a_query_that_fails_fails_the_start(self):
        """The property this guard exists to have: it never passes by not looking.

        `docker compose ps` writes nothing to stdout when it fails, so a
        pipeline into `grep` reads a broken query as "nothing is restarting"
        and the unit starts clean over an unknown stack. That is the same shape
        as the `--wait` defect this whole file guards.
        """
        result = run_assertion_against(self.QUERY_FAILS)
        self.assertNotEqual(
            result.returncode,
            0,
            "a `docker compose ps` that failed outright was read as `nothing is "
            "restarting` and the unit start succeeded. A query that could not be "
            "answered must fail the unit, never pass it.",
        )

    def test_the_query_is_validated_with_the_flag_it_depends_on(self):
        """A cheaper pre-flight would miss an unsupported `--status`.

        The host's Compose version is not pinned (20-install-docker.sh installs
        docker-compose-plugin unpinned, deliberately), so `--status` support is
        not something this repository controls. Only a probe carrying the flag
        discovers its absence, which is why the same query runs twice.
        """
        body = crash_loop_assertion_body()
        self.assertEqual(
            body.count("--status restarting"),
            2,
            "the pre-flight query must be identical to the one whose output is "
            f"read, flag included: {body}",
        )


if __name__ == "__main__":
    unittest.main()
