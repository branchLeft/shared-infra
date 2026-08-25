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

Nothing else backs that up. There is no post-start assertion in the unit to
fall back on, so a service with no health signal has none at all -- which is
why there is no general exemption table here. `NO_DEPLOY_TIME_COVERAGE` is not
one: it holds a single pinned entry recording a service knowingly left
uncovered, and a second entry fails this suite.

Everything here reads the `[Service]` section only, and matches whole stripped
lines. systemd ignores assignments before a section header, so a directive
found anywhere in the file is not a directive systemd applies.
"""

import pathlib
import re
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
# under it. Quoted and space-before-colon spellings are matched because YAML
# accepts them and a `services:` this missed would end the section early,
# leaving the rest of the file unread.
TOP_LEVEL_KEY = re.compile(r"""\A(?P<quote>["']?)(?P<key>[A-Za-z0-9_.-]+)(?P=quote)\s*:""")

# A service name under `services:`, at Compose's two-space nesting. Matched at
# a fixed indent rather than by name so a service added at the wrong depth --
# which Compose would not read as a service at all -- is not silently counted
# as one that has a healthcheck.
SERVICE_INDENT = 2
SERVICE_HEADER = re.compile(rf"\A {{{SERVICE_INDENT}}}([A-Za-z0-9][A-Za-z0-9_.-]*):\s*\Z")

# The healthcheck key of a service, with whatever follows it on the same line:
# `healthcheck: {disable: true}` is a declaration that switches the check off,
# and reads as one that turns it on unless the inline value is looked at.
HEALTHCHECK_INDENT = 4
HEALTHCHECK_HEADER = re.compile(rf"\A {{{HEALTHCHECK_INDENT}}}healthcheck:(?P<inline>.*)\Z")

# The two ways Compose switches a healthcheck off. Both leave the `healthcheck:`
# key in place, so a check for the key alone reads either as a declared probe --
# and for a service whose image supplies one, `disable: true` is what removes
# the only probe it has.
HEALTHCHECK_DISABLED = re.compile(r"\bdisable:\s*(?:true|yes|on)\b", re.IGNORECASE)
HEALTHCHECK_TEST_NONE = re.compile(
    r"""\btest:\s*(?:\[\s*)?["']?NONE["']?\s*\]?\s*(?=[,}]|\Z)"""
    r"""|\A\s*-\s*["']?NONE["']?\s*\Z"""
)

# The three states a service can be in, kept apart because "no healthcheck key"
# and "healthcheck key that turns the probe off" mean opposite things for a
# service whose image ships its own.
ABSENT, DECLARED, DISABLED = "absent", "declared", "disabled"

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

# The one service with no deploy-time coverage at all, and the only one this
# module will accept as having none. Not an exemption table: an entry here does
# not mean "covered another way", it means the crash loop this whole module
# exists to catch will pass `--wait` for that service and reach a running host.
#
# `crowdsec` holds the only permitted entry because a probe on it is unsafe
# until branchLeft/shared-infra#72 is fixed -- the image's entrypoint installs
# hub items unconditionally on every start, and the retry inside that failure
# branch is unguarded under `set -e`, so a failed install crash-loops the
# container and a probe would turn that into a failed edge deploy and an image
# rollback that repairs nothing. Detecting a down WAF is
# branchLeft/shared-infra#70's job, not the deploy signal's.
#
# `test_the_only_uncovered_service_is_still_crowdsec` pins the membership, so a
# second service cannot be added here without that decision being made
# explicitly and reviewed.
NO_DEPLOY_TIME_COVERAGE: dict[tuple[str, str], str] = {
    ("edge", "crowdsec"): (
        "A `cscli lapi status` probe was written and measured against the pinned "
        "digest and works, but installing it is gated on branchLeft/shared-infra#72: "
        "an unreachable CrowdSec hub crash-loops the container through an unguarded "
        "retry, so the probe would fail edge deploys for a cause unrelated to the "
        "image being deployed. Until then `crowdsec` has no deploy-time health "
        "signal, which is a recorded decision rather than an oversight."
    ),
}

# Every service the parser must find, per stack. An exact set rather than a
# sample: a parser that quietly skipped one would otherwise leave that service
# unasserted, which is the failure mode this whole module is about. Adding a
# service means adding it here, which is the point at which its health signal
# has to be decided.
EXPECTED_SERVICES: dict[str, set[str]] = {
    "edge": {"caddy", "crowdsec"},
    "monitoring": {
        "prometheus",
        "alertmanager",
        "grafana",
        "node-exporter",
        "blackbox-exporter",
        "cadvisor",
    },
}


class ComposeParseError(AssertionError):
    """A line under `services:` the parser cannot classify.

    Raised rather than skipped. The parser is a regex over indentation, so the
    forms it does not understand -- a YAML anchor on the service header, an
    inline mapping, a different nesting depth -- all look identical to "this
    service has no healthcheck key yet". Skipping them silently empties the
    result, and an empty result passes every assertion below.
    """


def healthcheck_states(compose_text: str) -> dict[str, str]:
    """Every service in `services:`, mapped to `ABSENT`, `DECLARED` or `DISABLED`.

    Regex rather than a YAML parse to keep this module stdlib-only, matching how
    the image-pin half above reads the same files. Takes text rather than a path
    so the shapes it must reject can be tested against fixtures.

    Shapes it cannot classify raise. The one gap it cannot raise on is a
    top-level key it fails to recognise at all, which would end the `services:`
    section early and leave the rest of the file unread -- `EXPECTED_SERVICES`
    is the backstop for that, because the services after it would go missing.
    """
    states: dict[str, str] = {}
    current: str | None = None
    in_services = False
    healthcheck_block_of: str | None = None
    for raw in bd.strip_yaml_comments(compose_text).splitlines():
        if not raw.strip():
            continue
        top_level = TOP_LEVEL_KEY.match(raw)
        if top_level:
            in_services = top_level.group("key") == "services"
            current = None
            healthcheck_block_of = None
            continue
        if not in_services:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= SERVICE_INDENT:
            header = SERVICE_HEADER.match(raw)
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
        if healthcheck_block_of is not None and indent <= HEALTHCHECK_INDENT:
            healthcheck_block_of = None
        header = HEALTHCHECK_HEADER.match(raw)
        if header:
            inline = header.group("inline")
            states[current] = (
                DISABLED
                if HEALTHCHECK_DISABLED.search(inline) or HEALTHCHECK_TEST_NONE.search(inline)
                else DECLARED
            )
            healthcheck_block_of = current
            continue
        if healthcheck_block_of is not None and (
            HEALTHCHECK_DISABLED.search(raw) or HEALTHCHECK_TEST_NONE.search(raw)
        ):
            states[healthcheck_block_of] = DISABLED
    return states


def stack_states() -> dict[str, dict[str, str]]:
    """`healthcheck_states` for every committed stack, keyed by stack."""
    return {
        stack: healthcheck_states(compose.read_text(encoding="utf-8"))
        for stack, compose in stack_compose_files().items()
    }


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


class ComposeHealthcheckParserTests(unittest.TestCase):
    """The parser's failure direction, against shapes the committed stacks lack.

    Every assertion in `WaitSignalContractTests` is a statement about what the
    parser found. A parser that finds nothing therefore asserts nothing while
    reporting success, so the shapes it cannot read have to raise rather than
    return an empty or partial mapping.
    """

    PLAIN = """\
name: fixture
services:
  probed:
    image: example
    healthcheck:
      test: ['CMD', 'true']
  bare:
    image: example
"""

    def probe(self, text: str) -> dict[str, str]:
        return healthcheck_states(text)

    def test_it_reads_a_plain_stack(self):
        self.assertEqual(self.probe(self.PLAIN), {"probed": DECLARED, "bare": ABSENT})

    def test_an_anchor_on_the_service_header_is_an_error(self):
        anchored = self.PLAIN.replace("  probed:", "  probed: &probed")
        with self.assertRaises(ComposeParseError):
            self.probe(anchored)

    def test_an_inline_mapping_service_is_an_error(self):
        inline = "name: fixture\nservices:\n  probed: {image: example}\n"
        with self.assertRaises(ComposeParseError):
            self.probe(inline)

    def test_a_service_nested_at_the_wrong_depth_is_an_error(self):
        nested = "name: fixture\nservices:\n    probed:\n      image: example\n"
        with self.assertRaises(ComposeParseError):
            self.probe(nested)

    def test_a_quoted_or_spaced_services_key_still_opens_the_section(self):
        """A `services:` the top-level matcher misses ends the section early.

        Nothing raises on that -- the services after it simply go missing -- so
        the two spellings YAML also accepts are matched rather than relied on
        never appearing.
        """
        for spelling in ('"services":', "services :"):
            with self.subTest(spelling=spelling):
                self.assertEqual(
                    self.probe(self.PLAIN.replace("services:", spelling, 1)),
                    {"probed": DECLARED, "bare": ABSENT},
                )

    def test_a_disabled_healthcheck_is_told_from_an_absent_one(self):
        """`disable: true` leaves the key in place; the two are not the same claim."""
        disabled = self.PLAIN.replace(
            "    healthcheck:\n      test: ['CMD', 'true']\n",
            "    healthcheck:\n      disable: true\n",
        )
        self.assertEqual(self.probe(disabled), {"probed": DISABLED, "bare": ABSENT})

    def test_an_inline_disabled_healthcheck_is_told_from_an_absent_one(self):
        inline = self.PLAIN.replace(
            "    healthcheck:\n      test: ['CMD', 'true']\n",
            "    healthcheck: {disable: true}\n",
        )
        self.assertEqual(self.probe(inline), {"probed": DISABLED, "bare": ABSENT})

    def test_test_none_is_the_other_way_to_switch_a_probe_off(self):
        """Docker's other disable idiom, in the spellings Compose accepts."""
        for spelling in (
            "    healthcheck:\n      test: ['NONE']\n",
            '    healthcheck:\n      test: ["NONE"]\n',
            "    healthcheck:\n      test: NONE\n",
            "    healthcheck:\n      test:\n        - NONE\n",
            "    healthcheck: {test: ['NONE']}\n",
        ):
            with self.subTest(spelling=spelling.strip()):
                text = self.PLAIN.replace(
                    "    healthcheck:\n      test: ['CMD', 'true']\n", spelling
                )
                self.assertEqual(
                    self.probe(text), {"probed": DISABLED, "bare": ABSENT}
                )

    def test_a_disable_outside_the_healthcheck_block_says_nothing_about_the_probe(self):
        """Scoped to the block, not to the service.

        `disable:` is an ordinary key elsewhere in Compose. A search across the
        whole service would read a label of that name as a switched-off probe
        and excuse a service that is in fact covered.
        """
        elsewhere = self.PLAIN.replace(
            "      test: ['CMD', 'true']\n",
            "      test: ['CMD', 'true']\n    labels:\n      disable: true\n",
        )
        self.assertEqual(self.probe(elsewhere), {"probed": DECLARED, "bare": ABSENT})


class WaitSignalContractTests(unittest.TestCase):
    """`docker compose up --wait` is only a deploy signal where healthchecks are."""

    def test_the_parser_still_reads_the_committed_stacks(self):
        """An exact set: a service the parser missed is a service nothing asserts."""
        found = {stack: set(services) for stack, services in stack_states().items()}
        self.assertEqual(
            found,
            EXPECTED_SERVICES,
            "the committed stacks and EXPECTED_SERVICES disagree. Add a new stack or "
            "service there, deciding its health signal as you do -- do not relax this "
            "assertion, it is what stops a parser miss from passing silently.",
        )

    def test_every_service_declares_a_healthcheck_or_carries_one_in_its_image(self):
        for stack, services in stack_states().items():
            for service, state in services.items():
                with self.subTest(stack=stack, service=service):
                    if (stack, service) in IMAGE_PROVIDED_HEALTHCHECK:
                        continue
                    if (stack, service) in NO_DEPLOY_TIME_COVERAGE:
                        continue
                    self.assertEqual(
                        state,
                        DECLARED,
                        f"{stack}: `{service}` has no working healthcheck ({state}), so "
                        "`docker compose up --wait` waits only for it to be running. "
                        "A container that starts and dies is transiently running, so "
                        "the unit start succeeds in front of a crash loop and "
                        "branchleft-deploy never rolls the image back. Nothing else "
                        "in the unit looks. Give it a healthcheck, or name it in "
                        "IMAGE_PROVIDED_HEALTHCHECK with the image's own instruction. "
                        "NO_DEPLOY_TIME_COVERAGE is not the answer here -- it holds one "
                        "permitted entry and adding a second fails this suite.",
                    )

    def test_an_image_provided_healthcheck_is_neither_restated_nor_switched_off(self):
        """Only `ABSENT` leaves the image's own probe in force.

        A Compose-level probe replaces the image's outright, and `disable: true`
        removes it — which for a service named here is removing the only health
        signal it has, while every assertion above reads it as covered.
        """
        states = stack_states()
        for stack, service in IMAGE_PROVIDED_HEALTHCHECK:
            with self.subTest(stack=stack, service=service):
                self.assertEqual(
                    states.get(stack, {}).get(service),
                    ABSENT,
                    f"{stack}: `{service}` is named in IMAGE_PROVIDED_HEALTHCHECK, so "
                    "its Compose file must carry no `healthcheck:` key at all. A "
                    "declared one replaces the image's; a disabled one removes it.",
                )

    def test_every_named_service_still_exists(self):
        """A stale entry silently widens the rule for whatever is named next."""
        real = {
            (stack, service)
            for stack, services in stack_states().items()
            for service in services
        }
        for table, name in (
            (IMAGE_PROVIDED_HEALTHCHECK, "IMAGE_PROVIDED_HEALTHCHECK"),
            (NO_DEPLOY_TIME_COVERAGE, "NO_DEPLOY_TIME_COVERAGE"),
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
        for table in (IMAGE_PROVIDED_HEALTHCHECK, NO_DEPLOY_TIME_COVERAGE):
            for entry, reason in table.items():
                with self.subTest(entry=entry):
                    self.assertTrue(reason.strip(), f"{entry} is excused with no reason")

    def test_a_service_is_not_named_in_both_tables(self):
        """They are opposite claims: covered by the image, versus not covered."""
        overlap = set(IMAGE_PROVIDED_HEALTHCHECK) & set(NO_DEPLOY_TIME_COVERAGE)
        self.assertFalse(overlap, f"named in both tables: {sorted(overlap)}")

    def test_the_only_uncovered_service_is_still_crowdsec(self):
        """Membership is pinned, so a second uncovered service cannot be slipped in.

        `IMAGE_PROVIDED_HEALTHCHECK` says "covered by the image instead".
        `NO_DEPLOY_TIME_COVERAGE` says "not covered at all", which is the state
        every other assertion here exists to prevent. One service is in it by an
        owner decision recorded against branchLeft/shared-infra#72; a second
        would be a silent widening of the only hole left.
        """
        self.assertEqual(
            set(NO_DEPLOY_TIME_COVERAGE),
            {("edge", "crowdsec")},
            "NO_DEPLOY_TIME_COVERAGE is not an exemption list to add to. Removing "
            "the entry means `crowdsec` now declares a healthcheck; adding one means "
            "a second service would ship with no crash-loop detection at all, which "
            "needs its own decision rather than a dict key.",
        )

    def test_a_service_with_no_deploy_time_coverage_declares_no_probe(self):
        """The two claims are contradictory, and the file is what settles it."""
        states = stack_states()
        for stack, service in NO_DEPLOY_TIME_COVERAGE:
            with self.subTest(stack=stack, service=service):
                self.assertEqual(
                    states.get(stack, {}).get(service),
                    ABSENT,
                    f"{stack}: `{service}` is named in NO_DEPLOY_TIME_COVERAGE but its "
                    "Compose file declares a healthcheck. If the probe is now safe to "
                    "run, remove the entry; the table records a service that has none.",
                )


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

    def test_the_wait_is_the_only_post_start_signal(self):
        """No `ExecStartPost` stands behind `--wait`, and adding one is a decision.

        A post-start `docker compose ps` is a weaker instrument than it looks:
        `--wait` returns the moment every container is `running`, so a sample
        taken after it lands in the window a crash loop spends *between* its
        restarts, and it cannot tell a service the deploy changed from one that
        was already in restart backoff. Docker's own health state machine
        answers both -- it marks a container with a healthcheck `unhealthy` on
        the transition into `restarting`, and `--wait` fails on that.
        """
        self.assertEqual(
            [line for line in self.lines if line.startswith("ExecStartPost=")],
            [],
            "the unit has an ExecStartPost. If a post-start assertion is being "
            "reintroduced, replace this test with one that states what it "
            "guarantees that `--wait` does not.",
        )


if __name__ == "__main__":
    unittest.main()
