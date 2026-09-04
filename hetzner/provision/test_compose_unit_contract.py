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

The only way past the assertion below is `IMAGE_PROVIDED_HEALTHCHECK`, which
claims the image carries a probe rather than that none is needed. Excusing a
service outright would mean writing a second register and the tests that
police it, which is a visible decision rather than one more key in a dict
somebody already trusts.

This module's assertion only reaches a stack whose Compose file is committed
in this repository, at test time. `branchleft_deploy.py`'s `deploy()` reads
the same `healthcheck_states()` a second time, at deploy time, for whatever
stack is about to be restarted -- committed here or not, including a stack
this module has never heard of. Its own exemption table,
`KNOWN_UNHEALTHCHECKED_SERVICES`, is what backs a gap this module finds; it
lives beside `deploy()` rather than here because a gap this module cannot see
at all still has to be decided by something that can.

The third contract is the reach of the first two, and it is the one a glob
cannot state. `branchleft-compose@.service` is installed by
30-install-deploy-tooling.sh, which run-all.sh runs on every host role, and
`branchleft-deploy` restarts `branchleft-compose@<stack>` for any stack name.
The template therefore starts instances whose Compose file is committed in a
different repository, and nothing here reads those -- so for them "no assertion
failed" means no file was read at all, which is the opposite of what it means
for a stack this repository commits. `CONTRACT_COVERS` and
`CONTRACT_DOES_NOT_REACH` name both sides, and the scan below refuses to let
this repository write down a stack that is in neither.

Everything here reads the `[Service]` section only, and matches whole stripped
lines. systemd ignores assignments before a section header, so a directive
found anywhere in the file is not a directive systemd applies.
"""

import os
import pathlib
import re
import unittest

import branchleft_deploy as bd
from branchleft_deploy import (
    ABSENT,
    DECLARED,
    DISABLED,
    IMAGE_PROVIDED_HEALTHCHECK,
    ComposeParseError,
    healthcheck_states,
)

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

# The stacks every assertion above is about: exactly the ones whose Compose file
# this repository commits, which is what `stack_compose_files()` globs and what
# `EXPECTED_SERVICES` pins. Derived from that table rather than restated, so
# there is one place a stack is added and no second list to forget.
CONTRACT_COVERS = frozenset(EXPECTED_SERVICES)

# The instances the same template starts whose Compose file lives in another
# repository, mapped to where that file is. Nothing here reads any of them: a
# service in one that declares no health signal reaches a running host with
# `--wait` reporting a clean start, and the rollback never fires. Written down
# because the alternative is a glob that reads as full coverage of a set it
# defines silently -- a reader of the unit template sees `%i` and cannot tell
# which instances have been checked and which have not.
#
# This list is a floor, not a census, and the difference is load-bearing. A
# stack introduced entirely from another repository -- a tenant slug is the
# ordinary case -- is named in no file here, so nothing in this module can
# discover it. What the scan below does guarantee is that a stack this
# repository *does* write down cannot stay unclassified.
CONTRACT_DOES_NOT_REACH: dict[str, str] = {
    "website": (
        "branchLeft/website commits deploy/compose.yml and deploys it through "
        "the unscoped wrapper from its own CI. That repository is the only "
        "thing that reads the file, and it runs no equivalent of this module."
    ),
    "db": (
        "branchLeft/ghost-platform commits db/stack/compose.yml for the "
        "database host. Same shape as website: committed in that repository, "
        "deployed through the wrapper, unread here."
    ),
    "blog": (
        "One instance per tenant, rendered by branchLeft/ghost-platform's "
        "infra/tenant/compose.ts and never committed as a Compose file at all, "
        "so there is no file for any static check here to read. `blog` is the "
        "only slug this repository names; the set is open, and a slug granted "
        "a deploy slot on a host appears in no file here."
    ),
}

# The stack-name rule the deploy wrapper actually applies, reused rather than
# restated: a wrapper widened to accept more names than this scan looks for
# would leave the wider names invisible to it, which is the drift this whole
# module exists to refuse.
STACK_NAME_FRAGMENT = bd.STACK_NAME.pattern.removeprefix(r"\A").removesuffix(r"\Z")

# Every written shape that names one instance of the template. Placeholders --
# `%i`, `<stack>`, `${stack}`, and the template's own `@.service` -- are
# excluded by the character class rather than by a stop list, because none of
# them begins with a lowercase letter.
STACK_MENTIONS = (
    re.compile(rf"branchleft-compose@({STACK_NAME_FRAGMENT})"),
    re.compile(rf"/opt/branchleft/({STACK_NAME_FRAGMENT})"),
    # The `.env` suffix is required so `/etc/branchleft/deploy-slots`, which is
    # the slot register's directory and not a stack, is not read as one.
    re.compile(rf"/etc/branchleft/({STACK_NAME_FRAGMENT})(?:\.image)?\.env"),
    re.compile(rf"branchleft-slot:({STACK_NAME_FRAGMENT})"),
)

REPOSITORY = HETZNER.parent

# Every suffix the tree currently holds bar the excused ones below, so the scan
# reads all of it. An allow-list that happened to omit a suffix would make a
# whole file type invisible while every assertion below still passed; the census
# test pairs this with `UNSCANNED_SUFFIXES` so a suffix in neither is a failure
# rather than a silent gap.
#
# `.local` is the shape that makes that census worth its cost: the suffix names
# an overlay convention rather than a file format, so `config.yaml.local` is
# hand-written YAML that the `.yaml` entry here does not match.
SCANNED_SUFFIXES = frozenset(
    {
        "",
        ".authoring",
        ".conf",
        ".enforcing",
        ".json",
        ".local",
        ".md",
        ".mode",
        ".py",
        ".service",
        ".sh",
        ".timer",
        ".tmpl",
        ".ts",
        ".yaml",
        ".yml",
    }
)

# Suffixes deliberately not read, with why. An entry here is the only way a file
# type leaves the scan, and it has to be a claim about the file holding no text
# this repository authored -- not a claim that it happens to name no stack.
UNSCANNED_SUFFIXES: dict[str, str] = {
    ".pyc": (
        "compiled bytecode. The source it was compiled from is scanned, and a "
        "name reachable only through a stale .pyc is not one anybody wrote down."
    ),
}

# Pruned during the walk, not filtered after it: `node_modules` alone holds more
# files than the rest of the tree by two orders of magnitude. Membership is
# pinned by a test of its own -- every name here is a directory whose contents
# this repository does not author, and adding one that it does would remove that
# directory from every assertion below in a one-word edit.
UNSCANNED_DIRECTORIES: dict[str, str] = {
    ".git": "git's own object store",
    ".worktrees": "sibling checkouts of this same repository",
    "graphify-out": "generated by CI, never hand-edited",
    "node_modules": "installed dependencies",
}


def scanned_files() -> list[pathlib.Path]:
    """The files the stack-name scan reads.

    Test modules are skipped. Their fixtures invent stack names for hosts that
    do not exist, and a fixture is not an estate stack -- including them would
    make every new test case a classification decision. It also keeps the two
    tables above out of their own scan, so the register cannot satisfy the scan
    by describing itself.
    """
    return sorted(
        path
        for path in walked_files()
        if not path.name.startswith("test_") and path.suffix in SCANNED_SUFFIXES
    )


def walked_files() -> list[pathlib.Path]:
    """Every file under the tree the scan is allowed to see, before filtering."""
    paths = []
    for directory, subdirectories, filenames in os.walk(REPOSITORY):
        subdirectories[:] = [name for name in subdirectories if name not in UNSCANNED_DIRECTORIES]
        paths.extend(pathlib.Path(directory, filename) for filename in filenames)
    return paths


# One row of the reach table: the instance it names, and whether the row claims
# this module reads that stack's Compose file. Read from the cells rather than
# searched for as text, because a `yes` found anywhere in the row would also
# match one inside the prose of a different column.
REACH_ROW_INSTANCE = re.compile(rf"`branchleft-compose@({STACK_NAME_FRAGMENT})`")


def documented_reach(readme: pathlib.Path) -> dict[str, bool]:
    """The reach table as a mapping of instance name to "this module reads it".

    Raises rather than skips, in both directions: a row naming two instances and
    a verdict cell holding anything but yes/no are each a shape this cannot
    classify, and returning a partial mapping would leave the rows it dropped
    unasserted.
    """
    reach: dict[str, bool] = {}
    for line in readme.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        instances = REACH_ROW_INSTANCE.findall(cells[0])
        if not instances:
            continue
        if len(instances) != 1:
            raise AssertionError(
                f"reach table row names {len(instances)} instances: {line!r}. One row "
                "per instance, or the verdict column says nothing about which."
            )
        verdict = cells[-1].lower()
        if verdict not in ("yes", "no"):
            raise AssertionError(
                f"reach table row for {instances[0]} has verdict {cells[-1]!r}, which "
                "is neither yes nor no."
            )
        reach[instances[0]] = verdict == "yes"
    return reach


def stacks_named_in_this_repository() -> dict[str, set[str]]:
    """Stack instance names this repository writes down, each with where.

    Carries the files rather than returning bare names so a failure can say
    where the unclassified name came from; a name with nowhere to look is a
    failure whose author has to reproduce the scan by hand before acting on it.

    Drop-in filenames are a source in their own right: `<stack>.override.conf`
    names an instance whether or not any prose mentions it, and a drop-in is
    exactly what a stack from another repository needs if it pins its images
    inline.
    """
    found: dict[str, set[str]] = {}
    for path in scanned_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in STACK_MENTIONS:
            for match in pattern.finditer(text):
                found.setdefault(match.group(1), set()).add(str(path.relative_to(REPOSITORY)))
    for drop_in in sorted(HETZNER.glob("*/systemd/*.override.conf")):
        stack = drop_in.name.removesuffix(".override.conf")
        found.setdefault(stack, set()).add(str(drop_in.relative_to(REPOSITORY)))
    return found


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
                        "There is no third answer, and adding one is a change to this "
                        "module rather than to a table it already reads.",
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
        for table, name in ((IMAGE_PROVIDED_HEALTHCHECK, "IMAGE_PROVIDED_HEALTHCHECK"),):
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
        for table in (
            IMAGE_PROVIDED_HEALTHCHECK,
            UNSCANNED_SUFFIXES,
            UNSCANNED_DIRECTORIES,
        ):
            for entry, reason in table.items():
                with self.subTest(entry=entry):
                    self.assertTrue(reason.strip(), f"{entry} is excused with no reason")


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


class StackNameScanTests(unittest.TestCase):
    """The scan's failure direction, against shapes this repository does not hold.

    Every assertion in `ContractReachTests` that reads the scan is a statement
    about what it found, so a pattern that quietly stopped matching would leave
    those assertions true and empty -- the same vacuous pass the Compose parser
    above raises rather than returns.
    """

    def names(self, text: str) -> set[str]:
        return {
            match.group(1) for pattern in STACK_MENTIONS for match in pattern.finditer(text)
        }

    def test_the_scan_applies_the_deploy_wrappers_own_stack_name_rule(self):
        """The fragment is sliced off `bd.STACK_NAME`, so it has to still fit it."""
        self.assertEqual(rf"\A{STACK_NAME_FRAGMENT}\Z", bd.STACK_NAME.pattern)

    def test_each_shape_that_names_an_instance_is_read(self):
        for text, expected in (
            ("systemctl restart branchleft-compose@cache", "cache"),
            ("branchleft-compose@cache.service.d/override.conf", "cache"),
            ("WorkingDirectory=/opt/branchleft/cache", "cache"),
            ("EnvironmentFile=/etc/branchleft/cache.env", "cache"),
            ("EnvironmentFile=/etc/branchleft/cache.image.env", "cache"),
            ("ssh-ed25519 AAAA branchleft-slot:cache", "cache"),
        ):
            with self.subTest(text=text):
                self.assertEqual(self.names(text), {expected})

    def test_a_placeholder_is_not_read_as_an_instance(self):
        """The spellings the template, the wrapper and the prose all use."""
        for text in (
            "branchleft-compose@.service",
            "branchleft-compose@%i",
            "branchleft-compose@<stack>",
            "branchleft-compose@${stack}",
            "branchleft-compose@{stack}",
            "WorkingDirectory=/opt/branchleft/%i",
            "EnvironmentFile=-/etc/branchleft/%i.env",
            "/etc/branchleft/<stack>.env",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.names(text), set())

    def test_the_slot_register_directory_is_not_read_as_a_stack(self):
        """`deploy-slots` is a well-formed stack name and is not a stack."""
        self.assertEqual(self.names("/etc/branchleft/deploy-slots/blog.pub"), set())

    def test_a_name_the_deploy_wrapper_would_refuse_is_not_read_as_one(self):
        """Pinned against today's rule, and meant to fail if that rule widens.

        The fragment tracks `bd.STACK_NAME` automatically, so a widened rule
        would widen the scan with it and fail here anyway. That is the wanted
        direction: accepting a new character class in unit names is a decision
        about what a stack may be called, and this module reads those names out
        of prose, where a wider class matches more of it.
        """
        self.assertEqual(self.names("branchleft-compose@Cache"), set())


class ContractReachTests(unittest.TestCase):
    """Which instances of the template the contract above reads, and which not.

    The assertions above all say something about a file that was read. These
    say which files there are to read, because a glob reports nothing at all
    about the stacks it does not match and a reader cannot see the difference
    between "checked and correct" and "never looked at".
    """

    def test_the_two_sets_are_disjoint(self):
        """A stack is read here or it is not; there is no third state to hold."""
        overlap = CONTRACT_COVERS & set(CONTRACT_DOES_NOT_REACH)
        self.assertFalse(overlap, f"registered on both sides of the boundary: {sorted(overlap)}")

    def test_a_stack_the_contract_does_not_reach_has_no_compose_file_here(self):
        """The register is a claim about the tree, so the tree is what settles it."""
        committed = set(stack_compose_files())
        for stack in sorted(CONTRACT_DOES_NOT_REACH):
            with self.subTest(stack=stack):
                self.assertNotIn(
                    stack,
                    committed,
                    f"{stack} is registered as owned by another repository, but this "
                    "one now commits a Compose file for it. Move it into "
                    "EXPECTED_SERVICES, deciding each service's health signal as you "
                    "do -- it is covered now, and the register says it is not.",
                )

    def test_every_registered_stack_is_a_name_the_deploy_wrapper_accepts(self):
        """A name the wrapper refuses is not an instance the template ever starts."""
        for stack in sorted(CONTRACT_COVERS | set(CONTRACT_DOES_NOT_REACH)):
            with self.subTest(stack=stack):
                self.assertRegex(stack, bd.STACK_NAME)

    def test_every_out_of_reach_stack_names_the_repository_that_owns_it(self):
        """An entry saying only "somewhere else" records the state being fixed.

        The owning repository is the only actionable thing in such an entry: it
        is where a reader goes to find out whether that stack declares a health
        signal, which is the question this module cannot answer for it.
        """
        for stack, owner in CONTRACT_DOES_NOT_REACH.items():
            with self.subTest(stack=stack):
                self.assertIn(
                    "branchLeft/",
                    owner,
                    f"{stack} is registered as out of reach without naming the "
                    "repository that owns its Compose file.",
                )

    def test_no_stack_this_repository_names_is_left_unclassified(self):
        classified = CONTRACT_COVERS | set(CONTRACT_DOES_NOT_REACH)
        for stack, where in sorted(stacks_named_in_this_repository().items()):
            with self.subTest(stack=stack):
                self.assertIn(
                    stack,
                    classified,
                    f"{sorted(where)} name the instance branchleft-compose@{stack}, "
                    "which is in neither register. Add it to EXPECTED_SERVICES if its "
                    "Compose file is committed here -- deciding each service's health "
                    "signal as you do -- or to CONTRACT_DOES_NOT_REACH naming the "
                    "repository that owns it, which records that nothing here sees "
                    "whether it declares one.",
                )

    def test_the_scan_still_sees_both_sides_of_the_boundary(self):
        """Otherwise the assertion above passes over an empty scan.

        The covered half is structural: this repository commits those stacks,
        so their names are in its own configuration whatever the prose says.

        The other half is not, and the difference is worth stating rather than
        implying. `website`, `db` and `blog` are named in `hetzner/README.md`
        and nowhere else here, and the README assertion below is what puts two
        of them there -- so this half detects the registers being emptied and
        does not prove the scan can see a mention from outside. Nothing in this
        repository can prove that, which is the same limit as the register being
        a floor rather than a census.
        """
        found = set(stacks_named_in_this_repository())
        self.assertLessEqual(
            CONTRACT_COVERS,
            found,
            "the scan no longer finds the stacks this repository commits, so it "
            "would read an unregistered one as absent rather than as new.",
        )
        self.assertTrue(
            found & set(CONTRACT_DOES_NOT_REACH),
            "the scan finds no stack from outside this repository, so it can no "
            "longer tell the two sides of the boundary apart.",
        )

    def test_the_unit_template_states_its_own_reach(self):
        """A reader of the unit file sees `%i` and cannot tell what checked it."""
        template = (HETZNER / "provision" / "branchleft-compose@.service").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "test_compose_unit_contract.py",
            template,
            "the unit template no longer names the module holding its contract, so "
            "the trail from the file that starts the stacks to the file that checks "
            "them is broken.",
        )
        for stack in sorted(CONTRACT_COVERS):
            with self.subTest(stack=stack):
                self.assertRegex(
                    template,
                    rf"\b{re.escape(stack)}\b",
                    f"the unit template does not name {stack}, so its comment "
                    "understates which instances the contract has actually read.",
                )

    def test_every_compose_file_committed_here_is_at_the_globbed_path(self):
        """The register claims no Compose file here, and the glob is one layout.

        `stack_compose_files()` matches `*/stack/compose.yml`. A Compose file a
        directory above that is committed here, is read by no assertion in this
        module, and is still consistent with a register entry saying another
        repository owns the stack -- which is the claim the register makes.
        """
        globbed = set(stack_compose_files().values())
        for path in sorted(HETZNER.rglob("compose.y*ml")):
            # Relative to the repository, never the absolute path: a checkout
            # under a directory named here -- `.worktrees` is the ordinary case
            # -- would otherwise match every path and skip the whole loop, which
            # passes silently and only in the checkout it was written in.
            relative = path.relative_to(REPOSITORY)
            if any(part in UNSCANNED_DIRECTORIES for part in relative.parts):
                continue
            with self.subTest(path=str(relative)):
                self.assertIn(
                    path,
                    globbed,
                    f"{relative} is a Compose file this repository "
                    "commits outside `<stack>/stack/compose.yml`, so nothing in this "
                    "module reads it and no register accounts for it. Move it onto "
                    "that path, or widen the glob and EXPECTED_SERVICES together.",
                )

    def test_the_deploy_documentation_agrees_with_the_registers(self):
        """One place a reader finds the whole set, and it has to be the true one.

        The table's verdict column is the only part of it carrying a claim.
        Asserting only that each instance is *mentioned* leaves a row free to
        say a stack is checked when nothing reads it -- the original defect,
        restated inside the document written to remove it.
        """
        documented = documented_reach(HETZNER / "README.md")
        self.assertEqual(
            set(documented),
            CONTRACT_COVERS | set(CONTRACT_DOES_NOT_REACH),
            "hetzner/README.md's reach table and the registers hold different sets. "
            "The table is what a reader finds, so it is the one that goes stale "
            "unmentioned.",
        )
        for stack, documented_as_read in sorted(documented.items()):
            with self.subTest(stack=stack):
                self.assertEqual(
                    documented_as_read,
                    stack in CONTRACT_COVERS,
                    f"hetzner/README.md says branchleft-compose@{stack} is "
                    f"{'read' if documented_as_read else 'not read'} by this module, "
                    f"and the registers say it is "
                    f"{'read' if stack in CONTRACT_COVERS else 'not read'}.",
                )

    def test_the_scan_surface_accounts_for_every_file_type_in_the_tree(self):
        """A suffix in neither set is a file type the scan silently cannot see.

        Both sets are hand-written, so without this the cheapest way to make a
        newly-failing scan pass is to drop the suffix that found the stack, and
        the cheapest way to introduce an unseen one is to write it in a file type
        nobody added.
        """
        for suffix in sorted({path.suffix for path in walked_files()}):
            with self.subTest(suffix=suffix or "(no extension)"):
                self.assertIn(
                    suffix,
                    SCANNED_SUFFIXES | set(UNSCANNED_SUFFIXES),
                    f"{suffix or 'files with no extension'} appear in this repository "
                    "and the scan neither reads them nor excuses them. Add the suffix "
                    "to SCANNED_SUFFIXES, or to UNSCANNED_SUFFIXES with why that file "
                    "type holds no text anybody authored.",
                )

    def test_the_walk_still_descends_into_everything_authored_here(self):
        """Membership is pinned: a pruned directory is invisible to every test above.

        Each name is a directory whose contents this repository does not write.
        Adding one that it does -- `mail`, `scripts`, a stack directory -- is a
        one-word edit that removes it from the scan with nothing else failing,
        which is the shape of drift this module exists to refuse.
        """
        self.assertEqual(
            set(UNSCANNED_DIRECTORIES),
            {".git", ".worktrees", "graphify-out", "node_modules"},
            "UNSCANNED_DIRECTORIES is not a list to add to. A directory named here is "
            "read by nothing in this module, so pruning one that holds authored "
            "configuration needs its own decision rather than a dict key.",
        )


if __name__ == "__main__":
    unittest.main()
