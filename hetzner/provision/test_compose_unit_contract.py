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


if __name__ == "__main__":
    unittest.main()
