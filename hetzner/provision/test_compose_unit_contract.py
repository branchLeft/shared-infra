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
"""

import pathlib
import unittest

import branchleft_deploy as bd

HETZNER = pathlib.Path(__file__).resolve().parent.parent

# A bare `EnvironmentFile=` clears every prior assignment (systemd.exec(5):
# "If the empty string is assigned to this option, the list of file to read is
# reset, all prior assignments have no effect"). Matched on the stripped line
# so an assignment with a value can never satisfy it.
RESET_DIRECTIVE = "EnvironmentFile="


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


def resets_environment_file(drop_in: pathlib.Path) -> bool:
    return any(
        line.strip() == RESET_DIRECTIVE for line in drop_in.read_text(encoding="utf-8").splitlines()
    )


class ComposeUnitContractTests(unittest.TestCase):
    def test_the_repository_actually_has_stacks_to_check(self):
        """A glob that matches nothing would pass every assertion below."""
        stacks = stack_compose_files()
        self.assertIn("edge", stacks)
        self.assertIn("monitoring", stacks)

    def test_an_inline_pinned_stack_resets_the_mandatory_image_pin(self):
        for stack, compose in stack_compose_files().items():
            with self.subTest(stack=stack):
                if bd.resolves_image_from_env(compose.read_text(encoding="utf-8")):
                    continue
                drop_in = drop_in_for(stack)
                self.assertIsNotNone(
                    drop_in,
                    f"{stack} pins its images inline, so nothing will ever write "
                    f"/etc/branchleft/{stack}.image.env, and the unit cannot start "
                    f"without it. It needs a {stack}.override.conf resetting "
                    "EnvironmentFile=.",
                )
                self.assertTrue(
                    resets_environment_file(drop_in),
                    f"{drop_in} must contain a bare `EnvironmentFile=` line: "
                    f"{stack} pins its images inline, so branchleft-deploy will "
                    f"refuse to write /etc/branchleft/{stack}.image.env and the "
                    "unit will fail to start on a missing EnvironmentFile.",
                )

    def test_an_image_pinned_stack_keeps_the_mandatory_image_pin(self):
        for stack, compose in stack_compose_files().items():
            with self.subTest(stack=stack):
                if not bd.resolves_image_from_env(compose.read_text(encoding="utf-8")):
                    continue
                drop_in = drop_in_for(stack)
                if drop_in is None:
                    continue
                self.assertFalse(
                    resets_environment_file(drop_in),
                    f"{drop_in} resets EnvironmentFile=, which drops the mandatory "
                    f"image pin for a stack that does resolve ${{IMAGE}}. {stack} "
                    "would then start on whatever tag its Compose file happens to "
                    "carry, which is the failure the no-leading-dash prevents.",
                )

    def test_the_reset_re_adds_the_stacks_own_secrets_file(self):
        """A reset drops `-/etc/branchleft/%i.env` along with the pin.

        Both are template assignments, so clearing the list clears both. A
        drop-in that resets and stops there starts a stack with none of its
        secrets, which for `monitoring` means Alertmanager rendering against
        empty placeholders.
        """
        for stack, compose in stack_compose_files().items():
            with self.subTest(stack=stack):
                if bd.resolves_image_from_env(compose.read_text(encoding="utf-8")):
                    continue
                drop_in = drop_in_for(stack)
                assert drop_in is not None  # asserted by the test above
                lines = [line.strip() for line in drop_in.read_text(encoding="utf-8").splitlines()]
                self.assertIn(
                    f"EnvironmentFile=/etc/branchleft/{stack}.env",
                    lines,
                    f"{drop_in} resets EnvironmentFile= without re-adding "
                    f"/etc/branchleft/{stack}.env, so the stack would start with "
                    "none of its secrets.",
                )
                self.assertLess(
                    lines.index(RESET_DIRECTIVE),
                    lines.index(f"EnvironmentFile=/etc/branchleft/{stack}.env"),
                    "the reset must come before the re-added file, or it clears it "
                    "again",
                )


class UnitTemplateAssumptionTests(unittest.TestCase):
    """The tests above are only meaningful while the template still reads this way."""

    def setUp(self):
        self.template = (HETZNER / "provision" / "branchleft-compose@.service").read_text(
            encoding="utf-8"
        )

    def test_the_image_pin_is_still_mandatory(self):
        self.assertIn("EnvironmentFile=/etc/branchleft/%i.image.env", self.template)
        self.assertNotIn("EnvironmentFile=-/etc/branchleft/%i.image.env", self.template)

    def test_the_secrets_file_is_still_optional(self):
        self.assertIn("EnvironmentFile=-/etc/branchleft/%i.env", self.template)


if __name__ == "__main__":
    unittest.main()
