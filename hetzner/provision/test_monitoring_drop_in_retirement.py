#!/usr/bin/env python3
"""The drop-in script is retired, and the runbooks name the roles that install the drop-ins.

workspace#2536: install-systemd-drop-ins.sh was the interim installer for the edge and
monitoring drop-ins while no playbook ran the roles. The edge1 playbook now runs
edge_stack and monitoring_stack (wired by shared-infra#544, converged 2026-11-01), so the
script is gone. These checks hold that: the file does not exist, nothing in the tree names
it, the monitoring runbook's step 5 names monitoring_stack with no hand fence, and the
provisioning runbook's step 4 names both roles with no command that reaches a host.

The neighbour-edit guards are carried over from the test file this one replaces. They keep
the runbook section helper finding each step by its own heading.
"""

import pathlib
import tempfile
import unittest
from unittest import mock

from runbook_sections import runbook_section

HETZNER = pathlib.Path(__file__).resolve().parent.parent
ROOT = HETZNER.parent
SCRIPT = HETZNER / "provision" / "install-systemd-drop-ins.sh"
RUNBOOK = HETZNER / "RUNBOOK-monitoring.md"
PROVISION_RUNBOOK = HETZNER / "RUNBOOK-provision-host.md"
RETIRED_NAME = "install-systemd-drop-ins"
# This file and the hand-block check hold the name on purpose: one as its assertion, the
# other as the write pattern that refuses a reintroduced call. Nothing else may name it.
ALLOWED_NAMERS = {
    pathlib.Path(__file__).resolve(),
    HETZNER / "provision" / "test_runbook_monitoring_hand_blocks.py",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__"}


def files_naming_the_script() -> list[str]:
    """Every text file in the repository that names the retired script, except the allowed ones."""
    found = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.resolve() in ALLOWED_NAMERS:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if RETIRED_NAME in text:
            found.append(str(path.relative_to(ROOT)))
    return sorted(found)


class ScriptIsRetiredTests(unittest.TestCase):
    def test_the_script_file_is_gone(self):
        self.assertFalse(SCRIPT.exists(), f"{SCRIPT} must be deleted (workspace#2536)")

    def test_nothing_in_the_tree_names_the_script(self):
        self.assertEqual(
            files_naming_the_script(),
            [],
            "a file still names install-systemd-drop-ins; point it at the role that owns the drop-in",
        )


class MonitoringRunbookStepFiveTests(unittest.TestCase):
    """RUNBOOK-monitoring.md step 5 names the role and carries no command that reaches a host."""

    @staticmethod
    def _step_5_body() -> str:
        return runbook_section(RUNBOOK, "## 5. Install the systemd cgroup drop-ins")

    def test_step_5_names_the_monitoring_stack_role(self):
        self.assertIn("monitoring_stack", self._step_5_body())

    def test_step_5_has_no_fenced_block(self):
        fences = [line for line in self._step_5_body().splitlines() if line.startswith("```")]
        self.assertEqual(fences, [], "step 5 is served by the role; it carries no hand fence")

    def test_step_5_does_not_name_the_script(self):
        self.assertNotIn(RETIRED_NAME, self._step_5_body())


class ProvisionHostRunbookStepFourTests(unittest.TestCase):
    """RUNBOOK-provision-host.md step 4 points at the roles that install the drop-ins."""

    @staticmethod
    def _step_body() -> str:
        return runbook_section(PROVISION_RUNBOOK, "### 4. Install the systemd cgroup drop-ins")

    def test_step_names_both_roles_that_install_the_drop_ins(self):
        body = self._step_body()
        self.assertIn("edge_stack", body)
        self.assertIn("monitoring_stack", body)

    def test_step_carries_no_command_that_reaches_a_host(self):
        body = self._step_body()
        self.assertNotIn("```", body)
        self.assertNotIn("scp -i", body)
        self.assertNotIn("ssh -i", body)

    def test_step_does_not_name_the_script(self):
        self.assertNotIn(RETIRED_NAME, self._step_body())


class NeighbouringEditsDoNotMoveAStep(unittest.TestCase):
    """A step is found by its own heading, so editing the heading of the step after it must
    not change what the step's own extraction returns. Before the fix both extractors ended
    on the neighbour's literal heading: dropping that heading's number made the slice run on
    to the end of the runbook, and renaming the neighbour's `##` heading made the lookup raise
    with nothing naming the cause."""

    @staticmethod
    def _runbook_copy(source, old, new):
        text = pathlib.Path(source).read_text(encoding="utf-8")
        assert text.count(old) == 1, f"{old!r} must occur once in {source.name}"
        directory = tempfile.TemporaryDirectory()
        copy = pathlib.Path(directory.name) / source.name
        copy.write_text(text.replace(old, new, 1), encoding="utf-8")
        return directory, copy

    def test_dropping_the_number_of_the_next_provision_step_leaves_step_4_unchanged(self):
        original = ProvisionHostRunbookStepFourTests._step_body()
        directory, edited = self._runbook_copy(
            PROVISION_RUNBOOK,
            "### 5. Provision a host that has no public address",
            "### Provision a host that has no public address",
        )
        self.addCleanup(directory.cleanup)
        with mock.patch(f"{__name__}.PROVISION_RUNBOOK", edited):
            self.assertEqual(ProvisionHostRunbookStepFourTests._step_body(), original)

    def test_renaming_the_next_monitoring_step_leaves_step_5_unchanged(self):
        original = MonitoringRunbookStepFiveTests._step_5_body()
        directory, edited = self._runbook_copy(
            RUNBOOK,
            "## 6. Restart the edge stack",
            "## Restart the edge stack",
        )
        self.addCleanup(directory.cleanup)
        with mock.patch(f"{__name__}.RUNBOOK", edited):
            self.assertEqual(MonitoringRunbookStepFiveTests._step_5_body(), original)

    def test_a_step_whose_own_heading_is_gone_fails_naming_that_heading(self):
        directory, edited = self._runbook_copy(
            PROVISION_RUNBOOK,
            "### 4. Install the systemd cgroup drop-ins",
            "### 4. Install the drop-ins",
        )
        self.addCleanup(directory.cleanup)
        with mock.patch(f"{__name__}.PROVISION_RUNBOOK", edited):
            with self.assertRaisesRegex(AssertionError, "Install the systemd cgroup drop-ins"):
                ProvisionHostRunbookStepFourTests._step_body()


if __name__ == "__main__":
    unittest.main()
