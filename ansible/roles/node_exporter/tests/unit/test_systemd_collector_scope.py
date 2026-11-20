"""Unit tests for the node_exporter unit's systemd collector: what it reads, and nothing wider.

The alerts ComposeUnitRestartLoop and ComposeUnitFailed (hetzner/monitoring/render.ts) read
node_systemd_unit_state and node_systemd_service_restart_total for the compose template's
instances. Those series exist only when the exporter runs the systemd collector, with the
restart counter switched on. The collector is off by default and, once on, reports every unit
of the host, so it is limited to the compose instances: the host's other units are not the
estate's metrics to publish, and a wide include would put every unit in every scrape.

These tests read the unit file the role installs (a link to hetzner/provision/node-exporter.service)
and fail in seconds if the flags drift. Whether a real exporter then answers is the monitoring
runbook's read-back, not this file.
"""

import re
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
UNIT = ROLE / "files" / "node-exporter.service"

COLLECTOR = "--collector.systemd"
INCLUDE = "--collector.systemd.unit-include="
RESTARTS = "--collector.systemd.enable-restarts-metrics"


def exec_start_words() -> list[str]:
    """The words of the unit's one ExecStart= line."""
    lines = [
        line.strip()
        for line in UNIT.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("ExecStart=")
    ]
    if len(lines) != 1:
        raise AssertionError(f"expected one ExecStart= line, found {len(lines)}")
    return lines[0].removeprefix("ExecStart=").split()


def include_pattern() -> str:
    """The unit-include regular expression, as systemd passes it to the exporter."""
    values = [word.removeprefix(INCLUDE) for word in exec_start_words() if word.startswith(INCLUDE)]
    if len(values) != 1:
        raise AssertionError(f"expected one {INCLUDE} flag, found {len(values)}")
    return values[0]


class SystemdCollectorScopeTests(unittest.TestCase):
    """The collector is on, counts restarts, and sees only the compose template's instances."""

    def test_the_systemd_collector_is_switched_on(self) -> None:
        self.assertIn(COLLECTOR, exec_start_words())

    def test_the_restart_counter_is_switched_on(self) -> None:
        self.assertIn(RESTARTS, exec_start_words())

    def test_the_include_matches_every_compose_instance(self) -> None:
        # node_exporter anchors the pattern: ^(?:pattern)$.
        pattern = re.compile(f"^(?:{include_pattern()})$")
        for name in (
            "branchleft-compose@edge.service",
            "branchleft-compose@control-plane.service",
            "branchleft-compose@Molecule-Probe.service",
            "branchleft-compose@db.service",
        ):
            with self.subTest(name=name):
                self.assertIsNotNone(pattern.match(name))

    def test_the_include_matches_no_other_unit(self) -> None:
        pattern = re.compile(f"^(?:{include_pattern()})$")
        for name in (
            "branchleft-compose@.service",
            "branchleft-compose@edge.timer",
            "branchleft-compose@edge.service.d",
            "docker.service",
            "ssh.service",
            "node_exporter.service",
            "branchleft-deploy.service",
            "xbranchleft-compose@edge.service",
        ):
            with self.subTest(name=name):
                self.assertIsNone(pattern.match(name))

    def test_the_include_has_no_backslash_systemd_would_read_as_an_escape(self) -> None:
        # ExecStart= reads C-style escapes, so `\.` would reach the exporter changed or
        # dropped. A character class does the same work.
        self.assertNotIn("\\", include_pattern())

    def test_the_include_has_no_specifier_or_variable_systemd_would_expand(self) -> None:
        for character in ("%", "$"):
            with self.subTest(character=character):
                self.assertNotIn(character, include_pattern())

    def test_the_include_is_one_word(self) -> None:
        # A space would split the flag, and the exporter would take its tail as an argument.
        self.assertNotRegex(include_pattern(), r"\s")


if __name__ == "__main__":
    unittest.main()
