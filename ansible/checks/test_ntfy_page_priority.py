"""The ntfy page template must set priority 5 for firing alerts (ws#3990).

ntfy v2.28.0 reads a file template's priority only from its `priority` key, so
the stack's template must carry it and the compose file must mount it over the
built-in template of the same name.
"""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "hetzner/monitoring/stack/ntfy/templates/alertmanager.yml"
COMPOSE = REPO / "hetzner/monitoring/stack/compose.yml"
FIRING_PRIORITY = "priority: '{{ if eq .status \"firing\" }}5{{ else }}3{{ end }}'"
MOUNT = "- ./ntfy/templates:/etc/ntfy/templates:ro"


class NtfyPagePriorityTest(unittest.TestCase):
    def test_firing_pages_are_priority_five(self) -> None:
        lines = TEMPLATE.read_text(encoding="utf-8").splitlines()
        self.assertIn(FIRING_PRIORITY, lines)

    def test_the_template_is_mounted_over_the_builtin_one(self) -> None:
        self.assertIn(MOUNT, COMPOSE.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
