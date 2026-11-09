"""Unit tests for where the status page sits in ops1's play.

The page is published on ops1's private address, where every host on the private network can
reach it until the control-plane host's DOCKER-USER policy drops all but the gateway on its
port. That policy is installed by the last tasks of the control_plane role. The role order of
ops1's playbook is therefore the control: the page must come after the role that installs the
drop, so a run that stops part-way never leaves the port bound with no drop. These tests read
the playbook, the control_plane tasks and the policy script, and fail when that order is lost.
"""

import re
import unittest
from pathlib import Path
from typing import Any

import yaml

ROLE = Path(__file__).resolve().parents[2]
ANSIBLE = ROLE.parents[1]
PLAYBOOK = ANSIBLE / "playbooks" / "ops1.yml"
CONTROL_PLANE = ANSIBLE / "roles" / "control_plane"
POLICY_SCRIPT = CONTROL_PLANE / "files" / "branchleft_docker_user_policy.sh"
INSTALL_RECONCILER = "Install the DOCKER-USER isolation reconciler"
APPLY_POLICY = "Apply the isolation policy when its reconciler or its unit changed"
PORTS_LINE = re.compile(r'^PROTECTED_PORTS="\$\{[A-Z_]+:-([0-9 ]+)\}"$', re.MULTILINE)


def _roles() -> list[str]:
    """Return the role names of ops1's playbook, in the order the play applies them."""
    play: dict[str, Any] = yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))[0]
    return [Path(str(entry["role"])).name for entry in play["roles"]]


def _control_plane_tasks() -> list[dict[str, Any]]:
    """Return every task of the control_plane role, parsed."""
    return list(yaml.safe_load((CONTROL_PLANE / "tasks" / "main.yml").read_text(encoding="utf-8")))


class StatusPageOrderTest(unittest.TestCase):
    """The page is bound only after the role that installs the port's drop has run."""

    # Safety class: a firewall boundary. Put the status page before the control plane and the
    # first apply binds the port with no drop, and a failure in the control plane leaves it so.
    def test_status_page_follows_the_role_that_installs_the_drop(self) -> None:
        names = _roles()
        self.assertEqual(names.count("status_page"), 1)
        self.assertEqual(names.count("control_plane"), 1)
        self.assertLess(
            names.index("control_plane"),
            names.index("status_page"),
            "status_page binds its port on the private address; control_plane installs the "
            "DOCKER-USER drop for that port, so it must run first",
        )

    # The order only helps if the role it waits for really installs the drop for this port.
    def test_the_policy_the_control_plane_installs_protects_the_status_page_port(self) -> None:
        constants = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))
        ports = PORTS_LINE.findall(POLICY_SCRIPT.read_text(encoding="utf-8"))
        self.assertEqual(len(ports), 1, "the policy script's protected-ports line was not found")
        self.assertIn(str(constants["status_page_port"]), ports[0].split())

    # The role must install the reconciler and restart its unit, in that order: without the
    # restart a changed reconciler is on disk and the rule is not yet loaded.
    def test_the_control_plane_installs_then_applies_the_policy(self) -> None:
        names = [str(task.get("name")) for task in _control_plane_tasks()]
        self.assertIn(INSTALL_RECONCILER, names)
        self.assertIn(APPLY_POLICY, names)
        self.assertLess(names.index(INSTALL_RECONCILER), names.index(APPLY_POLICY))


if __name__ == "__main__":
    unittest.main()
