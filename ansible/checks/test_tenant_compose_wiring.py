"""Tests that tenant_compose is wired into app1 where it must be.

The role restarts the live stacks of an app host, so three facts hold it in place: app1's list in
checks/host_roles.yml names it (the owner's merge, so a pulled playbook cannot widen what runs as
root), app1's playbook applies it as its last role (a failure there must not hold the website
back), and it never runs before the deploy tooling role in any playbook that applies both (the
tooling makes the directories, the template unit and the isolation policy it needs). The seed
tool, which reads the volume program the role calls, holds that program's path as a copy; the
path must equal the role's own. Each mutation edits a small copy of the tree and must produce its
own finding.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from check_enrolment import HOST_ROLES_FILE, ROOT

ROLE = "tenant_compose"
HOST = "app1"
TOOLING = "deploy_tooling"
PROGRAM_ASSIGNMENT = re.compile(r'^VOLUME_PROGRAM: Final = "([^"]+)"$', re.MULTILINE)
ROLE_LINE = "    - role: ../roles/tenant_compose # noqa: role-name[path]\n"


def _read(path: Path) -> object:
    if not path.is_file():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _roles_of(playbook: Path) -> list[str]:
    """The role directory names of the one play of a host playbook, in order."""
    plays = _read(playbook)
    if not isinstance(plays, list) or not plays or not isinstance(plays[0], dict):
        return []
    roles = plays[0].get("roles")
    if not isinstance(roles, list):
        return []
    names: list[str] = []
    for entry in roles:
        source = entry.get("role", "") if isinstance(entry, dict) else entry
        names.append(Path(str(source)).name)
    return names


def problems(ansible: Path) -> list[str]:
    """Every way the wiring is broken. Empty when it holds."""
    findings: list[str] = []
    host_roles = _read(ansible / HOST_ROLES_FILE)
    listed = host_roles.get(HOST) if isinstance(host_roles, dict) else None
    if not isinstance(listed, list) or ROLE not in listed:
        findings.append(f"{HOST_ROLES_FILE}: {ROLE} is not on {HOST}'s list")
    applied = _roles_of(ansible / "playbooks" / f"{HOST}.yml")
    if ROLE not in applied:
        findings.append(f"playbooks/{HOST}.yml does not apply {ROLE}")
    elif applied[-1] != ROLE:
        findings.append(f"playbooks/{HOST}.yml must apply {ROLE} as its last role")
    for playbook in sorted((ansible / "playbooks").glob("*.yml")):
        roles = _roles_of(playbook)
        if ROLE in roles and TOOLING in roles and roles.index(ROLE) < roles.index(TOOLING):
            findings.append(f"playbooks/{playbook.name}: {ROLE} is applied before {TOOLING}")
    findings.extend(_program_findings(ansible))
    return findings


def _program_findings(ansible: Path) -> list[str]:
    role_vars = _read(ansible / "roles" / ROLE / "vars" / "main.yml")
    program = (
        role_vars.get("tenant_compose_volume_program") if isinstance(role_vars, dict) else None
    )
    tool = ansible / "tools" / "seed_host_inputs.py"
    match = PROGRAM_ASSIGNMENT.search(tool.read_text(encoding="utf-8")) if tool.is_file() else None
    if not isinstance(program, str) or match is None or match.group(1) != program:
        return ["tools/seed_host_inputs.py: VOLUME_PROGRAM is not the role's volume program path"]
    return []


class RealTree(unittest.TestCase):
    def test_app1_lists_and_applies_the_role_last_and_the_seed_tool_agrees(self) -> None:
        self.assertEqual(problems(ROOT / "ansible"), [])

    def test_app1_applies_the_role_after_the_website_role(self) -> None:
        applied = _roles_of(ROOT / "ansible" / "playbooks" / f"{HOST}.yml")
        self.assertIn("website_app1", applied)
        self.assertGreater(applied.index(ROLE), applied.index("website_app1"))


class Mutations(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.ansible = Path(temp.name) / "ansible"
        real = ROOT / "ansible"
        (self.ansible / "checks").mkdir(parents=True)
        shutil.copy(real / HOST_ROLES_FILE, self.ansible / HOST_ROLES_FILE)
        (self.ansible / "playbooks").mkdir()
        shutil.copy(real / "playbooks" / f"{HOST}.yml", self.ansible / "playbooks" / f"{HOST}.yml")
        (self.ansible / "tools").mkdir()
        shutil.copy(
            real / "tools" / "seed_host_inputs.py", self.ansible / "tools" / "seed_host_inputs.py"
        )
        (self.ansible / "roles" / ROLE / "vars").mkdir(parents=True)
        shutil.copy(
            real / "roles" / ROLE / "vars" / "main.yml",
            self.ansible / "roles" / ROLE / "vars" / "main.yml",
        )

    def _edit(self, relative: str, old: str, new: str) -> None:
        path = self.ansible / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text, f"the mutation matched nothing in {relative}")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def _expect(self, fragment: str) -> None:
        found = problems(self.ansible)
        self.assertTrue(any(fragment in finding for finding in found), (fragment, found))

    def test_the_copy_passes_before_any_mutation(self) -> None:
        self.assertEqual(problems(self.ansible), [])

    def test_the_role_dropped_from_the_hosts_list_is_found(self) -> None:
        self._edit(HOST_ROLES_FILE, "  - tenant_compose\n", "")
        self._expect(f"{ROLE} is not on {HOST}'s list")

    def test_the_role_dropped_from_the_playbook_is_found(self) -> None:
        self._edit(f"playbooks/{HOST}.yml", ROLE_LINE, "")
        self._expect(f"does not apply {ROLE}")

    def test_the_role_applied_before_another_role_is_found(self) -> None:
        self._edit(f"playbooks/{HOST}.yml", ROLE_LINE, "")
        self._edit(
            f"playbooks/{HOST}.yml",
            "    - role: ../roles/website_app1 # noqa: role-name[path]\n",
            ROLE_LINE + "    - role: ../roles/website_app1 # noqa: role-name[path]\n",
        )
        self._expect("as its last role")

    def test_the_role_applied_before_the_deploy_tooling_is_found(self) -> None:
        self._edit(
            f"playbooks/{HOST}.yml",
            ROLE_LINE,
            ROLE_LINE + "    - role: ../roles/deploy_tooling # noqa: role-name[path]\n",
        )
        self._expect(f"{ROLE} is applied before {TOOLING}")

    def test_the_role_applied_after_the_deploy_tooling_passes(self) -> None:
        self._edit(
            f"playbooks/{HOST}.yml",
            ROLE_LINE,
            "    - role: ../roles/deploy_tooling # noqa: role-name[path]\n" + ROLE_LINE,
        )
        self.assertEqual(problems(self.ansible), [])

    def test_a_volume_program_path_the_role_does_not_use_is_found(self) -> None:
        self._edit(
            "tools/seed_host_inputs.py",
            'VOLUME_PROGRAM: Final = "/root/platform-provision/provision_tenant_volume.py"',
            'VOLUME_PROGRAM: Final = "/root/platform-provision/another_program.py"',
        )
        self._expect("VOLUME_PROGRAM is not the role's volume program path")

    def test_a_role_that_moved_its_volume_program_is_found(self) -> None:
        self._edit(
            "roles/tenant_compose/vars/main.yml",
            "tenant_compose_volume_program: /root/platform-provision/provision_tenant_volume.py",
            "tenant_compose_volume_program: /usr/local/sbin/provision_tenant_volume.py",
        )
        self._expect("VOLUME_PROGRAM is not the role's volume program path")


if __name__ == "__main__":
    unittest.main()
