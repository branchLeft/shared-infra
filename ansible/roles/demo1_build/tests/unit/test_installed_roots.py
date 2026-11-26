"""The host scan counts a secret beside installed code, and does not count the installed code.

demo1's Ansible toolchain, the pull program's work trees and the broker's Node runtime sit under the
scanned roots, and their packages, docs and test fixtures hold secret words (a filter's own doc, a
package called pytokens, a repository checkout's fixtures). The scan leaves out a found path under
three exact roots (``demo1_build_secret_installed_roots``) and names the mail spool's Compose
file in a holder row. These tests hold that to two things: each root is the directory its own role
installs into, and the exclusion is narrow. The collecting tasks are the role's own text, run for
real with the registers a scan would have left, so the real expressions decide a host's paths.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parent.parent.parent
ROLES = ROLE.parent
SCAN = ROLE / "tasks" / "_holder_scan.yml"
NOT_A_MAPPING = "a role variables file is not a mapping"
NOT_A_LIST = "a role variable is not a list"
COLLECTING = (
    "Collect the regular files the scan found, by name, by place and by content",
    "Collect the links whose target is a secret the scan can see",
    "Collect every path the scan found",
    "Collect the found paths the holder list does not name",
)

# Each excluded root and the variable of the role that installs into it (no role imports another, so
# the constant is copied here and pinned: ANS-12).
OWNERS = {
    "/opt/ansible-runtime": ("ansible_runtime", "defaults", "ansible_runtime_root"),
    "/var/lib/pull-trigger": ("pull_trigger", "vars", "pull_trigger_state_dir"),
    "/opt/branchleft/broker/node": ("broker_deploy", "defaults", "broker_deploy_node_dir"),
}

# What a host holds under the roots: found by the scan's content and name tests, and left out.
INSTALLED = [
    "/opt/ansible-runtime/requirements-4b5e0b6b56c2a4f9.txt",
    "/opt/ansible-runtime/venv-4b5e0b6b56c2a4f9/lib/python3.13/site-packages/ansible/plugins/filter/password_hash.yml",
    "/opt/ansible-runtime/venv-4b5e0b6b56c2a4f9/lib/python3.13/site-packages/x/ssl/test.key",
    "/var/lib/pull-trigger/work/d38c17d8.4i_vq_4n/ansible/roles/x/vars/main.yml",
    "/var/lib/pull-trigger/cache/objects/pack/fixture.env",
    "/opt/branchleft/broker/node/lib/node_modules/npm/docs/content/using-npm/config.md",
    "/opt/branchleft/broker/node/lib/node_modules/npm/man/man7/config.7",
]
# A real secret-looking file beside each root, in the three shapes: a sibling by a longer name, a
# neighbour in the directory above, and a different directory under the same parent.
STRAY = [
    "/opt/ansible-runtime-other/stray.env",
    "/opt/ansible-runtime.bak/venv/stray.env",
    "/var/lib/pull-trigger2/stray.env",
    "/var/lib/pull-trigger-state/stray.env",
    "/opt/branchleft/stray.env",
    "/opt/branchleft/broker/stray.env",
    "/opt/branchleft/broker/nodex/stray.env",
    "/opt/branchleft/broker/releases/0.0.1/stray.env",
    "/opt/branchleft/mail-spool/other.yml",
    "/opt/branchleft/mail-spool/compose.yml.bak",
    "/opt/ansible-runtime",
]
TARGET = "/srv/stand-in/id_a"
LISTED = ["/opt/branchleft/mail-spool/compose.yml"]


def load(role: str, folder: str) -> dict[str, object]:
    """One role variables file, defaults or vars.

    Raises:
        TypeError: the file is not a mapping.
    """
    raw = yaml.safe_load((ROLES / role / folder / "main.yml").read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(NOT_A_MAPPING)
    return raw


def strings(name: str) -> list[str]:
    """A list of strings from the role's vars.

    Raises:
        TypeError: the variable is not a list of strings.
    """
    value = load("demo1_build", "vars")[name]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError(NOT_A_LIST)
    return [str(item) for item in value]


def ansible_playbook() -> Path:
    """Return the ansible-playbook beside the interpreter that runs the tests.

    Raises:
        AssertionError: the interpreter's environment has no ansible-playbook.
    """
    found = Path(sys.executable).parent / "ansible-playbook"
    if not found.exists():
        message = f"{found} is missing: run these tests with the pinned tool environment"
        raise AssertionError(message)
    return found


def collecting_tasks() -> list[dict[str, object]]:
    """The role's own collecting tasks, in file order, by name.

    Raises:
        AssertionError: a task is missing or renamed.
    """
    tasks = yaml.safe_load(SCAN.read_text(encoding="utf-8"))
    by_name = {task["name"]: task for task in tasks if isinstance(task, dict) and "name" in task}
    missing = [name for name in COLLECTING if name not in by_name]
    if missing:
        message = f"the scan has no task named {missing}"
        raise AssertionError(message)
    return [by_name[name] for name in COLLECTING]


def unlisted(*, found: list[str], links: dict[str, str] | None = None) -> list[str]:
    """Run the collecting tasks over what a scan found, and return the paths no row names.

    Raises:
        AssertionError: the collecting tasks fail.
        TypeError: the result is not a list.
    """
    links = links or {}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        play = root / "play.yml"
        out = root / "out.json"
        tasks = [
            *collecting_tasks(),
            {
                "ansible.builtin.copy": {
                    "content": "{{ demo1_build_secret_unlisted | to_json }}",
                    "dest": str(out),
                }
            },
        ]
        play.write_text(
            yaml.safe_dump(
                [
                    {
                        "hosts": "localhost",
                        "connection": "local",
                        "gather_facts": False,
                        "vars_files": [
                            str(ROLE / "defaults" / "main.yml"),
                            str(ROLE / "vars" / "main.yml"),
                        ],
                        "tasks": tasks,
                    }
                ]
            ),
            encoding="utf-8",
        )
        registers = {
            "demo1_build_secret_content_strict_roots": {"stdout_lines": found},
            "demo1_build_secret_link_paths": {"stdout_lines": list(links)},
            "demo1_build_secret_link_targets": {"stdout_lines": list(links.values())},
            "ansible_python_interpreter": sys.executable,
        }
        extra = root / "extra.json"
        extra.write_text(json.dumps(registers), encoding="utf-8")
        config = root / "ansible.cfg"
        config.write_text("", encoding="utf-8")
        environment = {
            **os.environ,
            "ANSIBLE_CONFIG": str(config),
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_HOME": str(root / "ansible-home"),
        }
        command = [str(ansible_playbook()), "-i", "localhost,", "-e", f"@{extra}", str(play)]
        # The command is built here from fixed paths and the scratch tree.
        done = subprocess.run(  # noqa: S603
            command, capture_output=True, text=True, check=False, env=environment, timeout=180
        )
        if done.returncode != 0:
            message = f"the collecting tasks failed\n{done.stdout}{done.stderr}"
            raise AssertionError(message)
        result = json.loads(out.read_text(encoding="utf-8"))
    if not isinstance(result, list):
        raise TypeError(NOT_A_LIST)
    return [str(item) for item in result]


class RootsAreTheRolesOwn(unittest.TestCase):
    """Each excluded root is the exact directory its role installs into, and nothing wider."""

    def test_the_excluded_roots_are_the_three_this_file_knows(self) -> None:
        self.assertEqual(sorted(OWNERS), sorted(strings("demo1_build_secret_installed_roots")))

    def test_each_root_is_its_roles_own_variable(self) -> None:
        for root, (role, folder, variable) in OWNERS.items():
            with self.subTest(root=root):
                self.assertEqual(root, load(role, folder)[variable])

    def test_a_root_is_an_exact_absolute_directory_with_no_glob(self) -> None:
        for root in strings("demo1_build_secret_installed_roots"):
            with self.subTest(root=root):
                self.assertTrue(root.startswith("/"))
                self.assertFalse(root.endswith("/"))
                self.assertNotIn("//", root)
                self.assertEqual(set(), set(root) & set("*?[]{}$\\ "))
                self.assertGreaterEqual(
                    len(root.split("/")), 3, "a top-level directory is too wide"
                )

    def test_no_root_contains_a_scanned_root_a_holder_directory_or_the_rest_of_opt_branchleft(
        self,
    ) -> None:
        scanned = strings("demo1_build_secret_scan_roots")
        holders = strings("demo1_build_secret_holder_dirs")
        for root in strings("demo1_build_secret_installed_roots"):
            with self.subTest(root=root):
                self.assertNotIn(root, scanned)
                for guarded in (*scanned, *holders, "/opt/branchleft", "/opt/branchleft/broker"):
                    self.assertFalse(
                        guarded == root or guarded.startswith(root + "/"),
                        f"{root} would hide {guarded}",
                    )


class WhatTheScanCounts(unittest.TestCase):
    """The collecting tasks, run for real over the paths a host's scan would find."""

    def test_installed_code_under_the_roots_is_not_counted(self) -> None:
        self.assertEqual([], unlisted(found=INSTALLED))

    def test_a_secret_beside_a_root_is_still_counted(self) -> None:
        self.assertEqual(sorted(STRAY), unlisted(found=[*INSTALLED, *STRAY]))

    def test_the_mail_spools_compose_file_is_named_by_a_row_and_its_neighbours_are_not(
        self,
    ) -> None:
        self.assertEqual([], unlisted(found=LISTED))
        self.assertEqual(
            ["/opt/branchleft/mail-spool/other.yml"],
            unlisted(found=[*LISTED, "/opt/branchleft/mail-spool/other.yml"]),
        )

    def test_a_secret_named_link_under_a_root_is_not_counted_and_one_beside_it_is(self) -> None:
        inside = "/opt/ansible-runtime/venv-x/lib/id_link"
        beside = "/opt/ansible-runtime-other/id_link"
        self.assertEqual(
            [beside],
            unlisted(found=[], links={inside: TARGET, beside: TARGET}),
        )
        # A link elsewhere that points at installed code is not made a secret by the target.
        self.assertEqual(
            [],
            unlisted(found=INSTALLED, links={"/srv/app/doc": INSTALLED[1]}),
        )


if __name__ == "__main__":
    unittest.main()
