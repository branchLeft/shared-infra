"""Pins on the ci_login role: its copies stay equal to their homes, and the missing source limit
stays visible.

The role carries its own copy of the key shapes (the sudoers_and_keys pattern is not called, so
the role imports no pattern) and of the trigger program's path (pull_trigger owns it). It has no
`from` option on purpose: the owner accepted keys that work from any address. Each pin is shown
red on a sabotaged copy of the files it reads, and green again once the file is put back.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
ROLE = "ansible/roles/ci_login"
HOMES = (
    "ansible/patterns/sudoers_and_keys/vars/main.yml",
    "ansible/roles/pull_trigger/vars/main.yml",
)
# The role files that carry the role's behaviour. The README and molecule/ are prose and tests.
CODE_DIRECTORIES = ("tasks", "templates", "vars", "defaults", "meta")
SOURCE_LIMIT = re.compile(r"from=|from_addresses", re.IGNORECASE)
DEFAULTS_LINE = 'Defaults!{{ ci_login_program }} env_keep += "SSH_ORIGINAL_COMMAND"'
GRANT_LINE = re.compile(
    r"\{\{ ci_login_user \}\} ALL=\(root\) NOPASSWD: "
    r"\{\{ ci_login_program \}\} --mode apply, \{\{ ci_login_program \}\} --mode check"
)


def _variables(path: Path) -> dict[str, object]:
    document: object = yaml.safe_load(path.read_text(encoding="utf-8"))
    return (
        {str(key): value for key, value in document.items()} if isinstance(document, dict) else {}
    )


def _option_names(node: object) -> list[str]:
    """Every key under an `options` mapping of an argument spec, however deep."""
    names: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "options" and isinstance(value, dict):
                names.extend(str(name) for name in value)
            names.extend(_option_names(value))
    elif isinstance(node, list):
        for item in node:
            names.extend(_option_names(item))
    return names


def problems(root: Path) -> list[str]:
    """Return one finding per broken pin in the tree under ``root``."""
    found: list[str] = []
    role = root / ROLE
    mine = _variables(role / "vars" / "main.yml")
    pattern = _variables(root / HOMES[0])
    trigger = _variables(root / HOMES[1])

    if mine.get("ci_login_key_shapes") != pattern.get("sudoers_and_keys_key_shapes"):
        found.append("ci_login_key_shapes differs from sudoers_and_keys_key_shapes")
    if mine.get("ci_login_program") != trigger.get("pull_trigger_program_path"):
        found.append("ci_login_program differs from pull_trigger_program_path")

    lines = mine.get("ci_login_sudoers_lines")
    if not (
        isinstance(lines, list)
        and len(lines) == 2
        and lines[0] == DEFAULTS_LINE
        and isinstance(lines[1], str)
        and GRANT_LINE.fullmatch(lines[1])
    ):
        found.append("ci_login_sudoers_lines must be the env_keep line and the two-command grant")

    for directory in CODE_DIRECTORIES:
        for path in sorted((role / directory).rglob("*")):
            if path.is_file() and SOURCE_LIMIT.search(path.read_text(encoding="utf-8")):
                found.append(f"{path.relative_to(root).as_posix()}: names a source address option")
    spec = yaml.safe_load((role / "meta" / "argument_specs.yml").read_text(encoding="utf-8"))
    found.extend(
        f"meta/argument_specs.yml: option {name} is a source address option"
        for name in _option_names(spec)
        if "from" in name
    )
    return found


class RealTree(unittest.TestCase):
    def test_the_pins_hold_on_the_real_tree(self) -> None:
        self.assertEqual(problems(ROOT), [])

    def test_the_key_template_has_no_source_option_and_does_have_the_forced_command(self) -> None:
        template = (ROOT / ROLE / "templates" / "authorized_keys.j2").read_text(encoding="utf-8")
        self.assertNotIn("from", template)
        self.assertIn('command="sudo {{ ci_login_program }} --mode {{ entry.mode }}"', template)
        self.assertIn("{{ ci_login_key_options }},", template)

    def test_the_key_options_are_restrict(self) -> None:
        mine = _variables(ROOT / ROLE / "vars" / "main.yml")
        self.assertEqual(mine["ci_login_key_options"], "restrict")


class Sabotage(unittest.TestCase):
    """Break one file of a copy of the tree, require the named finding, put the file back and
    require none, so a pin that is always red cannot pass for one that is switched on."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        shutil.copytree(ROOT / ROLE, self.root / ROLE)
        for home in HOMES:
            (self.root / home).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / home, self.root / home)

    def _red_then_green(self, relative: str, old: str, new: str, expected: str) -> None:
        path = self.root / relative
        original = path.read_text(encoding="utf-8")
        self.assertIn(old, original, f"the sabotage matched nothing in {relative}")
        path.write_text(original.replace(old, new, 1), encoding="utf-8")
        red = problems(self.root)
        self.assertTrue(any(expected in finding for finding in red), f"{expected!r} not in {red}")
        path.write_text(original, encoding="utf-8")
        self.assertEqual(problems(self.root), [])

    def test_a_source_limit_in_the_key_template_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/templates/authorized_keys.j2",
            "{{ ci_login_key_options }},command=",
            'from="192.0.2.0/24",{{ ci_login_key_options }},command=',
            "templates/authorized_keys.j2: names a source address option",
        )

    def test_a_source_limit_option_in_the_interface_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/meta/argument_specs.yml",
            "          mode:\n",
            "          from_addresses:\n            type: list\n          mode:\n",
            "meta/argument_specs.yml",
        )

    def test_a_source_limit_option_with_another_name_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/meta/argument_specs.yml",
            "          mode:\n",
            "          allowed_from:\n            type: list\n          mode:\n",
            "option allowed_from is a source address option",
        )

    def test_drifted_key_shapes_are_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "ssh-ed25519 [A-Za-z0-9+/]{68}",
            "ssh-ed25519 [A-Za-z0-9+/]{60,}",
            "ci_login_key_shapes differs",
        )

    def test_a_changed_key_shape_in_the_home_is_red(self) -> None:
        self._red_then_green(
            HOMES[0],
            "ssh-rsa [A-Za-z0-9+/]{200,}={0,2}",
            "ssh-rsa [A-Za-z0-9+/]{100,}={0,2}",
            "ci_login_key_shapes differs",
        )

    def test_a_drifted_program_path_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "ci_login_program: /usr/local/sbin/pull-trigger",
            "ci_login_program: /usr/local/sbin/pull-trigger2",
            "ci_login_program differs",
        )

    def test_a_moved_program_in_the_home_is_red(self) -> None:
        self._red_then_green(
            HOMES[1],
            "pull_trigger_program_path: /usr/local/sbin/pull-trigger",
            "pull_trigger_program_path: /usr/local/sbin/pull-trigger2",
            "ci_login_program differs",
        )

    def test_a_wider_sudoers_grant_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "{{ ci_login_program }} --mode check'",
            "{{ ci_login_program }} --mode check, /bin/sh'",
            "ci_login_sudoers_lines must be",
        )

    def test_a_third_sudoers_line_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "--mode check'\n",
            "--mode check'\n  - 'ansible-ci ALL=(ALL) NOPASSWD: ALL'\n",
            "ci_login_sudoers_lines must be",
        )


if __name__ == "__main__":
    unittest.main()
