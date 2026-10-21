"""Check that the sudoers grant the role expects is the one the host's first boot writes.

The role never writes the CI deploy account's sudoers drop-in: cloud-init does, from the
constant `DEPLOY_SUDOERS` in `hetzner-host/cloudInit.ts`. The role reads the drop-in and
refuses anything but its own expected line, built in `vars/main.yml` from the wrapper path.
The two live in different languages and repositories' directories, so this test compares the
whole line, not only the path: a change to a runas, a tag such as `SETENV:`, or the path in
either one alone fails here.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

import deploy_tooling_vars as role_vars

CLOUD_INIT = role_vars.REPO_ROOT / "hetzner-host" / "cloudInit.ts"
_CONSTANT = re.compile(r"^const DEPLOY_SUDOERS = '(?P<line>[^'\n]*)';$", re.MULTILINE)
_DROP_IN = re.compile(
    r"- path: (?P<path>/etc/sudoers\.d/\S+)\n\s+owner: (?P<owner>\S+)\n"
    r"\s+permissions: '(?P<mode>\d{4})'\n\s+content: \|\n\s+\$\{DEPLOY_SUDOERS\}\n"
)


class SeamError(Exception):
    """The constant or the drop-in entry could not be read from the cloud-init source."""


def host_line(source: Path) -> str:
    """Return the sudoers line cloud-init writes, read from its source, whole.

    Raises:
        SeamError: the source does not hold exactly one constant.
    """
    found: list[str] = _CONSTANT.findall(source.read_text(encoding="utf-8"))
    if len(found) != 1:
        message = f"{source.name} holds {len(found)} DEPLOY_SUDOERS constants, expected one"
        raise SeamError(message)
    return found[0]


def host_drop_in(source: Path) -> tuple[str, str, str]:
    """Return the path, owner and mode cloud-init gives the drop-in that holds the constant.

    Raises:
        SeamError: the source does not write that drop-in exactly once.
    """
    found = _DROP_IN.findall(source.read_text(encoding="utf-8"))
    if len(found) != 1:
        message = f"{source.name} writes the DEPLOY_SUDOERS drop-in {len(found)} times"
        raise SeamError(message)
    path, owner, mode = found[0]
    return path, owner, mode


def role_expectation(role: Path) -> tuple[str, str, str]:
    """Return the line, path and mode the role expects, resolved from its own variables."""
    variables = role_vars.load_vars(role)
    line = role_vars.resolve("{{ deploy_tooling_sudoers_line }}", variables)
    path = role_vars.resolve("{{ deploy_tooling_sudoers_path }}", variables)
    mode = role_vars.resolve("{{ deploy_tooling_sudoers_mode }}", variables)
    return line, path, mode


def seam_problems(source: Path, role: Path) -> list[str]:
    """Return every way the role's expected drop-in differs from the one cloud-init writes."""
    line, path, mode = role_expectation(role)
    host_path, owner, host_mode = host_drop_in(source)
    problems: list[str] = []
    if host_line(source) != line:
        problems.append(f"line: cloud-init writes {host_line(source)!r}, the role expects {line!r}")
    if host_path != path:
        problems.append(f"path: cloud-init writes {host_path}, the role expects {path}")
    if host_mode != mode:
        problems.append(f"mode: cloud-init writes {host_mode}, the role expects {mode}")
    if owner != "root:root":
        problems.append(f"owner: cloud-init writes {owner}, the role requires root:root")
    return problems


class TestSeam(unittest.TestCase):
    """The real files agree, and each way of changing one alone is found."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="deploy-tooling-seam-"))
        self.addCleanup(shutil.rmtree, self.work)
        self.source = self.work / "cloudInit.ts"
        shutil.copy(CLOUD_INIT, self.source)

    def altered(self, old: str, new: str) -> list[str]:
        text = self.source.read_text(encoding="utf-8")
        self.assertIn(old, text)
        self.source.write_text(text.replace(old, new, 1), encoding="utf-8")
        return seam_problems(self.source, role_vars.ROLE)

    def test_the_real_files_agree(self) -> None:
        self.assertEqual(seam_problems(CLOUD_INIT, role_vars.ROLE), [])

    def test_a_changed_wrapper_path_in_cloud_init_is_found(self) -> None:
        found = self.altered(
            "/usr/local/sbin/branchleft-deploy'", "/usr/local/bin/branchleft-deploy'"
        )
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("line: "))

    def test_a_changed_runas_is_found(self) -> None:
        found = self.altered("ALL=(root) NOPASSWD:", "ALL=(ALL) NOPASSWD:")
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("line: "))

    def test_an_added_tag_is_found(self) -> None:
        found = self.altered("NOPASSWD: /usr", "NOPASSWD:SETENV: /usr")
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("line: "))

    def test_a_changed_drop_in_path_is_found(self) -> None:
        found = self.altered(
            "/etc/sudoers.d/50-branchleft-deploy", "/etc/sudoers.d/51-branchleft-deploy"
        )
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("path: "))

    def test_a_changed_drop_in_mode_is_found(self) -> None:
        found = self.altered("permissions: '0440'", "permissions: '0644'")
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("mode: "))

    def test_a_changed_drop_in_owner_is_found(self) -> None:
        found = self.altered(
            "owner: root:root\n    permissions: '0440'",
            "owner: deploy:deploy\n    permissions: '0440'",
        )
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("owner: "))

    def test_a_second_constant_is_refused(self) -> None:
        text = self.source.read_text(encoding="utf-8")
        self.source.write_text(text + "const DEPLOY_SUDOERS = 'x';\n", encoding="utf-8")
        with self.assertRaises(SeamError):
            seam_problems(self.source, role_vars.ROLE)


if __name__ == "__main__":
    unittest.main()
