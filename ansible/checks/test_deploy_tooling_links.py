"""Checks that bind the deploy_tooling role to the programs and scripts it must agree with.

The role installs four programs read from `hetzner/provision/`, the single home of each (it
holds no copy and no link of them). Two hand-run scripts install the same files until they
are retired, so the role's paths and modes must match what those scripts install, and the
role's README carries no hostname or address (ANS-14). Each check is a function that returns
the problems it found, so the tests run it on the real tree (no problems) and on a broken
fixture (the problem).
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

import deploy_tooling_vars as role_vars

SCRIPTS = ("30-install-deploy-tooling.sh", "app-host-isolation.sh")
_ASSIGNMENT = re.compile(r"^(?P<name>[A-Z_]+)=(?P<value>/\S+)\s*$", re.MULTILINE)
_INSTALL_FILE = re.compile(
    r'^\s*install -m (?P<mode>\d{4}) -o root -g root "\$SCRIPT_DIR/(?P<src>[^"]+)"'
    r' "\$(?P<var>[A-Z_]+)"',
    re.MULTILINE,
)
_INSTALL_DIRS = re.compile(
    r"^install -d -m (?P<mode>\d{4}) -o root -g root (?P<paths>/\S+(?: /\S+)*)\s*$", re.MULTILINE
)
_ADDRESS = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOST_NAME = re.compile(r"\b(?:edge|ops|db|app|mx|lab|gw)\d+\b", re.IGNORECASE)
_URL = re.compile(r"https?://", re.IGNORECASE)
_PROGRAMS_DIR = "{{ role_path }}/../../../hetzner/provision"
_PROGRAMS_RELATIVE = Path("..") / ".." / ".." / "hetzner" / "provision"


def program_problems(role: Path, provision: Path) -> list[str]:
    """Return what is wrong with where the role reads its programs: the one home, no copy."""
    variables = role_vars.load_vars(role)
    problems: list[str] = []
    declared = variables.get("deploy_tooling_programs_dir")
    if declared != _PROGRAMS_DIR:
        problems.append(f"deploy_tooling_programs_dir is not {_PROGRAMS_DIR}")
    if (role / _PROGRAMS_RELATIVE).resolve() != provision.resolve():
        problems.append(
            "deploy_tooling_programs_dir does not reach hetzner/provision from the role"
        )
    for name in sorted({t.program for t in role_vars.targets(variables) if t.kind == "file"}):
        program = provision / name
        if program.is_symlink() or not program.is_file():
            problems.append(f"hetzner/provision/{name} is missing, or is not a regular file")
    files = role / "files"
    held = sorted(entry.name for entry in files.iterdir()) if files.is_dir() else []
    problems.extend(
        f"files/{name} is held under the role, where hetzner/provision is the only home"
        for name in held
    )
    return problems


def _script_installs(
    script: Path,
) -> tuple[dict[str, str], dict[str, tuple[str, str]], dict[str, str]]:
    """Return a script's path variables, its file installs, and its directories by mode."""
    text = script.read_text(encoding="utf-8")
    paths = {m["name"]: m["value"] for m in _ASSIGNMENT.finditer(text)}
    files = {
        paths[m["var"]]: (m["mode"], m["src"])
        for m in _INSTALL_FILE.finditer(text)
        if m["var"] in paths
    }
    directories: dict[str, str] = {}
    for found in _INSTALL_DIRS.finditer(text):
        for path in found["paths"].split():
            directories[path] = found["mode"]
    return paths, files, directories


def agreement_problems(role: Path, provision: Path) -> list[str]:
    """Return each place a hand script installs a path, mode or source the role does not."""
    variables = role_vars.load_vars(role)
    by_path = {t.path: t for t in role_vars.targets(variables)}
    problems: list[str] = []
    seen: set[str] = set()
    for name in SCRIPTS:
        _, files, directories = _script_installs(provision / name)
        for path, (mode, src) in sorted(files.items()):
            target = by_path.get(path)
            if target is None:
                problems.append(f"{name} installs {path}, which the role does not")
                continue
            seen.add(path)
            if target.mode.lstrip("0") != mode.lstrip("0"):
                problems.append(f"{name} installs {path} with mode {mode}, the role {target.mode}")
            if target.program != src:
                problems.append(
                    f"{name} installs {path} from {src}, the role from {target.program}"
                )
        for path, mode in sorted(directories.items()):
            target = by_path.get(path)
            if target is None:
                problems.append(f"{name} creates {path}, which the role does not")
                continue
            seen.add(path)
            if target.mode.lstrip("0") != mode.lstrip("0"):
                problems.append(f"{name} creates {path} with mode {mode}, the role {target.mode}")
    problems.extend(
        f"no hand script installs {path}, which the role installs"
        for path in sorted(set(by_path) - seen)
    )
    return problems


def readme_problems(readme: Path) -> list[str]:
    """Return what in a README names a host, an address or a link (ANS-14)."""
    text = readme.read_text(encoding="utf-8")
    found = [f"address {m.group(0)}" for m in _ADDRESS.finditer(text)]
    found.extend(f"host name {m.group(0)}" for m in _HOST_NAME.finditer(text))
    found.extend(f"link {m.group(0)}" for m in _URL.finditer(text))
    return found


class TestRealTree(unittest.TestCase):
    """The repository as it stands has none of the problems."""

    def test_every_program_is_read_from_the_one_home_and_none_is_held(self) -> None:
        self.assertEqual(program_problems(role_vars.ROLE, role_vars.PROVISION), [])

    def test_the_role_and_the_hand_scripts_install_the_same_paths_and_modes(self) -> None:
        self.assertEqual(agreement_problems(role_vars.ROLE, role_vars.PROVISION), [])

    def test_the_readme_names_no_host_or_address(self) -> None:
        self.assertEqual(readme_problems(role_vars.ROLE / "README.md"), [])


class TestControls(unittest.TestCase):
    """Each way of breaking the binding is found, in a copy of the tree."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="deploy-tooling-links-"))
        self.addCleanup(shutil.rmtree, self.work)
        self.provision = self.work / "hetzner" / "provision"
        self.role = self.work / "ansible" / "roles" / "deploy_tooling"
        self.provision.mkdir(parents=True)
        (self.role / "vars").mkdir(parents=True)
        shutil.copy(role_vars.ROLE / "vars" / "main.yml", self.role / "vars" / "main.yml")
        for script in SCRIPTS:
            shutil.copy(role_vars.PROVISION / script, self.provision / script)
        for target in role_vars.targets(role_vars.load_vars()):
            if target.kind == "file":
                shutil.copy(role_vars.PROVISION / target.program, self.provision / target.program)

    def test_the_fixture_tree_is_clean(self) -> None:
        self.assertEqual(program_problems(self.role, self.provision), [])
        self.assertEqual(agreement_problems(self.role, self.provision), [])

    def test_a_byte_copy_held_under_the_role_is_found(self) -> None:
        (self.role / "files").mkdir()
        shutil.copy(self.provision / "branchleft_deploy.py", self.role / "files")
        found = program_problems(self.role, self.provision)
        self.assertEqual(
            found,
            [
                "files/branchleft_deploy.py is held under the role,"
                " where hetzner/provision is the only home"
            ],
        )

    def test_a_link_held_under_the_role_is_found(self) -> None:
        (self.role / "files").mkdir()
        (self.role / "files" / "branchleft_deploy.py").symlink_to(
            self.provision / "branchleft_deploy.py"
        )
        found = program_problems(self.role, self.provision)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("files/branchleft_deploy.py is held under the role"))

    def test_a_programs_directory_that_is_not_the_home_is_found(self) -> None:
        variables = self.role / "vars" / "main.yml"
        text = variables.read_text(encoding="utf-8")
        variables.write_text(text.replace("/../../../hetzner/provision", "/files"), "utf-8")
        found = program_problems(self.role, self.provision)
        self.assertEqual(found, [f"deploy_tooling_programs_dir is not {_PROGRAMS_DIR}"])

    def test_a_missing_program_is_found(self) -> None:
        (self.provision / "branchleft_deploy.py").unlink()
        found = program_problems(self.role, self.provision)
        self.assertEqual(
            found, ["hetzner/provision/branchleft_deploy.py is missing, or is not a regular file"]
        )

    def test_a_layout_the_relative_path_does_not_reach_is_found(self) -> None:
        elsewhere = self.work / "elsewhere"
        elsewhere.mkdir()
        found = program_problems(self.role, elsewhere)
        self.assertIn(
            "deploy_tooling_programs_dir does not reach hetzner/provision from the role", found
        )

    def test_a_script_that_installs_another_mode_is_found(self) -> None:
        script = self.provision / "30-install-deploy-tooling.sh"
        text = script.read_text(encoding="utf-8")
        script.write_text(text.replace("install -m 0755", "install -m 0775"), encoding="utf-8")
        found = agreement_problems(self.role, self.provision)
        self.assertEqual(
            found,
            [
                "30-install-deploy-tooling.sh installs /usr/local/sbin/branchleft-deploy"
                " with mode 0775, the role 0755"
            ],
        )

    def test_a_script_that_installs_another_path_is_found(self) -> None:
        script = self.provision / "app-host-isolation.sh"
        text = script.read_text(encoding="utf-8")
        moved = text.replace("RECONCILER=/usr/local/sbin/", "RECONCILER=/usr/local/bin/")
        script.write_text(moved, encoding="utf-8")
        found = agreement_problems(self.role, self.provision)
        self.assertIn(
            "app-host-isolation.sh installs /usr/local/bin/branchleft-docker-user-policy,"
            " which the role does not",
            found,
        )

    def test_a_role_target_no_script_installs_is_found(self) -> None:
        script = self.provision / "app-host-isolation.sh"
        text = script.read_text(encoding="utf-8")
        script.write_text(text.replace('"$UNIT"', '"$UNITS"'), encoding="utf-8")
        found = agreement_problems(self.role, self.provision)
        self.assertEqual(
            found,
            [
                "no hand script installs /etc/systemd/system/branchleft-docker-user-policy.service,"
                " which the role installs"
            ],
        )

    def test_a_readme_with_an_address_a_host_or_a_link_is_found(self) -> None:
        readme = self.work / "README.md"
        readme.write_text("The gateway is 10.20.1.10; see edge1 and https://example.org.\n")
        self.assertEqual(
            readme_problems(readme),
            ["address 10.20.1.10", "host name edge1", "link https://"],
        )


if __name__ == "__main__":
    unittest.main()
