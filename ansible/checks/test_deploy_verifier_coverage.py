"""Check that the deploy verifier is applied before every role that runs the deploy wrapper.

The deploy wrapper refuses a registered image unless the verifier and its pinned gh are on the host.
A host that runs the wrapper with no verifier refuses every registered deploy, so the role that
installs the verifier has to be applied on each such host, and before the first role that runs the
wrapper. This file holds that to three things:

  * the table of wrapper roles is complete: any other role that names the wrapper's path in its
    tasks, vars or defaults fails here until it is added to the table;
  * every playbook that applies a wrapper role applies deploy_verifier earlier in the same play, and
    exactly the listed wrapper hosts apply a wrapper role at all;
  * the paths the wrapper reads and the pins the role installs agree, and the pins sit in vars/
    where no caller can override them.

The role's pins are read from vars/main.yml. The wrapper's constants are read from
hetzner/provision/branchleft_deploy.py as text, so this test does not import the program.
"""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
PLAYBOOKS = ROOT / "ansible" / "playbooks"
WRAPPER = ROOT / "hetzner" / "provision" / "branchleft_deploy.py"

WRAPPER_PATH = "/usr/local/sbin/branchleft-deploy"
VERIFIER_ROLE = "deploy_verifier"

# The roles that run the deploy wrapper, or name its path in what they install or run. A role that
# names the path and is not here fails test_every_role_naming_the_wrapper_is_in_the_table.
WRAPPER_ROLES = frozenset(
    {
        "deploy_tooling",
        "control_plane",
        "db1_stack",
        "website_app1",
        "publicpress_website_app1",
        "db_t1",
    }
)

# The hosts that run the wrapper, one playbook each. Another host that applies a wrapper role
# fails test_only_the_listed_wrapper_hosts_apply_a_wrapper_role until it is listed here.
WRAPPER_PLAYBOOKS = frozenset({"edge1", "app1", "ops1", "db1", "dbt1", "appt1"})

PINS = (
    "deploy_verifier_gh_version",
    "deploy_verifier_gh_sha256",
    "deploy_verifier_gh_download_url",
)


def load_vars(path: Path) -> dict[str, str]:
    """Return a role's vars or defaults file as a mapping, empty when the file is empty."""
    loaded: dict[str, str] | None = yaml.safe_load(path.read_text(encoding="utf-8"))
    return loaded or {}


def load_plays(path: Path) -> list[dict[str, list[str | dict[str, str]]]]:
    """Return the plays of a playbook."""
    loaded: list[dict[str, list[str | dict[str, str]]]] | None = yaml.safe_load(
        path.read_text(encoding="utf-8")
    )
    return loaded or []


def playbook_roles(path: Path) -> list[list[str]]:
    """Return the role names of each play in a playbook, in the order the play applies them."""
    plays = []
    for play in load_plays(path):
        names = []
        for entry in play.get("roles") or []:
            value = entry.get("role") if isinstance(entry, dict) else entry
            if value:
                names.append(Path(str(value)).name)
        plays.append(names)
    return plays


def roles_naming_wrapper(roles_dir: Path) -> set[str]:
    """Return the roles whose tasks, vars or defaults name the wrapper's literal path."""
    named = set()
    for role in roles_dir.iterdir():
        if not role.is_dir() or role.name == VERIFIER_ROLE:
            continue
        for sub in ("tasks", "vars", "defaults"):
            directory = role / sub
            if not directory.is_dir():
                continue
            for path in directory.rglob("*.yml"):
                if WRAPPER_PATH in path.read_text(encoding="utf-8"):
                    named.add(role.name)
    return named


def findings_for(name: str, roles: list[str]) -> list[str]:
    """Return one finding per play that applies a wrapper role without the verifier first."""
    wrapper = [role for role in roles if role in WRAPPER_ROLES]
    if not wrapper:
        return []
    if VERIFIER_ROLE not in roles:
        return [f"{name} applies {wrapper[0]} and never applies {VERIFIER_ROLE}"]
    if roles.index(VERIFIER_ROLE) > roles.index(wrapper[0]):
        return [f"{name} applies {VERIFIER_ROLE} after {wrapper[0]}"]
    return []


def wrapper_constant(text: str, name: str) -> str:
    match = re.search(rf'^{name} = "([^"]+)"', text, re.MULTILINE)
    if match is None:
        message = f"{name} is not a string constant in branchleft_deploy.py"
        raise AssertionError(message)
    return match.group(1)


class VerifierCoverageTests(unittest.TestCase):
    def test_the_wrapper_roles_are_real_roles(self) -> None:
        for role in WRAPPER_ROLES:
            self.assertTrue((ROLES / role).is_dir(), f"{role} is in the table but not a role")

    def test_every_role_naming_the_wrapper_is_in_the_table(self) -> None:
        named = roles_naming_wrapper(ROLES)
        self.assertEqual(
            named - WRAPPER_ROLES,
            set(),
            "these roles name the deploy wrapper in tasks, vars or defaults and are not in "
            "WRAPPER_ROLES, so the verifier is not required before them",
        )

    def test_only_the_listed_wrapper_hosts_apply_a_wrapper_role(self) -> None:
        applying = set()
        for path in sorted(PLAYBOOKS.glob("*.yml")):
            for names in playbook_roles(path):
                if WRAPPER_ROLES & set(names):
                    applying.add(path.stem)
        self.assertEqual(applying, set(WRAPPER_PLAYBOOKS))

    def test_the_playbooks_that_apply_a_wrapper_role_apply_the_verifier_first(self) -> None:
        findings = []
        for path in sorted(PLAYBOOKS.glob("*.yml")):
            for names in playbook_roles(path):
                findings.extend(findings_for(path.stem, names))
        self.assertEqual(findings, [])

    def test_a_playbook_applying_a_wrapper_role_without_the_verifier_is_a_finding(self) -> None:
        self.assertEqual(
            findings_for("ops1", ["host_inputs", "control_plane"]),
            ["ops1 applies control_plane and never applies deploy_verifier"],
        )

    def test_a_verifier_applied_after_the_wrapper_role_is_a_finding(self) -> None:
        self.assertEqual(
            findings_for("app1", ["website_app1", "deploy_verifier"]),
            ["app1 applies deploy_verifier after website_app1"],
        )

    def test_a_verifier_applied_before_the_wrapper_role_is_no_finding(self) -> None:
        self.assertEqual(
            findings_for("app1", ["deploy_verifier", "website_app1", "deploy_tooling"]), []
        )

    def test_the_wrapper_and_the_role_agree_on_the_paths_they_share(self) -> None:
        text = WRAPPER.read_text(encoding="utf-8")
        variables = load_vars(ROLES / VERIFIER_ROLE / "vars" / "main.yml")
        self.assertEqual(
            wrapper_constant(text, "VERIFIER"), variables["deploy_verifier_verifier_path"]
        )
        self.assertEqual(
            wrapper_constant(text, "VERIFIER_GH_DIR"), variables["deploy_verifier_gh_dir"]
        )
        self.assertEqual(wrapper_constant(text, "VERIFIER_HOME"), variables["deploy_verifier_home"])
        self.assertEqual(
            f"{variables['deploy_verifier_gh_dir']}/gh", variables["deploy_verifier_gh_bin"]
        )

    def test_the_wrapper_and_the_role_agree_on_the_offline_paths(self) -> None:
        text = WRAPPER.read_text(encoding="utf-8")
        variables = load_vars(ROLES / VERIFIER_ROLE / "vars" / "main.yml")
        self.assertEqual(
            wrapper_constant(text, "OFFLINE_TRUSTED_ROOT"),
            variables["deploy_verifier_trusted_root_path"],
        )
        self.assertEqual(
            wrapper_constant(text, "OFFLINE_STAGING_DIR"), variables["deploy_verifier_staging_dir"]
        )
        self.assertEqual(
            f"{variables['deploy_verifier_trusted_root_dir']}/trusted_root.jsonl",
            variables["deploy_verifier_trusted_root_path"],
        )

    def test_the_trusted_root_pin_is_the_sha256_of_the_file_the_role_installs(self) -> None:
        variables = load_vars(ROLES / VERIFIER_ROLE / "vars" / "main.yml")
        installed = ROLES / VERIFIER_ROLE / "files" / "trusted_root.jsonl"
        self.assertEqual(
            hashlib.sha256(installed.read_bytes()).hexdigest(),
            variables["deploy_verifier_trusted_root_sha256"],
        )

    def test_offline_verification_is_off_by_default_and_its_pin_cannot_be_overridden(self) -> None:
        defaults = load_vars(ROLES / VERIFIER_ROLE / "defaults" / "main.yml")
        self.assertIs(defaults["deploy_verifier_offline"], False)
        for pin in (
            "deploy_verifier_trusted_root_sha256",
            "deploy_verifier_trusted_root_src",
            "deploy_verifier_trusted_root_path",
            "deploy_verifier_staging_dir",
        ):
            self.assertNotIn(pin, defaults, f"{pin} is a default, so an inventory can override it")

    def test_the_pins_agree_with_one_another_and_sit_in_vars(self) -> None:
        variables = load_vars(ROLES / VERIFIER_ROLE / "vars" / "main.yml")
        version = variables["deploy_verifier_gh_version"]
        self.assertRegex(version, r"\A[0-9]+[.][0-9]+[.][0-9]+\Z")
        self.assertRegex(variables["deploy_verifier_gh_sha256"], r"\Asha256:[0-9a-f]{64}\Z")
        self.assertEqual(
            variables["deploy_verifier_gh_download_url"],
            f"https://github.com/cli/cli/releases/download/v{version}/"
            f"gh_{version}_linux_amd64.tar.gz",
        )
        defaults = load_vars(ROLES / VERIFIER_ROLE / "defaults" / "main.yml")
        for pin in PINS:
            self.assertNotIn(pin, defaults, f"{pin} is a default, so an inventory can override it")

    def test_the_role_holds_no_copy_of_the_verifier(self) -> None:
        copies = list((ROLES / VERIFIER_ROLE).rglob("branchleft-verify-image"))
        self.assertEqual(copies, [])

    def test_the_role_copies_the_verifier_from_hetzner_provision(self) -> None:
        # The verifier's own bytes are pinned by digest in test_branchleft_deploy.py. This holds
        # only that the role reads that one file from its home, and does not hold its own copy.
        source = (ROLES / VERIFIER_ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("{{ deploy_verifier_programs_dir }}/branchleft-verify-image", source)


if __name__ == "__main__":
    unittest.main()
