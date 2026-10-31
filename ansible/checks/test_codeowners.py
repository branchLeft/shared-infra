"""Tests that the files which judge or gate a merge or a deploy are the owner's in CODEOWNERS.

This reads .github/CODEOWNERS the way GitHub does (the last matching line wins) and fails
when a file that must be the owner's is not. It covers the standards template's lines being
the file's final lines (SYNC-1), the estate and gate files, the pull-role paths, and the pin
gate's install program (check_pins.py loads the lock reader from it and keeps no copy), and
that a host playbook is not the owner's, and that every Ansible loader directory, and a bare
file or symlink of its name, is the owner's at each level it can sit in.
"""

from __future__ import annotations

import importlib
import unittest
from pathlib import Path

import check_pins
import pathspec

ROOT = Path(__file__).resolve().parents[2]
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
OWNER = "@branchLeft/branchleft-admin"
INSTALL_PROGRAM = "ansible/roles/ansible_runtime/files/install_runtime.py"
# The loader directories ansible-core searches, derived from the installed ansible-core rather
# than typed here, so a loader a bump adds is missing from this set until its lines are in
# CODEOWNERS. collections is not a loader subdirectory; Ansible's collection finder looks only at
# the top and playbook levels, so it is listed there and nowhere deeper.
LOADER_DIRS: frozenset[str] = frozenset(
    loader.subdir
    for _, loader in importlib.import_module("ansible.plugins.loader").get_all_plugin_loaders()
    if loader.subdir
)
COLLECTIONS_DIR = "collections"

# The lines of branchLeft/standards templates/codeowners at the tag the Standards job is pinned
# to (.github/workflows/standards.yml). SYNC-1 requires them, unchanged and in order, as the
# final lines of CODEOWNERS. A pin bump to a tag whose template differs changes this list too.
STANDARDS_TEMPLATE = [
    ("/.standardsignore", [OWNER]),
    ("/.standards.mode", [OWNER]),
    ("/.docs-lint*", [OWNER]),
    ("/tools/floors.tsv", [OWNER]),
    ("/.standards-db-tooling", [OWNER]),
    ("/.github/", [OWNER]),
]

# Estate files the merge script refuses at gate 6: mail/ runs under plan credentials, and every
# credentialed plan job installs from these lockfiles, pnpm-workspace.yaml files and .npmrc files.
# A directory path stands for a file under it.
ESTATE_PATHS = [
    "mail/index.ts",
    "pnpm-lock.yaml",
    "hetzner/pnpm-lock.yaml",
    "hetzner-host/pnpm-lock.yaml",
    "hetzner/pnpm-workspace.yaml",
    "hetzner-host/pnpm-workspace.yaml",
    ".npmrc",
    "hetzner/.npmrc",
    "hetzner-host/.npmrc",
]

# Gate files the CODEOWNERS header says judge a merge or a deploy: the review rule, the CI gate
# scripts, the guard and deploy-account files, the named gates, the coverage and hook configs,
# and the Ansible floors and harness.
GATE_PATHS = [
    ".github/CODEOWNERS",
    ".github/workflows/ci.yml",
    "scripts/assert-no-hetzner-deletes.py",
    "hetzner/scripts/anything.sh",
    "hetzner/projectGuard.ts",
    "hetzner/projectGuard.test.ts",
    "hetzner/dns.guard.test.ts",
    "hetzner/tenants.guard.test.ts",
    "hetzner/provision/branchleft_deploy.py",
    "hetzner/provision/test_branchleft_deploy.py",
    "hetzner/provision/provision_deploy_slot.py",
    "hetzner/provision/test_provision_deploy_slot.py",
    "hetzner/provision/30-install-deploy-tooling.sh",
    "hetzner/dns/zonecheck.py",
    "hetzner/dns/test_zonecheck.py",
    "hetzner/provision/test_suite_size.py",
    "hetzner/vitest.config.ts",
    "hetzner-host/vitest.config.ts",
    ".pre-commit-config.yaml",
    ".prettierignore",
    ".ansible-lint",
    ".yamllint",
    "ansible/harness/anything.py",
    "ansible/pyproject.toml",
    "ansible/requirements.in",
    "ansible/requirements.txt",
    "ansible/requirements.yml",
    "ansible/checks/check_pins.py",
    "ansible/checks/test_codeowners.py",
    "ansible/checks/pip-requirements.txt",
    "ansible/trust/edge1.yml",
]

# The pull roles are the owner's alone (owner ruling pull-roles-owner-only, 2026-10-21):
# pull_trigger decides which signed commits a host applies as root, ansible_runtime installs
# the Ansible that runs as root, and the broker deploy role's sudoers files decide what the
# deploy user may run as root.
PULL_ROLE_PATHS = [
    "ansible/roles/pull_trigger/tasks/main.yml",
    "ansible/roles/pull_trigger/README.md",
    INSTALL_PROGRAM,
    "ansible/roles/ansible_runtime/README.md",
    "ansible/roles/ansible_runtime/tasks/main.yml",
    "ansible/roles/broker_deploy/tasks/_sudoers.yml",
    "ansible/roles/broker_deploy/templates/branchleft-slot.sudoers.j2",
    "ansible/roles/deploy_slot_keys/tasks/main.yml",
    "ansible/roles/deploy_slot_keys/library/deploy_slot_keys_reconcile.py",
    "ansible/roles/deploy_slot_keys/tests/unit/test_deploy_slot_keys_reconcile.py",
    "ansible/roles/deploy_slot_keys/README.md",
    "ansible/checks/test_deploy_slot_keys_single_home.py",
]

# The loader of every pulled host's private role inputs is the owner's alone (owner ruling,
# option A): its tasks, its per-host rows, its molecule proof of the
# refusals, and its README all sit under one path.
HOST_INPUTS_PATHS = [
    "ansible/roles/host_inputs/tasks/main.yml",
    "ansible/roles/host_inputs/vars/main.yml",
    "ansible/roles/host_inputs/meta/argument_specs.yml",
    "ansible/roles/host_inputs/molecule/default/verify.yml",
    "ansible/roles/host_inputs/README.md",
]

# ci_login grants the pipeline account root-run sudo and writes its authorized_keys; the owner's
# values for edge1's roles are in owner_vars. Both are the owner's alone.
CI_LOGIN_PATHS = [
    "ansible/roles/ci_login/tasks/main.yml",
    "ansible/roles/ci_login/tasks/_sudoers.yml",
    "ansible/roles/ci_login/tasks/_keys.yml",
    "ansible/roles/ci_login/templates/authorized_keys.j2",
    "ansible/roles/ci_login/vars/main.yml",
    "ansible/owner_vars/edge1.yml",
]

# Files merged on the reviewer App's approval alone, so that a matcher that called everything
# owned would be seen. A host playbook is among them: the reviewer App may wire a listed role
# into one (owner ruling of 2026-10-25), and the per-host role list
# under ansible/checks/ is what is owner-only.
UNOWNED_PATHS = [
    "ansible/playbooks/app1.yml",
    "ansible/playbooks/edge1.yml",
    "ansible/roles/host_baseline/tasks/main.yml",
    "ansible/roles/broker_deploy/tasks/main.yml",
    "ansible/roles/broker_deploy/templates/broker.env.j2",
]


def parse_rules(text: str) -> list[tuple[str, list[str]]]:
    """Return each line of a CODEOWNERS file as its pattern and its owners, in file order."""
    rules: list[tuple[str, list[str]]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pattern, *owners = line.split()
        rules.append((pattern, owners))
    return rules


def owners_of(path: str, rules: list[tuple[str, list[str]]]) -> list[str]:
    """Return the owners of ``path``: those of the last rule that matches it, or none."""
    owners: list[str] = []
    for pattern, rule_owners in rules:
        if pathspec.GitIgnoreSpec.from_lines([pattern]).match_file(path):
            owners = rule_owners
    return owners


class CodeownersTests(unittest.TestCase):
    """The owner's files are the owner's, and the matcher can tell an owned file from not."""

    def setUp(self) -> None:
        self.rules = parse_rules(CODEOWNERS.read_text(encoding="utf-8"))

    def assert_owned(self, paths: list[str]) -> None:
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual([OWNER], owners_of(path, self.rules))

    def test_the_install_program_is_owned_by_the_owner(self) -> None:
        self.assertEqual([OWNER], owners_of(INSTALL_PROGRAM, self.rules))

    def test_the_program_is_the_file_check_pins_loads(self) -> None:
        # The path above is the one the gate reads, so the owner line cannot name another file.
        self.assertEqual(INSTALL_PROGRAM, check_pins.RUNTIME_PROGRAM.relative_to(ROOT).as_posix())

    def test_the_standards_template_lines_are_the_final_lines(self) -> None:
        # SYNC-1: the template's lines, unchanged and in order, end the file. Any line after
        # or between them can take ownership back, because the last matching line wins.
        self.assertEqual(STANDARDS_TEMPLATE, self.rules[-len(STANDARDS_TEMPLATE) :])

    def test_the_estate_files_are_owned_by_the_owner(self) -> None:
        self.assert_owned(ESTATE_PATHS)

    def test_the_gate_files_are_owned_by_the_owner(self) -> None:
        self.assert_owned(GATE_PATHS)

    def test_the_pull_roles_and_sudoers_files_are_owned_by_the_owner(self) -> None:
        self.assert_owned(PULL_ROLE_PATHS)

    def test_the_host_inputs_loader_is_owned_by_the_owner(self) -> None:
        self.assert_owned(HOST_INPUTS_PATHS)

    def test_the_ci_login_role_and_the_owner_vars_are_owned_by_the_owner(self) -> None:
        self.assert_owned(CI_LOGIN_PATHS)

    def test_the_standards_template_paths_are_owned_by_the_owner(self) -> None:
        self.assert_owned(
            [
                ".standardsignore",
                ".standards.mode",
                ".docs-lint.mode",
                ".docs-lintignore",
                "tools/floors.tsv",
                ".standards-db-tooling",
                ".github/workflows/standards.yml",
            ]
        )

    def test_a_host_playbook_and_ordinary_role_files_are_not_the_owners(self) -> None:
        for path in UNOWNED_PATHS:
            with self.subTest(path=path):
                self.assertEqual([], owners_of(path, self.rules))

    def test_every_listed_file_exists(self) -> None:
        # A path typed wrongly in CODEOWNERS owns nothing and nothing says so. The sample
        # paths that stand for a directory or a wildcard are not files on disk.
        stands_for_more = {
            "mail/index.ts",
            "hetzner/scripts/anything.sh",
            "ansible/harness/anything.py",
        }
        owned = PULL_ROLE_PATHS + HOST_INPUTS_PATHS + CI_LOGIN_PATHS
        for path in ESTATE_PATHS + GATE_PATHS + owned + UNOWNED_PATHS:
            if path in stands_for_more:
                continue
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).exists(), path)

    def test_the_host_role_lists_and_their_check_are_the_owners(self) -> None:
        # The list decides which roles a pulled playbook may run as root, so only the owner
        # merges an edit to it, to the check that reads it, or to the tests that hold the check.
        for path in (
            "ansible/checks/host_roles.yml",
            "ansible/checks/check_enrolment.py",
            "ansible/checks/test_check_host_roles.py",
        ):
            with self.subTest(path=path):
                self.assertEqual([OWNER], owners_of(path, self.rules))

    def test_the_loader_names_are_derived_from_ansible_core(self) -> None:
        # An empty or partial derivation must not pass, so four names every Ansible install has
        # are asserted by name as well as by count.
        self.assertGreaterEqual(len(LOADER_DIRS), 19)
        for name in ("library", "module_utils", "filter_plugins", "doc_fragments"):
            self.assertIn(name, LOADER_DIRS)

    def test_every_loader_line_the_derivation_implies_is_in_codeowners(self) -> None:
        patterns = {pattern for pattern, _ in self.rules}
        top_and_playbooks = LOADER_DIRS | {COLLECTIONS_DIR}
        expected = {"/ansible/ansible.cfg"}
        # No trailing slash: a pattern with one matches a directory only, so a symlink (a file
        # in git) named like a loader directory would be unowned while Ansible follows it.
        expected |= {f"/ansible/{name}" for name in top_and_playbooks}
        expected |= {f"/ansible/playbooks/{name}" for name in top_and_playbooks}
        expected |= {f"/ansible/playbooks/**/{name}" for name in LOADER_DIRS}
        expected |= {f"/ansible/roles/*/{name}" for name in LOADER_DIRS}
        self.assertEqual([], sorted(expected - patterns))

    def test_each_loader_directory_is_owned_at_every_level(self) -> None:
        for name in sorted(LOADER_DIRS | {COLLECTIONS_DIR}):
            self.assert_owned([f"ansible/{name}/x.py", f"ansible/playbooks/{name}/x.py"])
        for name in sorted(LOADER_DIRS):
            self.assert_owned(
                [f"ansible/playbooks/includes/{name}/x.py", f"ansible/roles/r/{name}/x.py"]
            )
        self.assert_owned(["ansible/ansible.cfg"])

    def test_a_bare_file_named_like_a_loader_directory_is_owned_at_every_level(self) -> None:
        # A symlink committed as library, filter_plugins and so on is a file in git, and Ansible
        # follows it to a directory it loads code from, so the bare name is the owner's too.
        for name in sorted(LOADER_DIRS | {COLLECTIONS_DIR}):
            self.assert_owned([f"ansible/{name}", f"ansible/playbooks/{name}"])
        for name in sorted(LOADER_DIRS):
            self.assert_owned([f"ansible/playbooks/includes/{name}", f"ansible/roles/r/{name}"])
        self.assert_owned(["ansible/roles/x/library", "ansible/playbooks/filter_plugins"])

    def test_the_paths_beside_a_loader_directory_stay_unowned(self) -> None:
        # A molecule scenario's library, a directory that is not a loader and a role's tasks are
        # ordinary work and stay on the reviewer App's approval.
        for path in (
            "ansible/roles/r/molecule/default/library/x.py",
            "ansible/patterns/typed_module/library/x.py",
            "ansible/roles/r/tasks/main.yml",
            "ansible/library.md",
        ):
            with self.subTest(path=path):
                self.assertEqual([], owners_of(path, self.rules))

    def test_the_last_matching_line_wins(self) -> None:
        rules = [("/a/", [OWNER]), ("/a/b.py", ["@someone-else"])]
        self.assertEqual(["@someone-else"], owners_of("a/b.py", rules))
        self.assertEqual([OWNER], owners_of("a/c.py", rules))
        self.assertEqual([], owners_of("z/c.py", rules))


if __name__ == "__main__":
    unittest.main()
