"""Tests that the files which judge or gate a merge or a deploy are the owner's in CODEOWNERS.

This reads .github/CODEOWNERS the way GitHub does (the last matching line wins; the matcher is
codeowners_match.py) and fails when a file that must be the owner's is not, or when a released
file is. It covers the standards template's lines being the file's final lines (SYNC-1), the
estate, gate, access and mail files, the pull-role paths, the pin gate's install program
(check_pins.py loads the lock reader from it and keeps no copy), that every Ansible loader
directory, and a bare file or symlink of its name, is the owner's at each level it can sit in, that
a new file of a kept kind is the owner's before it is listed, and that documents, lockfiles, host
configuration and the tests of no gate are not.
"""

from __future__ import annotations

import importlib
import os
import unittest
from pathlib import Path

import check_pins
import pathspec
from codeowners_match import (
    CODEOWNERS,
    OWNER,
    PENDING,
    ROOT,
    SAMPLES,
    mismatches,
    owners_of,
    parse_rules,
)

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
    ("/.standards-db-tooling", [OWNER]),
    ("/.github/", [OWNER]),
]

# Install-time controls: every credentialed plan job installs with the registry token in its
# environment, so a package.json script or main, a pnpm-workspace.yaml allowBuilds list and an
# .npmrc decide what runs there, and the mail programs run under plan credentials. Lockfiles are
# released (UNOWNED_PATHS), so a dependency bump that touches package.json still reaches the owner.
# A directory path stands for a file under it.
ESTATE_PATHS = [
    "mail/index.ts",
    "package.json",
    "hetzner/package.json",
    "hetzner-host/package.json",
    "hetzner/pnpm-workspace.yaml",
    "hetzner-host/pnpm-workspace.yaml",
    ".npmrc",
    "hetzner/.npmrc",
    "hetzner-host/.npmrc",
    "tsconfig.json",
    "hetzner/tsconfig.json",
]

# The Pulumi programs and stack files that create billed resources, the DNS zone data, and the
# guard tests that stand over them. A program file is the owner's even when no test names it.
BILLED_PATHS = [
    "hetzner/estate.ts",
    "hetzner/network.ts",
    "hetzner/dns.ts",
    "hetzner/dnsZone.ts",
    "hetzner/egress.ts",
    "hetzner/index.ts",
    "hetzner/projects.ts",
    "hetzner/tenants.ts",
    "hetzner/tenants.structure.scan.ts",
    "hetzner/tenants.fixtures.ts",
    "hetzner/Pulumi.yaml",
    "hetzner/Pulumi.production.yaml",
    "hetzner/dns/Pulumi.yaml",
    "hetzner/estate/Pulumi.production.yaml",
    "hetzner/tenants/Pulumi.production.yaml",
    "hetzner/dns/zone.json",
    "hetzner/dns/publicpress.co.uk.json",
    "hetzner-host/host.ts",
    "hetzner-host/index.ts",
    "hetzner-host/cloudInit.ts",
    "hetzner-host/firewalls.ts",
    "hetzner-host/addressPlan.ts",
    "hetzner-host/enrolment.fixtures.ts",
    "hetzner-host/enrolment.test.ts",
    "hetzner-host/pullBootstrapFixed.json",
    "hetzner/estate.guard.test.ts",
    "hetzner/dns.guard.test.ts",
    "hetzner/tenants.guard.test.ts",
    "hetzner/tenants.structure.test.ts",
    "hetzner/edge/breakGlassToken.test.ts",
    "mail/Pulumi.yaml",
    "ovh/copy2/Pulumi.yaml",
    "ovh/copy2/index.ts",
    "ovh/copy2/probe/probe.py",
    "ovh/copy2/probe/test_probe.py",
]

# The mail host: mx1 is live production mail. The server's playbook, inventory and variables, the
# role that makes its credentials, and the mail programs are the owner's; only mail documents are
# released.
MAIL_PATHS = [
    "mail/provision/provision_mailboxes.py",
    "ansible/playbooks/mx1.yml",
    "ansible/inventories/production/hosts.yml",
    "ansible/roles/mail_reconcilers/tasks/main.yml",
]

# The launch page and the owner's words.
PUBLIC_PATHS = [
    "hetzner/edge/publicpressHolding.ts",
    "hetzner/edge/publicpress/index.html",
    "LICENSE",
    "hetzner-host/LICENSE",
    "CLAUDE.md",
]

# Gate files the CODEOWNERS header says judge a merge or a deploy: the review rule, the CI gate
# scripts, the guard and deploy-account files, the named gates, the coverage and hook configs,
# and the Ansible floors and harness.
GATE_PATHS = [
    ".github/CODEOWNERS",
    ".github/workflows/ci.yml",
    "scripts/assert-no-hetzner-deletes.py",
    "scripts/choose-apply-environment.py",
    "hetzner/scripts/anything.sh",
    "hetzner/scripts/check-crowdsec-hub-pin.py",
    "hetzner/projectGuard.ts",
    "hetzner/projectGuard.test.ts",
    "hetzner/dns.guard.test.ts",
    "hetzner/tenants.guard.test.ts",
    "hetzner/provision/branchleft_deploy.py",
    "hetzner/provision/test_branchleft_deploy.py",
    "hetzner/provision/provision_deploy_slot.py",
    "hetzner/provision/test_provision_deploy_slot.py",
    "hetzner/provision/test_suite_size.py",
    "hetzner/vitest.config.ts",
    "hetzner-host/vitest.config.ts",
    "ovh/copy2/projectGuard.ts",
    "ovh/copy2/projectGuard.test.ts",
    "ovh/copy2/configGuard.ts",
    "ovh/copy2/configGuard.test.ts",
    "ovh/copy2/stack.ts",
    "ovh/copy2/stack.test.ts",
    "ovh/copy2/vitest.config.ts",
    ".pre-commit-config.yaml",
    ".prettierignore",
    ".ansible-lint",
    ".yamllint",
    "ansible/harness/anything.py",
    "ansible/pyproject.toml",
    "ansible/checks/check_pins.py",
    "ansible/checks/check_delivery.py",
    "ansible/checks/merge_group_proof.py",
    "ansible/checks/shard_results.py",
    "ansible/checks/daily_red_issue.py",
    "ansible/checks/test_codeowners.py",
    "ansible/checks/codeowners_match.py",
    "ansible/checks/test_ci_watched_paths.py",
    "ansible/checks/test_no_new_script_dependents.py",
    "ansible/trust/edge1.yml",
    "hetzner/provision/branchleft-verify-image",
    "hetzner/provision/test_branchleft_verify_image.py",
    "hetzner/control-plane/stack/postgres/pg_hba.conf",
]

# The pull roles are the owner's alone (owner ruling pull-roles-owner-only, 2026-10-21):
# pull_trigger decides which signed commits a host applies as root, ansible_runtime installs
# the Ansible that runs as root, and the broker deploy role's sudoers files decide what the
# deploy user may run as root.
PULL_ROLE_PATHS = [
    "ansible/roles/pull_trigger/tasks/main.yml",
    INSTALL_PROGRAM,
    "ansible/roles/ansible_runtime/tasks/main.yml",
    "ansible/roles/broker_deploy/tasks/_sudoers.yml",
    "ansible/roles/broker_deploy/tasks/_admin_keys_dir.yml",
    "ansible/roles/broker_deploy/templates/branchleft-slot.sudoers.j2",
    "ansible/roles/deploy_slot_keys/tasks/main.yml",
    "ansible/roles/deploy_slot_keys/library/deploy_slot_keys_reconcile.py",
    "ansible/roles/deploy_slot_keys/tests/unit/test_deploy_slot_keys_reconcile.py",
    "ansible/checks/test_deploy_slot_keys_single_home.py",
]

# The loader of every pulled host's private role inputs is the owner's alone (owner ruling,
# option A): its tasks, its per-host rows and its molecule proof of the refusals all sit under
# one path.
HOST_INPUTS_PATHS = [
    "ansible/roles/host_inputs/tasks/main.yml",
    "ansible/roles/host_inputs/vars/main.yml",
    "ansible/roles/host_inputs/meta/argument_specs.yml",
    "ansible/roles/host_inputs/molecule/default/verify.yml",
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

# ci_jump writes the options of the jump account's key lines, which decide which private hosts
# the gated run may reach through edge1. The whole role is the owner's, its module and the molecule
# plays that prove the restriction included.
CI_JUMP_PATHS = [
    "ansible/roles/ci_jump/tasks/main.yml",
    "ansible/roles/ci_jump/tasks/_guards.yml",
    "ansible/roles/ci_jump/tasks/_keys.yml",
    "ansible/roles/ci_jump/tasks/_readback.yml",
    "ansible/roles/ci_jump/templates/authorized_keys.j2",
    "ansible/roles/ci_jump/vars/main.yml",
    "ansible/roles/ci_jump/library/ci_jump_authorized_keys.py",
    "ansible/roles/ci_jump/tests/unit/test_ci_jump_authorized_keys.py",
    "ansible/roles/ci_jump/molecule/default/verify.yml",
    "ansible/roles/ci_jump/molecule/refusals/converge.yml",
    "ansible/checks/test_ci_jump_pins.py",
]

# The owner-run writer of a host's inputs file runs as root, takes every input value and writes
# the file the loader reads, so it is the owner's alone. Its test holds the proofs of what it
# keeps secret, so the test is the owner's too.
SEEDING_TOOL_PATHS = [
    "ansible/tools/seed_host_inputs.py",
    "ansible/tools/test_seed_host_inputs.py",
]

# The three guards the demo1 root bootstrap runbook calls, their tests and the captured docker
# output the image gate reads. A weaker guard or a fixture edited to suit it would let the runbook
# go on, so these are the owner's alone.
BOOTSTRAP_GUARD_PATHS = [
    "ansible/tools/pubkey_only.py",
    "ansible/tools/test_pubkey_only.py",
    "ansible/tools/ci_key_line.py",
    "ansible/tools/test_ci_key_line.py",
    "ansible/tools/spool_image_gate.py",
    "ansible/tools/test_spool_image_gate.py",
    "ansible/tools/fixtures/docker-inspect-loaded-by-digest.json",
    "ansible/tools/fixtures/docker-inspect-absent.json",
]

# safety_channel_key and ring_controller_host each generate a signing key on ops1 as root, so each
# whole role is the owner's, its module, units, environment template and the tests that hold them
# included. The ring controller role also installs the unit that hands its root-only key to a
# service account, and safety_service installs the unit that mounts the channel key and the
# hash-source credential.
KEY_ROLE_PATHS = [
    "ansible/roles/safety_channel_key/tasks/main.yml",
    "ansible/roles/safety_channel_key/library/safety_channel_key.py",
    "ansible/roles/ring_controller_host/tasks/main.yml",
    "ansible/roles/ring_controller_host/vars/main.yml",
    "ansible/roles/ring_controller_host/meta/argument_specs.yml",
    "ansible/roles/ring_controller_host/library/ring_controller_host_record_key.py",
    "ansible/roles/ring_controller_host/files/ring-controller.service",
    "ansible/roles/ring_controller_host/files/ring-controller.timer",
    "ansible/roles/ring_controller_host/templates/ring-controller.env.j2",
    "ansible/roles/ring_controller_host/tests/unit/test_ring_controller_host_record_key.py",
    "ansible/roles/ring_controller_host/tests/unit/test_ring_controller_host_units.py",
    "ansible/roles/ring_controller_host/molecule/default/verify.yml",
    "ansible/roles/safety_service/tasks/main.yml",
    "ansible/roles/safety_service/vars/main.yml",
    "ansible/roles/safety_service/meta/argument_specs.yml",
    "ansible/roles/safety_service/files/content-safety.service",
    "ansible/roles/safety_service/templates/service.env.j2",
    "ansible/roles/safety_service/templates/config.json.j2",
    "ansible/roles/safety_service/tests/unit/test_safety_service.py",
    "ansible/roles/safety_service/molecule/default/verify.yml",
]

# Roles that write sshd, sudoers, authorized_keys, login accounts, database grants, a break-glass
# key or the verifier's trusted keys, and the files that hold what the deploy verifier accepts.
# These had no line before; each is the owner's whole role, or the named file of it.
ACCESS_PATHS = [
    "ansible/roles/db1_grants/tasks/main.yml",
    "ansible/roles/breakglass_grant_host/tasks/main.yml",
    "ansible/roles/breakglass_mint_host/tasks/main.yml",
    "ansible/roles/tunnel_account/tasks/main.yml",
    "ansible/roles/tunnel_account/tasks/_account.yml",
    "ansible/roles/host_baseline/tasks/_ssh.yml",
    "ansible/roles/host_baseline/files/01-branchleft-hardening.conf",
    "ansible/roles/demo1_build/files/judge_caddy_config.py",
    "ansible/roles/demo1_build/tests/unit/test_caddy_judge.py",
    "ansible/roles/demo1_build/files/ghost-platform/demo-host/provision/branchleft_slot.py",
    "ansible/roles/demo1_build/files/ghost-platform/demo-host/provision/render_slot_sudoers.py",
    "ansible/patterns/sudoers_and_keys/tasks/main.yml",
    "ansible/patterns/sudoers_and_keys/templates/authorized_keys.j2",
    "ansible/playbooks/includes/require_signers.yml",
    "ansible/playbooks/includes/pull_trigger_common.yml",
]

# Stopping or shortening a database backup: the dump and prune timers, and their units.
BACKUP_PATHS = [
    "ansible/roles/db1_backup_timers/tasks/main.yml",
    "ansible/roles/db1_backup_timers/files/units/branchleft-db-prune.timer",
    "ansible/roles/db1_backup_timers/files/units/branchleft-db-dump.service",
]

# The image-scan exemption file (SEC-5): each entry is an exception to the image scan, so each is
# the owner's to review. It arrives with the edge-caddy image change, so it need not exist yet.
IMAGE_SCAN_PATHS = [".image-scan-exemptions.json"]

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
    # Host configuration that reaches a host only through the gated apply: the edge stack, the
    # NAT gateway, the mx1 stack's role and the deploy tooling's wiring.
    "ansible/roles/edge_stack/tasks/main.yml",
    "ansible/roles/egress_nat/tasks/main.yml",
    "ansible/roles/mx1_stack/tasks/main.yml",
    "ansible/roles/deploy_tooling/tasks/main.yml",
    "ansible/roles/monitoring_stack/tasks/main.yml",
]

# Released documents: every markdown file, the owner's directories' included. CLAUDE.md is the
# one markdown file that is owned again, and the files under /.github/ are the standards lines'.
RELEASED_DOCUMENT_PATHS = [
    "README.md",
    "mail/RUNBOOK-mx1-provision.md",
    "ansible/checks/README.md",
    "ansible/trust/README.md",
    "ansible/roles/pull_trigger/README.md",
    "ansible/roles/ansible_runtime/README.md",
    "ansible/roles/deploy_slot_keys/README.md",
    "ansible/roles/host_inputs/README.md",
    "ansible/roles/ci_jump/README.md",
    "ansible/roles/safety_channel_key/README.md",
    "ansible/roles/ring_controller_host/README.md",
    "ansible/roles/safety_service/README.md",
    "hetzner/scripts/check-address-plan-drift.md",
    "scripts/assert-no-hetzner-deletes.md",
]

# Released lockfiles and version pins: every one is hash-locked or an exact pin, and the deep
# review of a bump belongs to the merge route, not to this file.
RELEASED_PIN_PATHS = [
    "pnpm-lock.yaml",
    "hetzner/pnpm-lock.yaml",
    "hetzner-host/pnpm-lock.yaml",
    "mail/pnpm-lock.yaml",
    "ovh/copy2/pnpm-lock.yaml",
    "ansible/requirements.in",
    "ansible/requirements.txt",
    "ansible/requirements.yml",
    "ansible/checks/pip-requirements.txt",
    "ovh/copy2/probe/requirements.txt",
    ".nvmrc",
    "hetzner/.nvmrc",
    "mail/.nvmrc",
]

# Released tests, checkers and probes: agreement tests of a role and a list that stay owned, Pulumi
# program tests, and checkers and probes that no job holding a secret runs.
RELEASED_CHECK_PATHS = [
    "hetzner/estate.test.ts",
    "hetzner/tenants.test.ts",
    "hetzner-host/host.test.ts",
    "hetzner-host/testdata/cloud-init-public.golden",
    "hetzner/dns/zonecheck.py",
    "hetzner/dns/test_zonecheck.py",
    "hetzner/scripts/probe-object-storage.py",
    "hetzner/scripts/test_probe_object_storage.py",
    "hetzner/scripts/check-address-plan-drift.py",
    "hetzner/scripts/test_check_address_plan_drift.py",
    "scripts/assert-min-python-version.py",
    "scripts/nvmrc-node-exec.sh",
    "ansible/checks/offline_render.py",
    "ansible/checks/test_offline_render.py",
    "ansible/checks/test_edge_single_home.py",
    "ansible/checks/test_mx1_stack_agree.py",
    "ansible/checks/test_deploy_tooling_links.py",
    "ansible/checks/test_ci_jump_hosts.py",
    "ansible/roles/db1_grants/molecule/default/verify.yml",
    "ansible/patterns/sudoers_and_keys/molecule/default/verify.yml",
]

# Paths named above that the repository does not hold yet: the launch page directory is listed
# before a file is in it. Samples that stand for a directory or a wildcard are not files on disk.
STANDS_FOR_MORE = {
    "mail/index.ts",
    "hetzner/scripts/anything.sh",
    "ansible/harness/anything.py",
    "hetzner/edge/publicpress/index.html",
}


def repository_files() -> list[str]:
    """Return every file in the checkout as a repo-relative path, outside .git and node_modules."""
    found: list[str] = []
    for directory, subdirectories, names in os.walk(ROOT):
        subdirectories[:] = [d for d in subdirectories if d not in {".git", "node_modules"}]
        found.extend(Path(directory, name).relative_to(ROOT).as_posix() for name in names)
    return sorted(found)


class CodeownersTests(unittest.TestCase):
    """The owner's files are the owner's, and the matcher can tell an owned file from not."""

    def setUp(self) -> None:
        self.rules = parse_rules(CODEOWNERS.read_text(encoding="utf-8"))

    def assert_owned(self, paths: list[str]) -> None:
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual([OWNER], owners_of(path, self.rules))

    def assert_unowned(self, paths: list[str]) -> None:
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual([], owners_of(path, self.rules))

    def test_the_install_program_is_owned_by_the_owner(self) -> None:
        self.assertEqual([OWNER], owners_of(INSTALL_PROGRAM, self.rules))

    def test_the_program_is_the_file_check_pins_loads(self) -> None:
        # The path above is the one the gate reads, so the owner line cannot name another file.
        self.assertEqual(INSTALL_PROGRAM, check_pins.RUNTIME_PROGRAM.relative_to(ROOT).as_posix())

    def test_the_standards_template_lines_are_the_final_lines(self) -> None:
        # SYNC-1: the template's lines, unchanged and in order, end the file. Any line after
        # or between them can take ownership back, because the last matching line wins.
        self.assertEqual(STANDARDS_TEMPLATE, self.rules[-len(STANDARDS_TEMPLATE) :])

    def test_every_sample_gets_the_answer_the_table_requires(self) -> None:
        # The fixed table in codeowners_match.py: a path for each class the owner keeps and each
        # class that is released. The command line prints the same rows for any CODEOWNERS file.
        self.assertEqual([], mismatches(self.rules))

    def test_the_samples_cover_every_kept_class_and_the_released_ones(self) -> None:
        # A table that lost a class would pass for a file that lost the class's line.
        classes = {sample.klass.split(":")[0] for sample in SAMPLES if sample.owned}
        for kept in (
            "rule",
            "gate",
            "trust",
            "access",
            "mail",
            "billed",
            "dns",
            "public",
            "backup",
        ):
            self.assertIn(kept, classes)
        self.assertTrue(any(sample.klass.startswith("loader") for sample in SAMPLES))
        self.assertGreaterEqual(sum(1 for sample in SAMPLES if not sample.owned), 8)

    def test_the_estate_files_are_owned_by_the_owner(self) -> None:
        self.assert_owned(ESTATE_PATHS)

    def test_the_billed_programs_and_stack_files_are_owned_by_the_owner(self) -> None:
        self.assert_owned(BILLED_PATHS)

    def test_the_mail_host_is_owned_by_the_owner(self) -> None:
        self.assert_owned(MAIL_PATHS)

    def test_the_launch_page_and_the_owners_words_are_owned_by_the_owner(self) -> None:
        self.assert_owned(PUBLIC_PATHS)

    def test_the_gate_files_are_owned_by_the_owner(self) -> None:
        self.assert_owned(GATE_PATHS)

    def test_the_pull_roles_and_sudoers_files_are_owned_by_the_owner(self) -> None:
        self.assert_owned(PULL_ROLE_PATHS)

    def test_the_host_inputs_loader_is_owned_by_the_owner(self) -> None:
        self.assert_owned(HOST_INPUTS_PATHS)

    def test_the_ci_login_role_and_the_owner_vars_are_owned_by_the_owner(self) -> None:
        self.assert_owned(CI_LOGIN_PATHS)

    def test_the_ci_jump_role_is_owned_by_the_owner(self) -> None:
        self.assert_owned(CI_JUMP_PATHS)

    def test_the_key_making_roles_are_owned_by_the_owner(self) -> None:
        # The CODEOWNERS line for ring_controller_host is the control: delete it and every role
        # path above that is not under a loader directory falls back to no owner and this fails.
        self.assert_owned(KEY_ROLE_PATHS)

    def test_the_access_roles_and_the_verifier_files_are_owned_by_the_owner(self) -> None:
        self.assert_owned(ACCESS_PATHS)

    def test_the_database_backup_timers_are_owned_by_the_owner(self) -> None:
        self.assert_owned(BACKUP_PATHS)

    def test_the_ring_controller_role_line_is_its_own_not_a_loader_line(self) -> None:
        patterns = {pattern for pattern, _ in self.rules}
        self.assertIn("/ansible/roles/ring_controller_host/", patterns)
        for path in (
            "ansible/roles/ring_controller_host/vars/main.yml",
            "ansible/roles/ring_controller_host/tasks/main.yml",
        ):
            with self.subTest(path=path):
                lines = [
                    p
                    for p, _ in self.rules
                    if pathspec.GitIgnoreSpec.from_lines([p]).match_file(path)
                ]
                self.assertEqual(lines, ["/ansible/roles/ring_controller_host/"])

    def test_the_seeding_tool_is_owned_by_the_owner(self) -> None:
        self.assert_owned(SEEDING_TOOL_PATHS)

    def test_the_bootstrap_guards_are_owned_by_the_owner(self) -> None:
        self.assert_owned(BOOTSTRAP_GUARD_PATHS)

    def test_the_image_scan_exemption_file_is_owned_by_the_owner(self) -> None:
        self.assert_owned(IMAGE_SCAN_PATHS)

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
                ".github/workflows/ci.md",
            ]
        )

    def test_a_host_playbook_and_ordinary_role_files_are_not_the_owners(self) -> None:
        self.assert_unowned(UNOWNED_PATHS)

    def test_documents_are_not_the_owners_but_the_repository_instructions_are(self) -> None:
        self.assert_unowned(RELEASED_DOCUMENT_PATHS)
        self.assert_owned(["CLAUDE.md"])

    def test_lockfiles_and_version_pins_are_not_the_owners(self) -> None:
        self.assert_unowned(RELEASED_PIN_PATHS)

    def test_agreement_tests_program_tests_checkers_and_probes_are_not_the_owners(self) -> None:
        self.assert_unowned(RELEASED_CHECK_PATHS)

    def test_the_tests_of_a_kept_gate_stay_the_owners(self) -> None:
        # A released agreement test is not a gate; the tests that stand over a kept gate are.
        self.assert_owned(
            [
                "ansible/checks/test_check_delivery.py",
                "ansible/checks/test_check_enrolment.py",
                "ansible/checks/test_check_pins.py",
                "ansible/checks/test_check_host_roles.py",
                "ansible/checks/test_ci_gate_order.py",
                "ansible/checks/test_ci_python_steps.py",
                "ansible/checks/test_ci_watched_paths.py",
                "ansible/checks/test_lock_reader_parity.py",
                "ansible/checks/test_step_allowlist.py",
                "ansible/checks/test_plan_diff_scan.py",
                "ansible/checks/test_host_inputs_registry.py",
                "ansible/checks/test_deploy_tooling_sudoers_seam.py",
                "ansible/checks/test_offline_workflow.py",
                "ansible/checks/test_shard_results.py",
            ]
        )

    def test_every_listed_file_exists(self) -> None:
        # A path typed wrongly in a list here owns nothing and nothing says so. The sample
        # paths that stand for a directory or a wildcard are not files on disk.
        listed = (
            ESTATE_PATHS
            + BILLED_PATHS
            + MAIL_PATHS
            + PUBLIC_PATHS
            + GATE_PATHS
            + PULL_ROLE_PATHS
            + HOST_INPUTS_PATHS
            + CI_LOGIN_PATHS
            + SEEDING_TOOL_PATHS
            + BOOTSTRAP_GUARD_PATHS
            + KEY_ROLE_PATHS
            + ACCESS_PATHS
            + BACKUP_PATHS
            + UNOWNED_PATHS
            + RELEASED_DOCUMENT_PATHS
            + RELEASED_PIN_PATHS
            + RELEASED_CHECK_PATHS
            + [sample.path for sample in SAMPLES]
        )
        for path in listed:
            if path in STANDS_FOR_MORE or path in PENDING:
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

    def test_a_new_file_of_a_kept_kind_is_the_owners_before_it_is_listed(self) -> None:
        # No line names these files, so only a directory or a pattern can own them. A new check,
        # a new gate test, a new Pulumi program or stack file, and a new loader file fail closed.
        self.assert_owned(
            [
                "ansible/checks/check_a_new_gate.py",
                "ansible/checks/test_check_a_new_gate.py",
                "ansible/checks/a_new_gate_data.yml",
                "hetzner/aNewProgram.ts",
                "hetzner-host/aNewProgram.ts",
                "hetzner/new/Pulumi.production.yaml",
                "ovh/copy2/aNewGuard.ts",
                "mail/provision/a_new_program.py",
                "scripts/a_new_ci_script.py",
                "hetzner/scripts/a_new_ci_script.py",
                "ansible/trust/newhost.yml",
                "ansible/owner_vars/newhost.yml",
                "ansible/roles/mail_reconcilers/tasks/new.yml",
                "ansible/roles/db1_backup_timers/tasks/new.yml",
                "ansible/roles/a_new_role/library/a_new_module.py",
            ]
        )

    def test_every_check_script_and_its_test_is_the_owners_but_the_released_ones(self) -> None:
        # Each file in ansible/checks/ is the owner's unless a line releases it. The released
        # ones are named here, so a release line that spreads past them is seen.
        released = {
            "README.md",
            "advisory_passes.py",
            "advisory_passes_fixture.json",
            "offline_render.py",
            "sabotage_offline_render.py",
            "pip-requirements.txt",
            "test_offline_render.py",
            "test_broker_paths_agree.py",
            "test_db1_stack_verify_parts.py",
            "test_demo1_egress_spool_agree.py",
            "test_demo1_no_github_fetch.py",
            "test_deploy_tooling_edge1_class.py",
            "test_deploy_tooling_internal_class.py",
            "test_deploy_tooling_links.py",
            "test_deploy_tooling_probe_name.py",
            "test_deploy_tooling_single_owner.py",
            "test_deploy_verifier_coverage.py",
            "test_edge_single_home.py",
            "test_egress_nat_single_gateway.py",
            "test_host_baseline_matches_scripts.py",
            "test_monitoring_single_home.py",
            "test_mx1_stack_agree.py",
            "test_patterns_typecheck.py",
            "test_ci_jump_hosts.py",
        }
        checks = ROOT / "ansible" / "checks"
        top_level = sorted(p.name for p in checks.iterdir() if p.is_file())
        self.assertIn("check_pins.py", top_level)
        for name in top_level:
            path = f"ansible/checks/{name}"
            with self.subTest(path=path):
                if name in released:
                    self.assertEqual([], owners_of(path, self.rules))
                else:
                    self.assertEqual([OWNER], owners_of(path, self.rules))

    def test_every_pulumi_program_and_stack_file_and_package_manifest_is_the_owners(self) -> None:
        # Every Pulumi program file of hetzner/ and hetzner-host/ that is not a test, every
        # Pulumi*.yaml, and every package.json outside the Ansible roles' payload files.
        files = repository_files()
        programs = [
            f
            for f in files
            if f.startswith(("hetzner/", "hetzner-host/"))
            and f.endswith(".ts")
            and f.count("/") == 1
            and not f.endswith(".test.ts")
        ]
        stacks = [
            f for f in files if os.path.basename(f).startswith("Pulumi") and f.endswith(".yaml")
        ]
        manifests = [
            f
            for f in files
            if os.path.basename(f) == "package.json" and not f.startswith("ansible/")
        ]
        self.assertGreaterEqual(len(programs), 10)
        self.assertGreaterEqual(len(stacks), 8)
        self.assertGreaterEqual(len(manifests), 4)
        self.assert_owned(programs + stacks + manifests)

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
        self.assert_unowned(
            [
                "ansible/roles/r/molecule/default/library/x.py",
                "ansible/patterns/typed_module/library/x.py",
                "ansible/roles/r/tasks/main.yml",
                "ansible/library.md",
            ]
        )

    def test_the_last_matching_line_wins(self) -> None:
        rules = [("/a/", [OWNER]), ("/a/b.py", ["@someone-else"])]
        self.assertEqual(["@someone-else"], owners_of("a/b.py", rules))
        self.assertEqual([OWNER], owners_of("a/c.py", rules))
        self.assertEqual([], owners_of("z/c.py", rules))

    def test_a_line_with_no_owner_un_owns_what_it_matches(self) -> None:
        rules = [("/a/", [OWNER]), ("*.md", [])]
        self.assertEqual([], owners_of("a/README.md", rules))
        self.assertEqual([OWNER], owners_of("a/x.py", rules))


if __name__ == "__main__":
    unittest.main()
