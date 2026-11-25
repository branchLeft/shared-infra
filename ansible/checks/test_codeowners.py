"""Tests that the guardrail files and the human-facing documents are the owner's in CODEOWNERS.

This reads .github/CODEOWNERS the way GitHub does (the last matching line wins; the matcher is
codeowners_match.py). The owner reviews only guardrails (this file and its proof, the workflows and
the gates they run, the apply-gate allowlists, the guard tests, the floors, CLAUDE.md, .claude/) and
documents aimed at people (README, licences, the launch page copy). Everything else, the edge,
firewall, mail host, Ansible roles and playbooks, inventories, Pulumi programs and secrets handling
code included, merges on the reviewer App's approval and green CI. The standards template's lines
are the file's final lines (SYNC-1). A release is a kind of path or one file named in full, and the
rows of a block are in order, so adding a row for one more file edits no list here.
"""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path

from codeowners_match import (
    CODEOWNERS,
    OWNER,
    PENDING,
    ROOT,
    SAMPLES,
    mismatches,
    owner_changes,
    owners_of,
    parse_rules,
)

# The lines of branchLeft/standards templates/codeowners at the tag the Standards job is pinned
# to (.github/workflows/standards.yml). SYNC-1 requires them, unchanged and in order, as the
# final lines of CODEOWNERS. A pin bump to a tag whose template differs changes this list too.
STANDARDS_TEMPLATE = [
    ("/.standardsignore", [OWNER]),
    ("/.standards.mode", [OWNER]),
    ("/.docs-lint*", [OWNER]),
    ("/.standards-db-tooling", [OWNER]),
    ("/.github/CODEOWNERS", [OWNER]),
    ("/.github/workflows/standards.yml", [OWNER]),
    ("/.github/workflows/docs-lint.yml", [OWNER]),
]

# The kinds of path CODEOWNERS may release by a pattern. Everything else it releases is one file,
# named in full, so a new gate test is the owner's until a line names it.
RELEASE_KINDS: frozenset[str] = frozenset(
    {
        "*.md",  # every document; README, CLAUDE.md and .claude/ are owned again
        "/ansible/checks/offline/",  # the offline render fixtures
        "/scripts/nvmrc-node-exec.*",
    }
)

# Paths that must be the owner's, by class. Each is a file in the repository.
GUARDRAIL_PATHS = [
    ".github/CODEOWNERS",
    ".github/workflows/ci.yml",
    ".github/workflows/ci-config-validate.yml",
    ".github/workflows/ansible.yml",
    ".github/workflows/ansible-delivery.yml",
    ".github/workflows/ansible-environment-probe.yml",
    ".github/workflows/ovh-copy2-probe.yml",
    ".github/workflows/publish-edge-caddy.yml",
    ".github/workflows/publish-hetzner-host.yml",
    ".github/workflows/tenants-state-rewrap.yml",
    ".github/workflows/verify-package-attestations.yml",
    ".github/workflows/ansible-drift-check.yml",
    ".github/workflows/crowdsec-hub-pin-check.yml",
    ".github/workflows/secret-alert-pager.yml",
    ".github/scripts/secret_alert_pager.py",
    ".github/scripts/test_secret_alert_pager.py",
    ".github/workflows/docs-lint.yml",
    ".github/actions/ci-skip/action.yml",
    ".github/actions/ansible-venv/action.yml",
    "CLAUDE.md",
    ".claude/.gitignore",
    "ansible/checks/test_codeowners.py",
    "ansible/checks/codeowners_match.py",
    "ansible/checks/check_pins.py",
    "ansible/checks/check_delivery.py",
    "ansible/checks/check_enrolment.py",
    "ansible/checks/host_roles/edge1.yml",
    "ansible/checks/test_check_delivery.py",
    "ansible/checks/test_step_allowlist.py",
    "ansible/checks/test_ci_gate_order.py",
    "ansible/checks/test_deploy_verifier_coverage.py",
    "ansible/checks/a_new_gate_script.py",
    "ansible/harness/run_harness.py",
    "ansible/pyproject.toml",
    "ansible/trust/mx1.yml",
    "ansible/playbooks/includes/require_signers.yml",
    "ansible/roles/deploy_verifier/files/trusted_root.jsonl",
    "ansible/roles/deploy_verifier/files/branchleft-verify-image.py",
    "ansible/roles/deploy_verifier/tests/unit/test_branchleft_verify_image.py",
    "scripts/assert-no-hetzner-deletes.py",
    "scripts/choose-apply-environment.py",
    "scripts/a_new_ci_script.py",
    "hetzner/scripts/check-crowdsec-hub-pin.py",
    "hetzner/scripts/test_check_crowdsec_hub_pin.py",
    "hetzner/scripts/lib/docker_pull.py",
    "hetzner/scripts/lib/proof_harness.py",
    "hetzner/provision/test_suite_size.py",
    "hetzner/provision/test_counts/test_suite_size.txt",
    "hetzner/estate.guard.test.ts",
    "hetzner/dns.guard.test.ts",
    "hetzner/tenants.guard.test.ts",
    "hetzner/projectGuard.ts",
    "hetzner/projectGuard.test.ts",
    "ovh/copy2/projectGuard.ts",
    "ovh/copy2/projectGuard.test.ts",
    "ovh/copy2/configGuard.ts",
    "ovh/copy2/configGuard.test.ts",
    "ansible/roles/status_page/tests/unit/test_status_page_drop_guard.py",
    ".pre-commit-config.yaml",
    ".prettierignore",
    ".ansible-lint",
    ".yamllint",
    ".image-scan-exemptions.json",
    "tools/floors.tsv",
    ".standardsignore",
    ".standards.mode",
    ".docs-lint.mode",
    ".docs-lintignore",
    ".standards-db-tooling",
    ".github/workflows/standards.yml",
]

# Human-facing documents and the owner's words.
DOCUMENT_PATHS = [
    "README.md",
    "LICENSE",
    "hetzner-host/LICENSE",
    "hetzner/edge/publicpress/index.html",
]

# Paths released to agents: the owner has extended trust here, and the gated apply still stands
# between a merge and a host. Each is a file in the repository.
RELEASED_PATHS = [
    ".github/dependabot.yml",
    ".github/workflows/ci.md",
    ".github/workflows/ansible-offline.yml",
    ".github/workflows/ghost-pin-lag.yml",
    "sites.ts",
    "hetzner/edge/render.ts",
    "hetzner/edge/render.test.ts",
    "hetzner/edge/stack/caddy/Caddyfile",
    "hetzner/edge/validation/Caddyfile.enforcing",
    "hetzner/edge/breakGlassToken.test.ts",
    "hetzner/estate.ts",
    "hetzner/Pulumi.production.yaml",
    "hetzner/package.json",
    "hetzner/dns/zone.json",
    "hetzner-host/firewalls.ts",
    "hetzner-host/cloudInit.test.ts",
    "ovh/copy2/stack.ts",
    "mail/provision/provision_mailboxes.py",
    "ansible/playbooks/mx1.yml",
    "ansible/playbooks/edge1.yml",
    "ansible/inventories/production/hosts.yml",
    "ansible/owner_vars/edge1.yml",
    "ansible/roles/ci_jump/tasks/main.yml",
    "ansible/roles/ci_login/tasks/_sudoers.yml",
    "ansible/roles/host_baseline/tasks/_ssh.yml",
    "ansible/roles/pull_trigger/tasks/main.yml",
    "ansible/roles/backup_worker/defaults/main.yml",
    "ansible/roles/edge_stack/tasks/main.yml",
    "ansible/roles/deploy_verifier/vars/main.yml",
    "ansible/tools/seed_host_inputs.py",
    "hetzner/provision/branchleft_deploy.py",
    "hetzner/provision/branchleft_promote.py",
    "hetzner/control-plane/stack/postgres/pg_hba.conf",
    "hetzner/estate.test.ts",
    "hetzner/dns/zonecheck.py",
    "hetzner/scripts/probe-object-storage.py",
    "hetzner/scripts/check-address-plan-drift.py",
    "ansible/checks/test_edge_single_home.py",
    "ansible/requirements.txt",
    "pnpm-lock.yaml",
    "hetzner/pnpm-lock.yaml",
    "package.json",
    ".npmrc",
]

# Paths named above that the repository does not hold yet.
STANDS_FOR_MORE = {
    "ansible/checks/a_new_gate_script.py",
    "scripts/a_new_ci_script.py",
    # Named by the standards template; a repository that has no floors or ignore file yet has none.
    "tools/floors.tsv",
    ".standardsignore",
}


def repository_files() -> list[str]:
    """Return every file in the checkout as a repo-relative path, outside .git and node_modules."""
    found: list[str] = []
    for directory, subdirectories, names in os.walk(ROOT):
        subdirectories[:] = [d for d in subdirectories if d not in {".git", "node_modules"}]
        found.extend(Path(directory, name).relative_to(ROOT).as_posix() for name in names)
    return sorted(found)


def blocks_of(text: str) -> list[list[str]]:
    """Return the rows of each block of a CODEOWNERS file, comments and blank lines dropped."""
    blocks: list[list[str]] = [[]]
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            blocks.append([])
        elif not line.startswith("#"):
            blocks[-1].append(line)
    return [b for b in blocks if b]


def hold_reasons(text: str, is_action: bool) -> list[str]:
    """Why a workflow or action file stays owned, read from its own text.

    A file stays owned when it names a secret other than GITHUB_TOKEN, carries an environment,
    grants any write permission, has no explicit permissions block, or declares secrets on
    workflow_call.
    """
    out: list[str] = []
    if (
        re.search(r"(?<![\w-])secrets\.(?!GITHUB_TOKEN\b)[A-Za-z_]", text)
        or re.search(r"(?<![\w-])secrets\[", text)
        or re.search(r"secrets:\s*inherit", text)
    ):
        out.append("secrets")
    if re.search(r"^\s+environment:", text, re.M):
        out.append("environment")
    if re.search(r"^\s+[a-z-]+:\s*write\s*(#.*)?$", text, re.M) or re.search(
        r"permissions:\s*write-all", text
    ):
        out.append("write permission")
    if re.search(r"workflow_call:", text) and re.search(r"^\s{4}secrets:\s*$", text, re.M):
        out.append("workflow_call secrets")
    if not is_action and not re.search(r"^permissions:", text, re.M):
        start = re.search(r"^jobs:\s*$", text, re.M)
        body = text[start.end() :] if start else ""
        pattern = r"^  (?=[A-Za-z0-9_.-]+:\s*(?:#.*)?$)"
        jobs = re.split(pattern, body, flags=re.M)[1:]
        if not jobs or any(not re.search(r"^    permissions:", job, re.M) for job in jobs):
            out.append("no permissions block")
    return out


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

    def test_the_standards_template_lines_are_the_final_lines(self) -> None:
        # SYNC-1: the template's lines, unchanged and in order, end the file. Any line after
        # or between them can take ownership back, because the last matching line wins.
        self.assertEqual(STANDARDS_TEMPLATE, self.rules[-len(STANDARDS_TEMPLATE) :])

    def test_every_sample_gets_the_answer_the_table_requires(self) -> None:
        # The fixed table in codeowners_match.py. The command line prints the same rows for any
        # CODEOWNERS file.
        self.assertEqual([], mismatches(self.rules))

    def test_the_samples_cover_the_owned_and_the_released_classes(self) -> None:
        # A table that lost a class would pass for a file that lost the class's line.
        classes = {sample.klass.split(":")[0] for sample in SAMPLES if sample.owned}
        for kept in ("rule", "gate", "guard", "doc"):
            self.assertIn(kept, classes)
        self.assertGreaterEqual(sum(1 for sample in SAMPLES if not sample.owned), 20)

    def test_the_guardrail_files_are_owned_by_the_owner(self) -> None:
        self.assert_owned(GUARDRAIL_PATHS)

    def test_the_human_facing_documents_are_owned_by_the_owner(self) -> None:
        self.assert_owned(DOCUMENT_PATHS)

    def test_the_released_paths_are_not_the_owners(self) -> None:
        # The edge, firewall, mail host, Ansible roles and playbooks, inventories, Pulumi programs,
        # hetzner and ovh code, and the ssh and sudoers roles are the reviewer App's to approve.
        self.assert_unowned(RELEASED_PATHS)

    def test_a_new_file_in_a_gate_directory_is_the_owners_before_it_is_listed(self) -> None:
        # A new check or gate test, or a new CI script, fails closed.
        self.assert_owned(
            [
                "ansible/checks/check_a_new_gate.py",
                "ansible/checks/test_a_new_gate_agree.py",
                "ansible/checks/host_roles/a_new_host.yml",
                "ansible/trust/newhost.yml",
                "scripts/a_new_ci_script.py",
                "hetzner/aNewGuard.guard.test.ts",
            ]
        )

    def test_a_new_file_outside_the_guardrails_is_not_the_owners(self) -> None:
        self.assert_unowned(
            [
                "hetzner/aNewProgram.ts",
                "hetzner-host/aNewFirewall.ts",
                "ansible/roles/a_new_role/tasks/main.yml",
                "ansible/roles/a_new_role/library/a_new_module.py",
                "mail/a_new_program.py",
                ".github/workflows/a_new_workflow.yml",
            ]
        )

    def test_the_hold_rule_reads_what_it_names(self) -> None:
        cases = {
            "a secret": ("env:\n  T: ${{ secrets.TOKEN }}\n", "secrets"),
            "an environment": ("jobs:\n  a:\n    environment: prod\n", "environment"),
            "a write": ("permissions:\n  contents: write\n", "write permission"),
            "no block": ("on: push\njobs:\n  a:\n    runs-on: x\n", "no permissions block"),
        }
        for name, (text, reason) in cases.items():
            with self.subTest(case=name):
                self.assertIn(reason, hold_reasons(text, False))
        plain = "env:\n  T: ${{ secrets.GITHUB_TOKEN }}\npermissions: {}\n"
        self.assertEqual([], hold_reasons(plain, False))

    def test_a_workflow_or_action_that_matches_the_hold_rule_is_owned(self) -> None:
        # The rule is read from each file's own text, so a new workflow that holds a secret or
        # grants a write cannot be released by a name no line matches. The scripts a workflow
        # runs from .github/scripts/ stay owned with it.
        files = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
        files += sorted((ROOT / ".github" / "actions").glob("*/action.y*ml"))
        self.assertGreaterEqual(len(files), 10)
        for file in files:
            path = file.relative_to(ROOT).as_posix()
            reasons = hold_reasons(file.read_text(encoding="utf-8"), "/actions/" in path)
            if reasons:
                with self.subTest(path=path, reasons=reasons):
                    self.assertEqual([OWNER], owners_of(path, self.rules))
        pager_dir = ROOT / ".github" / "scripts"
        scripts = sorted(p.relative_to(ROOT).as_posix() for p in pager_dir.iterdir())
        self.assertTrue(scripts)
        self.assert_owned(scripts)

    def test_a_workflow_that_gates_a_deploy_or_emits_a_required_check_is_owned(self) -> None:
        # A workflow nothing names is released, so one that adds an approval environment, or a
        # job a required check is named after, would slip out of the owner's review. This reads
        # every workflow: any that waits on an environment, or emits a required job, must be owned.
        required_jobs = (
            "Type check",
            "Type check (mail)",
            "Lint + test (mail/provision)",
            "Type check (hetzner)",
            "Type check + test (hetzner-host)",
            "Lint + test (hetzner/provision)",
            "Validate (edge Caddy config)",
            "Test (scripts)",
            "Audit (Pulumi secrets + state backends)",
            "Validate (monitoring stack config)",
            "Lint and test the Ansible roles",
        )
        workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertGreaterEqual(len(workflows), 10)
        emitted: set[str] = set()
        for workflow in workflows:
            text = workflow.read_text(encoding="utf-8")
            found = re.findall(r"^    name: (.+?)\s*$", text, re.MULTILINE)
            names = {m.strip("'\"") for m in found}
            emitted |= names
            gates = bool(re.search(r"^    +environment:", text, re.MULTILINE)) or bool(
                names & set(required_jobs)
            )
            if gates:
                with self.subTest(workflow=workflow.name):
                    path = f".github/workflows/{workflow.name}"
                    self.assertEqual([OWNER], owners_of(path, self.rules))
        self.assertEqual(set(required_jobs) - emitted, set(), "a required job no workflow emits")

    def test_documents_are_not_the_owners_but_the_instructions_and_readme_are(self) -> None:
        # Every tracked markdown file, derived from the checkout so a new document needs no line
        # here. The owned ones are the top README, CLAUDE.md, and what sits in .claude/.
        documents = [
            f
            for f in repository_files()
            if f.endswith(".md")
            and f not in {"README.md", "CLAUDE.md"}
            and not f.startswith(".claude/")
        ]
        self.assertGreaterEqual(len(documents), 100)
        self.assert_unowned(documents)
        self.assert_owned(["README.md", "CLAUDE.md", ".claude/skills/x/SKILL.md"])

    def test_lockfiles_and_version_pins_are_not_the_owners(self) -> None:
        pin_name = re.compile(r"pnpm-lock\.yaml|\.nvmrc|(pip-)?requirements\.(txt|in|yml)")
        pins = [f for f in repository_files() if pin_name.fullmatch(os.path.basename(f))]
        self.assertGreaterEqual(len(pins), 10)
        self.assert_unowned(pins)

    def test_a_release_is_a_kind_of_path_or_one_file_named_in_full(self) -> None:
        # A row with no owner un-owns what it matches. Each is either one of the kinds in
        # RELEASE_KINDS or the full path of one file, so a release cannot reach a file that is
        # only named like a released one.
        for pattern, owners in self.rules:
            if owners:
                continue
            with self.subTest(pattern=pattern):
                if pattern in RELEASE_KINDS:
                    continue
                self.assertFalse(set("*?[]!") & set(pattern), "a wildcard outside the kinds")
                self.assertFalse(pattern.endswith("/"), "a directory outside the kinds")
                self.assertTrue(pattern.startswith("/"), "a name that matches at any depth")

    def test_every_row_is_in_a_sorted_block(self) -> None:
        # Rows in one block are in order of their patterns, so two changes that add rows at
        # different places in a block do not edit the same lines. The last block is the standards
        # template, whose order SYNC-1 fixes.
        blocks = [[row.split()[0] for row in block] for block in blocks_of(self._text())]
        self.assertGreaterEqual(len(blocks), 3)
        for block in blocks[:-1]:
            with self.subTest(first=block[0]):
                self.assertEqual(sorted(block), block)
        self.assertEqual([p for p, _ in STANDARDS_TEMPLATE], blocks[-1])

    def test_a_block_does_not_mix_owned_and_released_rows(self) -> None:
        # What makes the order inside a block free: no block holds rows with and without an owner.
        for block in blocks_of(self._text()):
            self.assertEqual(1, len({len(row.split()) > 1 for row in block}))

    def test_a_change_that_drops_an_owner_is_found(self) -> None:
        # The comparison the owner reads with `codeowners_match.py --against OLD`: a file that
        # had an owner and has none is lost, one that had none and has one is gained.
        old = [("/a/", [OWNER])]
        files = ["a/x.py", "a/y.py", "b/z.py"]
        self.assertEqual(([], []), owner_changes(old, old, files))
        self.assertEqual((["a/x.py"], []), owner_changes(old, old + [("/a/x.py", [])], files))
        self.assertEqual(([], ["b/z.py"]), owner_changes(old, old + [("/b/", [OWNER])], files))
        self.assertEqual(
            ([], []), owner_changes(old, [("/a/x.py", [OWNER]), ("/a/", [OWNER])], files)
        )

    def test_every_listed_file_exists(self) -> None:
        # A path typed wrongly in a list here owns nothing and nothing says so.
        listed = (
            GUARDRAIL_PATHS + DOCUMENT_PATHS + RELEASED_PATHS + [sample.path for sample in SAMPLES]
        )
        for path in listed:
            if path in STANDS_FOR_MORE or path in PENDING:
                continue
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).exists(), path)

    def test_the_last_matching_line_wins(self) -> None:
        rules = [("/a/", [OWNER]), ("/a/b.py", ["@someone-else"])]
        self.assertEqual(["@someone-else"], owners_of("a/b.py", rules))
        self.assertEqual([OWNER], owners_of("a/c.py", rules))
        self.assertEqual([], owners_of("z/c.py", rules))

    def test_a_line_with_no_owner_un_owns_what_it_matches(self) -> None:
        rules = [("/a/", [OWNER]), ("*.md", [])]
        self.assertEqual([], owners_of("a/README.md", rules))
        self.assertEqual([OWNER], owners_of("a/x.py", rules))

    @staticmethod
    def _text() -> str:
        return CODEOWNERS.read_text(encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
