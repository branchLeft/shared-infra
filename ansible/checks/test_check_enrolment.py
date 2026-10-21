"""Tests for check_enrolment (ws#2340): the real tree, and one sabotage per rule.

Each sabotage edits a copy of the real ansible/ tree and asserts that the named rule
fails. A sabotage that does not hit its text fails the test, so an edit that matched
nothing cannot pass for a red run.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from check_enrolment import ROOT, check


class RealTree(unittest.TestCase):
    def test_the_real_tree_passes(self) -> None:
        self.assertEqual(check(ROOT), [])


class Sabotage(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        shutil.copytree(ROOT / "ansible", self.root / "ansible", symlinks=True)
        self.ansible = self.root / "ansible"

    def _edit(self, relative: str, old: str, new: str) -> None:
        path = self.ansible / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text, f"the sabotage matched nothing in {relative}")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def _write(self, relative: str, text: str) -> None:
        path = self.ansible / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _assert_rule(self, rule: str) -> list[str]:
        findings = check(self.root)
        self.assertTrue(
            any(finding.startswith(rule) for finding in findings),
            f"expected a {rule} finding, got {findings}",
        )
        return findings

    # R0: the shared includes exist.
    def test_r0_missing_shared_include(self) -> None:
        (self.ansible / "playbooks" / "includes" / "require_signers.yml").unlink()
        self._assert_rule("R0")

    # R1: an empty enrolled set fails, it does not pass over nothing.
    def test_r1_no_enrolled_playbook(self) -> None:
        for host in ("edge1", "ops1", "app1"):
            (self.ansible / "playbooks" / f"{host}.yml").unlink()
            (self.ansible / "trust" / f"{host}.yml").unlink()
        self._assert_rule("R1")

    # R2: the refusal include is missing from pre_tasks (the plan's C1 red).
    def test_r2_refusal_include_removed(self) -> None:
        self._edit(
            "playbooks/ops1.yml",
            "      ansible.builtin.include_tasks: includes/refuse_other_hosts.yml\n",
            "",
        )
        self._assert_rule("R2 ops1.yml")

    # R2: a playbook names another host (the plan's C2 red, first value).
    def test_r2_enrolled_host_names_another_host(self) -> None:
        self._edit("playbooks/app1.yml", "enrolled_host: app1", "enrolled_host: ops1")
        self._assert_rule("R2 app1.yml")

    # R2: the file stem differs from enrolled_host.
    def test_r2_file_stem_differs_from_enrolled_host(self) -> None:
        text = (self.ansible / "playbooks" / "ops1.yml").read_text(encoding="utf-8")
        self._write("playbooks/db9.yml", text)
        findings = check(self.root)
        self.assertTrue(any(finding.startswith("R2 db9.yml") for finding in findings), findings)
        self.assertTrue(any(finding.startswith("R4 db9.yml") for finding in findings), findings)

    # R2: the vars_files point at another host's trust file (the far copy, first target).
    def test_r2_vars_files_points_at_another_hosts_trust_file(self) -> None:
        self._edit(
            "playbooks/ops1.yml",
            "'{{ playbook_dir }}/../trust/ops1.yml'",
            "'{{ playbook_dir }}/../trust/edge1.yml'",
        )
        self._assert_rule("R2 ops1.yml")

    # R2: the far copy, second target, in the other direction.
    def test_r2_second_far_copy_points_at_edge1_trust(self) -> None:
        self._edit(
            "playbooks/app1.yml",
            "'{{ playbook_dir }}/../trust/app1.yml'",
            "'{{ playbook_dir }}/../trust/ops1.yml'",
        )
        self._assert_rule("R2 app1.yml")

    # R3: the shared include derives the playbook from something other than enrolled_host.
    def test_r3_playbook_derivation_is_a_literal(self) -> None:
        self._edit(
            "playbooks/includes/pull_trigger_common.yml",
            "ansible/playbooks/{{ enrolled_host }}.yml",
            "ansible/playbooks/edge1.yml",
        )
        self._assert_rule("R3")

    # R3: the allowlist is a second literal, not derived from pull_trigger_playbook.
    def test_r3_allowlist_is_a_second_literal(self) -> None:
        self._edit(
            "playbooks/includes/pull_trigger_common.yml",
            "  - '{{ pull_trigger_playbook }}'",
            "  - ansible/playbooks/edge1.yml",
        )
        self._assert_rule("R3")

    # R4: an enrolled playbook has no trust file.
    def test_r4_enrolled_playbook_without_trust_file(self) -> None:
        (self.ansible / "trust" / "app1.yml").unlink()
        self._assert_rule("R4 app1.yml")

    # R4: a trust file has no enrolled playbook.
    def test_r4_trust_file_without_playbook(self) -> None:
        self._write("trust/db1.yml", "---\npull_trigger_signers: []\n")
        self._assert_rule("R4 trust/db1.yml")

    # R5: a trust file holds a key other than the signer list.
    def test_r5_trust_file_holds_a_second_key(self) -> None:
        self._edit(
            "trust/ops1.yml",
            "pull_trigger_signers: []\n",
            "pull_trigger_signers: []\npull_trigger_remote_url: https://example.invalid/x.git\n",
        )
        self._assert_rule("R5 trust/ops1.yml")

    # R6: a signer list in group_vars (the C3 sabotage, first place).
    def test_r6_signer_defined_in_group_vars(self) -> None:
        self._write(
            "inventories/production/group_vars/all.yml",
            "---\npull_trigger_signers: []\n",
        )
        self._assert_rule("R6 ansible/inventories/production/group_vars/all.yml")

    # R6: a signer list in a playbook's play vars (the C3 sabotage, second place).
    def test_r6_signer_defined_in_playbook_vars(self) -> None:
        self._edit(
            "playbooks/edge1.yml",
            "enrolled_host: edge1",
            "enrolled_host: edge1\n    pull_trigger_signers: []",
        )
        self._assert_rule("R6 ansible/playbooks/edge1.yml")

    # R6 and R2: a signer list in a vars_files target outside trust/ (the C3 sabotage, third).
    def test_r6_signer_defined_in_an_extra_vars_file(self) -> None:
        self._write("playbooks/includes/extra.yml", "---\npull_trigger_signers: []\n")
        self._edit(
            "playbooks/ops1.yml",
            "    - '{{ playbook_dir }}/../trust/ops1.yml'\n",
            "    - '{{ playbook_dir }}/../trust/ops1.yml'\n"
            "    - '{{ playbook_dir }}/includes/extra.yml'\n",
        )
        findings = check(self.root)
        self.assertTrue(any(finding.startswith("R6 ") for finding in findings), findings)
        self.assertTrue(any(finding.startswith("R2 ops1.yml") for finding in findings), findings)

    # R7: a playbook that is not enrolled names the trust path, so a partial enrolment hides.
    def test_r7_unenrolled_playbook_names_a_trust_file(self) -> None:
        self._edit(
            "playbooks/db1.yml",
            "---\n",
            "---\n# A partial enrolment would name trust/db1.yml here.\n",
        )
        self._assert_rule("R7 db1.yml")

    # R0: the refusal's assert replaced with a value that always passes.
    def test_r0_refusal_assert_replaced_with_true(self) -> None:
        self._edit(
            "playbooks/includes/refuse_other_hosts.yml",
            "ansible_play_hosts_all | length == 1",
            "true",
        )
        self._assert_rule("R0 playbooks/includes/refuse_other_hosts.yml")

    # R0: the signer assert replaced with a value that always passes.
    def test_r0_signer_assert_replaced_with_true(self) -> None:
        self._edit(
            "playbooks/includes/require_signers.yml",
            "pull_trigger_signers | length > 0",
            "true",
        )
        self._assert_rule("R0 playbooks/includes/require_signers.yml")

    # R0: the signer assert loses its length check.
    def test_r0_signer_assert_loses_length_check(self) -> None:
        self._edit(
            "playbooks/includes/require_signers.yml",
            "      - pull_trigger_signers | length > 0\n",
            "      - pull_trigger_signers is defined\n",
        )
        self._assert_rule("R0 playbooks/includes/require_signers.yml")

    # R2: the roles entry of the pull_trigger role carries a signer list (the reproduction).
    def test_r2_role_entry_carries_a_signer_list(self) -> None:
        self._edit(
            "playbooks/edge1.yml",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n"
            "      vars:\n"
            "        pull_trigger_signers: [ATTACKERFPR]\n",
        )
        findings = check(self.root)
        self.assertTrue(any(finding.startswith("R2 edge1.yml") for finding in findings), findings)
        self.assertTrue(any(finding.startswith("R6 ") for finding in findings), findings)

    # R2: a third roles entry is added after the trigger.
    def test_r2_roles_has_a_third_entry(self) -> None:
        self._edit(
            "playbooks/app1.yml",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n"
            "    - role: ../roles/ansible_runtime\n",
        )
        self._assert_rule("R2 app1.yml")

    # R2: the runtime entry carries a second variable beside its requirements path.
    def test_r2_runtime_entry_carries_a_second_variable(self) -> None:
        self._edit(
            "playbooks/ops1.yml",
            "        ansible_runtime_requirements_src: '{{ playbook_dir }}/../requirements.txt'\n",
            "        ansible_runtime_requirements_src: '{{ playbook_dir }}/../requirements.txt'\n"
            "        pull_trigger_remote_url: https://example.invalid/x.git\n",
        )
        self._assert_rule("R2 ops1.yml")

    # R2: a refusal include is switched off by a when key (the reproduction).
    def test_r2_refusal_include_switched_off_by_when(self) -> None:
        self._edit(
            "playbooks/edge1.yml",
            "      ansible.builtin.include_tasks: includes/refuse_other_hosts.yml\n",
            "      ansible.builtin.include_tasks: includes/refuse_other_hosts.yml\n"
            "      when: false\n",
        )
        self._assert_rule("R2 edge1.yml")

    # R2: a signer include is switched off by a tags key.
    def test_r2_signer_include_carries_a_tags_key(self) -> None:
        self._edit(
            "playbooks/app1.yml",
            "      ansible.builtin.include_tasks: includes/require_signers.yml\n",
            "      ansible.builtin.include_tasks: includes/require_signers.yml\n"
            "      tags: [never]\n",
        )
        self._assert_rule("R2 app1.yml")

    # R3: the shared remote is a fork's, which all three hosts would pull from.
    def test_r3_remote_url_points_at_a_fork(self) -> None:
        self._edit(
            "playbooks/includes/pull_trigger_common.yml",
            "https://github.com/branchLeft/shared-infra.git",
            "https://github.com/attacker/shared-infra.git",
        )
        self._assert_rule("R3 pull_trigger_common.yml")

    # R3: the shared include carries a key beyond the three the derivation sets.
    def test_r3_shared_include_carries_an_extra_key(self) -> None:
        self._edit(
            "playbooks/includes/pull_trigger_common.yml",
            "pull_trigger_playbooks:\n",
            "pull_trigger_extra: x\npull_trigger_playbooks:\n",
        )
        self._assert_rule("R3 pull_trigger_common.yml")

    # R6: a role's task sets a signer list with set_fact.
    def test_r6_role_task_sets_a_signer_list(self) -> None:
        self._write(
            "roles/pull_trigger/tasks/extra.yml",
            "---\n- name: Trust a key\n  ansible.builtin.set_fact:\n"
            "    pull_trigger_signers: [ATTACKERFPR]\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/extra.yml")

    # R6: a playbook sets the remote the shared include owns.
    def test_r6_playbook_defines_the_remote(self) -> None:
        self._edit(
            "playbooks/edge1.yml",
            "enrolled_host: edge1",
            "enrolled_host: edge1\n    pull_trigger_remote_url: https://example.invalid/x.git",
        )
        self._assert_rule("R6 ansible/playbooks/edge1.yml")


if __name__ == "__main__":
    unittest.main()
