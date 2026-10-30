"""Tests for check_enrolment: the real tree, and one sabotage per rule.

Each sabotage edits a copy of the real ansible/ tree and asserts that the named rule
fails. A sabotage that does not hit its text fails the test, so an edit that matched
nothing cannot pass for a red run.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from check_enrolment import ROOT, check

# A playbook that applies the pull on edge1: it is refused in any name the pull cannot read.
EVIL_PLAY = "- hosts: all\n  vars:\n    enrolled_host: edge1\n  roles:\n    - pull_trigger\n"
# The loader's entry in db1's playbook, as it stands on main.
LOADER_LINE = "    - role: ../roles/host_inputs # noqa: role-name[path]\n"


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
        for host in ("edge1", "ops1", "app1", "db1"):
            (self.ansible / "playbooks" / f"{host}.yml").unlink()
            (self.ansible / "trust" / f"{host}.yml").unlink()
        self._assert_rule("R1")

    # R2: the refusal include is missing from pre_tasks.
    def test_r2_refusal_include_removed(self) -> None:
        self._edit(
            "playbooks/ops1.yml",
            "      ansible.builtin.include_tasks: includes/refuse_other_hosts.yml\n",
            "",
        )
        self._assert_rule("R2 ops1.yml")

    # R2: a playbook names another host.
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

    # R2: the vars_files point at another host's trust file.
    def test_r2_vars_files_points_at_another_hosts_trust_file(self) -> None:
        self._edit(
            "playbooks/ops1.yml",
            "'{{ playbook_dir }}/../trust/ops1.yml'",
            "'{{ playbook_dir }}/../trust/edge1.yml'",
        )
        self._assert_rule("R2 ops1.yml")

    # R2: the vars_files point at the other host's trust file, in the other direction.
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
        self._write("trust/demo1.yml", "---\npull_trigger_signers: []\n")
        self._assert_rule("R4 trust/demo1.yml")

    # R4: db1 is enrolled, so its playbook needs its trust file. Without it the real tree is red.
    def test_r4_db1_playbook_without_trust_file(self) -> None:
        (self.ansible / "trust" / "db1.yml").unlink()
        self._assert_rule("R4 db1.yml is enrolled but has no trust/db1.yml")

    # R5: db1's trust file holds the signer list and nothing else.
    def test_r5_db1_trust_file_holds_a_second_key(self) -> None:
        self._edit(
            "trust/db1.yml",
            "pull_trigger_signers:\n",
            "db1_stack_exporter_password: x\npull_trigger_signers:\n",
        )
        self._assert_rule("R5 trust/db1.yml")

    # R2, fail closed: db1 without the signer refusal would run on an empty trust list.
    def test_r2_db1_signer_include_removed(self) -> None:
        self._edit(
            "playbooks/db1.yml",
            "    - name: Refuse an empty signer list\n"
            "      ansible.builtin.include_tasks: includes/require_signers.yml\n",
            "",
        )
        self._assert_rule("R2 db1.yml")

    # R2: db1 without the host refusal could be applied to any host.
    def test_r2_db1_refusal_include_removed(self) -> None:
        self._edit(
            "playbooks/db1.yml",
            "      ansible.builtin.include_tasks: includes/refuse_other_hosts.yml\n",
            "",
        )
        self._assert_rule("R2 db1.yml")

    # R2: db1 may apply only the roles on its own list in host_roles.yml.
    def test_r2_db1_applies_a_role_not_on_its_list(self) -> None:
        self._edit(
            "playbooks/db1.yml",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n"
            "    - role: ../roles/control_plane # noqa: role-name[path]\n",
        )
        self._assert_rule("R2 db1.yml: role control_plane is not on db1's list")

    # R2: a role entry of db1 may not carry the role inputs the pull route has no channel for.
    def test_r2_db1_role_entry_carries_an_input(self) -> None:
        self._edit(
            "playbooks/db1.yml",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n"
            "    - role: ../roles/db1_stack # noqa: role-name[path]\n"
            "      vars:\n"
            "        db1_stack_exporter_password: x\n",
        )
        self._assert_rule("R2 db1.yml")

    # R11: the loader of a host's private inputs is the first role after the pull roles, so no
    # role runs before the inputs are loaded or the run is refused. The positive control first:
    # a role after the loader passes, so a check that refused every extra role would not pass.
    def test_r10_a_role_after_the_loader_passes(self) -> None:
        self._edit(
            "playbooks/db1.yml",
            LOADER_LINE,
            LOADER_LINE + "    - role: ../roles/db1_stack # noqa: role-name[path]\n",
        )
        self.assertEqual(check(self.root), [])

    # R11, the sabotage: a role before the loader is refused by name.
    def test_r10_a_role_before_the_loader_is_refused(self) -> None:
        self._edit(
            "playbooks/db1.yml",
            LOADER_LINE,
            "    - role: ../roles/db1_stack # noqa: role-name[path]\n" + LOADER_LINE,
        )
        findings = self._assert_rule("R11 db1.yml")
        self.assertTrue(any("must be the first role after the pull roles" in f for f in findings))

    # R11, the sabotage: the loader behind two roles is refused too, not only behind one.
    def test_r10_the_loader_last_of_three_is_refused(self) -> None:
        self._edit(
            "playbooks/db1.yml",
            LOADER_LINE,
            "    - role: ../roles/db1_stack # noqa: role-name[path]\n"
            "    - role: ../roles/db1_grants # noqa: role-name[path]\n" + LOADER_LINE,
        )
        self._assert_rule("R11 db1.yml")

    # R2: the loader is on db1's list only, so another host cannot apply it.
    def test_r10_the_loader_on_another_host_is_refused(self) -> None:
        self._edit(
            "playbooks/edge1.yml",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n"
            "    - role: ../roles/host_inputs # noqa: role-name[path]\n",
        )
        self._assert_rule("R2 edge1.yml: role host_inputs is not on edge1's list")

    # R5: a trust file holds a key other than the signer list.
    def test_r5_trust_file_holds_a_second_key(self) -> None:
        self._edit(
            "trust/ops1.yml",
            "pull_trigger_signers:\n",
            "pull_trigger_remote_url: https://example.invalid/x.git\npull_trigger_signers:\n",
        )
        self._assert_rule("R5 trust/ops1.yml")

    # R6: a signer list in group_vars.
    def test_r6_signer_defined_in_group_vars(self) -> None:
        self._write(
            "inventories/production/group_vars/all.yml",
            "---\npull_trigger_signers: []\n",
        )
        self._assert_rule("R6 ansible/inventories/production/group_vars/all.yml")

    # R6: a signer list in a playbook's play vars.
    def test_r6_signer_defined_in_playbook_vars(self) -> None:
        self._edit(
            "playbooks/edge1.yml",
            "enrolled_host: edge1",
            "enrolled_host: edge1\n    pull_trigger_signers: []",
        )
        self._assert_rule("R6 ansible/playbooks/edge1.yml")

    # R6 and R2: a signer list in a vars_files target outside trust/.
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
            "playbooks/demo1.yml",
            "---\n",
            "---\n# A partial enrolment would name trust/demo1.yml here.\n",
        )
        self._assert_rule("R7 demo1.yml")

    # R2: a top-level .yaml playbook that applies pull_trigger is refused, not skipped.
    def test_r2_top_level_yaml_playbook_is_refused(self) -> None:
        self._write(
            "playbooks/evil.yaml",
            "- hosts: all\n  vars:\n    enrolled_host: edge1\n  roles:\n    - pull_trigger\n",
        )
        self._assert_rule("R2 evil.yaml")

    # R2: any other suffix, in any case, is refused too: ansible-playbook runs it anyway.
    def test_r2_top_level_uppercase_yaml_playbook_is_refused(self) -> None:
        self._write(
            "playbooks/evil.YAML",
            "- hosts: all\n  vars:\n    enrolled_host: edge1\n  roles:\n    - pull_trigger\n",
        )
        self._assert_rule("R2 evil.YAML")

    # Playbooks: a nested playbook whose name is not an exact .yml is refused.
    def test_nested_uppercase_yaml_playbook_is_refused(self) -> None:
        self._write("playbooks/sub/evil.YAML", EVIL_PLAY)
        self._assert_rule("R2 sub/evil.YAML")

    # Trust: an uppercase .YAML trust file is refused, not ignored by R4 and R5.
    def test_trust_uppercase_yaml_is_refused(self) -> None:
        self._write("trust/x.YAML", "---\npull_trigger_signers: [attacker]\n")
        self._assert_rule("R5 x.YAML")

    # Trust: a lowercase .yaml trust file is refused, not ignored by R4 and R5.
    def test_trust_lowercase_yaml_is_refused(self) -> None:
        self._write("trust/x.yaml", "---\npull_trigger_signers: [attacker]\n")
        self._assert_rule("R5 x.yaml")

    # Trust: case alone is enough to refuse, so a lower()-based test would be too weak.
    def test_trust_uppercase_yml_is_refused(self) -> None:
        self._write("trust/x.YML", "---\npull_trigger_signers: [attacker]\n")
        self._assert_rule("R5 x.YML")

    # Trust: a template suffix is a different name, so it is refused.
    def test_trust_yml_j2_is_refused(self) -> None:
        self._write("trust/x.yml.j2", "---\npull_trigger_signers: [attacker]\n")
        self._assert_rule("R5 x.yml.j2")

    # Playbooks: a .txt file is refused, because ansible-playbook runs any name given.
    def test_playbooks_txt_is_refused(self) -> None:
        self._write("playbooks/notes.txt", EVIL_PLAY)
        self._assert_rule("R2 notes.txt")

    # Trust is flat: a nested trust .yml is refused, and its stem never collides with a
    # top-level trust file in R4 or R5.
    def test_nested_yml_in_trust_is_refused(self) -> None:
        self._write("trust/sub/edge1.yml", "---\npull_trigger_signers: []\n")
        self._assert_rule("R5 sub/edge1.yml")

    # Playbooks: a nested playbook .yml is refused, not read by R2.
    def test_nested_yml_playbook_is_refused(self) -> None:
        self._write("playbooks/sub/evil.yml", EVIL_PLAY)
        self._assert_rule("R2 sub/evil.yml")

    # playbooks/includes/ is the one nested place a .yml is read; one level deeper is refused.
    def test_includes_nested_deeper_is_refused(self) -> None:
        self._write("playbooks/includes/sub/x.yml", "---\nfoo: bar\n")
        self._assert_rule("R2 includes/sub/x.yml")

    # Exact README paths: a README.md at any other path is not the exception, so refused.
    # The body is prose, not a play list, so only the exact-path pin refuses it.
    def test_nested_readme_is_not_the_exception(self) -> None:
        self._write("playbooks/sub/README.md", "# Notes\n\nProse only.\n")
        self._assert_rule("R2 sub/README.md")

    # A README exception that parses as a YAML list is refused, because ansible-playbook would
    # run it as plays. R6 does not read .md, so the name is no guard.
    def test_playbooks_readme_play_list_is_refused(self) -> None:
        self._write("playbooks/README.md", EVIL_PLAY)
        self._assert_rule("R2 README.md")

    def test_trust_readme_play_list_is_refused(self) -> None:
        play = "- hosts: all\n  vars:\n    pull_trigger_signers: [attacker]\n"
        self._write("trust/README.md", play)
        self._assert_rule("R5 README.md")

    # A play list with an Ansible tag fails under SafeLoader, so it must still be refused.
    # Ansible's loader runs it as plays.
    def test_playbooks_readme_tagged_play_list_is_refused(self) -> None:
        play = "- hosts: all\n  pull_trigger_signers: [attacker]\n  note: !unsafe '{{ x }}'\n"
        self._write("playbooks/README.md", play)
        self._assert_rule("R2 README.md")

    def test_trust_readme_tagged_play_list_is_refused(self) -> None:
        play = "- hosts: all\n  vars:\n    pull_trigger_signers: !vault |\n      $ANSIBLE_VAULT\n"
        self._write("trust/README.md", play)
        self._assert_rule("R5 README.md")

    # A play list whose item is a tagged mapping is refused. Without the mapping branch of
    # _construct_any_tag, the tagged item raises, _load reads nothing, and the list passes.
    def test_playbooks_readme_tagged_mapping_play_is_refused(self) -> None:
        play = (
            "- !unsafe\n"
            "  hosts: all\n"
            "  vars:\n"
            "    pull_trigger_signers: [attacker]\n"
            "  roles:\n"
            "    - ../roles/pull_trigger\n"
        )
        self._write("playbooks/README.md", play)
        self._assert_rule("R2 README.md")

    def test_trust_readme_tagged_mapping_play_is_refused(self) -> None:
        play = (
            "- !unsafe\n"
            "  hosts: all\n"
            "  vars:\n"
            "    pull_trigger_signers: [attacker]\n"
            "  roles:\n"
            "    - ../roles/pull_trigger\n"
        )
        self._write("trust/README.md", play)
        self._assert_rule("R5 README.md")

    # A tagged sequence value in a play is refused. Without the sequence branch of
    # _construct_any_tag, the tagged value raises, _load reads nothing, and the list passes.
    def test_playbooks_readme_tagged_sequence_value_is_refused(self) -> None:
        play = "- hosts: all\n  vars:\n    pull_trigger_signers: !unsafe [attacker]\n"
        self._write("playbooks/README.md", play)
        self._assert_rule("R2 README.md")

    # Link handling: a link is refused whatever its name, so the check never follows it.
    def test_symlink_named_yml_in_trust_is_refused(self) -> None:
        os.symlink("ops1.yml", self.ansible / "trust" / "link.yml")
        self._assert_rule("R5 link.yml")

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

    # R2: the roles entry of the pull_trigger role carries a signer list.
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

    # R2: a refusal include is switched off by a when key.
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

    # R8: the config writer takes its signers from a literal.
    def test_r8_writer_signers_is_a_literal(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "      signers: '{{ pull_trigger_signers }}'",
            "      signers: ['ATTACKERFPR']",
        )
        self._assert_rule("R8 ansible/roles/pull_trigger/tasks/main.yml")

    # R8: the config writer takes its remote from a fork's literal.
    def test_r8_writer_remote_is_a_fork_literal(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "      remote_url: '{{ pull_trigger_remote_url }}'",
            "      remote_url: 'https://github.com/attacker/shared-infra.git'",
        )
        self._assert_rule("R8 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: a role task includes a file that is not YAML, which holds the signer list.
    def test_r6_task_includes_a_non_yaml_file(self) -> None:
        self._write("roles/pull_trigger/tasks/signers.txt", "pull_trigger_signers: [ATTACKERFPR]\n")
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Load a file\n  ansible.builtin.include_tasks: signers.txt\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: a role task includes a molecule scenario, which R6 does not read.
    def test_r6_task_includes_a_molecule_scenario(self) -> None:
        self._write(
            "roles/pull_trigger/molecule/default/converge.yml",
            "---\n- name: Trust a key\n  ansible.builtin.set_fact:\n"
            "    pull_trigger_signers: [ATTACKERFPR]\n",
        )
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Load a scenario\n"
            "  ansible.builtin.include_tasks: ../molecule/default/converge.yml\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: a molecule scenario is not read, so a signer list in one alone is not a finding.
    def test_r6_molecule_scenario_alone_is_not_read(self) -> None:
        self._write(
            "roles/pull_trigger/molecule/default/converge.yml",
            "---\n- name: Trust a key\n  ansible.builtin.set_fact:\n"
            "    pull_trigger_signers: [ATTACKERFPR]\n",
        )
        self.assertEqual(check(self.root), [])

    # R6: an argument spec is not read, so an option named like a key alone is not a finding.
    def test_r6_argument_specs_alone_is_not_read(self) -> None:
        self._write(
            "roles/pull_trigger/meta/argument_specs.yml",
            "---\nargument_specs:\n  main:\n    options:\n      pull_trigger_signers:\n"
            "        type: list\n",
        )
        self.assertEqual(check(self.root), [])

    # R6: a role task includes an argument spec, which R6 does not read.
    def test_r6_task_includes_an_argument_spec(self) -> None:
        self._write(
            "roles/pull_trigger/meta/argument_specs.yml",
            "---\nargument_specs:\n  main:\n    options:\n      pull_trigger_signers:\n"
            "        type: list\n",
        )
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Load a spec\n  ansible.builtin.include_tasks: ../meta/argument_specs.yml\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: a task includes a file by a templated name, which R6 cannot resolve.
    def test_r6_templated_include_target(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Load by name\n"
            "  ansible.builtin.include_tasks: '{{ pull_trigger_extra }}.yml'\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: a role task loads variables with include_vars, which R6 cannot read.
    def test_r6_role_task_includes_vars(self) -> None:
        self._write("roles/pull_trigger/vars/extra.yml", "---\npull_trigger_signers: []\n")
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Load variables\n  ansible.builtin.include_vars: extra.yml\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: an unparseable file is refused, not read as text, so a hidden key cannot pass.
    def test_r6_unparseable_file_is_refused(self) -> None:
        self._write(
            "roles/pull_trigger/tasks/broken.yml",
            "- name: x\n  set_fact: [\n    pull_trigger_signers: y\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/broken.yml")

    # R6: a role task sets the enrolled host, which decides the playbook derivation.
    def test_r6_role_task_sets_enrolled_host(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Name another host\n  ansible.builtin.set_fact:\n"
            "    enrolled_host: edge1\n\n- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R0: the signer assert gains a key that switches it off, one case per key.
    def test_r0_signer_assert_gains_a_switching_key(self) -> None:
        for key in ("when: false", "ignore_errors: true", "tags: [never]"):
            with self.subTest(key=key):
                self.setUp()
                self._edit(
                    "playbooks/includes/require_signers.yml",
                    "    quiet: true\n",
                    f"    quiet: true\n  {key}\n",
                )
                self._assert_rule("R0 playbooks/includes/require_signers.yml")

    # R0: the refusal assert gains a when key, which switches the one-host test off.
    def test_r0_refusal_assert_gains_when(self) -> None:
        self._edit(
            "playbooks/includes/refuse_other_hosts.yml",
            "    quiet: true\n",
            "    quiet: true\n  when: false\n",
        )
        self._assert_rule("R0 playbooks/includes/refuse_other_hosts.yml")

    # R0: the refusal assert gains ignore_errors or tags, which can skip it.
    def test_r0_refusal_assert_gains_a_skipping_key(self) -> None:
        for key in ("ignore_errors: true", "tags: [never]"):
            with self.subTest(key=key):
                self.setUp()
                self._edit(
                    "playbooks/includes/refuse_other_hosts.yml",
                    "    quiet: true\n",
                    f"    quiet: true\n  {key}\n",
                )
                self._assert_rule("R0 playbooks/includes/refuse_other_hosts.yml")

    # R6: a JSON file under the role's vars is loaded by Ansible, so R6 reads it.
    def test_r6_role_vars_json_sets_signer(self) -> None:
        self._write("roles/pull_trigger/vars/extra.json", '{"pull_trigger_signers": ["X"]}')
        self._assert_rule("R6 ansible/roles/pull_trigger/vars/extra.json")

    # R6: an extensionless file in group_vars is loaded by Ansible, so R6 reads it.
    def test_r6_extensionless_group_vars_sets_signer(self) -> None:
        self._write("inventories/production/group_vars/all", "---\npull_trigger_signers: []\n")
        self._assert_rule("R6 ansible/inventories/production/group_vars/all")

    # R6: a tool's own cache .gitignore is no loader's input, so it is not a vars file.
    def test_r6_tool_cache_gitignore_is_not_a_vars_file(self) -> None:
        self._write(".mypy_cache/.gitignore", "# Automatically created by mypy\n*\n")
        self.assertEqual(check(self.root), [])

    # R6: a ruff cache entry is binary, with no suffix, under a hidden cache directory; it is no
    # vars file, so it is not read as YAML and gives no finding.
    def test_r6_ruff_cache_entry_is_not_a_vars_file(self) -> None:
        self._write(".ruff_cache/.gitignore", "*\n")
        cache = self.ansible / ".ruff_cache" / "0.17.0"
        cache.mkdir(parents=True, exist_ok=True)
        (cache / "1a2b3c4d5e").write_bytes(b"\x00\x01\xff\xfe")
        self.assertEqual(check(self.root), [])

    # R6: a hidden artefact outside a loaded directory is still read; one that sets a signer is
    # refused.
    def test_r6_hidden_artefact_that_sets_signer_is_refused(self) -> None:
        self._write(".ruff_cache/0.17.0/1a2b3c4d5e", "---\npull_trigger_signers: []\n")
        self._assert_rule("R6 ansible/.ruff_cache/0.17.0/1a2b3c4d5e")

    # R6: a hidden extensionless file inside a loaded directory is still read.
    def test_r6_hidden_extensionless_group_vars_sets_signer(self) -> None:
        self._write("inventories/production/group_vars/.all", "---\npull_trigger_signers: []\n")
        self._assert_rule("R6 ansible/inventories/production/group_vars/.all")

    # R6: a plain suffix-less file outside every loaded directory that does not parse is refused.
    # Without the hidden-part term it would pass as a tool's artefact.
    def test_r6_unparseable_plain_file_outside_loaded_dirs_is_refused(self) -> None:
        self._write("NOTES", "pull_trigger_signers: [\n")
        self._assert_rule("R6 ansible/NOTES")

    # R6: a hidden suffix-less file inside a loaded directory that does not parse is refused.
    # Without the loaded-directory term it would pass as a tool's artefact.
    def test_r6_unparseable_hidden_extensionless_group_vars_is_refused(self) -> None:
        self._write("inventories/production/group_vars/.all", "pull_trigger_signers: [\n")
        self._assert_rule("R6 ansible/inventories/production/group_vars/.all")

    # R6: a hidden .yml that does not parse is refused. Without the suffix term it would pass as
    # a tool's artefact.
    def test_r6_unparseable_hidden_yml_is_refused(self) -> None:
        self._write(".hidden/broken.yml", "pull_trigger_signers: [\n")
        self._assert_rule("R6 ansible/.hidden/broken.yml")

    # R6: a JSON file that does not parse is refused, not skipped.
    def test_r6_unparseable_json_in_group_vars_is_refused(self) -> None:
        self._write("inventories/production/group_vars/broken.json", '{"pull_trigger_signers": ')
        self._assert_rule("R6 ansible/inventories/production/group_vars/broken.json")

    # R6: an include of a JSON file is refused, because R6 reads task files of .yml only.
    def test_r6_task_includes_a_json_file(self) -> None:
        self._write("roles/pull_trigger/tasks/signers.json", '{"pull_trigger_signers": ["X"]}')
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Load a json\n  ansible.builtin.include_tasks: signers.json\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: a symlink under a loaded directory that leads out of ansible/ is refused.
    def test_r6_symlink_out_of_ansible_in_vars_is_refused(self) -> None:
        outside = self.root / "outside.yml"
        outside.write_text("---\npull_trigger_signers: []\n", encoding="utf-8")
        link = self.ansible / "roles" / "pull_trigger" / "vars" / "link.yml"
        link.symlink_to(outside)
        self._assert_rule("R6 ansible/roles/pull_trigger/vars/link.yml")

    # R6: include_vars under its legacy FQCN is a loader R6 cannot read.
    def test_r6_legacy_fqcn_include_vars(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Load variables\n  ansible.legacy.include_vars: extra.yml\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: an action form of include_vars is a loader R6 cannot read.
    def test_r6_action_form_include_vars(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Load variables\n  action: include_vars extra.yml\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: include_role with tasks_from names a task file R6 does not read.
    def test_r6_include_role_with_tasks_from(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Run a role task file\n  ansible.builtin.include_role:\n"
            "    name: pull_trigger\n    tasks_from: extra\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: the bare include alias of a molecule scenario is a loader R6 cannot read.
    def test_r6_bare_include_alias_of_molecule(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Load a scenario\n  include: ../molecule/default/converge.yml\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: a set_fact written as a string assigns a protected key, which R6 reads.
    def test_r6_string_form_sets_a_signer(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Trust a key\n  ansible.builtin.set_fact: pull_trigger_signers=[X]\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: a key written with a template is refused, since R6 cannot resolve its name.
    def test_r6_templated_key_is_refused(self) -> None:
        self._write("roles/pull_trigger/vars/extra.yml", "---\n'{{ x }}': 1\n")
        self._assert_rule("R6 ansible/roles/pull_trigger/vars/extra.yml")

    # R6: vars_files outside an enrolled play is refused, the play it may be in is pinned by R2.
    def test_r6_vars_files_in_a_role_task(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "- name: Create the state directory\n",
            "- name: Load a file\n  vars_files: [extra.yml]\n\n"
            "- name: Create the state directory\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/tasks/main.yml")

    # R6: enrolled_host set in a task of an enrolled playbook names another host.
    def test_r6_enrolled_host_set_fact_in_a_playbook_task(self) -> None:
        self._edit(
            "playbooks/ops1.yml",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n",
            "    - role: ../roles/pull_trigger # noqa: role-name[path]\n"
            "  tasks:\n    - name: Name another host\n"
            "      ansible.builtin.set_fact:\n        enrolled_host: edge1\n",
        )
        self._assert_rule("R6 ansible/playbooks/ops1.yml")

    # R6: a top-level playbook that is not enrolled sets enrolled_host in its play vars.
    def test_r6_unenrolled_playbook_sets_enrolled_host(self) -> None:
        self._write(
            "playbooks/tmp9.yml",
            "---\n- name: x\n  hosts: all\n  vars:\n    enrolled_host: tmp9\n  tasks: []\n",
        )
        self._assert_rule("R6 ansible/playbooks/tmp9.yml")

    # R6: a role dependency that names a molecule scenario is refused.
    def test_r6_role_dependency_names_molecule(self) -> None:
        self._edit(
            "roles/pull_trigger/meta/main.yml",
            "  min_ansible_version: '2.21.5'\n",
            "  min_ansible_version: '2.21.5'\ndependencies:\n  - molecule/default\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/meta/main.yml")

    # R6: the molecule exclusion is for a role's molecule directory only, not group_vars.
    def test_r6_group_vars_molecule_is_read(self) -> None:
        self._write(
            "inventories/production/group_vars/molecule/all.yml",
            "---\npull_trigger_signers: []\n",
        )
        self._assert_rule("R6 ansible/inventories/production/group_vars/molecule/all.yml")

    # R6: meta/main.yml beside an argument spec stays read, only the spec file is excluded.
    def test_r6_meta_main_beside_argument_specs_is_read(self) -> None:
        self._edit(
            "roles/pull_trigger/meta/main.yml",
            "  min_ansible_version: '2.21.5'\n",
            "  min_ansible_version: '2.21.5'\npull_trigger_signers: []\n",
        )
        self._assert_rule("R6 ansible/roles/pull_trigger/meta/main.yml")

    # R8: a second task that carries the config var, after the writer, is a decoy writer.
    def test_r8_decoy_writer_after_the_real_one(self) -> None:
        self._write(
            "roles/pull_trigger/tasks/decoy.yml",
            "---\n- name: Decoy\n  ansible.builtin.copy:\n    content: 'x'\n"
            "    dest: /etc/x.json\n  vars:\n    pull_trigger_config:\n"
            "      signers: ['ATTACKERFPR']\n      remote_url: 'https://github.com/x/y.git'\n",
        )
        self._assert_rule("R8 roles/pull_trigger/tasks: found 2")

    # R8: the config writer's copy writes its content from a literal.
    def test_r8_writer_content_is_a_literal(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            '    content: "{{ pull_trigger_config | ansible.builtin.to_nice_json }}\\n"',
            "    content: 'x'",
        )
        self._assert_rule("R8 ansible/roles/pull_trigger/tasks/main.yml")

    # R8: the config writer's dest is a literal, not the pinned config path.
    def test_r8_writer_dest_is_a_literal(self) -> None:
        self._edit(
            "roles/pull_trigger/tasks/main.yml",
            "    dest: '{{ pull_trigger_config_path }}'\n    owner: root\n"
            "    group: root\n    mode: '0644'",
            "    dest: '/etc/pull-trigger/other.json'\n    owner: root\n"
            "    group: root\n    mode: '0644'",
        )
        self._assert_rule("R8 ansible/roles/pull_trigger/tasks/main.yml")

    # R8: a role with no config writer fails, it does not pass over nothing.
    def test_r8_no_writer(self) -> None:
        self._write(
            "roles/pull_trigger/tasks/main.yml",
            "---\n- name: x\n  ansible.builtin.debug:\n    msg: hi\n",
        )
        self._assert_rule("R8 roles/pull_trigger/tasks: found 0")

    # R10 and R2: owner_vars/. The real tree is green; each sabotage below is red on its rule.
    def _owner_vars(self, text: str) -> None:
        self._write("owner_vars/edge1.yml", text)

    def _assert_one(self, prefix: str) -> None:
        findings = check(self.root)
        self.assertTrue(
            any(finding.startswith(prefix) for finding in findings),
            f"expected a finding starting {prefix!r}, got {findings}",
        )

    # Control: a file the owner has filled in, with both modes and the flag on, passes. Without
    # this a check that refused every file would pass for a strict one.
    def test_r10_a_filled_owner_vars_file_passes(self) -> None:
        key = "ssh-ed25519 " + "A" * 68
        self._owner_vars(
            "---\nci_login_manage_keys: true\nci_login_keys:\n"
            f"  - key: {key} a\n    mode: apply\n  - key: {key} b\n    mode: check\n"
        )
        self.assertEqual(check(self.root), [])

    # R10: a key beyond the two the host is allowed.
    def test_r10_owner_vars_holds_an_extra_key(self) -> None:
        self._edit("owner_vars/edge1.yml", "ci_login_keys: []\n", "ci_login_keys: []\nextra: 1\n")
        self._assert_one("R10 owner_vars/edge1.yml: must hold exactly")

    # R10 and R6: a signer list in owner_vars is refused by both, whatever R10 allows.
    def test_r10_and_r6_owner_vars_sets_the_signer_list(self) -> None:
        self._edit(
            "owner_vars/edge1.yml",
            "ci_login_keys: []\n",
            "ci_login_keys: []\npull_trigger_signers: []\n",
        )
        self._assert_one("R10 owner_vars/edge1.yml")
        self._assert_one("R6 ansible/owner_vars/edge1.yml: sets pull_trigger_signers")

    # R10: the flag is one of the two allowed keys, so a file without it is refused.
    def test_r10_owner_vars_lacks_the_flag(self) -> None:
        self._owner_vars("---\nci_login_keys: []\n")
        self._assert_one("R10 owner_vars/edge1.yml: must hold exactly")

    # R10: the flag is a bool, not the text a YAML user might quote.
    def test_r10_owner_vars_flag_is_text(self) -> None:
        self._edit(
            "owner_vars/edge1.yml", "ci_login_manage_keys: false", "ci_login_manage_keys: 'false'"
        )
        self._assert_one("R10 owner_vars/edge1.yml: ci_login_manage_keys must be a bool")

    # R10: an entry holds a key and a mode and nothing else; a source limit has no place here.
    def test_r10_owner_vars_entry_carries_a_source_limit(self) -> None:
        self._edit(
            "owner_vars/edge1.yml",
            "ci_login_keys: []\n",
            "ci_login_keys:\n  - key: x\n    mode: apply\n    from_addresses: [192.0.2.1]\n",
        )
        self._assert_one("R10 owner_vars/edge1.yml: a ci_login_keys entry must hold exactly")

    # R10: the mode is one of the two commands.
    def test_r10_owner_vars_entry_has_an_unknown_mode(self) -> None:
        self._edit(
            "owner_vars/edge1.yml",
            "ci_login_keys: []\n",
            "ci_login_keys:\n  - key: x\n    mode: step\n",
        )
        self._assert_one("R10 owner_vars/edge1.yml: a ci_login_keys mode must be one of")

    # R10: the key list is a list.
    def test_r10_owner_vars_keys_is_not_a_list(self) -> None:
        self._edit("owner_vars/edge1.yml", "ci_login_keys: []", "ci_login_keys: nothing")
        self._assert_one("R10 owner_vars/edge1.yml: ci_login_keys must be a list")

    # R10: a file for a host that is not enrolled.
    def test_r10_owner_vars_file_without_an_enrolled_playbook(self) -> None:
        self._write("owner_vars/demo1.yml", "---\nci_login_keys: []\n")
        self._assert_one("R10 owner_vars/demo1.yml: has no enrolled playbook")

    # R10 and R2: an enrolled host that has no owner_vars keys may have no file, and its
    # playbook, which does not load it, disagrees with the file.
    def test_r10_owner_vars_file_for_a_host_with_no_keys(self) -> None:
        self._write("owner_vars/ops1.yml", "---\nci_login_keys: []\n")
        self._assert_one("R10 owner_vars/ops1.yml: this host has no owner_vars keys")
        self._assert_one("R2 ops1.yml: vars_files must be exactly")

    # R10: the name rule. A README, a nested file, another suffix and a link are refused.
    def test_r10_owner_vars_readme_is_refused(self) -> None:
        self._write("owner_vars/README.md", "# Notes\n\nProse only.\n")
        self._assert_one("R10 README.md: must be an exact .yml")

    def test_r10_owner_vars_nested_file_is_refused(self) -> None:
        self._write("owner_vars/sub/edge1.yml", "---\nci_login_keys: []\n")
        self._assert_one("R10 sub/edge1.yml: a .yml must sit at the top of owner_vars/")

    def test_r10_owner_vars_other_suffix_is_refused(self) -> None:
        self._write("owner_vars/edge1.yaml", "---\nci_login_keys: []\n")
        self._assert_one("R10 edge1.yaml: must be an exact .yml")

    def test_r10_owner_vars_link_is_refused(self) -> None:
        (self.ansible / "owner_vars" / "link.yml").symlink_to("edge1.yml")
        self._assert_one("R10 link.yml: is a link")

    # R2: the playbook must load the owner_vars file when it exists, and only then.
    def test_r2_owner_vars_entry_dropped_from_vars_files(self) -> None:
        self._edit(
            "playbooks/edge1.yml", "    - '{{ playbook_dir }}/../owner_vars/edge1.yml'\n", ""
        )
        self._assert_one("R2 edge1.yml: vars_files must be exactly")

    def test_r2_owner_vars_entry_without_the_file(self) -> None:
        (self.ansible / "owner_vars" / "edge1.yml").unlink()
        self._assert_one("R2 edge1.yml: vars_files must be exactly")

    def test_r2_owner_vars_entry_names_another_hosts_file(self) -> None:
        self._edit("playbooks/edge1.yml", "../owner_vars/edge1.yml", "../owner_vars/ops1.yml")
        self._assert_one("R2 edge1.yml: vars_files must be exactly")

    def test_r2_vars_files_gains_a_fourth_entry(self) -> None:
        self._edit(
            "playbooks/edge1.yml",
            "    - '{{ playbook_dir }}/../owner_vars/edge1.yml'\n",
            "    - '{{ playbook_dir }}/../owner_vars/edge1.yml'\n"
            "    - '{{ playbook_dir }}/../owner_vars/other.yml'\n",
        )
        self._assert_one("R2 edge1.yml: vars_files must be exactly")


if __name__ == "__main__":
    unittest.main()
