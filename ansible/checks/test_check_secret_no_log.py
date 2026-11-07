"""The secret taint check passes the real tree, and each sabotage of a rule is red.

Each sabotage copies the files the check reads into a scratch directory, breaks one control
in the copy, and asserts the finding. The baseline asserts the untouched copy is clean, so a
red result is the mutation and not the copy. The real-tree tests guard that the check still
sees the secrets it is meant to see, so it cannot pass by seeing nothing.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_secret_no_log as checker

ROOT = checker.ROOT
NTFY = "ansible/roles/ntfy_pager/tasks/main.yml"
MONITORING = "ansible/roles/monitoring_stack/tasks/main.yml"
CONTROL_PLANE = "ansible/roles/control_plane/tasks/main.yml"
LOADER = "ansible/roles/host_inputs/vars/main.yml"
HOST_INPUTS = "ansible/roles/host_inputs/tasks/main.yml"
TENANT_STACK = "ansible/roles/tenant_compose/tasks/_stack.yml"
TENANT_MAIN = "ansible/roles/tenant_compose/tasks/main.yml"
SECRETS_WRITE = (
    "    content: '{{ tenant_compose_stack.secrets_env_text }}'\n"
    "    dest: '{{ tenant_compose_env_path }}'\n"
    "    owner: root\n"
    "    group: root\n"
    "    mode: '0600'\n"
    "  register: tenant_compose_secrets_delivery\n"
    "  no_log: true\n"
)
README = "ansible/patterns/secrets_and_no_log/README.md"

NTFY_WRITE_TAIL = (
    "  no_log: true\n  diff: false\n"
    "  when: not ansible_check_mode or ntfy_pager_env_stat.stat.exists\n"
)
MONITORING_WRITE_TAIL = (
    "  no_log: true\n  diff: false\n"
    "  when: not ansible_check_mode or monitoring_stack_env_stat.stat.exists\n"
)
MASTERKEY_WRITE_TAIL = (
    "  no_log: true\n  diff: false\n"
    "  when: not control_plane_masterkey_stat.stat.exists "
    "or control_plane_masterkey_stat.stat.size == 0\n"
)


def _copy_tree(destination: Path) -> Path:
    """The files the check reads: the roles and patterns, the host lists, and the names' trees."""
    shutil.copytree(
        ROOT / "ansible",
        destination / "ansible",
        ignore=shutil.ignore_patterns("molecule", "__pycache__", "*.pyc"),
    )
    for tree in ("hetzner", "mail"):
        shutil.copytree(
            ROOT / tree, destination / tree, ignore=shutil.ignore_patterns("__pycache__")
        )
    for runbook in ROOT.glob("RUNBOOK*.md"):
        shutil.copy(runbook, destination / runbook.name)
    return destination


class SecretNoLogTest(unittest.TestCase):
    def setUp(self) -> None:
        self._scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self._scratch.cleanup)
        self.count = 0

    def _mutate(self, relative: str, old: str, new: str) -> Path:
        """A copy of the tree with one text changed once. The old text must occur exactly once."""
        self.count += 1
        root = _copy_tree(Path(self._scratch.name) / f"tree{self.count}")
        path = root / relative
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1, f"sabotage anchor not unique in {relative}")
        path.write_text(text.replace(old, new), encoding="utf-8")
        return root

    def _mutate_row(self, relative: str, fragments: tuple[str, ...], new_line: str | None) -> Path:
        """A copy of the tree with the one table row that holds every fragment replaced, or
        removed when new_line is None. Matching by cell text keeps the test off the padding."""
        self.count += 1
        root = _copy_tree(Path(self._scratch.name) / f"tree{self.count}")
        path = root / relative
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        hits = [i for i, line in enumerate(lines) if all(f in line for f in fragments)]
        self.assertEqual(len(hits), 1, f"sabotage row not unique in {relative}")
        if new_line is None:
            del lines[hits[0]]
        else:
            lines[hits[0]] = new_line + "\n"
        path.write_text("".join(lines), encoding="utf-8")
        return root

    def _findings(self, root: Path) -> list[str]:
        return checker.check(root)

    def _assert_red(self, findings: list[str], *fragments: str) -> None:
        self.assertTrue(findings, "expected a finding, the tree passed")
        for fragment in fragments:
            self.assertTrue(
                any(fragment in finding for finding in findings),
                f"no finding contains {fragment!r}; findings: {findings}",
            )

    # Baseline and guards on the real tree.

    def test_real_tree_passes(self) -> None:
        self.assertEqual(checker.check(ROOT), [])

    def test_copy_of_real_tree_is_clean(self) -> None:
        root = _copy_tree(Path(self._scratch.name) / "baseline")
        self.assertEqual(self._findings(root), [])

    def test_secret_set_guard(self) -> None:
        secrets = checker.secret_options(ROOT)
        self.assertIn("ntfy_pager_pager_token", secrets["ntfy_pager"])
        self.assertIn("control_plane_masterkey", secrets["control_plane"])
        self.assertGreaterEqual(sum(len(names) for names in secrets.values()), 20)

    def test_taint_reaches_the_derived_variables(self) -> None:
        self.assertIn("ntfy_pager_env_lines", checker.tainted(ROOT, "ntfy_pager"))
        self.assertIn("monitoring_stack_env_keys", checker.tainted(ROOT, "monitoring_stack"))

    def test_master_key_attribute_record_is_not_tainted(self) -> None:
        # A file-attributes record, not a value: the write task names the secret directly (S3).
        self.assertNotIn("control_plane_masterkey_secret", checker.tainted(ROOT, "control_plane"))

    def test_expression_only_reference_is_allowed(self) -> None:
        root = _copy_tree(Path(self._scratch.name) / "expression")
        path = root / NTFY
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\n- name: Expression only\n  ansible.builtin.assert:\n    that:\n"
            + "      - ntfy_pager_pager_token is defined\n",
            encoding="utf-8",
        )
        self.assertEqual(self._findings(root), [])

    # R1: sabotage of the taint controls. Each must be red, and the baseline above is green.

    def test_s1_removing_no_log_from_ntfy_write_is_red_and_names_the_chain(self) -> None:
        root = self._mutate(
            NTFY,
            NTFY_WRITE_TAIL,
            "  diff: false\n  when: not ansible_check_mode or ntfy_pager_env_stat.stat.exists\n",
        )
        self._assert_red(
            self._findings(root),
            "R1 " + NTFY,
            "Write the four NTFY_ lines into the pager secrets file",
            "ntfy_pager_env_lines (secret through",
            "ntfy_pager_pager_token",
            "must set no_log: true",
        )

    def test_s1b_templated_no_log_is_refused(self) -> None:
        root = self._mutate(
            NTFY,
            NTFY_WRITE_TAIL,
            "  no_log: '{{ true }}'\n  diff: false\n"
            "  when: not ansible_check_mode or ntfy_pager_env_stat.stat.exists\n",
        )
        self._assert_red(self._findings(root), "must set no_log: true")

    def test_s2_removing_no_log_from_monitoring_loop_is_red(self) -> None:
        root = self._mutate(
            MONITORING,
            MONITORING_WRITE_TAIL,
            "  diff: false\n"
            "  when: not ansible_check_mode or monitoring_stack_env_stat.stat.exists\n",
        )
        self._assert_red(
            self._findings(root),
            "R1 " + MONITORING,
            "monitoring_stack_env_keys (secret through",
            "monitoring_stack_smtp_password",
        )

    def test_s3_removing_no_log_from_master_key_write_is_red(self) -> None:
        root = self._mutate(
            CONTROL_PLANE,
            MASTERKEY_WRITE_TAIL,
            "  diff: false\n  when: not control_plane_masterkey_stat.stat.exists "
            "or control_plane_masterkey_stat.stat.size == 0\n",
        )
        self._assert_red(
            self._findings(root),
            "R1 " + CONTROL_PLANE,
            "Write the master key's content while the file is empty",
            "control_plane_masterkey",
            "must set no_log: true",
        )

    def test_s4_removing_diff_false_from_a_tainted_copy_is_red(self) -> None:
        root = self._mutate(
            CONTROL_PLANE,
            MASTERKEY_WRITE_TAIL,
            "  no_log: true\n  when: not control_plane_masterkey_stat.stat.exists "
            "or control_plane_masterkey_stat.stat.size == 0\n",
        )
        self._assert_red(self._findings(root), "must set diff: false (ANS-16)")

    def test_s4b_unparsable_template_in_a_task_is_red(self) -> None:
        root = self._mutate(
            NTFY,
            "- name: Create the directory of the pager secrets file",
            "- name: Broken\n  ansible.builtin.debug:\n    msg: '{{ ntfy_pager_pager_token '\n"
            "- name: Create the directory of the pager secrets file",
        )
        self._assert_red(self._findings(root), "does not parse")

    # R2: the loader's names.

    def test_s5_row_name_that_is_no_option_is_red(self) -> None:
        root = self._mutate(
            LOADER,
            "    - monitoring_stack_smtp_password\n",
            "    - monitoring_stack_smtp_passwd\n",
        )
        self._assert_red(self._findings(root), "R2", "monitoring_stack_smtp_passwd", "not one")

    def test_s5b_unreadable_rows_file_is_red(self) -> None:
        root = self._mutate(
            LOADER, "host_inputs_required_by_host:", "host_inputs_required_by_host: ["
        )
        self._assert_red(self._findings(root), "R2")

    # R3: the table agrees with the options and their sources.

    def test_s6_secret_option_without_row_is_red(self) -> None:
        root = self._mutate_row(README, ("`ntfy_pager`", "`ntfy_pager_pager_token`"), None)
        self._assert_red(
            self._findings(root),
            "R3",
            "no row for the no_log option ntfy_pager ntfy_pager_pager_token",
        )

    def test_s6b_row_with_wrong_source_is_red(self) -> None:
        root = self._mutate_row(
            README,
            ("`ci_jump`", "`ci_jump_user`"),
            "| `ci_jump` | `ci_jump_user` | host_inputs: edge1 |",
        )
        self._assert_red(
            self._findings(root), "R3", "ci_jump ci_jump_user has source 'host_inputs: edge1'"
        )

    def test_s6c_missing_table_is_red(self) -> None:
        root = self._mutate(README, "## The secret options of the roles", "## The secret options")
        self._assert_red(
            self._findings(root), "R3", "the table under '## The secret options of the roles'"
        )

    def test_s6d_script_name_that_nothing_reads_is_red(self) -> None:
        root = self._mutate(
            README,
            "| `STALWART_PROMETHEUS_SECRET`                 | `mail/provision`",
            "| `NO_SUCH_SCRIPT_NAME_ANYWHERE`               | `mail/provision`",
        )
        self._assert_red(self._findings(root), "R3", "NO_SUCH_SCRIPT_NAME_ANYWHERE")

    # R1 over the host_inputs loader: its own variables are seeds, because it declares no option.

    def test_h1_removing_no_log_from_the_loader_set_fact_is_red(self) -> None:
        # Reviewer sabotage 1: the task that sets every input of the host as a fact.
        root = self._mutate(
            HOST_INPUTS,
            "  no_log: true\n  diff: false\n\n"
            "- name: Drop the file's text from memory (no value is shown)\n",
            "  diff: false\n\n- name: Drop the file's text from memory (no value is shown)\n",
        )
        self._assert_red(
            self._findings(root),
            "R1 " + HOST_INPUTS,
            "Set each input the file holds",
            "host_inputs_doc",
            "must set no_log: true",
        )

    def test_h1b_removing_no_log_from_the_loader_parse_is_red(self) -> None:
        # The parse task: a parse error of Ansible's own echoes the text it could not parse.
        root = self._mutate(
            HOST_INPUTS,
            "from_json }}'\n      no_log: true\n      diff: false\n",
            "from_json }}'\n      diff: false\n",
        )
        self._assert_red(
            self._findings(root),
            "R1 " + HOST_INPUTS,
            "Parse the file",
            "host_inputs_raw",
            "must set no_log: true",
        )

    def test_h1c_loader_variable_that_no_task_names_is_red(self) -> None:
        # A renamed loader variable must not leave the check looking at nothing.
        seeds = {**checker.LOADER_SEEDS, "host_inputs": ("host_inputs_raw", "host_inputs_gone")}
        with mock.patch.object(checker, "LOADER_SEEDS", seeds):
            findings = checker.check(ROOT)
        self._assert_red(findings, "host_inputs_gone", "is named by no task")

    # R1 over a secret held on a sub-option of a list option.

    def test_h2_sub_option_guard(self) -> None:
        subs = checker.sub_option_secrets(ROOT)
        self.assertEqual(subs["tenant_compose"], {"tenant_compose_stacks": {"secrets_env_text"}})
        self.assertEqual(subs["ci_jump"], {"ci_jump_keys": {"key"}})
        self.assertEqual(subs["deploy_slot_keys"], {"deploy_slot_keys_slots": {"public_key"}})
        self.assertEqual(subs["compose_stack"], {"compose_stack_secret_files": {"content"}})
        self.assertEqual(subs["secrets_and_no_log"], {"secrets_and_no_log_secrets": {"value"}})

    def test_h2_removing_no_log_from_the_tenant_secrets_write_is_red(self) -> None:
        # Reviewer sabotage 2: the write of a tenant's secrets file. The secret is read through
        # the loop variable of the include in main.yml, so the taint must follow that loop.
        root = self._mutate(
            TENANT_STACK,
            "  register: tenant_compose_secrets_delivery\n  no_log: true\n  diff: false\n",
            "  register: tenant_compose_secrets_delivery\n  diff: false\n",
        )
        self._assert_red(
            self._findings(root),
            "R1 " + TENANT_STACK,
            "Deliver the secrets file",
            "tenant_compose_stack (secret through tenant_compose_stacks.secrets_env_text)",
            "must set no_log: true",
        )

    def test_h2b_removing_diff_false_from_the_tenant_secrets_write_is_red(self) -> None:
        root = self._mutate(
            TENANT_STACK,
            "  register: tenant_compose_secrets_delivery\n  no_log: true\n  diff: false\n",
            "  register: tenant_compose_secrets_delivery\n  no_log: true\n",
        )
        self._assert_red(self._findings(root), "Deliver the secrets file", "diff: false (ANS-16)")

    def test_h2c_removing_no_log_from_the_loop_over_the_tenants_is_red(self) -> None:
        root = self._mutate(
            TENANT_MAIN,
            "    label: '{{ tenant_compose_stack.slug }}'\n  no_log: true\n",
            "    label: '{{ tenant_compose_stack.slug }}'\n",
        )
        self._assert_red(
            self._findings(root),
            "R1 " + TENANT_MAIN,
            "Deliver each tenant's stack",
            "tenant_compose_stacks (secret through tenant_compose_stacks.secrets_env_text)",
        )

    def test_h2d_loop_over_secrets_with_include_and_default_item_is_red(self) -> None:
        root = self._mutate(
            TENANT_MAIN,
            "    loop_var: tenant_compose_stack\n    label: '{{ tenant_compose_stack.slug }}'\n",
            "    label: '{{ item.slug }}'\n",
        )
        self._assert_red(
            self._findings(root), "Deliver each tenant's stack", "must name a loop_var"
        )

    def test_h2e_reading_a_secret_attribute_without_no_log_is_red(self) -> None:
        root = self._append_task(
            TENANT_STACK, "    msg: '{{ tenant_compose_stack.secrets_env_text }}'"
        )
        self._assert_red(self._findings(root), "R1 " + TENANT_STACK, "Appended task")

    def test_h2f_reading_another_attribute_without_no_log_is_clean(self) -> None:
        root = self._append_task(TENANT_STACK, "    msg: '{{ tenant_compose_stack.slug }}'")
        self.assertEqual(self._findings(root), [])

    def test_h2g_removing_no_log_from_the_other_sub_option_roles_is_red(self) -> None:
        cases = (
            (
                "ansible/roles/deploy_slot_keys/tasks/main.yml",
                "  failed_when: false\n  no_log: true\n  diff: false\n  when: not (ansible",
                "  failed_when: false\n  diff: false\n  when: not (ansible",
                "Make the deploy slots exactly the declared list",
            ),
            (
                "ansible/patterns/compose_stack/tasks/main.yml",
                "  register: compose_stack_secret_delivery\n  no_log: true\n",
                "  register: compose_stack_secret_delivery\n",
                "Deliver the secret files",
            ),
            (
                "ansible/roles/ci_jump/tasks/_readback.yml",
                "ci_jump_readback\n  failed_when: false\n  changed_when: false\n  no_log: true\n",
                "ci_jump_readback\n  failed_when: false\n  changed_when: false\n",
                "Read both files back",
            ),
            (
                "ansible/patterns/secrets_and_no_log/tasks/main.yml",
                "      no_log: true\n      diff: false\n      register: secrets_and_no_log_wri",
                "      diff: false\n      register: secrets_and_no_log_wri",
                "Write the secrets given as values",
            ),
        )
        for relative, old, new, task in cases:
            with self.subTest(task=task):
                self._assert_red(
                    self._findings(self._mutate(relative, old, new)),
                    "R1 " + relative,
                    task,
                    "must set no_log: true",
                )

    # A method call on a tainted value reads it too: only a declared non-secret attribute is
    # cleared, so .get('secret'), .items(), .values() and chains of calls all need no_log.

    def _secrets_write(self, expression: str, no_log: bool) -> Path:
        """A copy of the tree where the tenant secrets-file write reads `expression`, with or
        without its no_log. The anchor is the write task from its content to its no_log."""
        old = SECRETS_WRITE
        new = old.replace(
            "'{{ tenant_compose_stack.secrets_env_text }}'", '"{{ ' + expression + ' }}"'
        )
        if not no_log:
            new = new.replace("  no_log: true\n", "")
        self.assertNotEqual(old, new, "the sabotage changed nothing")
        return self._mutate(TENANT_STACK, old, new)

    def test_h3_reviewer_sabotage_get_without_no_log_is_red(self) -> None:
        root = self._secrets_write("tenant_compose_stack.get('secrets_env_text')", no_log=False)
        self._assert_red(
            self._findings(root),
            "R1 " + TENANT_STACK,
            "Deliver the secrets file",
            "tenant_compose_stack (secret through tenant_compose_stacks.secrets_env_text)",
            "must set no_log: true",
        )

    def test_h3_every_way_of_reading_the_item_needs_no_log(self) -> None:
        spellings = (
            "tenant_compose_stack.get('secrets_env_text')",
            "tenant_compose_stack.get('secrets_env_text', '')",
            "tenant_compose_stack.items() | list",
            "tenant_compose_stack.values() | list",
            "tenant_compose_stack.copy()",
            "tenant_compose_stack.get('secrets_env_text').strip()",
            "tenant_compose_stack.items() | list | first | last",
            "tenant_compose_stack['secrets_env_text']",
            "tenant_compose_stack.undeclared_name",
            "tenant_compose_stack | to_json",
        )
        for expression in spellings:
            with self.subTest(expression=expression):
                self.assertEqual(
                    self._findings(self._secrets_write(expression, no_log=True)),
                    [],
                    "the same read with no_log must be green, or the red below proves nothing",
                )
                self._assert_red(
                    self._findings(self._secrets_write(expression, no_log=False)),
                    "Deliver the secrets file",
                    "must set no_log: true",
                )

    def test_h3_a_call_on_a_declared_safe_attribute_stays_clean(self) -> None:
        for expression in (
            "tenant_compose_stack.slug",
            "tenant_compose_stack['slug']",
            "tenant_compose_stack.slug.upper()",
            "tenant_compose_stack.compose_text | length",
        ):
            with self.subTest(expression=expression):
                root = self._secrets_write(expression, no_log=False)
                self.assertEqual(self._findings(root), [])

    # A name an include binds in its `vars:` is read by the included file, and no_log on the
    # include does not reach that file, so the name carries the taint of its value.

    def _tenant_alias(self, value: str, no_log: bool) -> Path:
        """A copy of the tree where the include of the tenants binds `tenant_compose_alias` to
        `value` and the secrets-file write in _stack.yml writes that name, with or without its
        no_log and diff: false."""
        root = self._mutate(
            TENANT_MAIN,
            "    tenant_compose_is_spool: false\n",
            "    tenant_compose_is_spool: false\n    tenant_compose_alias: '{{ " + value + " }}'\n",
        )
        path = root / TENANT_STACK
        text = path.read_text(encoding="utf-8")
        old = SECRETS_WRITE + "  diff: false\n"
        self.assertEqual(text.count(old), 1, "sabotage anchor not unique")
        new = old.replace("tenant_compose_stack.secrets_env_text", "tenant_compose_alias")
        if not no_log:
            new = new.replace("  no_log: true\n  diff: false\n", "")
        path.write_text(text.replace(old, new), encoding="utf-8")
        return root

    def test_h4_include_var_alias_of_a_secret_attribute_needs_no_log(self) -> None:
        # Reviewer sabotage 4: the exact shape that passed before the include vars were followed.
        value = "tenant_compose_stack.secrets_env_text"
        self.assertEqual(
            self._findings(self._tenant_alias(value, no_log=True)),
            [],
            "the same write with no_log and diff: false must be green, or the red proves nothing",
        )
        self._assert_red(
            self._findings(self._tenant_alias(value, no_log=False)),
            "R1 " + TENANT_STACK,
            "Deliver the secrets file",
            "tenant_compose_alias (secret through tenant_compose_stacks.secrets_env_text)",
            "must set no_log: true",
            "must set diff: false (ANS-16)",
        )

    def test_h4_include_var_alias_of_the_whole_item_keeps_its_secret_attributes(self) -> None:
        # A bare partial name is bound as the same partial, so its secret attribute still counts.
        self.assertEqual(
            self._findings(self._tenant_alias("tenant_compose_stack", no_log=True)), []
        )
        self._assert_red(
            self._findings(self._tenant_alias("tenant_compose_stack", no_log=False)),
            "Deliver the secrets file",
            "must set no_log: true",
        )

    def test_h4_include_var_bound_from_a_non_secret_attribute_stays_clean(self) -> None:
        root = self._tenant_alias("tenant_compose_stack.slug", no_log=False)
        self.assertEqual(self._findings(root), [])

    def test_h4_an_alias_of_an_alias_is_followed(self) -> None:
        root = self._mutate(
            TENANT_MAIN,
            "    tenant_compose_is_spool: false\n",
            "    tenant_compose_is_spool: false\n"
            "    tenant_compose_first: '{{ tenant_compose_stack.secrets_env_text }}'\n"
            "    tenant_compose_second: '{{ tenant_compose_first | trim }}'\n",
        )
        path = root / TENANT_STACK
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\n- name: Appended task\n  ansible.builtin.debug:\n"
            + "    msg: '{{ tenant_compose_second }}'\n",
            encoding="utf-8",
        )
        self._assert_red(self._findings(root), "Appended task", "tenant_compose_second")

    def _ntfy_include(self, include: str, probe: str) -> Path:
        """A copy of the tree where the pager role includes a new file, binding the pager token
        under the name probe_token. `include` is the include task's key line and `probe` the
        tail of the write task in the included file."""
        self.count += 1
        root = _copy_tree(Path(self._scratch.name) / f"tree{self.count}")
        main = root / NTFY
        main.write_text(
            main.read_text(encoding="utf-8")
            + "\n- name: Probe through an include\n"
            + include
            + "  vars:\n    probe_token: '{{ ntfy_pager_pager_token }}'\n  no_log: true\n",
            encoding="utf-8",
        )
        (main.parent / "_probe.yml").write_text(
            "---\n- name: Write the probe\n  ansible.builtin.copy:\n"
            "    content: '{{ probe_token }}'\n    dest: /tmp/probe\n" + probe,
            encoding="utf-8",
        )
        return root

    def test_h4_a_whole_secret_bound_on_an_include_needs_no_log_in_the_included_file(self) -> None:
        include = "  ansible.builtin.include_tasks: _probe.yml\n"
        self.assertEqual(
            self._findings(self._ntfy_include(include, "  no_log: true\n  diff: false\n")), []
        )
        self._assert_red(
            self._findings(self._ntfy_include(include, "")),
            "R1 ansible/roles/ntfy_pager/tasks/_probe.yml",
            "Write the probe",
            "probe_token (secret through ntfy_pager_pager_token)",
            "must set no_log: true",
        )

    def test_h4_import_tasks_and_a_dictionary_form_are_followed_too(self) -> None:
        for include in (
            "  ansible.builtin.import_tasks: _probe.yml\n",
            "  ansible.builtin.include_tasks:\n    file: _probe.yml\n",
        ):
            with self.subTest(include=include):
                self._assert_red(
                    self._findings(self._ntfy_include(include, "")),
                    "R1 ansible/roles/ntfy_pager/tasks/_probe.yml",
                    "must set no_log: true",
                )

    def test_h4_a_secret_passed_to_a_file_that_cannot_be_followed_is_red(self) -> None:
        for include in (
            "  ansible.builtin.include_tasks: '{{ ntfy_pager_probe_file }}'\n",
            "  ansible.builtin.include_tasks: missing_file.yml\n",
            "  ansible.builtin.include_role:\n    name: ntfy_pager\n",
        ):
            with self.subTest(include=include):
                self._assert_red(
                    self._findings(self._ntfy_include(include, "  no_log: true\n  diff: false\n")),
                    "R1 " + NTFY,
                    "Probe through an include",
                    "probe_token",
                    "cannot be followed",
                )

    def _append_task(self, relative: str, argument_line: str) -> Path:
        """A copy of the tree with a debug task, without no_log, added to the end of a task file."""
        self.count += 1
        root = _copy_tree(Path(self._scratch.name) / f"tree{self.count}")
        path = root / relative
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\n- name: Appended task\n  ansible.builtin.debug:\n"
            + argument_line
            + "\n",
            encoding="utf-8",
        )
        return root


if __name__ == "__main__":
    unittest.main()
