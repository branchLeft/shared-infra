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
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import check_secret_no_log as checker

ROOT = checker.ROOT
NTFY = "ansible/roles/ntfy_pager/tasks/main.yml"
PROBE_VALUE = "'{{ ntfy_pager_pager_token }}'"
VARS_BINDING = f"  vars:\n    probe_token: {PROBE_VALUE}\n"
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

    def _assert_red(self, findings: list[str], *fragments: str, because: str = "") -> None:
        """`because` names the mechanism under test, so a failure says which one went unread."""
        reason = f" ({because})" if because else ""
        self.assertTrue(findings, f"expected a finding{reason}, the tree passed")
        for fragment in fragments:
            self.assertTrue(
                any(fragment in finding for finding in findings),
                f"no finding contains {fragment!r}{reason}; findings: {findings}",
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

    def _ntfy_include(self, include: str, probe: str, binding: str = VARS_BINDING) -> Path:
        """A copy of the tree where the pager role includes a new file, binding the pager token
        under the name probe_token. `include` is the include task's key lines, `binding` the
        lines that bind the name (the task's own `vars:` unless the test puts it elsewhere) and
        `probe` the tail of the write task in the included file."""
        self.count += 1
        root = _copy_tree(Path(self._scratch.name) / f"tree{self.count}")
        main = root / NTFY
        main.write_text(
            main.read_text(encoding="utf-8")
            + "\n- name: Probe through an include\n"
            + include
            + binding
            + "  no_log: true\n",
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

    def _assert_binding_reaches_the_file(
        self, include: str, binding_of: Callable[[str], str], because: str
    ) -> None:
        """One binding form, three trees: the secret under it and a write with no_log and
        diff: false is green; a non-secret under it and an unprotected write is green; the secret
        under it and an unprotected write is red and names the bound name and the included task."""
        safe = "  no_log: true\n  diff: false\n"
        self.assertEqual(
            self._findings(self._ntfy_include(include, safe, binding_of(PROBE_VALUE))),
            [],
            "the protected write must be green, or the red proves nothing",
        )
        self.assertEqual(
            self._findings(self._ntfy_include(include, "", binding_of("plain"))),
            [],
            "a non-secret bound the same way must be green, or the red is not the secret",
        )
        self._assert_red(
            self._findings(self._ntfy_include(include, "", binding_of(PROBE_VALUE))),
            "R1 ansible/roles/ntfy_pager/tasks/_probe.yml",
            "Write the probe",
            "probe_token (secret through ntfy_pager_pager_token)",
            "must set no_log: true",
            because=because,
        )

    def test_h5_apply_vars_under_the_task_args_keyword_is_followed(self) -> None:
        # Ansible merges the task's `args:` into the include's arguments, so `apply:` there binds.
        # import_tasks is not in this test: Ansible rejects `apply` on it (task_include.py,
        # check_options, "Invalid options for import_tasks: apply"), so the form never runs.
        self._assert_binding_reaches_the_file(
            "  ansible.builtin.include_tasks: _probe.yml\n",
            lambda value: f"  args:\n    apply:\n      vars:\n        probe_token: {value}\n",
            "include_tasks binds under the task args: keyword, apply: vars:",
        )

    def test_h5_file_and_apply_both_under_the_task_args_keyword_are_followed(self) -> None:
        # The include's own value is empty: `args:` names the file and carries the binding.
        self._assert_binding_reaches_the_file(
            "  ansible.builtin.include_tasks:\n",
            lambda value: (
                "  args:\n    file: _probe.yml\n    apply:\n      vars:\n"
                f"        probe_token: {value}\n"
            ),
            "include_tasks takes its file and its apply: vars: from the task args: keyword",
        )

    def test_h5_apply_vars_under_the_includes_own_mapping_is_followed(self) -> None:
        def include(value: str) -> str:
            return (
                "  ansible.builtin.include_tasks:\n    file: _probe.yml\n    apply:\n      vars:\n"
                f"        probe_token: {value}\n"
            )

        safe = "  no_log: true\n  diff: false\n"
        self.assertEqual(self._findings(self._ntfy_include(include(PROBE_VALUE), safe, "")), [])
        self.assertEqual(
            self._findings(self._ntfy_include(include("plain"), "", "")),
            [],
            "a non-secret under the include's own apply must be green",
        )
        self._assert_red(
            self._findings(self._ntfy_include(include(PROBE_VALUE), "", "")),
            "R1 ansible/roles/ntfy_pager/tasks/_probe.yml",
            "Write the probe",
            "probe_token (secret through ntfy_pager_pager_token)",
            "must set no_log: true",
            because="apply: vars: under the include's own mapping",
        )

    def test_h5_an_apply_under_the_task_args_of_a_role_include_cannot_be_followed(self) -> None:
        self._assert_red(
            self._findings(
                self._ntfy_include(
                    "  ansible.builtin.include_role:\n    name: ntfy_pager\n",
                    "  no_log: true\n  diff: false\n",
                    "  args:\n    apply:\n      vars:\n        probe_token: " + PROBE_VALUE + "\n",
                )
            ),
            "R1 " + NTFY,
            "Probe through an include",
            "probe_token",
            "cannot be followed",
            because="a role include binding under the task args: keyword",
        )

    def test_h5_task_args_that_is_not_a_mapping_is_a_finding(self) -> None:
        mapping = "  args:\n    apply:\n      vars:\n        probe_token: plain\n"
        self.assertEqual(
            self._findings(
                self._ntfy_include("  ansible.builtin.include_tasks: _probe.yml\n", "", mapping)
            ),
            [],
            "the same include with a mapping for args: and nothing secret must be green",
        )
        for args in ("'{{ probe_args }}'", "[apply]", "_probe.yml"):
            with self.subTest(args=args):
                self._assert_red(
                    self._findings(
                        self._ntfy_include(
                            "  ansible.builtin.include_tasks: _probe.yml\n",
                            "",
                            f"  args: {args}\n",
                        )
                    ),
                    "R4 " + NTFY,
                    "Probe through an include",
                    "Ansible's own task parser refuses it",
                    because=f"task args: that is not a mapping, {args}",
                )

    def test_h5_an_include_value_that_is_not_text_or_a_mapping_is_a_finding(self) -> None:
        self._assert_red(
            self._findings(
                self._ntfy_include("  ansible.builtin.include_tasks: [_probe.yml]\n", "")
            ),
            "R4 " + NTFY,
            "Probe through an include",
            "Ansible's own task parser refuses it",
            because="an include value that is neither text nor a mapping",
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


MINI_SPEC = (
    "---\nargument_specs:\n  main:\n    options:\n      probe_secret:\n"
    "        type: str\n        no_log: true\n"
)
PROTECT = "  no_log: true\n  diff: false\n"
APPLY_FLAT = "  args:\n    apply:\n      vars:\n        probe_token: '{{ probe_secret }}'\n"
APPLY_NESTED = "    apply:\n      vars:\n        probe_token: '{{ probe_secret }}'\n"
WRITE_BOUND = (
    "---\n- name: Write the probe\n  ansible.builtin.copy:\n"
    "    content: '{{ probe_token }}'\n    dest: /tmp/probe\n"
)
BENIGN = "---\n- name: Benign\n  ansible.builtin.debug:\n    msg: fine\n"

# Each spelling of an include that Ansible's parser accepts: the lines that name `{file}`, and the
# lines that bind a secret under `apply: vars:` in the spelling's own place (None: `apply` is not
# accepted on an import).
FILE_INCLUDES: dict[str, tuple[str, str | None]] = {
    "include_tasks": ("  ansible.builtin.include_tasks: {file}\n", APPLY_FLAT),
    "bare include_tasks": ("  include_tasks: {file}\n", APPLY_FLAT),
    "ansible.legacy.include_tasks": ("  ansible.legacy.include_tasks: {file}\n", APPLY_FLAT),
    "action: string": ("  action: ansible.builtin.include_tasks {file}\n", APPLY_FLAT),
    "action: bare name": ("  action: include_tasks {file}\n", APPLY_FLAT),
    "own mapping file:": ("  ansible.builtin.include_tasks:\n    file: {file}\n", APPLY_NESTED),
    "own mapping _raw_params:": (
        "  ansible.legacy.include_tasks:\n    _raw_params: {file}\n",
        APPLY_NESTED,
    ),
    "args: file:": ("  ansible.builtin.include_tasks:\n  args:\n    file: {file}\n", APPLY_NESTED),
    "args: _raw_params:": (
        "  ansible.legacy.include_tasks:\n  args:\n    _raw_params: {file}\n",
        APPLY_NESTED,
    ),
    "import_tasks": ("  ansible.builtin.import_tasks: {file}\n", None),
    "bare import_tasks": ("  import_tasks: {file}\n", None),
    "ansible.legacy.import_tasks": ("  ansible.legacy.import_tasks: {file}\n", None),
    "action: import_tasks": ("  action: import_tasks {file}\n", None),
    "import own mapping": ("  ansible.builtin.import_tasks:\n    file: {file}\n", None),
    "import args: file:": ("  ansible.builtin.import_tasks:\n  args:\n    file: {file}\n", None),
}
ROLE_INCLUDES = {
    "include_role": "  ansible.builtin.include_role:\n    name: other\n",
    "import_role": "  ansible.builtin.import_role:\n    name: other\n",
    "bare include_role": "  include_role:\n    name: other\n",
    "ansible.legacy.include_role": "  ansible.legacy.include_role:\n    name: other\n",
    "ansible.legacy.import_role": "  ansible.legacy.import_role:\n    name: other\n",
    "action: include_role": "  action: include_role name=other\n",
    "action: import_role": "  action: ansible.builtin.import_role name=other\n",
    "args: name:": "  ansible.builtin.include_role:\n  args:\n    name: other\n",
    "role: alias": "  ansible.builtin.include_role:\n    role: other\n",
}
# Spellings of a file write whose content is the secret itself.
COPY_SPELLINGS = {
    "ansible.builtin.copy": (
        "  ansible.builtin.copy:\n    content: '{{ probe_secret }}'\n    dest: /tmp/probe\n"
    ),
    "ansible.legacy.copy": (
        "  ansible.legacy.copy:\n    content: '{{ probe_secret }}'\n    dest: /tmp/probe\n"
    ),
    "bare copy": "  copy:\n    content: '{{ probe_secret }}'\n    dest: /tmp/probe\n",
    "free-form copy": "  copy: content='{{ probe_secret }}' dest=/tmp/probe\n",
    "action: string": (
        "  action: ansible.builtin.copy content='{{ probe_secret }}' dest=/tmp/probe\n"
    ),
    "action: bare name": "  action: copy content='{{ probe_secret }}' dest=/tmp/probe\n",
    "local_action:": "  local_action: copy content='{{ probe_secret }}' dest=/tmp/probe\n",
    "args: keyword": (
        "  ansible.builtin.copy:\n  args:\n    content: '{{ probe_secret }}'\n"
        "    dest: /tmp/probe\n"
    ),
}
TEMPLATE_SPELLINGS = {
    "ansible.builtin.template": (
        "  ansible.builtin.template:\n    src: probe.j2\n    dest: /tmp/probe\n"
    ),
    "ansible.legacy.template": (
        "  ansible.legacy.template:\n    src: probe.j2\n    dest: /tmp/probe\n"
    ),
    "free-form template": "  template: src=probe.j2 dest=/tmp/probe\n",
    "action: string": "  action: ansible.builtin.template src=probe.j2 dest=/tmp/probe\n",
    "args: keyword": (
        "  ansible.builtin.template:\n  args:\n    src: probe.j2\n    dest: /tmp/probe\n"
    ),
}
ASSERT_SPELLINGS = {
    "ansible.builtin.assert": (
        "  ansible.builtin.assert:\n    that:\n      - probe_secret is defined\n{extra}"
    ),
    "ansible.legacy.assert": (
        "  ansible.legacy.assert:\n    that:\n      - probe_secret is defined\n{extra}"
    ),
    "bare assert": "  assert:\n    that:\n      - probe_secret is defined\n{extra}",
    "action: string": "  action: ansible.builtin.assert that='probe_secret is defined'\n{extra}",
    "args: keyword": (
        "  ansible.builtin.assert:\n  args:\n    that:\n      - probe_secret is defined\n{extra}"
    ),
}


class TaskParserTest(unittest.TestCase):
    """Task and include resolution is Ansible's own: every spelling its parser accepts resolves
    to what the executor would run, and one it cannot resolve is a finding (R4).

    Each test builds a one-role tree whose only secret is `probe_secret`, so it is fast, and
    follows the same rule as the sabotage tests above: a green control for the same shape, then
    the red. The control proves the red is the spelling and not the tree."""

    def setUp(self) -> None:
        self._scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self._scratch.cleanup)
        self.count = 0

    def _role(self, files: dict[str, str], *, secret: bool = True) -> list[str]:
        """R1 and R4 over a one-role tree with the given files (path in the role: text)."""
        self.count += 1
        root = Path(self._scratch.name) / f"tree{self.count}"
        role = root / "ansible" / "roles" / "probe"
        (role / "meta").mkdir(parents=True)
        spec = MINI_SPEC if secret else MINI_SPEC.replace("no_log: true", "no_log: false")
        (role / "meta" / "argument_specs.yml").write_text(spec, encoding="utf-8")
        for relative, text in files.items():
            path = role / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        findings: list[str] = []
        checker._r1(root, findings)
        return list(dict.fromkeys(findings))

    @staticmethod
    def _main(
        task_lines: str, name: str = "Probe through an include", tail: str = "  no_log: true\n"
    ) -> str:
        """A task file of one task. The default tail is what an include may carry: Ansible
        rejects `diff:` on an include (TaskInclude.VALID_INCLUDE_KEYWORDS), so the parser would
        refuse a fixture that put it there."""
        return f"---\n- name: {name}\n{task_lines}{tail}"

    def _include(
        self, spelling: str, file: str, files: dict[str, str] | None = None, apply: bool = False
    ) -> list[str]:
        """The findings for the one include spelling naming `file`, with the usual task files
        beside it (a followed `_probe.yml` that writes the bound secret under no_log, `benign.yml`,
        and the same write under `files/`, which the check does not read)."""
        head, apply_lines = FILE_INCLUDES[spelling]
        lines = head.format(file=file) + (apply_lines or "" if apply else "")
        tree = {
            "tasks/main.yml": self._main(lines),
            "tasks/_probe.yml": WRITE_BOUND + PROTECT,
            "tasks/benign.yml": BENIGN,
            "files/_probe.yml": WRITE_BOUND + PROTECT,
        }
        tree.update(files or {})
        return self._role(tree)

    def _red(self, findings: list[str], *fragments: str, because: str) -> None:
        self.assertTrue(findings, f"expected a finding ({because}), the tree passed")
        for fragment in fragments:
            self.assertTrue(
                any(fragment in finding for finding in findings),
                f"no finding contains {fragment!r} ({because}); findings: {findings}",
            )

    # An include is followed to the file the executor would include, whatever its spelling.

    def test_every_spelling_of_a_file_include_is_followed_to_its_file(self) -> None:
        for spelling in FILE_INCLUDES:
            with self.subTest(spelling=spelling):
                self.assertEqual(
                    self._include(spelling, "_probe.yml"),
                    [],
                    "naming a task file the check reads must be green, or the red proves nothing",
                )
                self._red(
                    self._include(spelling, "../files/_probe.yml"),
                    "R4 ansible/roles/probe/tasks/main.yml",
                    "Probe through an include",
                    "cannot be followed",
                    "not a task file",
                    because=f"{spelling} naming a file outside tasks/ and handlers/",
                )

    def test_a_secret_bound_under_apply_reaches_the_included_file_in_every_spelling(self) -> None:
        for spelling, (_, apply_lines) in FILE_INCLUDES.items():
            if apply_lines is None:
                continue
            with self.subTest(spelling=spelling):
                self.assertEqual(
                    self._include(spelling, "_probe.yml", apply=True),
                    [],
                    "the protected write must be green, or the red proves nothing",
                )
                self._red(
                    self._include(
                        spelling,
                        "_probe.yml",
                        {"tasks/_probe.yml": WRITE_BOUND},
                        apply=True,
                    ),
                    "R1 ansible/roles/probe/tasks/_probe.yml",
                    "Write the probe",
                    "probe_token (secret through probe_secret)",
                    "must set no_log: true",
                    because=f"{spelling} binding a secret under apply: vars:",
                )

    def test_import_tasks_with_apply_is_refused_as_ansible_refuses_it(self) -> None:
        for lines in (
            "  ansible.builtin.import_tasks:\n    file: _probe.yml\n" + APPLY_NESTED,
            "  ansible.legacy.import_tasks: _probe.yml\n" + APPLY_FLAT,
            "  action: import_tasks _probe.yml\n" + APPLY_FLAT,
        ):
            with self.subTest(lines=lines):
                self._red(
                    self._role(
                        {"tasks/main.yml": self._main(lines), "tasks/_probe.yml": WRITE_BOUND}
                    ),
                    "R4 ansible/roles/probe/tasks/main.yml",
                    "Ansible's own task parser refuses it",
                    "apply",
                    because="Ansible rejects apply on an import_tasks",
                )

    # Which of two names for the file Ansible includes: `_raw_params` when set, else `file`.

    def _both(self, raw: str, file: str, form: int) -> list[str]:
        lines = (
            f"  ansible.builtin.include_tasks: {raw}\n  args:\n    file: {file}\n",
            f"  ansible.builtin.include_tasks:\n    _raw_params: {raw}\n    file: {file}\n",
            "  ansible.builtin.include_tasks:\n  args:\n"
            f"    _raw_params: {raw}\n    file: {file}\n",
        )[form]
        return self._role(
            {
                "tasks/main.yml": self._main(lines),
                "tasks/_probe.yml": WRITE_BOUND + PROTECT,
                "tasks/benign.yml": BENIGN,
                "files/_probe.yml": WRITE_BOUND,
            }
        )

    def test_when_both_raw_params_and_file_are_set_the_raw_params_file_is_followed(self) -> None:
        for form in range(3):
            with self.subTest(form=form):
                # `_raw_params` names a followed file and `file` an unread one: the executor
                # includes the first, so the include is followed and clean.
                self.assertEqual(self._both("_probe.yml", "../files/_probe.yml", form), [])
                self.assertEqual(self._both("_probe.yml", "benign.yml", form), [])
                # `_raw_params` names the unread file and `file` a followed one: the executor
                # includes the unread one, so the include is not followed.
                self._red(
                    self._both("../files/_probe.yml", "_probe.yml", form),
                    "R4 ansible/roles/probe/tasks/main.yml",
                    "Probe through an include",
                    "not a task file",
                    because="raw params naming an unread file, file naming a followed one",
                )
                self._red(
                    self._both("'{{ role_path }}/files/_probe.yml'", "benign.yml", form),
                    "R4 ansible/roles/probe/tasks/main.yml",
                    "named by a template",
                    because="templated raw params, file naming a followed file",
                )

    # An include of a role is not followed, whatever its spelling.

    def test_every_spelling_of_a_role_include_is_a_finding(self) -> None:
        for spelling, lines in ROLE_INCLUDES.items():
            with self.subTest(spelling=spelling):
                self._red(
                    self._role({"tasks/main.yml": self._main(lines)}),
                    "R4 ansible/roles/probe/tasks/main.yml",
                    "Probe through an include",
                    "cannot be followed",
                    "includes a role",
                    because=f"{spelling} includes a role the check does not read",
                )

    # What Ansible's parser refuses, or cannot resolve, is a finding and never a pass.

    def test_an_include_shape_ansible_refuses_is_a_finding(self) -> None:
        shapes = {
            "null value, no args": "  ansible.builtin.include_tasks:\n",
            "empty mapping": "  ansible.builtin.include_tasks: {}\n",
            "list value": "  ansible.builtin.include_tasks: [_probe.yml]\n",
            "unknown key": "  ansible.builtin.include_tasks:\n    file: _probe.yml\n    frob: 1\n",
            "args not a mapping": "  ansible.builtin.include_tasks: _probe.yml\n  args: [apply]\n",
            "args a template": "  ansible.builtin.include_tasks: _probe.yml\n  args: '{{ a }}'\n",
            "args a string": "  ansible.builtin.include_tasks: _probe.yml\n  args: _probe.yml\n",
            "apply not a mapping": (
                "  ansible.builtin.include_tasks:\n    file: _probe.yml\n    apply: x\n"
            ),
            "import null": "  ansible.legacy.import_tasks:\n",
            "role without a name": "  ansible.builtin.include_role:\n    tasks_from: x\n",
            "vars a list": "  ansible.builtin.include_tasks: _probe.yml\n  vars:\n    - a: b\n",
            "local_action, which delegates": "  local_action: include_tasks _probe.yml\n",
            "diff on an include": "  ansible.builtin.include_tasks: _probe.yml\n  diff: false\n",
        }
        for label, lines in shapes.items():
            with self.subTest(shape=label):
                self._red(
                    self._role(
                        {"tasks/main.yml": self._main(lines), "tasks/_probe.yml": WRITE_BOUND}
                    ),
                    "R4 ansible/roles/probe/tasks/main.yml",
                    "Probe through an include",
                    "cannot be followed",
                    "Ansible's own task parser refuses it",
                    because=label,
                )

    def test_an_include_whose_file_cannot_be_chosen_without_running_it_is_a_finding(self) -> None:
        names = {
            "template in the free-form text": "'{{ probe_file }}'",
            "template with a statement": "'{% if a %}x{% endif %}.yml'",
            "template in part of the name": "'_{{ probe_part }}.yml'",
        }
        for label, name in names.items():
            for head in (
                f"  ansible.builtin.include_tasks: {name}\n",
                f"  ansible.builtin.import_tasks:\n    file: {name}\n",
                f"  action: include_tasks {name}\n",
            ):
                with self.subTest(label=label, head=head):
                    self._red(
                        self._role(
                            {"tasks/main.yml": self._main(head), "tasks/_probe.yml": BENIGN}
                        ),
                        "R4 ansible/roles/probe/tasks/main.yml",
                        "named by a template",
                        because=f"{label}: no static target",
                    )

    def test_an_include_of_a_file_that_is_not_there_is_a_finding(self) -> None:
        self._red(
            self._role(
                {"tasks/main.yml": self._main("  ansible.builtin.include_tasks: gone.yml\n")}
            ),
            "R4 ansible/roles/probe/tasks/main.yml",
            "not a task file",
            because="a literal name that no file answers",
        )

    def test_an_action_ansible_cannot_resolve_is_a_finding(self) -> None:
        cases = {
            "unknown action": "  frobnicate: x\n",
            "bare include, removed from ansible-core": "  include: _probe.yml\n",
            "templated action": "  action: '{{ probe_action }} a=b'\n",
            "unknown collection module": "  no_such.collection.module:\n    a: b\n",
            "two actions": "  ansible.builtin.debug:\n    msg: a\n  ansible.builtin.ping:\n",
            "action is not text": "  action: [debug]\n",
        }
        for label, lines in cases.items():
            with self.subTest(case=label):
                self._red(
                    self._role({"tasks/main.yml": self._main(lines, "Odd task")}),
                    "R4 ansible/roles/probe/tasks/main.yml",
                    "Odd task",
                    "cannot be followed",
                    because=label,
                )

    def test_a_module_ansible_resolves_is_followed_and_clean(self) -> None:
        # The control for the refusals above: the same tree shape with a task Ansible resolves.
        main = (
            "---\n- name: Plain\n  ansible.builtin.debug:\n    msg: fine\n"
            "- name: Short name\n  debug:\n    msg: fine\n"
            "- name: Legacy name\n  ansible.legacy.debug:\n    msg: fine\n"
            "- name: Action string\n  action: ansible.builtin.debug msg=fine\n"
            "- name: Meta\n  ansible.builtin.meta: flush_handlers\n"
            "- name: Loop with a lookup\n  ansible.builtin.debug:\n    msg: '{{ item }}'\n"
            "  with_items: [a, b]\n"
        )
        self.assertEqual(self._role({"tasks/main.yml": main}), [])

    def test_a_role_without_a_secret_is_not_read_by_the_parser(self) -> None:
        # R4 follows only roles that hold a secret: the check is about where a secret goes.
        self.assertEqual(
            self._role({"tasks/main.yml": self._main("  frobnicate: x\n")}, secret=False), []
        )

    # The kind of task is what Ansible resolves, so a file write or an assert is the same
    # whatever its spelling: the rules for `copy`, `template` and `assert` apply to all of them.

    def test_every_spelling_of_a_file_write_needs_no_log_and_diff_false(self) -> None:
        for spelling, lines in COPY_SPELLINGS.items():
            with self.subTest(spelling=spelling):
                protected = {"tasks/main.yml": self._main(lines, "Write it", PROTECT)}
                self.assertEqual(self._role(protected), [], "the protected write must be green")
                self._red(
                    self._role(
                        {"tasks/main.yml": self._main(lines, "Write it", "  no_log: true\n")}
                    ),
                    "R1 ansible/roles/probe/tasks/main.yml",
                    "Write it",
                    "must set diff: false (ANS-16)",
                    because=f"{spelling} writing a secret without diff: false",
                )
                self._red(
                    self._role(
                        {"tasks/main.yml": self._main(lines, "Write it", "  diff: false\n")}
                    ),
                    "R1 ansible/roles/probe/tasks/main.yml",
                    "Write it",
                    "must set no_log: true",
                    because=f"{spelling} writing a secret without no_log",
                )

    def test_every_spelling_of_a_template_task_reads_its_template(self) -> None:
        template = "value={{ probe_secret }}\n"
        for spelling, lines in TEMPLATE_SPELLINGS.items():
            with self.subTest(spelling=spelling):
                files = {"templates/probe.j2": template}
                self.assertEqual(
                    self._role(
                        {**files, "tasks/main.yml": self._main(lines, "Render it", PROTECT)}
                    ),
                    [],
                    "the protected template task must be green",
                )
                self._red(
                    self._role(
                        {
                            **files,
                            "tasks/main.yml": self._main(lines, "Render it", "  diff: false\n"),
                        }
                    ),
                    "R1 ansible/roles/probe/tasks/main.yml",
                    "Render it",
                    "must set no_log: true",
                    because=f"{spelling} rendering a template that names a secret",
                )
                self._red(
                    self._role({"tasks/main.yml": self._main(lines, "Render it")}),
                    "R1 ansible/roles/probe/tasks/main.yml",
                    "Render it",
                    "names a template that cannot be read",
                    because=f"{spelling} naming a template that is missing",
                )

    def test_every_spelling_of_an_assert_is_an_expression_only_read(self) -> None:
        for spelling, lines in ASSERT_SPELLINGS.items():
            with self.subTest(spelling=spelling):
                quiet = lines.format(extra="")
                self.assertEqual(
                    self._role({"tasks/main.yml": self._main(quiet, "Check it", "")}),
                    [],
                    "an assert whose `that` names a secret is an expression-only read",
                )
                loud = lines.format(extra="    fail_msg: '{{ probe_secret }}'\n")
                if spelling.startswith("action"):
                    loud = lines.format(extra="  vars:\n    probe_copy: '{{ probe_secret }}'\n")
                self._red(
                    self._role({"tasks/main.yml": self._main(loud, "Check it", "")}),
                    "R1 ansible/roles/probe/tasks/main.yml",
                    "Check it",
                    "must set no_log: true",
                    because=f"{spelling} naming a secret outside its `that`",
                )

    def test_a_loop_over_a_secret_that_includes_with_the_default_item_is_a_finding(self) -> None:
        for head in (
            "  ansible.legacy.include_tasks: _probe.yml\n",
            "  action: include_tasks _probe.yml\n",
            "  ansible.builtin.import_tasks:\n  args:\n    file: _probe.yml\n",
        ):
            with self.subTest(head=head):
                lines = head + "  loop: '{{ probe_secret }}'\n"
                if "import_tasks" in head:
                    lines = head.replace("import_tasks", "include_tasks") + (
                        "  loop: '{{ probe_secret }}'\n"
                    )
                self._red(
                    self._role({"tasks/main.yml": self._main(lines), "tasks/_probe.yml": BENIGN}),
                    "R1 ansible/roles/probe/tasks/main.yml",
                    "must name a loop_var",
                    because="a loop over a secret that includes tasks reads it through item",
                )

    # Handlers are loaded as handlers, and an include there is followed within handlers/.

    def test_handlers_and_their_includes_are_resolved_as_handlers(self) -> None:
        handler = (
            "---\n- name: Reload it\n  listen: probe reload\n  ansible.builtin.debug:\n"
            "    msg: fine\n"
            "- name: Reload more\n  listen: probe reload\n"
            "  ansible.legacy.include_tasks: _more.yml\n"
        )
        self.assertEqual(
            self._role({"handlers/main.yml": handler, "handlers/_more.yml": BENIGN}), []
        )
        self._red(
            self._role({"handlers/main.yml": handler}),
            "R4 ansible/roles/probe/handlers/main.yml",
            "Reload more",
            "not a task file",
            because="a handler include of a file that is not in handlers/",
        )
        self._red(
            self._role(
                {
                    "handlers/main.yml": handler.replace(
                        "ansible.builtin.debug:\n    msg: fine",
                        "ansible.builtin.debug:\n    msg: '{{ probe_secret }}'",
                    ),
                    "handlers/_more.yml": BENIGN,
                }
            ),
            "R1 ansible/roles/probe/handlers/main.yml",
            "Reload it",
            "must set no_log: true",
            because="a handler that names a secret",
        )


if __name__ == "__main__":
    unittest.main()
