"""Tests that the host_inputs loader, its per-host rows and the host role lists agree.

The rows in the role's vars/main.yml, the literal keys of its one set_fact task and the
host's list in checks/host_roles.yml must say the same thing. A name in a row must be a
required argument, with no default (ANS-16), of a role on that host's list, and a host with
a row must apply the loader. The role's tasks are held to structure too: nothing skippable,
content-touching tasks hidden, every check before the first input is set. Each mutation
edits a small copy of the tree and must produce its own finding.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from check_enrolment import HOST_ROLES_FILE, PROTECTED_KEYS, PULL_ROLES, ROOT

LOADER = "host_inputs"
ROW_VAR = "host_inputs_required_by_host"
SET_TASK_PREFIX = "Set each input"
VALUE_EXPRESSION = "{{{{ host_inputs_doc['{key}'] | default(omit) }}}}"
# Keys that make a task skippable, ignorable, or re-routable. None may appear on any task. A
# loop is not one: the stat of the directories above the file loops over a constant list, and
# an empty loop leaves every directory unconfirmed, which the next task refuses.
FORBIDDEN_TASK_KEYS = frozenset(
    (
        "when",
        "ignore_errors",
        "ignore_unreachable",
        "failed_when",
        "changed_when",
        "tags",
        "check_mode",
        "delegate_to",
        "run_once",
    )
)
# The modules whose result carries the file's content or a value taken from it.
HIDING_MODULES = frozenset(("ansible.builtin.slurp", "ansible.builtin.set_fact"))
CHECK_MODULES = frozenset(("ansible.builtin.assert", "ansible.builtin.fail"))
# The role's own scratch names start with this; an input never may.
INTERNAL_PREFIX = "host_inputs_"


def _mapping(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    return {}


def _names(value: object) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _read(path: Path) -> object:
    if not path.is_file():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _flatten(tasks: object) -> list[dict[str, object]]:
    """Every task of a task list, with the tasks inside block, rescue and always after it."""
    flat: list[dict[str, object]] = []
    if not isinstance(tasks, list):
        return flat
    for entry in tasks:
        task = _mapping(entry)
        flat.append(task)
        for section in ("block", "rescue", "always"):
            flat.extend(_flatten(task.get(section)))
    return flat


def _module(task: dict[str, object]) -> str:
    for key in task:
        if key.startswith("ansible.builtin."):
            return key
    return ""


def rows_of(ansible: Path) -> dict[str, list[str]]:
    doc = _mapping(_read(ansible / "roles" / LOADER / "vars" / "main.yml"))
    return {host: _names(names) for host, names in _mapping(doc.get(ROW_VAR)).items()}


def _top_tasks(ansible: Path) -> list[dict[str, object]]:
    doc = _read(ansible / "roles" / LOADER / "tasks" / "main.yml")
    return [_mapping(entry) for entry in doc] if isinstance(doc, list) else []


def _is_input_task(task: dict[str, object]) -> bool:
    keys = _mapping(task.get("ansible.builtin.set_fact"))
    return any(not key.startswith(INTERNAL_PREFIX) for key in keys)


def _required_options(ansible: Path, role: str) -> dict[str, bool]:
    """The options of a role's main entry point, each True when required and with no default.
    A role with no directory yet has none."""
    spec = _mapping(_read(ansible / "roles" / role / "meta" / "argument_specs.yml"))
    options = _mapping(_mapping(_mapping(spec.get("argument_specs")).get("main")).get("options"))
    defaults = _mapping(_read(ansible / "roles" / role / "defaults" / "main.yml"))
    found: dict[str, bool] = {}
    for name, raw in options.items():
        option = _mapping(raw)
        found[name] = (
            option.get("required") is True and "default" not in option and name not in defaults
        )
    return found


def _declared_with_default(ansible: Path, role: str, name: str) -> bool:
    spec = _mapping(_read(ansible / "roles" / role / "meta" / "argument_specs.yml"))
    options = _mapping(_mapping(_mapping(spec.get("argument_specs")).get("main")).get("options"))
    defaults = _mapping(_read(ansible / "roles" / role / "defaults" / "main.yml"))
    return name in defaults or "default" in _mapping(options.get(name))


def _check_rows(ansible: Path, rows: dict[str, list[str]], findings: list[str]) -> None:
    host_roles = _mapping(_read(ansible / HOST_ROLES_FILE))
    for host, names in sorted(rows.items()):
        label = f"row {host}"
        if not names or len(set(names)) != len(names):
            findings.append(f"{label}: must be a non-empty list of distinct names")
        listed = _names(host_roles.get(host))
        if LOADER not in listed:
            findings.append(f"{label}: {LOADER} is not on {host}'s list in {HOST_ROLES_FILE}")
        for name in names:
            if name in PROTECTED_KEYS or name.startswith(INTERNAL_PREFIX):
                findings.append(f"{label}: {name} is a protected or internal name")
            required = [
                r for r in listed if r != LOADER and _required_options(ansible, r).get(name)
            ]
            if not required:
                findings.append(
                    f"{label}: {name} is not a required argument, without a default, "
                    f"of any role on {host}'s list"
                )
            for role in listed:
                if role != LOADER and _declared_with_default(ansible, role, name):
                    findings.append(f"{label}: role {role} gives {name} a default (ANS-16)")
        playbook = _mapping_list(_read(ansible / "playbooks" / f"{host}.yml"))
        applied = [Path(str(entry.get("role", entry))).name for entry in playbook]
        if LOADER not in applied:
            findings.append(f"{label}: playbooks/{host}.yml does not apply {LOADER}")
        elif set(applied[: applied.index(LOADER)]) - PULL_ROLES:
            findings.append(f"{label}: playbooks/{host}.yml applies a role before {LOADER}")


def _mapping_list(doc: object) -> list[dict[str, object]]:
    """The role entries of the one play of a host playbook."""
    plays = doc if isinstance(doc, list) else []
    roles = _mapping(plays[0]).get("roles") if plays else None
    return [_mapping(entry) for entry in roles] if isinstance(roles, list) else []


def _check_set_task(
    tasks: list[dict[str, object]], rows: dict[str, list[str]], findings: list[str]
) -> None:
    setters = [task for task in tasks if _is_input_task(task)]
    if len(setters) != 1 or not str(setters[0].get("name", "")).startswith(SET_TASK_PREFIX):
        findings.append(f"tasks: want exactly one input task, named '{SET_TASK_PREFIX}...'")
        return
    keys = _mapping(setters[0]["ansible.builtin.set_fact"])
    wanted = sorted({name for names in rows.values() for name in names})
    if sorted(keys) != wanted:
        findings.append(f"tasks: the input task sets {sorted(keys)}, the rows name {wanted}")
    for key, value in keys.items():
        if value != VALUE_EXPRESSION.format(key=key):
            findings.append(f"tasks: the value of {key} must be exactly the loader's expression")
    index = tasks.index(setters[0])
    after = tasks[index + 1 :]
    if any(
        bool(CHECK_MODULES & set(task))
        or "block" in task
        or _module(task) != "ansible.builtin.set_fact"
        or _is_input_task(task)
        for task in after
    ):
        findings.append("tasks: only the clearing of the loader's own facts may follow the inputs")
    if not any(CHECK_MODULES & set(task) for task in tasks[:index]):
        findings.append("tasks: no check comes before the inputs are set")


def _check_tasks(ansible: Path, findings: list[str]) -> None:
    for task in _flatten(_read(ansible / "roles" / LOADER / "tasks" / "main.yml")):
        name = str(task.get("name", "?"))
        for key in sorted(FORBIDDEN_TASK_KEYS & set(task)):
            findings.append(f"tasks: '{name}' has {key}, which could skip or ignore it")
        if _module(task) in HIDING_MODULES and not (
            task.get("no_log") is True and task.get("diff") is False
        ):
            findings.append(f"tasks: '{name}' must have no_log: true and diff: false")


def problems(ansible: Path) -> list[str]:
    """Every way the loader, its rows and the host lists disagree. Empty when they agree."""
    findings: list[str] = []
    rows = rows_of(ansible)
    if not rows:
        findings.append(f"vars/main.yml: {ROW_VAR} holds no host")
    _check_rows(ansible, rows, findings)
    _check_set_task(_top_tasks(ansible), rows, findings)
    _check_tasks(ansible, findings)
    return findings


class RealTree(unittest.TestCase):
    def test_the_loader_the_rows_and_the_host_lists_agree(self) -> None:
        self.assertEqual(problems(ROOT / "ansible"), [])

    def test_the_rows_name_the_db1_and_app1_inputs(self) -> None:
        # Pinned, so that an edit which changed a row and the loader together still shows.
        self.assertEqual(
            rows_of(ROOT / "ansible"),
            {
                "db1": [
                    "db1_stack_exporter_password",
                    "db1_grants_tenants",
                    "db1_grants_ops1_host",
                ],
                "app1": [
                    "website_app1_smtp_host",
                    "website_app1_smtp_port",
                    "website_app1_smtp_user",
                    "website_app1_smtp_password",
                    "deploy_slot_keys_slots",
                ],
            },
        )

    def test_app1_applies_the_loader_then_the_website_role_and_the_deploy_roles(self) -> None:
        # The order is the point: the loader sets the four SMTP facts the website role requires and
        # the slots the slot-keys role requires, so both must follow it, and all must follow the
        # two pull roles (check_enrolment R11). The host baseline installs Docker, which the
        # website role needs, so it too sits before the role. The deploy tooling goes last but one
        # and the slot keys last: the slot program needs the wrapper the tooling installs.
        playbook = _mapping_list(_read(ROOT / "ansible" / "playbooks" / "app1.yml"))
        applied = [Path(str(entry.get("role", entry))).name for entry in playbook]
        self.assertEqual(
            applied,
            [
                "ansible_runtime",
                "pull_trigger",
                LOADER,
                "host_baseline",
                "breakglass_grant_host",
                "website_app1",
                "deploy_tooling",
                "deploy_slot_keys",
            ],
        )


class Mutations(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.ansible = Path(temp.name) / "ansible"
        real = ROOT / "ansible"
        leave_out = shutil.ignore_patterns("molecule", "tests", "files", "templates")
        for role in (
            LOADER,
            "db1_stack",
            "db1_grants",
            "db1_backup_timers",
            "tunnel_account",
            "website_app1",
            "deploy_tooling",
            "deploy_slot_keys",
        ):
            shutil.copytree(real / "roles" / role, self.ansible / "roles" / role, ignore=leave_out)
        (self.ansible / "checks").mkdir()
        shutil.copy(real / HOST_ROLES_FILE, self.ansible / HOST_ROLES_FILE)
        (self.ansible / "playbooks").mkdir()
        for host in ("db1", "app1"):
            shutil.copy(
                real / "playbooks" / f"{host}.yml", self.ansible / "playbooks" / f"{host}.yml"
            )

    def _edit(self, relative: str, old: str, new: str) -> None:
        path = self.ansible / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text, f"the mutation matched nothing in {relative}")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def _expect(self, fragment: str) -> None:
        found = problems(self.ansible)
        self.assertTrue(any(fragment in finding for finding in found), (fragment, found))

    def test_the_copy_passes_before_any_mutation(self) -> None:
        self.assertEqual(problems(self.ansible), [])

    def test_a_key_set_by_the_loader_with_no_row_is_found(self) -> None:
        self._edit(
            "roles/host_inputs/tasks/main.yml",
            "    db1_grants_ops1_host: ",
            "    control_plane_master_key: \"{{ host_inputs_doc['control_plane_master_key']"
            ' | default(omit) }}"\n    db1_grants_ops1_host: ',
        )
        self._expect("the input task sets")

    def test_a_row_name_the_loader_does_not_set_is_found(self) -> None:
        self._edit(
            "roles/host_inputs/vars/main.yml",
            "    - db1_grants_ops1_host\n",
            "    - db1_grants_ops1_host\n    - db1_backup_extra\n",
        )
        self._expect("the input task sets")

    def test_a_row_name_that_is_no_roles_required_argument_is_found(self) -> None:
        self._edit(
            "roles/host_inputs/vars/main.yml",
            "    - db1_stack_exporter_password\n",
            "    - db1_stack_exporter_passwrod\n",
        )
        self._expect("db1_stack_exporter_passwrod is not a required argument")

    def test_a_default_in_a_roles_defaults_file_is_found(self) -> None:
        path = self.ansible / "roles" / "db1_grants" / "defaults" / "main.yml"
        path.write_text("db1_grants_ops1_host: 192.0.2.1\n", encoding="utf-8")
        self._expect("role db1_grants gives db1_grants_ops1_host a default")
        self._expect("db1_grants_ops1_host is not a required argument")

    def test_a_default_in_a_roles_argument_spec_is_found(self) -> None:
        self._edit(
            "roles/db1_stack/meta/argument_specs.yml",
            "        required: true\n        no_log: true\n",
            "        required: true\n        no_log: true\n        default: changeme\n",
        )
        self._expect("role db1_stack gives db1_stack_exporter_password a default")

    def test_a_protected_name_in_a_row_is_found(self) -> None:
        self._edit(
            "roles/host_inputs/vars/main.yml",
            "    - db1_grants_ops1_host\n",
            "    - db1_grants_ops1_host\n    - pull_trigger_signers\n",
        )
        self._expect("pull_trigger_signers is a protected or internal name")

    def test_a_host_with_a_row_but_no_loader_on_its_list_is_found(self) -> None:
        self._edit("checks/host_roles.yml", "db1:\n  - host_inputs\n", "db1:\n")
        self._expect("host_inputs is not on db1's list")

    def test_app1_with_a_row_but_no_loader_on_its_list_is_found(self) -> None:
        self._edit("checks/host_roles.yml", "app1:\n  - host_inputs\n", "app1:\n")
        self._expect("host_inputs is not on app1's list")

    def test_an_app1_row_name_that_is_no_roles_required_argument_is_found(self) -> None:
        self._edit(
            "roles/host_inputs/vars/main.yml",
            "    - website_app1_smtp_password\n",
            "    - website_app1_smtp_passwrod\n",
        )
        self._expect("website_app1_smtp_passwrod is not a required argument")

    def test_a_default_for_the_website_roles_smtp_port_is_found(self) -> None:
        path = self.ansible / "roles" / "website_app1" / "defaults" / "main.yml"
        path.write_text(
            path.read_text(encoding="utf-8") + "website_app1_smtp_port: '25'\n", encoding="utf-8"
        )
        self._expect("role website_app1 gives website_app1_smtp_port a default")

    def test_the_website_role_applied_before_the_loader_on_app1_is_found(self) -> None:
        self._edit(
            "playbooks/app1.yml",
            "    - role: ../roles/host_inputs # noqa: role-name[path]\n",
            "    - role: ../roles/website_app1 # noqa: role-name[path]\n"
            "    - role: ../roles/host_inputs # noqa: role-name[path]\n",
        )
        self._expect("playbooks/app1.yml applies a role before host_inputs")

    def test_an_app1_input_the_loader_sets_with_no_row_is_found(self) -> None:
        self._edit("roles/host_inputs/vars/main.yml", "    - website_app1_smtp_user\n", "")
        self._expect("the input task sets")

    # Safety class: the deploy slots are private (tenant stack names and public keys), so the loader
    # is their only route onto a pulled host. Red with the name taken from app1's row while the
    # loader still sets it, green with the row as it is.
    def test_the_deploy_slots_dropped_from_app1s_row_are_found(self) -> None:
        self._edit("roles/host_inputs/vars/main.yml", "    - deploy_slot_keys_slots\n", "")
        self._expect("the input task sets")

    def test_a_misspelt_deploy_slots_name_in_app1s_row_is_found(self) -> None:
        self._edit(
            "roles/host_inputs/vars/main.yml",
            "    - deploy_slot_keys_slots\n",
            "    - deploy_slot_keys_slotz\n",
        )
        self._expect("deploy_slot_keys_slotz is not a required argument")

    def test_a_default_for_the_deploy_slots_is_found(self) -> None:
        path = self.ansible / "roles" / "deploy_slot_keys" / "defaults" / "main.yml"
        path.write_text("deploy_slot_keys_slots: []\n", encoding="utf-8")
        self._expect("role deploy_slot_keys gives deploy_slot_keys_slots a default")

    def test_the_deploy_slots_role_applied_before_the_loader_on_app1_is_found(self) -> None:
        self._edit(
            "playbooks/app1.yml",
            "    - role: ../roles/host_inputs # noqa: role-name[path]\n",
            "    - role: ../roles/deploy_slot_keys # noqa: role-name[path]\n"
            "    - role: ../roles/host_inputs # noqa: role-name[path]\n",
        )
        self._expect("playbooks/app1.yml applies a role before host_inputs")

    def test_a_host_playbook_that_does_not_apply_the_loader_is_found(self) -> None:
        self._edit(
            "playbooks/db1.yml", "    - role: ../roles/host_inputs # noqa: role-name[path]\n", ""
        )
        self._expect("playbooks/db1.yml does not apply host_inputs")

    def test_a_role_applied_before_the_loader_is_found(self) -> None:
        self._edit(
            "playbooks/db1.yml",
            "    - role: ../roles/host_inputs # noqa: role-name[path]\n",
            "    - role: ../roles/db1_stack # noqa: role-name[path]\n"
            "    - role: ../roles/host_inputs # noqa: role-name[path]\n",
        )
        self._expect("applies a role before host_inputs")

    def test_a_when_on_a_task_is_found(self) -> None:
        self._edit(
            "roles/host_inputs/tasks/main.yml",
            "- name: Refuse a file that is not one JSON object\n",
            "- name: Refuse a file that is not one JSON object\n  when: false\n",
        )
        self._expect("has when, which could skip or ignore it")

    def test_an_ignored_failure_in_the_block_is_found(self) -> None:
        self._edit(
            "roles/host_inputs/tasks/main.yml",
            "    - name: Parse the file (no value is shown)\n",
            "    - name: Parse the file (no value is shown)\n      ignore_errors: true\n",
        )
        self._expect("has ignore_errors")

    def test_a_task_that_shows_the_content_is_found(self) -> None:
        self._edit(
            "roles/host_inputs/tasks/main.yml",
            "        host_inputs_doc: '{{ host_inputs_raw.content | b64decode | from_json }}'\n"
            "      no_log: true\n",
            "        host_inputs_doc: '{{ host_inputs_raw.content | b64decode | from_json }}'\n",
        )
        self._expect("'Parse the file (no value is shown)' must have no_log: true")

    def test_a_check_after_the_inputs_are_set_is_found(self) -> None:
        path = self.ansible / "roles" / LOADER / "tasks" / "main.yml"
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\n- name: A late check\n  ansible.builtin.assert:\n    that:\n      - true\n",
            encoding="utf-8",
        )
        self._expect("only the clearing of the loader's own facts may follow the inputs")

    def test_a_value_expression_that_is_not_the_loaders_is_found(self) -> None:
        self._edit(
            "roles/host_inputs/tasks/main.yml",
            "{{ host_inputs_doc['db1_grants_tenants'] | default(omit) }}",
            "{{ host_inputs_doc['db1_grants_tenants'] | default([]) }}",
        )
        self._expect("the value of db1_grants_tenants must be exactly the loader's expression")


if __name__ == "__main__":
    unittest.main()
