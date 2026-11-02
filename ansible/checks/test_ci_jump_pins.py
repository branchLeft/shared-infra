"""Pins on the ci_jump role: its copies stay equal to their homes, its output stays out of the plan
scan, and the order and hiding of its tasks stay as they are.

The role writes the key options of the account the gated run jumps through, so a drift here is a
silent widening or a plan that is withheld. Each pin is shown red on a sabotaged copy of the files
it reads, and green again once the file is put back.

The plan scan. The gated apply withholds a host's whole plan when one line reads like a credential
assignment (branchLeft/github-workflows, .github/actions/ssh-check-hosts/action.yml, the
credential-assignment row of `patterns`, line 434 at tag v1.0.19, applied with grep -Ei). The role's
module carries a copy of that pattern as SCAN_PATTERN and this test holds the role's text to it.
Drift of the copy from the original is NOT checked here: branchLeft/shared-infra#574 is the change
that adds a test holding the original and the copies equal, and when it lands this copy is replaced
by an import of its constant. Until then a change of the original is not seen by this file.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

import jinja2
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
ROLE = "ansible/roles/ci_jump"
MODULE = f"{ROLE}/library/ci_jump_authorized_keys.py"
HOMES = (
    "ansible/roles/ci_login/vars/main.yml",
    "ansible/roles/tunnel_account/vars/main.yml",
    "ansible/owner_vars/edge1.yml",
)
SCAN_CITATION = ("ssh-check-hosts/action.yml", "v1.0.19", "line 434")
ROLE_PREFIX = "ci_jump_"
KEY_TYPE = "ssh-ed25519"
# A well-formed ed25519 key made for the test: the blob is the type and 32 bytes.
SAMPLE_BODY = "AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"


def _variables(path: Path) -> dict[str, object]:
    document: object = yaml.safe_load(path.read_text(encoding="utf-8"))
    return (
        {str(key): value for key, value in document.items()} if isinstance(document, dict) else {}
    )


def _load_module(root: Path) -> types.ModuleType:
    """Import the role's module from the tree under root, as a new module each time.

    Raises:
        ImportError: when the file cannot be loaded as a module.
    """
    name = f"ci_jump_pins_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(name, root / MODULE)
    if spec is None or spec.loader is None:
        message = f"cannot load {MODULE}"
        raise ImportError(message)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _strings(node: object, keys: tuple[str, ...]) -> list[str]:
    """Every text under one of the named keys, anywhere in a loaded YAML document."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in keys and isinstance(value, str):
                found.append(value)
            found.extend(_strings(value, keys))
    elif isinstance(node, list):
        for item in node:
            found.extend(_strings(item, keys))
    return found


def _tasks(role: Path, name: str) -> list[dict[str, object]]:
    document: object = yaml.safe_load((role / "tasks" / name).read_text(encoding="utf-8"))
    return [
        task for task in (document if isinstance(document, list) else []) if isinstance(task, dict)
    ]


def _template_lines(root: Path, destinations: list[str]) -> list[str]:
    """Render the key template the way Ansible does and return its lines."""
    role = root / ROLE
    mine = _variables(role / "vars" / "main.yml")
    environment = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)  # noqa: S701
    template = environment.from_string(
        (role / "templates" / "authorized_keys.j2").read_text(encoding="utf-8")
    )
    text = template.render(
        ci_jump_keys=[{"key": f"{KEY_TYPE} {SAMPLE_BODY} a comment"}],
        ci_jump_destinations=destinations,
        ci_jump_fixed_options=mine["ci_jump_fixed_options"],
        ci_jump_port=mine["ci_jump_port"],
    )
    return [line for line in text.splitlines() if line.strip()]


class _Host:
    """A host that holds one jump account whose values are hostile, for the output pin."""

    def __init__(self, module: types.ModuleType) -> None:
        self.module = module

    def accounts(self) -> list[object]:
        """An account named like a credential, and its shell."""
        return [
            self.module.Account("token", 1001, "/home/token", "/usr/sbin/nologin=EXAMPLE_VALUE")
        ]

    def read(self, path: str) -> str | None:
        """Key lines whose option values read like credentials."""
        if not path.endswith("/authorized_keys"):
            return None
        return (
            'restrict,permitopen="secret:2222",permitopen="token=abcdefgh:22",'
            'command="password=EXAMPLE_VALUE",from="api_key:EXAMPLE_VALUE" '
            f"{KEY_TYPE} {SAMPLE_BODY} secret=EXAMPLE_COMMENT\n"
            f'permitlisten="credential:12345" {KEY_TYPE} {SAMPLE_BODY}\n'
        )

    def sshd_test(self, user: str | None) -> dict[str, list[str]]:
        """Settings whose values read like credentials."""
        del user
        return {
            "authorizedkeyscommand": ["/usr/local/bin/x --secret=EXAMPLE_VALUE"],
            "authorizedkeysfile": [".ssh/authorized_keys token:abcdefgh"],
        }


def problems(root: Path) -> list[str]:
    """Return one finding per broken pin in the tree under ``root``."""
    found: list[str] = []
    role = root / ROLE
    module = _load_module(root)
    mine = _variables(role / "vars" / "main.yml")
    login = _variables(root / HOMES[0])
    tunnel = _variables(root / HOMES[1])
    owner = _variables(root / HOMES[2])

    # The module pins the port and the fixed options for itself, as the oracle of its read-back.
    if mine.get("ci_jump_port") != module.PINNED_PORT:
        found.append("ci_jump_port differs from the module's PINNED_PORT")
    if str(mine.get("ci_jump_fixed_options", "")).split(",") != list(module.PINNED_FIXED_OPTIONS):
        found.append("ci_jump_fixed_options differs from the module's PINNED_FIXED_OPTIONS")

    # One account has one owning role: the accounts other roles own are copies of their homes.
    expected_owned = {
        "root": "root",
        "ci_login": login.get("ci_login_user"),
        "tunnel_account": tunnel.get("tunnel_account_user"),
    }
    if mine.get("ci_jump_owned_accounts") != expected_owned:
        found.append("ci_jump_owned_accounts differs from ci_login_user and tunnel_account_user")

    # The template that writes the lines and the module that judges them agree.
    destinations = ["db-t1", "10.0.0.5"]
    wanted = module.wanted_lines(destinations, [(KEY_TYPE, SAMPLE_BODY)])
    try:
        written = _template_lines(root, destinations)
    except jinja2.TemplateError:
        written = []
    if [line.strip() for line in written] != wanted:
        found.append("templates/authorized_keys.j2 writes other lines than the module expects")

    # The interface: spec, defaults and the owner's file name the same four variables.
    spec = yaml.safe_load((role / "meta" / "argument_specs.yml").read_text(encoding="utf-8"))
    options = set(spec["argument_specs"]["main"]["options"])
    defaults = _variables(role / "defaults" / "main.yml")
    in_owner_file = {name for name in owner if name.startswith(ROLE_PREFIX)}
    if not (options == set(defaults) == in_owner_file):
        found.append(
            "the argument spec, the defaults and owner_vars/edge1.yml name different variables"
        )
    if any(owner.get(name) != value for name, value in defaults.items()):
        found.append(
            "owner_vars/edge1.yml does not ship the role's defaults (the role must ship inert)"
        )
    if defaults.get("ci_jump_manage_keys") is not False:
        found.append("ci_jump_manage_keys must default to false")

    found.extend(_scan_findings(role, module))
    found.extend(_task_findings(role))
    return found


def _scan_findings(role: Path, module: types.ModuleType) -> list[str]:
    """The role's own text and the module's output stay out of the plan scan."""
    found: list[str] = []
    pattern: re.Pattern[str] = module.SCAN_PATTERN
    source = (role / "library" / "ci_jump_authorized_keys.py").read_text(encoding="utf-8")
    if not all(part in source for part in SCAN_CITATION):
        found.append("the module's SCAN_PATTERN no longer cites its source file, tag and line")
    if not pattern.search("password=abcdefgh"):
        found.append("SCAN_PATTERN does not match a plain credential assignment (the copy is dead)")

    # Variable names, task names and messages are all printed, and a name is shown with a value.
    names: list[str] = []
    for filename in ("defaults/main.yml", "vars/main.yml"):
        names.extend(_variables(role / filename))
    spec = yaml.safe_load((role / "meta" / "argument_specs.yml").read_text(encoding="utf-8"))
    names.extend(spec["argument_specs"]["main"]["options"])
    found.extend(
        f"the variable name {name} reads like a credential in a plan line"
        for name in names
        if pattern.search(f"{name}: EXAMPLE_VALUE") or pattern.search(f"{name}=EXAMPLE_VALUE")
    )
    for path in sorted((role / "tasks").glob("*.yml")):
        document: object = yaml.safe_load(path.read_text(encoding="utf-8"))
        found.extend(
            f"tasks/{path.name}: a printed text reads like a credential assignment: {text[:40]}"
            for text in _strings(document, ("name", "fail_msg", "msg"))
            if pattern.search(text)
        )

    # The module's report and plan over hostile values: no line is withheld, none matches.
    host = _Host(module)
    lines, _ = module.do_report(host, {"root": "root", "ci_login": "token"})
    try:
        lines += module.do_plan(host, "token", ["db-t1"], [f"{KEY_TYPE} {SAMPLE_BODY}"], {})
    except module.RefusalError as error:
        lines.append(str(error))
    if any(pattern.search(line) for line in lines):
        found.append("the module printed a line that reads like a credential assignment")
    if module.WITHHELD_LINE in lines:
        found.append("the module printed from values that only its last guard kept out of the scan")
    return found


def _task_findings(role: Path) -> list[str]:
    """The order, the guards and the hiding of the role's tasks."""
    found: list[str] = []
    main_tasks = _tasks(role, "main.yml")
    imports = [
        (str(task.get("ansible.builtin.import_tasks")), str(task.get("when", "")))
        for task in main_tasks
    ]
    names = [name for name, _ in imports]
    if names != ["_report.yml", "_guards.yml", "_keys.yml", "_readback.yml"]:
        found.append(
            "tasks/main.yml must import _report, _guards, _keys and _readback, in that order"
        )
    else:
        for name, condition in imports[1:]:
            if "ci_jump_manage_keys" not in condition:
                found.append(f"tasks/main.yml: {name} is not behind ci_jump_manage_keys")
        if "ci_jump_manage_keys" in imports[0][1]:
            found.append("tasks/main.yml: the report must run whatever the flag is")
        if "ansible_check_mode" not in imports[3][1]:
            found.append("tasks/main.yml: the read-back must be skipped in check mode")

    def hidden(task: dict[str, object]) -> bool:
        return task.get("no_log") is True and task.get("diff") is False

    writes = [t for t in _tasks(role, "_keys.yml") if "ansible.posix.authorized_key" in t]
    if len(writes) != 1:
        found.append("tasks/_keys.yml: expected one authorized_key task")
    else:
        arguments = writes[0]["ansible.posix.authorized_key"]
        if not hidden(writes[0]):
            found.append("tasks/_keys.yml: the key write must set no_log: true and diff: false")
        if not (isinstance(arguments, dict) and arguments.get("exclusive") is True):
            found.append("tasks/_keys.yml: the key write must be exclusive")
    for filename in ("_guards.yml", "_readback.yml"):
        calls = [t for t in _tasks(role, filename) if "ci_jump_authorized_keys" in t]
        if len(calls) != 1 or not hidden(calls[0]):
            found.append(f"tasks/{filename}: the module call must set no_log: true and diff: false")
    reports = [t for t in _tasks(role, "_report.yml") if "ci_jump_authorized_keys" in t]
    if len(reports) != 1 or reports[0].get("changed_when") is not False:
        found.append("tasks/_report.yml: the report must set changed_when: false")
    return found


class RealTree(unittest.TestCase):
    def test_the_pins_hold_on_the_real_tree(self) -> None:
        self.assertEqual(problems(ROOT), [])

    def test_the_hostile_fixture_does_trigger_the_scan_when_it_is_printed_raw(self) -> None:
        """The control for the output pin: the same values, printed raw, would be withheld."""
        module = _load_module(ROOT)
        raw = 'token=abcdefgh command="password=EXAMPLE_VALUE" permitopen="secret:2222"'
        self.assertTrue(module.SCAN_PATTERN.search(raw))
        self.assertEqual(module.safe_line(raw), module.WITHHELD_LINE)


class Sabotage(unittest.TestCase):
    """Break one file of a copy of the tree, require the named finding, put the file back and
    require none, so a pin that is always red cannot pass for one that is switched on."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        shutil.copytree(ROOT / ROLE, self.root / ROLE, ignore=shutil.ignore_patterns("molecule"))
        for home in HOMES:
            (self.root / home).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / home, self.root / home)

    def _red_then_green(self, relative: str, old: str, new: str, expected: str) -> None:
        path = self.root / relative
        original = path.read_text(encoding="utf-8")
        self.assertIn(old, original, f"the sabotage matched nothing in {relative}")
        path.write_text(original.replace(old, new, 1), encoding="utf-8")
        red = problems(self.root)
        self.assertTrue(any(expected in finding for finding in red), f"{expected!r} not in {red}")
        path.write_text(original, encoding="utf-8")
        self.assertEqual(problems(self.root), [])

    def test_a_drifted_port_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "ci_jump_port: 22",
            "ci_jump_port: 2222",
            "ci_jump_port differs",
        )

    def test_a_moved_port_in_the_module_is_red(self) -> None:
        self._red_then_green(
            MODULE, "PINNED_PORT = 22", "PINNED_PORT = 2222", "ci_jump_port differs"
        )

    def test_a_wider_fixed_option_set_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "ci_jump_fixed_options: restrict,port-forwarding",
            "ci_jump_fixed_options: restrict,port-forwarding,agent-forwarding",
            "ci_jump_fixed_options differs",
        )

    def test_a_drifted_ci_login_account_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "  ci_login: ansible-ci\n",
            "  ci_login: ansible-ci2\n",
            "ci_jump_owned_accounts differs",
        )

    def test_a_renamed_tunnel_account_in_its_home_is_red(self) -> None:
        self._red_then_green(
            HOMES[1],
            "tunnel_account_user: dbtunnel",
            "tunnel_account_user: dbtunnel2",
            "ci_jump_owned_accounts differs",
        )

    def test_a_dropped_owned_account_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "  tunnel_account: dbtunnel\n",
            "",
            "ci_jump_owned_accounts differs",
        )

    def test_an_extra_option_in_the_template_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/templates/authorized_keys.j2",
            "{{ ci_jump_fixed_options }}",
            "{{ ci_jump_fixed_options }},no-pty",
            "templates/authorized_keys.j2 writes other lines",
        )

    def test_a_template_that_drops_the_port_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/templates/authorized_keys.j2",
            ':{{ ci_jump_port }}"',
            '"',
            "templates/authorized_keys.j2 writes other lines",
        )

    def test_a_template_that_keeps_the_comment_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/templates/authorized_keys.j2",
            "{{ entry.key.split(' ')[0] }} {{ entry.key.split(' ')[1] }}",
            "{{ entry.key }}",
            "templates/authorized_keys.j2 writes other lines",
        )

    def test_a_default_that_switches_the_role_on_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/defaults/main.yml",
            "ci_jump_manage_keys: false",
            "ci_jump_manage_keys: true",
            "ci_jump_manage_keys must default to false",
        )

    def test_an_owner_file_that_ships_the_role_on_is_red(self) -> None:
        self._red_then_green(
            HOMES[2],
            "ci_jump_manage_keys: false",
            "ci_jump_manage_keys: true",
            "does not ship the role's defaults",
        )

    def test_an_option_missing_from_the_spec_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/meta/argument_specs.yml",
            "      ci_jump_user:\n",
            "      ci_jump_user_renamed:\n",
            "name different variables",
        )

    def test_a_variable_name_that_reads_like_a_credential_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/defaults/main.yml",
            "ci_jump_user: ''",
            "ci_jump_user: ''\nci_jump_token_file: ''",
            "reads like a credential in a plan line",
        )

    def test_a_task_name_that_reads_like_a_credential_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_report.yml",
            "- name: Show what the host holds today",
            "- name: Show what the host holds, password=EXAMPLE_VALUE",
            "a printed text reads like a credential assignment",
        )

    def test_a_failure_message_that_reads_like_a_credential_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_guards.yml",
            "- name: Stop if the module refused",
            "- name: Stop if the module refused, secret=EXAMPLE_VALUE",
            "a printed text reads like a credential assignment",
        )

    def test_a_print_that_lets_a_colon_through_is_red(self) -> None:
        self._red_then_green(
            MODULE,
            'UNSAFE_PRINT = re.compile(r"[^A-Za-z0-9_./%@+-]")',
            'UNSAFE_PRINT = re.compile(r"[^A-Za-z0-9_./%@+:=-]")',
            "the module printed",
        )

    def test_a_scan_copy_that_lost_its_citation_is_red(self) -> None:
        self._red_then_green(MODULE, "(line 434 at tag v1.0.19)", "(somewhere)", "no longer cites")

    def test_a_dead_scan_copy_is_red(self) -> None:
        self._red_then_green(MODULE, "passw(or)?d|", "passwordx|", "the copy is dead")

    def test_no_log_off_the_key_write_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_keys.yml", "  no_log: true\n", "", "the key write must set no_log"
        )

    def test_diff_shown_on_the_key_write_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_keys.yml", "  diff: false\n", "", "the key write must set no_log"
        )

    def test_a_non_exclusive_key_write_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_keys.yml",
            "    exclusive: true\n",
            "    exclusive: false\n",
            "the key write must be exclusive",
        )

    def test_a_module_call_that_shows_its_result_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_guards.yml", "  no_log: true\n", "", "the module call must set no_log"
        )

    def test_a_guard_that_is_not_behind_the_flag_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/main.yml",
            "  ansible.builtin.import_tasks: _keys.yml\n  when: ci_jump_manage_keys | bool\n",
            "  ansible.builtin.import_tasks: _keys.yml\n",
            "_keys.yml is not behind ci_jump_manage_keys",
        )

    def test_a_write_before_the_guards_is_red(self) -> None:
        path = self.root / ROLE / "tasks" / "main.yml"
        original = path.read_text(encoding="utf-8")
        guards = "ansible.builtin.import_tasks: _guards.yml"
        keys = "ansible.builtin.import_tasks: _keys.yml"
        swapped = original.replace(guards, "@@").replace(keys, guards).replace("@@", keys)
        path.write_text(swapped, encoding="utf-8")
        red = problems(self.root)
        self.assertTrue(any("in that order" in finding for finding in red), red)
        path.write_text(original, encoding="utf-8")
        self.assertEqual(problems(self.root), [])

    def test_a_report_behind_the_flag_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/main.yml",
            "  ansible.builtin.import_tasks: _report.yml\n",
            "  ansible.builtin.import_tasks: _report.yml\n  when: ci_jump_manage_keys | bool\n",
            "the report must run whatever the flag is",
        )

    def test_a_read_back_in_check_mode_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/main.yml",
            "  when: ci_jump_manage_keys | bool and not ansible_check_mode\n",
            "  when: ci_jump_manage_keys | bool\n",
            "the read-back must be skipped in check mode",
        )


if __name__ == "__main__":
    unittest.main()
