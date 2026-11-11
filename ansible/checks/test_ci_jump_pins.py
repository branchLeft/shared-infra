"""Pins on the ci_jump role: its copies stay equal to their homes, the key file and the sshd
drop-in are made from one destination list, its output stays out of the plan scan and free of the
jump account's name, and the order and hiding of its tasks stay as they are.

The role writes the key options and the sshd Match block of the account the gated run jumps
through, so a drift here is a silent widening, a key that can open a port on the jump host, or a
plan that is withheld. Each pin is shown red on a sabotaged copy of the files it reads, and green
again once the file is put back.

The plan scan. The gated apply withholds a host's whole plan when one line reads like a credential
assignment (branchLeft/github-workflows, .github/actions/ssh-check-hosts/action.yml, the
credential-assignment row of `patterns`, line 434 at tag v1.0.19, applied with grep -Ei). The role's
module carries a copy of that pattern as SCAN_PATTERN and this test holds the role's text to it.
Drift of the copy from the original is NOT checked here: no test holds the original and the copies
equal yet, and when one exists this copy is replaced by an import of its constant. Until then a
change of the original is not seen by this file.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

import jinja2
import jinja2.meta
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
ROLE = "ansible/roles/ci_jump"
MODULE = f"{ROLE}/library/ci_jump_authorized_keys.py"
HOMES = (
    "ansible/roles/ci_login/vars/main.yml",
    "ansible/roles/tunnel_account/vars/main.yml",
    "ansible/checks/host_roles.yml",
    "ansible/roles/host_inputs/vars/main.yml",
)
OWNER_VARS = "ansible/owner_vars"
SCAN_CITATION = ("ssh-check-hosts/action.yml", "v1.0.19", "line 434")
ROLE_PREFIX = "ci_jump_"
# The variables whose default is empty: the role ships with no address, destination or key.
INERT_EMPTY = ("ci_jump_own_address", "ci_jump_destinations", "ci_jump_keys")
# The jump account's name is the owner's secret. It is the one role variable that is not in an
# owner_vars file: it reaches the role through the host's private inputs file, set by host_inputs.
SECRET_VARIABLE = "ci_jump_user"  # noqa: S105
# A realistic name for the pins to render paths with: the lowercase-hyphen shape of a real one. It
# is made up here and is not the owner's.
SAMPLE_NAME = "gate-hopper"
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


def _environment() -> jinja2.Environment:
    """The Jinja settings Ansible renders a template with."""
    return jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)  # noqa: S701


def _source(root: Path, name: str) -> str:
    return (root / ROLE / "templates" / name).read_text(encoding="utf-8")


def _render(root: Path, name: str, destinations: list[str], user: str = SAMPLE_NAME) -> str:
    """Render one of the role's templates the way Ansible does, with its role variables."""
    mine = _variables(root / ROLE / "vars" / "main.yml")
    return (
        _environment()
        .from_string(_source(root, name))
        .render(
            ci_jump_keys=[{"key": f"{KEY_TYPE} {SAMPLE_BODY} a comment"}],
            ci_jump_user=user,
            ci_jump_destinations=destinations,
            **{key: value for key, value in mine.items() if isinstance(value, str | int)},
        )
    )


def _template_lines(root: Path, destinations: list[str]) -> list[str]:
    """The key template's lines."""
    text = _render(root, "authorized_keys.j2", destinations)
    return [line for line in text.splitlines() if line.strip()]


def _template_variables(root: Path, name: str) -> set[str]:
    """Every variable a template reads."""
    return jinja2.meta.find_undeclared_variables(_environment().parse(_source(root, name)))


class _Host:
    """A host that holds one jump account whose values are hostile, for the output pin."""

    def __init__(self, module: types.ModuleType) -> None:
        self.module = module

    def accounts(self) -> list[object]:
        """An account named like a credential, and its shell."""
        return [
            self.module.Account(
                "hostilename", 1001, "/home/hostilename", "/usr/sbin/nologin=EXAMPLE_VALUE"
            )
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

    def info(self, path: str) -> object:
        """A file that is not root's."""
        del path
        return self.module.FileInfo(1001, 1001, 0o666, True, False)

    def sshd_test(self, user: str | None, address: str) -> dict[str, list[str]]:
        """Settings whose values read like credentials."""
        del user, address
        return {
            "authorizedkeyscommand": ["/usr/local/bin/x --secret=EXAMPLE_VALUE"],
            "authorizedkeysfile": [".ssh/authorized_keys token:abcdefgh"],
            "permitopen": ["password=abcdefgh:22"],
        }


def _owner_files(root: Path) -> dict[str, dict[str, object]]:
    """Every owner_vars file, by host."""
    return {path.stem: _variables(path) for path in sorted((root / OWNER_VARS).glob("*.yml"))}


def problems(root: Path) -> list[str]:
    """Return one finding per broken pin in the tree under ``root``."""
    found: list[str] = []
    role = root / ROLE
    module = _load_module(root)
    mine = _variables(role / "vars" / "main.yml")
    login = _variables(root / HOMES[0])
    tunnel = _variables(root / HOMES[1])

    # The module pins the constants for itself, as the oracle of its read-back.
    if mine.get("ci_jump_port") != module.PINNED_PORT:
        found.append("ci_jump_port differs from the module's PINNED_PORT")
    if str(mine.get("ci_jump_fixed_options", "")).split(",") != list(module.PINNED_FIXED_OPTIONS):
        found.append("ci_jump_fixed_options differs from the module's PINNED_FIXED_OPTIONS")
    if mine.get("ci_jump_forced_command") != module.PINNED_COMMAND:
        found.append("ci_jump_forced_command differs from the module's PINNED_COMMAND")
    for variable, constant in (
        ("ci_jump_key_dir", "KEY_DIR"),
        ("ci_jump_key_file", "KEY_FILE"),
        ("ci_jump_sshd_dropin", "DROPIN_FILE"),
    ):
        if mine.get(variable) != getattr(module, constant):
            found.append(f"{variable} differs from the module's {constant}")
    if (
        mine.get("ci_jump_sshd_dropin")
        != f"{mine.get('ci_jump_sshd_config_dir')}/40-branchleft-jump.conf"
    ):
        found.append("ci_jump_sshd_dropin is not the 40- file of ci_jump_sshd_config_dir")
    found.extend(_path_findings(mine, module))

    # Remote forwarding: the module must require sshd to say local for the account, and the
    # drop-in must say it. A key line with port-forwarding opens a port on the jump host (ssh -R)
    # under any other value.
    if module.EXPECTED_EFFECTIVE.get("allowtcpforwarding") != "local":
        found.append("the module does not require AllowTcpForwarding local for the jump account")
    if module.EFFECTIVE_CODES.get("allowtcpforwarding") != "E-SSHD-FORWARDING":
        found.append("the module does not refuse a forwarding setting that is not local")

    # One account has one owning role: the accounts other roles own are copies of their homes.
    expected_owned = {
        "root": "root",
        "ci_login": login.get("ci_login_user"),
        "tunnel_account": tunnel.get("tunnel_account_user"),
    }
    if mine.get("ci_jump_owned_accounts") != expected_owned:
        found.append("ci_jump_owned_accounts differs from ci_login_user and tunnel_account_user")

    found.extend(_template_findings(root, module))
    found.extend(_interface_findings(root, role))
    found.extend(_scan_findings(role, module))
    found.extend(_task_findings(role))
    return found


def _render_text(text: str, user: str) -> str:
    """Render one role variable's text with the account's name, as Ansible would."""
    return _environment().from_string(text).render(ci_jump_user=user)


def _path_findings(mine: dict[str, object], module: types.ModuleType) -> list[str]:
    """No path the role writes or the module pins is made from the account's name, and the paths
    of the earlier hand-made layout, which are, are the only ones that are.

    The name is held out of this public repository and of every public log, and a path is printed
    by a lot of tooling (a stat, a diff, a plan line), so a path made from it is a leak whatever
    hides the task. Each managed path is rendered with a realistic name and must not hold it.
    """
    found: list[str] = []
    managed = (
        "ci_jump_key_dir",
        "ci_jump_key_file",
        "ci_jump_sshd_dropin",
        "ci_jump_sshd_config_dir",
        "ci_jump_reload_marker",
    )
    for variable in managed:
        text = mine.get(variable)
        if not isinstance(text, str) or SAMPLE_NAME in _render_text(text, SAMPLE_NAME):
            found.append(f"{variable} is made from the account's name")
        elif "{{" in text:
            found.append(f"{variable} is templated; a managed path is a literal")
    for constant in ("KEY_DIR", "KEY_FILE", "DROPIN_FILE"):
        if SAMPLE_NAME in getattr(module, constant) or "{" in getattr(module, constant):
            found.append(f"the module's {constant} is made from the account's name")
    legacy = (
        "ci_jump_legacy_dir",
        "ci_jump_legacy_key_file",
        "ci_jump_legacy_dropin",
    )
    for variable in legacy:
        text = mine.get(variable)
        if not isinstance(text, str) or SAMPLE_NAME not in _render_text(text, SAMPLE_NAME):
            found.append(f"{variable} is not made from the account's name (the earlier layout is)")
    if mine.get("ci_jump_legacy_files") != [
        "{{ ci_jump_legacy_dropin }}",
        "{{ ci_jump_legacy_key_file }}",
    ]:
        found.append("ci_jump_legacy_files is not the earlier drop-in and key file")
    return found


def _template_findings(root: Path, module: types.ModuleType) -> list[str]:
    """The templates that write the files and the module that judges them agree, and both are
    made from the one destination list."""
    found: list[str] = []
    destinations = ["db-t1", "10.0.0.5", "app-t1"]
    wanted = module.wanted_lines(destinations, [(KEY_TYPE, SAMPLE_BODY)])
    try:
        written = _template_lines(root, destinations)
        dropin = _render(root, "sshd-drop-in.conf.j2", destinations)
    except jinja2.TemplateError:
        written, dropin = [], ""
    if [line.strip() for line in written] != wanted:
        found.append("templates/authorized_keys.j2 writes other lines than the module expects")
    if dropin != module.wanted_dropin(SAMPLE_NAME, destinations):
        found.append("templates/sshd-drop-in.conf.j2 writes other text than the module expects")

    # One list: the destinations of the key lines and of the Match block come from the one
    # variable, so the two cannot be edited apart.
    try:
        key_vars = _template_variables(root, "authorized_keys.j2")
        dropin_vars = _template_variables(root, "sshd-drop-in.conf.j2")
    except jinja2.TemplateError:
        key_vars, dropin_vars = set(), set()
    for label, names in (("authorized_keys.j2", key_vars), ("sshd-drop-in.conf.j2", dropin_vars)):
        listed = {name for name in names if "destination" in name}
        if listed != {"ci_jump_destinations"}:
            found.append(
                f"templates/{label} must read its destinations from ci_jump_destinations only"
            )
    if dropin_vars - {
        "ci_jump_user",
        "ci_jump_destinations",
        "ci_jump_port",
        "ci_jump_key_file",
        "ci_jump_forced_command",
    }:
        found.append("templates/sshd-drop-in.conf.j2 reads a variable the pins do not know")
    if key_vars - {
        "ci_jump_keys",
        "ci_jump_destinations",
        "ci_jump_port",
        "ci_jump_fixed_options",
        "ci_jump_forced_command",
    }:
        found.append("templates/authorized_keys.j2 reads a variable the pins do not know")
    try:
        in_keys = re.findall(r'permitopen="([^"]+)"', written[0] if written else "")
        permit = next(
            (
                line.split()[1:]
                for line in dropin.splitlines()
                if line.strip().startswith("PermitOpen")
            ),
            [],
        )
    except IndexError:
        in_keys, permit = [], []
    if in_keys != permit or in_keys != [f"{item}:22" for item in destinations]:
        found.append("the key lines and the Match block do not carry the same destinations")
    return found


def _enabled_findings(host: str, values: dict[str, object]) -> list[str]:
    """The findings for a host whose file turns the role on: an address, destinations and keys.

    What an address, a destination or a key may look like is the role's rule alone, in its
    module; this holds only that none is missing or of the wrong shape, so a half-filled file
    cannot pass for an enabled host.
    """
    found: list[str] = []
    address = values.get("ci_jump_own_address")
    if not isinstance(address, str) or not address:
        found.append(f"owner_vars/{host}.yml enables ci_jump without ci_jump_own_address")
    destinations = values.get("ci_jump_destinations")
    if (
        not isinstance(destinations, list)
        or not destinations
        or not all(isinstance(item, str) and item for item in destinations)
    ):
        found.append(
            f"owner_vars/{host}.yml enables ci_jump without a list of ci_jump_destinations"
        )
    keys = values.get("ci_jump_keys")
    if (
        not isinstance(keys, list)
        or not keys
        or not all(isinstance(item, dict) and set(item) == {"key"} for item in keys)
    ):
        found.append(f"owner_vars/{host}.yml enables ci_jump without a list of ci_jump_keys")
    return found


def _interface_findings(root: Path, role: Path) -> list[str]:
    """The spec, the defaults and every owner's file name the same variables.

    The defaults ship inert. A host's file ships the defaults too, unless it turns the role on
    (the flag true), and then it must bring an address, destinations and keys.
    """
    found: list[str] = []
    spec = yaml.safe_load((role / "meta" / "argument_specs.yml").read_text(encoding="utf-8"))
    options = set(spec["argument_specs"]["main"]["options"])
    if spec["argument_specs"]["main"]["options"].get(SECRET_VARIABLE, {}).get("no_log") is not True:
        found.append(f"the argument spec must hide {SECRET_VARIABLE} with no_log: true")
    defaults = _variables(role / "defaults" / "main.yml")
    if options - {SECRET_VARIABLE} != set(defaults):
        found.append("the argument spec and the defaults name different variables")
    secret = spec["argument_specs"]["main"]["options"].get(SECRET_VARIABLE, {})
    if "default" in secret or SECRET_VARIABLE in defaults:
        found.append(f"{SECRET_VARIABLE} must have no default (a private input)")
    if secret.get("required") is True:
        # The file may leave the name out until the owner seeds it (host_inputs_optional_by_host),
        # so a required argument would stop the plan that delivers the seeding tool.
        # The role refuses by itself when the flag is on and the name is absent (_guards.yml).
        found.append(f"{SECRET_VARIABLE} must not be a required argument (it is optional input)")
    if defaults.get("ci_jump_manage_keys") is not False:
        found.append("ci_jump_manage_keys must default to false")
    # The role ships inert: no default carries an address, a destination or a key. This is the
    # pin on the role itself; a host that enables the role is judged by its own file below.
    found.extend(
        f"{name} must default to empty (the role must ship inert)"
        for name in INERT_EMPTY
        if defaults.get(name) not in ("", [])
    )
    carrying = {
        host: values
        for host, values in _owner_files(root).items()
        if any(name.startswith(ROLE_PREFIX) for name in values)
    }
    for host, values in carrying.items():
        in_file = {name for name in values if name.startswith(ROLE_PREFIX)}
        if SECRET_VARIABLE in in_file:
            found.append(
                f"owner_vars/{host}.yml carries {SECRET_VARIABLE}: the account's name stays out of"
                " the repository and comes from the host's private inputs file"
            )
        if in_file - {SECRET_VARIABLE} != options - {SECRET_VARIABLE}:
            found.append(f"owner_vars/{host}.yml names other ci_jump variables than the spec")
        if values.get("ci_jump_manage_keys") is True:
            # The owner has turned the role on for this host: the values it brings must be
            # complete, because the role refuses a missing address, destination or key.
            found.extend(_enabled_findings(host, values))
        elif any(
            values.get(name) != value for name, value in defaults.items() if name != SECRET_VARIABLE
        ):
            found.append(
                f"owner_vars/{host}.yml does not ship the role's defaults"
                " (a host that does not enable the role must ship it inert)"
            )
    # Every host that lists the role has its own owner's file with the variables, and the account's
    # name in the host's private inputs row, so the loader sets it before the role runs.
    host_roles = _variables(root / HOMES[2])
    loader_vars = _variables(root / HOMES[3])
    rows = loader_vars.get("host_inputs_required_by_host")
    optional = loader_vars.get("host_inputs_optional_by_host")
    for host, roles in host_roles.items():
        if isinstance(roles, list) and "ci_jump" in roles:
            if host not in carrying:
                found.append(
                    f"{host} lists ci_jump but owner_vars/{host}.yml carries no ci_jump variable"
                )
            row = rows.get(host) if isinstance(rows, dict) else None
            if not isinstance(row, list) or SECRET_VARIABLE not in row:
                found.append(
                    f"{host} lists ci_jump but its host_inputs row lacks {SECRET_VARIABLE}"
                )
            options_of_host = optional.get(host) if isinstance(optional, dict) else None
            if not isinstance(options_of_host, list) or SECRET_VARIABLE not in options_of_host:
                found.append(
                    f"{host} lists ci_jump but {SECRET_VARIABLE} is not optional in its"
                    " host_inputs row: the plan that delivers the seeding tool would stop"
                )
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

    # The module's report and plan over hostile values: no line is withheld, none matches, and
    # the account is named in none.
    host = _Host(module)
    lines, accounts = module.do_report(
        host, {"root": "root", "ci_login": "hostilename"}, ["password"], "10.0.0.2"
    )
    try:
        lines += module.do_plan(
            host, "hostilename", "10.0.0.2", ["10.0.0.2"], [f"{KEY_TYPE} {SAMPLE_BODY}"], {}
        )
    except module.RefusalError as error:
        lines.append(str(error))
    if any(pattern.search(line) for line in lines):
        found.append("the module printed a line that reads like a credential assignment")
    if module.WITHHELD_LINE in lines:
        found.append("the module printed from values that only its last guard kept out of the scan")
    if "hostilename" in " ".join(lines) + json.dumps(accounts):
        found.append("the module printed the name of the jump account")
    return found


def _walk(tasks: object) -> list[dict[str, object]]:
    """Every task of a task list, with the tasks of its blocks, rescues and always sections."""
    found: list[dict[str, object]] = []
    for task in tasks if isinstance(tasks, list) else []:
        if not isinstance(task, dict):
            continue
        found.append(task)
        for section in ("block", "rescue", "always"):
            found.extend(_walk(task.get(section)))
    return found


def _asks_only_whether_set(task: dict[str, object]) -> bool:
    """Is this a task that asks whether the account's name is set and handles nothing of it?

    The name may be absent from the host's file (it is the one optional input), so the role asks
    whether it is set and says so. Such a task is an assert or a debug whose only mention of the
    name is the exact test ``ci_jump_user is [not] defined`` and the key's name in a literal
    message. A message that is templated, or any other use of the name, is a handler of it and
    stays under the no_log rule.
    """
    module = next(
        (key for key in ("ansible.builtin.assert", "ansible.builtin.debug") if key in task), ""
    )
    if not module:
        return False
    rest = {
        key: value
        for key, value in task.items()
        if key not in ("name", "when", module) and key not in ("tags",)
    }
    arguments = task.get(module)
    if not isinstance(arguments, dict):
        return False
    messages = [arguments.get(key) for key in ("msg", "fail_msg")]
    if any(isinstance(m, str) and ("{{" in m or "{%" in m) for m in messages):
        return False
    tests = arguments.get("that", [])
    tests = tests if isinstance(tests, list) else [tests]
    if module == "ansible.builtin.assert" and tests != ["ci_jump_user is defined"]:
        return False
    if module == "ansible.builtin.debug" and task.get("when") != "ci_jump_user is not defined":
        return False
    others = {
        key: value
        for key, value in arguments.items()
        if key not in ("msg", "fail_msg", "that", "quiet")
    }
    return "ci_jump_user" not in json.dumps(others) and "ci_jump_user" not in json.dumps(rest)


def _task_findings(role: Path) -> list[str]:
    """The order, the guards and the hiding of the role's tasks."""
    found: list[str] = []
    main_tasks = _tasks(role, "main.yml")
    imports = [
        (str(task.get("ansible.builtin.import_tasks")), str(task.get("when", "")))
        for task in main_tasks
        if "ansible.builtin.import_tasks" in task
    ]
    names = [name for name, _ in imports]
    if names != ["_report.yml", "_guards.yml", "_write.yml"]:
        found.append("tasks/main.yml must import _report, _guards and _write, in that order")
    else:
        for name, condition in imports[1:]:
            if "ci_jump_manage_keys" not in condition:
                found.append(f"tasks/main.yml: {name} is not behind ci_jump_manage_keys")
        if "ci_jump_manage_keys" in imports[0][1]:
            found.append("tasks/main.yml: the report must run whatever the flag is")

    # The name is optional input (host_inputs_optional_by_host), so the role must refuse by itself
    # when the flag is on and the name is absent, before any task that handles it, and must not
    # refuse when the flag is off: the notice is a debug behind the name being undefined only.
    guard_tasks = _tasks(role, "_guards.yml")
    first = guard_tasks[0] if guard_tasks else {}
    if not (
        _args(first, "ansible.builtin.assert").get("that") == ["ci_jump_user is defined"]
        and "ci_jump[user-missing]" in str(_args(first, "ansible.builtin.assert").get("fail_msg"))
    ):
        found.append("tasks/_guards.yml: must open by refusing a flag that is on with no name set")
    notices = [
        task
        for task in main_tasks
        if "ansible.builtin.debug" in task and task.get("when") == "ci_jump_user is not defined"
    ]
    if len(notices) != 1 or "WARNING" not in str(notices[0]):
        found.append("tasks/main.yml: must warn, and only warn, when the account's name is unset")

    def hidden(task: dict[str, object]) -> bool:
        return task.get("no_log") is True and task.get("diff") is False

    # The account's name is in the module's arguments: any task that names the variable must
    # hide its result. The drop-in that holds it is written by a hidden task (checked below).
    # The paths of the earlier hand-made layout are made from the name, so a task that names one
    # handles the name as much as one that names the variable: it hides its result, and a task
    # that can show a diff hides that too.
    for path in sorted((role / "tasks").glob("*.yml")):
        carriers = [
            task
            for task in _walk(_tasks_all(path))
            if "block" not in task
            and not _asks_only_whether_set(task)
            and ("ci_jump_user" in json.dumps(task) or "ci_jump_legacy" in json.dumps(task))
        ]
        found.extend(
            f"tasks/{path.name}: a task that handles the account's name must set no_log: true"
            for task in carriers
            if task.get("no_log") is not True
        )
        found.extend(
            f"tasks/{path.name}: a task that writes or removes a file of the account's name"
            " must set diff: false"
            for task in carriers
            if any(
                key in task
                for key in (
                    "ansible.builtin.file",
                    "ansible.builtin.copy",
                    "ansible.builtin.template",
                )
            )
            and task.get("diff") is not False
        )

    write = _walk(_tasks_all(role / "tasks" / "_write.yml"))
    templates = [t for t in write if "ansible.builtin.template" in t]
    if sorted(str(_args(t, "ansible.builtin.template").get("src")) for t in templates) != [
        "authorized_keys.j2",
        "sshd-drop-in.conf.j2",
    ]:
        found.append(
            "tasks/_write.yml: expected the key file and the drop-in, each from its template"
        )
    for task in templates:
        arguments = _args(task, "ansible.builtin.template")
        if not hidden(task):
            found.append("tasks/_write.yml: a template write must set no_log: true and diff: false")
        if not (
            arguments.get("owner") == "root"
            and arguments.get("group") == "root"
            and arguments.get("mode") == "0644"
        ):
            found.append("tasks/_write.yml: the managed files must be root:root at 0644")
    if any("ansible.posix.authorized_key" in t for t in write):
        found.append(
            "tasks/_write.yml: the key file must be written as root, never with authorized_key"
        )
    commands = [
        str(_args(t, "ansible.builtin.command").get("argv"))
        for t in write
        if "ansible.builtin.command" in t
    ]
    if not any("sshd" in command and "-t" in command for command in commands):
        found.append("tasks/_write.yml: the whole sshd configuration must be checked with sshd -t")
    if not any("ansible.builtin.systemd_service" in t for t in write):
        found.append("tasks/_write.yml: sshd must be reloaded after the write")
    block = next((t for t in write if "block" in t), None)
    if block is None or "rescue" not in block:
        found.append(
            "tasks/_write.yml: the write must have a rescue that puts the previous files back"
        )
    elif not any("_readback.yml" in str(t) for t in _walk(block["block"])):
        found.append("tasks/_write.yml: the read-back must be inside the block that is rolled back")
    elif not all(
        "ansible_check_mode" in str(t.get("when", ""))
        for t in _walk(block["block"])
        if "_readback.yml" in str(t)
    ):
        found.append("tasks/_write.yml: the read-back must be skipped in check mode")

    for filename in ("_guards.yml", "_readback.yml"):
        calls = [t for t in _tasks(role, filename) if "ci_jump_authorized_keys" in t]
        if len(calls) != 1 or not hidden(calls[0]):
            found.append(f"tasks/{filename}: the module call must set no_log: true and diff: false")
    reports = [t for t in _tasks(role, "_report.yml") if "ci_jump_authorized_keys" in t]
    if len(reports) != 1 or reports[0].get("changed_when") is not False:
        found.append("tasks/_report.yml: the report must set changed_when: false")
    return found


def _args(task: dict[str, object], module: str) -> dict[str, object]:
    """The arguments of a task's module, or an empty mapping."""
    value = task.get(module)
    return value if isinstance(value, dict) else {}


def _tasks_all(path: Path) -> list[object]:
    """A task file as loaded."""
    document: object = yaml.safe_load(path.read_text(encoding="utf-8"))
    return document if isinstance(document, list) else []


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
        shutil.copytree(ROOT / OWNER_VARS, self.root / OWNER_VARS)

    def _red_then_green(
        self, relative: str, old: str, new: str, expected: str, every: bool = False
    ) -> None:
        path = self.root / relative
        original = path.read_text(encoding="utf-8")
        self.assertIn(old, original, f"the sabotage matched nothing in {relative}")
        path.write_text(original.replace(old, new, -1 if every else 1), encoding="utf-8")
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

    def _enabled(self) -> dict[str, object]:
        """The values of a host the owner has turned the role on for, complete."""
        return {
            "ci_jump_manage_keys": True,
            "ci_jump_own_address": "10.0.0.7",
            "ci_jump_destinations": ["10.0.0.7", "db-t1"],
            "ci_jump_keys": [{"key": f"{KEY_TYPE} {SAMPLE_BODY} a comment"}],
        }

    def _findings_with_owner_file(self, host: str, values: dict[str, object]) -> list[str]:
        """The findings with one host's owner file replaced, then the file put back and green."""
        path = self.root / OWNER_VARS / f"{host}.yml"
        original = path.read_text(encoding="utf-8")
        path.write_text(yaml.safe_dump(values), encoding="utf-8")
        red = problems(self.root)
        path.write_text(original, encoding="utf-8")
        self.assertEqual(problems(self.root), [])
        return red

    def test_a_host_the_owner_has_enabled_is_accepted(self) -> None:
        """The positive case: a complete enabled file passes every other pin of this file."""
        self.assertEqual(self._findings_with_owner_file("edget", self._enabled()), [])

    def test_an_enabled_host_that_carries_the_account_name_is_red(self) -> None:
        values = self._enabled() | {SECRET_VARIABLE: SAMPLE_NAME}
        red = self._findings_with_owner_file("edget", values)
        self.assertTrue(any("carries ci_jump_user" in finding for finding in red), red)

    def test_an_enabled_host_with_partial_values_is_red(self) -> None:
        for name, value, expected in (
            ("ci_jump_own_address", "", "without ci_jump_own_address"),
            ("ci_jump_destinations", [], "without a list of ci_jump_destinations"),
            ("ci_jump_destinations", "10.0.0.7", "without a list of ci_jump_destinations"),
            ("ci_jump_destinations", ["10.0.0.7", 22], "without a list of ci_jump_destinations"),
            ("ci_jump_keys", [], "without a list of ci_jump_keys"),
            ("ci_jump_keys", [{"key": "k", "to": ["x"]}], "without a list of ci_jump_keys"),
        ):
            with self.subTest(name=name, value=value):
                red = self._findings_with_owner_file("edget", self._enabled() | {name: value})
                self.assertTrue(any(expected in finding for finding in red), red)

    def test_an_enabled_host_that_leaves_a_variable_out_is_red(self) -> None:
        values = {k: v for k, v in self._enabled().items() if k != "ci_jump_keys"}
        red = self._findings_with_owner_file("edget", values)
        self.assertTrue(any("names other ci_jump variables than the spec" in f for f in red), red)

    def test_a_host_that_is_not_enabled_but_holds_values_is_red(self) -> None:
        """Destinations or keys under a flag that is off are not inert: only the flag set to true
        (the bool) turns a host's file into an enabled one."""
        for flag in (False, "true", 1):
            with self.subTest(flag=flag):
                red = self._findings_with_owner_file(
                    "edget", self._enabled() | {"ci_jump_manage_keys": flag}
                )
                self.assertTrue(any("does not ship the role's defaults" in f for f in red), red)

    def test_a_default_that_carries_a_destination_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/defaults/main.yml",
            "ci_jump_destinations: []",
            "ci_jump_destinations: ['10.0.0.7']",
            "ci_jump_destinations must default to empty",
        )

    def test_a_default_that_carries_an_address_or_a_key_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/defaults/main.yml",
            "ci_jump_own_address: ''",
            "ci_jump_own_address: '10.0.0.7'",
            "ci_jump_own_address must default to empty",
        )
        self._red_then_green(
            f"{ROLE}/defaults/main.yml",
            "ci_jump_keys: []",
            "ci_jump_keys: [{key: a}]",
            "ci_jump_keys must default to empty",
        )

    def test_an_owner_file_that_publishes_the_account_name_is_red(self) -> None:
        self._red_then_green(
            f"{OWNER_VARS}/edge1.yml",
            "ci_jump_manage_keys: true",
            "ci_jump_manage_keys: true\nci_jump_user: gate-hopper",
            "carries ci_jump_user",
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
            "ci_jump_manage_keys: false",
            "ci_jump_manage_keys: false\nci_jump_token_file: ''",
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
            f"{ROLE}/tasks/_write.yml",
            "      register: ci_jump_keys_written\n      no_log: true\n",
            "      register: ci_jump_keys_written\n",
            "a template write must set no_log",
        )

    def test_diff_shown_on_the_drop_in_write_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_write.yml",
            "      register: ci_jump_dropin_written\n      no_log: true\n      diff: false\n",
            "      register: ci_jump_dropin_written\n      no_log: true\n",
            "a template write must set no_log",
        )

    def test_a_key_file_owned_by_the_account_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_write.yml",
            "        owner: root\n        group: root\n        mode: '0644'\n"
            "      register: ci_jump_keys_written",
            "        owner: '{{ ci_jump_user }}'\n        group: root\n        mode: '0644'\n"
            "      register: ci_jump_keys_written",
            "the managed files must be root:root at 0644",
        )

    def test_a_key_file_that_is_group_writable_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_write.yml",
            "        mode: '0644'\n      register: ci_jump_dropin_written",
            "        mode: '0664'\n      register: ci_jump_dropin_written",
            "the managed files must be root:root at 0644",
        )

    def test_no_whole_configuration_check_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_write.yml",
            "argv: [sshd, -t]",
            "argv: [true]",
            "must be checked with sshd -t",
            every=True,
        )

    def test_no_rollback_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_write.yml",
            "\n  rescue:\n",
            "\n  rescue_removed:\n",
            "a rescue that puts the previous files back",
        )

    def test_a_drop_in_that_allows_remote_forwarding_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/templates/sshd-drop-in.conf.j2",
            "AllowTcpForwarding local",
            "AllowTcpForwarding yes",
            "sshd-drop-in.conf.j2 writes other text",
        )

    def test_a_second_destination_list_in_the_drop_in_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/templates/sshd-drop-in.conf.j2",
            "for destination in ci_jump_destinations",
            "for destination in ci_jump_other_destinations",
            "must read its destinations from ci_jump_destinations only",
        )

    def test_a_module_that_stops_requiring_local_forwarding_is_red(self) -> None:
        self._red_then_green(
            MODULE,
            '"allowtcpforwarding": "local",',
            '"allowtcpforwarding": "yes",',
            "does not require AllowTcpForwarding local",
        )

    def test_a_module_that_stops_refusing_other_forwarding_is_red(self) -> None:
        self._red_then_green(
            MODULE,
            '"allowtcpforwarding": "E-SSHD-FORWARDING",',
            "",
            "does not refuse a forwarding setting that is not local",
        )

    def test_a_moved_key_file_in_the_module_is_red(self) -> None:
        self._red_then_green(
            MODULE,
            'KEY_FILE = "/etc/ssh/authorized_keys.d/branchleft-jump"',
            'KEY_FILE = "/etc/ssh/authorized_keys.d/keys"',
            "ci_jump_key_file differs",
        )

    def test_a_report_that_prints_the_account_name_is_red(self) -> None:
        self._red_then_green(
            MODULE,
            'f"account {index} shell class {shell_class(account.shell)} owned by role"',
            'f"account {account.name} shell class {shell_class(account.shell)} owned by role"',
            "printed the name of the jump account",
        )

    def test_a_host_that_lists_the_role_without_its_variables_is_red(self) -> None:
        self._red_then_green(
            HOMES[2],
            "\nops1:\n",
            "\nedge-t:\n  - ci_jump\nops1:\n",
            "edge-t lists ci_jump but owner_vars/edge-t.yml carries no ci_jump variable",
        )

    def test_a_module_call_that_shows_its_result_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_guards.yml", "  no_log: true\n", "", "the module call must set no_log"
        )

    def test_a_guard_that_is_not_behind_the_flag_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/main.yml",
            "  ansible.builtin.import_tasks: _write.yml\n  when: ci_jump_manage_keys | bool\n",
            "  ansible.builtin.import_tasks: _write.yml\n",
            "_write.yml is not behind ci_jump_manage_keys",
        )

    def test_a_write_before_the_guards_is_red(self) -> None:
        path = self.root / ROLE / "tasks" / "main.yml"
        original = path.read_text(encoding="utf-8")
        guards = "ansible.builtin.import_tasks: _guards.yml"
        keys = "ansible.builtin.import_tasks: _write.yml"
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
            f"{ROLE}/tasks/_write.yml",
            "      ansible.builtin.import_tasks: _readback.yml\n"
            "      when: not ansible_check_mode\n",
            "      ansible.builtin.import_tasks: _readback.yml\n",
            "the read-back must be skipped in check mode",
        )

    # The account's name is the owner's secret (the owner ruled keep-secret on publishing it): no
    # path the role writes or pins may be made from it, whatever hides the task that prints it.
    def test_a_managed_path_made_from_the_account_name_is_red(self) -> None:
        for variable, old in (
            ("ci_jump_key_file", "/etc/ssh/authorized_keys.d/branchleft-jump"),
            ("ci_jump_key_dir", "/etc/ssh/authorized_keys.d\n"),
            ("ci_jump_sshd_dropin", "/etc/ssh/sshd_config.d/40-branchleft-jump.conf"),
            ("ci_jump_reload_marker", "/run/branchleft-jump-reload-owed"),
        ):
            with self.subTest(variable=variable):
                path = self.root / ROLE / "vars" / "main.yml"
                original = path.read_text(encoding="utf-8")
                lines = original.splitlines(keepends=True)
                index = next(i for i, line in enumerate(lines) if line.startswith(f"{variable}:"))
                self.assertIn(old.strip(), lines[index])
                lines[index] = f"{variable}: '{old.strip()}-{{{{ ci_jump_user }}}}'\n"
                path.write_text("".join(lines), encoding="utf-8")
                red = problems(self.root)
                self.assertTrue(
                    any(f"{variable} is made from the account's name" in f for f in red), red
                )
                path.write_text(original, encoding="utf-8")
                self.assertEqual(problems(self.root), [])

    def test_a_path_in_the_module_made_from_the_account_name_is_red(self) -> None:
        self._red_then_green(
            MODULE,
            'DROPIN_FILE = "/etc/ssh/sshd_config.d/40-branchleft-jump.conf"',
            'DROPIN_FILE = "/etc/ssh/sshd_config.d/40-gate-hopper.conf"',
            "DROPIN_FILE is made from the account's name",
        )

    def test_a_removal_of_the_earlier_layout_that_shows_its_path_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_write.yml",
            "      register: ci_jump_retired_dropin\n      no_log: true\n      diff: false\n",
            "      register: ci_jump_retired_dropin\n      diff: false\n",
            "must set no_log: true",
        )
        self._red_then_green(
            f"{ROLE}/tasks/_write.yml",
            "      register: ci_jump_retired_key\n      no_log: true\n      diff: false\n",
            "      register: ci_jump_retired_key\n      no_log: true\n",
            "must set diff: false",
        )

    def test_a_jump_host_whose_private_inputs_lack_the_account_is_red(self) -> None:
        self._red_then_green(
            HOMES[3],
            "    - ci_jump_user\n  ops1:",
            "  ops1:",
            "its host_inputs row lacks ci_jump_user",
        )

    def test_a_default_given_to_the_account_name_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/meta/argument_specs.yml",
            "      ci_jump_user:\n        type: str\n        no_log: true\n",
            "      ci_jump_user:\n        type: str\n        default: ''\n        no_log: true\n",
            "must have no default",
        )

    def test_the_account_name_made_a_required_argument_again_is_red(self) -> None:
        # The plan that has to deliver the seeding tool stops at the door of the role.
        self._red_then_green(
            f"{ROLE}/meta/argument_specs.yml",
            "      ci_jump_user:\n        type: str\n        no_log: true\n",
            "      ci_jump_user:\n        type: str\n"
            "        required: true\n        no_log: true\n",
            "must not be a required argument",
        )

    def test_a_jump_host_whose_name_is_required_by_the_loader_is_red(self) -> None:
        self._red_then_green(
            HOMES[3],
            "  edge1:\n    - ci_jump_user\n  edget:",
            "  edget:",
            "ci_jump_user is not optional in its host_inputs row",
        )

    def test_a_guard_that_no_longer_refuses_a_flag_on_with_no_name_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_guards.yml",
            "      - ci_jump_user is defined\n",
            "      - true\n",
            "must open by refusing a flag that is on with no name set",
        )

    def test_a_silent_inert_role_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/main.yml",
            "  when: ci_jump_user is not defined\n",
            "  when: false\n",
            "must warn, and only warn",
        )

    def test_a_notice_that_prints_the_account_name_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/main.yml",
            "      ci_jump_user; until then ci_jump_manage_keys must stay false.\n",
            "      ci_jump_user; until then ci_jump_manage_keys must stay false.\n"
            "      {{ ci_jump_user }}\n",
            "a task that handles the account's name must set no_log: true",
        )

    def test_the_account_name_in_the_argument_spec_left_visible_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/meta/argument_specs.yml",
            "        no_log: true\n        description: >-\n          The jump account,",
            "        description: >-\n          The jump account,",
            "must hide ci_jump_user",
        )


if __name__ == "__main__":
    unittest.main()
