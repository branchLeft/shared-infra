"""Render every Ansible template of every host offline and validate it, with typed dummies.

The roles a host applies are replayed on localhost: each `template` task is kept (its source,
loop, vars and validate) and written into a throwaway directory, with dummy values for the
inputs the owner supplies and a fixture for the facts. Nothing reaches a host. It prints a
class and a name for each result, never a rendered line and never a variable value.
Exit 0: no red. 1: a red. 2: a tool or usage error. Narrative and limits: offline/README.md.
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from check_pins import load_yaml
from test_plan_diff_scan import _module_args, named_roles, role_variables, tasks_of

ROOT = Path(__file__).resolve().parents[2]
DATA = Path("ansible") / "checks" / "offline"
UNWIRED = "unwired"
TEMPLATE_ARGS = frozenset(
    (
        "src",
        "validate",
        "trim_blocks",
        "lstrip_blocks",
        "newline_sequence",
        "output_encoding",
        "variable_start_string",
        "variable_end_string",
        "block_start_string",
        "block_end_string",
        "comment_start_string",
        "comment_end_string",
    )
)
LOOP_KEYS = frozenset(("loop", "with_items", "with_list", "with_dict", "with_sequence"))
# The only variables of the caller's environment that reach a child process.
ENV_ALLOWED = ("PATH", "LANG", "LC_ALL")
# Two independent layers keep a rendered line out of the logs: Ansible's own output goes nowhere,
# and every task it runs is no_log. sabotage_offline_render.py removes each in turn.
ANSIBLE_STDIO = subprocess.DEVNULL
NO_LOG = True
LEGACY_FACTS = ("all_ipv4_addresses", "mounts")
FACT_READ = re.compile(r"""ansible_facts(?:\.(\w+)|\[['"](\w+)['"]\])""")
LEGACY_READ = re.compile(r"\bansible_(" + "|".join(LEGACY_FACTS) + r")\b")
ASSIGNING = ("set_fact",)
PLAYBOOK_DIR = "{{ playbook_dir }}"

SUMMARY_TEMPLATE = r"""{%- set ns = namespace(rows=[]) -%}
{%- for name in _or_names -%}
{%- set r = lookup('ansible.builtin.vars', name, default=none) -%}
{%- if r is none -%}
{%- set ns.rows = ns.rows + [{'id': name, 'state': 'missing', 'items': []}] -%}
{%- else -%}
{%- set items = r['results'] if 'results' in r else [r] -%}
{%- set cur = namespace(out=[]) -%}
{%- for it in items -%}
{%- set msg = ((it['msg'] | default('')) | string) -%}
{%- set p_undefined = "'([A-Za-z_][A-Za-z0-9_]*)' is undefined" -%}
{%- set p_attr = "has no attribute '([A-Za-z0-9_]+)'" -%}
{%- set p_rc = "(?s)failed to validate.*?rc:\s*(-?[0-9]+)" -%}
{%- set undefined = (msg | regex_findall(p_undefined)) | first | default(none) -%}
{%- set attr = (msg | regex_findall(p_attr)) | first | default(none) -%}
{%- set rc = (msg | regex_findall(p_rc)) | first | default(none) -%}
{%- set cur.out = cur.out + [{
  'failed': (it['failed'] | default(false)) | bool,
  'skipped': (it['skipped'] | default(false)) | bool,
  'undefined': undefined,
  'attr': attr,
  'rc': rc,
  'validate': ('failed to validate' in msg),
  'syntax': ('yntax error' in msg or 'TemplateSyntaxError' in msg),
}] -%}
{%- endfor -%}
{%- set ns.rows = ns.rows + [{'id': name, 'state': 'ran', 'items': cur.out}] -%}
{%- endif -%}
{%- endfor -%}
{{ {'rows': ns.rows} | to_json }}
"""


class ToolError(Exception):
    """The tool, not the tree, is at fault: bad usage, a missing program, a broken fixture."""


Env = dict[str, object]


def mapping(value: object) -> Env:
    """Return ``value`` as a dict with string keys, or an empty dict."""
    return {str(k): v for k, v in value.items()} if isinstance(value, dict) else {}


def sequence(value: object) -> list[object]:
    """Return ``value`` if it is a list, else an empty list."""
    return list(value) if isinstance(value, list) else []


@functools.cache
def load_mapping(path: Path) -> Env:
    """Return the YAML mapping in ``path``.

    Raises:
        ToolError: The file cannot be read or is not a mapping.
    """
    document, problem = load_yaml(path)
    if problem is not None or not isinstance(document, dict):
        message = f"{path.name} is not a readable YAML mapping"
        raise ToolError(message)
    return mapping(document)


# ---------------------------------------------------------------- argument specs and dummies


@functools.cache
def role_specs(role: Path) -> dict[str, Env]:
    """Return the role's argument_specs entry points, by name."""
    path = role / "meta" / "argument_specs.yml"
    if not path.is_file():
        return {}
    specs = mapping(load_mapping(path).get("argument_specs"))
    return {name: mapping(entry) for name, entry in specs.items()}


def role_options(role: Path) -> dict[str, Env]:
    """Return every option of every entry point of the role, by name."""
    found: dict[str, Env] = {}
    for entry in role_specs(role).values():
        for name, option in mapping(entry.get("options")).items():
            found.setdefault(name, mapping(option))
    return found


def dummy_value(name: str, spec: Mapping[str, object]) -> object:
    """Return the dummy for an option: its first choice, else a value of its declared type."""
    choices = sequence(spec.get("choices"))
    if choices:
        return choices[0]
    kind = str(spec.get("type", "str"))
    simple: dict[str, object] = {"int": 1, "float": 1.0, "bool": False, "list": []}
    if kind in simple:
        return simple[kind]
    if kind == "dict":
        return {
            sub: dummy_value(sub, mapping(rule))
            for sub, rule in mapping(spec.get("options")).items()
            if mapping(rule).get("required") is True and "default" not in mapping(rule)
        }
    return f"/dummy/{name}" if kind == "path" else f"DUMMY_{name}"


def type_matches(kind: str, value: object) -> bool:
    """Return whether ``value`` is of the argument_specs type ``kind``."""
    if kind == "bool":
        return isinstance(value, bool)
    if kind in ("int", "float"):
        return isinstance(value, int | float) and not isinstance(value, bool)
    if kind in ("list", "dict"):
        return isinstance(value, list if kind == "list" else dict)
    if kind == "raw":
        return True
    return isinstance(value, str)


def required_without_default(options: Mapping[str, Env]) -> dict[str, Env]:
    """Return the options the caller must supply and the role gives no default."""
    return {
        name: spec
        for name, spec in options.items()
        if spec.get("required") is True and "default" not in spec
    }


# ---------------------------------------------------------------- hosts and environments


@dataclass(frozen=True)
class RoleUse:
    """A role as a playbook applies it: its name and the parameters on the entry."""

    name: str
    params: Env


@dataclass(frozen=True)
class HostPlan:
    """What one host applies: roles in order, play vars and the vars files, already loaded."""

    name: str
    roles: tuple[RoleUse, ...]
    play_vars: Env
    file_vars: tuple[Env, ...]


def host_plans(root: Path) -> list[HostPlan]:
    """Return a plan for each playbook, and one for the roles no playbook applies.

    Raises:
        ToolError: A playbook is not one play, or a vars file it names cannot be read.
    """
    playbooks = root / "ansible" / "playbooks"
    plans: list[HostPlan] = []
    for path in sorted(playbooks.glob("*.yml")):
        document, problem = load_yaml(path)
        plays = sequence(document)
        if problem is not None or len(plays) != 1:
            message = f"{path.name} is not a playbook of one play"
            raise ToolError(message)
        play = mapping(plays[0])
        roles = []
        for entry in sequence(play.get("roles")):
            given = mapping(entry)
            text = str(given.get("role", entry) if given else entry)
            roles.append(RoleUse(Path(text).name, mapping(given.get("vars"))))
        files = tuple(
            load_mapping(Path(str(item).replace(PLAYBOOK_DIR, str(playbooks))).resolve())
            for item in sequence(play.get("vars_files"))
        )
        plans.append(HostPlan(path.stem, tuple(roles), mapping(play.get("vars")), files))
    applied = set(named_roles(playbooks))
    every = sorted(p.name for p in (root / "ansible" / "roles").iterdir() if p.is_dir())
    leftover = tuple(RoleUse(name, {}) for name in every if name not in applied)
    plans.append(HostPlan(UNWIRED, leftover, {}, ()))
    return plans


def host_input_keys(root: Path, host: str) -> list[str]:
    """Return the host_inputs keys the host's file must hold (their values are never read)."""
    path = root / "ansible" / "roles" / "host_inputs" / "vars" / "main.yml"
    table = mapping(load_mapping(path).get("host_inputs_required_by_host"))
    return [str(key) for key in sequence(table.get(host))]


def declared_overrides(root: Path) -> dict[str, Env]:
    """Return the dummies.yml overrides: name -> {type, value}."""
    path = root / DATA / "dummies.yml"
    return {
        name: mapping(entry) for name, entry in mapping(load_mapping(path).get("overrides")).items()
    }


def build_env(root: Path, plan: HostPlan, facts: Env) -> Env:
    """Return the variables of the host's run, lowest layer first.

    Dummies, role defaults and vars, play vars, vars files, the overrides, role parameters. The
    overrides sit where a host's own inputs sit: the loader sets them as facts, which outrank role
    defaults and vars and the vars files. Without that, a default of [] or the owner's empty list
    would replace the override, and an empty authorized_keys renders nothing that validates.
    """
    roles_dir = root / "ansible" / "roles"
    all_options: dict[str, Env] = {}
    for use in plan.roles:
        all_options.update(role_options(roles_dir / use.name))
    env: Env = {}
    for use in plan.roles:
        needed = required_without_default(role_options(roles_dir / use.name))
        env.update({name: dummy_value(name, spec) for name, spec in needed.items()})
    for key in host_input_keys(root, plan.name):
        env[key] = dummy_value(key, all_options.get(key, {}))
    for use in plan.roles:
        env.update(role_variables(roles_dir / use.name))
    env.update(plan.play_vars)
    for loaded in plan.file_vars:
        env.update(loaded)
    for name, entry in declared_overrides(root).items():
        env[name] = entry.get("value")
    for use in plan.roles:
        env.update(use.params)
    env["_or_facts"] = facts
    env.update({f"ansible_{key}": facts[key] for key in LEGACY_FACTS if key in facts})
    return _with_playbook_dir(env, str(root / "ansible" / "playbooks"))


def _with_playbook_dir(value: object, directory: str) -> Env:
    """Return ``value`` with the playbook_dir reference replaced by the real directory."""
    result = _replace(value, directory)
    return mapping(result)


def _replace(value: object, directory: str) -> object:
    if isinstance(value, str):
        return value.replace(PLAYBOOK_DIR, directory)
    if isinstance(value, list):
        return [_replace(item, directory) for item in value]
    if isinstance(value, dict):
        return {k: _replace(v, directory) for k, v in value.items()}
    return value


# ---------------------------------------------------------------- the template tasks


@dataclass(frozen=True)
class Replay:
    """One template task as it is replayed."""

    role: str
    file: str
    src: str
    index: int
    task: Env
    uses_loop: bool
    validate: str | None
    uncovered: str | None


def validator_binary(command: str) -> str:
    """Return the program a validate: command runs."""
    parts = shlex.split(command)
    return parts[0] if parts else ""


def binary_present(program: str) -> bool:
    """Return whether the program exists, by path when it is one."""
    return Path(program).exists() if "/" in program else shutil.which(program) is not None


def replay_tasks(root: Path, plan: HostPlan, outdir: Path) -> list[Replay]:
    """Return the template tasks of the plan's roles, ready to run into ``outdir``.

    Raises:
        ToolError: A template task has no literal ``src`` or is not written as arguments.
    """
    found: list[Replay] = []
    for use in plan.roles:
        role = root / "ansible" / "roles" / use.name
        for path, task, _off in tasks_of(role):
            module = _module_args(task, frozenset(("template",)))
            if module is None:
                continue
            arguments = mapping(module[1])
            src = arguments.get("src")
            if not isinstance(src, str):
                message = f"{use.name} {path.name}: a template task with no src"
                raise ToolError(message)
            index = len(found)
            found.append(
                _replay(
                    use.name, path.relative_to(role).as_posix(), src, index, task, arguments, outdir
                )
            )
    return found


def _replay(
    role: str, file: str, src: str, index: int, task: Env, arguments: Env, outdir: Path
) -> Replay:
    kept = {key: value for key, value in arguments.items() if key in TEMPLATE_ARGS}
    command = kept.get("validate")
    validate = command if isinstance(command, str) else None
    uncovered = None
    if validate is not None and not binary_present(validator_binary(validate)):
        uncovered = validator_binary(validate)
        del kept["validate"]
    looped = any(key in task for key in LOOP_KEYS)
    replay: Env = {"name": f"{role} {file} {src}", "register": f"_or_r{index}"}
    control = mapping(task.get("loop_control"))
    index_var = str(control.setdefault("index_var", "_or_n"))
    destination = f"{outdir}/{index}/" + (f"{{{{ {index_var} }}}}" if looped else "0")
    replay["ansible.builtin.template"] = {**kept, "dest": destination}
    replay.update({key: task[key] for key in ("vars", *LOOP_KEYS) if key in task})
    if looped:
        replay["loop_control"] = control
    replay.update({"no_log": NO_LOG, "ignore_errors": True, "diff": False})
    return Replay(role, file, src, index, replay, looped, validate, uncovered)


def assigned_names(root: Path, plan: HostPlan) -> set[str]:
    """Return the names a task of the plan's roles assigns while it runs.

    Registers, set_fact keys, task and block vars, loop and index variables.
    """
    names: set[str] = {"item", "ansible_loop", "ansible_index", "_or_n"}
    for use in plan.roles:
        for path in sorted((root / "ansible" / "roles" / use.name / "tasks").rglob("*.y*ml")):
            document, _problem = load_yaml(path)
            _collect(document, names)
    return names


def _collect(node: object, names: set[str]) -> None:
    if isinstance(node, list):
        for item in node:
            _collect(item, names)
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        short = str(key).rsplit(".", 1)[-1]
        if key == "register" and isinstance(value, str):
            names.add(value)
        elif key == "vars" and isinstance(value, dict):
            names.update(str(name) for name in value)
        elif key == "loop_control" and isinstance(value, dict):
            names.update(str(value[k]) for k in ("loop_var", "index_var") if k in value)
        elif short in ASSIGNING and isinstance(value, dict):
            names.update(str(name) for name in value if name != "cacheable")
        _collect(value, names)


def fact_keys_read(root: Path, plan: HostPlan) -> set[str]:
    """Return the fact names the plan's roles read, from their tasks, templates and variables."""
    found: set[str] = set()
    for use in plan.roles:
        role = root / "ansible" / "roles" / use.name
        for folder in ("tasks", "templates", "defaults", "vars"):
            for path in sorted((role / folder).rglob("*")):
                if not path.is_file():
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                found.update(m[1] or m[2] for m in FACT_READ.finditer(text))
                found.update(m[1] for m in LEGACY_READ.finditer(text))
    return found


# ---------------------------------------------------------------- running Ansible


def scrubbed_env(workdir: Path) -> dict[str, str]:
    """Return the environment of the Ansible child: an allowlist, a fresh HOME, no config file."""
    kept = {key: os.environ[key] for key in ENV_ALLOWED if key in os.environ}
    home = workdir / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    (workdir / "ansible.cfg").write_text("", encoding="utf-8")
    kept["PATH"] = os.pathsep.join([str(Path(sys.executable).parent), kept.get("PATH", "")])
    kept.update(
        {
            "HOME": str(home),
            "TMPDIR": str(workdir),
            "ANSIBLE_CONFIG": str(workdir / "ansible.cfg"),
            "ANSIBLE_HOME": str(home / ".ansible"),
            "ANSIBLE_LOCALHOST_WARNING": "false",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "false",
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_DEPRECATION_WARNINGS": "false",
            "ANSIBLE_RETRY_FILES_ENABLED": "false",
        }
    )
    return kept


def write_tree(
    root: Path, plan: HostPlan, replays: Sequence[Replay], env: Env, workdir: Path
) -> tuple[Path, dict[str, str]]:
    """Write the playbook, inventory and replay roles; return the playbook and the spec checks.

    The checks map a role to the register name of its argument-spec task.
    """
    roles_dir = root / "ansible" / "roles"
    play_roles: list[Env] = []
    names: list[str] = []
    checks: dict[str, str] = {}
    for use in plan.roles:
        replay_role = workdir / "roles" / f"replay_{use.name}"
        (replay_role / "tasks").mkdir(parents=True)
        for folder in ("templates", "files"):
            if (roles_dir / use.name / folder).is_dir():
                (replay_role / folder).symlink_to(roles_dir / use.name / folder)
        tasks: list[Env] = []
        spec = mapping(role_specs(roles_dir / use.name).get("main")).get("options")
        if spec is not None:
            check = f"_or_a{len(names)}"
            names.append(check)
            checks[use.name] = check
            tasks.append(
                {
                    "name": f"{use.name} argument spec",
                    "ansible.builtin.validate_argument_spec": {"argument_spec": mapping(spec)},
                    "register": check,
                    "no_log": NO_LOG,
                    "ignore_errors": True,
                }
            )
        for replay in replays:
            if replay.role == use.name:
                tasks.append(replay.task)
                names.append(f"_or_r{replay.index}")
        (replay_role / "tasks" / "main.yml").write_text(json.dumps(tasks), encoding="utf-8")
        play_roles.append({"role": str(replay_role)})
    (workdir / "env.json").write_text(json.dumps({**env, "_or_names": names}), encoding="utf-8")
    (workdir / "summary.j2").write_text(SUMMARY_TEMPLATE, encoding="utf-8")
    interpreter = json.dumps(sys.executable)
    (workdir / "inventory.yml").write_text(
        f"all:\n  hosts:\n    localhost:\n      ansible_connection: local\n"
        f"      ansible_python_interpreter: {interpreter}\n",
        encoding="utf-8",
    )
    play: Env = {
        "name": f"offline render of {plan.name}",
        "hosts": "localhost",
        "gather_facts": False,
        "vars_files": [str(workdir / "env.json")],
        "pre_tasks": [
            {"ansible.builtin.set_fact": {"ansible_facts": "{{ _or_facts }}"}, "no_log": NO_LOG}
        ],
        "roles": play_roles,
        "post_tasks": [
            {
                "ansible.builtin.template": {
                    "src": str(workdir / "summary.j2"),
                    "dest": str(workdir / "summary.json"),
                },
                "no_log": NO_LOG,
            }
        ],
    }
    playbook = workdir / "playbook.yml"
    playbook.write_text(json.dumps([play]), encoding="utf-8")
    return playbook, checks


def run_ansible(playbook: Path, workdir: Path) -> Env:
    """Run the playbook and return the summary it wrote.

    Raises:
        ToolError: ansible-playbook is missing or wrote no summary.
    """
    program = Path(sys.executable).parent / "ansible-playbook"
    if not program.is_file():
        message = "ansible-playbook is not beside the Python that runs this tool"
        raise ToolError(message)
    subprocess.run(  # noqa: S603
        [str(program), "-i", str(workdir / "inventory.yml"), str(playbook)],
        env=scrubbed_env(workdir),
        stdin=subprocess.DEVNULL,
        stdout=ANSIBLE_STDIO,
        stderr=ANSIBLE_STDIO,
        check=False,
        timeout=600,
    )
    summary = workdir / "summary.json"
    if not summary.is_file():
        message = "ansible-playbook wrote no summary"
        raise ToolError(message)
    return mapping(json.loads(summary.read_text(encoding="utf-8")))


# ---------------------------------------------------------------- results


@dataclass(frozen=True)
class Result:
    """The outcome for one template task of one host."""

    host: str
    role: str
    src: str
    status: str
    reason: str = ""


@dataclass(frozen=True)
class Data:
    """The files under offline/ that steer a run."""

    facts: dict[str, Env]
    validators: dict[str, Env]
    unresolved: frozenset[tuple[str, str]]


def classify(
    item: Mapping[str, object], assigned: set[str], facts: Env, read: set[str]
) -> tuple[str, str]:
    """Return (status, reason) for one rendered item from the summary's extracts."""
    if item.get("skipped") is True or item.get("failed") is not True:
        return "ok", ""
    if item.get("syntax") is True:
        return "red", "syntax"
    name, attr, rc = item.get("undefined"), item.get("attr"), item.get("rc")
    if isinstance(name, str):
        if name in assigned:
            return "unresolved", f"assigned at run time: {name}"
        return "red", f"variable defined nowhere: {name}"
    if isinstance(attr, str) and attr in read and attr not in facts:
        return "red", f"fact missing from the fixture: {attr}"
    if item.get("validate") is True:
        return "red", f"validate: exited {rc if rc is not None else 'non-zero'}"
    return "unresolved", "shape of a value (needs a dummies.yml override)"


def table_validation(path: Path, entry: Env, show: bool) -> tuple[str, str]:
    """Run a table validator on one rendered file; return (status, reason)."""
    program = str(entry.get("binary", ""))
    if not binary_present(program):
        return "not-covered", f"{program} is not installed"
    argv = [str(part).replace("{file}", str(path)) for part in sequence(entry.get("argv"))]
    kept = {key: os.environ[key] for key in (*ENV_ALLOWED, "HOME") if key in os.environ}
    done = subprocess.run(  # noqa: S603
        argv,
        env=kept,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=120,
        cwd=path.parent,
    )
    if done.returncode == 0:
        return "ok", ""
    if show:
        sys.stderr.write(
            done.stdout.decode(errors="replace") + done.stderr.decode(errors="replace")
        )
    return "red", f"{program} exited {done.returncode}"


def render_host(root: Path, plan: HostPlan, data: Data, show: bool) -> list[Result]:
    """Render one host and return one result per template task.

    Raises:
        ToolError: The host has no fact fixture.
    """
    facts = mapping(data.facts.get(plan.name))
    if not facts:
        message = f"no fact fixture for {plan.name}"
        raise ToolError(message)
    with tempfile.TemporaryDirectory(prefix="offline-render-") as scratch:
        workdir = Path(scratch)
        workdir.chmod(0o700)
        outdir = workdir / "out"
        replays = replay_tasks(root, plan, outdir)
        for replay in replays:
            (outdir / str(replay.index)).mkdir(parents=True, mode=0o700)
        env = build_env(root, plan, facts)
        playbook, checks = write_tree(root, plan, replays, env, workdir)
        summary = run_ansible(playbook, workdir)
        rows = {str(mapping(row).get("id")): mapping(row) for row in sequence(summary.get("rows"))}
        assigned = assigned_names(root, plan)
        read = fact_keys_read(root, plan)
        found = spec_reds(plan.name, rows, checks)
        for replay in replays:
            found.append(
                task_result(plan.name, replay, rows, assigned, facts, read, data, outdir, show)
            )
    return found


def task_result(
    host: str,
    replay: Replay,
    rows: Mapping[str, Env],
    assigned: set[str],
    facts: Env,
    read: set[str],
    data: Data,
    outdir: Path,
    show: bool,
) -> Result:
    """Return the result of one replayed template task, with its table validator."""
    row = rows.get(f"_or_r{replay.index}")
    items = [mapping(item) for item in sequence(row.get("items") if row else None)]
    if not items:
        return Result(host, replay.role, replay.src, "red", "the task did not run")
    worst = ("ok", "")
    order = {"ok": 0, "not-covered": 1, "unresolved": 2, "red": 3}
    for item in items:
        status, reason = classify(item, assigned, facts, read)
        if order[status] > order[worst[0]]:
            worst = (status, reason)
    if worst[0] == "ok" and replay.uncovered is not None:
        worst = ("not-covered", f"{replay.uncovered} is not installed")
    entry = data.validators.get(replay.src)
    if worst[0] == "ok" and entry is not None:
        for produced in sorted((outdir / str(replay.index)).iterdir()):
            status, reason = table_validation(produced, entry, show)
            if order[status] > order[worst[0]]:
                worst = (status, reason)
    return Result(host, replay.role, replay.src, worst[0], worst[1])


def spec_reds(host: str, rows: Mapping[str, Env], checks: Mapping[str, str]) -> list[Result]:
    """Return a red result for each role whose argument spec the environment does not satisfy."""
    found: list[Result] = []
    for role, name in checks.items():
        items = [mapping(item) for item in sequence(mapping(rows.get(name)).get("items"))]
        if any(item.get("failed") is True for item in items):
            found.append(
                Result(host, role, "argument_specs", "red", "the inputs break the argument spec")
            )
    return found


def load_data(root: Path) -> Data:
    """Read the files under offline/.

    Raises:
        ToolError: A data file is missing or has the wrong shape.
    """
    base = root / DATA
    facts = {path.stem: load_mapping(path) for path in sorted((base / "facts").glob("*.yml"))}
    table = mapping(load_mapping(base / "validators.yml").get("validators"))
    pairs = frozenset(
        (str(mapping(item).get("role")), str(mapping(item).get("template")))
        for item in sequence(load_mapping(base / "unresolved.yml").get("allowed"))
    )
    return Data(facts, {name: mapping(entry) for name, entry in table.items()}, pairs)


def apply_ratchet(
    results: Sequence[Result], allowed: frozenset[tuple[str, str]], whole: bool
) -> list[Result]:
    """Turn an unresolved result outside the ratchet into a red one.

    On a run of every host, a listed pair that no longer comes out unresolved is red too, so the
    list only shrinks.
    """
    out: list[Result] = []
    for result in results:
        if result.status == "unresolved" and (result.role, result.src) not in allowed:
            reason = f"new unresolved ({result.reason})"
            out.append(Result(result.host, result.role, result.src, "red", reason))
        else:
            out.append(result)
    if whole:
        seen = {(r.role, r.src) for r in results if r.status == "unresolved"}
        out.extend(
            Result("-", role, src, "red", "listed in unresolved.yml but it renders")
            for role, src in sorted(allowed - seen)
        )
    return out


def write_summary(path: Path, results: Sequence[Result], line: str) -> None:
    """Write a Markdown summary: the totals and every result that is not ok. No content."""
    rows = [
        f"- `{r.status}` {r.host} {r.role} {r.src} {r.reason}" for r in results if r.status != "ok"
    ]
    path.write_text(
        "\n".join(["### Offline render", "", f"`{line}`", "", *rows, ""]), encoding="utf-8"
    )


def format_line(result: Result) -> str:
    """Return the one line printed for a result: names and a class, no content."""
    tail = f" ({result.reason})" if result.reason else ""
    return f"{result.status:<12} {result.host} {result.role} {result.src}{tail}"


def totals(results: Sequence[Result], hosts: int) -> str:
    """Return the totals line."""
    counts = {
        s: sum(1 for r in results if r.status == s)
        for s in ("ok", "red", "unresolved", "not-covered")
    }
    return (
        f"hosts={hosts} outputs={len(results)} ok={counts['ok']} red={counts['red']} "
        f"unresolved={counts['unresolved']} not-covered={counts['not-covered']}"
    )


def run(root: Path, selected: Sequence[str], show: bool) -> tuple[list[Result], int]:
    """Render the selected hosts (all when none); return every result, ratchet applied, and N.

    N is the number of hosts rendered, counting one that has no template task.

    Raises:
        ToolError: A selected host does not exist.
    """
    data = load_data(root)
    plans = [p for p in host_plans(root) if not selected or p.name in selected]
    unknown = sorted(set(selected) - {p.name for p in plans})
    if unknown:
        message = f"no such host: {', '.join(unknown)}"
        raise ToolError(message)
    with ThreadPoolExecutor(max_workers=max(1, len(plans))) as pool:
        groups = list(pool.map(lambda p: render_host(root, p, data, show), plans))
    flat = [r for group in groups for r in group]
    return apply_ratchet(flat, data.unresolved, not selected), len(plans)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the tool; return its exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--host", action="append", default=[])
    parser.add_argument("--summary-file", type=Path)
    parser.add_argument("--show-validator-output", action="store_true")
    args = parser.parse_args(argv)
    try:
        results, hosts = run(args.root.resolve(), args.host, args.show_validator_output)
    except ToolError as error:
        print(f"offline_render: {error}", file=sys.stderr)
        return 2
    for result in results:
        print(format_line(result))
    line = totals(results, hosts)
    print(line)
    if args.summary_file is not None:
        write_summary(args.summary_file, results, line)
    return 1 if any(r.status == "red" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
