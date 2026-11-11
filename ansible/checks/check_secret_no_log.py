"""Check that a secret reaches no task without no_log, and that the secret names agree.

R1 takes each secret option of a role (an argument with no_log: true) and follows it through
the role's vars/ and defaults/ to every variable whose value names it. A task under tasks/ or
handlers/ that names one of those variables must set no_log: true, and a task that writes a
file from one must set diff: false. R2 holds the host_inputs loader's rows to the options they
feed. R3 holds the secret table of the pattern README to the options and their sources, and the
older table of script-side names to the files that read them. R4 refuses a task of a role that
holds a secret that the check cannot follow. What a task calls, and which file an include names,
is decided by Ansible's own task parser and plugin loaders (see "The task layer" below), never by
a spelling matcher of this module. The rules, and what they do not see, are in
ansible/checks/README.md, "The secret taint check". A finding names the rule, the file and the
task, never a value.
"""

from __future__ import annotations

import copy
import functools
import re
import sys
from pathlib import Path
from typing import NamedTuple

from ansible import constants as ansible_constants  # type: ignore[import-untyped]
from ansible.parsing.dataloader import DataLoader  # type: ignore[import-untyped]
from ansible.parsing.mod_args import ModuleArgsParser  # type: ignore[import-untyped]
from ansible.playbook.handler import Handler  # type: ignore[import-untyped]
from ansible.playbook.handler_task_include import HandlerTaskInclude  # type: ignore[import-untyped]
from ansible.playbook.role_include import IncludeRole  # type: ignore[import-untyped]
from ansible.playbook.task import Task  # type: ignore[import-untyped]
from ansible.playbook.task_include import TaskInclude  # type: ignore[import-untyped]
from ansible.plugins.loader import (  # type: ignore[import-untyped]
    add_all_plugin_dirs,
    init_plugin_loader,
    lookup_loader,
)
from ansible.template import Templar  # type: ignore[import-untyped]
from check_enrolment import _read_host_roles
from check_pins import load_yaml
from jinja2 import Environment, TemplateSyntaxError, nodes

ROOT = Path(__file__).resolve().parents[2]
ROLE_GROUPS = ("roles", "patterns")
LOADER = "host_inputs"
ROW_KEY = "host_inputs_required_by_host"
README = Path("patterns/secrets_and_no_log/README.md")
# The R1 findings the check reports on the tree today, listed by file and task name. Shrink-only.
BASELINE = Path("ansible/checks/secret_no_log_baseline.yml")
SOURCE_HEADING = "## The secret options of the roles"
SOURCE_COLUMNS = ["Role", "Option", "Source on a pulled host"]
NAMES_HEADING = "## The secret names the services will need"
NAMES_COLUMNS = ["Name", "Read under", "How it is made today"]
NAMES_TREES = ("hetzner", "mail")
LOADER_SEEDS = {LOADER: ("host_inputs_raw", "host_inputs_doc")}
EXPRESSION_KEYS = frozenset(("when", "failed_when", "changed_when", "until"))
CONTAINER_KEYS = frozenset(("block", "rescue", "always"))
# The actions the rules name, as the fully qualified name Ansible's plugin loader resolves a
# task's action to (`copy`, `ansible.legacy.copy` and `action: copy ...` all resolve to the first).
ASSERT_FQCNS = frozenset(("ansible.builtin.assert",))
TEMPLATE_FQCNS = frozenset(("ansible.builtin.template",))
# debug takes `var` as a bare expression (an implicit {{ }}), not as a template: its action plugin
# calls evaluate_expression on it. It is the only action of ansible-core 2.21.5 that does besides
# assert, whose `that` is the expression-only read above (plugins/action/*.py: evaluate_expression).
DEBUG_FQCNS = frozenset(("ansible.builtin.debug",))
# set_fact copies each of its arguments into a variable of its own name (`cacheable` is no variable).
SET_FACT_FQCNS = frozenset(("ansible.builtin.set_fact",))
VARS_LOOKUP_FQCN = "ansible.builtin.vars"
LOOKUP_CALLS = frozenset(("lookup", "query", "q"))
NAMESPACES = frozenset(("vars", "hostvars"))
# The names the executor classifies includes by, read at import so that a rename in a new
# ansible-core is an AttributeError when this module loads (loud in CI), not a per-task finding.
_CONSTANTS = ansible_constants
INCLUDE_TASKS_ACTIONS = _CONSTANTS._ACTION_ALL_INCLUDE_IMPORT_TASKS
INCLUDE_ROLE_ACTIONS = _CONSTANTS._ACTION_ALL_PROPER_INCLUDE_IMPORT_ROLES
# What Ansible's Role._load_role_yaml reads: these extensions, or none (hard-coded there, and the
# default of this setting, which Role._get_role_argspecs reads from it).
YAML_EXTENSIONS = tuple(_CONSTANTS.YAML_FILENAME_EXTENSIONS)
DIFF_FQCNS = frozenset(
    f"ansible.builtin.{name}"
    for name in ("copy", "template", "lineinfile", "blockinfile", "replace", "assemble")
)
ENV = Environment(autoescape=True)


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _strings(value: object) -> list[str]:
    """Every string in a YAML value, keys included; a value holds no template outside a string."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for key, item in value.items():
            if isinstance(key, str):
                out.append(key)
            out.extend(_strings(item))
        return out
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(_strings(item))
        return out
    return []


def _parse(text: str, rel: str, where: str, findings: list[str]) -> nodes.Template | None:
    """A template text parsed by Jinja's own parser. Only the parse is used, not the compile,
    because Ansible's filters (dirname, password_hash) are not Jinja's and a compile refuses
    them. Text that does not parse is a finding: an unreadable template cannot be cleared."""
    try:
        tree = ENV.parse(text)
    except TemplateSyntaxError:
        findings.append(f"R1 {rel}: {where} holds a template that does not parse")
        return None
    for how in dict.fromkeys(_opaque_reads(tree)):
        findings.append(
            f"R4 {rel}: {where} reads variables indirectly ({how}), so the check cannot follow "
            "what it reads: name the variable"
        )
    return tree


@functools.cache
def _is_vars_lookup(plugin: str) -> bool:
    """Whether Ansible's lookup loader resolves this name to the `vars` lookup, in any spelling
    (`vars`, `ansible.builtin.vars`, `ansible.legacy.vars`)."""
    _plugins_ready()
    context = lookup_loader.find_plugin_with_context(plugin)
    return bool(context.resolved) and context.resolved_fqcn == VARS_LOOKUP_FQCN


def _literal(node: nodes.Node) -> str | None:
    return node.value if isinstance(node, nodes.Const) and isinstance(node.value, str) else None


def _vars_access(node: nodes.Node) -> tuple[str, str | None] | None:
    """For `vars[k]`, `vars.k`, `hostvars[h][k]` and `hostvars[h].k`: the namespace and the key
    when it is a literal (None when it is not). `hostvars[h]` alone is not an access to a
    variable: it is the base of one, or an opaque read of every variable of a host."""
    if not isinstance(node, (nodes.Getattr, nodes.Getitem)):
        return None
    base = node.node
    if isinstance(base, nodes.Name) and base.name == "vars":
        return "vars", _constant_key(node)
    inner = base.node if isinstance(base, (nodes.Getattr, nodes.Getitem)) else None
    if isinstance(inner, nodes.Name) and inner.name == "hostvars":
        return "hostvars", _constant_key(node)
    return None


def _lookup_terms(node: nodes.Node) -> tuple[str | None, list[nodes.Node]] | None:
    """For `lookup('p', ...)`, `query('p', ...)` and `q('p', ...)`: the plugin name when it is a
    literal, and the terms. None when the node is no such call."""
    if (
        isinstance(node, nodes.Call)
        and isinstance(node.node, nodes.Name)
        and node.node.name in LOOKUP_CALLS
        and node.args
    ):
        return _literal(node.args[0]), list(node.args[1:])
    return None


def _indirect_names(node: nodes.Node) -> set[str]:
    """The variables this node reads by a literal name through `vars`, `hostvars` or the `vars`
    lookup, which have no Name node of their own."""
    access = _vars_access(node)
    if access is not None and access[1] is not None:
        return {access[1]}
    call = _lookup_terms(node)
    if call is not None and call[0] is not None and _is_vars_lookup(call[0]):
        return {t for t in map(_literal, call[1]) if t is not None}
    return set()


def _opaque_reads(node: nodes.Node) -> list[str]:
    """How this tree reads variables by a name the check cannot see: `vars` or `hostvars` taken
    whole or called on, a subscript of them that is not a literal, a `vars` lookup with a term
    that is not a literal or with arguments splatted in, and a lookup whose plugin is not a
    literal. Each is a finding (R4) in a role that holds a secret."""
    out: list[str] = []
    if isinstance(node, nodes.Call):
        callee = node.node
        if isinstance(callee, (nodes.Getattr, nodes.Getitem)) and _vars_access(callee):
            out.append("a method called on vars or hostvars")
        call = _lookup_terms(node)
        if call is not None:
            plugin, terms = call
            if plugin is None:
                out.append("a lookup whose plugin is not a literal name")
            elif _is_vars_lookup(plugin) and (
                node.dyn_args is not None or any(_literal(t) is None for t in terms)
            ):
                out.append("a vars lookup with a term that is not a literal name")
    access = _vars_access(node)
    if access is not None:
        if access[1] is None:
            out.append(f"a {access[0]} subscript that is not a literal name")
        walk: list[nodes.Node] = []
        if isinstance(node, nodes.Getitem):
            walk.append(node.arg)
        if (
            access[0] == "hostvars"
            and isinstance(node, (nodes.Getattr, nodes.Getitem))
            and isinstance(node.node, nodes.Getitem)
        ):
            walk.append(node.node.arg)
        for child in walk:
            out.extend(_opaque_reads(child))
        return out
    if isinstance(node, nodes.Name) and node.ctx == "load" and node.name in NAMESPACES:
        out.append(f"{node.name} taken as a whole")
    for child in node.iter_child_nodes():
        out.extend(_opaque_reads(child))
    return out


class Attrs(NamedTuple):
    """The attributes of a variable that holds a secret only in some of them: the secret ones, and
    the declared non-secret ones. Only a read through a declared non-secret attribute is cleared.
    Every other read counts: a secret attribute, an undeclared name, and a method call such as
    .get('x'), .items(), .values() or .copy(), which parses as an attribute read of its name."""

    secret: frozenset[str]
    safe: frozenset[str]


Partial = dict[str, Attrs]


def _constant_key(node: nodes.Node) -> str | None:
    """The constant key an attribute or item read names, or None when it is not constant."""
    if isinstance(node, nodes.Getattr):
        return node.attr
    if isinstance(node, nodes.Getitem) and isinstance(node.arg, nodes.Const):
        return node.arg.value if isinstance(node.arg.value, str) else None
    return None


def _loaded(node: nodes.Node, partial: Partial) -> set[str]:
    """The names a parse tree loads. A name bound by a loop is counted too, which can only ask
    for more no_log. A name in `partial` holds a secret only in some attributes, so it counts
    unless it is read through a declared non-secret attribute (x.slug, x['slug']), counted
    (length, count), or mapped to a declared non-secret attribute. Anything else counts,
    including a call on it: only the read of the name by itself is looked at, never what follows."""
    if isinstance(node, (nodes.Getattr, nodes.Getitem)) and isinstance(node.node, nodes.Name):
        name = node.node.name
        key = _constant_key(node)
        if name in partial and key is not None and key in partial[name].safe:
            return set()
    if isinstance(node, nodes.Filter) and isinstance(node.node, nodes.Name):
        name = node.node.name
        if name in partial and node.name in ("length", "count") and not node.args:
            return set()
        if name in partial and node.name == "map" and not node.args:
            attribute = [k.value for k in node.kwargs if k.key == "attribute"]
            if len(attribute) == 1 and isinstance(attribute[0], nodes.Const):
                first = str(attribute[0].value).split(".")[0]
                if first in partial[name].safe:
                    return set()
    found: set[str] = _indirect_names(node)
    if isinstance(node, nodes.Name) and node.ctx == "load":
        found.add(node.name)
    for child in node.iter_child_nodes():
        found |= _loaded(child, partial)
    return found


def _names_in(text: str, rel: str, where: str, findings: list[str], partial: Partial) -> set[str]:
    tree = _parse(text, rel, where, findings)
    return set() if tree is None else _loaded(tree, partial)


def _is_data_file(path: Path) -> bool:
    """Whether Ansible reads this file as data in a role directory: an extension of
    YAML_FILENAME_EXTENSIONS or none, and not hidden or a backup (DataLoader._get_dir_vars_files
    skips those)."""
    if path.name.startswith(".") or path.name.endswith("~"):
        return False
    return path.suffix in YAML_EXTENSIONS or path.suffix == ""


def _data_files(directory: Path) -> list[Path]:
    """Every data file under a role directory, at any depth: the check reads all of them, which
    is more than Ansible loads by name (`main`) and so asks for more, never less."""
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.rglob("*") if p.is_file() and _is_data_file(p))


def _role_yaml_files(role_dir: Path, subdir: str, main: str | None, allow_dir: bool) -> list[Path]:
    """The file or files Ansible's Role._load_role_yaml loads for `subdir`: the same name and
    extension order, resolved by the maintained DataLoader.find_vars_files (a directory named
    `main`, or `main.yml`, `main.yaml`, `main.json`, then `main` with no extension; with `main`
    given, that name first with no extension)."""
    base = role_dir / subdir
    if not base.is_dir():
        return []
    extensions = list(YAML_EXTENSIONS)
    if main is None:
        name = "main"
        extensions.append("")
    else:
        name = main
        extensions.insert(0, "")
    found = _data_loader().find_vars_files(str(base), name, extensions, allow_dir)
    return [Path(f) for f in found]


def _spec_file(role_dir: Path) -> Path | None:
    """The file Ansible reads the role's argument specs from (Role._get_role_argspecs): the first
    of meta/argument_specs.yml, .yaml, .json that exists, else the role's meta/main file, whose
    `argument_specs` key is then used. Data is not combined between the files."""
    for ext in YAML_EXTENSIONS:
        if (role_dir / "meta" / f"argument_specs{ext}").exists():
            files = _role_yaml_files(role_dir, "meta", "argument_specs", False)
            return files[0] if files else None
    files = _role_yaml_files(role_dir, "meta", None, False)
    return files[0] if files else None


def _role_files(role_dir: Path) -> tuple[list[Path], list[Path]]:
    """Every file under the role's tasks/, handlers/, vars/, defaults/ and meta/, split into the
    ones the check reads and the ones it does not. In meta/ Ansible loads only the spec file
    and the metadata file (main) it chooses, so only those are read; elsewhere every data file."""
    read: list[Path] = []
    unread: list[Path] = []
    for sub in ("tasks", "handlers", "vars", "defaults"):
        base = role_dir / sub
        if base.is_dir():
            for path in sorted(p for p in base.rglob("*") if p.is_file()):
                (read if _is_data_file(path) else unread).append(path)
    meta = role_dir / "meta"
    if meta.is_dir():
        spec = _spec_file(role_dir)
        chosen = {spec} if spec is not None else set()
        chosen.update(_role_yaml_files(role_dir, "meta", None, False))
        for path in sorted(p for p in meta.rglob("*") if p.is_file()):
            (read if path in chosen else unread).append(path)
    return read, unread


def _role_dirs(root: Path) -> list[Path]:
    dirs: list[Path] = []
    for group in ROLE_GROUPS:
        base = root / "ansible" / group
        if base.is_dir():
            dirs.extend(sorted(p for p in base.iterdir() if p.is_dir()))
    return dirs


def _option_specs(root: Path, role_dir: Path, findings: list[str]) -> dict[str, dict[str, object]]:
    """The options of the role's main argument spec, with their specs, from the file Ansible
    reads the specs from (see `_spec_file`)."""
    path = _spec_file(role_dir)
    if path is None:
        return {}
    doc, problem = load_yaml(path)
    if problem is not None:
        findings.append(f"R1 {_rel(root, path)}: {problem}")
        return {}
    main = _dict(_dict(_dict(doc).get("argument_specs")).get("main"))
    return {
        name: _dict(spec)
        for name, spec in _dict(main.get("options")).items()
        if isinstance(name, str)
    }


def _secrets_of(root: Path, role_dir: Path, findings: list[str]) -> set[str]:
    return {
        name
        for name, spec in _option_specs(root, role_dir, findings).items()
        if spec.get("no_log") is True
    }


def _secret_attrs(spec: dict[str, object]) -> set[str]:
    """The sub-options of an option spec that hold a secret: one with no_log: true, or one whose
    own sub-options do. A secret nested deeper counts its whole branch, which asks for more."""
    attrs: set[str] = set()
    for name, sub in _dict(spec.get("options")).items():
        if isinstance(name, str) and (
            _dict(sub).get("no_log") is True or _secret_attrs(_dict(sub))
        ):
            attrs.add(name)
    return attrs


def _seeds_of(root: Path, role_dir: Path, findings: list[str]) -> tuple[set[str], Partial]:
    """The seeds of a role: the variables whose whole value is a secret, and the variables
    that hold a secret only in some attributes (a list or mapping option with a no_log
    sub-option), mapped to those attributes and to the declared non-secret ones. The loader's
    own variables are seeds as well."""
    whole: set[str] = set(LOADER_SEEDS.get(role_dir.name, ()))
    partial: Partial = {}
    for name, spec in _option_specs(root, role_dir, findings).items():
        if spec.get("no_log") is True:
            whole.add(name)
        elif _secret_attrs(spec):
            secret = _secret_attrs(spec)
            declared = {k for k in _dict(spec.get("options")) if isinstance(k, str)}
            partial[name] = Attrs(frozenset(secret), frozenset(declared - secret))
    return whole, partial


def sub_option_secrets(root: Path = ROOT) -> dict[str, dict[str, set[str]]]:
    """Each role or pattern with a list or mapping option that has a no_log sub-option, with the
    option and the attributes."""
    scratch: list[str] = []
    out: dict[str, dict[str, set[str]]] = {}
    for role_dir in _role_dirs(root):
        _, partial = _seeds_of(root, role_dir, scratch)
        if partial:
            out[role_dir.name] = {name: set(attrs.secret) for name, attrs in partial.items()}
    return out


def secret_options(root: Path = ROOT) -> dict[str, set[str]]:
    """Each role or pattern that declares a no_log option, with the names of those options."""
    scratch: list[str] = []
    out: dict[str, set[str]] = {}
    for role_dir in _role_dirs(root):
        names = _secrets_of(root, role_dir, scratch)
        if names:
            out[role_dir.name] = names
    return out


def _find_role(root: Path, role: str) -> Path | None:
    for role_dir in _role_dirs(root):
        if role_dir.name == role:
            return role_dir
    return None


class _Call(NamedTuple):
    """What a task calls, as Ansible's own parser and plugin loaders resolve it. `kind` is "tasks"
    for an include_tasks or import_tasks, "role" for an include_role or import_role, and "module"
    for every other action. `action` is the name as the parser returns it, `fqcn` the name the
    plugin loader resolves a module to, `args` the arguments after Ansible has merged the task's
    `args:` keyword and the free-form text. For an include of tasks, `target` is the file Ansible
    itself chooses (TaskInclude.check_options) and `apply_vars` what the include binds under
    `apply: vars:`. `problem` says why the task cannot be followed (the parser refuses it, or the
    action does not resolve), and is None when the task resolves."""

    kind: str
    action: str
    fqcn: str
    args: dict[str, object]
    target: str | None
    apply_vars: dict[str, object]
    problem: str | None


class _Where(NamedTuple):
    """One task file of a role: where it is, and the task files the check reads in that role
    (resolved paths), which is what an include can be followed into."""

    role_dir: Path
    path: Path
    rel: str
    handler: bool
    walked: frozenset[Path]


@functools.cache
def _plugins_ready() -> bool:
    """Install Ansible's collection finder, as `ansible-playbook` does before it loads a task
    (CLI.run calls init_plugin_loader), so that a fully qualified name in a collection resolves."""
    init_plugin_loader()
    return True


@functools.cache
def _role_plugins(role_dir: Path) -> tuple[str, ...]:
    """Add the role's own `library/` and plugin directories to Ansible's loaders, as Ansible does
    when it loads a role (Role._load_role_data calls add_all_plugin_dirs). A module the role
    ships then resolves, as it does in a play. The directories stay added for the process, as
    they do for a play, so a module of one role resolves for another role checked after it.
    Returns the names of the files the role ships there, which a resolution may depend on."""
    _plugins_ready()
    add_all_plugin_dirs(str(role_dir))
    return tuple(
        sorted(
            f"{sub}/{p.name}"
            for sub in ("library", "action_plugins")
            for p in (role_dir / sub).glob("*")
        )
    )


@functools.cache
def _data_loader() -> DataLoader:
    return DataLoader()


@functools.cache
def _templar() -> Templar:
    return Templar()


def _refused(why: str) -> _Call:
    return _Call("module", "", "", {}, None, {}, why)


def _detail(ex: Exception) -> str:
    """The class and the message of a parser's refusal. Ansible's messages name keys and actions,
    never the data of a task, because the task itself travels as `obj`, which is left out."""
    message = getattr(ex, "message", "")
    text = message.strip().splitlines()[0][:160] if isinstance(message, str) and message else ""
    return f"{type(ex).__name__}: {text}" if text else type(ex).__name__


def _parse_call(task: dict[str, object], handler: bool) -> _Call:
    """Resolve one task as the executor does (ansible.playbook.helpers.load_list_of_tasks): the
    parser's (action, args, delegate_to) classifies it, and the loader of its class validates and
    normalises it. Nothing here chooses by a module name or a keyword spelling of this module."""
    _plugins_ready()
    try:
        action = ModuleArgsParser(copy.deepcopy(task)).parse(skip_action_validation=True)[0]
        if action in INCLUDE_TASKS_ACTIONS:
            include = (HandlerTaskInclude if handler else TaskInclude).load(copy.deepcopy(task))
            kind = "tasks"
        elif action in INCLUDE_ROLE_ACTIONS:
            include = IncludeRole.load(copy.deepcopy(task))
            kind = "role"
        else:
            loaded = (Handler if handler else Task).load(copy.deepcopy(task))
            fqcn = loaded.resolved_action
            if not isinstance(fqcn, str) or not fqcn:
                return _refused(
                    "its action does not resolve to a plugin Ansible can load (a templated "
                    "action, an unknown name, or a collection that is not installed)"
                )
            return _Call("module", str(action), fqcn, dict(loaded.args), None, {}, None)
        args = dict(include.args)
        target = args.get("_raw_params") if kind == "tasks" else None
        apply = args.get("apply") or {}
        apply_vars = apply.get("vars") if isinstance(apply, dict) else None
        if kind == "tasks" and not isinstance(target, str):
            return _refused("the file it includes is not text")
        if apply_vars is not None and not isinstance(apply_vars, dict):
            return _refused("its `apply: vars:` is not a mapping")
        return _Call(kind, str(action), "", args, target, apply_vars or {}, None)
    except Exception as ex:  # noqa: BLE001 - whatever the parser raises on is a finding
        return _refused(f"Ansible's own task parser refuses it ({_detail(ex)})")


_CALLS: dict[tuple[str, bool, tuple[str, ...]], _Call] = {}


def _call(task: dict[str, object], where: _Where) -> _Call:
    """The resolution of a task, kept by the task's content, whether it is a handler, and the
    modules and action plugins its role ships (which it may name). It depends on nothing else,
    so a copy of a tree resolves from what an earlier copy resolved."""
    shipped = _role_plugins(where.role_dir)
    key = (repr(task), where.handler, shipped)
    if key not in _CALLS:
        _CALLS[key] = _parse_call(task, where.handler)
    return _CALLS[key]


def _included_file(target: str, where: _Where) -> Path | None:
    """The task file an include names, found by Ansible's own DataLoader the way the executor
    finds it: beside the including file, then in the role's tasks (or handlers) directory.
    None when the name is a template, or no file of that name answers."""
    if _templar().is_possibly_template(target):
        return None
    subdir = "handlers" if where.handler else "tasks"
    for base in (where.path.parent, where.role_dir / subdir):
        found = Path(_data_loader().path_dwim_relative(str(base), subdir, target, is_role=True))
        if found.is_file():
            return found.resolve()
    return None


def _unfollowed(call: _Call, where: _Where) -> str | None:
    """Why the check cannot follow this task, or None. A task the parser refuses or cannot
    resolve, an include of a role, and an include whose file is named by a template or is not
    one of the task files the check reads are all unfollowed."""
    if call.problem is not None:
        return call.problem
    if call.kind == "role":
        return (
            "it includes a role, whose tasks and reads are outside this role's taint, and no "
            "role includes another (ANS-12)"
        )
    if call.kind == "tasks" and call.target is not None:
        if _templar().is_possibly_template(call.target):
            return "it includes a file named by a template, so no file can be chosen without a run"
        found = _included_file(call.target, where)
        if found is None or found not in where.walked:
            return (
                f"it includes '{call.target}', which is not a task file of the role that the "
                "check reads (under tasks/ or handlers/)"
            )
    return None


def _includes(call: _Call) -> bool:
    """Whether the task includes other tasks, which see its variables. A task that could not be
    resolved counts as one, which asks for more no_log."""
    return call.kind != "module" or call.problem is not None


class _Loop(NamedTuple):
    """A task that loops: the loop variable it names (None for the default `item`), the parsed
    loop expression, the name the expression is when it is that name alone, and whether the task
    includes other tasks, which see the loop variable."""

    var: str | None
    trees: list[nodes.Template]
    bare: str | None
    includes: bool
    rel: str
    name: str


def _bare_name(tree: nodes.Template) -> str | None:
    body = tree.body
    if len(body) == 1 and isinstance(body[0], nodes.Output) and len(body[0].nodes) == 1:
        only = body[0].nodes[0]
        if isinstance(only, nodes.Name):
            return only.name
    return None


def _loops_in(items: list[object], where: _Where, out: list[_Loop]) -> None:
    rel = where.rel
    for task in items:
        if not isinstance(task, dict):
            continue
        keys = [k for k in task if isinstance(k, str) and (k == "loop" or k.startswith("with_"))]
        if keys:
            includes = not CONTAINER_KEYS & task.keys() and _includes(_call(task, where))
            trees: list[nodes.Template] = []
            for key in keys:
                for text in _strings(task[key]):
                    tree = _parse(text, rel, "a loop", [])
                    if tree is not None:
                        trees.append(tree)
            bare = _bare_name(trees[0]) if len(keys) == 1 and len(trees) == 1 else None
            var = _dict(task.get("loop_control")).get("loop_var")
            out.append(
                _Loop(
                    var if isinstance(var, str) and var.isidentifier() else None,
                    trees,
                    bare,
                    includes,
                    rel,
                    str(task.get("name", "(unnamed)")),
                )
            )
        for key in CONTAINER_KEYS & task.keys():
            inner = task[key]
            if isinstance(inner, list):
                _loops_in(inner, where, out)


def _task_file_wheres(root: Path, role_dir: Path) -> list[_Where]:
    """Each task file of the role (tasks/ and handlers/) with the set the check reads."""
    paths = _task_paths(role_dir)
    walked = frozenset(p.resolve() for p in paths)
    handlers = role_dir / "handlers"
    return [_Where(role_dir, p, _rel(root, p), handlers in p.parents, walked) for p in paths]


def _loops(root: Path, role_dir: Path) -> list[_Loop]:
    out: list[_Loop] = []
    for where in _task_file_wheres(root, role_dir):
        doc, problem = load_yaml(where.path)
        if problem is None and isinstance(doc, list):
            _loops_in(doc, where, out)
    return out


class _Bind(NamedTuple):
    """A name bound by a task's `vars:` (or an include's `apply: vars:`, wherever Ansible's own
    parser finds `apply`): its parsed value, the name the value is when it is that name alone,
    and, when the task includes other tasks, whether the check can follow the include (False for
    a role, a template name, and a file it does not read)."""

    key: str
    trees: list[nodes.Template]
    bare: str | None
    rel: str
    name: str
    includes: bool
    followed: bool


def _binds_in(items: list[object], where: _Where, out: list[_Bind]) -> None:
    rel = where.rel
    for task in items:
        if not isinstance(task, dict):
            continue
        call = None if CONTAINER_KEYS & task.keys() else _call(task, where)
        includes = call is not None and _includes(call)
        followed = call is not None and _unfollowed(call, where) is None
        scopes = [task.get("vars"), call.apply_vars if call is not None else None]
        pairs = [item for scope in scopes for item in _dict(scope).items()]
        if call is not None and call.fqcn in SET_FACT_FQCNS:
            # set_fact sets each argument as a variable of that name, which later tasks read.
            pairs += [(k, v) for k, v in call.args.items() if k != "cacheable"]
        for key, value in pairs:
            if not isinstance(key, str):
                continue
            trees = [t for t in (_parse(s, rel, "a vars value", []) for s in _strings(value)) if t]
            bare = _bare_name(trees[0]) if isinstance(value, str) and len(trees) == 1 else None
            out.append(
                _Bind(
                    key,
                    trees,
                    bare,
                    rel,
                    str(task.get("name", "(unnamed)")),
                    includes,
                    followed,
                )
            )
        for key in CONTAINER_KEYS & task.keys():
            inner = task[key]
            if isinstance(inner, list):
                _binds_in(inner, where, out)


def _task_paths(role_dir: Path) -> list[Path]:
    return _data_files(role_dir / "tasks") + _data_files(role_dir / "handlers")


def _binds(root: Path, role_dir: Path) -> list[_Bind]:
    out: list[_Bind] = []
    for where in _task_file_wheres(root, role_dir):
        doc, problem = load_yaml(where.path)
        if problem is None and isinstance(doc, list):
            _binds_in(doc, where, out)
    return out


class _Reg(NamedTuple):
    """A task that registers its result under `key`. The result holds what the task printed or
    wrote, so it is a secret when the task names one (see `_taint`)."""

    key: str
    task: dict[str, object]
    call: _Call
    where: _Where


def _regs_in(items: list[object], where: _Where, out: list[_Reg]) -> None:
    for task in items:
        if not isinstance(task, dict):
            continue
        if not CONTAINER_KEYS & task.keys() and isinstance(task.get("register"), str):
            out.append(_Reg(str(task["register"]), task, _call(task, where), where))
        for key in CONTAINER_KEYS & task.keys():
            inner = task[key]
            if isinstance(inner, list):
                _regs_in(inner, where, out)


def _registers(root: Path, role_dir: Path) -> list[_Reg]:
    out: list[_Reg] = []
    for where in _task_file_wheres(root, role_dir):
        doc, problem = load_yaml(where.path)
        if problem is None and isinstance(doc, list):
            _regs_in(doc, where, out)
    return out


def _taint(
    root: Path,
    role_dir: Path,
    seeds: set[str],
    partial_seeds: Partial,
    findings: list[str],
) -> tuple[dict[str, set[str]], Partial]:
    """Each variable of the role that holds a secret, mapped to the secret options it came from,
    and the subset of those that hold a secret only in some attributes, mapped to the attributes.
    A seed maps to itself, and an attribute seed to `name.attribute`. Taint follows a value that
    names a tainted variable, to a fixed point, and a variable reached through two secrets names
    both. It follows a loop over a tainted variable into the loop variable the loop names, role
    wide, because an included task file reads that variable: a loop over the attribute seed
    alone gives a loop variable with the same secret attributes. A name bound by a task's
    `vars:` (an include's too) is followed the same way, role wide, because the included file
    reads it and no_log on an include does not reach the tasks it includes. An include that
    passes such a name into a file the check cannot read is a finding."""
    partial: Partial = dict(partial_seeds)
    origin: dict[str, set[str]] = {seed: {seed} for seed in seeds}
    for name, attrs in partial.items():
        origin[name] = {f"{name}.{attr}" for attr in sorted(attrs.secret)}
    pinned = set(origin)
    defs: dict[str, list[nodes.Template]] = {}
    for sub in ("vars", "defaults"):
        for path in _data_files(role_dir / sub):
            doc, problem = load_yaml(path)
            rel = _rel(root, path)
            if problem is not None:
                findings.append(f"R1 {rel}: {problem}")
                continue
            for key, value in _dict(doc).items():
                if not isinstance(key, str):
                    continue
                for text in _strings(value):
                    tree = _parse(text, rel, f"variable {key}", findings)
                    if tree is not None:
                        defs.setdefault(key, []).append(tree)
    loops = _loops(root, role_dir)
    binds = _binds(root, role_dir)
    regs = _registers(root, role_dir)
    changed = True
    while changed:
        changed = False
        for key, trees in defs.items():
            if key in pinned:
                continue
            reached: set[str] = set()
            for tree in trees:
                for ref in _loaded(tree, partial) & origin.keys():
                    reached |= origin[ref]
            if reached and not reached <= origin.get(key, set()):
                origin[key] = origin.get(key, set()) | reached
                changed = True
        for loop in loops:
            if loop.var is None or loop.var in pinned:
                continue
            hits: set[str] = set()
            for tree in loop.trees:
                hits |= _loaded(tree, partial) & origin.keys()
            if loop.bare is not None and loop.bare in partial:
                if loop.var not in origin:
                    partial[loop.var] = partial[loop.bare]
                    origin[loop.var] = set(origin[loop.bare])
                    changed = True
            elif hits:
                reached = set().union(*(origin[hit] for hit in hits))
                if loop.var in partial or not reached <= origin.get(loop.var, set()):
                    partial.pop(loop.var, None)
                    origin[loop.var] = origin.get(loop.var, set()) | reached
                    changed = True
        for bind in binds:
            if bind.key in pinned:
                continue
            hits = set()
            for tree in bind.trees:
                hits |= _loaded(tree, partial) & origin.keys()
            if bind.bare is not None and bind.bare in partial:
                taken = partial[bind.bare]
                held = partial.get(bind.key)
                if bind.key in origin and held is None:
                    continue
                merged = taken
                if held is not None:
                    secret = held.secret | taken.secret
                    merged = Attrs(secret, (held.safe & taken.safe) - secret)
                if merged != held:
                    partial[bind.key] = merged
                    origin[bind.key] = origin.get(bind.key, set()) | origin[bind.bare]
                    changed = True
            elif hits:
                reached = set().union(*(origin[hit] for hit in hits))
                if bind.key in partial or not reached <= origin.get(bind.key, set()):
                    partial.pop(bind.key, None)
                    origin[bind.key] = origin.get(bind.key, set()) | reached
                    changed = True
        for reg in regs:
            if reg.key in pinned:
                continue
            # The findings of this pass are reported by _walk, so they are not kept here.
            scratch: list[str] = []
            refs = _task_refs(reg.task, reg.call, reg.where.rel, reg.key, scratch, partial)
            refs |= _template_refs(reg.call, reg.where, reg.key, scratch, partial)
            hits = refs & origin.keys()
            if hits:
                reached = set().union(*(origin[hit] for hit in hits))
                if reg.key in partial or not reached <= origin.get(reg.key, set()):
                    partial.pop(reg.key, None)
                    origin[reg.key] = origin.get(reg.key, set()) | reached
                    changed = True
    role_binds =[b for b in binds if b.includes and b.key in origin]
    for bind in role_binds:
        if not bind.followed:
            findings.append(
                f"R1 {bind.rel}: task '{bind.name}' passes {bind.key}, which holds a secret, "
                "into an include that cannot be followed: name a task file of the role"
            )
    for loop in loops:
        if loop.var is None and loop.includes:
            if any(_loaded(tree, partial) & origin.keys() for tree in loop.trees):
                findings.append(
                    f"R1 {loop.rel}: task '{loop.name}' loops over a secret and includes tasks, "
                    "so it must name a loop_var: the included tasks cannot be followed through item"
                )
    return origin, partial


def tainted(root: Path, role: str) -> set[str]:
    """The variables of one role that hold a secret: its seeds and what they reach."""
    role_dir = _find_role(root, role)
    if role_dir is None:
        return set()
    whole, partial = _seeds_of(root, role_dir, [])
    return set(_taint(root, role_dir, whole, partial, [])[0])


def _task_refs(
    task: dict[str, object],
    call: _Call | None,
    rel: str,
    name: str,
    findings: list[str],
    partial: Partial,
) -> set[str]:
    """The variables a task names in any position that prints or uses a value. The expression
    keywords are left out: they print only their expression, and the refusal asserts are read
    for their coded messages. A secret named in an assert's fail message still counts. An assert
    is what Ansible resolves to the assert action, whatever its spelling, and its `that` is read
    from the arguments Ansible's parser merged, wherever the task wrote them."""
    body = {k: v for k, v in task.items() if k not in EXPRESSION_KEYS and k not in CONTAINER_KEYS}
    if call is not None and call.fqcn in ASSERT_FQCNS:
        for carrier in ("action", "local_action", "args", call.action):
            body.pop(carrier, None)
        body["(arguments of the assert)"] = {k: v for k, v in call.args.items() if k != "that"}
    scoped = body.get("vars")
    if isinstance(scoped, dict):
        # A name bound by `vars:` is set, not read: only what it is set to can leak.
        body["vars"] = list(scoped.values())
    refs: set[str] = set()
    for text in _strings(body):
        refs |= _names_in(text, rel, f"task '{name}'", findings, partial)
    if call is not None and call.fqcn in DEBUG_FQCNS and isinstance(call.args.get("var"), str):
        # debug evaluates `var` as an expression with an implicit {{ }}, so it names a variable
        # with no braces: read it as the template it is evaluated as.
        expression = "{{ " + str(call.args["var"]) + " }}"
        refs |= _names_in(expression, rel, f"task '{name}'", findings, partial)
    for key, value in task.items():
        # with_<lookup> hands its terms to the lookup, and the `vars` lookup reads each term as
        # the name of a variable.
        if isinstance(key, str) and key.startswith("with_") and _is_vars_lookup(key[5:]):
            terms = value if isinstance(value, list) else [value]
            literal = [
                t for t in terms if isinstance(t, str) and not _templar().is_possibly_template(t)
            ]
            if len(literal) == len(terms):
                refs |= set(literal)
            else:
                findings.append(
                    f"R4 {rel}: task '{name}' reads variables indirectly ({key} with a term that "
                    "is not a literal name), so the check cannot follow what it reads: name the "
                    "variable"
                )
    return refs


def _template_refs(
    call: _Call,
    where: _Where,
    name: str,
    findings: list[str],
    partial: Partial,
) -> set[str]:
    refs: set[str] = set()
    if call.fqcn in TEMPLATE_FQCNS:
        src = call.args.get("src")
        path = where.role_dir / "templates" / src if isinstance(src, str) else None
        if path is None or not path.is_file():
            findings.append(f"R1 {where.rel}: task '{name}' names a template that cannot be read")
            return refs
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            findings.append(f"R1 {where.rel}: task '{name}' names a template that cannot be read")
            return refs
        refs |= _names_in(text, where.rel, f"template of task '{name}'", findings, partial)
    return refs


def _chain(name: str, origin: dict[str, set[str]]) -> str:
    if origin[name] == {name}:
        return name
    return f"{name} (secret through {', '.join(sorted(origin[name]))})"


def _judge(
    refs: set[str],
    call: _Call | None,
    no_log: object,
    diff: object,
    name: str,
    rel: str,
    origin: dict[str, set[str]],
    findings: list[str],
) -> None:
    hit = sorted(refs & origin.keys())
    if not hit:
        return
    named = ", ".join(_chain(n, origin) for n in hit)
    if no_log is not True:
        findings.append(f"R1 {rel}: task '{name}' refers to {named} and must set no_log: true")
    if call is not None and call.fqcn in DIFF_FQCNS and diff is not False:
        findings.append(f"R1 {rel}: task '{name}' writes {named} and must set diff: false (ANS-16)")


def _walk(
    items: list[object],
    where: _Where,
    taint: tuple[dict[str, set[str]], Partial],
    inherited_no_log: object,
    inherited_diff: object,
    findings: list[str],
) -> int:
    origin, partial = taint
    rel = where.rel
    count = 0
    for task in items:
        if not isinstance(task, dict):
            findings.append(f"R1 {rel}: an entry is not a task mapping")
            continue
        name = str(task.get("name", "(unnamed)"))
        no_log = task["no_log"] if "no_log" in task else inherited_no_log
        diff = task["diff"] if "diff" in task else inherited_diff
        if CONTAINER_KEYS.intersection(task.keys()):
            refs = _task_refs(task, None, rel, name, findings, partial)
            _judge(refs, None, no_log, diff, name, rel, origin, findings)
            for key in CONTAINER_KEYS.intersection(task.keys()):
                inner = task[key]
                if not isinstance(inner, list):
                    findings.append(f"R1 {rel}: task '{name}' has a {key} that is not a list")
                    continue
                count += _walk(inner, where, taint, no_log, diff, findings)
            continue
        count += 1
        call = _call(task, where)
        why = _unfollowed(call, where)
        if why is not None:
            findings.append(f"R4 {rel}: task '{name}' cannot be followed: {why}")
        refs = _task_refs(task, call, rel, name, findings, partial)
        refs |= _template_refs(call, where, name, findings, partial)
        _judge(refs, call, no_log, diff, name, rel, origin, findings)
    return count


def _r1(root: Path, findings: list[str]) -> int:
    """R1 over every role and pattern that declares a secret, and R4 over the same tasks.
    Returns the tasks checked."""
    checked = 0
    for role_dir in _role_dirs(root):
        whole, partial = _seeds_of(root, role_dir, findings)
        if not whole and not partial:
            continue
        taint = _taint(root, role_dir, whole, partial, findings)
        for path in _role_files(role_dir)[1]:
            findings.append(
                f"R4 {_rel(root, path)}: a file of a role that holds a secret which the check "
                "does not read, so nothing in it is checked: Ansible loads data files here by "
                "the extensions .yml, .yaml, .json or none (and in meta/ only the spec file and "
                "main it chooses), so rename it, or remove it"
            )
        wheres = _task_file_wheres(root, role_dir)
        for name in LOADER_SEEDS.get(role_dir.name, ()):
            if not any(name in where.path.read_text(encoding="utf-8") for where in wheres):
                findings.append(
                    f"R1 {_rel(root, role_dir)}: the loader variable {name} is named by no task, "
                    "so the check would see nothing"
                )
        for where in wheres:
            doc, problem = load_yaml(where.path)
            if problem is not None:
                findings.append(f"R1 {where.rel}: {problem}")
                continue
            if doc is None:
                continue
            if not isinstance(doc, list):
                findings.append(f"R1 {where.rel}: must be a list of tasks")
                continue
            checked += _walk(doc, where, taint, None, None, findings)
    return checked


def _declared(root: Path) -> dict[str, set[str]]:
    scratch: list[str] = []
    return {
        role_dir.name: set(_option_specs(root, role_dir, scratch)) for role_dir in _role_dirs(root)
    }


def _rows(root: Path, findings: list[str]) -> dict[tuple[str, str], set[str]]:
    """R2: each host_inputs row name resolves to exactly one declared option of a role on the
    host's list. Returns (role, option) mapped to the hosts whose row feeds it. An unreadable
    file or host list gives no rows at all, which R3 then reports as missing sources."""
    rel = f"ansible/roles/{LOADER}/vars/main.yml"
    doc, problem = load_yaml(root / "ansible" / "roles" / LOADER / "vars" / "main.yml")
    if problem is not None:
        findings.append(f"R2 {rel}: {problem}")
        return {}
    rows = _dict(doc).get(ROW_KEY)
    if not isinstance(rows, dict) or not rows:
        findings.append(f"R2 {rel}: {ROW_KEY} must be a non-empty mapping of host to names")
        return {}
    host_scratch: list[str] = []
    host_roles = _read_host_roles(root / "ansible", host_scratch)
    if host_scratch:
        findings.extend(f"R2 host list unreadable: {message}" for message in host_scratch)
        return {}
    declared = _declared(root)
    resolved: dict[tuple[str, str], set[str]] = {}
    for host, names in rows.items():
        if host not in host_roles:
            findings.append(f"R2 {rel}: host {host} has a row but is not in the host list")
            continue
        if not isinstance(names, list) or not names or not all(isinstance(n, str) for n in names):
            findings.append(f"R2 {rel}: the row of {host} is not a non-empty list of names")
            continue
        for name in names:
            owners = [role for role in host_roles[host] if name in declared.get(role, set())]
            if len(owners) != 1:
                findings.append(
                    f"R2 {rel}: the row of {host} names {name}, which resolves to "
                    f"{len(owners)} options, not one"
                )
                continue
            resolved.setdefault((owners[0], name), set()).add(host)
    return resolved


def _plain(cell: str) -> str:
    return cell.replace("`", "").strip()


def _table(text: str, heading: str, columns: list[str]) -> list[list[str]] | None:
    """The body rows of the first table under a heading, or None when the table is missing,
    not the expected columns, or empty."""
    lines = text.splitlines()
    if heading not in lines:
        return None
    start = lines.index(heading)
    table: list[str] = []
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if stripped.startswith("|"):
            table.append(stripped)
        elif table or stripped.startswith("#"):
            break
    cells = [[c.strip() for c in line.strip("|").split("|")] for line in table]
    if len(cells) < 3 or cells[0] != columns:
        return None
    if not all(re.fullmatch(r":?-+:?", c) for c in cells[1]):
        return None
    body = cells[2:]
    if any(len(row) != len(columns) for row in body):
        return None
    return body


def _source(hosts: set[str]) -> str:
    if not hosts:
        return "none"
    return f"{LOADER}: {', '.join(sorted(hosts))}"


def _corpus(root: Path) -> str:
    parts: list[str] = []
    paths: list[Path] = []
    for tree in NAMES_TREES:
        base = root / tree
        if base.is_dir():
            paths.extend(sorted(p for p in base.rglob("*") if p.is_file()))
    paths.extend(sorted(root.glob("RUNBOOK*.md")))
    for path in paths:
        try:
            parts.append(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
    return "\n".join(parts)


def _r3(root: Path, resolved: dict[tuple[str, str], set[str]], findings: list[str]) -> None:
    """R3: the secret table of the pattern README agrees with the no_log options and their
    sources; each name in the older table is read by some file under hetzner/, mail/ or root."""
    rel = f"ansible/{README.as_posix()}"
    path = root / "ansible" / README
    if not path.is_file():
        findings.append(f"R3 {rel}: is missing")
        return
    text = path.read_text(encoding="utf-8")
    expected: dict[tuple[str, str], str] = {
        (role, name): _source(resolved.get((role, name), set()))
        for role, names in secret_options(root).items()
        for name in names
    }
    rows = _table(text, SOURCE_HEADING, SOURCE_COLUMNS)
    if rows is None:
        findings.append(
            f"R3 {rel}: the table under '{SOURCE_HEADING}' is missing, empty, or not three columns"
        )
    else:
        seen: dict[tuple[str, str], str] = {}
        for cells in rows:
            key = (_plain(cells[0]), _plain(cells[1]))
            source = _plain(cells[2])
            if key in seen:
                findings.append(f"R3 {rel}: {key[0]} {key[1]} has two rows")
            seen[key] = source
            if key not in expected:
                findings.append(f"R3 {rel}: {key[0]} {key[1]} is a row for no no_log option")
            elif source != expected[key]:
                findings.append(
                    f"R3 {rel}: {key[0]} {key[1]} has source '{source}', "
                    f"the derived source is '{expected[key]}'"
                )
        for key in sorted(expected.keys() - seen.keys()):
            findings.append(f"R3 {rel}: no row for the no_log option {key[0]} {key[1]}")
    names_rows = _table(text, NAMES_HEADING, NAMES_COLUMNS)
    if names_rows is None:
        findings.append(
            f"R3 {rel}: the table under '{NAMES_HEADING}' is missing, empty, or not three columns"
        )
        return
    corpus = _corpus(root)
    for cells in names_rows:
        for name in re.findall(r"`([A-Z][A-Z0-9_]*)`", cells[0]):
            if not re.search(rf"(?<![A-Z0-9_]){name}(?![A-Za-z0-9_])", corpus):
                findings.append(
                    f"R3 {rel}: the name {name} is read by no file under hetzner/, mail/, or root"
                )


_R1_TASK = re.compile(
    r"^R1 (?P<rel>[^:]+): task '(?P<name>.*)' (?:refers to|writes) "
    r".*must set (?P<rule>no_log|diff)\b"
)


def _key(finding: str) -> tuple[str, str, str] | None:
    """The baseline key of an R1 finding about a task that lacks no_log or diff: file, task name
    and rule. No line number and no variable chain, so an edit elsewhere does not churn the list."""
    match = _R1_TASK.match(finding)
    return None if match is None else (match["rel"], match["name"], match["rule"])


def _baseline(root: Path) -> tuple[set[tuple[str, str, str]], list[str]]:
    """The keys the baseline file lists, and the findings about its shape (R5)."""
    path = root / BASELINE
    doc, problem = load_yaml(path)
    if problem is not None:
        return set(), [f"R5 {BASELINE}: {problem}"]
    if doc is None:
        doc = {}
    if not isinstance(doc, dict):
        return set(), [f"R5 {BASELINE}: must map each file to its list of entries"]
    listed: set[tuple[str, str, str]] = set()
    problems: list[str] = []
    for rel, entries in doc.items():
        if not isinstance(entries, list):
            problems.append(f"R5 {BASELINE}: the entries of {rel} must be a list")
            continue
        for entry in entries:
            task = entry.get("task") if isinstance(entry, dict) else None
            rule = entry.get("rule") if isinstance(entry, dict) else None
            if not isinstance(task, str) or rule not in ("no_log", "diff"):
                problems.append(f"R5 {BASELINE}: an entry of {rel} needs a task and a rule")
                continue
            listed.add((str(rel), task, rule))
    return listed, problems


def _against_baseline(root: Path, findings: list[str]) -> list[str]:
    """Hold the findings to the baseline, which only shrinks: a finding it does not list is a
    finding, and a listed entry that no longer fires is a finding too (so a fixed task leaves it)."""
    listed, problems = _baseline(root)
    fired: set[tuple[str, str, str]] = set()
    out = list(problems)
    for finding in findings:
        key = _key(finding)
        if key is not None and key in listed:
            fired.add(key)
        else:
            out.append(finding)
    for rel, task, rule in sorted(listed - fired):
        out.append(
            f"R5 {BASELINE}: {rel}: task '{task}' ({rule}) no longer fires: remove the entry"
        )
    return out


def check(root: Path = ROOT) -> list[str]:
    """One finding per broken rule that the baseline does not hold, or an empty list when the tree
    passes. The R1 findings the baseline lists are known and not reported (see BASELINE)."""
    findings: list[str] = []
    _r1(root, findings)
    resolved = _rows(root, findings)
    _r3(root, resolved, findings)
    return _against_baseline(root, list(dict.fromkeys(findings)))


def summary(root: Path = ROOT) -> list[str]:
    """Counts for the reader: the secret options, and the variables that the taint reaches."""
    secrets = secret_options(root)
    subs = sub_option_secrets(root)
    derived: set[str] = set()
    for role in sorted(set(secrets) | set(subs) | set(LOADER_SEEDS)):
        seeds = secrets.get(role, set()) | set(subs.get(role, {})) | set(LOADER_SEEDS.get(role, ()))
        derived |= tainted(root, role) - seeds
    count = sum(len(names) for names in secrets.values())
    sub_count = sum(len(options) for options in subs.values())
    return [
        f"note: {count} no_log options in {len(secrets)} roles and patterns",
        f"note: {sub_count} list options with a no_log sub-option in {len(subs)} roles,"
        f" and the {LOADER} loader's own variables",
        f"note: {len(derived)} variables reached from them: {', '.join(sorted(derived))}",
    ]


def main() -> int:
    findings = check(ROOT)
    for line in summary(ROOT):
        print(line)
    for finding in findings:
        print(f"FAIL {finding}")
    if not findings:
        print("ok: no finding")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
