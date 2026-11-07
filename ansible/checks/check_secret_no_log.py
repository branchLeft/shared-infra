"""Check that a secret reaches no task without no_log, and that the secret names agree.

R1 takes each secret option of a role (an argument with no_log: true) and follows it through
the role's vars/ and defaults/ to every variable whose value names it. A task under tasks/ or
handlers/ that names one of those variables must set no_log: true, and a task that writes a
file from one must set diff: false. R2 holds the host_inputs loader's rows to the options they
feed. R3 holds the secret table of the pattern README to the options and their sources, and the
older table of script-side names to the files that read them. The rules, and what they do not
see, are in ansible/checks/README.md, "The secret taint check". A finding names the rule, the
file and the task, never a value.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NamedTuple

from check_enrolment import _read_host_roles
from check_pins import load_yaml
from jinja2 import Environment, TemplateSyntaxError, nodes

ROOT = Path(__file__).resolve().parents[2]
ROLE_GROUPS = ("roles", "patterns")
LOADER = "host_inputs"
ROW_KEY = "host_inputs_required_by_host"
README = Path("patterns/secrets_and_no_log/README.md")
SOURCE_HEADING = "## The secret options of the roles"
SOURCE_COLUMNS = ["Role", "Option", "Source on a pulled host"]
NAMES_HEADING = "## The secret names the services will need"
NAMES_COLUMNS = ["Name", "Read under", "How it is made today"]
NAMES_TREES = ("hetzner", "mail")
LOADER_SEEDS = {LOADER: ("host_inputs_raw", "host_inputs_doc")}
INCLUDE_NAMES = frozenset(
    f"{prefix}{name}"
    for prefix in ("", "ansible.builtin.")
    for name in ("include_tasks", "import_tasks", "include_role", "import_role")
)
EXPRESSION_KEYS = frozenset(("when", "failed_when", "changed_when", "until"))
CONTAINER_KEYS = frozenset(("block", "rescue", "always"))
ASSERT_NAMES = frozenset(("assert", "ansible.builtin.assert"))
TEMPLATE_NAMES = frozenset(("template", "ansible.builtin.template"))
DIFF_NAMES = frozenset(
    f"{prefix}{name}"
    for prefix in ("", "ansible.builtin.")
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
        return ENV.parse(text)
    except TemplateSyntaxError:
        findings.append(f"R1 {rel}: {where} holds a template that does not parse")
        return None


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
    found: set[str] = set()
    if isinstance(node, nodes.Name) and node.ctx == "load":
        found.add(node.name)
    for child in node.iter_child_nodes():
        found |= _loaded(child, partial)
    return found


def _names_in(text: str, rel: str, where: str, findings: list[str], partial: Partial) -> set[str]:
    tree = _parse(text, rel, where, findings)
    return set() if tree is None else _loaded(tree, partial)


def _yaml_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.rglob("*") if p.suffix in (".yml", ".yaml") and p.is_file())


def _role_dirs(root: Path) -> list[Path]:
    dirs: list[Path] = []
    for group in ROLE_GROUPS:
        base = root / "ansible" / group
        if base.is_dir():
            dirs.extend(sorted(p for p in base.iterdir() if p.is_dir()))
    return dirs


def _option_specs(root: Path, role_dir: Path, findings: list[str]) -> dict[str, dict[str, object]]:
    """The options of the role's main argument spec, with their specs."""
    path = role_dir / "meta" / "argument_specs.yml"
    if not path.is_file():
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


def _loops_in(items: list[object], rel: str, out: list[_Loop]) -> None:
    for task in items:
        if not isinstance(task, dict):
            continue
        keys = [k for k in task if isinstance(k, str) and (k == "loop" or k.startswith("with_"))]
        if keys:
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
                    bool(INCLUDE_NAMES & task.keys()),
                    rel,
                    str(task.get("name", "(unnamed)")),
                )
            )
        for key in CONTAINER_KEYS & task.keys():
            inner = task[key]
            if isinstance(inner, list):
                _loops_in(inner, rel, out)


def _loops(root: Path, role_dir: Path) -> list[_Loop]:
    out: list[_Loop] = []
    for path in _yaml_files(role_dir / "tasks") + _yaml_files(role_dir / "handlers"):
        doc, problem = load_yaml(path)
        if problem is None and isinstance(doc, list):
            _loops_in(doc, _rel(root, path), out)
    return out


class _Bind(NamedTuple):
    """A name bound by a task's `vars:` (or an include's `apply: vars:`): its parsed value, the
    name the value is when it is that name alone, and, when the task includes other tasks, the
    file it names (None when it names no file or a role) with the file that holds the task."""

    key: str
    trees: list[nodes.Template]
    bare: str | None
    rel: str
    name: str
    includes: bool
    target: str | None
    holder: Path


def _include_target(args: object) -> str | None:
    """The file an include_tasks or import_tasks names: its free-form text, or its file key."""
    if isinstance(args, str):
        return args.strip()
    named = _dict(args).get("file", _dict(args).get("_raw_params"))
    return named.strip() if isinstance(named, str) else None


def _binds_in(items: list[object], path: Path, rel: str, out: list[_Bind]) -> None:
    for task in items:
        if not isinstance(task, dict):
            continue
        kinds = [k for k in INCLUDE_NAMES if k in task]
        args = task[kinds[0]] if kinds else None
        file_include = bool(kinds) and kinds[0].rsplit(".", 1)[-1].endswith("_tasks")
        scopes = [task.get("vars"), _dict(_dict(args).get("apply")).get("vars")]
        for scope in scopes:
            for key, value in _dict(scope).items():
                if not isinstance(key, str):
                    continue
                trees = [
                    t for t in (_parse(s, rel, "a vars value", []) for s in _strings(value)) if t
                ]
                bare = _bare_name(trees[0]) if isinstance(value, str) and len(trees) == 1 else None
                target = _include_target(args) if file_include else None
                out.append(
                    _Bind(
                        key,
                        trees,
                        bare,
                        rel,
                        str(task.get("name", "(unnamed)")),
                        bool(kinds),
                        target,
                        path,
                    )
                )
        for key in CONTAINER_KEYS & task.keys():
            inner = task[key]
            if isinstance(inner, list):
                _binds_in(inner, path, rel, out)


def _task_paths(role_dir: Path) -> list[Path]:
    return _yaml_files(role_dir / "tasks") + _yaml_files(role_dir / "handlers")


def _binds(root: Path, role_dir: Path) -> list[_Bind]:
    out: list[_Bind] = []
    for path in _task_paths(role_dir):
        doc, problem = load_yaml(path)
        if problem is None and isinstance(doc, list):
            _binds_in(doc, path, _rel(root, path), out)
    return out


def _followed(bind: _Bind, role_dir: Path) -> bool:
    """Whether the file an include names is one of the task files the check reads: a literal
    path, looked for beside the including file and then in the role's tasks directory, as
    Ansible does. A templated name, a missing file and a role are not followed."""
    if bind.target is None or "{{" in bind.target or "{%" in bind.target:
        return False
    known = {p.resolve() for p in _task_paths(role_dir)}
    candidates = (bind.holder.parent / bind.target, role_dir / "tasks" / bind.target)
    return any(c.resolve() in known for c in candidates)


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
        for path in _yaml_files(role_dir / sub):
            if path.parent != role_dir / sub:
                continue
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
    role_binds = [b for b in binds if b.includes and b.key in origin]
    for bind in role_binds:
        if not _followed(bind, role_dir):
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
    rel: str,
    name: str,
    findings: list[str],
    partial: Partial,
) -> set[str]:
    """The variables a task names in any position that prints or uses a value. The expression
    keywords are left out: they print only their expression, and the refusal asserts are read
    for their coded messages. A secret named in an assert's fail message still counts."""
    body = {k: v for k, v in task.items() if k not in EXPRESSION_KEYS and k not in CONTAINER_KEYS}
    for key in ASSERT_NAMES & body.keys():
        args = body[key]
        if isinstance(args, dict):
            body[key] = {k: v for k, v in args.items() if k != "that"}
    scoped = body.get("vars")
    if isinstance(scoped, dict):
        # A name bound by `vars:` is set, not read: only what it is set to can leak.
        body["vars"] = list(scoped.values())
    refs: set[str] = set()
    for text in _strings(body):
        refs |= _names_in(text, rel, f"task '{name}'", findings, partial)
    return refs


def _template_refs(
    task: dict[str, object],
    role_dir: Path,
    rel: str,
    name: str,
    findings: list[str],
    partial: Partial,
) -> set[str]:
    refs: set[str] = set()
    for key in TEMPLATE_NAMES & task.keys():
        src = _dict(task[key]).get("src")
        path = role_dir / "templates" / src if isinstance(src, str) else None
        if path is None or not path.is_file():
            findings.append(f"R1 {rel}: task '{name}' names a template that cannot be read")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            findings.append(f"R1 {rel}: task '{name}' names a template that cannot be read")
            continue
        refs |= _names_in(text, rel, f"template of task '{name}'", findings, partial)
    return refs


def _chain(name: str, origin: dict[str, set[str]]) -> str:
    if origin[name] == {name}:
        return name
    return f"{name} (secret through {', '.join(sorted(origin[name]))})"


def _judge(
    refs: set[str],
    task: dict[str, object],
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
    if DIFF_NAMES.intersection(task.keys()) and diff is not False:
        findings.append(f"R1 {rel}: task '{name}' writes {named} and must set diff: false (ANS-16)")


def _walk(
    items: list[object],
    role_dir: Path,
    taint: tuple[dict[str, set[str]], Partial],
    rel: str,
    inherited_no_log: object,
    inherited_diff: object,
    findings: list[str],
) -> int:
    origin, partial = taint
    count = 0
    for task in items:
        if not isinstance(task, dict):
            findings.append(f"R1 {rel}: an entry is not a task mapping")
            continue
        name = str(task.get("name", "(unnamed)"))
        no_log = task["no_log"] if "no_log" in task else inherited_no_log
        diff = task["diff"] if "diff" in task else inherited_diff
        refs = _task_refs(task, rel, name, findings, partial)
        if CONTAINER_KEYS.intersection(task.keys()):
            _judge(refs, task, no_log, diff, name, rel, origin, findings)
            for key in CONTAINER_KEYS.intersection(task.keys()):
                inner = task[key]
                if not isinstance(inner, list):
                    findings.append(f"R1 {rel}: task '{name}' has a {key} that is not a list")
                    continue
                count += _walk(inner, role_dir, taint, rel, no_log, diff, findings)
            continue
        count += 1
        refs |= _template_refs(task, role_dir, rel, name, findings, partial)
        _judge(refs, task, no_log, diff, name, rel, origin, findings)
    return count


def _r1(root: Path, findings: list[str]) -> int:
    """R1 over every role and pattern that declares a secret. Returns the tasks checked."""
    checked = 0
    for role_dir in _role_dirs(root):
        whole, partial = _seeds_of(root, role_dir, findings)
        if not whole and not partial:
            continue
        taint = _taint(root, role_dir, whole, partial, findings)
        task_files = _yaml_files(role_dir / "tasks") + _yaml_files(role_dir / "handlers")
        for name in LOADER_SEEDS.get(role_dir.name, ()):
            if not any(name in path.read_text(encoding="utf-8") for path in task_files):
                findings.append(
                    f"R1 {_rel(root, role_dir)}: the loader variable {name} is named by no task, "
                    "so the check would see nothing"
                )
        for path in task_files:
            rel = _rel(root, path)
            doc, problem = load_yaml(path)
            if problem is not None:
                findings.append(f"R1 {rel}: {problem}")
                continue
            if doc is None:
                continue
            if not isinstance(doc, list):
                findings.append(f"R1 {rel}: must be a list of tasks")
                continue
            checked += _walk(doc, role_dir, taint, rel, None, None, findings)
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


def check(root: Path = ROOT) -> list[str]:
    """One finding per broken rule, or an empty list when the tree passes."""
    findings: list[str] = []
    _r1(root, findings)
    resolved = _rows(root, findings)
    _r3(root, resolved, findings)
    return list(dict.fromkeys(findings))


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
