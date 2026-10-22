"""Hold the default a role runs with to the default its argument_specs declares.

What is read and what is not: restart_stamp/README.md, "Composition (ANS-12)".
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, TemplateSyntaxError, nodes
from role_tasks import (
    ROLE_YAML_AREAS,
    load_yaml,
    mapping_at,
    option_specs,
    reached_from,
    role_files,
)

JINJA = Environment(autoescape=True)  # only ever parses: nothing is rendered
DEFAULT_FILTERS = frozenset({"default", "d"})
# The keys whose value Ansible reads as an expression with no braces round it.
BARE_KEYS = frozenset({"when", "that", "changed_when", "failed_when", "until", "break_when"})
UNREADABLE = object()


@dataclass(frozen=True)
class Option:
    """An option of a list element that declares a default, and where its copies are looked for."""

    where: str
    entry: str
    list_name: str
    attributes: tuple[str, ...]
    declared: object


def declared_defaults(role: Path) -> list[tuple[str, str, object]]:
    """Return the entry point, the option path and the default of each option that has one."""
    specs = mapping_at(role / "meta" / "argument_specs.yml", "argument_specs")
    found: list[tuple[str, str, object]] = []
    for entry, spec in specs.items():
        options = spec.get("options") if isinstance(spec, Mapping) else None
        for path, option in option_specs(options):
            if isinstance(option, Mapping) and "default" in option:
                found.append((str(entry), path, option["default"]))
    return found


def templates_in(data: object, bare: bool = False) -> Iterator[str]:
    """Yield each string of a parsed YAML value that Jinja reads, a bare expression in braces."""
    if isinstance(data, str):
        if any(mark in data for mark in ("{{", "{%", "{#")):
            yield data
        elif bare:
            yield "{{ " + data + " }}"
    elif isinstance(data, Mapping):
        for key, value in data.items():
            yield from templates_in(value, str(key) in BARE_KEYS)
    elif isinstance(data, list):
        for item in data:
            yield from templates_in(item, bare)


def parsed_templates(path: Path) -> tuple[list[nodes.Template], list[str]]:
    """Return the parsed templates of a YAML file, and why each one that did not parse did not."""
    found: list[nodes.Template] = []
    errors: list[str] = []
    for text in templates_in(load_yaml(path)):
        try:
            found.append(JINJA.parse(text))
        except TemplateSyntaxError as error:
            errors.append(f"{error.message} (line {error.lineno})")
    return found, errors


def attribute_chain(node: nodes.Node | None) -> tuple[nodes.Node | None, tuple[str, ...]]:
    """Split ``a.b['c']`` into ``a`` and ``('b', 'c')``: both spellings read an attribute."""
    attributes: list[str] = []
    while True:
        if isinstance(node, nodes.Getattr):
            attributes.append(node.attr)
        elif (
            isinstance(node, nodes.Getitem)
            and isinstance(node.arg, nodes.Const)
            and isinstance(node.arg.value, str)
        ):
            attributes.append(node.arg.value)
        else:
            return node, tuple(reversed(attributes))
        node = node.node


def dotted(node: nodes.Node) -> str | None:
    """Return a name and the attributes read from it as one dotted word, else None."""
    base, attributes = attribute_chain(node)
    return ".".join((base.name, *attributes)) if isinstance(base, nodes.Name) else None


def elements_of(loop: nodes.For, list_name: str) -> frozenset[str]:
    """Return the name a ``for`` gives each element of the list, none for any other loop."""
    source: nodes.Node = loop.iter
    while isinstance(source, nodes.Filter) and source.node is not None:
        source = source.node
    if isinstance(loop.target, nodes.Name) and dotted(source) == list_name:
        return frozenset({loop.target.name})
    return frozenset()


def defaults_in(
    node: nodes.Node, list_name: str, elements: frozenset[str] = frozenset()
) -> Iterator[tuple[nodes.Filter, frozenset[str]]]:
    """Yield each ``default`` filter of a template with the element names in scope round it."""
    if isinstance(node, nodes.Filter) and node.name in DEFAULT_FILTERS:
        yield node, elements
    if isinstance(node, nodes.For):
        inner = elements | elements_of(node, list_name)
        yield from defaults_in(node.iter, list_name, elements)
        for part in (*node.body, node.test):
            if part is not None:
                yield from defaults_in(part, list_name, inner)
        for part in node.else_:
            yield from defaults_in(part, list_name, elements)
        return
    for child in node.iter_child_nodes():
        yield from defaults_in(child, list_name, elements)


def literal(node: nodes.Node) -> object:
    """Return the value of a Jinja literal (a word, integer or string), else UNREADABLE."""
    if isinstance(node, nodes.Neg) and isinstance(node.node, nodes.Const):
        value = node.node.value
        return -value if isinstance(value, int) and not isinstance(value, bool) else UNREADABLE
    if isinstance(node, nodes.Const) and (
        node.value is None or isinstance(node.value, (bool, int, str))
    ):
        return node.value
    return UNREADABLE


def running_value(call: nodes.Filter) -> object:
    """Return the value a ``default(...)`` gives: its one argument, if that is a literal."""
    if len(call.args) != 1 or call.kwargs or call.dyn_args or call.dyn_kwargs:
        return UNREADABLE
    return literal(call.args[0])


def shown(value: object) -> str:
    """Return a value as Jinja writes it, or say that this reading could not place it."""
    if value is UNREADABLE:
        return "a default this check cannot read"
    if value is None:
        return "default(none)"
    return f"default({str(value).lower() if isinstance(value, bool) else repr(value)})"


def same_value(running: object, declared: object) -> bool:
    """Say whether two values are one: of the same type, so ``0`` is not ``false``."""
    return running is not UNREADABLE and type(running) is type(declared) and running == declared


def copy_problems(
    option: Option,
    parsed: Mapping[str, list[nodes.Template]],
    reached: set[str],
    held: set[str],
) -> list[str]:
    """Return what is wrong with each ``default`` for an option, in every file the role holds.

    ``held`` is the files any entry point that declares this option reaches: held to that one.
    """
    spelled = ".".join(option.attributes)
    found: list[str] = []
    seen = 0
    for name, templates in parsed.items():
        for template in templates:
            for call, elements in defaults_in(template, option.list_name):
                base, chain = attribute_chain(call.node)
                if chain != option.attributes:
                    continue
                if name not in reached:
                    if name not in held:
                        found.append(
                            f"{option.where}: {name} gives `.{spelled}` a default, and "
                            f"tasks/{option.entry}.yml does not reach that file"
                        )
                elif not (isinstance(base, nodes.Name) and base.name in elements):
                    found.append(
                        f"{option.where}: {name} gives `.{spelled}` a default on something "
                        f"other than an element of {option.list_name}"
                    )
                else:
                    seen += 1
                    running = running_value(call)
                    if not same_value(running, option.declared):
                        found.append(
                            f"{option.where}: meta/argument_specs.yml declares default "
                            f"{option.declared!r} but {name} runs with {shown(running)}"
                        )
    if not seen:
        found.append(
            f"{option.where}: no `<element>.{spelled} | default(...)` in "
            f"tasks/{option.entry}.yml or a file it includes, so the value it runs with is "
            "not shown"
        )
    return found


def running_default_problems(role: Path) -> list[str]:
    """Return each option whose running default is not the one its spec declares.

    What is read, and what is reported instead of passed, is in the README of restart_stamp.
    """
    declared = declared_defaults(role)
    if not declared:
        return []
    parsed: dict[str, list[nodes.Template]] = {}
    problems: list[str] = []
    for name, file in role_files(role, ROLE_YAML_AREAS):
        parsed[name], errors = parsed_templates(file)
        problems.extend(f"{role.name} {name}: a template cannot be parsed: {e}" for e in errors)
    reach = {
        entry: {name for name, _ in reached_from(role, role / "tasks" / f"{entry}.yml")}
        for entry, _, _ in declared
    }
    for entry, path, value in declared:
        where = f"{role.name} {path} ({entry})"
        list_name, _, name = path.partition("[].")
        if not name:
            problems.append(
                f"{where}: declares a default but is not an option of a list element, and this "
                "check reads only the tasks of the entry point, where those run"
            )
        elif "[]" in name:
            problems.append(f"{where}: declares a default in a list inside a list element")
        else:
            held = set().union(*(reach[e] for e, p, _ in declared if p == path))
            option = Option(where, entry, list_name, tuple(name.split(".")), value)
            problems.extend(copy_problems(option, parsed, reach[entry], held))
    return problems
