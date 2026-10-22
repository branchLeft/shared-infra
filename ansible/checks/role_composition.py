"""Find where a role composes another role, and what the ANS-12 amendment lets it do.

The conditions are listed once, here; the README of restart_stamp states the same list and a
test compares the two (restart_stamp/README.md, "Composition (ANS-12)").
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from amendment_citation import StandardsApi, StandardsReadError, citation_problems
from role_tasks import (
    ROLE_MODULES,
    TASK_FILE_MODULES,
    included_role,
    mapping_at,
    options_without_default,
    own_file,
    parsed_tasks,
    parsed_tasks_with_inputs,
    role_call,
    task_modules,
    var_names,
)

# Held by the gate: a mechanical test fails the pull request that breaks one.
CONDITIONS = (
    "It is included with `include_role`, never `import_role`.",
    "It is named by a path built from the caller's own `role_path`, not by a bare name.",
    "It declares its inputs in `meta/argument_specs.yml`, and the call gives every "
    "top-level required input of the entry point it names and no input that entry point does "
    "not declare.",
    "Every option of the entry point it names, an option of a list element or of a dictionary "
    "included, is `required: true` or has a `default` key in `meta/argument_specs.yml`: the key "
    "counts whatever its value, null included, and a default found only in `defaults/main.yml`, "
    "in group vars or in the caller's vars does not.",
    "It includes no role itself, and no role's `meta/main.yml` carries `dependencies`.",
    "Its README names the roles that call it.",
    "A role's `include_tasks` and `import_tasks` name a YAML file that exists under their own "
    "role's `tasks/` or `handlers/` (with links followed), as a literal path.",
)
# Held by review only: nothing in a task file shows any of them.
REVIEW_ONLY = (
    "It is a cross-cutting capability with one reason to change, not a service: "
    "it configures no service and owns no host state.",
    "It computes and records only.",
    "Every variable its tasks read is an input it declares: the gate reads what a call gives, "
    "not what a task reads.",
    "The value an omitted optional input takes when the role runs (in `defaults/main.yml`, or "
    "in the role's tasks for an option of a list element) equals the `default` its "
    "`argument_specs` entry declares: Ansible does not apply the declared default, and the gate "
    "reads the spec and the call.",
    "Each list element a call passes gives the required options of its element: the gate reads "
    "the names of the vars a call sets, not what is inside the list.",
)

NO_CITATION = (
    "a role includes another role, which ANS-12 leaves to an amendment, and {citation} "
    "{state}. Merge the amendment in the standards repository, then record one line: "
    "https://github.com/branchLeft/standards/pull/<number> merged <40-hex merge commit>"
)


def including_roles(bases: tuple[Path, ...]) -> dict[str, list[str]]:
    """Return each role that has a task including another role, with the files of those tasks."""
    found: dict[str, list[str]] = {}
    for base in bases:
        for role in role_dirs(base):
            files = including_files(role)
            if files:
                found[f"{base.name}/{role.name}"] = files
    return found


def including_files(role: Path) -> list[str]:
    """Return the task files of a role that have a task including or importing a role."""
    return sorted(
        {
            name
            for name, task in parsed_tasks(role)
            if any(module in ROLE_MODULES for module, _ in task_modules(task))
        }
    )


def role_dirs(base: Path) -> list[Path]:
    """Return the role directories under a base, none when the base is not there."""
    return sorted(path for path in base.iterdir() if path.is_dir()) if base.is_dir() else []


def call_problems(
    role: Path,
    where: str,
    task: Mapping[str, object],
    arguments: object,
    inherited: frozenset[str],
) -> list[str]:
    """Return how an include_role of ``role`` breaks the conditions of a capability role.

    ``inherited`` is the names of the vars that reach the call from above it (the blocks round
    it and the includes of its file): they reach the callee as the call's own vars do.
    """
    name, entry = role_call(arguments)
    target = included_role(role, name)
    if target is None:
        return [
            f"{where}: the role it includes ({name!r}) cannot be resolved through this role's "
            "vars/ and defaults/ to a path built from role_path"
        ]
    found: list[str] = []
    if not target.by_path:
        found.append(f"{where}: {target.name} is named bare, not by a path built from role_path")
    callee = role.parent / target.name
    if not callee.is_dir():
        return [*found, f"{where}: {target.name} is not a role beside {role.name}"]
    options = mapping_at(callee / "meta" / "argument_specs.yml", "argument_specs", entry)
    if not options:
        found.append(f"{where}: {target.name} has no argument_specs for its entry point {entry}")
    inputs = options.get("options")
    declared = {str(key) for key in (inputs if isinstance(inputs, Mapping) else [])}
    required = {
        str(key)
        for key, spec in (inputs.items() if isinstance(inputs, Mapping) else [])
        if isinstance(spec, Mapping) and spec.get("required") is True
    }
    given = set(var_names(task)) | inherited
    missing = required - given
    if missing:
        found.append(f"{where}: the call does not give required input(s) {sorted(missing)}")
    # Only the entry point the call names is read: another entry point of the same role, never
    # called, is not (README, "Composition (ANS-12)").
    undefaulted = options_without_default(inputs)
    if undefaulted:
        found.append(
            f"{where}: the entry point {entry} of {target.name} declares optional input(s) "
            f"{undefaulted} with no `default` in its meta/argument_specs.yml"
        )
    # An entry with no argument_specs at all is reported above; here the entry exists and the
    # call passes something it does not declare, whether it declares other inputs or none.
    undeclared = given - declared
    if options and undeclared:
        found.append(
            f"{where}: the call gives input(s) {sorted(undeclared)} that the entry point "
            f"{entry} of {target.name} does not declare"
        )
    if including_files(callee):
        found.append(f"{where}: {target.name} includes a role itself")
    readme = callee / "README.md"
    named = readme.is_file() and re.search(
        rf"(?<![A-Za-z0-9_]){re.escape(role.name)}(?![A-Za-z0-9_])",
        readme.read_text(encoding="utf-8"),
    )
    if not named:
        found.append(f"{where}: the README of {target.name} does not name {role.name}")
    return found


def composition_problems(bases: tuple[Path, ...]) -> list[str]:
    """Return every place a role composes another role in a way a capability role does not allow."""
    found: list[str] = []
    for base in bases:
        for role in role_dirs(base):
            label = f"{base.name}/{role.name}"
            if mapping_at(role / "meta" / "main.yml").get("dependencies"):
                found.append(f"{label}: meta/main.yml carries dependencies")
            for name, task, inherited in parsed_tasks_with_inputs(role):
                where = f"{label} ({name})"
                for module, arguments in task_modules(task):
                    if module in TASK_FILE_MODULES and not own_file(role, arguments):
                        found.append(
                            f"{where}: {module} names a file that is not a literal path "
                            "in this role"
                        )
                    elif module == "import_role":
                        found.append(f"{where}: import_role is never used to compose roles")
                    elif module == "include_role":
                        found.extend(call_problems(role, where, task, arguments, inherited))
    return found


def readme_conditions(readme: str, marker: str) -> list[str]:
    """Return the numbered items the README lists between ``<!-- marker -->`` and its close."""
    section = re.search(rf"<!-- {marker} -->(.*?)<!-- /{marker} -->", readme, re.DOTALL)
    body = section.group(1) if section else ""
    items = re.findall(r"^\d+\. (.+(?:\n[ ]{3}.+)*)", body, re.MULTILINE)
    return [" ".join(item.split()) for item in items]


def run_gate(
    bases: tuple[Path, ...], citation: Path, api: StandardsApi, in_ci: bool
) -> tuple[list[str], str | None]:
    """Run the citation gate and say what a failed lookup means: red in CI, skipped elsewhere.

    Returns the problems and, when the lookup could not be made outside CI, the reason the
    run is skipped, which the caller prints. In CI a lookup that fails is a problem.
    """
    try:
        return citation_gate(bases, citation, api), None
    except StandardsReadError as error:
        if in_ci:
            return [f"the cited standards pull request could not be read in CI: {error}"], None
        return (
            [],
            f"the standards repository could not be read, so the citation is not checked ({error})",
        )


def citation_gate(bases: tuple[Path, ...], citation: Path, api: StandardsApi) -> list[str]:
    """Return what stops a merge: a role includes a role, and the amendment is not cited.

    Raises StandardsReadError when a citation is there and the standards repository cannot be read.
    """
    roles = including_roles(bases)
    if not roles:
        return []
    shown = ", ".join(f"{role} ({', '.join(files)})" for role, files in roles.items())
    if not citation.is_file():
        return [f"{shown}: " + NO_CITATION.format(citation=citation.name, state="is missing")]
    return [
        f"{shown}: {problem}"
        for problem in citation_problems(citation.read_text(encoding="utf-8"), api)
    ]
