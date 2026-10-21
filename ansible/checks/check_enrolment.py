"""Check the host playbooks under the gated pull.

Rules R0 to R8, and what each one does not see, are in ansible/checks/README.md. A
failure names the rule and the file. This check catches a protected key set outside
its one file. It does not judge a role edit: nothing here gates one (see checks/README.md).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
SIGNER_KEY = "pull_trigger_signers"
REMOTE_KEY = "pull_trigger_remote_url"
PLAYBOOK_KEY = "pull_trigger_playbook"
PLAYBOOKS_KEY = "pull_trigger_playbooks"
HOST_KEY = "enrolled_host"
CONFIG_VAR = "pull_trigger_config"
DERIVATION_KEYS = (REMOTE_KEY, PLAYBOOK_KEY, PLAYBOOKS_KEY)
PROTECTED_KEYS = frozenset((SIGNER_KEY, HOST_KEY, *DERIVATION_KEYS))
VARS_SUFFIXES = frozenset((".yml", ".yaml", ".json", ""))
LOADED_DIRS = frozenset(
    (
        "vars",
        "defaults",
        "group_vars",
        "host_vars",
        "tasks",
        "meta",
        "handlers",
        "playbooks",
        "trust",
        "inventories",
    )
)
TASK_SUFFIXES = (".yml", ".yaml")
TREES = ("playbooks", "trust")
README_EXCEPTIONS = frozenset(("playbooks/README.md", "trust/README.md"))
INCLUDE_VARS = frozenset(
    ("include_vars", "ansible.builtin.include_vars", "ansible.legacy.include_vars")
)
TASK_FILE_LOADERS = frozenset(
    (
        "include",
        "include_tasks",
        "import_tasks",
        "import_playbook",
        "ansible.builtin.include",
        "ansible.builtin.include_tasks",
        "ansible.builtin.import_tasks",
        "ansible.builtin.import_playbook",
        "ansible.legacy.include_tasks",
        "ansible.legacy.import_tasks",
        "ansible.legacy.import_playbook",
    )
)
ROLE_LOADERS = frozenset(
    (
        "include_role",
        "import_role",
        "ansible.builtin.include_role",
        "ansible.builtin.import_role",
        "ansible.legacy.include_role",
        "ansible.legacy.import_role",
    )
)
LOADER_MODULES = INCLUDE_VARS | TASK_FILE_LOADERS | ROLE_LOADERS
ROLE_SUBFILE_KEYS = ("tasks_from", "vars_from", "defaults_from", "handlers_from")
ACTION_KEYS = ("action", "local_action")
ROLE_LISTS = frozenset(("roles", "dependencies"))
ENROLLED_ROLE = "pull_trigger"
SHARED_INCLUDES = ("pull_trigger_common.yml", "refuse_other_hosts.yml", "require_signers.yml")
COMMON_INCLUDE = "{{ playbook_dir }}/includes/pull_trigger_common.yml"
REFUSE_TASKS = "includes/refuse_other_hosts.yml"
SIGNER_TASKS = "includes/require_signers.yml"
DERIVED_PLAYBOOK = "ansible/playbooks/{{ enrolled_host }}.yml"
REMOTE_URL = "https://github.com/branchLeft/shared-infra.git"
SIGNERS_EXPR = "{{ pull_trigger_signers }}"
REMOTE_EXPR = "{{ pull_trigger_remote_url }}"
CONFIG_DEST = "{{ pull_trigger_config_path }}"
CONFIG_CONTENT = "{{ pull_trigger_config | ansible.builtin.to_nice_json }}\n"
CONFIG_MENTION = re.compile(r"pull_trigger_config(\b|_path\b)")
REFUSE_ASSERT = [
    "ansible_play_hosts_all | length == 1",
    "inventory_hostname in ['localhost', enrolled_host]",
]
SIGNER_ASSERT = ["pull_trigger_signers | length > 0"]
EXPECTED_ROLES = [
    {
        "role": "../roles/ansible_runtime",
        "vars": {"ansible_runtime_requirements_src": "{{ playbook_dir }}/../requirements.txt"},
    },
    {"role": "../roles/pull_trigger"},
]
EXPECTED_COMMON = {
    REMOTE_KEY: REMOTE_URL,
    PLAYBOOK_KEY: DERIVED_PLAYBOOK,
    PLAYBOOKS_KEY: ["{{ pull_trigger_playbook }}"],
}


def _load(path: Path, findings: list[str], label: str) -> object:
    """The one YAML reader, for every rule and for R6. A missing file is reported by its own
    rule, not here. An unparseable file is a finding under the caller's label."""
    if not path.is_file():
        return None
    try:
        doc: object = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as error:
        findings.append(f"{label}: cannot be read as YAML: {error}")
        return None
    return doc


def _mapping(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    return {}


def _plays(doc: object) -> list[dict[str, object]]:
    if not isinstance(doc, list):
        return []
    return [_mapping(play) for play in doc if isinstance(play, dict)]


def _role_names(play: dict[str, object]) -> list[str]:
    roles = play.get("roles")
    if not isinstance(roles, list):
        return []
    names: list[str] = []
    for entry in roles:
        name: object = entry.get("role") if isinstance(entry, dict) else entry
        if isinstance(name, str):
            names.append(name)
    return names


def _enrolled(play: dict[str, object]) -> bool:
    return any(Path(name).name == ENROLLED_ROLE for name in _role_names(play))


def _exact_include(task: object, target: str) -> bool:
    """True when the task is a name and one include of the target, and nothing else."""
    if not isinstance(task, dict):
        return False
    for key in ("ansible.builtin.include_tasks", "include_tasks"):
        if key in task:
            return set(task) == {"name", key} and task[key] == target
    return False


def _check_enrolled(stem: str, plays: list[dict[str, object]], findings: list[str]) -> None:
    label = f"R2 {stem}.yml"
    if len(plays) != 1:
        findings.append(f"{label}: expected one play, found {len(plays)}")
        return
    play = plays[0]
    if play.get("hosts") != "all":
        findings.append(f"{label}: hosts must be all")
    variables = _mapping(play.get("vars"))
    if variables.get(HOST_KEY) != stem:
        findings.append(f"{label}: vars.{HOST_KEY} must be {stem}")
    expected_files = [COMMON_INCLUDE, f"{{{{ playbook_dir }}}}/../trust/{stem}.yml"]
    if play.get("vars_files") != expected_files:
        findings.append(f"{label}: vars_files must be exactly {expected_files}")
    if play.get("roles") != EXPECTED_ROLES:
        findings.append(f"{label}: roles must be exactly the runtime entry, then the bare trigger")
    pre_tasks = play.get("pre_tasks")
    expected_pre = [REFUSE_TASKS, SIGNER_TASKS]
    if not (
        isinstance(pre_tasks, list)
        and len(pre_tasks) == len(expected_pre)
        and all(
            _exact_include(task, target)
            for task, target in zip(pre_tasks, expected_pre, strict=True)
        )
    ):
        findings.append(f"{label}: pre_tasks must be exactly {REFUSE_TASKS}, then {SIGNER_TASKS}")


def _check_gate(path: Path, that: list[str], findings: list[str]) -> None:
    """R0: an include holds one task, its assert, and that assert's keys and expressions."""
    label = f"R0 playbooks/includes/{path.name}"
    doc = _load(path, findings, label)
    tasks = doc if isinstance(doc, list) else []
    if len(tasks) != 1 or not isinstance(tasks[0], dict):
        findings.append(f"{label}: must hold exactly one task")
        return
    task = _mapping(tasks[0])
    module = next((key for key in ("ansible.builtin.assert", "assert") if key in task), None)
    if module is None or set(task) != {"name", module}:
        findings.append(f"{label}: the one task must be a name and its assert, nothing else")
        return
    if _mapping(task[module]).get("that") != that:
        findings.append(f"{label}: assert that must be exactly {that}")


def _check_gates(includes: Path, findings: list[str]) -> None:
    gates = {"refuse_other_hosts.yml": REFUSE_ASSERT, "require_signers.yml": SIGNER_ASSERT}
    for name, that in gates.items():
        if (includes / name).is_file():
            _check_gate(includes / name, that, findings)


def _check_derivation(includes: Path, findings: list[str]) -> None:
    common = _mapping(
        _load(includes / "pull_trigger_common.yml", findings, "R3 pull_trigger_common.yml")
    )
    if common != EXPECTED_COMMON:
        findings.append(
            f"R3 pull_trigger_common.yml: must hold exactly {REMOTE_KEY} {REMOTE_URL!r}, "
            f"and the playbook derivation from enrolled_host, and no other key"
        )


def _check_trust_file(path: Path, findings: list[str]) -> None:
    doc = _mapping(_load(path, findings, f"R5 trust/{path.name}"))
    if set(doc) != {SIGNER_KEY} or not isinstance(doc.get(SIGNER_KEY), list):
        findings.append(f"R5 trust/{path.name}: must hold exactly {SIGNER_KEY}, as a list")


def _names_config(node: object) -> bool:
    """True when a task mentions the config var or the config path anywhere in its text."""
    if isinstance(node, dict):
        return any(_names_config(key) or _names_config(value) for key, value in node.items())
    if isinstance(node, list):
        return any(_names_config(item) for item in node)
    return isinstance(node, str) and CONFIG_MENTION.search(node) is not None


def _check_writer(ansible: Path, findings: list[str]) -> None:
    """R8: exactly one task in the role writes the config, pinned to the shared values."""
    tasks_dir = ansible / "roles" / ENROLLED_ROLE / "tasks"
    writers: list[tuple[str, dict[str, object]]] = []
    for path in sorted(tasks_dir.rglob("*")):
        if not path.is_file() or path.suffix not in TASK_SUFFIXES:
            continue
        where = f"ansible/{path.relative_to(ansible).as_posix()}"
        doc = _load(path, findings, f"R8 {where}")
        for task in doc if isinstance(doc, list) else []:
            if _names_config(task):
                writers.append((where, _mapping(task)))
    if len(writers) != 1:
        findings.append(
            f"R8 roles/{ENROLLED_ROLE}/tasks: found {len(writers)} config writers, want 1"
        )
        return
    where, task = writers[0]
    module = next((key for key in ("ansible.builtin.copy", "copy") if key in task), None)
    args = _mapping(task.get(module)) if module else {}
    config = _mapping(_mapping(task.get("vars")).get(CONFIG_VAR))
    if module is None or args.get("dest") != CONFIG_DEST or args.get("content") != CONFIG_CONTENT:
        findings.append(
            f"R8 {where}: the config writer must copy {CONFIG_CONTENT!r} to {CONFIG_DEST}"
        )
    if config.get("signers") != SIGNERS_EXPR or config.get("remote_url") != REMOTE_EXPR:
        findings.append(
            f"R8 {where}: the config writer's signers and remote_url must be "
            f"{SIGNERS_EXPR} and {REMOTE_EXPR}, not a literal"
        )


def _allowed_in(relative: str) -> frozenset[str]:
    """Return the protected keys a file may set, by its path under ansible/."""
    if relative.startswith("trust/"):
        return frozenset((SIGNER_KEY,))
    if relative == "playbooks/includes/pull_trigger_common.yml":
        return frozenset(DERIVATION_KEYS)
    return frozenset()


ROLE_ROOTS = ("roles", "patterns")


def _is_scanned(relative: Path) -> bool:
    """A role's or pattern's molecule scenarios and argument specs are fixtures, not config."""
    parts = relative.parts
    if len(parts) < 3 or parts[0] not in ROLE_ROOTS:
        return True
    if parts[2] == "molecule":
        return False
    return parts[2:] != ("meta", "argument_specs.yml") or len(parts) != 4


def _inside(path: Path, ansible: Path) -> Path | None:
    try:
        return path.relative_to(ansible)
    except ValueError:
        return None


def _literal(value: object) -> bool:
    return isinstance(value, str) and "{{" not in value and "{%" not in value


def _task_target_ok(value: object, base: Path, ansible: Path) -> bool:
    """A task-loaded file must be a literal .yml path that R6 reads."""
    if not _literal(value):
        return False
    candidate = (base / str(value)).resolve()
    relative = _inside(candidate, ansible)
    return (
        relative is not None
        and candidate.suffix in TASK_SUFFIXES
        and candidate.is_file()
        and _is_scanned(relative)
    )


def _role_ok(value: object, base: Path, ansible: Path) -> bool:
    """A role must be a literal path under ansible/ that holds no molecule scenario."""
    if not _literal(value) or not isinstance(value, str):
        return False
    candidate = (base / value if "/" in value else ansible / "roles" / value).resolve()
    relative = _inside(candidate, ansible)
    return relative is not None and "molecule" not in relative.parts


def _action_module(value: object) -> str:
    """The module an action or local_action names, in its string or mapping form."""
    if isinstance(value, str):
        words = value.split()
        return words[0] if words else ""
    if isinstance(value, dict):
        return str(value.get("module", ""))
    return ""


def _assigns_protected(text: str) -> str | None:
    """A protected key assigned inside a string argument, as in set_fact 'key=value'."""
    for key in sorted(PROTECTED_KEYS):
        if re.search(rf"(?<![\w.]){re.escape(key)}\s*=", text):
            return key
    return None


def _scan(
    node: object,
    base: Path,
    ansible: Path,
    where: str,
    allowed: frozenset[str],
    out: list[str],
) -> None:
    """Record each protected key and each loader R6 cannot read, anywhere in the document."""
    if isinstance(node, list):
        for item in node:
            _scan(item, base, ansible, where, allowed, out)
        return
    if isinstance(node, str):
        key = _assigns_protected(node)
        if key is not None and key not in allowed:
            out.append(f"R6 {where}: sets {key} in a string argument, which R6 cannot read")
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        name = str(key)
        if "{{" in name or "{%" in name:
            out.append(f"R6 {where}: has a templated key, which R6 cannot read")
        elif name in PROTECTED_KEYS and name not in allowed:
            out.append(f"R6 {where}: sets {name}, which only its owner's file may set")
        elif name in INCLUDE_VARS:
            out.append(f"R6 {where}: loads variables with {name}, which R6 cannot read")
        elif name == "vars_files":
            out.append(f"R6 {where}: loads variables with vars_files outside an enrolled play")
        elif name in TASK_FILE_LOADERS and not _task_target_ok(value, base, ansible):
            out.append(f"R6 {where}: {name} loads {value!r}, which R6 cannot read")
        elif name in ROLE_LOADERS:
            args = _mapping(value)
            if not _role_ok(args.get("name"), base, ansible) or any(
                sub in args for sub in ROLE_SUBFILE_KEYS
            ):
                out.append(f"R6 {where}: {name} names a role or a file R6 cannot read")
        elif name in ACTION_KEYS and _action_module(value) in LOADER_MODULES:
            out.append(f"R6 {where}: {name} runs {_action_module(value)}, which R6 cannot read")
        elif name in ROLE_LISTS and isinstance(value, list):
            for entry in value:
                target = _mapping(entry).get("role") if isinstance(entry, dict) else entry
                if not _role_ok(target, base, ansible):
                    out.append(f"R6 {where}: {name} names {target!r}, which R6 cannot read")
        _scan(value, base, ansible, where, allowed, out)


def _scan_playbook(doc: object, path: Path, ansible: Path, where: str, out: list[str]) -> None:
    """A top-level playbook may set enrolled_host in a play's vars, and only an enrolled
    play may load vars_files, and that is pinned by R2 rather than read here."""
    if doc is None:
        return
    if not isinstance(doc, list):
        out.append(f"R6 {where}: is not a list of plays, so R6 cannot read it")
        return
    for play in doc:
        if not isinstance(play, dict):
            out.append(f"R6 {where}: holds an entry that is not a play, so R6 cannot read it")
            continue
        body = _mapping(play)
        enrolled = _enrolled(body)
        if enrolled:
            body.pop("vars_files", None)
        play_vars = body.pop("vars", None)
        if isinstance(play_vars, dict) and HOST_KEY in play_vars:
            if not enrolled:
                out.append(f"R6 {where}: sets {HOST_KEY} outside an enrolled playbook's vars")
            play_vars = {key: item for key, item in play_vars.items() if key != HOST_KEY}
        _scan({"vars": play_vars, **body}, path.parent, ansible, where, frozenset(), out)


def _check_no_other_definition(ansible: Path, findings: list[str]) -> None:
    resolved = ansible.resolve()
    for path in sorted(ansible.rglob("*")):
        relative = path.relative_to(ansible)
        where = f"ansible/{relative.as_posix()}"
        if not _is_scanned(relative):
            continue
        loaded = LOADED_DIRS.intersection(relative.parts)
        if path.is_symlink() and loaded and _inside(path.resolve(), resolved) is None:
            findings.append(f"R6 {where}: links out of ansible/ where Ansible loads files")
            continue
        if not path.is_file() or path.suffix not in VARS_SUFFIXES:
            continue
        doc = _load(path, findings, f"R6 {where}")
        if relative.parent == Path("playbooks") and path.suffix in TASK_SUFFIXES:
            _scan_playbook(doc, path, resolved, where, findings)
        else:
            allowed = _allowed_in(relative.as_posix())
            _scan(doc, path.parent.resolve(), resolved, where, allowed, findings)


def _is_play_list(path: Path) -> bool:
    """True when the file parses as a YAML list, which ansible-playbook would run as plays. A
    file that does not parse as YAML is not a playbook, so it is not a finding here."""
    try:
        return isinstance(yaml.safe_load(path.read_text(encoding="utf-8")), list)
    except (OSError, ValueError, yaml.YAMLError):
        return False


def _in_place(tree: str, inside: tuple[str, ...]) -> bool:
    """A .yml sits where Ansible reads it: at the top of its tree, or in playbooks/includes/."""
    if len(inside) == 1:
        return True
    return tree == "playbooks" and inside[:-1] == ("includes",)


def _check_names(ansible: Path, findings: list[str]) -> None:
    """Shared by R2, R4 and R5: the one name rule for playbooks/ and trust/, at any depth.

    Every entry that is not a directory is refused unless it is a link-free exact .yml placed
    where Ansible reads it, or one of the two README paths named exactly. A link is refused
    whatever its name, so the check never follows one. Any other name, case or depth is
    refused, so R6 reads every file the pull can load from these two trees.
    """
    for tree in TREES:
        rule = "R5" if tree == "trust" else "R2"
        base = ansible / tree
        for path in sorted(base.rglob("*")):
            inside = path.relative_to(base)
            label = f"{rule} {inside.as_posix()}"
            if path.is_symlink():
                findings.append(f"{label}: is a link, which the check does not follow")
            elif path.is_dir():
                continue
            elif f"{tree}/{inside.as_posix()}" in README_EXCEPTIONS:
                if _is_play_list(path):
                    findings.append(f"{label}: a README that parses as a YAML list is refused")
            elif path.suffix != ".yml":
                findings.append(f"{label}: must be an exact .yml, as Ansible reads it")
            elif not _in_place(tree, inside.parts):
                where = "or in playbooks/includes/" if tree == "playbooks" else ""
                findings.append(f"{label}: a .yml must sit at the top of {tree}/ {where}".rstrip())


def _yml_files(directory: Path) -> list[Path]:
    """The top-level .yml files of a tree. _check_names has already refused every other name."""
    return sorted(path for path in directory.iterdir() if path.is_file() and path.suffix == ".yml")


def check(root: Path) -> list[str]:
    """Return one finding per broken rule, or an empty list when the tree passes."""
    findings: list[str] = []
    ansible = root / "ansible"
    playbooks = ansible / "playbooks"
    includes = playbooks / "includes"
    trust = ansible / "trust"

    for name in SHARED_INCLUDES:
        if not (includes / name).is_file():
            findings.append(f"R0 playbooks/includes/{name} is missing")
    _check_gates(includes, findings)
    _check_names(ansible, findings)

    enrolled: dict[str, list[dict[str, object]]] = {}
    for path in _yml_files(playbooks):
        plays = _plays(_load(path, findings, f"R2 {path.name}"))
        if any(_enrolled(play) for play in plays):
            enrolled[path.stem] = plays
            continue
        text = path.read_text(encoding="utf-8")
        for marker in (ENROLLED_ROLE, "trust/"):
            if marker in text:
                findings.append(f"R7 {path.name}: not enrolled, but names '{marker}'")

    if not enrolled:
        findings.append("R1 no top-level playbook applies the pull_trigger role")
    for stem, plays in sorted(enrolled.items()):
        _check_enrolled(stem, plays, findings)
    _check_derivation(includes, findings)

    trust_files = _yml_files(trust)
    trust_stems = {path.stem for path in trust_files}
    for stem in sorted(set(enrolled) - trust_stems):
        findings.append(f"R4 {stem}.yml is enrolled but has no trust/{stem}.yml")
    for stem in sorted(trust_stems - set(enrolled)):
        findings.append(f"R4 trust/{stem}.yml has no enrolled playbook")
    for path in trust_files:
        _check_trust_file(path, findings)

    _check_writer(ansible, findings)
    _check_no_other_definition(ansible, findings)
    return findings


def main() -> int:
    findings = check(ROOT)
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        return 1
    print("check_enrolment: every enrolled playbook names its own host and trust file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
