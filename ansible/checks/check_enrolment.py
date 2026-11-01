"""Check the host playbooks under the gated pull.

Rules R0 to R11, and what each one does not see, are in ansible/checks/README.md. A
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
        "owner_vars",
        "inventories",
    )
)
TASK_SUFFIXES = (".yml", ".yaml")
TREES = ("playbooks", "trust", "owner_vars")
TREE_RULES = {"playbooks": "R2", "trust": "R5", "owner_vars": "R10"}
OWNER_VARS_DIR = "owner_vars"
# The keys a host's owner_vars file holds, exactly. A host named nowhere here may have no file.
OWNER_VARS_KEYS = {
    "edge1": frozenset(("ci_login_keys", "ci_login_manage_keys")),
    "ops1": frozenset(("pull_trigger_steps",)),
}
STEPS_KEY = "pull_trigger_steps"
# Only the shape of an allow-list entry. Which ids, tags and words are valid is the program's
# rule alone (pull_trigger.py: STEP_IDS, _step_from, WORD_PATTERN), and test_step_allowlist.py
# feeds the real file through the program's own parser, so none of it is copied here.
STEP_ENTRY = frozenset(("id", "tag", "word"))
OWNER_KEY_ENTRY = frozenset(("key", "mode"))
OWNER_KEY_MODES = frozenset(("apply", "check"))
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
CONFIG_CONTENT = (
    "{{ pull_trigger_config | ansible.builtin.combine(pull_trigger_config_source)"
    " | ansible.builtin.to_nice_json }}\n"
)
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
# The play vars a host's playbook carries beside enrolled_host, pinned per host and exactly. The
# owner merges every edit here, so the value is decided by this table and not by the playbook.
# A host not in the table gets enrolled_host alone. deploy_tooling_host_class has no default in
# the role (ANS-7), so a host that applies the role must name its class here. The egress_nat role
# makes a host the estate's NAT gateway only when egress_nat_gateway_enabled is true (a bool, so
# the string "true" does not match), and a second gateway loops the estate's egress, so edge1
# alone carries that switch. R2 allows no `vars` on a role entry, so this row is its one home.
HOST_PLAY_VARS: dict[str, dict[str, str | bool]] = {
    "edge1": {"deploy_tooling_host_class": "gateway", "egress_nat_gateway_enabled": True}
}
PLAY_KEYS = frozenset(("name", "hosts", "gather_facts", "vars", "vars_files", "pre_tasks", "roles"))
HOST_ROLES_FILE = "checks/host_roles.yml"
ROLE_PATH = "../roles/"
ROLE_NAME = re.compile(r"[a-z][a-z0-9_]*")
HOST_NAME = re.compile(r"[a-z][a-z0-9]*")
PULL_ROLES = frozenset(("ansible_runtime", "pull_trigger"))
LOADER_ROLE = "host_inputs"
EXPECTED_COMMON = {
    REMOTE_KEY: REMOTE_URL,
    PLAYBOOK_KEY: DERIVED_PLAYBOOK,
    PLAYBOOKS_KEY: ["{{ pull_trigger_playbook }}"],
}


# The one definition of the loader every read uses: libyaml's C parser where PyYAML was built
# with it (the pinned wheel is), else the pure-Python SafeLoader. Both build only plain data.
_BASE_LOADER: type[yaml.SafeLoader] = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


# PyYAML ships no type stubs and the lock has no types-PyYAML, so mypy sees SafeLoader as Any.
class _AnyTagLoader(_BASE_LOADER):  # type: ignore[misc]
    """SafeLoader with every tag accepted. Ansible's loader takes !unsafe and !vault, and a
    list that carries such a value still runs as plays, so the README play-list parse must
    not refuse to read one. Only the README play-list check uses it."""


def _construct_any_tag(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    return loader.construct_scalar(node)


_AnyTagLoader.add_multi_constructor("", _construct_any_tag)


# What a parse gave, by loader and file text: the document, or the error message. The text is
# the key because a rewrite in place keeps the path, the size and perhaps the mtime, and a
# stale parse here would be a false green in a safety check; the same text parses the same
# whichever path it was read from, so one parse serves every copy of the tree. A caller must
# not change a document it is handed: they are shared. None does: _mapping and _plays copy.
_PARSED: dict[tuple[type[yaml.SafeLoader], str], tuple[object, str | None]] = {}


def _load(
    path: Path, findings: list[str], label: str, loader: type[yaml.SafeLoader] = _BASE_LOADER
) -> object:
    """The one YAML reader, for every rule, for R6 and for the README play-list check. The
    loader is the only difference: the README check passes _AnyTagLoader, the same reader with
    every tag accepted. A missing file is reported by its own rule, not here. An unparseable
    file is a finding under the caller's label. The file is read on every call; only the
    parse of a text already seen is skipped."""
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError) as error:
        findings.append(f"{label}: cannot be read as YAML: {error}")
        return None
    parsed = _PARSED.get((loader, text))
    if parsed is None:
        try:
            # The loader is always a SafeLoader subclass whose only addition turns any tag into
            # a plain list, dict or string, so no Python object is built here.
            parsed = (yaml.load(text, Loader=loader), None)  # noqa: S506
        except (ValueError, yaml.YAMLError) as error:
            parsed = (None, str(error))
        _PARSED[(loader, text)] = parsed
    doc, error_text = parsed
    if error_text is not None:
        findings.append(f"{label}: cannot be read as YAML: {error_text}")
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


def _plain_role(entry: object) -> str | None:
    """The role name of an entry that is exactly `role: ../roles/NAME` and no other key."""
    if not isinstance(entry, dict) or set(entry) != {"role"}:
        return None
    path = entry["role"]
    if not isinstance(path, str) or not path.startswith(ROLE_PATH):
        return None
    name = path[len(ROLE_PATH) :]
    return name if ROLE_NAME.fullmatch(name) else None


def _check_roles(label: str, stem: str, roles: object, listed: list[str], out: list[str]) -> None:
    """The two pull roles first, as pinned, then only plain entries from the host's own list."""
    pinned = len(EXPECTED_ROLES)
    if not isinstance(roles, list) or roles[:pinned] != EXPECTED_ROLES:
        out.append(f"{label}: roles must start with the runtime entry, then the bare trigger")
        return
    seen: list[str] = []
    for entry in roles[pinned:]:
        name = _plain_role(entry)
        if name is None:
            out.append(
                f"{label}: a role entry after the pull roles must be only `role: ../roles/NAME`"
            )
        elif name not in listed:
            out.append(f"{label}: role {name} is not on {stem}'s list in {HOST_ROLES_FILE}")
        elif name in seen:
            out.append(f"{label}: role {name} is applied twice")
        else:
            seen.append(name)
    if LOADER_ROLE in seen and seen[0] != LOADER_ROLE:
        out.append(
            f"R11 {stem}.yml: role {LOADER_ROLE} must be the first role after the pull roles, "
            f"so no role runs before the host's inputs are loaded or refused"
        )


def _check_enrolled(
    stem: str,
    plays: list[dict[str, object]],
    listed: list[str],
    has_owner_vars: bool,
    findings: list[str],
) -> None:
    label = f"R2 {stem}.yml"
    if len(plays) != 1:
        findings.append(f"{label}: expected one play, found {len(plays)}")
        return
    play = plays[0]
    for key in sorted(set(play) - PLAY_KEYS):
        findings.append(f"{label}: play key {key} is not allowed, only {sorted(PLAY_KEYS)}")
    if play.get("hosts") != "all":
        findings.append(f"{label}: hosts must be all")
    expected_vars = {HOST_KEY: stem, **HOST_PLAY_VARS.get(stem, {})}
    if play.get("vars") != expected_vars:
        findings.append(f"{label}: vars must be exactly {expected_vars}")
    expected_files = [COMMON_INCLUDE, f"{{{{ playbook_dir }}}}/../trust/{stem}.yml"]
    if has_owner_vars:
        expected_files.append(f"{{{{ playbook_dir }}}}/../{OWNER_VARS_DIR}/{stem}.yml")
    if play.get("vars_files") != expected_files:
        findings.append(f"{label}: vars_files must be exactly {expected_files}")
    _check_roles(label, stem, play.get("roles"), listed, findings)
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


def _read_host_roles(ansible: Path, findings: list[str]) -> dict[str, list[str]]:
    """R9: the owner's list of roles per host. A missing or unreadable file, or a host whose
    entry is not a clean list of role names, gives that host no roles beyond the pull roles."""
    label = f"R9 {HOST_ROLES_FILE}"
    path = ansible / HOST_ROLES_FILE
    if not path.is_file():
        findings.append(f"{label}: is missing")
        return {}
    doc = _load(path, findings, label)
    if not isinstance(doc, dict):
        findings.append(f"{label}: must be a mapping of host to a list of role names")
        return {}
    lists: dict[str, list[str]] = {}
    for host, roles in doc.items():
        clean = (
            isinstance(host, str)
            and HOST_NAME.fullmatch(host) is not None
            and isinstance(roles, list)
            and all(isinstance(role, str) and ROLE_NAME.fullmatch(role) for role in roles)
            and not PULL_ROLES.intersection(roles)
            and len(set(roles)) == len(roles)
        )
        if clean:
            lists[host] = list(roles)
        else:
            findings.append(
                f"{label}: {host!r} must be a host name with a list of distinct role names, "
                f"without {sorted(PULL_ROLES)}"
            )
    return lists


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


def _is_vars_candidate(relative: Path) -> bool:
    """True when R6 reads the file as vars: a file with a vars suffix, or with no suffix."""
    return relative.suffix in VARS_SUFFIXES


def _is_tool_artefact(relative: Path) -> bool:
    """True for a file with no suffix under a hidden path part (.ruff_cache/0.17.0/<hash>, or a
    cache's .gitignore) outside every loaded directory. Such a file is a tool's own artefact, not
    a vars file Ansible loads from a loaded directory. It is still read, so one that parses and
    sets a signer is refused; one that does not parse is no vars file, so it is not a finding."""
    return (
        relative.suffix == ""
        and any(part.startswith(".") for part in relative.parts)
        and not LOADED_DIRS.intersection(relative.parts)
    )


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
        if not path.is_file() or not _is_vars_candidate(relative):
            continue
        parse_findings = [] if _is_tool_artefact(relative) else findings
        doc = _load(path, parse_findings, f"R6 {where}")
        if relative.parent == Path("playbooks") and path.suffix in TASK_SUFFIXES:
            _scan_playbook(doc, path, resolved, where, findings)
        else:
            allowed = _allowed_in(relative.as_posix())
            _scan(doc, path.parent.resolve(), resolved, where, allowed, findings)


def _is_play_list(path: Path) -> bool:
    """True when the file parses as a YAML list, which ansible-playbook would run as plays. It
    reads through _load with _AnyTagLoader, so a list that holds a tagged value (!unsafe,
    !vault) still parses as a list. A file that does not parse as YAML is not a playbook, so
    it is not a finding here; _load's error goes to a list nobody reads."""
    return isinstance(_load(path, [], "README", _AnyTagLoader), list)


def _in_place(tree: str, inside: tuple[str, ...]) -> bool:
    """A .yml sits where Ansible reads it: at the top of its tree, or in playbooks/includes/."""
    if len(inside) == 1:
        return True
    return tree == "playbooks" and inside[:-1] == ("includes",)


def _check_names(ansible: Path, findings: list[str]) -> None:
    """Shared by R2, R4, R5 and R10: the one name rule for playbooks/, trust/ and owner_vars/.

    Every entry that is not a directory is refused unless it is a link-free exact .yml placed
    where Ansible reads it, or one of the two README paths named exactly (owner_vars/ has
    none). A link is refused whatever its name, so the check never follows one. Any other
    name, case or depth is refused, so R6 reads every file the pull can load from these trees.
    """
    for tree in TREES:
        rule = TREE_RULES[tree]
        base = ansible / tree
        if not base.is_dir():
            continue
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
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.iterdir() if path.is_file() and path.suffix == ".yml")


def _step_shape_problems(steps: object) -> list[str]:
    """The shape of pull_trigger_steps: a list of mappings with exactly id, tag and word, all
    text. Whether an id is on the program's closed list, a tag is the id's own and a word is
    well formed is judged by the program (see STEP_ENTRY), not here."""
    if not isinstance(steps, list):
        return [f"{STEPS_KEY} must be a list of {sorted(STEP_ENTRY)} entries"]
    problems: list[str] = []
    for entry in steps:
        if not isinstance(entry, dict) or set(entry) != STEP_ENTRY:
            problems.append(f"a {STEPS_KEY} entry must hold exactly {sorted(STEP_ENTRY)}")
        elif not all(isinstance(value, str) for value in entry.values()):
            problems.append(f"a {STEPS_KEY} entry needs a text id, tag and word")
    return problems


def _owner_key_problems(doc: dict[str, object]) -> list[str]:
    """What is wrong with the values of an owner_vars file, by key. A missing key is reported
    by the caller, which compares the key set."""
    problems: list[str] = []
    if STEPS_KEY in doc:
        problems.extend(_step_shape_problems(doc[STEPS_KEY]))
    if "ci_login_manage_keys" in doc and not isinstance(doc["ci_login_manage_keys"], bool):
        problems.append("ci_login_manage_keys must be a bool")
    keys = doc.get("ci_login_keys", [])
    if not isinstance(keys, list):
        problems.append("ci_login_keys must be a list of {key, mode} entries")
        return problems
    for entry in keys:
        if not isinstance(entry, dict) or set(entry) != OWNER_KEY_ENTRY:
            problems.append(f"a ci_login_keys entry must hold exactly {sorted(OWNER_KEY_ENTRY)}")
            continue
        mode = entry["mode"]
        if not isinstance(entry["key"], str) or not isinstance(mode, str):
            problems.append("a ci_login_keys entry needs a text key and a text mode")
        elif mode not in OWNER_KEY_MODES:
            problems.append(f"a ci_login_keys mode must be one of {sorted(OWNER_KEY_MODES)}")
    return problems


def _check_owner_vars(directory: Path, enrolled: set[str], findings: list[str]) -> None:
    """R10: an owner_vars file exists only for an enrolled host, and holds exactly the keys its
    host is allowed (OWNER_VARS_KEYS), with values of the right shape. The name rule is shared
    (_check_names). A protected key in one of these files is refused by R6, whose allowed set
    for this tree is empty."""
    for path in _yml_files(directory):
        label = f"R10 {OWNER_VARS_DIR}/{path.name}"
        if path.stem not in enrolled:
            findings.append(f"{label}: has no enrolled playbook")
            continue
        allowed = OWNER_VARS_KEYS.get(path.stem)
        if allowed is None:
            findings.append(f"{label}: this host has no owner_vars keys, so it may have no file")
            continue
        doc = _mapping(_load(path, findings, label))
        if set(doc) != allowed:
            findings.append(f"{label}: must hold exactly {sorted(allowed)}")
        findings.extend(f"{label}: {problem}" for problem in _owner_key_problems(doc))


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
    host_roles = _read_host_roles(ansible, findings)
    owner_vars = ansible / OWNER_VARS_DIR
    owner_stems = {path.stem for path in _yml_files(owner_vars)}
    for stem, plays in sorted(enrolled.items()):
        _check_enrolled(stem, plays, host_roles.get(stem, []), stem in owner_stems, findings)
    _check_derivation(includes, findings)
    _check_owner_vars(owner_vars, set(enrolled), findings)

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
