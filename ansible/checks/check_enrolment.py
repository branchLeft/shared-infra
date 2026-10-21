"""Check the host playbooks under the gated pull (ws#2340).

Rules R0 to R8 and their reasons are in ansible/checks/README.md. A failure names the
rule and the file. This check catches a protected key set outside its one file. It
does not make a role edit safe: the deploy approval is the control on root code.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
SIGNER_KEY = "pull_trigger_signers"
REMOTE_KEY = "pull_trigger_remote_url"
PLAYBOOK_KEY = "pull_trigger_playbook"
PLAYBOOKS_KEY = "pull_trigger_playbooks"
HOST_KEY = "enrolled_host"
DERIVATION_KEYS = (REMOTE_KEY, PLAYBOOK_KEY, PLAYBOOKS_KEY)
PROTECTED_KEYS = frozenset((SIGNER_KEY, HOST_KEY, *DERIVATION_KEYS))
INCLUDE_VARS = frozenset(("include_vars", "ansible.builtin.include_vars"))
TASK_FILE_LOADERS = frozenset(
    (
        "include_tasks",
        "ansible.builtin.include_tasks",
        "import_tasks",
        "ansible.builtin.import_tasks",
        "import_playbook",
        "ansible.builtin.import_playbook",
    )
)
ROLE_LOADERS = frozenset(
    ("include_role", "ansible.builtin.include_role", "import_role", "ansible.builtin.import_role")
)
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
WRITER = "roles/pull_trigger/tasks/main.yml"
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


def _load(path: Path, findings: list[str], rule: str) -> object:
    """Parse a YAML file. A missing file is reported by its own rule, not here."""
    if not path.is_file():
        return None
    try:
        doc: object = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as error:
        findings.append(f"{rule} {path.name}: cannot be read as YAML: {error}")
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
    doc = _load(path, findings, "R0")
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
    common = _mapping(_load(includes / "pull_trigger_common.yml", findings, "R3"))
    if common != EXPECTED_COMMON:
        findings.append(
            f"R3 pull_trigger_common.yml: must hold exactly {REMOTE_KEY} {REMOTE_URL!r}, "
            f"and the playbook derivation from enrolled_host, and no other key"
        )


def _check_trust_file(path: Path, findings: list[str]) -> None:
    doc = _mapping(_load(path, findings, "R5"))
    if set(doc) != {SIGNER_KEY} or not isinstance(doc.get(SIGNER_KEY), list):
        findings.append(f"R5 trust/{path.name}: must hold exactly {SIGNER_KEY}, as a list")


def _check_writer(ansible: Path, findings: list[str]) -> None:
    """R8: the config the trigger reads takes its signers and remote from the pinned values."""
    path = ansible / WRITER
    tasks = _load(path, findings, "R8") if path.is_file() else None
    config: dict[str, object] = {}
    for task in tasks if isinstance(tasks, list) else []:
        variables = _mapping(_mapping(task).get("vars"))
        if "pull_trigger_config" in variables:
            config = _mapping(variables["pull_trigger_config"])
    if config.get("signers") != SIGNERS_EXPR or config.get("remote_url") != REMOTE_EXPR:
        findings.append(
            f"R8 ansible/{WRITER}: the config writer's signers and remote_url must be "
            f"{SIGNERS_EXPR} and {REMOTE_EXPR}, not a literal"
        )


def _allowed_in(relative: str) -> frozenset[str]:
    """Return the protected keys a file may set, by its path under ansible/."""
    if relative.startswith("trust/"):
        return frozenset((SIGNER_KEY,))
    if relative == "playbooks/includes/pull_trigger_common.yml":
        return frozenset(DERIVATION_KEYS)
    if relative.startswith("playbooks/") and relative.count("/") == 1:
        return frozenset((HOST_KEY,))
    return frozenset()


def _is_scanned(relative: Path) -> bool:
    """Molecule scenarios and role argument specs are fixtures and schema, not config."""
    parts = relative.parts
    if "molecule" in parts:
        return False
    if len(parts) == 4 and parts[0] == "roles" and parts[2:] == ("meta", "argument_specs.yml"):
        return False
    return True


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
        and candidate.suffix in (".yml", ".yaml")
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


def _scan(
    node: object,
    base: Path,
    ansible: Path,
    where: str,
    allowed: frozenset[str],
    top_playbook: bool,
    out: list[str],
) -> None:
    """Record each protected key and each loader R6 cannot read, anywhere in the document."""
    if isinstance(node, list):
        for item in node:
            _scan(item, base, ansible, where, allowed, top_playbook, out)
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        name = str(key)
        if name in PROTECTED_KEYS and name not in allowed:
            out.append(f"R6 {where}: sets {name}, which only its owner's file may set")
        elif name in INCLUDE_VARS:
            out.append(f"R6 {where}: loads variables with {name}, which R6 cannot read")
        elif name in TASK_FILE_LOADERS and not _task_target_ok(value, base, ansible):
            out.append(f"R6 {where}: {name} loads {value!r}, which R6 cannot read")
        elif name in ROLE_LOADERS and not _role_ok(_mapping(value).get("name"), base, ansible):
            out.append(f"R6 {where}: {name} names a role R6 cannot read")
        elif name in ROLE_LISTS and isinstance(value, list):
            for entry in value:
                target = _mapping(entry).get("role") if isinstance(entry, dict) else entry
                if not _role_ok(target, base, ansible):
                    out.append(f"R6 {where}: {name} names {target!r}, which R6 cannot read")
        elif name == "vars_files" and not top_playbook:
            out.append(f"R6 {where}: loads variables with vars_files outside a top-level playbook")
        _scan(value, base, ansible, where, allowed, top_playbook, out)


def _check_no_other_definition(ansible: Path, findings: list[str]) -> None:
    resolved = ansible.resolve()
    for path in sorted(ansible.rglob("*")):
        if not path.is_file() or path.suffix not in (".yml", ".yaml"):
            continue
        relative = path.relative_to(ansible)
        if not _is_scanned(relative):
            continue
        where = f"ansible/{relative.as_posix()}"
        try:
            doc: object = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, yaml.YAMLError) as error:
            findings.append(f"R6 {where}: cannot be read as YAML, so R6 cannot read it: {error}")
            continue
        _scan(
            doc,
            path.parent.resolve(),
            resolved,
            where,
            _allowed_in(relative.as_posix()),
            relative.parent == Path("playbooks"),
            findings,
        )


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

    enrolled: dict[str, list[dict[str, object]]] = {}
    for path in sorted(playbooks.glob("*.yml")):
        plays = _plays(_load(path, findings, "R2"))
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

    trust_files = sorted(trust.glob("*.yml"))
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
