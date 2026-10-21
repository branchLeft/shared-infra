"""Check the enrolment of the host playbooks under the pull (ws#2340).

A host playbook is under the pull when one of its plays applies the pull_trigger role.
Its trust anchor is the signer file ansible/trust/<host>.yml. The rules below keep each
host to its own playbook, its own trust file and its own signer list, and keep the
shared remote and the playbook derivation in one include that no host can change. A
failure names the rule (R0 to R7) and the file. test_check_enrolment.py runs the check
over the real tree and over sabotaged copies of it.

R0  the three shared includes exist under ansible/playbooks/includes/. The two refusal
    includes each hold exactly one task: their assert, with exactly its expressions.
R1  at least one top-level playbook is enrolled. An empty set fails, so the check
    cannot pass over nothing.
R2  each enrolled playbook <host>.yml has one play, hosts all, vars.enrolled_host equal
    to <host>, vars_files exactly the shared include and ../trust/<host>.yml, roles
    exactly the runtime entry (with only its requirements path) and then the bare
    pull_trigger entry, and pre_tasks exactly the refusal include then the signer
    include, each a task holding only its name and its include.
R3  the shared include holds exactly the remote literal and the playbook derivation from
    enrolled_host, and nothing else.
R4  the trust files are exactly the enrolled playbooks, one file each.
R5  each trust file holds one key, pull_trigger_signers, as a list (it may be empty).
R6  the protected keys are set only where they may be. pull_trigger_signers only in
    ansible/trust/. The remote and the playbook derivation only in the shared include.
    Every key of every YAML file under ansible/ is read, so an inventory, a play's vars,
    a role entry's vars and a role task's set_fact or vars are all covered. A file that
    does not parse is read as text. Role argument specs and molecule scenarios hold
    schema and test fixtures, not host configuration, and are not read. include_vars
    loads keys this check cannot open, so it is refused outside those scenarios.
R7  a top-level playbook that is not enrolled names neither pull_trigger nor trust/.
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
DERIVATION_KEYS = (REMOTE_KEY, PLAYBOOK_KEY, PLAYBOOKS_KEY)
PROTECTED_KEYS = frozenset((SIGNER_KEY, *DERIVATION_KEYS))
LOADER_KEYS = frozenset(("include_vars", "ansible.builtin.include_vars"))
ENROLLED_ROLE = "pull_trigger"
SHARED_INCLUDES = ("pull_trigger_common.yml", "refuse_other_hosts.yml", "require_signers.yml")
COMMON_INCLUDE = "{{ playbook_dir }}/includes/pull_trigger_common.yml"
REFUSE_TASKS = "includes/refuse_other_hosts.yml"
SIGNER_TASKS = "includes/require_signers.yml"
DERIVED_PLAYBOOK = "ansible/playbooks/{{ enrolled_host }}.yml"
REMOTE_URL = "https://github.com/branchLeft/shared-infra.git"
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


def _load(path: Path, findings: list[str]) -> object:
    """Parse a YAML file. A missing file is R0's finding, so it is not reported here."""
    if not path.is_file():
        return None
    try:
        doc: object = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        findings.append(f"{path.name}: cannot be read as YAML: {error}")
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
    if variables.get("enrolled_host") != stem:
        findings.append(f"{label}: vars.enrolled_host must be {stem}")
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
    """R0: an include holds one task, its assert, and that assert's expressions exactly."""
    label = f"R0 playbooks/includes/{path.name}"
    doc = _load(path, findings)
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
    common = _mapping(_load(includes / "pull_trigger_common.yml", findings))
    if common != EXPECTED_COMMON:
        findings.append(
            f"R3 pull_trigger_common.yml: must hold exactly {REMOTE_KEY} {REMOTE_URL!r}, "
            f"and the playbook derivation from enrolled_host, and no other key"
        )


def _check_trust_file(path: Path, findings: list[str]) -> None:
    doc = _mapping(_load(path, findings))
    if set(doc) != {SIGNER_KEY} or not isinstance(doc.get(SIGNER_KEY), list):
        findings.append(f"R5 trust/{path.name}: must hold exactly {SIGNER_KEY}, as a list")


def _walk(doc: object) -> set[str]:
    """Return every mapping key in the document that R6 protects or cannot read."""
    found: set[str] = set()
    if isinstance(doc, dict):
        for key, value in doc.items():
            if str(key) in PROTECTED_KEYS or str(key) in LOADER_KEYS:
                found.add(str(key))
            found |= _walk(value)
    elif isinstance(doc, list):
        for item in doc:
            found |= _walk(item)
    return found


def _allowed_in(relative: str) -> frozenset[str]:
    """Return the protected keys a file may set, by its place in the tree."""
    if relative.startswith("ansible/trust/"):
        return frozenset((SIGNER_KEY,))
    if relative == "ansible/playbooks/includes/pull_trigger_common.yml":
        return frozenset(DERIVATION_KEYS)
    return frozenset()


def _is_scanned(relative: Path) -> bool:
    """Molecule scenarios and role argument specs are fixtures and schema, not config."""
    parts = relative.parts
    if "molecule" in parts:
        return False
    if len(parts) == 4 and parts[0] == "roles" and parts[2:] == ("meta", "argument_specs.yml"):
        return False
    return True


def _check_no_other_definition(root: Path, findings: list[str]) -> None:
    ansible = root / "ansible"
    for path in sorted(ansible.rglob("*")):
        if not path.is_file() or path.suffix not in (".yml", ".yaml"):
            continue
        relative = path.relative_to(ansible)
        if not _is_scanned(relative):
            continue
        where = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        try:
            doc: object = yaml.safe_load(text)
            keys = _walk(doc)
        except yaml.YAMLError:
            keys = {key for key in (*PROTECTED_KEYS, *LOADER_KEYS) if key in text}
        for key in sorted(keys - _allowed_in(where)):
            if key in LOADER_KEYS:
                findings.append(f"R6 {where}: loads variables with {key}, which R6 cannot read")
            else:
                findings.append(f"R6 {where}: sets {key}, which only its owner's file may set")


def check(root: Path) -> list[str]:
    """Return one finding per broken rule, or an empty list when the tree passes."""
    findings: list[str] = []
    playbooks = root / "ansible" / "playbooks"
    includes = playbooks / "includes"
    trust = root / "ansible" / "trust"

    for name in SHARED_INCLUDES:
        if not (includes / name).is_file():
            findings.append(f"R0 playbooks/includes/{name} is missing")
    _check_gates(includes, findings)

    enrolled: dict[str, list[dict[str, object]]] = {}
    for path in sorted(playbooks.glob("*.yml")):
        plays = _plays(_load(path, findings))
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

    _check_no_other_definition(root, findings)
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
