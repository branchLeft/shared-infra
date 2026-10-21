"""Check the enrolment of the host playbooks under the pull (ws#2340).

A host playbook is under the pull when one of its plays applies the pull_trigger role.
Its trust anchor is the signer file ansible/trust/<host>.yml. The rules below keep each
host to its own playbook, its own trust file and its own signer list. A failure names
the rule (R0 to R7) and the file. test_check_enrolment.py runs the check over the real
tree and over sabotaged copies of it.

R0  the three shared includes exist under ansible/playbooks/includes/.
R1  at least one top-level playbook is enrolled. An empty set fails, so the check
    cannot pass over nothing.
R2  each enrolled playbook <host>.yml has one play, hosts all, vars.enrolled_host equal
    to <host>, vars_files exactly the shared include and ../trust/<host>.yml, and
    pre_tasks exactly the refusal and the signer check, in that order.
R3  the shared include derives the playbook from enrolled_host and from nothing else.
R4  the trust files are exactly the enrolled playbooks, one file each.
R5  each trust file holds one key, pull_trigger_signers, as a list (it may be empty).
R6  no other file defines pull_trigger_signers: not an inventory, a playbook or a
    role's defaults or vars.
R7  a top-level playbook that is not enrolled names neither pull_trigger nor trust/.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
SIGNER_KEY = "pull_trigger_signers"
ENROLLED_ROLE = "pull_trigger"
SHARED_INCLUDES = ("pull_trigger_common.yml", "refuse_other_hosts.yml", "require_signers.yml")
COMMON_INCLUDE = "{{ playbook_dir }}/includes/pull_trigger_common.yml"
REFUSE_TASKS = "includes/refuse_other_hosts.yml"
SIGNER_TASKS = "includes/require_signers.yml"
DERIVED_PLAYBOOK = "ansible/playbooks/{{ enrolled_host }}.yml"


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


def _include_target(task: object) -> object:
    if not isinstance(task, dict):
        return None
    for key in ("ansible.builtin.include_tasks", "include_tasks"):
        if key in task:
            return task[key]
    return None


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
    pre_tasks = play.get("pre_tasks")
    targets = [_include_target(task) for task in pre_tasks] if isinstance(pre_tasks, list) else []
    if targets != [REFUSE_TASKS, SIGNER_TASKS]:
        findings.append(f"{label}: pre_tasks must be exactly {REFUSE_TASKS}, then {SIGNER_TASKS}")


def _check_derivation(includes: Path, findings: list[str]) -> None:
    common = _mapping(_load(includes / "pull_trigger_common.yml", findings))
    if common.get("pull_trigger_playbook") != DERIVED_PLAYBOOK:
        findings.append(
            f"R3 pull_trigger_common.yml: pull_trigger_playbook is not {DERIVED_PLAYBOOK}"
        )
    if common.get("pull_trigger_playbooks") != ["{{ pull_trigger_playbook }}"]:
        findings.append("R3 pull_trigger_common.yml: pull_trigger_playbooks is not the one derived")


def _check_trust_file(path: Path, findings: list[str]) -> None:
    doc = _mapping(_load(path, findings))
    if set(doc) != {SIGNER_KEY} or not isinstance(doc.get(SIGNER_KEY), list):
        findings.append(f"R5 trust/{path.name}: must hold exactly {SIGNER_KEY}, as a list")


def _defined_keys(doc: object) -> set[str]:
    keys: set[str] = set(_mapping(doc))
    for play in _plays(doc):
        keys.update(_mapping(play.get("vars")))
    return keys


def _check_no_other_definition(root: Path, findings: list[str]) -> None:
    ansible = root / "ansible"
    scanned = [
        *sorted((ansible / "inventories").rglob("*.yml")),
        *sorted((ansible / "playbooks").rglob("*.yml")),
        *sorted((ansible / "roles").glob("*/defaults/*.yml")),
        *sorted((ansible / "roles").glob("*/vars/*.yml")),
    ]
    for path in scanned:
        if SIGNER_KEY in _defined_keys(_load(path, [])):
            where = path.relative_to(root).as_posix()
            findings.append(f"R6 {where}: defines {SIGNER_KEY} outside ansible/trust/")


def check(root: Path) -> list[str]:
    """Return one finding per broken rule, or an empty list when the tree passes."""
    findings: list[str] = []
    playbooks = root / "ansible" / "playbooks"
    includes = playbooks / "includes"
    trust = root / "ansible" / "trust"

    for name in SHARED_INCLUDES:
        if not (includes / name).is_file():
            findings.append(f"R0 playbooks/includes/{name} is missing")

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
