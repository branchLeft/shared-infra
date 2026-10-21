"""Build and check the bootstrap record that a new host's first-boot document is made from.

A new host fetches three files of this repository over HTTPS and checks each against a
SHA-256 before it runs anything: the pull program, the program that installs the pinned
Ansible, and the hash-locked requirements. It also writes the pull program's configuration.
This tool produces the record that names those files at a commit of ``main``, their hashes
and the configuration text, and checks a record against the repository.

The pin of each file is the last commit that changed it, read from the history, so the record
never names a commit that a squash merge could remove. That is enforced here, not assumed:
both commands first fetch ``main`` from ``origin`` afresh and refuse without it. ``generate``
refuses unless HEAD is the tip of that fetched ``main``, and ``verify`` refuses a record whose
pin is not an ancestor of it, so a record built on a branch, or one that names a commit that
only a pull request's ref or a fork holds, is never accepted. ``origin`` is taken to be
``branchLeft/shared-infra``: the tool runs in a checkout of it.

The configuration is not written a second time here. Its keys are read from the role's own
task, its values from the role's own variable files, and it is serialised the way Ansible's
``to_nice_json`` does; ``test_pull_bootstrap`` runs the role's own task and compares the bytes.

Usage::

    pull_bootstrap.py generate --repo DIR --out FILE
    pull_bootstrap.py verify --repo DIR --record FILE
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

REMOTE: Final = "origin"
MAIN_BRANCH: Final = "main"
SCHEMA: Final = 1

# The values the record holds fixed (where the files are served from, which files, the one
# playbook, the keys the configuration needs) are written once, in this JSON file. The
# first-boot document's TypeScript (hetzner-host/cloudInit.ts) imports the same file, so a
# path that moves is changed in one place and not in two languages.
FIXED_PATH: Final = Path(__file__).resolve().parents[2] / "hetzner-host" / "pullBootstrapFixed.json"


class BootstrapError(Exception):
    """The record cannot be built, or the inputs are not what the tool is built for."""


def load_fixed(path: Path) -> dict[str, object]:
    """Return the fixed values of the record, read from their one home.

    Raises:
        BootstrapError: The file cannot be read or is not a JSON object.
    """
    try:
        loaded: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        message = f"{path} cannot be read as JSON: {type(error).__name__}"
        raise BootstrapError(message) from error
    if not isinstance(loaded, dict) or not all(isinstance(key, str) for key in loaded):
        message = f"{path} is not a JSON object"
        raise BootstrapError(message)
    return {str(key): value for key, value in loaded.items()}


def fixed_text(fixed: Mapping[str, object], key: str) -> str:
    """Return one fixed value that must be a string.

    Raises:
        BootstrapError: The value is absent or not a string.
    """
    value = fixed.get(key)
    if not isinstance(value, str):
        message = f"{FIXED_PATH.name} has no string {key}"
        raise BootstrapError(message)
    return value


def fixed_strings(fixed: Mapping[str, object], key: str) -> dict[str, str]:
    """Return one fixed value that must be an object whose values are strings.

    Raises:
        BootstrapError: The value is absent, or not an object of strings.
    """
    value = fixed.get(key)
    if not isinstance(value, dict) or not all(
        isinstance(name, str) and isinstance(item, str) for name, item in value.items()
    ):
        message = f"{FIXED_PATH.name} has no object of strings {key}"
        raise BootstrapError(message)
    return {str(name): str(item) for name, item in value.items()}


def fixed_names(fixed: Mapping[str, object], key: str) -> frozenset[str]:
    """Return one fixed value that must be a list of strings.

    Raises:
        BootstrapError: The value is absent, or not a list of strings.
    """
    value = fixed.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        message = f"{FIXED_PATH.name} has no list of strings {key}"
        raise BootstrapError(message)
    return frozenset(str(item) for item in value)


_FIXED: Final = load_fixed(FIXED_PATH)
RAW_BASE: Final = fixed_text(_FIXED, "rawBase")
REMOTE_URL: Final = fixed_text(_FIXED, "remoteUrl")
PLAYBOOK_PATH: Final = fixed_text(_FIXED, "playbook")
# The three files a host fetches, by the name the record gives them.
FETCHED: Final = fixed_strings(_FIXED, "fetched")
REQUIRED_CONFIG_KEYS: Final = fixed_names(_FIXED, "requiredConfigKeys")

DEFAULTS_PATH: Final = "ansible/roles/pull_trigger/defaults/main.yml"
VARS_PATH: Final = "ansible/roles/pull_trigger/vars/main.yml"
TASKS_PATH: Final = "ansible/roles/pull_trigger/tasks/main.yml"
GROUP_VARS_PATH: Final = "ansible/inventories/production/group_vars/edge/pull_trigger.yml"
INPUTS: Final = (DEFAULTS_PATH, VARS_PATH, TASKS_PATH, GROUP_VARS_PATH, PLAYBOOK_PATH)

CONFIG_TASK_NAME: Final = "Write the configuration"
CONFIG_CONTENT: Final = "{{ pull_trigger_config | ansible.builtin.to_nice_json }}\n"
CONFIG_VARIABLE: Final = "pull_trigger_config"
VALUE_EXPRESSION: Final = re.compile(r"\{\{ (?P<name>pull_trigger_[a-z_]+)(?P<int> \| int)? \}\}")
COMMIT: Final = re.compile(r"[0-9a-f]{40}")
SHA256: Final = re.compile(r"[0-9a-f]{64}")


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    """Run git in the repository and return the finished process.

    Raises:
        BootstrapError: The command fails and ``check`` is set.
    """
    completed = subprocess.run(  # noqa: S603 - argv is built here from constants and checked values
        ["git", "-C", str(repo), *args],  # noqa: S607 - git is looked up on the PATH by design
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        message = f"git {' '.join(args)} failed: {detail}"
        raise BootstrapError(message)
    return completed


def parse_yaml(text: str, what: str) -> object:
    """Parse YAML text, with a named error for malformed input.

    Raises:
        BootstrapError: The text is not valid YAML.
    """
    try:
        return YAML(typ="safe").load(text)
    except YAMLError as error:
        message = f"{what} is not valid YAML: {type(error).__name__}"
        raise BootstrapError(message) from error


def mapping(value: object, what: str) -> dict[str, object]:
    """Return a YAML value as a mapping with string keys.

    Raises:
        BootstrapError: The value is not a mapping with string keys.
    """
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        message = f"{what} is not a mapping"
        raise BootstrapError(message)
    return {str(key): item for key, item in value.items()}


def sequence(value: object, what: str) -> list[object]:
    """Return a YAML value as a list.

    Raises:
        BootstrapError: The value is not a list.
    """
    if not isinstance(value, list):
        message = f"{what} is not a list"
        raise BootstrapError(message)
    return list(value)


def merge_variables(*sources: tuple[str, dict[str, object]]) -> dict[str, object]:
    """Merge variable files that must not overlap.

    Ansible would let one outrank another, which is a precedence rule a reader has to
    know. The files of this role set different names, so a name set twice is refused
    rather than resolved.

    Raises:
        BootstrapError: A name is set in two files.
    """
    merged: dict[str, object] = {}
    owner: dict[str, str] = {}
    for label, variables in sources:
        for name, value in variables.items():
            if name in merged:
                message = f"{name} is set in {owner[name]} and in {label}"
                raise BootstrapError(message)
            merged[name] = value
            owner[name] = label
    return merged


def config_task(tasks: object) -> dict[str, object]:
    """Return the role's task that writes the configuration.

    Raises:
        BootstrapError: There is not exactly one such task.
    """
    found = [
        task
        for task in sequence(tasks, TASKS_PATH)
        if isinstance(task, dict) and task.get("name") == CONFIG_TASK_NAME
    ]
    if len(found) != 1:
        message = f"{TASKS_PATH} has {len(found)} tasks named {CONFIG_TASK_NAME!r}, not one"
        raise BootstrapError(message)
    return mapping(found[0], CONFIG_TASK_NAME)


def render_config(tasks_text: str, defaults_text: str, vars_text: str, group_vars_text: str) -> str:
    """Return the text of the pull program's configuration file.

    Raises:
        BootstrapError: An input is malformed, a name is unresolved or a rule below fails.
    """
    task = config_task(parse_yaml(tasks_text, TASKS_PATH))
    copy = mapping(task.get("ansible.builtin.copy"), "the configuration task's copy")
    if copy.get("content") != CONFIG_CONTENT:
        message = "the configuration task no longer writes to_nice_json of one variable"
        raise BootstrapError(message)
    declared = mapping(
        mapping(task.get("vars"), "the task's vars").get(CONFIG_VARIABLE), CONFIG_VARIABLE
    )
    variables = merge_variables(
        (DEFAULTS_PATH, mapping(parse_yaml(defaults_text, DEFAULTS_PATH), DEFAULTS_PATH)),
        (VARS_PATH, mapping(parse_yaml(vars_text, VARS_PATH), VARS_PATH)),
        (GROUP_VARS_PATH, mapping(parse_yaml(group_vars_text, GROUP_VARS_PATH), GROUP_VARS_PATH)),
    )
    config: dict[str, object] = {}
    for key, expression in declared.items():
        config[key] = resolve(key, expression, variables)
    check_config(config)
    return json.dumps(config, indent=4, sort_keys=True, separators=(",", ": ")) + "\n"


def resolve(key: str, expression: object, variables: Mapping[str, object]) -> object:
    """Return the value one configuration key takes.

    Raises:
        BootstrapError: The expression is not a plain variable, optionally as an integer.
    """
    matched = VALUE_EXPRESSION.fullmatch(expression) if isinstance(expression, str) else None
    if matched is None:
        message = f"the configuration key {key} is not a plain variable"
        raise BootstrapError(message)
    name = matched.group("name")
    if name not in variables:
        message = f"the configuration key {key} names {name}, which no variable file sets"
        raise BootstrapError(message)
    value = variables[name]
    if matched.group("int") is None:
        return value
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        message = f"{name} is not a number"
        raise BootstrapError(message)
    try:
        return int(value)
    except ValueError as error:
        message = f"{name} is not a number"
        raise BootstrapError(message) from error


def check_config(config: Mapping[str, object]) -> None:
    """Refuse a configuration that a new host must not be given.

    Raises:
        BootstrapError: A key is missing, the signer list is empty or the playbook is not edge1's.
    """
    missing = sorted(REQUIRED_CONFIG_KEYS - set(config))
    if missing:
        message = f"the configuration has no {', '.join(missing)}"
        raise BootstrapError(message)
    signers = config["signers"]
    if not isinstance(signers, list) or not signers:
        message = "the signer allowlist is empty"
        raise BootstrapError(message)
    playbooks = config["playbooks"]
    playbook = config["playbook"]
    if not isinstance(playbooks, list) or playbook not in playbooks:
        message = "the host's playbook is not on the playbook allowlist"
        raise BootstrapError(message)
    if playbook != PLAYBOOK_PATH or playbooks != [PLAYBOOK_PATH]:
        message = f"only {PLAYBOOK_PATH} is allowed, as the host's one playbook"
        raise BootstrapError(message)
    if config["remote_url"] != REMOTE_URL:
        message = f"the remote is not {REMOTE_URL}"
        raise BootstrapError(message)


def check_playbook(playbook_text: str) -> None:
    """Refuse an edge1 playbook that does not load the group variables this tool reads.

    Raises:
        BootstrapError: The playbook has no play that loads them.
    """
    plays = sequence(parse_yaml(playbook_text, PLAYBOOK_PATH), PLAYBOOK_PATH)
    for play in plays:
        files = mapping(play, "a play").get("vars_files")
        if isinstance(files, list) and any(
            isinstance(entry, str) and entry.endswith(GROUP_VARS_PATH.split("ansible/", 1)[1])
            for entry in files
        ):
            return
    message = f"{PLAYBOOK_PATH} does not load {GROUP_VARS_PATH}"
    raise BootstrapError(message)


def read_inputs(repo: Path) -> dict[str, str]:
    """Return the text of the configuration inputs, refusing any that is not committed as it is.

    Raises:
        BootstrapError: An input differs from HEAD, so the record would describe bytes
            that no commit holds.
    """
    changed = git(repo, "status", "--porcelain", "--", *INPUTS, *FETCHED.values()).stdout
    if changed.strip():
        message = "an input has changes that are not committed: " + changed.decode().strip()
        raise BootstrapError(message)
    return {path: (repo / path).read_text(encoding="utf-8") for path in INPUTS}


def head(repo: Path) -> str:
    """Return the full commit id of HEAD."""
    return git(repo, "rev-parse", "HEAD").stdout.decode().strip()


def main_tip(repo: Path) -> str:
    """Fetch ``main`` from ``origin`` afresh and return the commit it points at.

    A stale local copy of ``main`` must not stand in for the real one, so this asks the remote
    each time and never reads a remote-tracking branch that an earlier fetch left behind.

    Raises:
        BootstrapError: The fetch fails, so there is no main to bind a pin to.
    """
    git(repo, "fetch", "--quiet", REMOTE, f"refs/heads/{MAIN_BRANCH}")
    tip = git(repo, "rev-parse", "FETCH_HEAD").stdout.decode().strip()
    if COMMIT.fullmatch(tip) is None:
        message = f"{REMOTE}/{MAIN_BRANCH} did not resolve to a commit"
        raise BootstrapError(message)
    return tip


def last_commit(repo: Path, path: str) -> str:
    """Return the last commit at HEAD that changed the file.

    Raises:
        BootstrapError: No commit changed it.
    """
    commit = git(repo, "log", "-1", "--format=%H", "HEAD", "--", path).stdout.decode().strip()
    if COMMIT.fullmatch(commit) is None:
        message = f"no commit changed {path}"
        raise BootstrapError(message)
    return commit


def blob_sha256(repo: Path, commit: str, path: str) -> str:
    """Return the SHA-256 of the file as the commit holds it."""
    return hashlib.sha256(git(repo, "show", f"{commit}:{path}").stdout).hexdigest()


def raw_url(commit: str, path: str) -> str:
    """Return the address of a file at a commit."""
    return f"{RAW_BASE}/{commit}/{path}"


def repository_config(repo: Path) -> str:
    """Return the configuration text the repository's files at HEAD give.

    Raises:
        BootstrapError: An input is not committed, malformed or not what the tool allows.
    """
    inputs = read_inputs(repo)
    check_playbook(inputs[PLAYBOOK_PATH])
    return render_config(
        inputs[TASKS_PATH], inputs[DEFAULTS_PATH], inputs[VARS_PATH], inputs[GROUP_VARS_PATH]
    )


def build_record(repo: Path) -> dict[str, object]:
    """Return the record for the repository, which must be at the tip of ``main``.

    Raises:
        BootstrapError: HEAD is not the tip of a freshly fetched ``main``, or an input is
            not committed, malformed or not what the tool allows.
    """
    tip = main_tip(repo)
    top = head(repo)
    if top != tip:
        message = (
            f"HEAD {top} is not the tip of {REMOTE}/{MAIN_BRANCH} ({tip}): "
            "a record is built from main, never from a branch"
        )
        raise BootstrapError(message)
    config = repository_config(repo)
    record: dict[str, object] = {"schema": SCHEMA}
    for name, path in FETCHED.items():
        commit = last_commit(repo, path)
        record[name] = {
            "pin": commit,
            "sha256": blob_sha256(repo, commit, path),
            "url": raw_url(commit, path),
        }
    record["config"] = config
    return record


def verify_record(repo: Path, record: object) -> list[str]:
    """Return what is wrong with a record, as one line each. An empty list means it is current."""
    problems: list[str] = []
    if not isinstance(record, dict) or record.get("schema") != SCHEMA:
        return [f"the record is not schema {SCHEMA}"]
    try:
        tip = main_tip(repo)
        top = head(repo)
    except BootstrapError as error:
        return [str(error)]
    for name, path in FETCHED.items():
        try:
            problems.extend(verify_entry(repo, tip, top, name, path, record.get(name)))
        except BootstrapError as error:
            problems.append(f"{name}: {error}")
    try:
        if record.get("config") != repository_config(repo):
            problems.append("config: differs from the one the repository's files give")
    except BootstrapError as error:
        problems.append(f"config: {error}")
    return problems


def verify_entry(repo: Path, tip: str, top: str, name: str, path: str, entry: object) -> list[str]:
    """Return what is wrong with one file's entry in the record.

    ``tip`` is the freshly fetched tip of ``main`` and ``top`` is HEAD.
    """
    if not isinstance(entry, dict) or set(entry) != {"pin", "sha256", "url"}:
        return [f"{name}: the entry is not a pin, a sha256 and a url"]
    pin, digest, url = entry["pin"], entry["sha256"], entry["url"]
    if not (isinstance(pin, str) and COMMIT.fullmatch(pin)):
        return [f"{name}: the pin is not a full commit id"]
    problems: list[str] = []
    if not (isinstance(digest, str) and SHA256.fullmatch(digest)):
        problems.append(f"{name}: the sha256 is not 64 lowercase hex digits")
    if url != raw_url(pin, path):
        problems.append(f"{name}: the url does not name the recorded pin and the file")
    if git(repo, "merge-base", "--is-ancestor", pin, tip, check=False).returncode != 0:
        return [*problems, f"{name}: the pin is not an ancestor of {REMOTE}/{MAIN_BRANCH}"]
    if git(repo, "merge-base", "--is-ancestor", pin, top, check=False).returncode != 0:
        return [*problems, f"{name}: the pin is not an ancestor of HEAD"]
    shown = git(repo, "show", f"{pin}:{path}", check=False)
    if shown.returncode != 0 or hashlib.sha256(shown.stdout).hexdigest() != digest:
        problems.append(f"{name}: the sha256 is not that of the file at the pin")
    if last_commit(repo, path) != pin:
        problems.append(f"{name}: a later commit changed the file, so the pin is stale")
    return problems


def main(argv: Sequence[str]) -> int:
    """Run the command line. Exit status 0 means it built or verified; anything else does not."""
    parser = argparse.ArgumentParser(prog="pull_bootstrap")
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate")
    generate.add_argument("--repo", type=Path, required=True)
    generate.add_argument("--out", type=Path, required=True)
    check = commands.add_parser("verify")
    check.add_argument("--repo", type=Path, required=True)
    check.add_argument("--record", type=Path, required=True)
    arguments = parser.parse_args(list(argv))
    try:
        if arguments.command == "generate":
            record = build_record(arguments.repo)
            arguments.out.write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return 0
        problems = verify_record(
            arguments.repo, json.loads(arguments.record.read_text(encoding="utf-8"))
        )
    except (BootstrapError, OSError, ValueError) as error:
        print(f"pull_bootstrap: {error}", file=sys.stderr)
        return 1
    for problem in problems:
        print(f"pull_bootstrap: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
