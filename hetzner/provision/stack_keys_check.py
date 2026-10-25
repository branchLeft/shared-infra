#!/usr/bin/env python3
"""Structural check of the control-plane stack files, on their parsed YAML.

The check reads keys, not spellings. Quoting, flow style, anchors and merge
keys all parse to the key they name, and Compose reads them the same way, so
none of them can slip past a check that matches text.

The checker refuses the Zitadel master key in any environment entry, whatever
its spelling, and in any --masterkey* command flag except the exact pair
--masterkeyFile /run/secrets/zitadel-masterkey.

Usage: stack_keys_check.py FILE...
Exit 0: clean. Exit 1: at least one violation, printed one per line.
Exit 2: a file could not be read or parsed.
"""

import pathlib
import shlex
import sys

import yaml

# A key that pulls another file's contents in whole. Its values would reach a
# service without being named, so the named-variable checks cannot see them.
FORBIDDEN = frozenset({"env_file", "include", "extends"})

MASTER_KEY_MARKER = "MASTERKEY"
MASTER_KEY_FLAG_PREFIX = "--masterkey"
MASTER_KEY_FILE_FLAG = "--masterkeyFile"
MASTER_KEY_FILE_PATH = "/run/secrets/zitadel-masterkey"

# Every service key the stack files carry today. A new key is added here on
# purpose, with the reason it cannot bring in another file's values.
ALLOWED_SERVICE_KEYS = {
    "command": "the phase the runtime runs; names no file",
    "cpu_shares": "scheduler weight; carries no value",
    "depends_on": "start order between the stack's own services",
    "environment": "named variables only; the checker refuses a master-key variable by name and the tests pin the named variables",
    "healthcheck": "the probe command; carries no value",
    "image": "the image reference, pinned by digest and checked by the tests",
    "mem_limit": "memory cap, checked against the measured budget",
    "oom_score_adj": "kill priority, checked by the tests",
    "ports": "published addresses, checked by the tests",
    "profiles": "gates the application services behind the apps profile",
    "restart": "restart policy; carries no value",
    "secrets": "secrets mounted as files from the top-level secrets block",
    "volumes": "bind mounts and named volumes, checked by the tests",
}


def environment_names(environment: object) -> list[str]:
    """The variable names an environment value sets: mapping keys, or list entries before '='."""
    if isinstance(environment, dict):
        return [str(key) for key in environment]
    if isinstance(environment, list):
        return [str(entry).split("=", 1)[0] for entry in environment]
    return []


def command_tokens(command: object) -> list[str]:
    """The arguments of a command; a string is split the way a shell would split it."""
    if isinstance(command, str):
        return shlex.split(command)
    if isinstance(command, list):
        return [str(item) for item in command]
    return []


def is_allowed_master_key_flag(tokens: list[str], index: int) -> bool:
    """True only for the exact pair --masterkeyFile /run/secrets/zitadel-masterkey."""
    following = tokens[index + 1] if index + 1 < len(tokens) else None
    return tokens[index] == MASTER_KEY_FILE_FLAG and following == MASTER_KEY_FILE_PATH


def environment_problems(name: str, service: dict[str, object], label: str) -> list[str]:
    """Master-key variables named in the environment. The value is never echoed."""
    return [
        (
            f"{label}: service '{name}' environment names '{variable}'; "
            "the master key is read from a secret file only"
        )
        for variable in environment_names(service.get("environment"))
        if MASTER_KEY_MARKER in variable.upper()
    ]


def command_problems(name: str, service: dict[str, object], label: str) -> list[str]:
    """Master-key flags in the command, failing closed when a string cannot be split."""
    try:
        tokens = command_tokens(service.get("command"))
    except ValueError:
        return [
            (
                f"{label}: service '{name}' command cannot be split into arguments; "
                "the master key flags cannot be checked"
            )
        ]
    return [
        f"{label}: service '{name}' command has '{token}'; "
        f"only '{MASTER_KEY_FILE_FLAG} {MASTER_KEY_FILE_PATH}' is accepted"
        for index, token in enumerate(tokens)
        if token.lower().startswith(MASTER_KEY_FLAG_PREFIX.lower())
        and not is_allowed_master_key_flag(tokens, index)
    ]


def service_problems(name, service, label):
    """Problems in one service: a file-pulling key, a key not on the allowlist, or a master key."""
    if not isinstance(service, dict):
        return [f"{label}: service '{name}' is not a mapping"]
    problems = []
    for key in service:
        if key in FORBIDDEN:
            problems.append(
                f"{label}: service '{name}' key '{key}' pulls another file in; "
                "env_file would reach the administrator credential past the "
                "named-variable check"
            )
        elif key not in ALLOWED_SERVICE_KEYS:
            problems.append(
                f"{label}: service '{name}' key '{key}' is not in "
                "ALLOWED_SERVICE_KEYS; add it there deliberately, with a reason"
            )
    problems.extend(environment_problems(name, service, label))
    problems.extend(command_problems(name, service, label))
    return problems


def violations(document, label):
    """Every problem in one parsed stack file, each naming its key."""
    if not isinstance(document, dict):
        return [f"{label}: the file is not a mapping"]
    problems = [
        f"{label}: top-level '{key}' pulls another file in" for key in document if key in FORBIDDEN
    ]
    for name, service in (document.get("services") or {}).items():
        if name in FORBIDDEN:
            problems.append(f"{label}: service named '{name}' pulls another file in")
        problems.extend(service_problems(name, service, label))
    return problems


def check_file(path):
    """Parse one stack file and return its problems. Raises if it cannot be read."""
    with open(path, encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    return violations(document, pathlib.Path(path).name)


def main(argv):
    if not argv:
        print("usage: stack_keys_check.py FILE...", file=sys.stderr)
        return 2
    problems = []
    for name in argv:
        try:
            problems.extend(check_file(name))
        except (OSError, yaml.YAMLError) as error:
            print(f"{name}: cannot read or parse: {error}", file=sys.stderr)
            return 2
    for line in problems:
        print(line)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
