#!/usr/bin/env python3
"""A stand-in for the docker command line, for the edge ban owner program and its molecule run.

It answers exactly the four calls the program makes and exits 64 for anything else, so a test that
passes has proved the program sent those argument lists and no others:

  ps -q --filter label=com.docker.compose.project=P --filter label=com.docker.compose.service=S
  exec ID ls -1 -- DIRECTORY
  exec ID cat -- FILE
  exec ID cscli decisions list -o json --limit 0

Container paths map into `fake-root/` beside this file. `fake-root/cscli.json` is what cscli
prints and `fake-root/cscli.rc` (an integer, default 0) is its exit status. Two containers exist:
`fakecaddy` (service caddy) answers ls and cat, `fakecrowdsec` (service crowdsec) answers cscli.
It needs no environment, because a systemd service has none.
"""

import sys
from pathlib import Path

PROJECT = "edge"
CONTAINERS = {"caddy": "fakecaddy", "crowdsec": "fakecrowdsec"}
EXIT_USAGE = 64
EXIT_FAILED = 1

PS_PREFIX = ["ps", "-q", "--filter"]
LABEL_PROJECT = "label=com.docker.compose.project="
LABEL_SERVICE = "label=com.docker.compose.service="
CSCLI_ARGUMENTS = ["cscli", "decisions", "list", "-o", "json", "--limit", "0"]


def root() -> Path:
    return Path(__file__).resolve().parent / "fake-root"


def inside_root(container_path: str) -> Path | None:
    """The file a container path stands for, or None when it is not absolute or climbs out."""
    if not container_path.startswith("/") or ".." in Path(container_path).parts:
        return None
    return root() / container_path.lstrip("/")


def list_containers(arguments: list[str]) -> int:
    """Answers `ps`; a project or service it does not know prints nothing, as docker does."""
    if len(arguments) != 6 or arguments[:3] != PS_PREFIX or arguments[4] != "--filter":
        return EXIT_USAGE
    project_label, service_label = arguments[3], arguments[5]
    if not project_label.startswith(LABEL_PROJECT) or not service_label.startswith(LABEL_SERVICE):
        return EXIT_USAGE
    project = project_label.removeprefix(LABEL_PROJECT)
    service = service_label.removeprefix(LABEL_SERVICE)
    if project == PROJECT and service in CONTAINERS:
        sys.stdout.write(CONTAINERS[service] + "\n")
    return 0


def list_directory(path: str) -> int:
    target = inside_root(path)
    if target is None or not target.is_dir():
        sys.stderr.write("ls: cannot access directory\n")
        return EXIT_FAILED
    for name in sorted(entry.name for entry in target.iterdir()):
        sys.stdout.write(name + "\n")
    return 0


def print_file(path: str) -> int:
    target = inside_root(path)
    if target is None or not target.is_file():
        sys.stderr.write("cat: cannot open file\n")
        return EXIT_FAILED
    sys.stdout.buffer.write(target.read_bytes())
    sys.stdout.buffer.flush()
    return 0


def run_cscli() -> int:
    status_file = root() / "cscli.rc"
    status = int(status_file.read_text().strip()) if status_file.is_file() else 0
    if status != 0:
        sys.stderr.write("cscli: simulated failure\n")
        return status
    sys.stdout.buffer.write((root() / "cscli.json").read_bytes())
    sys.stdout.buffer.flush()
    return 0


def execute(arguments: list[str]) -> int:
    """Answers `exec ID ...`; the arguments exclude the leading `exec`."""
    if len(arguments) < 2:
        return EXIT_USAGE
    container, command = arguments[0], arguments[1:]
    if container == CONTAINERS["caddy"]:
        if len(command) == 4 and command[:3] == ["ls", "-1", "--"]:
            return list_directory(command[3])
        if len(command) == 3 and command[:2] == ["cat", "--"]:
            return print_file(command[2])
    if container == CONTAINERS["crowdsec"] and command == CSCLI_ARGUMENTS:
        return run_cscli()
    return EXIT_USAGE


def main(arguments: list[str]) -> int:
    if arguments[:1] == ["ps"]:
        return list_containers(arguments)
    if arguments[:1] == ["exec"]:
        return execute(arguments[1:])
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
