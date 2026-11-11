#!/usr/bin/python
"""The control plane's preflight on a host it shares with Nextcloud (ANS-9).

Three read-only actions, none of which changes the host in check mode or out of it:

``collisions`` refuses a deploy whose Compose project name or volume name is Nextcloud's, before
anything starts. ``snapshot`` refuses a host that has too little free memory or free disk and
records the host's memory, disk and Nextcloud's containers, volumes and Compose project.
``compare`` records them again and fails if anything of Nextcloud's differs from the first record.

Nothing it returns holds a container's environment, a secret or the raw output of a command: the
one format string given to ``docker inspect`` names fields and never ``Config.Env``, because
Nextcloud's own containers carry credentials there.
"""

import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: control_plane_preflight
short_description: Preflight of the control plane's deploy on the host it shares with Nextcloud
description:
  - C(collisions) fails when a Compose project name, or the name of a volume that Compose files
      would create, is Nextcloud's. It reads no host state and starts nothing.
  - C(snapshot) fails when the memory available, or the free space on the root file system or on
      Docker's data root, is below its floor. It returns the memory, the disk and Nextcloud's
      containers, volumes and Compose project as a record.
  - C(compare) takes the record of an earlier C(snapshot), makes a new one and fails when
      Nextcloud's containers, volumes or Compose project differ.
  - Only reads, in check mode and out of it. Returns no environment variable and no secret.
version_added: "1.0.0"
author:
  - branchLeft
options:
  action:
    description: What to do.
    type: str
    required: true
    choices: [collisions, snapshot, compare]
  project_names:
    description: Compose project names the deploy is configured with, for C(collisions).
    type: list
    elements: str
    default: []
  compose_documents:
    description: >-
      The parsed Compose files of the stack, for C(collisions). A volume's name is its C(name) if
      it has one, else the project name, an underscore and its key.
    type: list
    elements: dict
    default: []
  default_project:
    description: The project name Compose uses when no file names one, for C(collisions).
    type: str
  stack_project:
    description: The Compose project of the stack being deployed, for C(snapshot) and C(compare).
    type: str
  min_available_memory_fresh_mib:
    description: The floor for the memory available, in MiB, while the stack has no container.
    type: int
  min_available_memory_running_mib:
    description: The floor for the memory available, in MiB, once the stack has a container.
    type: int
  min_free_disk_mib:
    description: The floor for the free space on each of the two file systems, in MiB.
    type: int
  before:
    description: The C(record) that C(snapshot) returned, for C(compare).
    type: dict
  proc_root:
    description: Where the memory is read. Only a test changes it.
    type: path
    default: /proc
attributes:
  check_mode:
    support: full
    description: Every action only reads, so check mode and a real run are the same.
  diff_mode:
    support: none
    description: Nothing is changed.
"""

EXAMPLES = r"""
- name: Refuse a floor breach before anything starts
  control_plane_preflight:
    action: snapshot
    stack_project: control-plane
    min_available_memory_fresh_mib: 2664
    min_available_memory_running_mib: 1000
    min_free_disk_mib: 5120
  register: before
"""

RETURN = r"""
record:
  description: >-
    For C(snapshot), the memory, disk, stack and Nextcloud readings. For C(compare), the same
    under C(before) and C(after).
  returned: when the action reads the host
  type: dict
"""

# Nextcloud's identity on ops1. The role's unit test holds these equal to the Compose file that
# declares them (hetzner/nextcloud1/stack/compose.yml), so a rename there fails a test here.
NEXTCLOUD_PROJECT = "nextcloud1"
NEXTCLOUD_VOLUME_KEYS = ("nextcloud-app", "nextcloud-db")
NEXTCLOUD_VOLUMES = frozenset(f"{NEXTCLOUD_PROJECT}_{key}" for key in NEXTCLOUD_VOLUME_KEYS)

PROJECT_LABEL = "com.docker.compose.project"
CONFIG_HASH_LABEL = "com.docker.compose.config-hash"
WORKING_DIR_LABEL = "com.docker.compose.project.working_dir"

# The only fields read from a container. No environment, no command line, no mount.
CONTAINER_FIELDS = (
    "id",
    "name",
    "created",
    "started_at",
    "status",
    "restarts",
    "image_id",
    "project",
    "config_hash",
    "working_dir",
    "health",
)
CONTAINER_FORMAT = "|".join(
    (
        "{{.Id}}",
        "{{.Name}}",
        "{{.Created}}",
        "{{.State.StartedAt}}",
        "{{.State.Status}}",
        "{{.RestartCount}}",
        "{{.Image}}",
        f'{{{{index .Config.Labels "{PROJECT_LABEL}"}}}}',
        f'{{{{index .Config.Labels "{CONFIG_HASH_LABEL}"}}}}',
        f'{{{{index .Config.Labels "{WORKING_DIR_LABEL}"}}}}',
        "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
    )
)
# Health is recorded and not compared: it moves with load and carries no change of identity.
# A restart or a recreate shows in the start time, the restart count, the id and the image.
RECORDED_ONLY_FIELDS = frozenset({"health"})

VOLUME_FIELDS = ("name", "created_at", "mountpoint", "project")
VOLUME_FORMAT = "|".join(
    (
        "{{.Name}}",
        "{{.CreatedAt}}",
        "{{.Mountpoint}}",
        f'{{{{index .Labels "{PROJECT_LABEL}"}}}}',
    )
)

MEBIBYTE = 1024 * 1024
MEMINFO_LINE = re.compile(r"(?P<key>[A-Za-z_()0-9]+):\s+(?P<value>\d+) kB\Z")
ACTIONS = ("collisions", "snapshot", "compare")

Runner = Callable[[Sequence[str]], tuple[int, str, str]]
Statvfs = Callable[[str], os.statvfs_result]
Record = dict[str, object]


class PreflightError(Exception):
    """A refusal. Its text is fixed words and names; it never carries a command's raw output."""

    def __init__(self, code: str, message: str, record: Record | None = None) -> None:
        super().__init__(f"control_plane preflight [{code}]: {message}")
        self.code = code
        self.record = record


@dataclass(frozen=True)
class Floors:
    """The three floors, in MiB."""

    memory_fresh: int
    memory_running: int
    disk: int


def compose_names(
    documents: Sequence[Mapping[str, object]], default_project: str
) -> tuple[set[str], set[str]]:
    """Return the project names the files name and the volume names they would create.

    A name that holds ``$`` is read from the environment when Compose runs, so it cannot be
    judged here and is refused.

    Raises:
        PreflightError: a project or volume name that cannot be known from the files.
    """
    projects = {default_project}
    named = [
        str(document["name"]) for document in documents if isinstance(document.get("name"), str)
    ]
    projects.update(named)
    project = named[0] if named else default_project
    volumes: set[str] = set()
    for document in documents:
        declared = document.get("volumes")
        if not isinstance(declared, Mapping):
            continue
        for key, value in declared.items():
            if isinstance(value, Mapping) and isinstance(value.get("name"), str):
                volumes.add(str(value["name"]))
            elif isinstance(value, Mapping) and value.get("external"):
                volumes.add(str(key))
            else:
                volumes.add(f"{project}_{key}")
    for name in projects | volumes:
        if "$" in name:
            raise PreflightError(
                "unverifiable-name",
                f"the name '{name}' is filled in when Compose runs, so it cannot be checked "
                "against Nextcloud's. Nothing was started.",
            )
    return projects, volumes


def refuse_collisions(
    project_names: Sequence[str],
    documents: Sequence[Mapping[str, object]],
    default_project: str,
) -> None:
    """Refuse a deploy configured with Nextcloud's project name or one of its volume names.

    Raises:
        PreflightError: the first collision found.
    """
    projects, volumes = compose_names(documents, default_project)
    projects.update(project_names)
    for name in sorted(projects):
        if name.lower() == NEXTCLOUD_PROJECT:
            raise PreflightError(
                "project-collision",
                f"the Compose project name '{name}' is Nextcloud's. Nothing was started.",
            )
    nextcloud_volumes = {name.lower() for name in NEXTCLOUD_VOLUMES}
    for name in sorted(volumes):
        if name.lower() in nextcloud_volumes:
            raise PreflightError(
                "volume-collision",
                f"the volume name '{name}' is one of Nextcloud's. Nothing was started.",
            )


def read_meminfo(proc_root: str) -> dict[str, int]:
    """Return the figures of /proc/meminfo, in KiB.

    Raises:
        PreflightError: the file cannot be read.
    """
    try:
        with open(os.path.join(proc_root, "meminfo"), encoding="ascii") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError) as error:
        raise PreflightError(
            "memory-unreadable", "the memory figures could not be read."
        ) from error
    figures: dict[str, int] = {}
    for line in text.splitlines():
        match = MEMINFO_LINE.match(line)
        if match:
            figures[match.group("key")] = int(match.group("value"))
    for needed in ("MemAvailable", "SwapTotal"):
        if needed not in figures:
            raise PreflightError("memory-unreadable", f"the memory figures hold no {needed}.")
    return figures


def free_mib(path: str, statvfs: Statvfs) -> int:
    """Return the space an unprivileged writer can still use on the file system of path, in MiB.

    Raises:
        PreflightError: the path cannot be read.
    """
    try:
        stat = statvfs(path)
    except OSError as error:
        raise PreflightError(
            "disk-unreadable", f"the free space of '{path}' could not be read."
        ) from error
    return stat.f_bavail * stat.f_frsize // MEBIBYTE


def docker_lines(run: Runner, argv: Sequence[str], what: str) -> list[str]:
    """Return the output lines of a docker command that must succeed.

    Raises:
        PreflightError: the command failed.
    """
    code, stdout, _ = run(argv)
    if code != 0:
        raise PreflightError("docker-unreadable", f"docker could not {what}.")
    return [line for line in stdout.splitlines() if line.strip()]


def project_container_ids(run: Runner, docker: str, project: str) -> list[str]:
    """Return the ids of every container, running or not, that belongs to a Compose project."""
    return sorted(
        docker_lines(
            run,
            [
                docker,
                "ps",
                "--all",
                "--no-trunc",
                "--quiet",
                "--filter",
                f"label={PROJECT_LABEL}={project}",
            ],
            f"list the containers of the project {project}",
        )
    )


def inspect_containers(run: Runner, docker: str, ids: Sequence[str]) -> list[dict[str, str]]:
    """Return the fixed fields of each container, ordered by name.

    Raises:
        PreflightError: docker failed or answered in another shape.
    """
    if not ids:
        return []
    lines = docker_lines(
        run, [docker, "inspect", "--format", CONTAINER_FORMAT, *ids], "inspect the containers"
    )
    containers = []
    for line in lines:
        parts = line.split("|")
        if len(parts) != len(CONTAINER_FIELDS):
            raise PreflightError(
                "docker-unreadable", "docker answered an inspect in an unknown shape."
            )
        entry = dict(zip(CONTAINER_FIELDS, parts, strict=True))
        entry["name"] = entry["name"].lstrip("/")
        containers.append(entry)
    return sorted(containers, key=lambda entry: entry["name"])


def inspect_volumes(run: Runner, docker: str) -> list[dict[str, str]]:
    """Return the fixed fields of each of Nextcloud's volumes, ordered by name.

    A volume is Nextcloud's when it is one of its two named volumes or its name starts with the
    project name and an underscore.

    Raises:
        PreflightError: docker failed or answered in another shape.
    """
    names = [
        name.strip()
        for name in docker_lines(run, [docker, "volume", "ls", "--quiet"], "list the volumes")
        if name.strip() in NEXTCLOUD_VOLUMES or name.strip().startswith(f"{NEXTCLOUD_PROJECT}_")
    ]
    if not names:
        return []
    lines = docker_lines(
        run,
        [docker, "volume", "inspect", "--format", VOLUME_FORMAT, *sorted(names)],
        "inspect the volumes",
    )
    volumes = []
    for line in lines:
        parts = line.split("|")
        if len(parts) != len(VOLUME_FIELDS):
            raise PreflightError(
                "docker-unreadable", "docker answered a volume inspect in an unknown shape."
            )
        volumes.append(dict(zip(VOLUME_FIELDS, parts, strict=True)))
    return sorted(volumes, key=lambda entry: entry["name"])


def nextcloud_record(run: Runner, docker: str) -> Record:
    """Return Nextcloud's containers, volumes and Compose project as the host holds them now."""
    containers = inspect_containers(
        run, docker, project_container_ids(run, docker, NEXTCLOUD_PROJECT)
    )
    return {
        "project": NEXTCLOUD_PROJECT,
        "projects_seen": sorted({entry["project"] for entry in containers}),
        "containers": containers,
        "volumes": inspect_volumes(run, docker),
    }


def docker_root(run: Runner, docker: str) -> str:
    """Return Docker's data root.

    Raises:
        PreflightError: docker failed.
    """
    lines = docker_lines(
        run, [docker, "info", "--format", "{{.DockerRootDir}}"], "report its data root"
    )
    if len(lines) != 1 or not lines[0].startswith("/"):
        raise PreflightError("docker-unreadable", "docker named no data root.")
    return lines[0].strip()


def host_record(
    run: Runner, docker: str, stack_project: str, proc_root: str, statvfs: Statvfs
) -> Record:
    """Read the memory, the disk, the stack's containers and Nextcloud's, and change nothing."""
    figures = read_meminfo(proc_root)
    root = docker_root(run, docker)
    disk = {"/": free_mib("/", statvfs), root: free_mib(root, statvfs)}
    return {
        "memory": {
            "available_mib": figures["MemAvailable"] // 1024,
            "swap_total_mib": figures["SwapTotal"] // 1024,
        },
        "disk_free_mib": disk,
        "stack": {
            "project": stack_project,
            "containers": len(project_container_ids(run, docker, stack_project)),
        },
        "nextcloud": nextcloud_record(run, docker),
    }


def judge_floors(record: Record, floors: Floors) -> None:
    """Refuse a record whose memory or disk is under its floor.

    Raises:
        PreflightError: the first floor not met, with the whole record attached.
    """
    memory = record["memory"]
    stack = record["stack"]
    disk = record["disk_free_mib"]
    if not (isinstance(memory, dict) and isinstance(stack, dict) and isinstance(disk, dict)):
        raise PreflightError("internal", "the record has an unexpected shape.")
    running = int(stack["containers"]) > 0
    floor = floors.memory_running if running else floors.memory_fresh
    record["floors"] = {
        "memory_available_mib": floor,
        "disk_free_mib": floors.disk,
        "stack_running": running,
    }
    if int(memory["available_mib"]) < floor:
        raise PreflightError(
            "memory-low",
            f"{memory['available_mib']} MiB of memory is available and the floor is {floor} MiB. "
            "Nothing was started.",
            record,
        )
    for path, free in sorted(disk.items()):
        if int(free) < floors.disk:
            raise PreflightError(
                "disk-low",
                f"{free} MiB is free on '{path}' and the floor is {floors.disk} MiB. "
                "Nothing was started.",
                record,
            )


def differences(before: Mapping[str, object], after: Mapping[str, object]) -> list[str]:
    """Return what differs between two records of Nextcloud, naming each container or volume."""
    found: list[str] = []
    if before.get("projects_seen") != after.get("projects_seen"):
        found.append("the Compose project of its containers")
    for kind, fields in (("containers", CONTAINER_FIELDS), ("volumes", VOLUME_FIELDS)):
        old = {str(entry["name"]): entry for entry in _entries(before, kind)}
        new = {str(entry["name"]): entry for entry in _entries(after, kind)}
        singular = kind.removesuffix("s")
        for name in sorted(old.keys() - new.keys()):
            found.append(f"{singular} {name} is gone")
        for name in sorted(new.keys() - old.keys()):
            found.append(f"{singular} {name} is new")
        for name in sorted(old.keys() & new.keys()):
            for field in fields:
                if field not in RECORDED_ONLY_FIELDS and old[name].get(field) != new[name].get(
                    field
                ):
                    found.append(f"{singular} {name}: {field} differs")
    return found


def _entries(record: Mapping[str, object], kind: str) -> list[Mapping[str, object]]:
    """Return the container or volume entries of a Nextcloud record."""
    entries = record.get(kind)
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, Mapping)]


def compare(
    before: Mapping[str, object],
    run: Runner,
    docker: str,
    stack_project: str,
    proc_root: str,
    statvfs: Statvfs,
) -> Record:
    """Record the host again and fail if Nextcloud differs from the earlier record.

    Raises:
        PreflightError: Nextcloud's containers, volumes or Compose project changed.
    """
    earlier = before.get("nextcloud")
    if not isinstance(earlier, Mapping):
        raise PreflightError("before-missing", "the earlier record holds no Nextcloud reading.")
    after = host_record(run, docker, stack_project, proc_root, statvfs)
    record: Record = {"before": dict(before), "after": after}
    now = after["nextcloud"]
    if not isinstance(now, Mapping):
        raise PreflightError("internal", "the record has an unexpected shape.")
    changed = differences(earlier, now)
    if changed:
        raise PreflightError("nextcloud-changed", "Nextcloud's " + "; ".join(changed) + ".", record)
    return record


def as_documents(raw: object) -> list[Mapping[str, object]]:
    """Return the dictionaries of a list argument."""
    return [item for item in raw if isinstance(item, Mapping)] if isinstance(raw, list) else []


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(
        argument_spec={
            "action": {"type": "str", "required": True, "choices": list(ACTIONS)},
            "project_names": {"type": "list", "elements": "str", "default": []},
            "compose_documents": {"type": "list", "elements": "dict", "default": []},
            "default_project": {"type": "str"},
            "stack_project": {"type": "str"},
            "min_available_memory_fresh_mib": {"type": "int"},
            "min_available_memory_running_mib": {"type": "int"},
            "min_free_disk_mib": {"type": "int"},
            "before": {"type": "dict"},
            "proc_root": {"type": "path", "default": "/proc"},
        },
        required_if=[
            ("action", "collisions", ["default_project"]),
            (
                "action",
                "snapshot",
                [
                    "stack_project",
                    "min_available_memory_fresh_mib",
                    "min_available_memory_running_mib",
                    "min_free_disk_mib",
                ],
            ),
            ("action", "compare", ["stack_project", "before"]),
        ],
        supports_check_mode=True,
    )
    params = module.params

    def run(argv: Sequence[str]) -> tuple[int, str, str]:
        code, stdout, stderr = module.run_command(list(argv), check_rc=False)
        return int(code), str(stdout), str(stderr)

    try:
        if params["action"] == "collisions":
            refuse_collisions(
                [str(name) for name in params["project_names"]],
                as_documents(params["compose_documents"]),
                str(params["default_project"]),
            )
            module.exit_json(changed=False)
        docker = module.get_bin_path("docker", required=True)
        if params["action"] == "snapshot":
            record = host_record(
                run, docker, str(params["stack_project"]), params["proc_root"], os.statvfs
            )
            judge_floors(
                record,
                Floors(
                    int(params["min_available_memory_fresh_mib"]),
                    int(params["min_available_memory_running_mib"]),
                    int(params["min_free_disk_mib"]),
                ),
            )
        else:
            record = compare(
                params["before"],
                run,
                docker,
                str(params["stack_project"]),
                params["proc_root"],
                os.statvfs,
            )
    except PreflightError as error:
        if error.record is None:
            module.fail_json(msg=str(error))
        module.fail_json(msg=str(error), record=error.record)
    else:
        module.exit_json(changed=False, record=record)


if __name__ == "__main__":
    main()
