"""Unit tests for control_plane_preflight, the module that guards the host Nextcloud shares.

The module refuses a deploy configured with Nextcloud's project or volume names, refuses a host
short of memory or disk, and fails when Nextcloud's containers, volumes or Compose project differ
after the deploy. Docker is a fake that answers from tables, and the host's memory and disk are
files and a function made by each test: nothing here reads or changes a real host.

Each refusal has a sabotage control, named in its test's docstring: break the check it names and
that test goes red. The README gives the command, with the files and library directories on
PYTHONPATH.
"""

import contextlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable, Iterator, Mapping, Sequence
from functools import partial
from pathlib import Path

import control_plane_preflight as preflight
from ansible.module_utils.testing import patch_module_args
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
REPOSITORY = ROLE.parents[2]
STACK = REPOSITORY / "hetzner" / "control-plane" / "stack"
NEXTCLOUD_COMPOSE = REPOSITORY / "hetzner" / "nextcloud1" / "stack" / "compose.yml"
TASKS = ROLE / "tasks" / "main.yml"
VARS = ROLE / "vars" / "main.yml"

ROOT_DIR = "/var/lib/docker"
STACK_PROJECT = "control-plane"
FLOORS = preflight.Floors(memory_fresh=2664, memory_running=1000, disk=5120)
Fields = dict[str, str]


def load_mapping(path: Path) -> dict[str, object]:
    """Return a YAML file's top-level mapping.

    Raises:
        TypeError: the file is not a mapping.
    """
    loaded: object = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        message = f"{path} is not a mapping"
        raise TypeError(message)
    return {str(key): value for key, value in loaded.items()}


def section(task: Mapping[str, object], key: str) -> Mapping[str, object]:
    """Return a task's module arguments, which the test has just found there.

    Raises:
        TypeError: the task has no such mapping.
    """
    found = task.get(key)
    if not isinstance(found, Mapping):
        message = f"{key} is not a mapping in {task.get('name')!r}"
        raise TypeError(message)
    return found


def real_documents() -> list[Mapping[str, object]]:
    """Return the two Compose files the role delivers, parsed."""
    return [load_mapping(STACK / "compose.yml"), load_mapping(STACK / "compose.init.yml")]


def container(name: str, project: str, **changes: str) -> Fields:
    """Return a container's fixed fields."""
    fields = {
        "id": f"id-{name}",
        "name": name,
        "created": "2026-10-01T10:00:00.000000000Z",
        "started_at": "2026-10-01T10:00:05.000000000Z",
        "status": "running",
        "restarts": "0",
        "image_id": f"sha256:image-{name}",
        "project": project,
        "config_hash": f"hash-{name}",
        "working_dir": f"/opt/branchleft/{project}",
        "health": "healthy",
    }
    fields.update(changes)
    return fields


def volume(name: str, **changes: str) -> Fields:
    """Return a volume's fixed fields."""
    fields = {
        "name": name,
        "created_at": "2026-10-01T10:00:00Z",
        "mountpoint": f"{ROOT_DIR}/volumes/{name}/_data",
        "project": name.split("_", 1)[0],
    }
    fields.update(changes)
    return fields


def nextcloud_containers() -> list[Fields]:
    """Return Nextcloud's three containers as the host runs them."""
    return [container(f"nextcloud1-{part}-1", "nextcloud1") for part in ("app", "db", "redis")]


def nextcloud_volumes() -> list[Fields]:
    """Return Nextcloud's two volumes as the host holds them."""
    return [volume("nextcloud1_nextcloud-app"), volume("nextcloud1_nextcloud-db")]


class FakeDocker:
    """A docker that answers the commands the module sends, from tables, and records them."""

    def __init__(
        self,
        containers: Sequence[Fields] | None = None,
        volumes: Sequence[Fields] | None = None,
        *,
        failing: str | None = None,
    ) -> None:
        self.containers = list(containers if containers is not None else nextcloud_containers())
        self.volumes = list(volumes if volumes is not None else nextcloud_volumes())
        self.failing = failing
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str]) -> tuple[int, str, str]:
        """Answer one command.

        Raises:
            AssertionError: the module sent a command or a format the tests do not expect.
        """
        words = list(argv)
        self.calls.append(words)
        verb = " ".join(words[1:3])
        if self.failing is not None and self.failing in " ".join(words):
            return 1, "", "boom"
        if verb == "info --format":
            return 0, f"{ROOT_DIR}\n", ""
        if verb == "ps --all":
            project = words[-1].rsplit("=", 1)[1]
            return (
                0,
                "".join(f"{c['id']}\n" for c in self.containers if c["project"] == project),
                "",
            )
        if verb == "inspect --format":
            if words[3] != preflight.CONTAINER_FORMAT:
                raise AssertionError(words[3])
            rows = [c for i in words[4:] for c in self.containers if c["id"] == i]
            return 0, "".join(self.container_line(c) for c in rows), ""
        if verb == "volume ls":
            return 0, "".join(f"{v['name']}\n" for v in self.volumes) + "unrelated_volume\n", ""
        if verb == "volume inspect":
            if words[4] != preflight.VOLUME_FORMAT:
                raise AssertionError(words[4])
            rows = [v for n in words[5:] for v in self.volumes if v["name"] == n]
            return (
                0,
                "".join("|".join(v[f] for f in preflight.VOLUME_FIELDS) + "\n" for v in rows),
                "",
            )
        message = f"the module sent a command the test does not know: {words}"
        raise AssertionError(message)

    @staticmethod
    def container_line(fields: Fields) -> str:
        """Return the line docker prints for one container: the name has a leading slash."""
        shown = {**fields, "name": "/" + fields["name"]}
        return "|".join(shown[field] for field in preflight.CONTAINER_FIELDS) + "\n"


def statvfs_for(free: Mapping[str, int]) -> preflight.Statvfs:
    """Return a statvfs function that reports the given free MiB per path."""

    def statvfs(path: str) -> os.statvfs_result:
        mib = free[path]
        return os.statvfs_result((4096, 4096, 10**9, 10**9, mib * 256, 0, 0, 0, 0, 255))

    return statvfs


@contextlib.contextmanager
def proc_with(available_mib: int, swap_mib: int = 0) -> Iterator[str]:
    """Make a directory with a meminfo file and yield it."""
    with tempfile.TemporaryDirectory() as directory:
        text = (
            f"MemTotal:        3918000 kB\nMemAvailable:    {available_mib * 1024} kB\n"
            f"SwapTotal:       {swap_mib * 1024} kB\nSwapFree:               0 kB\n"
        )
        Path(directory, "meminfo").write_text(text, encoding="ascii")
        yield directory


@contextlib.contextmanager
def environment(**changes: str) -> Iterator[None]:
    """Set environment variables for a block and put them back."""
    saved = {name: os.environ.get(name) for name in changes}
    os.environ.update(changes)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def run_module(params: Mapping[str, object]) -> tuple[bool, dict[str, object]]:
    """Run the module's main the way Ansible does; return (failed, the JSON it printed)."""
    buffer = io.StringIO()
    args = {**params, "_ansible_check_mode": True}
    with patch_module_args(args), contextlib.redirect_stdout(buffer):
        with contextlib.suppress(SystemExit):
            preflight.main()
    document = json.loads(buffer.getvalue())
    return bool(document.get("failed")), document


def snapshot(
    docker: FakeDocker,
    *,
    available: int = 3009,
    free: Mapping[str, int] | None = None,
    stack: Sequence[Fields] = (),
) -> preflight.Record:
    """Take a record and judge it against the floors."""
    docker.containers.extend(stack)
    disk = free if free is not None else {"/": 27316, ROOT_DIR: 27316}
    with proc_with(available) as proc:
        record = preflight.host_record(docker, "docker", STACK_PROJECT, proc, statvfs_for(disk))
    preflight.judge_floors(record, FLOORS)
    return record


def refusal_of(call: Callable[[], object]) -> preflight.PreflightError:
    """Run a call that must refuse and return the refusal.

    Raises:
        AssertionError: the call did not refuse.
    """
    try:
        call()
    except preflight.PreflightError as error:
        return error
    message = "the call did not refuse"
    raise AssertionError(message)


class CollisionTests(unittest.TestCase):
    """A deploy configured with Nextcloud's project or volume names is refused."""

    def check(self, names: Sequence[str], documents: Sequence[Mapping[str, object]]) -> None:
        """Run the collision check as the role does."""
        preflight.refuse_collisions(names, documents, STACK_PROJECT)

    def test_the_stack_as_committed_is_accepted(self) -> None:
        """The control case: the real files and the role's own names pass."""
        self.check([STACK_PROJECT, STACK_PROJECT, STACK_PROJECT], real_documents())

    def test_nextcloud_project_name_in_the_role_is_refused(self) -> None:
        """Sabotage: delete the project-name loop in refuse_collisions and this goes red."""
        error = refusal_of(lambda: self.check(["nextcloud1"], real_documents()))
        self.assertEqual(error.code, "project-collision")

    def test_nextcloud_project_name_in_a_compose_file_is_refused(self) -> None:
        """Sabotage: stop reading the `name` of a document and this goes red."""
        documents = [{"name": "nextcloud1", "services": {}}]
        error = refusal_of(lambda: self.check([STACK_PROJECT], documents))
        self.assertEqual(error.code, "project-collision")

    def test_the_project_name_is_compared_without_regard_to_case(self) -> None:
        """Compose lower-cases a project name, so NextCloud1 is Nextcloud's."""
        error = refusal_of(lambda: self.check(["NextCloud1"], real_documents()))
        self.assertEqual(error.code, "project-collision")

    def test_each_of_nextclouds_volume_names_is_refused(self) -> None:
        """Sabotage: empty NEXTCLOUD_VOLUMES and both cases go red."""
        for name in sorted(preflight.NEXTCLOUD_VOLUMES):
            documents = [{"name": STACK_PROJECT, "volumes": {"data": {"name": name}}}]
            error = refusal_of(partial(self.check, [STACK_PROJECT], documents))
            self.assertEqual(error.code, "volume-collision", name)

    def test_an_external_volume_of_nextclouds_is_refused(self) -> None:
        """An external volume is named by its key, so the key `nextcloud1_nextcloud-db` collides."""
        volumes = {"nextcloud1_nextcloud-db": {"external": True}}
        documents = [{"name": STACK_PROJECT, "volumes": volumes}]
        error = refusal_of(lambda: self.check([STACK_PROJECT], documents))
        self.assertEqual(error.code, "volume-collision")

    def test_a_volume_key_alone_is_not_a_collision_under_another_project(self) -> None:
        """Compose prefixes the key with the project: `nextcloud-db` becomes control-plane_..."""
        self.check([STACK_PROJECT], [{"name": STACK_PROJECT, "volumes": {"nextcloud-db": None}}])

    def test_a_name_filled_in_at_run_time_is_refused(self) -> None:
        """A name that holds `$` is not known from the file, so it cannot be shown to differ."""
        named_volume = {"name": STACK_PROJECT, "volumes": {"data": {"name": "${VOLUME}"}}}
        for documents in ([{"name": "${PROJECT}"}], [named_volume]):
            error = refusal_of(partial(self.check, [STACK_PROJECT], documents))
            self.assertEqual(error.code, "unverifiable-name")

    def test_the_constants_equal_what_nextcloud_declares(self) -> None:
        """Sabotage: rename the project or a volume in the Nextcloud file and this goes red."""
        compose = load_mapping(NEXTCLOUD_COMPOSE)
        volumes = compose["volumes"]
        if not isinstance(volumes, dict):
            self.fail("the Nextcloud file declares no volumes")
        self.assertEqual(compose["name"], preflight.NEXTCLOUD_PROJECT)
        self.assertEqual(sorted(volumes), sorted(preflight.NEXTCLOUD_VOLUME_KEYS))

    def test_the_module_refuses_through_ansible_with_the_message_and_no_record(self) -> None:
        """The refusal as Ansible receives it: failed, with the code."""
        failed, document = run_module(
            {
                "action": "collisions",
                "default_project": STACK_PROJECT,
                "project_names": ["nextcloud1"],
                "compose_documents": [{"name": STACK_PROJECT}],
            }
        )
        self.assertTrue(failed)
        self.assertIn("[project-collision]", str(document["msg"]))
        self.assertNotIn("record", document)
        passed, _ = run_module(
            {"action": "collisions", "default_project": STACK_PROJECT, "project_names": ["x"]}
        )
        self.assertFalse(passed)


class FloorTests(unittest.TestCase):
    """A host short of memory or disk is refused."""

    def test_a_host_with_room_is_accepted_and_recorded(self) -> None:
        """The control case: the owner's own reading of ops1 passes."""
        record = snapshot(FakeDocker())
        self.assertEqual(record["memory"], {"available_mib": 3009, "swap_total_mib": 0})
        self.assertEqual(record["disk_free_mib"], {"/": 27316, ROOT_DIR: 27316})

    def test_memory_one_below_the_fresh_floor_is_refused_and_at_it_is_not(self) -> None:
        """Sabotage: change `<` to `<=` or drop the memory test and a case goes red."""
        snapshot(FakeDocker(), available=2664)
        error = refusal_of(lambda: snapshot(FakeDocker(), available=2663))
        self.assertEqual(error.code, "memory-low")
        self.assertIsNotNone(error.record)

    def test_a_running_stack_needs_less_than_a_fresh_one(self) -> None:
        """The floor is 1000 once a stack container exists, 2664 before: 2000 passes only then."""
        running = [container("control-plane-db-1", STACK_PROJECT)]
        snapshot(FakeDocker(), available=2000, stack=running)
        fresh = refusal_of(lambda: snapshot(FakeDocker(), available=2000))
        self.assertEqual(fresh.code, "memory-low")
        low = refusal_of(lambda: snapshot(FakeDocker(), available=999, stack=running))
        self.assertEqual(low.code, "memory-low")

    def test_disk_below_the_floor_on_either_file_system_is_refused(self) -> None:
        """Sabotage: check only `/` (or only Docker's root) and one of these goes red."""
        for free in ({"/": 5119, ROOT_DIR: 27316}, {"/": 27316, ROOT_DIR: 5119}):
            error = refusal_of(partial(snapshot, FakeDocker(), free=free))
            self.assertEqual(error.code, "disk-low", free)
        snapshot(FakeDocker(), free={"/": 5120, ROOT_DIR: 5120})

    def test_a_host_that_cannot_be_read_is_refused_not_passed(self) -> None:
        """An unreadable figure is a refusal: a check that cannot see must not say yes."""
        for failing in ("info --format", "inspect --format"):
            error = refusal_of(partial(snapshot, FakeDocker(failing=failing)))
            self.assertEqual(error.code, "docker-unreadable", failing)
        with tempfile.TemporaryDirectory() as empty:
            error = refusal_of(
                lambda: preflight.host_record(
                    FakeDocker(), "docker", STACK_PROJECT, empty, statvfs_for({})
                )
            )
        self.assertEqual(error.code, "memory-unreadable")

    def test_the_module_refuses_through_ansible_when_docker_cannot_be_read(self) -> None:
        """The refusal as Ansible receives it, with a docker on PATH that always fails."""
        with tempfile.TemporaryDirectory() as directory, proc_with(1500) as proc:
            fake = Path(directory, "docker")
            fake.write_text(f"#!{sys.executable}\nraise SystemExit(1)\n", encoding="utf-8")
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            with environment(PATH=directory):
                failed, document = run_module(
                    {
                        "action": "snapshot",
                        "stack_project": STACK_PROJECT,
                        "min_available_memory_fresh_mib": 2664,
                        "min_available_memory_running_mib": 1000,
                        "min_free_disk_mib": 5120,
                        "proc_root": proc,
                    }
                )
        self.assertTrue(failed)
        self.assertIn("[docker-unreadable]", str(document["msg"]))


class RecordTests(unittest.TestCase):
    """Nextcloud's record before and after: any change of its own fails the deploy."""

    def compare(self, before: preflight.Record, after: FakeDocker) -> preflight.Record:
        """Compare a new reading of the fake against an earlier record."""
        disk = statvfs_for({"/": 27316, ROOT_DIR: 27316})
        with proc_with(3000) as proc:
            return preflight.compare(before, after, "docker", STACK_PROJECT, proc, disk)

    def test_an_unchanged_nextcloud_passes_and_both_records_are_returned(self) -> None:
        """The control case."""
        record = self.compare(snapshot(FakeDocker()), FakeDocker())
        self.assertEqual(set(record), {"before", "after"})

    def test_the_record_holds_memory_disk_containers_volumes_and_project(self) -> None:
        """What the node asks to be recorded is in the record."""
        record = snapshot(FakeDocker())
        nextcloud = record["nextcloud"]
        if not isinstance(nextcloud, dict):
            self.fail("the record holds no Nextcloud reading")
        self.assertEqual(set(record), {"memory", "disk_free_mib", "stack", "nextcloud", "floors"})
        self.assertEqual(nextcloud["project"], "nextcloud1")
        self.assertEqual(nextcloud["projects_seen"], ["nextcloud1"])
        self.assertEqual(len(nextcloud["containers"]), 3)
        self.assertEqual(len(nextcloud["volumes"]), 2)

    def test_each_kind_of_change_to_nextcloud_fails(self) -> None:
        """Sabotage: make `differences` return [] and every case below goes red."""
        app, others = nextcloud_containers()[0], nextcloud_containers()[1:]
        volumes = nextcloud_volumes()
        recreated = container("nextcloud1-app-1", "nextcloud1", id="id-new")
        again = {**app, "started_at": "2026-11-09T10:00:00Z"}
        extra = container("nextcloud1-x-1", "nextcloud1")
        cases: dict[str, tuple[list[Fields], list[Fields]]] = {
            "a container recreated": ([recreated, *others], volumes),
            "a container gone": (others, volumes),
            "a container added": ([app, *others, extra], volumes),
            "a container stopped": ([{**app, "status": "exited"}, *others], volumes),
            "a container restarted": ([{**app, "restarts": "1"}, *others], volumes),
            "a container started again": ([again, *others], volumes),
            "a configuration changed": ([{**app, "config_hash": "changed"}, *others], volumes),
            "a container's project": ([{**app, "project": "other"}, *others], volumes),
            "a volume gone": ([app, *others], volumes[:1]),
            "a volume recreated": (
                [app, *others],
                [{**volumes[0], "created_at": "2026-11-09T10:00:00Z"}, volumes[1]],
            ),
        }
        before = snapshot(FakeDocker())
        for label, (containers, kept) in cases.items():
            error = refusal_of(partial(self.compare, before, FakeDocker(containers, kept)))
            self.assertEqual(error.code, "nextcloud-changed", label)
            self.assertIsNotNone(error.record, label)

    def test_a_change_of_health_alone_is_recorded_and_does_not_fail(self) -> None:
        """Health moves with load; a restart shows in the start time and the count instead."""
        slow = nextcloud_containers()
        slow[0] = container("nextcloud1-app-1", "nextcloud1", health="starting")
        record = self.compare(snapshot(FakeDocker()), FakeDocker(slow))
        self.assertIn("starting", json.dumps(record))

    def test_the_stack_gaining_containers_is_not_a_change_of_nextcloud(self) -> None:
        """The deploy adds the stack's containers; only Nextcloud's own must stay put."""
        stack = [container(f"control-plane-{part}-1", STACK_PROJECT) for part in ("db", "zitadel")]
        self.compare(snapshot(FakeDocker()), FakeDocker([*nextcloud_containers(), *stack]))

    def test_an_earlier_record_without_nextcloud_is_refused(self) -> None:
        """A comparison with nothing to compare against must not pass."""
        error = refusal_of(lambda: self.compare({"memory": {}}, FakeDocker()))
        self.assertEqual(error.code, "before-missing")

    def test_only_reads_are_sent_to_docker_and_no_environment_is_asked_for(self) -> None:
        """Nextcloud's containers hold credentials in their environment: no command asks for it."""
        docker = FakeDocker()
        self.compare(snapshot(docker), docker)
        allowed = {"info --format", "ps --all", "inspect --format", "volume ls", "volume inspect"}
        for call in docker.calls:
            self.assertIn(" ".join(call[1:3]), allowed, call)
        for text in (preflight.CONTAINER_FORMAT, preflight.VOLUME_FORMAT):
            self.assertNotIn("Env", text)
            self.assertNotIn(".Config.Cmd", text)
        labels = re.findall(r'index \.Config\.Labels "([^"]+)"', preflight.CONTAINER_FORMAT)
        self.assertEqual(
            sorted(labels),
            sorted(
                [
                    "com.docker.compose.project",
                    "com.docker.compose.config-hash",
                    "com.docker.compose.project.working_dir",
                ]
            ),
        )


class RoleWiringTests(unittest.TestCase):
    """The role calls the module first and last, with floors that a caller cannot move."""

    def setUp(self) -> None:
        """Make a scratch directory for the playbook of the end-to-end tests."""
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)

    def tasks(self) -> list[dict[str, object]]:
        """Return the role's tasks, parsed."""
        loaded: object = YAML(typ="safe").load(TASKS.read_text(encoding="utf-8"))
        if not isinstance(loaded, list):
            self.fail("tasks/main.yml is not a list")
        return [task for task in loaded if isinstance(task, dict)]

    def test_the_collision_check_is_the_first_task_and_runs_on_every_host(self) -> None:
        """Sabotage: move it below the first write, or gate it, and this goes red."""
        first = self.tasks()[0]
        self.assertEqual(section(first, "control_plane_preflight")["action"], "collisions")
        self.assertNotIn("when", first)

    def test_the_snapshot_comes_second_and_is_registered_for_the_comparison(self) -> None:
        """The floors and the first record are settled before anything is read or written."""
        second = self.tasks()[1]
        self.assertEqual(section(second, "control_plane_preflight")["action"], "snapshot")
        self.assertEqual(second["register"], "control_plane_preflight_before")

    def test_the_comparison_comes_last_and_is_given_the_first_record(self) -> None:
        """The comparison covers everything the role did, and is given the record taken first."""
        tasks = self.tasks()
        compare, shown = tasks[-2], tasks[-1]
        arguments = section(compare, "control_plane_preflight")
        self.assertEqual(arguments["action"], "compare")
        self.assertEqual(arguments["before"], "{{ control_plane_preflight_before.record }}")
        self.assertIn("ansible.builtin.debug", shown)

    def test_no_preflight_task_hides_its_result_or_forces_check_mode(self) -> None:
        """The record is printed on purpose, and the module only reads so check mode is its own."""
        for task in self.tasks():
            if "control_plane_preflight" in task:
                self.assertNotIn("no_log", task)
                self.assertNotIn("check_mode", task)

    def test_the_floors_are_constants_the_runbook_figures(self) -> None:
        """The floors sit in vars/main.yml, which an inventory or play variable cannot override."""
        values = load_mapping(VARS)
        self.assertEqual(values["control_plane_min_available_memory_fresh_mib"], 2664)
        self.assertEqual(values["control_plane_min_available_memory_running_mib"], 1000)
        self.assertEqual(values["control_plane_min_free_disk_mib"], 5120)
        defaults = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
        self.assertNotIn("min_available_memory", defaults)
        self.assertNotIn("min_free_disk", defaults)

    def test_the_documents_checked_are_the_stack_files_the_role_delivers(self) -> None:
        """The check reads the files the role copies, not a list of its own."""
        documents = load_mapping(VARS)["control_plane_compose_documents"]
        if not isinstance(documents, list):
            self.fail("control_plane_compose_documents is not a list")
        named = sorted(re.findall(r"stack/([\w.]+)", " ".join(str(item) for item in documents)))
        self.assertEqual(named, ["compose.init.yml", "compose.yml"])

    def run_role(self, *extra: str) -> subprocess.CompletedProcess[str]:
        """Run the real role under ansible-playbook in check mode, with the bring-up off."""
        playbook = Path(self.scratch.name, "play.yml")
        playbook.write_text(
            "- hosts: localhost\n  gather_facts: false\n  connection: local\n"
            f"  roles:\n    - role: {ROLE}\n",
            encoding="utf-8",
        )
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": self.scratch.name,
            "ANSIBLE_LOCAL_TEMP": str(Path(self.scratch.name, "tmp")),
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_LOCALHOST_WARNING": "False",
        }
        command = [
            str(Path(sys.executable).parent / "ansible-playbook"),
            str(playbook),
            "--check",
            "-e",
            f"ansible_python_interpreter={sys.executable}",
            "-e",
            "control_plane_bring_up=false",
            "-e",
            "control_plane_start_units=false",
            *extra,
        ]
        return subprocess.run(  # noqa: S603 - the venv's own ansible-playbook, a fixed list
            command,
            capture_output=True,
            text=True,
            env=env,
            cwd=self.scratch.name,
            check=False,
            timeout=300,
        )

    def test_the_real_role_refuses_nextclouds_project_name_before_its_second_task(self) -> None:
        """Red then green through Ansible itself: the role, given Nextcloud's name, stops at once.

        Sabotage: delete the first task of tasks/main.yml, or break `control_plane_project_names`
        in vars/main.yml, and this test goes red. The next task's name must not appear.
        """
        refused = self.run_role("-e", "control_plane_project_name=nextcloud1")
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertIn("[project-collision]", refused.stdout)
        self.assertNotIn("Look at the environment file before anything", refused.stdout)
        accepted = self.run_role()
        self.assertRegex(
            accepted.stdout,
            r"Refuse a deploy configured with Nextcloud's project name[^\n]*\nok:",
        )
        self.assertIn("Look at the environment file before anything", accepted.stdout)

    def test_the_real_role_refuses_a_volume_of_nextclouds_named_in_the_stack(self) -> None:
        """The same through Ansible, with the parsed files replaced by one that names the volume."""
        volumes = {"d": {"name": "nextcloud1_nextcloud-db"}}
        documents = [{"name": STACK_PROJECT, "volumes": volumes}]
        refused = self.run_role("-e", json.dumps({"control_plane_compose_documents": documents}))
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertIn("[volume-collision]", refused.stdout)


if __name__ == "__main__":
    unittest.main()
