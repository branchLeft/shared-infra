"""Unit tests for the order and the gates of the control_plane role's tasks.

Each secret is written in two steps: created empty at its final owner and mode, then
filled. The attribute task must sit between the create-empty tasks and the fills, or a
fill leaves content in a file that is still wide. The role also settles its inputs before
its first write and leaves a deployed stack's containers to the unit. These tests read
tasks/main.yml and fail when that order or those gates are lost.
"""

import importlib.util
import re
import sys
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tests" / "support"))

from role_tasks import task_lines  # noqa: E402

CREATE_ENV = "Create the environment file empty, if it is absent"
CREATE_KEY = "Create the master key empty, if it is absent"
ATTRIBUTES = "Set the owner, group and mode of each secret file on every run"
FILL_ENV = "Write the environment file's content while the file is empty"
FILL_KEY = "Write the master key's content while the file is empty"

FIRST_WRITE = "Create the host configuration directories of the control plane"
INPUT_REFUSALS = (
    "Refuse an absent or empty environment file when no content was given",
    "Refuse an absent or empty master key when no content was given",
    "Refuse a run with no image to deploy",
    "Refuse an image that is not pinned by digest",
)
REFUSAL_CODES = ("env-missing", "masterkey-missing", "image-missing", "image-not-pinned")
DOCKER_READS = (
    "Look for the portal container of the stack",
    "Read the image the portal container was created from",
)


def _load(path: Path) -> object:
    """Return a YAML file, parsed."""
    loaded: object = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    return loaded


def _tasks() -> list[dict[str, object]]:
    """Return every task of tasks/main.yml, parsed.

    Raises:
        TypeError: the file is not a list.
    """
    loaded = _load(TASKS)
    if not isinstance(loaded, list):
        message = "tasks/main.yml is not a list of tasks"
        raise TypeError(message)
    return [task for task in loaded if isinstance(task, dict)]


def _flat_tasks(tasks: list[dict[str, object]]) -> list[dict[str, object]]:
    """Return the tasks and every task nested in a block, rescue or always, in file order."""
    flat: list[dict[str, object]] = []
    for task in tasks:
        flat.append(task)
        for key in ("block", "rescue", "always"):
            nested = task.get(key)
            if isinstance(nested, list):
                flat.extend(_flat_tasks([item for item in nested if isinstance(item, dict)]))
    return flat


def _names(tasks: object) -> list[str]:
    """Return the names of a list of tasks, or none when the value is not a list."""
    if not isinstance(tasks, list):
        return []
    return [str(item.get("name")) for item in tasks if isinstance(item, Mapping)]


def _section(task: Mapping[str, object], key: str) -> Mapping[str, object]:
    """Return the arguments of a task's module, which the test has just found there.

    Raises:
        TypeError: the task has no such mapping.
    """
    section = task.get(key)
    if not isinstance(section, Mapping):
        message = f"{key} is not a mapping in {task.get('name')!r}"
        raise TypeError(message)
    return section


def _argv(task: Mapping[str, object]) -> list[str]:
    command = task.get("ansible.builtin.command")
    if not isinstance(command, Mapping):
        return []
    argv = command["argv"]
    return [str(word) for word in argv] if isinstance(argv, list) else []


def _conditions(task: Mapping[str, object]) -> list[str]:
    when = task.get("when", [])
    return [str(item) for item in (when if isinstance(when, list) else [when])]


class TaskOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.names = [name for name, _ in task_lines(TASKS)]

    def _position(self, name: str) -> int:
        self.assertEqual(
            self.names.count(name), 1, f"{name!r} must appear exactly once in tasks/main.yml"
        )
        return self.names.index(name)

    def test_the_five_secret_tasks_are_all_present(self) -> None:
        for name in (CREATE_ENV, CREATE_KEY, ATTRIBUTES, FILL_ENV, FILL_KEY):
            self.assertIn(name, self.names)

    def test_both_create_empty_tasks_come_before_the_attribute_task(self) -> None:
        attributes = self._position(ATTRIBUTES)
        self.assertLess(
            self._position(CREATE_ENV),
            attributes,
            "the environment file is created after its attributes are set",
        )
        self.assertLess(
            self._position(CREATE_KEY),
            attributes,
            "the master key is created after its attributes are set",
        )

    def test_the_attribute_task_comes_before_both_fills(self) -> None:
        attributes = self._position(ATTRIBUTES)
        self.assertLess(
            attributes,
            self._position(FILL_ENV),
            "the environment file is filled before its attributes are set",
        )
        self.assertLess(
            attributes,
            self._position(FILL_KEY),
            "the master key is filled before its attributes are set",
        )


class InputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.names = [name for name, _ in task_lines(TASKS)]

    def test_every_input_refusal_comes_before_the_first_write(self) -> None:
        first_write = self.names.index(FIRST_WRITE)
        for name in INPUT_REFUSALS:
            self.assertEqual(self.names.count(name), 1, name)
            self.assertLess(self.names.index(name), first_write, f"{name!r} comes after a write")

    def test_the_refusals_name_their_input_and_show_no_value(self) -> None:
        by_name = {str(task.get("name")): task for task in _tasks()}
        for name, needle in zip(INPUT_REFUSALS, REFUSAL_CODES, strict=True):
            task = by_name[name]
            self.assertIn(
                f"control_plane[{needle}]",
                str(_section(task, "ansible.builtin.assert")["fail_msg"]),
            )
            self.assertNotIn("no_log", task, f"{name!r} hides its own message")
        for name in INPUT_REFUSALS[:2]:
            message = str(_section(by_name[name], "ansible.builtin.assert")["fail_msg"])
            self.assertNotIn("control_plane_env_content }}", message)
            self.assertNotIn("control_plane_masterkey }}", message)

    def test_the_direct_compose_tasks_are_gated_on_a_stack_not_yet_deployed(self) -> None:
        gated = 0
        for task in _flat_tasks(_tasks()):
            words = _argv(task)
            direct = words[:2] == ["docker", "compose"]
            stamp = "Record that the init phase has completed" == task.get("name")
            if not direct and not stamp:
                continue
            gated += 1
            self.assertTrue(
                any(
                    "control_plane_deployed" in condition and "not" in condition
                    for condition in _conditions(task)
                ),
                f"{task.get('name')!r} runs without the not-yet-deployed gate",
            )
        self.assertEqual(
            gated, 4, "expected the database start, the init run, its stamp and the sign-in start"
        )

    def test_the_reads_of_the_running_stack_run_in_check_mode_and_change_nothing(self) -> None:
        by_name = {str(task.get("name")): task for task in _tasks()}
        for name in DOCKER_READS:
            task = by_name[name]
            self.assertIs(task.get("check_mode"), False, f"{name!r} is skipped in check mode")
            self.assertIs(task.get("changed_when"), False, f"{name!r} can report a change")
            self.assertEqual(_argv(task)[0], "docker")
            self.assertIn(_argv(task)[1], ("ps", "inspect"), f"{name!r} is not a read")

    def test_only_the_settled_image_is_used_by_the_tasks_that_run_it(self) -> None:
        for task in _flat_tasks(_tasks()):
            command = task.get("ansible.builtin.command")
            if not isinstance(command, dict):
                continue
            used = f"{command} {task.get('environment', '')}"
            self.assertNotIn(
                "control_plane_app_image", used, f"{task.get('name')!r} uses the image as given"
            )


WRAPPER = "Start the stack through the deploy wrapper with the pinned image"
UNIT_ACTIVE = "Refuse a stack unit that is not active after the deploy"
DELIVER_OTHER = "Deliver the stack's other files"
DELIVER_COMPOSE = "Deliver the stack's compose files"
MAKE_SUBDIRECTORIES = "Create the subdirectories of the stack"
RELOAD = "Reload the database so the delivered access rules are the ones in force"
REMOVE_LEGACY = "Remove the access rules file from its old place"
DELIVERY_BLOCK = "Deliver the access rules, and undo the delivery if a step after it fails"
DELIVER_RULES = "Deliver the access rules, keeping the rules they replace"
DROP_KEPT = "Remove the kept access rules, now that the delivered ones are in force"
RESTORE = "Put the kept access rules back on disk, where the database reads them"
RELOAD_KEPT = "Reload the database on the kept access rules"
DROP_RESTORED = "Remove the kept access rules, now that they are back"
REFUSE_UNDONE = "Refuse the delivery after the kept access rules were put back"
STACK = ROLE.parents[2] / "hetzner" / "control-plane" / "stack"
# Words that, in a command of this role, would take a container or a volume away.
DESTRUCTIVE_WORDS = frozenset(
    {"down", "rm", "-v", "--volumes", "--force-recreate", "prune", "kill", "stop"}
)


def _vars() -> dict[str, object]:
    loaded = _load(ROLE / "vars" / "main.yml")
    return {str(key): value for key, value in loaded.items()} if isinstance(loaded, dict) else {}


def _vars_list(name: str) -> list[str]:
    value = _vars()[name]
    return [str(item) for item in value] if isinstance(value, list) else []


class HbaDeliveryTests(unittest.TestCase):
    """A changed pg_hba.conf must reach the running database with no hand step.

    The file is mounted into the db container as a directory, and the role reloads the
    server after the deploy wrapper on every apply. These tests hold the shape that depends
    on; the real-server test (hetzner/provision/test_control_plane_hba_server.py) holds the
    behaviour, and goes red when the reload is not made.
    """

    def setUp(self) -> None:
        flat = _flat_tasks(_tasks())
        self.names = [str(task.get("name")) for task in flat]
        self.by_name = {str(task.get("name")): task for task in flat}

    def _position(self, name: str) -> int:
        self.assertEqual(self.names.count(name), 1, f"{name!r} must appear exactly once")
        return self.names.index(name)

    def _block(self) -> Mapping[str, object]:
        found = [task for task in _tasks() if task.get("name") == DELIVERY_BLOCK]
        self.assertEqual(len(found), 1, "the access rules are not delivered inside one block")
        return found[0]

    def test_the_rules_are_delivered_with_a_backup_and_outside_the_loop_of_the_other_files(
        self,
    ) -> None:
        # Ansible's own backup keeps the replaced file only when the new one differs, so a
        # second apply of one commit makes no file and reports no change. A hand-made keep
        # step, or a changed_when written to hide one, is what this refuses.
        task = self.by_name[DELIVER_RULES]
        copy = _section(task, "ansible.builtin.copy")
        self.assertIs(copy.get("backup"), True)
        self.assertEqual(copy["src"], "stack/{{ control_plane_hba_file }}")
        self.assertEqual(task.get("register"), "control_plane_hba_delivery")
        self.assertNotIn("changed_when", task)
        self.assertNotIn("when", task)
        self.assertIn(DELIVER_RULES, _names(self._block()["block"]))
        self.assertIn(
            "difference(control_plane_stack_files_in_block)",
            str(self.by_name[DELIVER_OTHER]["loop"]),
        )
        self.assertEqual(_vars()["control_plane_hba_file"], "postgres/pg_hba.conf")
        self.assertEqual(_vars_list("control_plane_stack_files_in_block"), ["postgres/pg_hba.conf"])

    def test_a_failed_step_after_the_delivery_puts_the_kept_rules_back_and_reloads(self) -> None:
        block = self._block()
        for name in (DELIVER_RULES, WRAPPER, UNIT_ACTIVE, RELOAD, DROP_KEPT):
            self.assertIn(name, _names(block["block"]), f"{name!r} is outside the block")
        self.assertEqual(
            _names(block.get("rescue")), [RESTORE, RELOAD_KEPT, DROP_RESTORED, REFUSE_UNDONE]
        )
        # The kept copy is dropped last in the block, after the reload that proves the rules.
        self.assertEqual(_names(block["block"])[-1], DROP_KEPT)
        self.assertLess(self._position(RELOAD), self._position(DROP_KEPT))
        restore = self.by_name[RESTORE]
        copy = _section(restore, "ansible.builtin.copy")
        self.assertEqual(copy["src"], "{{ control_plane_hba_delivery.backup_file }}")
        self.assertEqual(
            copy["dest"], "{{ control_plane_project_dir }}/{{ control_plane_hba_file }}"
        )
        self.assertIs(copy.get("remote_src"), True)
        self.assertTrue(
            any("backup_file" in condition for condition in _conditions(restore)),
            "the restore runs with no kept file to put back",
        )
        reload_kept = self.by_name[RELOAD_KEPT]
        self.assertEqual(_argv(reload_kept), _argv(self.by_name[RELOAD]))
        self.assertIs(reload_kept.get("changed_when"), False)
        self.assertIn("control_plane_start_units | ansible.builtin.bool", _conditions(reload_kept))
        self.assertIn("ansible.builtin.fail", self.by_name[REFUSE_UNDONE])
        self.assertIn(
            "control_plane[hba-undone]",
            str(_section(self.by_name[REFUSE_UNDONE], "ansible.builtin.fail")["msg"]),
        )

    def test_no_task_reports_the_kept_copy_as_unchanged_by_hand(self) -> None:
        for name in (DELIVER_RULES, DROP_KEPT, RESTORE, DROP_RESTORED):
            self.assertNotIn("changed_when", self.by_name[name], f"{name!r} hides its change")

    def test_the_reload_comes_after_the_wrapper_and_after_the_stack_files_are_delivered(
        self,
    ) -> None:
        reload_at = self._position(RELOAD)
        for earlier in (WRAPPER, UNIT_ACTIVE, DELIVER_OTHER, DELIVER_COMPOSE, MAKE_SUBDIRECTORIES):
            self.assertLess(
                self._position(earlier), reload_at, f"the reload comes before {earlier!r}"
            )

    def test_the_reload_runs_the_one_script_in_the_db_container_on_every_apply(self) -> None:
        task = self.by_name[RELOAD]
        self.assertEqual(
            _argv(task),
            ["docker", "exec", "--interactive", "{{ control_plane_db_container }}", "sh", "-s"],
        )
        self.assertEqual(
            _section(task, "ansible.builtin.command")["stdin"],
            "{{ lookup('ansible.builtin.file', 'reload_hba.sh') }}",
        )
        self.assertTrue((ROLE / "files" / "reload_hba.sh").is_file())
        self.assertIs(task.get("changed_when"), False)
        # On every apply: nothing but the units switch decides whether it runs, so an
        # interrupted run, which leaves the file delivered and not loaded, is finished by
        # the next one.
        self.assertEqual(_conditions(task), ["control_plane_start_units | ansible.builtin.bool"])
        self.assertNotIn("register", task)

    def test_the_reload_script_takes_the_password_from_the_container_and_checks_the_reload(
        self,
    ) -> None:
        text = (ROLE / "files" / "reload_hba.sh").read_text(encoding="utf-8")
        self.assertIn('PGPASSWORD="${POSTGRES_PASSWORD:?', text)
        self.assertIn("pg_reload_conf()", text)
        self.assertIn("pg_conf_load_time()", text)
        self.assertIn("pg_hba_file_rules", text)
        self.assertIn("error is not null", text)
        self.assertIn("</dev/null", text, "psql would read the script from standard input")
        # The password is never put on a command line.
        self.assertNotIn("--password", text)
        self.assertNotRegex(text, r"(?m)^\s*(export\s+)?PGPASSWORD=['\"]?[A-Za-z0-9]")

    def test_the_container_is_the_one_compose_names_for_the_database(self) -> None:
        compose = (STACK / "compose.yml").read_text(encoding="utf-8")
        project = re.search(r"^name: (\S+)\s*$", compose, re.MULTILINE)
        if project is None:
            self.fail("the compose file no longer names its project")
        self.assertEqual(_vars()["control_plane_db_container"], f"{project.group(1)}-db-1")

    def test_the_legacy_file_is_removed_only_after_the_wrapper(self) -> None:
        self.assertGreater(self._position(REMOVE_LEGACY), self._position(WRAPPER))
        task = self.by_name[REMOVE_LEGACY]
        file_module = _section(task, "ansible.builtin.file")
        self.assertEqual(file_module["state"], "absent")
        self.assertEqual(file_module["path"], "{{ control_plane_legacy_hba_file }}")
        self.assertEqual(_conditions(task), ["control_plane_start_units | ansible.builtin.bool"])
        variables = _vars()
        self.assertEqual(
            variables["control_plane_legacy_hba_file"],
            "{{ control_plane_project_dir }}/pg_hba.conf",
        )
        # The legacy path is not a path the role still delivers.
        self.assertNotIn("pg_hba.conf", _vars_list("control_plane_stack_files"))

    def test_the_rules_are_delivered_into_a_subdirectory_the_role_makes_first(self) -> None:
        variables = _vars()
        self.assertIn("postgres/pg_hba.conf", _vars_list("control_plane_stack_files"))
        self.assertEqual(variables["control_plane_stack_dirs"], ["postgres"])
        self.assertLess(self._position(MAKE_SUBDIRECTORIES), self._position(DELIVER_OTHER))
        self.assertLess(self._position(MAKE_SUBDIRECTORIES), self._position(DELIVER_COMPOSE))
        for relative in _vars_list("control_plane_stack_files"):
            self.assertTrue(
                (STACK / relative).is_file(), f"{relative} is not in the repository's stack"
            )

    def test_no_task_removes_a_container_or_a_volume(self) -> None:
        # The data lives in the db-data volume. Nothing the role runs may take it away.
        for task in _flat_tasks(_tasks()):
            words = set(_argv(task))
            self.assertEqual(
                words & DESTRUCTIVE_WORDS,
                set(),
                f"{task.get('name')!r} runs a command that can remove a container or a volume",
            )
        text = TASKS.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"(?m)^\s+- ('?)(down|--volumes|-v|--force-recreate)\1\s*$")
        script = (ROLE / "files" / "reload_hba.sh").read_text(encoding="utf-8")
        code = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotRegex(code, r"docker|rm -|--volumes|drop |truncate ")


class WrapperRecordTests(unittest.TestCase):
    """The role reads the deploy wrapper's record, so the path and the key come from its source."""

    def setUp(self) -> None:
        source = ROLE.parents[2] / "hetzner" / "provision" / "branchleft_deploy.py"
        spec = importlib.util.spec_from_file_location("branchleft_deploy", source)
        if spec is None or spec.loader is None:
            self.fail(f"cannot load {source}")
        self.wrapper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.wrapper)

    def test_the_role_reads_the_file_the_wrapper_writes(self) -> None:
        variables = _vars()
        self.assertEqual(
            variables["control_plane_image_record"], self.wrapper.image_env_path("control-plane")
        )

    def test_the_wrapper_writes_the_key_the_role_reads(self) -> None:
        image = "example.invalid/app@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control-plane.image.env"
            self.wrapper.write_image_env(str(path), image)
            self.assertEqual(path.read_text(encoding="utf-8"), f"IMAGE={image}\n")
        self.assertIn("^IMAGE=", TASKS.read_text(encoding="utf-8"))


COMPOSE = ROLE.parents[2] / "hetzner" / "control-plane" / "stack" / "compose.yml"
README = ROLE / "README.md"


def _seconds(value: object) -> int:
    """Return a Compose duration such as ``15s`` as whole seconds.

    Raises:
        ValueError: the value is not a whole number of seconds.
    """
    match = re.fullmatch(r"(\d+)s", str(value))
    if match is None:
        message = f"not a whole number of seconds: {value!r}"
        raise ValueError(message)
    return int(match.group(1))


class FirstApplyWindowTests(unittest.TestCase):
    """The README's account of the first apply is derived from the stack, never typed by hand.

    The owner's ruling is that the first apply after the directory mount may interrupt a
    service for no more than 10 seconds. Nothing in the role measures that, so the README must
    not call the interruption brief. It states the least time Compose's own gate takes, which
    comes from the health checks in compose.yml, and these tests fail when the two disagree.
    """

    def setUp(self) -> None:
        loaded = _load(COMPOSE)
        if not isinstance(loaded, Mapping):
            self.fail("compose.yml is not a mapping")
        self.services = loaded["services"]
        self.readme = README.read_text(encoding="utf-8")
        # Docker runs a service's first health probe one interval after it starts.
        db = _seconds(self.services["db"]["healthcheck"]["interval"])
        zitadel = db + _seconds(self.services["zitadel"]["healthcheck"]["interval"])
        apps = zitadel + max(
            _seconds(self.services[name]["healthcheck"]["interval"])
            for name in ("portal", "console")
        )
        self.floors = {"db": db, "zitadel": zitadel, "apps": apps}

    def test_every_dependant_waits_for_a_healthy_database(self) -> None:
        for name in ("zitadel", "portal", "console"):
            self.assertEqual(
                self.services[name]["depends_on"]["db"]["condition"], "service_healthy", name
            )
        for name in ("portal", "console"):
            self.assertEqual(
                self.services[name]["depends_on"]["zitadel"]["condition"], "service_healthy", name
            )

    def test_the_database_mounts_the_rules_as_a_directory(self) -> None:
        mounts = self.services["db"]["volumes"]
        self.assertIn("./postgres:/etc/postgresql-hba:ro", mounts)

    def test_the_readme_does_not_call_the_interruption_brief(self) -> None:
        self.assertNotRegex(self.readme, r"(?i)\ba brief (sign-in|interruption)")

    def test_the_readme_says_the_window_is_not_measured_against_the_ruling(self) -> None:
        self.assertIn("not measured", self.readme)
        self.assertIn("10 seconds", self.readme)

    def test_the_readme_states_the_gate_floors_the_compose_file_gives(self) -> None:
        for label, seconds in self.floors.items():
            self.assertIn(f"gate floor {label}: {seconds} seconds", self.readme)


PROVISIONING_REFUSALS = (
    "Refuse enabling the provisioning API while an input file is absent or empty",
    "Refuse enabling the provisioning API with no image pin given",
)
PROVISIONING_CODES = ("provisioning-input-missing", "provisioning-image-missing")
WRITE_ENV = "Write the stack's interpolation file from whether the provisioning API is enabled"
SET_INPUT_ATTRIBUTES = "Set the owner, group and mode of the provisioning API's input files"


class ProvisioningApiTests(unittest.TestCase):
    """The provisioning API is off until the owner enables it, and the switch and the stack agree."""

    def setUp(self) -> None:
        self.names = [name for name, _ in task_lines(TASKS)]
        self.by_name = {str(task.get("name")): task for task in _tasks()}
        compose = _load(STACK / "compose.yml")
        assert isinstance(compose, Mapping)
        self.compose_text = (STACK / "compose.yml").read_text(encoding="utf-8")
        self.services = compose["services"]

    def _mounts(self, service: str) -> dict[str, str]:
        """The service's read-only and writable bind mounts, container path to host path."""
        mounts: dict[str, str] = {}
        for entry in self.services[service].get("volumes", []):
            host, container = str(entry).split(":")[:2]
            mounts[container] = host
        return mounts

    def test_the_switch_is_off_by_default_and_the_defaults_file_says_so(self) -> None:
        defaults = _load(ROLE / "defaults" / "main.yml")
        assert isinstance(defaults, Mapping)
        self.assertIs(defaults["control_plane_provisioning_enabled"], False)
        self.assertEqual(self.services["provisioning"]["scale"], "${PROVISIONING_SCALE:-0}")

    def test_enabling_is_refused_before_the_first_write_and_names_a_code_and_no_value(self) -> None:
        first_write = self.names.index(FIRST_WRITE)
        for name, code in zip(PROVISIONING_REFUSALS, PROVISIONING_CODES, strict=True):
            self.assertEqual(self.names.count(name), 1, name)
            self.assertLess(self.names.index(name), first_write, f"{name!r} comes after a write")
            task = self.by_name[name]
            self.assertIn(f"control_plane[{code}]", str(_section(task, "ansible.builtin.assert")["fail_msg"]))
            self.assertIn("control_plane_provisioning_enabled", " ".join(_conditions(task)))
            self.assertNotIn("no_log", task)
        refusal = _section(self.by_name[PROVISIONING_REFUSALS[1]], "ansible.builtin.assert")
        self.assertEqual(refusal["that"], ["control_plane_image_given | ansible.builtin.bool"])

    def test_the_input_files_are_looked_at_before_the_first_write(self) -> None:
        look = "Look at the provisioning API's input files before anything is written"
        self.assertLess(self.names.index(look), self.names.index(FIRST_WRITE))
        self.assertIs(_section(self.by_name[look], "ansible.builtin.stat")["get_checksum"], False)

    def test_the_interpolation_file_is_written_from_the_switch_and_holds_no_secret(self) -> None:
        task = self.by_name[WRITE_ENV]
        copy = _section(task, "ansible.builtin.copy")
        self.assertEqual(copy["dest"], "{{ control_plane_project_env_file }}")
        self.assertEqual(_vars()["control_plane_project_env_file"], "{{ control_plane_project_dir }}/.env")
        self.assertNotIn("no_log", task)
        self.assertIn("control_plane_provisioning_enabled", str(copy["content"]))
        self.assertLess(self.names.index(WRITE_ENV), self.names.index("Deliver the access rules, and undo the delivery if a step after it fails"))
        enabled = str(_vars()["control_plane_project_env_enabled"])
        disabled = str(_vars()["control_plane_project_env_disabled"])
        self.assertNotRegex(enabled + disabled, r"(?i)password|secret|token|key")
        self.assertIn("PROVISIONING_SCALE=1", enabled)
        self.assertIn("PROVISIONING_SCALE=0", disabled)
        self.assertNotIn("PROVISIONING_URL", disabled)

    def test_every_reference_compose_leaves_empty_is_set_by_the_enabled_file_and_no_other(self) -> None:
        references = set(re.findall(r"\$\{(\w+):-[^}]*\}", self.compose_text))
        provisioning = {name for name in references if "PROVISIONING" in name}
        enabled = {
            line.split("=", 1)[0]
            for line in str(_vars()["control_plane_project_env_enabled"]).splitlines()
            if "=" in line
        }
        self.assertEqual(enabled, provisioning)

    def test_the_urls_the_enabled_file_sets_are_the_service_on_the_stacks_own_network(self) -> None:
        enabled = str(_vars()["control_plane_project_env_enabled"])
        urls = re.findall(r"_PROVISIONING_URL=(\S+)", enabled)
        self.assertEqual(urls, ["http://provisioning:8095"] * 2)
        self.assertEqual(self.services["provisioning"]["environment"]["PORT"], "8095")
        self.assertNotIn("ports", self.services["provisioning"])

    def test_each_application_is_mounted_its_own_credentials_directory_and_never_the_others(self) -> None:
        tenant = "/etc/branchleft/control-plane/provisioning/tenant"
        owner = "/etc/branchleft/control-plane/provisioning/owner"
        portal = {host.removesuffix(":ro") for host in self._mounts("portal").values()}
        console = {host.removesuffix(":ro") for host in self._mounts("console").values()}
        self.assertIn(tenant, self._mounts("portal").values())
        self.assertNotIn(owner, self._mounts("portal").values())
        self.assertIn(owner, self._mounts("console").values())
        self.assertNotIn(tenant, self._mounts("console").values())
        self.assertTrue(portal and console)
        service = set(self._mounts("provisioning").values())
        self.assertLessEqual({tenant, owner}, service)

    def test_every_input_file_is_under_a_directory_the_role_makes_and_the_stack_mounts(self) -> None:
        made = {entry["path"]: entry for entry in _vars()["control_plane_host_dirs"]}
        mounted = {host: container for container, host in self._mounts("provisioning").items()}
        environment = self.services["provisioning"]["environment"]
        wanted = {
            environment["PROVISIONING_OWNER_CREDENTIAL_FILE"],
            environment["PROVISIONING_TENANT_CREDENTIALS_FILE"],
            environment["PROVISIONING_DEMOS_FILE"],
        }
        placed = {}
        for entry in _vars()["control_plane_provisioning_input_files"]:
            directory = entry["path"].rsplit("/", 1)[0]
            self.assertIn(directory, made, entry["path"])
            self.assertIn(directory, mounted, entry["path"])
            placed[mounted[directory] + "/" + entry["path"].rsplit("/", 1)[1]] = entry
        self.assertEqual(set(placed), wanted)
        # A credential is never writable and the container user reads it through the group.
        for path, entry in placed.items():
            if "credential" in path:
                self.assertEqual((entry["owner"], entry["group"], entry["mode"]), ("root", "1000", "0440"))

    def test_the_state_directory_is_the_services_alone_and_private(self) -> None:
        made = {entry["path"]: entry for entry in _vars()["control_plane_host_dirs"]}
        state = made["/var/lib/branchleft/control-plane/provisioning"]
        self.assertEqual((state["owner"], state["mode"]), ("1000", "0700"))
        self.assertIn("/var/lib/branchleft/control-plane/provisioning", self._mounts("provisioning").values())
        for other in ("portal", "console", "db", "zitadel"):
            self.assertNotIn("/var/lib/branchleft/control-plane/provisioning", self._mounts(other).values())

    def test_the_input_attributes_are_set_only_when_enabled_and_never_touch_content(self) -> None:
        task = self.by_name[SET_INPUT_ATTRIBUTES]
        file_module = _section(task, "ansible.builtin.file")
        self.assertEqual(file_module["state"], "file")
        self.assertNotIn("content", file_module)
        self.assertIn("control_plane_provisioning_enabled", " ".join(_conditions(task)))


if __name__ == "__main__":
    unittest.main()
