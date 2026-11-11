"""Unit tests that hold the role's files and tasks to what the ring controller host must be.

The tests read the real files, never a copy. Each control that a test names was run red on a
sabotaged copy and green on the file as shipped (the pull request records both). The checks that
look for a forbidden thing are first shown able to find it, on text made to hold it.

The model-key and agent-binary deny-list has one home, `modelFreeEnvironment.ts` in the ring
controller (branchLeft/ghost-platform). It is not restated here. This role keeps the unit's
environment to an exact allow-list of names and a fixed PATH, which needs no deny-list; the only
strings below that look like a deny-list entry are the sabotage inputs of the tests themselves.
"""

import re
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import jinja2
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
SERVICE = ROLE / "files" / "ring-controller.service"
TIMER = ROLE / "files" / "ring-controller.timer"
ENV_TEMPLATE = ROLE / "templates" / "ring-controller.env.j2"
DIGEST = "a" * 64

# The names the environment file may hold, exactly. They avoid the words the plan-diff scan reads
# as a credential, and they are the proposed contract with the controller's entrypoint.
ENV_ALLOW_LIST = [
    "RING_CONTROLLER_LEDGER_URL",
    "RING_CONTROLLER_LEDGER_PUSH_REMOTE",
    "RING_CONTROLLER_LEDGER_SIGNING_IDENTITY_FILE",
    "RING_CONTROLLER_PUSH_IDENTITY_FILE",
    "RING_CONTROLLER_KNOWN_HOSTS_FILE",
    "RING_CONTROLLER_STATE_DIR",
]
# Where the role may put a file: its own directories, its own two units, nothing else.
ALLOWED_PREFIXES = (
    "/etc/branchleft/ring-controller",
    "/var/lib/branchleft/ring-controller",
    "/opt/branchleft/ring-controller",
    "/etc/systemd/system/ring-controller.service",
    "/etc/systemd/system/ring-controller.timer",
)
# The modules whose destination is a path the role writes.
WRITING_MODULES = {"copy", "template", "file", "get_url", "unarchive"}
FORBIDDEN_MODULES = {"shell", "command", "script", "raw", "slurp", "pipe", "fetch", "lineinfile"}
# Paths of other roles and of the owner's data: the role names none of them.
OTHER_PATHS = (
    "/etc/branchleft/control-plane",
    "/etc/branchleft/backup-worker",
    "/etc/branchleft/host-inputs.json",
    "/etc/branchleft/content-safety",
    "/var/lib/nextcloud",
    "/var/lib/branchleft/control-plane",
    "/opt/branchleft/control-plane",
    "/opt/branchleft/backup-worker",
    "nextcloud",
)


def load(path: Path) -> object:
    """Load a YAML file with the safe loader."""
    return YAML(typ="safe").load(path.read_text(encoding="utf-8"))


def role_vars() -> dict[str, object]:
    """Return the role's vars/main.yml."""
    return cast("dict[str, object]", load(ROLE / "vars" / "main.yml"))


def role_defaults() -> dict[str, object]:
    """Return the role's defaults/main.yml."""
    return cast("dict[str, object]", load(ROLE / "defaults" / "main.yml"))


def tasks() -> list[dict[str, object]]:
    """Return the role's tasks."""
    return cast("list[dict[str, object]]", load(ROLE / "tasks" / "main.yml"))


def render(text: str, variables: Mapping[str, object] | None = None) -> str:
    """Render a Jinja string with the role's vars, defaults and any extra values.

    The role's own variables hold templates of each other, so they are resolved first, a few
    passes deep, and the text is rendered against the resolved values.
    """
    merged: dict[str, object] = {**role_defaults(), **role_vars(), **(variables or {})}
    # Ansible text and unit files, never HTML, so there is nothing to escape.
    environment = jinja2.Environment(  # noqa: S701
        undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    for _ in range(5):
        merged = {key: _render_value(environment, value, merged) for key, value in merged.items()}
    return environment.from_string(text).render(**merged)


def _render_value(
    environment: jinja2.Environment, value: object, scope: dict[str, object]
) -> object:
    """Render a string, or each string of a list, against the scope."""
    if isinstance(value, str) and "{{" in value:
        return environment.from_string(value).render(**scope)
    if isinstance(value, list):
        return [_render_value(environment, item, scope) for item in value]
    return value


def resolved_list(template: str) -> list[str]:
    """Return the items of a loop that is `{{ some_role_list }}` or a literal list as strings."""
    name = template.strip().removeprefix("{{").removesuffix("}}").strip()
    merged = {**role_defaults(), **role_vars()}
    items = merged[name]
    return [render(str(item)) for item in cast("list[object]", items)]


def unit_keys(text: str) -> list[tuple[str, str]]:
    """Return each Key=value line of a unit file as a pair, in file order."""
    return [
        (line.split("=", 1)[0], line.split("=", 1)[1])
        for line in text.splitlines()
        if "=" in line and not line.lstrip().startswith("#") and not line.startswith("[")
    ]


def env_names(text: str) -> list[str]:
    """Return the variable names an environment file defines."""
    return [
        line.split("=", 1)[0]
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    ]


def environment_problems(text: str) -> list[str]:
    """Return what is wrong with an environment file: any name off the list or model-shaped."""
    problems = [f"name off the allow-list: {n}" for n in env_names(text) if n not in ENV_ALLOW_LIST]
    problems += [f"model-shaped name: {n}" for n in env_names(text) if _model_shaped(n)]
    problems += [
        f"allow-list name missing: {n}" for n in ENV_ALLOW_LIST if n not in env_names(text)
    ]
    return problems


def _model_shaped(name: str) -> bool:
    """Whether a name looks like a model key (a sabotage input of this test, not the deny-list)."""
    return name.endswith("_API_KEY") or name.startswith("ANTHROPIC_")


def module_of(task: dict[str, object]) -> str | None:
    """Return the short name of the module a task calls, or None for a block."""
    keywords = {
        "name", "when", "loop", "loop_control", "register", "notify", "no_log", "diff",
        "failed_when", "changed_when", "check_mode", "tags", "vars", "block", "rescue",
        "always", "become", "environment", "delegate_to", "until", "retries", "delay",
    }  # fmt: skip
    for key in task:
        if key not in keywords:
            return str(key).rsplit(".", 1)[-1]
    return None


def named(name_start: str) -> dict[str, object]:
    """Return the one task whose name starts with the text.

    Raises:
        AssertionError: when no task, or more than one, matches.
    """
    found = [t for t in tasks() if str(t.get("name", "")).startswith(name_start)]
    if len(found) != 1:
        message = f"{len(found)} tasks start with {name_start!r}"
        raise AssertionError(message)
    return found[0]


def args_of(task: dict[str, object]) -> dict[str, object]:
    """Return the arguments of a task's module."""
    module = module_of(task)
    for key, value in task.items():
        if str(key).rsplit(".", 1)[-1] == module and isinstance(value, dict):
            return cast("dict[str, object]", value)
    return {}


class UnitFileTests(unittest.TestCase):
    """The service is a plain, single-instance, hardened unit that matches the process lock."""

    def setUp(self) -> None:
        self.service = SERVICE.read_text(encoding="utf-8")
        self.timer = TIMER.read_text(encoding="utf-8")
        self.service_keys = unit_keys(self.service)

    def values(self, key: str) -> list[str]:
        return [v for k, v in self.service_keys if k == key]

    def test_the_unit_is_plain_never_templated_and_names_no_instance(self) -> None:
        self.assertNotIn("@", SERVICE.name)
        self.assertNotIn("@", TIMER.name)
        for text in (self.service, self.timer):
            self.assertNotIn("%i", text)
            self.assertNotIn("%I", text)
            self.assertNotIn("{{", text)
            self.assertNotIn("{%", text)
        self.assertEqual(role_vars()["ring_controller_host_service_unit"], SERVICE.name)
        self.assertEqual(role_vars()["ring_controller_host_timer_unit"], TIMER.name)

    def test_the_unit_runs_once_per_tick_as_the_service_account_and_not_as_root(self) -> None:
        self.assertEqual(self.values("Type"), ["oneshot"])
        self.assertEqual(self.values("User"), [role_vars()["ring_controller_host_account"]])
        self.assertEqual(self.values("Group"), [role_vars()["ring_controller_host_account"]])
        self.assertNotEqual(self.values("User"), ["root"])

    def test_the_unit_is_hardened(self) -> None:
        for key, value in (
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "yes"),
            ("PrivateTmp", "yes"),
        ):
            with self.subTest(key=key):
                self.assertEqual(self.values(key), [value])
        self.assertEqual(
            self.values("ReadWritePaths"), [role_vars()["ring_controller_host_state_dir"]]
        )

    def test_the_unit_does_not_set_a_private_network_because_the_lock_lives_there(self) -> None:
        # processLock.ts binds an abstract-namespace socket in the network namespace. A private
        # namespace would hide it from a second copy started by hand, so the single-instance
        # guarantee would rest on systemd alone.
        self.assertEqual(self.values("PrivateNetwork"), [])
        self.assertNotRegex(self.service, r"(?mi)^\s*PrivateNetwork\s*=\s*(yes|true|1)")
        self.assertNotIn("JoinsNamespaceOf", self.service)

    def test_the_unit_has_one_environment_file_and_one_environment_the_fixed_path(self) -> None:
        self.assertEqual(
            self.values("EnvironmentFile"), [role_vars()["ring_controller_host_env_file"]]
        )
        self.assertEqual(
            self.values("Environment"),
            ["PATH=" + str(role_vars()["ring_controller_host_unit_path"])],
        )
        self.assertEqual(self.values("PassEnvironment"), [])
        self.assertEqual(self.values("UnsetEnvironment"), [])

    def test_the_path_is_four_system_directories_and_names_no_user_or_release_directory(
        self,
    ) -> None:
        path = str(role_vars()["ring_controller_host_unit_path"]).split(":")
        self.assertEqual(path, ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin"])

    def test_the_unit_names_no_model_key_and_no_agent_binary(self) -> None:
        for text in (self.service, self.timer, ENV_TEMPLATE.read_text(encoding="utf-8")):
            self.assertNotRegex(text, r"[A-Z0-9_]*_API_KEY")
            self.assertNotIn("ANTHROPIC_", text)
            self.assertNotRegex(text, r"(?i)\bclaude\b")

    def test_the_condition_the_start_and_the_link_are_one_path(self) -> None:
        current = str(role_vars()["ring_controller_host_current_link"])
        binary = f"{current}/{role_vars()['ring_controller_host_binary_relative']}"
        self.assertEqual(self.values("ConditionPathExists"), [binary])
        self.assertEqual(self.values("ExecStart"), [binary])

    def test_the_service_is_started_by_the_timer_only(self) -> None:
        self.assertNotIn("[Install]", self.service)
        self.assertIn("[Install]", self.timer)
        self.assertIn(f"Unit={SERVICE.name}", self.timer)
        self.assertIn("WantedBy=timers.target", self.timer)

    def test_the_tick_and_the_timeout_are_the_constants_the_controller_is_told(self) -> None:
        self.assertIn("OnUnitInactiveSec=5min", self.timer)
        self.assertEqual(self.values("TimeoutStartSec"), ["1800"])


class EnvironmentFileTests(unittest.TestCase):
    """The unit's environment is an exact allow-list of names, all public."""

    def setUp(self) -> None:
        self.template = ENV_TEMPLATE.read_text(encoding="utf-8")

    def sample(self, text: str) -> str:
        return render(
            text,
            {
                "ring_controller_host_ledger_url": "https://example.test/ledger",
                "ring_controller_host_ledger_push_remote": "ssh://git@example.test/org/repo.git",
            },
        )

    def test_the_rendered_names_equal_the_allow_list_exactly(self) -> None:
        self.assertEqual(env_names(self.sample(self.template)), ENV_ALLOW_LIST)
        self.assertEqual(environment_problems(self.sample(self.template)), [])

    def test_the_check_can_see_a_model_key_or_a_stray_name_added_to_the_file(self) -> None:
        # The control: the same check, run on text made to hold the forbidden thing, finds it.
        for extra in ("FOO_API_KEY=x", "ANTHROPIC_X=x", "OTHER_NAME=x", "PATH=/tmp/agent"):
            with self.subTest(extra=extra):
                problems = environment_problems(self.sample(self.template) + extra + "\n")
                self.assertTrue(problems, extra)
        self.assertTrue(
            environment_problems(
                self.sample(self.template).replace("RING_CONTROLLER_STATE_DIR", "X")
            )
        )

    def test_the_file_is_public_values_only_and_none_of_them_is_an_input_secret(self) -> None:
        # Every value is a role input or a role constant: nothing is read from a lookup, a
        # file or a fact, so no value can be anything but public.
        for line in self.template.splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                for name in re.findall(r"\{\{\s*([a-z_]+)\s*\}\}", line):
                    self.assertTrue(name.startswith("ring_controller_host_"), name)
        self.assertNotRegex(self.template, r"lookup|query|slurp|ansible_facts|hostvars|vault")

    def test_an_empty_input_renders_an_empty_value_not_a_missing_name(self) -> None:
        text = render(self.template)
        self.assertIn("RING_CONTROLLER_LEDGER_URL=\n", text)
        self.assertEqual(env_names(text), ENV_ALLOW_LIST)


class TaskTests(unittest.TestCase):
    """The tasks keep the key material hidden, touch only the role's paths and refuse early."""

    def test_the_key_module_task_is_hidden_and_its_diff_is_off_and_it_is_the_only_one(self) -> None:
        users = [t for t in tasks() if module_of(t) == "ring_controller_host_keys"]
        self.assertEqual(len(users), 1)
        task = users[0]
        self.assertIs(task.get("no_log"), True)
        self.assertIs(task.get("diff"), False)
        self.assertNotIn("block", task)

    def test_the_hide_is_not_loosened_by_a_task_that_unhides_it_or_prints_the_result(self) -> None:
        text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertNotRegex(text, r"no_log:\s*(false|no)")
        self.assertNotRegex(text, r"diff:\s*(true|yes)")
        # The only readers of the module's result are the refusal assert and the two debug
        # lines, and they name the public fields only.
        uses = re.findall(r"ring_controller_host_keys_result\.([a-z_]+)", text)
        self.assertEqual(
            sorted(set(uses)),
            [
                "ledger_signing_fingerprint",
                "ledger_signing_public",
                "msg",
                "push_fingerprint",
                "push_public",
            ],
        )

    def test_no_task_runs_a_program_reads_a_key_or_looks_up_a_file(self) -> None:
        for task in tasks():
            self.assertNotIn(module_of(task), FORBIDDEN_MODULES, task.get("name"))
        text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertNotRegex(text, r"lookup\(|query\(|\bpipe\b|\|\s*b64decode|\bslurp\b")
        for task in tasks():
            if module_of(task) == "stat":
                target = str(args_of(task).get("path", ""))
                self.assertNotIn("keys_directory", target)
                self.assertNotIn("key_name", target)
                self.assertIs(args_of(task).get("get_checksum"), False, task.get("name"))

    def test_no_literal_destination_is_outside_the_roles_own_paths(self) -> None:
        # Every path a writing task names, resolved against vars/main.yml, sits under one of
        # the allowed prefixes. A loop item is resolved against the loop's own list.
        seen: list[str] = []
        for task in tasks():
            if module_of(task) not in WRITING_MODULES:
                continue
            args = args_of(task)
            for key in ("dest", "path"):
                if key not in args:
                    continue
                templates = [str(args[key])]
                if "{{ item }}" in templates[0]:
                    loop = task["loop"]
                    items = (
                        [render(str(i)) for i in cast("list[object]", loop)]
                        if isinstance(loop, list)
                        else resolved_list(str(loop))
                    )
                    templates = [templates[0].replace("{{ item }}", i) for i in items]
                seen.extend(render(template) for template in templates)
        self.assertGreater(len(seen), 8)
        outside = [p for p in seen if not p.startswith(ALLOWED_PREFIXES)]
        self.assertEqual(outside, [])

    def test_no_file_of_the_role_names_a_path_of_another_role_or_the_owners_data(self) -> None:
        for path in sorted(ROLE.rglob("*")):
            if not path.is_file() or "molecule" in path.parts or "tests" in path.parts:
                continue
            if path.suffix not in {".yml", ".j2", ".service", ".timer", ".py"}:
                continue
            text = path.read_text(encoding="utf-8")
            for other in OTHER_PATHS:
                with self.subTest(file=path.name, other=other):
                    self.assertNotIn(other, text)

    def test_the_inputs_are_refused_before_anything_changes(self) -> None:
        changing = {
            "group", "user", "file", "copy", "template", "get_url", "unarchive",
            "systemd_service", "ring_controller_host_keys",
        }  # fmt: skip
        first_change = next(i for i, t in enumerate(tasks()) if module_of(t) in changing)
        before = tasks()[:first_change]
        self.assertGreaterEqual(len([t for t in before if module_of(t) == "assert"]), 9)
        # And every input is read by an assert before the group is made.
        text = "\n".join(str(t) for t in before)
        for name in role_defaults():
            self.assertIn(name, text)

    def test_the_bundle_is_held_to_its_digest_before_it_is_unpacked_and_before_the_link_moves(
        self,
    ) -> None:
        names = [str(t.get("name")) for t in tasks()]
        download = names.index(named("Download the bundle").get("name"))  # type: ignore[arg-type]
        unpack = names.index(str(named("Unpack the bundle").get("name")))
        check = names.index(str(named("Require the program").get("name")))
        link = names.index(str(named("Point current").get("name")))
        self.assertLess(download, unpack)
        self.assertLess(unpack, check)
        self.assertLess(check, link)
        get_url = args_of(named("Download the bundle"))
        # The sabotage for the digest: remove this key and the bundle scenario's mismatch case
        # goes red, and so does this assertion.
        self.assertEqual(get_url.get("checksum"), "sha256:{{ ring_controller_host_bundle_sha256 }}")
        self.assertEqual(get_url.get("dest"), "{{ ring_controller_host_bundle_file }}")

    def test_the_link_and_every_bundle_step_wait_for_a_digest(self) -> None:
        for start in (
            "Make the directory of this release",
            "Download the bundle",
            "Unpack the bundle",
            "Require the program",
            "Point current",
        ):
            with self.subTest(task=start):
                condition = str(named(start).get("when"))
                self.assertIn("ring_controller_host_bundle_sha256 | length > 0", condition)

    def test_with_no_digest_the_timer_is_disabled_and_stopped_and_with_one_it_is_started(
        self,
    ) -> None:
        # The one task that handles the timer, rendered both ways.
        timer = args_of(named("Hold the timer"))
        for digest, enabled, state in (("", "False", "stopped"), (DIGEST, "True", "started")):
            with self.subTest(digest=digest):
                variables = {"ring_controller_host_bundle_sha256": digest}
                self.assertEqual(render(str(timer["enabled"]), variables), enabled)
                self.assertEqual(render(str(timer["state"]), variables), state)
        self.assertEqual(timer["name"], "{{ ring_controller_host_timer_unit }}")

    def test_the_units_are_static_files_copied_not_templated(self) -> None:
        install = named("Install the service and timer units")
        self.assertEqual(module_of(install), "copy")
        self.assertNotIn("content", args_of(install))
        self.assertEqual(
            [
                render(str(i))
                for i in cast("list[object]", role_vars()["ring_controller_host_units"])
            ],
            [SERVICE.name, TIMER.name],
        )

    def test_the_account_is_a_system_account_that_cannot_log_in(self) -> None:
        user = args_of(named("Create the service account"))
        self.assertIs(user["system"], True)
        self.assertIs(user["create_home"], False)
        self.assertEqual(user["shell"], "/usr/sbin/nologin")

    def test_the_parents_are_asserted_and_never_changed(self) -> None:
        parents = cast("list[str]", role_vars()["ring_controller_host_parents"])
        self.assertEqual(parents, ["/etc/branchleft", "/opt/branchleft", "/var/lib/branchleft"])
        # The only tasks that name a parent are the stat that reads it and the loop that
        # asserts it: no writing task has one as its path (the prefix test above would refuse
        # it anyway, since a parent is shorter than every allowed prefix).
        for task in tasks():
            if module_of(task) in WRITING_MODULES:
                self.assertNotIn("ring_controller_host_parents", str(task))
        self.assertEqual(module_of(named("Look at the parent directories")), "stat")

    def test_the_state_directory_is_the_accounts_and_closed_to_everyone_else(self) -> None:
        state = args_of(named("Make the state directory"))
        self.assertEqual(state["mode"], "0700")
        self.assertEqual(state["owner"], "{{ ring_controller_host_account }}")


def promotion_record_problems(
    record_dir: str, state_dir: str, task_text: str, env_text: str, rw_paths: list[str]
) -> list[str]:
    """Return what is wrong with the reserved promotion record path.

    The path is a name only: under the state directory, covered by the unit's one writable path,
    and named by no task and by no line of the environment file.
    """
    problems: list[str] = []
    if not record_dir.startswith(state_dir + "/") or ".." in record_dir:
        problems.append(f"not under the state directory: {record_dir}")
    if not any(record_dir == p or record_dir.startswith(p + "/") for p in rw_paths):
        problems.append("not inside a path the unit may write")
    if "ring_controller_host_promotion_record_dir" in task_text or record_dir in task_text:
        problems.append("a task names it, so the role would make or touch it")
    if record_dir in env_text or "PROMOTION" in env_text.upper():
        problems.append("the environment file names it")
    return problems


class PromotionRecordPathTests(unittest.TestCase):
    """The promotion record's path is reserved under the state directory and is built by nothing."""

    def setUp(self) -> None:
        self.record_dir = render("{{ ring_controller_host_promotion_record_dir }}")
        self.state_dir = render("{{ ring_controller_host_state_dir }}")
        self.task_text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.env_text = ENV_TEMPLATE.read_text(encoding="utf-8")
        self.rw_paths = [
            v.strip()
            for key, value in unit_keys(SERVICE.read_text(encoding="utf-8"))
            if key == "ReadWritePaths"
            for v in value.split()
        ]

    def problems(
        self,
        record_dir: str | None = None,
        task_text: str | None = None,
        env_text: str | None = None,
    ) -> list[str]:
        return promotion_record_problems(
            self.record_dir if record_dir is None else record_dir,
            self.state_dir,
            self.task_text if task_text is None else task_text,
            self.env_text if env_text is None else env_text,
            self.rw_paths,
        )

    def test_the_path_is_under_the_state_directory_and_nothing_names_it(self) -> None:
        self.assertEqual(self.problems(), [])
        self.assertEqual(self.record_dir, "/var/lib/branchleft/ring-controller/promotion-record")

    def test_the_check_sees_a_path_moved_out_of_the_state_directory(self) -> None:
        problems = self.problems(record_dir="/var/lib/branchleft/promotion-record")
        self.assertIn("not under the state directory", " ".join(problems))
        self.assertIn("not inside a path the unit may write", " ".join(problems))

    def test_the_check_sees_a_task_that_would_make_the_directory(self) -> None:
        extra = self.task_text + "\n    path: '{{ ring_controller_host_promotion_record_dir }}'\n"
        self.assertIn("a task names it", " ".join(self.problems(task_text=extra)))

    def test_the_check_sees_the_environment_file_naming_it(self) -> None:
        extra = self.env_text + "RING_CONTROLLER_PROMOTION_RECORD_DIR=x\n"
        self.assertIn("the environment file names it", " ".join(self.problems(env_text=extra)))


class InterfaceTests(unittest.TestCase):
    """The argument spec, the defaults and the patterns agree, and the patterns judge as meant."""

    def test_defaults_mirror_the_spec_and_every_default_is_empty(self) -> None:
        spec = cast(
            "dict[str, dict[str, dict[str, dict[str, dict[str, object]]]]]",
            load(ROLE / "meta" / "argument_specs.yml"),
        )["argument_specs"]["main"]["options"]
        defaults = role_defaults()
        self.assertEqual(sorted(spec), sorted(defaults))
        for name, option in spec.items():
            self.assertEqual(option["default"], defaults[name], name)
            self.assertEqual(option["type"], "str", name)
            self.assertEqual(defaults[name], "", name)
            self.assertNotIn("no_log", option, name)

    def pattern(self, name: str) -> re.Pattern[str]:
        return re.compile(str(role_vars()[name]))

    def test_the_digest_pattern(self) -> None:
        pattern = self.pattern("ring_controller_host_sha256_pattern")
        self.assertTrue(pattern.match(DIGEST))
        for bad in ("a" * 63, "A" * 64, "g" * 64, DIGEST + "\n", " " + DIGEST):
            self.assertIsNone(pattern.match(bad), bad)

    def test_a_url_carries_no_credential_query_or_fragment_and_is_https(self) -> None:
        for name in (
            "ring_controller_host_bundle_url_pattern",
            "ring_controller_host_ledger_url_pattern",
        ):
            pattern = self.pattern(name)
            for good in (
                "https://example.test/a/b.tar.gz",
                "https://example.test:8443/x",
                "https://a.example.test",
            ):
                self.assertTrue(pattern.match(good), good)
            for bad in (
                "http://example.test/x",
                "https://user:pw@example.test/x",
                "https://user@example.test/x",
                "https://example.test/x?a=b",
                "https://example.test/x#f",
                "https://example.test/x y",
                "https://example.test/x\n",
                "https://example.test/$x",
                "file:///tmp/x",
                "https://example.test/x'y",
            ):
                self.assertIsNone(pattern.match(bad), bad)

    def test_the_push_remote_is_one_ssh_git_remote_with_no_repository_hard_coded(self) -> None:
        pattern = self.pattern("ring_controller_host_push_remote_pattern")
        self.assertTrue(pattern.match("ssh://git@example.test/org/repo.git"))
        self.assertTrue(pattern.match("ssh://git@example.test:2222/org/repo.git"))
        for bad in (
            "ssh://root@example.test/org/repo.git",
            "ssh://git@example.test/org/repo",
            "git@example.test:org/repo.git",
            "https://example.test/org/repo.git",
            "ssh://git@example.test/org/repo.git\n",
            "ssh://git@example.test/org/repo.git --upload-pack=x",
        ):
            self.assertIsNone(pattern.match(bad), bad)
        # The shipped text files only: not the tests, the scenarios or what a tool caches.
        skipped = {"tests", "molecule", "__pycache__", ".mypy_cache", ".ruff_cache"}
        for path in ROLE.rglob("*"):
            if path.is_file() and not skipped & set(path.relative_to(ROLE).parts):
                self.assertNotRegex(
                    path.read_text(encoding="utf-8"), r"promotion-ledger|branchLeft/"
                )

    def test_a_known_hosts_line_is_one_host_one_type_and_one_key(self) -> None:
        pattern = self.pattern("ring_controller_host_known_hosts_pattern")
        key = "AAAAC3NzaC1lZDI1NTE5AAAAIA=="
        for good in (
            f"example.test ssh-ed25519 {key}",
            f"[example.test]:2222,203.0.113.4 ssh-ed25519 {key}",
        ):
            self.assertTrue(pattern.match(good), good)
        for bad in (
            f"example.test ssh-ed25519 {key}\nother ssh-ed25519 {key}",
            f"example.test ssh-ed25519 {key} comment",
            f"example.test ssh-dss {key}",
            f"@cert-authority example.test ssh-ed25519 {key}",
            f"example.test ssh-ed25519 {key}\n",
        ):
            self.assertIsNone(pattern.match(bad), bad)


if __name__ == "__main__":
    unittest.main()
