"""Unit tests that hold the role's files and tasks to what the collector's host side must be.

The tests read the real files, never a copy. Each control a test names was run red on a
sabotaged copy and green on the file as shipped (the pull request records both). The checks that
look for a forbidden thing are first shown able to find it, on text made to hold it.

The collector holds three secrets (the sending user and password, the drain token and the
heartbeat URL) and none of them is a value here: they are a root-only file the owner places, which
the unit waits for. A collector that cannot start is not a pass, so every test below that guards
the unit also guards the host's side of that rule: with no settings, no descriptor or no
credentials the unit does not run, and with an input missing the role holds it off.
"""

import re
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import jinja2
from ansible.plugins.filter.core import FilterModule
from ansible.plugins.test.core import TestModule
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
UNIT = ROLE / "files" / "mail-collector.service"
UNIT_ENV_TEMPLATE = ROLE / "templates" / "unit.env.j2"
ENV_TEMPLATE = ROLE / "templates" / "collector.env.j2"
IMAGE = "ghcr.io/branchleft/mail-collector@sha256:" + "a" * 64

# The settings the collector's own reader takes from the environment (services/mail-collector/src
# config.ts): the public ones this role writes, and the four the owner's file holds. A name outside
# both would be ignored by the collector, so the check for it is a check that the role does not
# drift from the reader.
PUBLIC_NAMES = [
    "COLLECTOR_DESCRIPTOR_DIR",
    "COLLECTOR_DEDUPE_STATE_PATH",
    "COLLECTOR_PIN_STATE_DIR",
    "COLLECTOR_SWEEGO_USAGE_STATE_PATH",
    "COLLECTOR_SMTP_HOST",
    "COLLECTOR_SMTP_PORT",
    "COLLECTOR_SMTP_SECURE",
    "COLLECTOR_SHIM_SCHEME",
    "COLLECTOR_SHIM_PORT",
]
CREDENTIAL_NAMES = {
    "COLLECTOR_SMTP_USER",
    "COLLECTOR_SMTP_PASS",
    "COLLECTOR_DRAIN_TOKEN",
    "COLLECTOR_HEARTBEAT_URL",
}
ENV_NAMES = ["MAIL_COLLECTOR_IMAGE", "MAIL_COLLECTOR_USER"]
ALLOWED_PREFIXES = (
    "/etc/branchleft/mail-collector",
    "/var/lib/branchleft/mail-collector",
    "/etc/systemd/system/mail-collector.service",
)
WRITING_MODULES = {"copy", "template", "file"}
FORBIDDEN_MODULES = {"shell", "command", "script", "raw", "slurp", "pipe", "fetch", "lineinfile"}
CHANGING_MODULES = {"group", "user", "file", "copy", "template", "systemd_service", "meta"}


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
    # Ansible text, unit files and environment files, never HTML, so there is nothing to escape.
    environment = jinja2.Environment(  # noqa: S701
        undefined=jinja2.StrictUndefined, keep_trailing_newline=True, trim_blocks=True
    )
    # Ansible's own filters, so a template is judged by what it does on a host.
    environment.filters.update(FilterModule().filters())
    environment.tests.update(TestModule().tests())
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


def holds(task: dict[str, object], variables: Mapping[str, object]) -> bool:
    """Return whether every condition of an assert task holds for the variables.

    Each condition is judged as Ansible judges it: rendered with the role's own variables, the
    Ansible filters and the Ansible tests (`match`), so a refusal is proven by the task as shipped.
    """
    conditions = cast("list[str]", args_of(task)["that"])
    return all(render("{{ " + c + " }}", variables) == "True" for c in conditions)


def module_of(task: dict[str, object]) -> str | None:
    """Return the short name of the module a task calls."""
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


def unit_values(text: str, key: str) -> list[str]:
    """Return the values of every `key=` line of a unit file, in file order."""
    return [
        line.split("=", 1)[1]
        for line in text.splitlines()
        if line.startswith(f"{key}=") and not line.lstrip().startswith("#")
    ]


def unit_problems(text: str) -> list[str]:
    """Return what is wrong with the unit: each way it could run with more than it is meant to."""
    start = " ".join(unit_values(text, "ExecStart"))
    problems = []
    for flag in ("--read-only", "--cap-drop ALL", "--security-opt no-new-privileges"):
        if flag not in start:
            problems.append(f"missing {flag}")
    if "--user ${MAIL_COLLECTOR_USER}" not in start:
        problems.append("does not run as the account")
    for forbidden in (
        "--privileged", "--publish", " -p ", "--network", "--pid", "--ipc", "--userns",
        "--cap-add", "docker.sock", "--device", "--volumes-from", "--entrypoint", "--env ",
        "--add-host", "--dns",
    ):  # fmt: skip
        if forbidden in start:
            problems.append(f"has {forbidden.strip()}")
    credentials = str(role_vars()["mail_collector_credentials_file"])
    credentials_dir = credentials.rsplit("/", 1)[0]
    descriptors = str(role_vars()["mail_collector_descriptor_dir"])
    for volume in re.findall(r"--volume (\S+)", start):
        if volume.endswith((":rw", ":ro")) is False:
            problems.append(f"volume without a mode: {volume}")
        source = volume.split(":", 1)[0]
        if credentials.startswith(source.rstrip("/") + "/") or source == credentials_dir:
            problems.append(f"credentials mounted into the container: {volume}")
        if source == descriptors and not volume.endswith(":ro"):
            problems.append("descriptor directory is not mounted read-only")
    return problems


class UnitFileTests(unittest.TestCase):
    """The unit runs the pinned image with the least the collector needs, and only when it can."""

    def setUp(self) -> None:
        self.text = UNIT.read_text(encoding="utf-8")

    def test_the_unit_is_a_plain_static_file_named_as_the_role_says(self) -> None:
        self.assertEqual(role_vars()["mail_collector_unit"], UNIT.name)
        for marker in ("{{", "{%", "%i", "%I"):
            self.assertNotIn(marker, self.text)

    def test_the_unit_runs_only_when_the_settings_the_credentials_and_a_descriptor_exist(
        self,
    ) -> None:
        # A condition that is not met leaves the unit inactive instead of failing. No path to a
        # running collector without a real configuration, the owner's credentials and at least
        # one descriptor: with none named the heartbeat would be withheld by design, and starting
        # against a real heartbeat URL before a host is named is not what is meant.
        self.assertEqual(
            unit_values(self.text, "ConditionFileNotEmpty"),
            [
                role_vars()["mail_collector_env_file"],
                role_vars()["mail_collector_credentials_file"],
            ],
        )
        self.assertEqual(
            unit_values(self.text, "ConditionDirectoryNotEmpty"),
            [role_vars()["mail_collector_descriptor_dir"]],
        )
        self.assertEqual(unit_values(self.text, "ConditionPathExists"), [])

    def test_the_unit_is_hardened_and_the_check_can_see_each_way_it_could_be_loosened(self) -> None:
        self.assertEqual(unit_problems(self.text), [])
        # The control: the same check, run on text made to hold each forbidden thing, finds it.
        start = unit_values(self.text, "ExecStart")[0]
        credentials_dir = str(role_vars()["mail_collector_credentials_file"]).rsplit("/", 1)[0]
        descriptors = str(role_vars()["mail_collector_descriptor_dir"])
        loosened = [
            start.replace("--read-only ", ""),
            start.replace("--cap-drop ALL ", ""),
            start.replace("--security-opt no-new-privileges ", ""),
            start.replace("--user ${MAIL_COLLECTOR_USER}", "--user 0:0"),
            start.replace("--rm ", "--rm --privileged "),
            start.replace("--rm ", "--rm --publish 8080:8080 "),
            start.replace("--rm ", "--rm --network host "),
            start.replace("--rm ", "--rm --volume /var/run/docker.sock:/var/run/docker.sock:rw "),
            start.replace("--rm ", f"--rm --volume {credentials_dir}:/creds:ro "),
            start.replace(f"{descriptors}:/descriptors:ro", f"{descriptors}:/descriptors:rw"),
            start.replace("--rm ", "--rm --env COLLECTOR_DRAIN_TOKEN=x "),
        ]
        for variant in loosened:
            with self.subTest(variant=variant[:90]):
                self.assertTrue(unit_problems(f"ExecStart={variant}\n"))

    def test_the_unit_mounts_the_descriptors_read_only_and_the_state_read_write_and_nothing_else(
        self,
    ) -> None:
        start = unit_values(self.text, "ExecStart")[0]
        descriptors = str(role_vars()["mail_collector_descriptor_dir"])
        state = str(role_vars()["mail_collector_state_dir"])
        self.assertEqual(
            re.findall(r"--volume (\S+)", start),
            [
                f"{descriptors}:{role_vars()['mail_collector_container_descriptor_dir']}:ro",
                f"{state}:{role_vars()['mail_collector_container_state_dir']}:rw",
            ],
        )

    def test_the_container_gets_its_settings_from_the_two_files_in_that_order_and_nothing_else(
        self,
    ) -> None:
        start = unit_values(self.text, "ExecStart")[0]
        self.assertEqual(
            re.findall(r"--env-file (\S+)", start),
            [
                role_vars()["mail_collector_env_file"],
                role_vars()["mail_collector_credentials_file"],
            ],
        )
        self.assertEqual(
            unit_values(self.text, "EnvironmentFile"), [role_vars()["mail_collector_unit_env_file"]]
        )
        self.assertEqual(start.split()[-1], "${MAIL_COLLECTOR_IMAGE}")

    def test_the_unit_names_no_credential_value_and_no_agent_or_model_key(self) -> None:
        for text in (
            self.text,
            UNIT_ENV_TEMPLATE.read_text(encoding="utf-8"),
            ENV_TEMPLATE.read_text(encoding="utf-8"),
        ):
            self.assertNotRegex(text, r"[A-Z0-9_]*_API_KEY")
            self.assertNotRegex(text, r"(?i)\bbearer\b|authorization")
            self.assertNotRegex(text, r"(?i)\bclaude\b")
            for name in CREDENTIAL_NAMES:
                self.assertNotIn(name, text)

    def test_the_unit_restarts_always_with_no_start_limit_and_a_pause_between_tries(self) -> None:
        # A collector that stops is a host whose mail is never collected, so a start limit that
        # leaves it failed after a burst would be the silent failure the unit is built against.
        self.assertEqual(unit_values(self.text, "Restart"), ["always"])
        self.assertEqual(unit_values(self.text, "RestartSec"), ["10"])
        self.assertEqual(unit_values(self.text, "StartLimitIntervalSec"), ["0"])
        self.assertEqual(unit_values(self.text, "StartLimitBurst"), [])

    def test_the_unit_has_a_start_condition_the_sabotaged_unit_does_not(self) -> None:
        # Sabotage control: drop the descriptor condition and the test above must see it gone.
        without = "\n".join(
            line for line in self.text.splitlines() if not line.startswith("ConditionDirectory")
        )
        self.assertEqual(unit_values(without, "ConditionDirectoryNotEmpty"), [])
        self.assertNotEqual(unit_values(self.text, "ConditionDirectoryNotEmpty"), [])


class RenderedFilesTests(unittest.TestCase):
    """The environment files hold public values and exactly the names the collector reads."""

    def public(self, **overrides: object) -> dict[str, str]:
        variables: dict[str, object] = {"mail_collector_smtp_host": "submit.example", **overrides}
        text = render(ENV_TEMPLATE.read_text(encoding="utf-8"), variables)
        pairs = [line.split("=", 1) for line in text.splitlines() if line and line[0] != "#"]
        self.assertEqual([name for name, _ in pairs], PUBLIC_NAMES)
        return dict(pairs)

    def test_the_settings_hold_only_names_the_collector_reads_and_none_of_the_credentials(
        self,
    ) -> None:
        values = self.public()
        self.assertTrue(set(values).isdisjoint(CREDENTIAL_NAMES))

    def test_the_sending_target_and_the_drain_surface_are_inputs(self) -> None:
        values = self.public(
            mail_collector_smtp_host="submit.example",
            mail_collector_smtp_port=465,
            mail_collector_smtp_secure=True,
            mail_collector_shim_scheme="https",
            mail_collector_shim_port=8443,
        )
        self.assertEqual(values["COLLECTOR_SMTP_HOST"], "submit.example")
        self.assertEqual(values["COLLECTOR_SMTP_PORT"], "465")
        self.assertEqual(values["COLLECTOR_SMTP_SECURE"], "true")
        self.assertEqual(values["COLLECTOR_SHIM_SCHEME"], "https")
        self.assertEqual(values["COLLECTOR_SHIM_PORT"], "8443")

    def test_the_secure_flag_renders_false_by_default(self) -> None:
        self.assertEqual(self.public()["COLLECTOR_SMTP_SECURE"], "false")

    def test_the_demo_mail_domain_is_written_only_when_set_and_empty_means_demo_mail_is_held(
        self,
    ) -> None:
        # Unset, the collector holds every demo host's mail unsent and unacked, the safe state, so
        # the default writes no line at all rather than an empty one.
        self.assertEqual(role_defaults()["mail_collector_demo_mail_domain"], "")
        self.assertNotIn("COLLECTOR_DEMO_MAIL_DOMAIN", self.public())
        text = render(
            ENV_TEMPLATE.read_text(encoding="utf-8"),
            {
                "mail_collector_smtp_host": "s.example",
                "mail_collector_demo_mail_domain": "demo.example",
            },
        )
        pairs = [line.split("=", 1) for line in text.splitlines() if line and line[0] != "#"]
        names = [name for name, _ in pairs]
        self.assertEqual(
            names, [*PUBLIC_NAMES[:5], "COLLECTOR_DEMO_MAIL_DOMAIN", *PUBLIC_NAMES[5:]]
        )
        self.assertEqual(dict(pairs)["COLLECTOR_DEMO_MAIL_DOMAIN"], "demo.example")
        self.assertNotIn("\n\n", text.split("COLLECTOR_DESCRIPTOR_DIR", 1)[1])

    def test_the_container_paths_are_the_ones_the_unit_mounts(self) -> None:
        values = self.public()
        self.assertEqual(
            values["COLLECTOR_DESCRIPTOR_DIR"],
            role_vars()["mail_collector_container_descriptor_dir"],
        )
        dedupe = values["COLLECTOR_DEDUPE_STATE_PATH"]
        self.assertTrue(dedupe.startswith(str(role_vars()["mail_collector_container_state_dir"])))

    def test_the_three_state_settings_are_set_and_under_the_persistent_volume_the_unit_mounts(
        self,
    ) -> None:
        # Unset, the collector keeps pins, the record of submitted messages and the Sweego usage
        # counters in memory only. All three are written, each under the one directory the unit
        # mounts read-write, which is the host's persistent state directory.
        values = self.public()
        state = str(role_vars()["mail_collector_container_state_dir"])
        start = unit_values(UNIT.read_text(encoding="utf-8"), "ExecStart")[0]
        self.assertIn(f"{role_vars()['mail_collector_state_dir']}:{state}:rw", start)
        for name in (
            "COLLECTOR_DEDUPE_STATE_PATH",
            "COLLECTOR_PIN_STATE_DIR",
            "COLLECTOR_SWEEGO_USAGE_STATE_PATH",
        ):
            with self.subTest(name=name):
                self.assertTrue(values[name].startswith(state + "/"), values[name])
        self.assertEqual(
            values["COLLECTOR_PIN_STATE_DIR"], role_vars()["mail_collector_container_pin_dir"]
        )
        # The pin directory the role makes on the host is the one the container sees as the pins.
        host_pins = str(role_vars()["mail_collector_host_pin_dir"])
        host_state = str(role_vars()["mail_collector_state_dir"])
        pin_dir = str(role_vars()["mail_collector_container_pin_dir"])
        self.assertEqual(host_pins.removeprefix(host_state), pin_dir.removeprefix(state))

    def test_no_rendered_file_holds_a_secret_name_or_anything_but_plain_words(self) -> None:
        # The files are public text. A name that smells of a credential, or a value that is not one
        # plain word, is where a secret would hide; the check is shown able to find one below.
        smell = re.compile(r"(?i)pass|secret|token|key|credential|heartbeat")
        rendered = [
            render(
                ENV_TEMPLATE.read_text(encoding="utf-8"), {"mail_collector_smtp_host": "s.example"}
            ),
            render(
                UNIT_ENV_TEMPLATE.read_text(encoding="utf-8"),
                {"mail_collector_uid": "921", "mail_collector_gid": "922"},
            ),
        ]
        for text in rendered:
            for line in (line for line in text.splitlines() if line and line[0] != "#"):
                name, value = line.split("=", 1)
                self.assertNotRegex(
                    name.removeprefix("COLLECTOR_").removeprefix("MAIL_COLLECTOR_"), smell
                )
                self.assertRegex(value, r"^[A-Za-z0-9./:@_-]*\Z", name)
        # The control: a planted credential line is found by both halves of the check.
        planted = "COLLECTOR_SMTP_PASS=hunter2 and more\n"
        name, value = planted.split("=", 1)
        self.assertRegex(name.removeprefix("COLLECTOR_"), smell)
        self.assertIsNone(re.match(r"^[A-Za-z0-9./:@_-]*\Z", value.rstrip("\n")))

    def test_the_unit_environment_holds_the_image_and_the_account_and_nothing_else(self) -> None:
        text = render(
            UNIT_ENV_TEMPLATE.read_text(encoding="utf-8"),
            {"mail_collector_uid": "921", "mail_collector_gid": "922"},
        )
        pairs = [line.split("=", 1) for line in text.splitlines() if line and line[0] != "#"]
        self.assertEqual([name for name, _ in pairs], ENV_NAMES)
        self.assertEqual(
            dict(pairs)["MAIL_COLLECTOR_IMAGE"], role_defaults()["mail_collector_image"]
        )
        self.assertEqual(dict(pairs)["MAIL_COLLECTOR_USER"], "921:922")


class InterfaceTests(unittest.TestCase):
    """The argument spec, the defaults and the patterns agree, and the patterns judge as meant."""

    def pattern(self, name: str) -> re.Pattern[str]:
        return re.compile(str(role_vars()[name]))

    def test_defaults_mirror_the_spec(self) -> None:
        spec = cast(
            "dict[str, dict[str, dict[str, dict[str, dict[str, object]]]]]",
            load(ROLE / "meta" / "argument_specs.yml"),
        )["argument_specs"]["main"]["options"]
        defaults = role_defaults()
        self.assertEqual(sorted(spec), sorted(defaults))
        for name, option in spec.items():
            self.assertEqual(option["default"], defaults[name], name)
            self.assertNotIn("no_log", option, name)

    def test_the_default_image_is_the_placeholder_the_role_refuses_to_run(self) -> None:
        image = str(role_defaults()["mail_collector_image"])
        self.assertEqual(image, role_vars()["mail_collector_image_placeholder"])
        # Right shape, so the role accepts it as an input, and a digest of nothing but zeros.
        self.assertRegex(image, str(role_vars()["mail_collector_image_pattern"]))
        self.assertEqual(image.split(":")[-1], "0" * 64)

    def test_the_image_must_be_the_collectors_image_pinned_by_digest(self) -> None:
        pattern = self.pattern("mail_collector_image_pattern")
        self.assertTrue(pattern.match(IMAGE))
        for bad in (
            "",
            "ghcr.io/branchleft/mail-collector:latest",
            "ghcr.io/branchleft/mail-collector:" + "a" * 64,
            "ghcr.io/branchleft/mail-collector",
            "ghcr.io/branchleft/other@sha256:" + "a" * 64,
            "example.test/branchleft/mail-collector@sha256:" + "a" * 64,
            "ghcr.io/branchleft/mail-collector@sha256:" + "A" * 64,
            "ghcr.io/branchleft/mail-collector@sha256:" + "a" * 63,
            IMAGE + "\n",
            IMAGE + " --privileged",
            "--privileged " + IMAGE,
        ):
            self.assertIsNone(pattern.match(bad), bad)

    def test_the_demo_mail_domain_is_a_bare_domain(self) -> None:
        pattern = self.pattern("mail_collector_demo_mail_domain_pattern")
        for good in ("demo.example", "a.b.c.example", "xn--bcher-kva.example", "a-b.example"):
            self.assertTrue(pattern.match(good), good)
        for bad in (
            "", "demo", "https://demo.example", "demo.example/", "user@demo.example",
            "@demo.example", "demo.example ", " demo.example", "de mo.example", "demo.example\n",
            "demo.example:25", "-demo.example", "demo-.example", ".demo.example", "demo..example",
            "demo.example.", "demo_x.example", "demo.example, other.example", "*.demo.example",
        ):  # fmt: skip
            self.assertIsNone(pattern.match(bad), bad)

    def test_a_sending_host_is_one_plain_host_name(self) -> None:
        pattern = self.pattern("mail_collector_smtp_host_pattern")
        for good in ("a", "submit.example", "a-b.c.example", "x" * 253):
            self.assertTrue(pattern.match(good), good)
        for bad in (
            "", "-a.example", "a.example-", "a b", "a/b", "a:587", "a\n", "a$b", "a'b", "x" * 254
        ):  # fmt: skip
            self.assertIsNone(pattern.match(bad), bad)

    def test_the_schemes_are_http_and_https(self) -> None:
        self.assertEqual(role_vars()["mail_collector_shim_schemes"], ["http", "https"])


class TaskTests(unittest.TestCase):
    """The tasks refuse early, hold the collector off without its inputs, touch only its paths."""

    def test_no_task_runs_a_program_or_reads_a_secret(self) -> None:
        for task in tasks():
            self.assertNotIn(module_of(task), FORBIDDEN_MODULES, task.get("name"))
        text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertNotRegex(text, r"lookup\(|query\(|\bpipe\b|\bslurp\b")
        self.assertNotRegex(text, r"no_log:\s*(false|no)")

    def test_no_literal_destination_is_outside_the_roles_own_paths(self) -> None:
        seen: list[str] = []
        for task in tasks():
            if module_of(task) not in WRITING_MODULES:
                continue
            args = args_of(task)
            seen.extend(render(str(args[key])) for key in ("dest", "path") if key in args)
        self.assertGreaterEqual(len(seen), 6)
        outside = [p for p in seen if not p.startswith(ALLOWED_PREFIXES)]
        self.assertEqual(outside, [])

    def test_the_role_never_writes_the_credentials_file(self) -> None:
        credentials = str(role_vars()["mail_collector_credentials_file"])
        for task in tasks():
            if module_of(task) in WRITING_MODULES:
                dest = str(args_of(task).get("dest", args_of(task).get("path", "")))
                self.assertNotEqual(render(dest), credentials, task.get("name"))
        text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        # It is named by a stat and an assert only, and a stat of it takes no checksum.
        stat = args_of(named("Look at the credentials file"))
        self.assertIs(stat["get_checksum"], False)
        self.assertEqual(text.count("mail_collector_credentials_file"), 1)

    def test_the_role_leaves_the_descriptor_directory_empty(self) -> None:
        make = args_of(named("Make the descriptor directory"))
        self.assertEqual(make["state"], "directory")
        for task in tasks():
            if module_of(task) in {"copy", "template"}:
                dest = render(str(args_of(task)["dest"]))
                self.assertFalse(
                    dest.startswith(str(role_vars()["mail_collector_descriptor_dir"]) + "/"),
                    task.get("name"),
                )

    def test_a_placed_credentials_file_must_be_roots_and_mode_0600_or_the_run_stops(self) -> None:
        check = named("Require a placed credentials file")
        self.assertEqual(module_of(check), "assert")
        self.assertEqual(check["when"], "mail_collector_credentials_stat.stat.exists")
        that = "\n".join(str(item) for item in cast("list[object]", args_of(check)["that"]))
        self.assertIn("stat.uid == 0", that)
        self.assertIn("stat.mode == mail_collector_credentials_mode", that)
        self.assertEqual(role_vars()["mail_collector_credentials_mode"], "0600")

    def test_the_inputs_are_refused_before_anything_changes(self) -> None:
        first_change = next(i for i, t in enumerate(tasks()) if module_of(t) in CHANGING_MODULES)
        before = tasks()[:first_change]
        self.assertGreaterEqual(len([t for t in before if module_of(t) == "assert"]), 4)
        text = "\n".join(str(t) for t in before)
        for name in role_defaults():
            self.assertIn(name, text)

    def test_a_demo_mail_domain_that_is_set_and_not_a_bare_domain_stops_the_run(self) -> None:
        check = named("Refuse a demo mail domain")
        self.assertEqual(module_of(check), "assert")
        first_change = next(i for i, t in enumerate(tasks()) if module_of(t) in CHANGING_MODULES)
        self.assertLess(tasks().index(check), first_change)
        for good in ("", "demo.example", "a.b.example"):
            with self.subTest(good=good):
                self.assertTrue(holds(check, {"mail_collector_demo_mail_domain": good}))
        for bad in (
            "https://demo.example", "user@demo.example", "demo.example ", "de mo.example",
            "demo", "demo.example\n", "demo.example:25", ("a" * 63 + ".") * 4 + "example",
        ):  # fmt: skip
            with self.subTest(bad=bad[:30]):
                self.assertFalse(holds(check, {"mail_collector_demo_mail_domain": bad}))

    def test_an_empty_or_unpinned_image_stops_the_run_before_anything_changes(self) -> None:
        # Fail closed: the digest has no default that passes as set. An empty value, a tag and a
        # value that is not a string all fail the assert, so the run stops at the first task.
        check = tasks()[0]
        self.assertEqual(module_of(check), "assert")
        self.assertIn("mail_collector_image", str(check))
        self.assertTrue(holds(check, {"mail_collector_image": IMAGE}))
        for bad in ("", "ghcr.io/branchleft/mail-collector:latest", "sha256:" + "a" * 64, "\n"):
            with self.subTest(image=bad[:30]):
                self.assertFalse(holds(check, {"mail_collector_image": bad}))
        # The all-zero placeholder is the one value that passes the assert and is held off by the
        # run rule instead; the host's play carries the default, so a stop there would fail every
        # apply of ops1 until the owner sets a digest.
        self.assertTrue(
            holds(check, {"mail_collector_image": role_defaults()["mail_collector_image"]})
        )

    def test_a_state_path_that_is_empty_or_not_under_the_persistent_directory_stops_the_run(
        self,
    ) -> None:
        check = named("Refuse a state path")
        self.assertEqual(module_of(check), "assert")
        # The loop covers each of the three paths the collector keeps state in, and the assert is
        # the first change-free gate: it sits before every task that changes the host.
        self.assertEqual(
            check["loop"],
            [
                "{{ mail_collector_container_dedupe_file }}",
                "{{ mail_collector_container_pin_dir }}",
                "{{ mail_collector_container_sweego_usage_file }}",
            ],
        )
        first_change = next(i for i, t in enumerate(tasks()) if module_of(t) in CHANGING_MODULES)
        self.assertLess(tasks().index(check), first_change)
        for good in (
            "/state/dedupe.json",
            "/state/pins",
            "/state/sweego-usage.json",
            "/state/a/b-c_d.json",
        ):
            with self.subTest(good=good):
                self.assertTrue(holds(check, {"item": good}))
        for bad in (
            "", "/elsewhere/dedupe.json", "/state", "/state/", "/statefoo/x", "/state/../etc/x",
            "/state/a b", "state/x", "/state/x\n", "/state/.hidden/../x",
        ):  # fmt: skip
            with self.subTest(bad=bad):
                self.assertFalse(holds(check, {"item": bad}))

    def test_the_pin_directory_is_made_by_the_role_for_the_account_and_closed_to_everyone_else(
        self,
    ) -> None:
        make = named("Make the pin directory")
        self.assertEqual(module_of(make), "file")
        pins = args_of(make)
        self.assertEqual(pins["state"], "directory")
        self.assertEqual(pins["mode"], "0700")
        self.assertEqual(pins["owner"], "{{ mail_collector_account }}")
        self.assertEqual(pins["path"], "{{ mail_collector_host_pin_dir }}")

    def test_the_collector_runs_only_with_a_real_image_and_a_sending_host(self) -> None:
        fact = args_of(named("Note whether the collector is meant to run"))
        run_template = str(fact["mail_collector_run"])
        placeholder = str(role_vars()["mail_collector_image_placeholder"])
        for image, host, expected in (
            (placeholder, "", "False"),
            (placeholder, "submit.example", "False"),
            (IMAGE, "", "False"),
            (IMAGE, "submit.example", "True"),
        ):
            with self.subTest(image=image[-6:], host=host):
                variables = {"mail_collector_image": image, "mail_collector_smtp_host": host}
                self.assertEqual(render(run_template, variables), expected)

    def test_the_collector_is_held_off_unless_it_is_meant_to_run(self) -> None:
        hold = args_of(named("Hold the collector"))
        for run, enabled, state in (("False", "False", "stopped"), ("True", "True", "started")):
            with self.subTest(run=run):
                variables = {"mail_collector_run": run == "True"}
                self.assertEqual(render(str(hold["enabled"]), variables), enabled)
                self.assertEqual(render(str(hold["state"]), variables), state)
        self.assertEqual(hold["name"], "{{ mail_collector_unit }}")

    def test_the_settings_are_written_only_when_the_collector_is_meant_to_run(self) -> None:
        write = named("Write the collector's settings")
        self.assertEqual(module_of(write), "template")
        self.assertEqual(write["when"], "mail_collector_run | bool")
        remove = named("Remove the collector's settings")
        self.assertEqual(args_of(remove)["state"], "absent")
        self.assertEqual(remove["when"], "not mail_collector_run | bool")

    def test_the_restart_handler_runs_only_for_a_collector_that_is_meant_to_run(self) -> None:
        handlers = cast("list[dict[str, object]]", load(ROLE / "handlers" / "main.yml"))
        restart = next(h for h in handlers if str(h["name"]).startswith("Restart"))
        for run, check, restarts in (
            (False, False, False),
            (False, True, False),
            (True, False, True),
            (True, True, False),
        ):
            with self.subTest(run=run, check=check):
                variables = {"mail_collector_run": run, "ansible_check_mode": check}
                expression = "{{ " + str(restart["when"]) + " }}"
                self.assertEqual(render(expression, variables), str(restarts))

    def test_the_account_is_a_system_account_that_cannot_log_in(self) -> None:
        user = args_of(named("Create the collector account"))
        self.assertIs(user["system"], True)
        self.assertIs(user["create_home"], False)
        self.assertEqual(user["shell"], "/usr/sbin/nologin")

    def test_the_state_directory_is_the_accounts_and_closed_to_everyone_else(self) -> None:
        state = args_of(named("Make the state directory"))
        self.assertEqual(state["mode"], "0700")
        self.assertEqual(state["owner"], "{{ mail_collector_account }}")

    def test_the_parents_are_asserted_and_never_changed(self) -> None:
        parents = cast("list[str]", role_vars()["mail_collector_parents"])
        self.assertEqual(parents, ["/etc/branchleft", "/var/lib/branchleft"])
        for task in tasks():
            if module_of(task) in WRITING_MODULES:
                self.assertNotIn("mail_collector_parents", str(task))

    def test_the_unit_is_installed_as_a_static_file(self) -> None:
        install = named("Install the collector unit")
        self.assertEqual(module_of(install), "copy")
        self.assertNotIn("content", args_of(install))


if __name__ == "__main__":
    unittest.main()
