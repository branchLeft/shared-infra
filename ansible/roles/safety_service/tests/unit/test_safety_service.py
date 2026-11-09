"""Unit tests that hold the role's files and tasks to what the safety service's host side must be.

The tests read the real files, never a copy. Each control a test names was run red on a
sabotaged copy and green on the file as shipped (the pull request records both). The checks that
look for a forbidden thing are first shown able to find it, on text made to hold it.

The service holds one credential (the hash source's) and one key (the channel's signing key), and
neither is a value here: both are files the unit waits for. A service that cannot start is not a
pass, so every test below that guards the unit also guards the host's side of that rule: with no
configuration, key or credential the unit does not run, and with an input missing the role holds
it off.
"""

import json
import re
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import jinja2
from ansible.plugins.filter.core import FilterModule
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
ROLES = ROLE.parent
UNIT = ROLE / "files" / "content-safety.service"
ENV_TEMPLATE = ROLE / "templates" / "service.env.j2"
CONFIG_TEMPLATE = ROLE / "templates" / "config.json.j2"
IMAGE = "ghcr.io/branchleft/content-safety@sha256:" + "a" * 64
HOST = {"id": "host-one", "kind": "demo", "endpoint": "https://host-one.example"}

# The keys the service's own configuration reader accepts, from its src/config.ts. The service
# refuses a key it does not know, so a rendered key outside these lists would keep it from starting.
SERVICE_CONFIG_KEYS = {"arachnid", "channel", "cache", "audit", "shutdownGraceMs", "hosts"}
SERVICE_HOST_KEYS = {"id", "kind", "safety", "endpoint"}
ENV_NAMES = ["SAFETY_SERVICE_IMAGE", "SAFETY_SERVICE_USER"]
ALLOWED_PREFIXES = (
    "/etc/branchleft/safety-service",
    "/var/lib/branchleft/safety-service",
    "/etc/systemd/system/content-safety.service",
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
    # Ansible text, unit files and JSON, never HTML, so there is nothing to escape.
    environment = jinja2.Environment(  # noqa: S701
        undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    # Ansible's own filters, so a template is judged by what it does on a host.
    environment.filters.update(FilterModule().filters())
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
    secrets = str(role_vars()["safety_service_secrets_dir"])
    problems = []
    for flag in ("--read-only", "--cap-drop ALL", "--security-opt no-new-privileges"):
        if flag not in start:
            problems.append(f"missing {flag}")
    if "--user ${SAFETY_SERVICE_USER}" not in start:
        problems.append("does not run as the account")
    for forbidden in (
        "--privileged", "--publish", " -p ", "--network", "--pid", "--ipc", "--userns",
        "--cap-add", "docker.sock", "--device", "--volumes-from", "--env-file", "--entrypoint",
    ):  # fmt: skip
        if forbidden in start:
            problems.append(f"has {forbidden.strip()}")
    if f"--volume {secrets}:{secrets}:ro" not in start:
        problems.append("secrets directory is not mounted read-only")
    for volume in re.findall(r"--volume (\S+)", start):
        if volume.endswith((":rw", ":ro")) is False:
            problems.append(f"volume without a mode: {volume}")
    env_flags = re.findall(r"--env (\S+)", start)
    if env_flags != ["SAFETY_SERVICE_CONFIG=" + str(role_vars()["safety_service_config_file"])]:
        problems.append(f"environment passed to the container: {env_flags}")
    return problems


class UnitFileTests(unittest.TestCase):
    """The unit runs the pinned image with the least the service needs, and only when it can."""

    def setUp(self) -> None:
        self.text = UNIT.read_text(encoding="utf-8")

    def test_the_unit_is_a_plain_static_file_named_as_the_role_says(self) -> None:
        self.assertEqual(role_vars()["safety_service_unit"], UNIT.name)
        for marker in ("{{", "{%", "%i", "%I"):
            self.assertNotIn(marker, self.text)

    def test_the_unit_runs_only_when_the_configuration_the_key_and_the_credential_exist(
        self,
    ) -> None:
        # A condition that is not met leaves the unit inactive instead of failing, and the service
        # would refuse to start without its credential in any case: no path to a running service
        # without all three.
        expected = [
            role_vars()["safety_service_config_file"],
            role_vars()["safety_service_signing_key_file"],
            role_vars()["safety_service_credential_file"],
        ]
        self.assertEqual(unit_values(self.text, "ConditionPathExists"), expected)

    def test_the_unit_is_hardened_and_the_check_can_see_each_way_it_could_be_loosened(self) -> None:
        self.assertEqual(unit_problems(self.text), [])
        # The control: the same check, run on text made to hold each forbidden thing, finds it.
        start = unit_values(self.text, "ExecStart")[0]
        loosened = [
            start.replace("--read-only ", ""),
            start.replace("--cap-drop ALL ", ""),
            start.replace("--security-opt no-new-privileges ", ""),
            start.replace("--user ${SAFETY_SERVICE_USER}", "--user 0:0"),
            start.replace("--rm ", "--rm --privileged "),
            start.replace("--rm ", "--rm --publish 80:80 "),
            start.replace("--rm ", "--rm --network host "),
            start.replace("--rm ", "--rm --volume /var/run/docker.sock:/var/run/docker.sock:rw "),
            start.replace("/etc/branchleft/content-safety:ro", "/etc/branchleft/content-safety:rw"),
            start.replace("--rm ", "--rm --env HASH_SOURCE_CREDENTIAL=x "),
            start.replace("--rm ", "--rm --env-file /etc/branchleft/x.env "),
        ]
        for variant in loosened:
            with self.subTest(variant=variant[:90]):
                self.assertTrue(unit_problems(f"ExecStart={variant}\n"))

    def test_the_unit_mounts_the_configuration_and_the_secrets_read_only_and_the_state_read_write(
        self,
    ) -> None:
        start = unit_values(self.text, "ExecStart")[0]
        config = str(role_vars()["safety_service_config_dir"])
        secrets = str(role_vars()["safety_service_secrets_dir"])
        state = str(role_vars()["safety_service_state_dir"])
        self.assertEqual(
            re.findall(r"--volume (\S+)", start),
            [f"{config}:{config}:ro", f"{secrets}:{secrets}:ro", f"{state}:{state}:rw"],
        )

    def test_the_unit_names_no_credential_value_and_no_agent_or_model_key(self) -> None:
        for text in (self.text, ENV_TEMPLATE.read_text(encoding="utf-8")):
            self.assertNotRegex(text, r"[A-Z0-9_]*_API_KEY")
            self.assertNotRegex(text, r"(?i)\bbearer\b|authorization")
            self.assertNotRegex(text, r"(?i)\bclaude\b")

    def test_the_container_gets_the_image_and_account_from_the_environment_file_only(self) -> None:
        self.assertEqual(
            unit_values(self.text, "EnvironmentFile"), [role_vars()["safety_service_env_file"]]
        )
        self.assertIn("${SAFETY_SERVICE_IMAGE}", unit_values(self.text, "ExecStart")[0])
        self.assertEqual(
            unit_values(self.text, "ExecStart")[0].split()[-1], "${SAFETY_SERVICE_IMAGE}"
        )

    def test_the_unit_restarts_on_failure_with_a_bound_on_how_often(self) -> None:
        self.assertEqual(unit_values(self.text, "Restart"), ["on-failure"])
        self.assertEqual(unit_values(self.text, "StartLimitBurst"), ["5"])
        self.assertEqual(unit_values(self.text, "StartLimitIntervalSec"), ["600"])


class RenderedFilesTests(unittest.TestCase):
    """The configuration and the environment hold public values and what the service reads."""

    def config(self, **overrides: object) -> dict[str, object]:
        variables: dict[str, object] = {
            "safety_service_arachnid_base_url": "https://hash-source.example",
            "safety_service_hosts": [HOST, {**HOST, "id": "host-two", "kind": "tenant"}],
            **overrides,
        }
        text = render(CONFIG_TEMPLATE.read_text(encoding="utf-8"), variables)
        return cast("dict[str, object]", json.loads(text))

    def test_the_configuration_has_only_the_keys_the_service_reads(self) -> None:
        config = self.config()
        self.assertEqual(set(config), SERVICE_CONFIG_KEYS - {"shutdownGraceMs"})
        for host in cast("list[dict[str, object]]", config["hosts"]):
            self.assertEqual(set(host), SERVICE_HOST_KEYS)

    def test_every_host_is_asked_on_both_axes_and_the_origin_is_the_input(self) -> None:
        config = self.config()
        for host in cast("list[dict[str, object]]", config["hosts"]):
            self.assertEqual(host["safety"], {"near": True, "exact": True})
        self.assertEqual(
            cast("dict[str, object]", config["arachnid"])["baseUrl"], "https://hash-source.example"
        )

    def test_the_configuration_names_the_files_and_holds_no_credential(self) -> None:
        config = self.config()
        arachnid = cast("dict[str, object]", config["arachnid"])
        channel = cast("dict[str, object]", config["channel"])
        self.assertEqual(arachnid["credentialFile"], role_vars()["safety_service_credential_file"])
        self.assertEqual(channel["signingKeyFile"], role_vars()["safety_service_signing_key_file"])
        self.assertEqual(
            cast("dict[str, object]", config["audit"])["file"],
            role_vars()["safety_service_audit_file"],
        )
        self.assertEqual(set(arachnid), {"baseUrl", "credentialFile"})
        self.assertNotRegex(
            CONFIG_TEMPLATE.read_text(encoding="utf-8"), r"lookup|query|slurp|vault"
        )

    def test_the_negative_lifetime_is_inside_the_services_cap(self) -> None:
        ttl = cast("int", role_vars()["safety_service_negative_ttl_ms"])
        self.assertGreater(ttl, 0)
        self.assertLessEqual(ttl, 7 * 24 * 60 * 60 * 1000)

    def test_the_environment_holds_the_image_and_the_account_and_nothing_else(self) -> None:
        text = render(
            ENV_TEMPLATE.read_text(encoding="utf-8"),
            {"safety_service_uid": "921", "safety_service_gid": "922"},
        )
        pairs = [line.split("=", 1) for line in text.splitlines() if line and line[0] != "#"]
        self.assertEqual([name for name, _ in pairs], ENV_NAMES)
        self.assertEqual(
            dict(pairs)["SAFETY_SERVICE_IMAGE"], role_defaults()["safety_service_image"]
        )
        self.assertEqual(dict(pairs)["SAFETY_SERVICE_USER"], "921:922")


class PinsTests(unittest.TestCase):
    """The names the role pins equal the names the roles beside it own."""

    def test_the_secrets_directory_and_key_are_the_key_roles(self) -> None:
        key_vars = cast(
            "dict[str, object]", load(ROLES / "safety_channel_key" / "vars" / "main.yml")
        )
        directory = str(key_vars["safety_channel_key_directory"])
        self.assertEqual(role_vars()["safety_service_secrets_dir"], directory)
        self.assertEqual(
            role_vars()["safety_service_signing_key_file"],
            f"{directory}/{key_vars['safety_channel_key_key_name']}",
        )
        # The credential is a file the owner places in that same directory.
        self.assertEqual(
            str(role_vars()["safety_service_credential_file"]).rsplit("/", 1)[0], directory
        )

    def test_the_role_writes_nothing_in_the_secrets_directory(self) -> None:
        secrets = str(role_vars()["safety_service_secrets_dir"])
        for task in tasks():
            if module_of(task) in WRITING_MODULES:
                dest = str(args_of(task).get("dest", args_of(task).get("path", "")))
                self.assertFalse(render(dest).startswith(secrets), task.get("name"))


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

    def test_the_default_image_is_a_digest_pin_of_the_services_image(self) -> None:
        self.assertRegex(
            str(role_defaults()["safety_service_image"]),
            str(role_vars()["safety_service_image_pattern"]),
        )

    def test_the_image_must_be_the_services_image_pinned_by_digest(self) -> None:
        pattern = self.pattern("safety_service_image_pattern")
        self.assertTrue(pattern.match(IMAGE))
        for bad in (
            "ghcr.io/branchleft/content-safety:latest",
            "ghcr.io/branchleft/content-safety:" + "a" * 64,
            "ghcr.io/branchleft/content-safety",
            "ghcr.io/branchleft/other@sha256:" + "a" * 64,
            "example.test/branchleft/content-safety@sha256:" + "a" * 64,
            "ghcr.io/branchleft/content-safety@sha256:" + "A" * 64,
            "ghcr.io/branchleft/content-safety@sha256:" + "a" * 63,
            IMAGE + "\n",
            IMAGE + " --privileged",
            "--privileged " + IMAGE,
        ):
            self.assertIsNone(pattern.match(bad), bad)

    def test_an_origin_is_https_with_no_path_credential_query_or_fragment(self) -> None:
        pattern = self.pattern("safety_service_origin_pattern")
        for good in ("https://a.example", "https://a.example:8443", "https://a-b.c.example"):
            self.assertTrue(pattern.match(good), good)
        for bad in (
            "http://a.example",
            "https://a.example/",
            "https://a.example/x",
            "https://u:p@a.example",
            "https://a.example?x=1",
            "https://a.example#f",
            "https://a.example\n",
            "https://a.example y",
            "https://-a.example",
            "file:///x",
        ):
            self.assertIsNone(pattern.match(bad), bad)

    def test_a_host_id_is_one_plain_word_of_at_most_sixty_four(self) -> None:
        pattern = self.pattern("safety_service_host_id_pattern")
        for good in ("a", "host-one", "h.o_s-t9", "x" * 64):
            self.assertTrue(pattern.match(good), good)
        for bad in ("", "x" * 65, "a b", "a/b", "a\n", "a$b", "a'b"):
            self.assertIsNone(pattern.match(bad), bad)

    def test_the_host_kinds_and_keys_are_the_services(self) -> None:
        self.assertEqual(role_vars()["safety_service_host_kinds"], ["demo", "tenant"])
        self.assertEqual(
            role_vars()["safety_service_host_keys"], sorted(SERVICE_HOST_KEYS - {"safety"})
        )


class TaskTests(unittest.TestCase):
    """The tasks refuse early, hold the service off without its inputs and touch only its paths."""

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

    def test_the_inputs_are_refused_before_anything_changes(self) -> None:
        first_change = next(i for i, t in enumerate(tasks()) if module_of(t) in CHANGING_MODULES)
        before = tasks()[:first_change]
        self.assertGreaterEqual(len([t for t in before if module_of(t) == "assert"]), 6)
        text = "\n".join(str(t) for t in before)
        for name in role_defaults():
            self.assertIn(name, text)

    def test_the_service_runs_only_when_the_origin_and_a_host_are_both_set(self) -> None:
        fact = args_of(named("Note whether the service is meant to run"))
        run_template = str(fact["safety_service_run"])
        for origin, hosts, expected in (
            ("", [], "False"),
            ("https://a.example", [], "False"),
            ("", [HOST], "False"),
            ("https://a.example", [HOST], "True"),
        ):
            with self.subTest(origin=origin, hosts=len(hosts)):
                variables = {
                    "safety_service_arachnid_base_url": origin,
                    "safety_service_hosts": hosts,
                }
                self.assertEqual(render(run_template, variables), expected)

    def test_the_service_is_held_off_unless_it_is_meant_to_run(self) -> None:
        hold = args_of(named("Hold the service"))
        for run, enabled, state in (("False", "False", "stopped"), ("True", "True", "started")):
            with self.subTest(run=run):
                variables = {"safety_service_run": run == "True"}
                self.assertEqual(render(str(hold["enabled"]), variables), enabled)
                self.assertEqual(render(str(hold["state"]), variables), state)
        self.assertEqual(hold["name"], "{{ safety_service_unit }}")

    def test_the_configuration_is_written_only_when_the_service_is_meant_to_run(self) -> None:
        write = named("Write the configuration")
        self.assertEqual(module_of(write), "template")
        self.assertEqual(write["when"], "safety_service_run | bool")
        remove = named("Remove the configuration")
        self.assertEqual(args_of(remove)["state"], "absent")
        self.assertEqual(remove["when"], "not safety_service_run | bool")

    def test_the_restart_handler_runs_only_for_a_service_that_is_meant_to_run(self) -> None:
        handlers = cast("list[dict[str, object]]", load(ROLE / "handlers" / "main.yml"))
        restart = next(h for h in handlers if str(h["name"]).startswith("Restart"))
        self.assertEqual(restart["when"], "safety_service_run | bool")

    def test_the_account_is_a_system_account_that_cannot_log_in(self) -> None:
        user = args_of(named("Create the service account"))
        self.assertIs(user["system"], True)
        self.assertIs(user["create_home"], False)
        self.assertEqual(user["shell"], "/usr/sbin/nologin")

    def test_the_state_directory_is_the_accounts_and_closed_to_everyone_else(self) -> None:
        state = args_of(named("Make the state directory"))
        self.assertEqual(state["mode"], "0700")
        self.assertEqual(state["owner"], "{{ safety_service_account }}")

    def test_the_parents_are_asserted_and_never_changed(self) -> None:
        parents = cast("list[str]", role_vars()["safety_service_parents"])
        self.assertEqual(parents, ["/etc/branchleft", "/var/lib/branchleft"])
        for task in tasks():
            if module_of(task) in WRITING_MODULES:
                self.assertNotIn("safety_service_parents", str(task))

    def test_the_unit_is_installed_as_a_static_file(self) -> None:
        install = named("Install the service unit")
        self.assertEqual(module_of(install), "copy")
        self.assertNotIn("content", args_of(install))


if __name__ == "__main__":
    unittest.main()
