"""Unit tests that hold the role's files and tasks to what the provisioning controller host must be.

The tests read the real files, never a copy. Each control that a test names was run red on a
sabotaged copy and green on the file as shipped (the pull request records both). The checks that
look for a forbidden thing are first shown able to find it, on text made to hold it.
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import cast

import jinja2
import provisioning_controller_host_ssh_key as module
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
SERVICE = ROLE / "files" / "provisioning-controller.service"
PATH_UNIT = ROLE / "files" / "provisioning-controller.path"
TIMER = ROLE / "files" / "provisioning-controller.timer"
REGISTER = ROLE / "files" / "register.json"
CONFIG_TEMPLATE = ROLE / "templates" / "config.json.j2"
SSH_CONFIG_TEMPLATE = ROLE / "templates" / "ssh_config.j2"
KNOWN_HOSTS_TEMPLATE = ROLE / "templates" / "known_hosts.j2"
PREFIX = "provisioning_controller_host_"

# The keys the controller's run configuration accepts, copied from `runConfig.ts` and
# `sshEntryConfig.ts` in branchLeft/ghost-platform (services/provisioning-controller). The
# controller refuses a key it does not know, so a key outside these would stop every run.
TOP_KEYS = {
    "stateFile",
    "approvalsFile",
    "registerFile",
    "hosts",
    "sshEntry",
    "dbEntry",
    "retry",
    "reportTimeoutMs",
}
SSH_KEYS = {
    "keyFile", "knownHostsFile", "jumpHops", "target", "inputs", "sshConfigFile", "sshProgram",
    "timeoutMs", "connectTimeoutSeconds", "maxOutputBytes", "maxPayloadBytes",
}  # fmt: skip
SSH_INPUT_KEYS = {"secretsFile", "stackFile"}
# parseDbEntry in sshEntryConfig.ts: exactly a target endpoint and an absolute hand-over directory.
DB_KEYS = {"target", "handOverDir"}
ENDPOINT_KEYS = {"user", "host", "port"}
HOST_KEYS = {"argv", "timeoutMs"}

FORBIDDEN_MODULES = {"shell", "command", "script", "raw", "slurp", "pipe", "fetch", "lineinfile"}
WRITING_MODULES = {"copy", "template", "file", "get_url", "unarchive"}
# Where the role may put a file: its own directories, its own units, nothing else.
ALLOWED_PREFIXES = (
    "/etc/branchleft/provisioning-controller",
    "/var/lib/branchleft/provisioning-controller",
    "/opt/branchleft/provisioning-controller",
    "/etc/systemd/system/provisioning-controller.",
)
# The words a model key or an agent program would bring. The unit and the programs hold none.
AGENT_WORDS = ("ANTHROPIC", "OPENAI", "claude", "codex", "API_KEY")
KEY_HOLDERS = {"provisioning_controller_host_ssh_key"}


def load_yaml(path: Path) -> object:
    """Read one YAML file."""
    return YAML(typ="safe").load(path.read_text(encoding="utf-8"))


def _resolve(env: jinja2.Environment, value: object, scope: dict[str, object]) -> object:
    """Render every string in a value, lists included, against the scope."""
    if isinstance(value, str):
        return env.from_string(value).render(**scope)
    if isinstance(value, list):
        return [_resolve(env, item, scope) for item in value]
    return value


def role_vars() -> dict[str, object]:
    """Return the role's fixed variables with every reference to another resolved."""
    raw = cast(dict[str, object], load_yaml(ROLE / "vars" / "main.yml"))
    defaults = cast(dict[str, object], load_yaml(ROLE / "defaults" / "main.yml"))
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)  # noqa: S701 - the output is text, never HTML
    merged: dict[str, object] = {**defaults, **raw}
    for _ in range(5):
        merged = {k: _resolve(env, v, merged) for k, v in merged.items()}
    return merged


def filtering_environment() -> jinja2.Environment:
    """Return a Jinja environment with the two list filters the role's loops use."""
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)  # noqa: S701 - the output is text, never HTML
    env.filters["intersect"] = lambda a, b: [x for x in a if x in b]
    env.filters["difference"] = lambda a, b: [x for x in a if x not in b]
    return env


def render(template: Path, values: dict[str, object]) -> str:
    """Render a role template with the filters the role uses."""
    env = jinja2.Environment(  # noqa: S701 - the output is text, never HTML
        undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    env.filters["to_json"] = json.dumps
    return env.from_string(template.read_text(encoding="utf-8")).render(**values)


def tasks() -> list[dict[str, object]]:
    """Return the role's tasks, flattened through blocks."""
    out: list[dict[str, object]] = []

    def walk(items: object) -> None:
        for item in cast(list[dict[str, object]], items):
            if "block" in item:
                walk(item["block"])
            else:
                out.append(item)

    walk(load_yaml(ROLE / "tasks" / "main.yml"))
    return out


def module_of(task: dict[str, object]) -> str:
    """Return the short name of the module a task calls."""
    reserved = {"name", "when", "register", "notify", "loop", "loop_control", "no_log", "diff",
                "failed_when", "changed_when", "vars", "check_mode", "tags"}  # fmt: skip
    (name,) = [k for k in task if k not in reserved]
    return name.rsplit(".", 1)[-1]


def forbidden_in(text: str) -> list[str]:
    """Return the forbidden modules a tasks file calls, found by parsing it."""
    parsed = cast(list[dict[str, object]], YAML(typ="safe").load(text))
    found = []
    for task in parsed:
        try:
            name = module_of(task)
        except ValueError:
            continue
        if name in FORBIDDEN_MODULES:
            found.append(name)
    return found


class UnitTests(unittest.TestCase):
    """What the three unit files say."""

    def test_the_service_hands_the_key_to_the_account_under_the_name_the_config_expects(
        self,
    ) -> None:
        values = role_vars()
        text = SERVICE.read_text(encoding="utf-8")
        key_path = f"{values['provisioning_controller_host_ssh_key_directory']}/{module.KEY_NAME}"
        self.assertIn(
            f"LoadCredential={values['provisioning_controller_host_ssh_key_id']}:{key_path}\n", text
        )
        self.assertEqual(
            values["provisioning_controller_host_ssh_key_runtime_path"],
            f"/run/credentials/{values['provisioning_controller_host_service_unit']}/"
            f"{values['provisioning_controller_host_ssh_key_id']}",
        )

    def test_the_service_runs_as_the_account_and_runs_the_pass_with_the_roles_paths(self) -> None:
        values = role_vars()
        text = SERVICE.read_text(encoding="utf-8")
        self.assertIn(f"User={values['provisioning_controller_host_account']}\n", text)
        self.assertIn(f"Group={values['provisioning_controller_host_account']}\n", text)
        expected = (
            f"ExecStart={values['provisioning_controller_host_pass_program']}"
            f" --program {values['provisioning_controller_host_program']}"
            f" --config {values['provisioning_controller_host_config_file']}"
            f" --approvals {values['provisioning_controller_host_approvals_file']}"
            f" --state {values['provisioning_controller_host_run_state_file']}\n"
        )
        self.assertIn(expected, text)
        self.assertIn(
            f"ConditionPathExists={values['provisioning_controller_host_program']}\n", text
        )
        self.assertIn(f"ReadWritePaths={values['provisioning_controller_host_state_dir']}\n", text)

    def test_the_service_is_a_plain_one_shot_with_the_sandbox_and_no_agent(self) -> None:
        text = SERVICE.read_text(encoding="utf-8")
        for needle in ("Type=oneshot", "NoNewPrivileges=yes", "ProtectSystem=strict",
                       "PrivateTmp=yes", "UMask=0077", "RestrictSUIDSGID=yes"):  # fmt: skip
            self.assertIn(needle, text)
        self.assertNotRegex(text, r"(?m)^\s*(Environment|EnvironmentFile)=(?!PATH=)")
        for word in AGENT_WORDS:
            self.assertNotIn(word, text)
        self.assertNotIn("%i", text)

    def test_the_unit_path_is_the_one_the_vars_name(self) -> None:
        values = role_vars()
        text = SERVICE.read_text(encoding="utf-8")
        self.assertIn(
            f"Environment=PATH={values['provisioning_controller_host_unit_path']}\n", text
        )

    def test_the_path_unit_watches_the_ledger_and_starts_the_service(self) -> None:
        values = role_vars()
        text = PATH_UNIT.read_text(encoding="utf-8")
        self.assertIn(
            f"PathChanged={values['provisioning_controller_host_approvals_file']}\n", text
        )
        self.assertIn(f"Unit={values['provisioning_controller_host_service_unit']}\n", text)
        self.assertIn("WantedBy=multi-user.target", text)

    def test_the_timer_starts_the_same_service_and_is_enabled_by_the_role_alone(self) -> None:
        values = role_vars()
        text = TIMER.read_text(encoding="utf-8")
        self.assertIn(f"Unit={values['provisioning_controller_host_service_unit']}\n", text)
        self.assertIn("OnUnitInactiveSec=", text)

    def test_the_service_unit_is_hidden_from_the_plan_diff_and_the_others_are_not(self) -> None:
        """The service unit carries the load directive the plan's scan reads as a credential."""
        values = role_vars()
        pattern = re.compile(
            r"(passw(or)?d|passphrase|secret|token|api[_-]?key|private[_-]?key|credential)"
            r'[A-Za-z0-9_.-]*"?\s*[:=]\s*"?[^\s"]{4,}',
            re.IGNORECASE | re.ASCII,
        )
        hidden = set(cast(list[str], values["provisioning_controller_host_units_hidden"]))
        for name in cast(list[str], values["provisioning_controller_host_units"]):
            matches = any(
                pattern.search(line)
                for line in (ROLE / "files" / name).read_text(encoding="utf-8").splitlines()
            )
            with self.subTest(name):
                self.assertEqual(matches, name in hidden)


class TaskTests(unittest.TestCase):
    """What the tasks may and may not do."""

    def test_no_task_calls_a_module_that_could_read_copy_or_run_the_key(self) -> None:
        self.assertEqual(
            forbidden_in((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")), []
        )

    def test_the_check_is_able_to_find_what_it_looks_for(self) -> None:
        planted = (
            "- name: x\n  ansible.builtin.slurp:\n    src: /etc/x\n"
            "- name: y\n  ansible.builtin.command: id\n"
        )
        self.assertEqual(forbidden_in(planted), ["slurp", "command"])

    def test_only_the_key_module_names_the_key_and_it_is_hidden(self) -> None:
        holders = []
        for task in tasks():
            text = json.dumps(task)
            if "ssh_key_directory" in text or "ssh_key_name" in text or module.KEY_NAME in text:
                holders.append(task)
        self.assertEqual([module_of(t) for t in holders], ["provisioning_controller_host_ssh_key"])
        (task,) = holders
        self.assertIs(task.get("no_log"), True)
        self.assertIs(task.get("diff"), False)

    def test_no_task_registers_or_prints_more_than_the_public_half(self) -> None:
        prints = [t for t in tasks() if module_of(t) == "debug"]
        for task in prints:
            text = json.dumps(task)
            with self.subTest(task["name"]):
                self.assertNotIn("ssh_key_directory", text)
                self.assertNotIn(".stdout", text)
                self.assertNotIn("content", text.replace("route inputs", ""))

    def test_every_written_path_is_one_of_the_roles_own(self) -> None:
        values = role_vars()
        env = filtering_environment()
        checked = 0
        for task in tasks():
            name = module_of(task)
            if name not in WRITING_MODULES:
                continue
            args = cast(dict[str, object], task.get(name) or task[f"ansible.builtin.{name}"])
            raw = str(args.get("dest") or args.get("path"))
            loop = task.get("loop")
            if isinstance(loop, str):
                expression = loop.strip()[2:-2].strip()
                loop = env.compile_expression(expression)(**values)
            items: list[object] = list(cast(list[object], loop)) if loop is not None else [None]
            for item in items:
                if isinstance(item, str):
                    item = _resolve(env, item, values)
                scope = {**values, "item": item}
                if raw.startswith("{{ item }}"):
                    scope["item"] = env.from_string(str(item)).render(**values)
                path = env.from_string(raw).render(**scope)
                if path.startswith("{{") or "{{" in path:
                    continue
                checked += 1
                with self.subTest(path):
                    self.assertTrue(path.startswith(ALLOWED_PREFIXES), path)
        self.assertGreaterEqual(checked, 15)

    def test_the_role_names_no_path_of_another_role_or_the_owners_data(self) -> None:
        text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8") + (
            ROLE / "vars" / "main.yml"
        ).read_text(encoding="utf-8")
        for other in (
            "control-plane",
            "backup-worker",
            "host-inputs.json",
            "nextcloud",
            "ring-controller",
        ):
            self.assertNotIn(other, text)


class ModuleAgreementTests(unittest.TestCase):
    """The role's constants are the module's."""

    def test_the_key_name_modes_and_comment_agree(self) -> None:
        values = role_vars()
        self.assertEqual(values["provisioning_controller_host_ssh_key_name"], module.KEY_NAME)
        self.assertEqual(
            int(str(values["provisioning_controller_host_ssh_key_mode"]), 8), module.KEY_MODE
        )
        self.assertEqual(
            int(str(values["provisioning_controller_host_ssh_key_directory_mode"]), 8),
            module.DIR_MODE,
        )
        self.assertEqual(module.KEY_MODE, 0o400)
        self.assertEqual(module.DIR_MODE, 0o700)

    def test_the_key_is_not_under_the_directory_the_units_or_the_account_can_reach(self) -> None:
        values = role_vars()
        key_dir = str(values["provisioning_controller_host_ssh_key_directory"])
        self.assertTrue(
            key_dir.startswith(str(values["provisioning_controller_host_config_dir"]) + "/")
        )
        self.assertFalse(key_dir.startswith(str(values["provisioning_controller_host_state_dir"])))
        self.assertNotEqual(
            values["provisioning_controller_host_ssh_key_runtime_path"],
            f"{key_dir}/{module.KEY_NAME}",
        )

    def test_the_public_file_is_outside_the_key_directory(self) -> None:
        values = role_vars()
        public = str(values["provisioning_controller_host_ssh_public_file"])
        self.assertFalse(
            public.startswith(str(values["provisioning_controller_host_ssh_key_directory"]) + "/")
        )


class InterfaceTests(unittest.TestCase):
    """The argument spec and the defaults say the same thing, and refuse what the tasks refuse."""

    def spec(self) -> dict[str, dict[str, object]]:
        """Return the role's options."""
        document = cast(
            dict[str, dict[str, dict[str, dict[str, dict[str, object]]]]],
            load_yaml(ROLE / "meta" / "argument_specs.yml"),
        )
        return document["argument_specs"]["main"]["options"]

    def test_every_default_is_an_option_and_every_option_has_a_default(self) -> None:
        defaults = cast(dict[str, object], load_yaml(ROLE / "defaults" / "main.yml"))
        self.assertEqual(set(defaults), set(self.spec()))

    def test_the_defaults_pass_the_spec_and_are_all_empty(self) -> None:
        defaults = cast(dict[str, object], load_yaml(ROLE / "defaults" / "main.yml"))
        self.assertTrue(all(v == "" for v in defaults.values()))
        result = ArgumentSpecValidator(self.spec()).validate(defaults)
        self.assertFalse(result.error_messages)

    def test_the_two_account_names_are_held_out_of_logs(self) -> None:
        for name in ("edge1_jump_user", "edget_jump_user"):
            self.assertIs(self.spec()[PREFIX + name].get("no_log"), True)

    def test_the_patterns_accept_what_they_should_and_refuse_what_they_should_not(self) -> None:
        values = role_vars()
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "A" * 43
        accepted = {
            "host_key_pattern": [key],
            "user_pattern": ["jump", "j_1-x"],
            "sha256_pattern": ["a" * 64],
            "bundle_url_pattern": ["https://example.test/a/b.tar.gz"],
        }
        refused = {
            "host_key_pattern": [
                key + " root@h",
                key + "\n",
                "ssh-rsa AAAAB3NzaC1yc2E",
                key[:-1],
                "",
            ],
            "user_pattern": ["Jump", "1jump", "j u", "jump\n", "a" * 33, ""],
            "sha256_pattern": ["A" * 64, "a" * 63, "a" * 64 + "\n"],
            "bundle_url_pattern": [
                "http://example.test/a",
                "https://u:p@example.test/a",
                "https://e.test/a?x=1",
            ],
        }
        for name, good in accepted.items():
            pattern = re.compile(str(values[PREFIX + name]))
            for text in good:
                with self.subTest(name=name, text=text):
                    self.assertTrue(pattern.match(text))
        for name, bad in refused.items():
            pattern = re.compile(str(values[PREFIX + name]))
            for text in bad:
                with self.subTest(name=name, text=text):
                    self.assertFalse(pattern.match(text))


class ConfigTests(unittest.TestCase):
    """The controller's configuration, as the role renders it."""

    @staticmethod
    def rendered() -> dict[str, object]:
        """Render the configuration with made-up route inputs."""
        values = {
            **role_vars(),
            PREFIX + "edge1_jump_user": "jumpone",
            PREFIX + "edget_jump_user": "jumptwo",
        }
        return cast(dict[str, object], json.loads(render(CONFIG_TEMPLATE, values)))

    def test_it_is_json_with_only_keys_the_controller_accepts(self) -> None:
        config = self.rendered()
        self.assertTrue(set(config) <= TOP_KEYS)
        ssh = cast(dict[str, object], config["sshEntry"])
        self.assertTrue(set(ssh) <= SSH_KEYS)
        self.assertEqual(set(cast(dict[str, object], ssh["inputs"])), SSH_INPUT_KEYS)
        for spec in cast(dict[str, dict[str, object]], config["hosts"]).values():
            self.assertTrue(set(spec) <= HOST_KEYS)

    def test_it_names_the_roles_paths_and_the_estates_route(self) -> None:
        values = role_vars()
        config = self.rendered()
        self.assertEqual(config["stateFile"], values["provisioning_controller_host_run_state_file"])
        self.assertEqual(
            config["approvalsFile"], values["provisioning_controller_host_approvals_file"]
        )
        self.assertEqual(
            config["registerFile"], values["provisioning_controller_host_register_file"]
        )
        ssh = cast(dict[str, object], config["sshEntry"])
        self.assertEqual(
            ssh["keyFile"], values["provisioning_controller_host_ssh_key_runtime_path"]
        )
        self.assertEqual(
            ssh["knownHostsFile"], values["provisioning_controller_host_known_hosts_file"]
        )
        self.assertEqual(
            ssh["sshConfigFile"], values["provisioning_controller_host_ssh_config_file"]
        )
        self.assertEqual(
            ssh["jumpHops"],
            [{"user": "jumpone", "host": "10.20.1.10"}, {"user": "jumptwo", "host": "10.20.1.210"}],
        )
        self.assertEqual(ssh["target"], {"user": "tenant-entry", "host": "10.20.1.201"})

    def test_the_controller_programs_are_the_roles_two_files_and_every_path_is_absolute(
        self,
    ) -> None:
        values = role_vars()
        config = self.rendered()
        controller = cast(dict[str, dict[str, list[str]]], config["hosts"])["controller"]
        self.assertEqual(
            controller["argv"],
            [
                values["provisioning_controller_host_steps_program"],
                "--register", values["provisioning_controller_host_register_file"],
                "--escrow-dir", values["provisioning_controller_host_escrow_dir"],
            ],
        )  # fmt: skip
        self.assertEqual(
            (ROLE / "files" / str(values["provisioning_controller_host_steps_source"])).exists(),
            True,
        )

    def test_the_ssh_paths_have_only_the_characters_the_controller_allows(self) -> None:
        safe = re.compile(r"^/[A-Za-z0-9._@+/-]+$")
        ssh = cast(dict[str, object], self.rendered()["sshEntry"])
        for name in ("keyFile", "knownHostsFile", "sshConfigFile"):
            self.assertRegex(str(ssh[name]), safe)

    def test_the_slot_keys_the_controller_makes_are_under_the_state_directory_it_may_write(
        self,
    ) -> None:
        """The controller makes them in `slot-keys` beside its run state file."""
        values = role_vars()
        self.assertEqual(
            str(Path(str(values["provisioning_controller_host_run_state_file"])).parent),
            values["provisioning_controller_host_state_dir"],
        )
        self.assertIn(
            f"ReadWritePaths={values['provisioning_controller_host_state_dir']}",
            SERVICE.read_text(encoding="utf-8"),
        )

    def test_a_db_entry_is_rendered_and_meets_the_rules_parse_db_entry_applies(self) -> None:
        """parseRunConfig refuses the whole run when sshEntry has no dbEntry (sshEntryConfig.ts)."""
        values = role_vars()
        config = self.rendered()
        self.assertIn("dbEntry", config)
        db = cast(dict[str, object], config["dbEntry"])
        self.assertEqual(set(db), DB_KEYS)
        target = cast(dict[str, object], db["target"])
        self.assertTrue(set(target) <= ENDPOINT_KEYS)
        self.assertEqual(
            target,
            {
                "user": values[PREFIX + "db_entry_user"],
                "host": values[PREFIX + "db_t1_address"],
            },
        )
        self.assertEqual(db["handOverDir"], values[PREFIX + "handover_dir"])
        self.assertTrue(str(db["handOverDir"]).startswith("/"))

    def test_the_hand_over_directory_is_the_accounts_at_0750_as_the_controller_requires(
        self,
    ) -> None:
        """dbHandOver.ts refuses a directory with mode & 0o027 set, or another user's owner."""
        handover_task = [
            spec
            for task in tasks()
            if isinstance(spec := task.get("ansible.builtin.file"), dict)
            and spec.get("path") == "{{ " + PREFIX + "handover_dir }}"
        ]
        self.assertEqual(len(handover_task), 1)
        spec = handover_task[0]
        self.assertEqual(spec["owner"], "{{ " + PREFIX + "account }}")
        self.assertEqual(spec["group"], "{{ " + PREFIX + "account }}")
        self.assertEqual(spec["state"], "directory")
        self.assertEqual(int(str(spec["mode"]), 8) & 0o027, 0)
        self.assertEqual(
            str(Path(str(role_vars()[PREFIX + "handover_dir"])).parent),
            role_vars()[PREFIX + "state_dir"],
        )


class RegisterTests(unittest.TestCase):
    """The tenant register the role delivers."""

    def entry(self) -> dict[str, object]:
        """Return the one entry."""
        document = json.loads(REGISTER.read_text(encoding="utf-8"))
        (entry,) = document["entries"]
        return cast(dict[str, object], entry)

    def test_it_is_the_private_demo_tenant_with_nothing_public(self) -> None:
        entry = self.entry()
        self.assertEqual(entry["tenantId"], "demo-tenant")
        self.assertEqual(entry["appHostSlot"], "demo-tenant")
        self.assertEqual(entry["hostnames"], [])
        self.assertIs(entry["mail"], False)
        self.assertIs(entry["backups"], False)
        self.assertEqual(entry["mediaMode"], "s3")

    def test_it_pins_the_image_by_digest_and_holds_no_secret(self) -> None:
        entry = self.entry()
        self.assertRegex(str(entry["imageDigest"]), r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(str(entry["stateFolder"]), r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
        self.assertNotIn(str(entry["appHostSlot"]), str(entry["stateFolder"]))
        text = REGISTER.read_text(encoding="utf-8").lower()
        for word in ("password", "secret", "token", "key"):
            self.assertNotIn(word, text)


class SshClientFileTests(unittest.TestCase):
    """What the real ssh client applies to each hop, which the controller checks before it runs."""

    def values(self, directory: Path) -> dict[str, object]:
        """Return the vars with the known hosts file moved into a temporary place."""
        values = role_vars()
        values["provisioning_controller_host_known_hosts_file"] = str(directory / "known_hosts")
        return values

    def test_every_hop_is_pinned_batch_only_and_uses_the_key(self) -> None:
        """The controller's own start-up check, run against the rendered file with ssh -G."""
        ssh = shutil.which("ssh")
        self.assertIsNotNone(ssh, "the test needs an ssh client to show what the file does")
        with tempfile.TemporaryDirectory() as holder:
            directory = Path(holder)
            values = self.values(directory)
            config = directory / "ssh_config"
            config.write_text(render(SSH_CONFIG_TEMPLATE, values), encoding="utf-8")
            for address in ("10.20.1.10", "10.20.1.210"):
                shown = subprocess.run(  # noqa: S603 - the client named above, a file of this test
                    [str(ssh), "-G", "-F", str(config), "-l", "jumpone", address],
                    capture_output=True, text=True, check=True,
                ).stdout.splitlines()  # fmt: skip
                with self.subTest(address):
                    self.assertIn("stricthostkeychecking true", shown)
                    self.assertIn("batchmode yes", shown)
                    self.assertIn("identitiesonly yes", shown)
                    self.assertIn(f"userknownhostsfile {directory / 'known_hosts'}", shown)
                    self.assertIn("globalknownhostsfile /dev/null", shown)
                    self.assertIn(
                        "identityfile "
                        + str(values["provisioning_controller_host_ssh_key_runtime_path"]),
                        shown,
                    )

    def test_the_target_is_given_no_identity_by_the_file(self) -> None:
        """The slot key is the controller's own -i; the file offers the target no other."""
        ssh = shutil.which("ssh")
        self.assertIsNotNone(ssh)
        with tempfile.TemporaryDirectory() as holder:
            directory = Path(holder)
            config = directory / "ssh_config"
            config.write_text(render(SSH_CONFIG_TEMPLATE, self.values(directory)), encoding="utf-8")
            shown = subprocess.run(  # noqa: S603 - as above
                [str(ssh), "-G", "-F", str(config), "-l", "tenant-entry", "10.20.1.201"],
                capture_output=True, text=True, check=True,
            ).stdout  # fmt: skip
            self.assertNotIn("/run/credentials", shown)

    def test_the_known_hosts_file_pins_the_four_addresses(self) -> None:
        values = {
            **role_vars(),
            PREFIX + "edge1_host_key": "ssh-ed25519 AAAA1",
            PREFIX + "edget_host_key": "ssh-ed25519 AAAA2",
            PREFIX + "app_t1_host_key": "ssh-ed25519 AAAA3",
            PREFIX + "db_t1_host_key": "ssh-ed25519 AAAA4",
        }
        lines = [
            line
            for line in render(KNOWN_HOSTS_TEMPLATE, values).splitlines()
            if not line.startswith("#")
        ]
        self.assertEqual(
            lines,
            [
                "10.20.1.10 ssh-ed25519 AAAA1",
                "10.20.1.210 ssh-ed25519 AAAA2",
                "10.20.1.201 ssh-ed25519 AAAA3",
                "10.20.1.200 ssh-ed25519 AAAA4",
            ],
        )


if __name__ == "__main__":
    unittest.main()
