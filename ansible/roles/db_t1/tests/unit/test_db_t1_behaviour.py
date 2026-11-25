"""Behaviour of the db_t1 task files, run for real with ansible-playbook on localhost.

The contract tests read the files; these run them. A task file is included by a small play
in a scratch directory, with every path of the role moved into the scratch tree and the
host's deploy program replaced by a stand-in that records its arguments and writes the pin
the way the real one does. Nothing here touches a host or a container. They prove the
plan and apply behaviour the owner approves from, which a read of the YAML cannot: that a
plan shows a first deploy, that a second run changes nothing, and that each refusal stops
the run before any deploy.

A missing ansible-playbook is a failure, not a skip: the suite of a role is a control.
"""

from __future__ import annotations

import base64
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from netfilter_fake import FakeTable

ROLE = Path(__file__).resolve().parents[2]
DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
IMAGE = f"ghcr.io/branchleft/percona-server@sha256:{DIGEST}"
OTHER_IMAGE = f"ghcr.io/branchleft/percona-server@sha256:{OTHER_DIGEST}"
GOOD_LINE = "MYSQL_ROOT_PASSWORD=abcdefghijklmnopqrstuvwxyz012345ABCD\n"
# A throwaway, in the shape of a classic token. Never a real value.
LOGIN = "reader-account"
TOKEN = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
REGISTRY_REFUSAL = "registry read key"
REPORT = "Report in check mode that the image would be pinned and the stack started"
TASK_LINE = re.compile(r"^TASK \[(?P<name>.*?)\] \*+$")
RESULT_LINE = re.compile(r"^(?P<status>ok|changed|skipping|fatal|failed): \[localhost\]")


@dataclass
class Outcome:
    """What one run of ansible-playbook did."""

    code: int
    output: str
    statuses: dict[str, str]

    @property
    def changed(self) -> int:
        """Return the recap's changed count."""
        found = re.search(r"changed=(\d+)", self.output)
        return int(found.group(1)) if found else -1

    def status_of(self, fragment: str) -> str:
        """Return the status of the one task whose name contains the fragment.

        Raises:
            AssertionError: there is not exactly one such task.
        """
        names = [name for name in self.statuses if fragment in name]
        if len(names) != 1:
            message = f"expected one task named like {fragment!r}, found {names}"
            raise AssertionError(message)
        return self.statuses[names[0]]


def ansible_playbook() -> Path:
    """Return the ansible-playbook beside the interpreter that runs the tests.

    Raises:
        AssertionError: the interpreter's environment has no ansible-playbook.
    """
    found = Path(sys.executable).parent / "ansible-playbook"
    if not found.exists():
        message = f"{found} is missing: run these tests with the pinned tool environment"
        raise AssertionError(message)
    return found


def parse(output: str) -> dict[str, str]:
    """Return each task's last status from the default callback's text."""
    statuses: dict[str, str] = {}
    current = ""
    for line in output.splitlines():
        task = TASK_LINE.match(line)
        if task:
            current = task.group("name")
            continue
        result = RESULT_LINE.match(line)
        if result and current:
            statuses[current] = result.group("status")
    return statuses


class Lab(unittest.TestCase):
    """A scratch tree, a stand-in deploy program and a runner."""

    include = "_pin.yml"

    def setUp(self) -> None:
        """Make the scratch tree and the stand-in."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        (self.root / "etc").mkdir()
        (self.root / "data").mkdir()
        self.pin = self.root / "etc" / "dbt1.image.env"
        self.secrets = self.root / "etc" / "dbt1.env"
        self.log = self.root / "deploy.log"
        self.registry_parent = self.root / "etc" / "registry"
        self.registry_dir = self.registry_parent / "docker"
        self.key_file = self.registry_dir / "config.json"
        self.program = self.root / "branchleft-deploy"
        self.program.write_text(
            f"#!{sys.executable}\n"
            "import sys\n"
            f"open({str(self.log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
            f"open({str(self.pin)!r}, 'w').write('IMAGE=' + sys.argv[2] + '\\n')\n",
            encoding="utf-8",
        )
        self.program.chmod(self.program.stat().st_mode | stat.S_IXUSR)
        self.play = self.root / "play.yml"
        self.play.write_text(
            "- hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  vars_files:\n"
            f"    - {ROLE / 'defaults' / 'main.yml'}\n"
            f"    - {ROLE / 'vars' / 'main.yml'}\n"
            "  tasks:\n"
            f"    - ansible.builtin.include_tasks: {ROLE / 'tasks' / self.include}\n",
            encoding="utf-8",
        )

    def write_secrets(self, content: str = GOOD_LINE, mode: int = 0o600) -> None:
        """Place the owner's root file in the scratch tree."""
        self.secrets.write_text(content, encoding="utf-8")
        self.secrets.chmod(mode)

    def place_key(self, mode: int = 0o600) -> None:
        """Place a registry key file the way a hand placement or an earlier apply would."""
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.key_file.write_text('{"auths": {"ghcr.io": {"auth": "x"}}}\n', encoding="utf-8")
        self.key_file.chmod(mode)

    def run_role(
        self,
        image: str,
        *,
        check: bool = False,
        registry: dict[str, str] | None = None,
        place_key: bool = True,
    ) -> Outcome:
        """Run the included task file once with the given image.

        A key file is in the scratch tree unless the case says otherwise, so the cases about the
        deploy are not about the key. `registry` gives the two optional inputs.
        """
        if place_key and not self.key_file.exists():
            self.place_key()
        variables: dict[str, object] = {
            "db_t1_image": image,
            "db_t1_image_env_path": str(self.pin),
            "db_t1_secrets_path": str(self.secrets),
            "db_t1_data_directory": str(self.root / "data"),
            "db_t1_deploy_program": str(self.program),
            "db_t1_registry_parent_directory": str(self.registry_parent),
            "db_t1_registry_docker_directory": str(self.registry_dir),
            "db_t1_registry_config_path": str(self.key_file),
            "db_t1_systemd_running_path": str(self.root / "no-systemd"),
            "db_t1_root_user_id": os.getuid(),
            "db_t1_root_group_id": os.getgid(),
            "ansible_python_interpreter": sys.executable,
        }
        if self.secrets.exists():
            # Whatever group the scratch tree gives a new file is the group the check wants.
            variables["db_t1_root_group_id"] = self.secrets.stat().st_gid
        if not self.secrets.exists() and self.key_file.exists():
            variables["db_t1_root_group_id"] = self.key_file.stat().st_gid
        variables.update(registry or {})
        extra = self.root / "extra.json"
        extra.write_text(json.dumps(variables), encoding="utf-8")
        command = [str(ansible_playbook()), "-i", "localhost,", "-e", f"@{extra}"]
        if check:
            command.append("--check")
        command.append(str(self.play))
        environment = {
            **os.environ,
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_HOME": str(self.root / "ansible-home"),
        }
        # The command is built here from fixed paths and the scratch tree.
        done = subprocess.run(  # noqa: S603
            command, capture_output=True, text=True, check=False, env=environment, timeout=120
        )
        output = done.stdout + done.stderr
        return Outcome(done.returncode, output, parse(output))

    def deploys(self) -> list[str]:
        """Return the arguments of each call the stand-in received."""
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []


class PlanAndApply(Lab):
    """What the plan shows and what the apply does."""

    def test_a_plan_shows_the_first_deploy_and_runs_nothing(self) -> None:
        self.write_secrets()
        outcome = self.run_role(IMAGE, check=True)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(outcome.status_of(REPORT), "changed")
        self.assertGreaterEqual(outcome.changed, 1)
        self.assertEqual(self.deploys(), [])
        self.assertFalse(self.pin.exists())

    def test_a_plan_with_the_pin_in_place_shows_no_change(self) -> None:
        self.write_secrets()
        self.pin.write_text(f"IMAGE={IMAGE}\n", encoding="utf-8")
        outcome = self.run_role(IMAGE, check=True)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(outcome.changed, 0, outcome.output)
        self.assertEqual(outcome.status_of(REPORT), "skipping")

    def test_a_plan_with_no_image_shows_no_change(self) -> None:
        outcome = self.run_role("", check=True)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(outcome.changed, 0, outcome.output)

    def test_the_apply_deploys_once_and_the_next_run_changes_nothing(self) -> None:
        self.write_secrets()
        first = self.run_role(IMAGE)
        self.assertEqual(first.code, 0, first.output)
        self.assertEqual(self.deploys(), [f"dbt1 {IMAGE}"])
        self.assertEqual(self.pin.read_text(encoding="utf-8"), f"IMAGE={IMAGE}\n")
        second = self.run_role(IMAGE)
        self.assertEqual(second.code, 0, second.output)
        self.assertEqual(second.changed, 0, second.output)
        self.assertEqual(self.deploys(), [f"dbt1 {IMAGE}"])

    def test_the_root_value_is_in_no_output_and_the_file_is_untouched(self) -> None:
        self.write_secrets()
        before = (self.secrets.read_bytes(), self.secrets.stat().st_mtime_ns)
        outcome = self.run_role(IMAGE)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertNotIn(GOOD_LINE.strip().split("=", 1)[1], outcome.output)
        self.assertEqual((self.secrets.read_bytes(), self.secrets.stat().st_mtime_ns), before)


class RegistryKeyDeploy(Lab):
    """The deploy needs the registry read key, from the host's inputs or placed by hand."""

    def refused(self, outcome: Outcome) -> None:
        """Assert the run failed on the key and the stand-in was never called."""
        self.assertNotEqual(outcome.code, 0, outcome.output)
        self.assertIn(REGISTRY_REFUSAL, outcome.output)
        self.assertEqual(self.deploys(), [])

    def test_a_deploy_with_no_key_on_the_host_is_refused(self) -> None:
        self.write_secrets()
        self.refused(self.run_role(IMAGE, place_key=False))

    def test_a_key_open_to_others_is_refused(self) -> None:
        self.write_secrets()
        self.place_key(mode=0o644)
        self.refused(self.run_role(IMAGE))

    def test_a_key_that_is_a_link_is_refused(self) -> None:
        self.write_secrets()
        self.registry_dir.mkdir(parents=True)
        target = self.root / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        target.chmod(0o600)
        self.key_file.symlink_to(target)
        self.refused(self.run_role(IMAGE, place_key=False))

    def test_a_key_in_place_lets_the_deploy_go_through(self) -> None:
        self.write_secrets()
        outcome = self.run_role(IMAGE)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(self.deploys(), [f"dbt1 {IMAGE}"])

    def test_a_plan_with_the_inputs_given_and_no_file_yet_goes_through(self) -> None:
        # The write is skipped in check mode (the directory is not made), so the plan reads the
        # file as absent. The inputs given are the key to come, and the plan still names the deploy.
        self.write_secrets()
        given = {"db_t1_registry_token_given": "true"}
        outcome = self.run_role(IMAGE, check=True, registry=given, place_key=False)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(outcome.status_of(REPORT), "changed")

    def test_a_plan_with_no_inputs_and_no_file_is_refused(self) -> None:
        self.write_secrets()
        outcome = self.run_role(IMAGE, check=True, place_key=False)
        self.assertNotEqual(outcome.code, 0, outcome.output)
        self.assertIn(REGISTRY_REFUSAL, outcome.output)

    def test_no_deploy_due_needs_no_key(self) -> None:
        outcome = self.run_role("", place_key=False)
        self.assertEqual(outcome.code, 0, outcome.output)


class RegistryKeyWrite(Lab):
    """The key file the role writes from the two optional inputs."""

    include = "_registry_key.yml"
    GIVEN = {"db_t1_registry_login": LOGIN, "db_t1_registry_token": TOKEN}

    def run_keys(self, registry: dict[str, str] | None, *, check: bool = False) -> Outcome:
        """Run the key tasks alone, with no key placed first."""
        return self.run_role("", check=check, registry=registry, place_key=False)

    def assert_no_secret_in(self, outcome: Outcome) -> None:
        """Assert the token, and its two encodings, are in no output."""
        auth = base64.b64encode(f"{LOGIN}:{TOKEN}".encode()).decode()
        for needle in (TOKEN, auth, TOKEN[4:]):
            self.assertNotIn(needle, outcome.output)

    def test_both_inputs_write_one_entry_for_the_one_registry_root_closed(self) -> None:
        outcome = self.run_keys(self.GIVEN)
        self.assertEqual(outcome.code, 0, outcome.output)
        document = json.loads(self.key_file.read_text(encoding="utf-8"))
        auth = base64.b64encode(f"{LOGIN}:{TOKEN}".encode()).decode()
        self.assertEqual(document, {"auths": {"ghcr.io": {"auth": auth}}})
        self.assertEqual(stat.S_IMODE(self.key_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.registry_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.registry_parent.stat().st_mode), 0o755)
        self.assert_no_secret_in(outcome)

    def test_a_second_run_changes_nothing_and_a_new_token_rewrites_the_file(self) -> None:
        self.assertEqual(self.run_keys(self.GIVEN).code, 0)
        again = self.run_keys(self.GIVEN)
        self.assertEqual(again.code, 0, again.output)
        self.assertEqual(again.status_of("Write the registry key"), "ok")
        rotated = {**self.GIVEN, "db_t1_registry_token": TOKEN[:-1] + "A"}
        third = self.run_keys(rotated)
        self.assertEqual(third.status_of("Write the registry key"), "changed")
        self.assert_no_secret_in(third)

    def test_a_plan_writes_nothing_and_shows_no_value(self) -> None:
        outcome = self.run_keys(self.GIVEN, check=True)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertGreaterEqual(outcome.changed, 1)
        self.assertFalse(self.key_file.exists())
        self.assert_no_secret_in(outcome)

    def test_neither_input_writes_nothing_and_leaves_a_placed_file_alone(self) -> None:
        self.place_key()
        before = (self.key_file.read_bytes(), self.key_file.stat().st_mtime_ns)
        for registry in (None, {"db_t1_registry_login": "", "db_t1_registry_token": ""}):
            with self.subTest(registry):
                outcome = self.run_keys(registry)
                self.assertEqual(outcome.code, 0, outcome.output)
                self.assertEqual(outcome.changed, 0, outcome.output)
                after = (self.key_file.read_bytes(), self.key_file.stat().st_mtime_ns)
                self.assertEqual(after, before)

    def test_neither_input_makes_no_directory(self) -> None:
        self.assertEqual(self.run_keys(None).code, 0)
        self.assertFalse(self.registry_parent.exists())

    def test_one_input_without_the_other_is_refused_and_writes_nothing(self) -> None:
        for name, registry in (
            ("login only", {"db_t1_registry_login": LOGIN}),
            ("token only", {"db_t1_registry_token": TOKEN}),
        ):
            with self.subTest(name):
                outcome = self.run_keys(registry)
                self.assertNotEqual(outcome.code, 0, outcome.output)
                self.assertIn("rule: registry key pair", outcome.output)
                self.assertFalse(self.registry_parent.exists())
                self.assert_no_secret_in(outcome)

    def test_a_login_or_a_token_of_the_wrong_shape_is_refused_and_writes_nothing(self) -> None:
        bad = {
            "a colon in the login": {**self.GIVEN, "db_t1_registry_login": "reader:account"},
            "a double hyphen in the login": {**self.GIVEN, "db_t1_registry_login": "read--er"},
            "a hyphen at the end of the login": {**self.GIVEN, "db_t1_registry_login": "reader-"},
            "a login of forty characters": {**self.GIVEN, "db_t1_registry_login": "a" * 40},
            "a fine-grained token": {
                **self.GIVEN,
                "db_t1_registry_token": "github_pat_" + "A1" * 30,
            },
            "a short token": {**self.GIVEN, "db_t1_registry_token": "ghp_short"},
            "a token with a line break": {**self.GIVEN, "db_t1_registry_token": TOKEN + "\nx"},
            "a token with a template": {
                **self.GIVEN,
                "db_t1_registry_token": "ghp_{{ 7 * 7 }}" + "A" * 30,
            },
        }
        for name, registry in bad.items():
            with self.subTest(name):
                outcome = self.run_keys(registry)
                self.assertNotEqual(outcome.code, 0, outcome.output)
                self.assertIn("rule: registry key shape", outcome.output)
                self.assertFalse(self.registry_parent.exists())
                self.assertNotIn(TOKEN, outcome.output)


class Refusals(Lab):
    """Each refusal stops the run with its message and calls no deploy."""

    def refused(self, outcome: Outcome, fragment: str) -> None:
        """Assert the run failed with the fragment and the stand-in was never called."""
        self.assertNotEqual(outcome.code, 0, outcome.output)
        self.assertIn(fragment, outcome.output)
        self.assertEqual(self.deploys(), [])

    def test_a_pin_that_differs_is_refused(self) -> None:
        self.write_secrets()
        self.pin.write_text(f"IMAGE={OTHER_IMAGE}\n", encoding="utf-8")
        self.refused(self.run_role(IMAGE), "pins a different image")

    def test_initialised_data_with_no_pin_is_refused(self) -> None:
        self.write_secrets()
        (self.root / "data" / "mysql").mkdir()
        self.refused(self.run_role(IMAGE), "holds an initialised database")

    def test_a_root_file_that_is_absent_is_refused(self) -> None:
        self.refused(self.run_role(IMAGE), "must be a plain file owned by root")

    def test_a_root_file_open_to_others_is_refused(self) -> None:
        self.write_secrets(mode=0o644)
        self.refused(self.run_role(IMAGE), "must be a plain file owned by root")

    def test_root_files_that_are_not_the_one_expected_line_are_refused(self) -> None:
        bad = {
            "short": "MYSQL_ROOT_PASSWORD=short\n",
            "quote": "MYSQL_ROOT_PASSWORD=abcdefghijklmnopqrstuvwxyz012345'ABCD\n",
            "image line": GOOD_LINE + f"IMAGE={OTHER_IMAGE}\n",
            "indented image line": GOOD_LINE + f" IMAGE={OTHER_IMAGE}\n",
        }
        for name, content in bad.items():
            with self.subTest(name):
                self.write_secrets(content)
                self.refused(self.run_role(IMAGE), "must hold one line")


class ImageInput(Lab):
    """The image input: empty, or a digest in the organisation's registry."""

    include = "_inputs.yml"

    def test_an_empty_image_and_a_digest_pinned_image_are_accepted(self) -> None:
        for image in ("", IMAGE, "ghcr.io/branchleft/a/b-c.d@sha256:" + DIGEST):
            with self.subTest(image):
                outcome = self.run_role(image)
                self.assertEqual(outcome.code, 0, outcome.output)

    def test_every_other_image_is_refused(self) -> None:
        refused = {
            "tag only": "ghcr.io/branchleft/percona-server:8.0",
            "another registry": f"docker.io/percona/percona-server@sha256:{DIGEST}",
            "another owner": f"ghcr.io/other/percona-server@sha256:{DIGEST}",
            "upper-case registry owner": f"ghcr.io/BranchLeft/percona-server@sha256:{DIGEST}",
            "upper-case digest": f"ghcr.io/branchleft/percona-server@sha256:{'A' * 64}",
            "short digest": f"ghcr.io/branchleft/percona-server@sha256:{DIGEST[:63]}",
            "long digest": f"ghcr.io/branchleft/percona-server@sha256:{DIGEST}a",
            "tag and digest": f"ghcr.io/branchleft/percona-server:8.0@sha256:{DIGEST}",
            "trailing text": IMAGE + " --privileged",
            "no name": f"ghcr.io/branchleft/@sha256:{DIGEST}",
        }
        for name, image in refused.items():
            with self.subTest(name):
                outcome = self.run_role(image)
                self.assertNotEqual(outcome.code, 0, outcome.output)
                self.assertIn("must be empty", outcome.output)


CHAIN = "BRANCHLEFT-DBT1-IN"
JUMP = f"-A INPUT -j {CHAIN}"
ACCEPT = f"-A {CHAIN} -s 10.20.1.201/32 -p tcp -m tcp --dport 3306 -j ACCEPT"
DROP = f"-A {CHAIN} -p tcp -m tcp --dport 3306 -j DROP"
REPORT_RULE = "Report in check mode that the database port rule would be installed or reloaded"
PROBE = "Ask the rule program whether the loaded rule is the wanted one"


class ListenerRule(unittest.TestCase):
    """The rule's task file, run for real against a fake iptables, with no systemd.

    systemd is absent here, so the tasks that load the rule through the unit, enable it and
    read systemd back are skipped (Molecule runs them). What is proven is the rest: what a plan
    says before and after the rule is loaded, that the apply installs the files, that a rule
    that admits another source is seen, and that a second run changes nothing.
    """

    def setUp(self) -> None:
        """Make the scratch tree, a copy of the program for this interpreter, and the fakes."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        for name in ("sbin", "units", "src"):
            (self.root / name).mkdir()
        self.fakes = FakeTable(self)
        source = (ROLE / "files" / "branchleft_dbt1_listener_rule.py").read_text(encoding="utf-8")
        self.program_source = self.root / "src" / "branchleft_dbt1_listener_rule.py"
        self.program_source.write_text(
            source.replace("#!/usr/bin/python3 -I", f"#!{sys.executable} -I", 1), encoding="utf-8"
        )
        self.program = self.root / "sbin" / "branchleft-dbt1-listener-rule"
        self.unit = self.root / "units" / "rule.service"
        self.dropin_dir = self.root / "units" / "docker.service.d"
        self.dropin = self.dropin_dir / "20-rule.conf"
        self.play = self.root / "play.yml"
        self.play.write_text(
            "- hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  tasks:\n"
            "    - ansible.builtin.include_role:\n"
            f"        name: {ROLE}\n"
            "        tasks_from: _listener_rule.yml\n",
            encoding="utf-8",
        )

    def run_rule(self, *, check: bool = False, path: str | None = None) -> Outcome:
        """Run the rule's task file once; path replaces the fakes' PATH when given."""
        variables: dict[str, object] = {
            "db_t1_rule_program_src": str(self.program_source),
            "db_t1_rule_program_dest": str(self.program),
            "db_t1_rule_unit_dest": str(self.unit),
            "db_t1_rule_docker_dropin_dir": str(self.dropin_dir),
            "db_t1_rule_docker_dropin_dest": str(self.dropin),
            "db_t1_systemd_running_path": str(self.root / "no-systemd"),
            "db_t1_root_user_id": os.getuid(),
            "db_t1_root_group_id": os.getgid(),
            "ansible_python_interpreter": sys.executable,
        }
        extra = self.root / "extra.json"
        extra.write_text(json.dumps(variables), encoding="utf-8")
        command = [str(ansible_playbook()), "-i", "localhost,", "-e", f"@{extra}"]
        if check:
            command.append("--check")
        command.append(str(self.play))
        environment = {
            **os.environ,
            **self.fakes.environment(),
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_HOME": str(self.root / "ansible-home"),
        }
        if path is not None:
            environment["PATH"] = path
        # The command is built here from fixed paths and the scratch tree.
        done = subprocess.run(  # noqa: S603
            command, capture_output=True, text=True, check=False, env=environment, timeout=120
        )
        output = done.stdout + done.stderr
        return Outcome(done.returncode, output, parse(output))

    def load_rule(self) -> None:
        """Load the rule the way the unit does at boot: run the installed program."""
        done = subprocess.run(  # noqa: S603
            [str(self.program), "--allow-source", "10.20.1.201", "--port", "3306"],
            capture_output=True,
            text=True,
            check=False,
            env=self.fakes.environment(),
            timeout=60,
        )
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_plan_on_a_fresh_host_reports_a_change_and_writes_nothing(self) -> None:
        outcome = self.run_rule(check=True)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(outcome.status_of(REPORT_RULE), "changed")
        self.assertFalse(self.program.exists())
        self.assertFalse(self.unit.exists())
        self.assertEqual(self.fakes.calls(), [])

    def test_the_apply_installs_the_program_the_unit_and_the_drop_in(self) -> None:
        outcome = self.run_rule()
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(stat.S_IMODE(self.program.stat().st_mode), 0o755)
        self.assertEqual(self.program.read_bytes(), self.program_source.read_bytes())
        self.assertIn(
            f"\nExecStart={self.program} --allow-source 10.20.1.201 --port 3306\n",
            self.unit.read_text(),
        )
        self.assertIn("Requires=branchleft-dbt1-listener-rule.service", self.dropin.read_text())
        self.assertEqual(stat.S_IMODE(self.unit.stat().st_mode), 0o644)

    def test_the_apply_sees_that_the_rule_is_not_loaded_and_says_what_is_missing(self) -> None:
        outcome = self.run_rule()
        self.assertEqual(outcome.status_of(PROBE), "changed")
        self.assertIn(f"+ {JUMP}", outcome.output)
        self.assertIn("+ chain " + CHAIN, outcome.output)

    def test_a_plan_after_the_rule_is_loaded_and_the_files_are_in_place_shows_no_change(
        self,
    ) -> None:
        self.assertEqual(self.run_rule().code, 0)
        self.load_rule()
        outcome = self.run_rule(check=True)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(outcome.changed, 0, outcome.output)
        self.assertEqual(outcome.status_of(PROBE), "ok")

    def test_the_second_apply_changes_nothing(self) -> None:
        self.assertEqual(self.run_rule().code, 0)
        self.load_rule()
        before = self.fakes.writes()
        outcome = self.run_rule()
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(outcome.changed, 0, outcome.output)
        self.assertEqual(self.fakes.writes(), before)

    def test_a_loaded_rule_that_admits_another_source_shows_in_the_plan_as_a_change(self) -> None:
        self.assertEqual(self.run_rule().code, 0)
        self.load_rule()
        stray = f"-A {CHAIN} -s 10.20.1.99/32 -p tcp -m tcp --dport 3306 -j ACCEPT"
        self.fakes.put(input_rules=[JUMP], chain=[stray, DROP])
        outcome = self.run_rule(check=True)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(outcome.status_of(PROBE), "changed")
        self.assertIn("- -A BRANCHLEFT-DBT1-IN -s 10.20.1.99/32", outcome.output)
        self.assertIn("+ -A BRANCHLEFT-DBT1-IN -s 10.20.1.201/32", outcome.output)
        self.assertEqual(self.fakes.table()["chain"], [stray, DROP])

    def test_a_jump_under_another_rule_fails_the_plan(self) -> None:
        self.assertEqual(self.run_rule().code, 0)
        ssh = "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"
        self.fakes.put(input_rules=[ssh, JUMP], chain=[ACCEPT, DROP])
        outcome = self.run_rule(check=True)
        self.assertNotEqual(outcome.code, 0, outcome.output)
        self.assertIn("is rule 2 of INPUT", outcome.output)

    def test_a_host_with_no_iptables_fails_the_plan_naming_the_role_that_installs_it(self) -> None:
        self.assertEqual(self.run_rule().code, 0)
        outcome = self.run_rule(check=True, path="/usr/bin:/bin")
        self.assertNotEqual(outcome.code, 0, outcome.output)
        self.assertIn("iptables is not installed", outcome.output)


if __name__ == "__main__":
    unittest.main()
