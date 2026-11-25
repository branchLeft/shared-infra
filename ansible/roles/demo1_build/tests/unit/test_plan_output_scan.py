"""What the host scan's refusal prints must not match the plan's secret scan.

demo1's plan is withheld whole when any line of its check-mode output matches the scan's
credential-assignment pattern (github-workflows, ssh-check-hosts, host_output_scan.py v1.3.1).
The refusal's message was bounded and was not the match: Ansible prints an `Origin:` line under a
failed task that ends in the task file's path, line and column, and `_secret_holders.yml:256:3`
reads as a credential assignment. So a task file named with a word of the pattern withholds the
plan whenever any task in it fails.

The tests run the refusal for real (ansible-playbook, in check mode as the plan does, and as an
apply) over hostile paths and read every printed line through a copy of the pattern, and hold the
task file names of every role of the demo1 play to it. Drift of the copy from the original is not
checked here (ansible/checks/test_plan_diff_scan.py holds its own copy, checked against grep).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

ROLE = Path(__file__).resolve().parent.parent.parent
ROLES = ROLE.parent
DEMO1_PLAY = ROLES.parent / "playbooks" / "demo1.yml"
TASKS = ROLE / "tasks"
HANDLERS = ROLE / "handlers"
ORIGIN_DIR = "/opt/branchleft/checkout/ansible/roles/demo1_build/tasks"
FIRST_TASK = "Summarise the unlisted paths, bounded"
REFUSAL = "Refuse a host that holds a secret-bearing file the holder list does not name"

# The credential-assignment pattern and the shapes taken out of a line before it is read.
CREDENTIAL_ASSIGNMENT = re.compile(
    r"(passw(or)?d|passphrase|secret|token|api[_-]?key|private[_-]?key|credential)"
    r'[A-Za-z0-9_.-]*"?\s*[:=]\s*"?[^\s"]{4,}',
    re.IGNORECASE | re.ASCII,
)
SHAPES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(expression, re.ASCII), replacement)
    for expression, replacement in (
        (r"(^|[\s)])nopasswd:", r"\1"),
        (r"\$\{[a-z_][a-z0-9_]*(:?\?[^}]*)?\}", ""),
        (r"\$\(cat [^\s)]+\)", ""),
        (r'[a-z0-9_.-]*[_.-](file|filename|path|dir)"?\s*[:=](\s*"?[/~])', r"\2"),
        (r'[:=]\s*"?(true|false|null|none)"?\s*([\],}]|$)', r" \2"),
    )
)
LOWER = {code: code + 32 for code in range(ord("A"), ord("Z") + 1)}
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def matching_lines(text: str) -> list[str]:
    """Return each line of ``text`` that the scan reads as a credential assignment.

    The scan reads the text as Latin-1 bytes, drops control characters, splits on the newline alone,
    lower-cases ASCII letters and takes the shapes out before it reads a line.
    """
    found: list[str] = []
    for line in CONTROL.sub("", text).split("\n"):
        scrubbed = line.translate(LOWER)
        for shape, replacement in SHAPES:
            scrubbed = shape.sub(replacement, scrubbed)
        if CREDENTIAL_ASSIGNMENT.search(scrubbed):
            found.append(line)
    return found


def refusal_file() -> Path:
    """Return the task file that holds the refusal, found by the task's name.

    Raises:
        AssertionError: no task file of the role holds the refusal.
    """
    holders = [
        path
        for path in sorted(TASKS.glob("*.yml"))
        if f"- name: {REFUSAL}" in path.read_text("utf-8")
    ]
    if len(holders) != 1:
        message = f"{len(holders)} task files hold the refusal {REFUSAL!r}, not one"
        raise AssertionError(message)
    return holders[0]


@dataclass
class Outcome:
    """What one run of ansible-playbook did."""

    code: int
    output: str


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


def unlisted_bulk() -> list[str]:
    """Return a host's worth of unlisted paths: a Python environment whose names hold the words."""
    packages = ("secretstorage", "google/auth", "passlib", "keyring", "oauthlib", "tokenize", "jwt")
    names = (
        "credentials.py",
        "token.py",
        "secret_store.py",
        "passwd.txt",
        "api_key.json",
        "__init__.py",
    )
    root = "/opt/venv/lib/python3.12/site-packages"
    return [
        f"{root}/{package}/{name}" for package in packages for name in names for _ in range(8)
    ] + [
        f"{root}/{package}/{name}.{number}"
        for package in packages
        for name in names
        for number in range(6)
    ]


def unlisted_hostile() -> list[str]:
    """Return paths made to read as an assignment, in every way a name can hold the pieces."""
    return [
        "/srv/app/token=abc12345",
        "/srv/app/secret: value1234",
        '/srv/app/password = "hunter2222"',
        "/srv/app/api_key=0123456789abcdef",
        "/srv/app/private-key:\tvalue1234",
        '/srv/app/credential": "value1234',
        '/srv/app/passphrase"=value1234',
        "/srv/app/secret.env=${HOME}/value1234",
        "/srv/app/token$(cat x)=value1234",
        "/srv/app/{{ 7 * 7 }} token=value1234",
        "/srv/app/passwd",
        "/srv/app/secret ",
        "/srv/app/credentials\\",
        "/srv/app/café token =value1234",
        "/" + "a" * 300 + "/token=value1234",
        "/token=abc12345/secret: value1234/password=hunter2222/x/y",
        "/secret",
        "/token:abcd",
        "/etc/sudoers.d/nopasswd: ALL",
    ]


class RefusalOutput(unittest.TestCase):
    """The real refusal task, run for real, and every line of what it printed read by the scan."""

    def setUp(self) -> None:
        """Make a scratch play that runs the role's own task file from the summary on."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.play = self.root / "play.yml"
        self.play.write_text(
            "- hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  vars_files:\n"
            f"    - {ROLE / 'defaults' / 'main.yml'}\n"
            f"    - {ROLE / 'vars' / 'main.yml'}\n"
            "  tasks:\n"
            f"    - ansible.builtin.import_tasks: {refusal_file()}\n",
            encoding="utf-8",
        )
        self.config = self.root / "ansible.cfg"
        self.config.write_text("", encoding="utf-8")

    def refuse(self, unlisted: list[str], *, check: bool) -> Outcome:
        """Run the refusal against ``unlisted``: check mode with a diff (the plan), or an apply."""
        extra = self.root / "extra.json"
        extra.write_text(
            json.dumps(
                {
                    "demo1_build_secret_unlisted": unlisted,
                    "ansible_python_interpreter": sys.executable,
                }
            ),
            encoding="utf-8",
        )
        command = [str(ansible_playbook()), "-i", "localhost,", "-e", f"@{extra}"]
        command += ["--start-at-task", FIRST_TASK]
        if check:
            command += ["--check", "--diff"]
        command.append(str(self.play))
        environment = {
            **os.environ,
            "ANSIBLE_CONFIG": str(self.config),
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_HOME": str(self.root / "ansible-home"),
        }
        # The command is built here from fixed paths and the scratch tree.
        done = subprocess.run(  # noqa: S603
            command, capture_output=True, text=True, check=False, env=environment, timeout=180
        )
        return Outcome(done.returncode, done.stdout + done.stderr)

    def assert_refused_and_readable(self, unlisted: list[str], *, check: bool) -> None:
        """Hold one run to the three things the refusal is for."""
        outcome = self.refuse(unlisted, check=check)
        mode = "check" if check else "apply"
        # It refused, and the run's own text says which task and where: these lines are what the
        # scan reads, so a run that printed no origin would prove nothing.
        self.assertNotEqual(outcome.code, 0, f"{mode}: the refusal did not fail\n{outcome.output}")
        self.assertIn(f"{len(unlisted)} unlisted path(s)", outcome.output, mode)
        self.assertIn("Origin:", outcome.output, mode)
        self.assertIn(refusal_file().name, outcome.output, mode)
        # It still names the directories and the paths, with ':' and '=' turned into '?'.
        self.assertIn("By directory, the most first", outcome.output, mode)
        shown = unlisted[0].replace(":", "?").replace("=", "?")
        self.assertIn(
            shown.replace('"', '\\"') if check else shown, outcome.output.replace("\n", " "), mode
        )
        # And no line of it reads as a credential assignment to the plan's scan.
        self.assertEqual([], [line[:200] for line in matching_lines(outcome.output)], mode)

    def test_a_hosts_worth_of_paths_that_hold_the_words_is_readable_in_the_plan(self) -> None:
        self.assert_refused_and_readable(unlisted_bulk(), check=True)

    def test_a_hosts_worth_of_paths_that_hold_the_words_is_readable_in_the_apply(self) -> None:
        self.assert_refused_and_readable(unlisted_bulk(), check=False)

    def test_paths_made_to_read_as_an_assignment_are_readable_in_the_plan(self) -> None:
        self.assert_refused_and_readable(unlisted_hostile(), check=True)

    def test_paths_made_to_read_as_an_assignment_are_readable_in_the_apply(self) -> None:
        self.assert_refused_and_readable(unlisted_hostile(), check=False)


class TaskFileNames(unittest.TestCase):
    """The names of the role's task files, which Ansible prints in the Origin line of a failure."""

    def test_no_task_file_name_reads_as_a_credential_assignment_in_its_origin_line(self) -> None:
        names = sorted(path.name for folder in (TASKS, HANDLERS) for path in folder.glob("*.yml"))
        self.assertIn("main.yml", names)
        found = [name for name in names if matching_lines(f"Origin: {ORIGIN_DIR}/{name}:256:3")]
        self.assertEqual(
            [], found, "a failure in these files prints a line the plan scan withholds the plan for"
        )

    def test_no_task_file_of_any_role_the_demo1_play_runs_is_named_with_a_word_of_the_scan(
        self,
    ) -> None:
        roles = sorted(set(re.findall(r"role: \.\./roles/(\w+)", DEMO1_PLAY.read_text("utf-8"))))
        self.assertIn("demo1_egress_spool", roles)
        self.assertGreaterEqual(len(roles), 5)
        found = [
            f"{role}/{folder.name}/{path.name}"
            for role in roles
            for folder in (ROLES / role / "tasks", ROLES / role / "handlers")
            for path in sorted(folder.glob("*.yml"))
            if matching_lines(f"Origin: {ORIGIN_DIR}/{path.name}:256:3")
        ]
        self.assertEqual(
            [], found, "a failure in these files prints a line the plan scan withholds the plan for"
        )

    def test_control_the_line_that_withheld_demo1_s_plan_is_found(self) -> None:
        line = f"Origin: {ORIGIN_DIR}/_secret_holders.yml:256:3"
        self.assertEqual([line], matching_lines(line))

    def test_control_a_line_with_no_word_of_the_pattern_is_not_found(self) -> None:
        line = f"Origin: {ORIGIN_DIR}/_holder_scan.yml:256:3"
        self.assertEqual([], matching_lines(line))

    def test_control_a_path_in_a_message_with_its_colon_kept_is_found(self) -> None:
        self.assertTrue(matching_lines("The first 1 in order: /srv/app/token=abc12345"))
        self.assertTrue(matching_lines("/srv/app/token:abcd, /srv/other"))


if __name__ == "__main__":
    unittest.main()
