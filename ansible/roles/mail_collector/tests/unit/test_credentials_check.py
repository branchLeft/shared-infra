"""Tests that hold the credentials-file check to refusing anything but a regular, closed file.

The owner places the credentials file, and the role only looks at it: it must be a regular file,
root's, mode 0600. The check stands on two controls that a reading of the task cannot prove, so
these tests run the role's own two tasks (the look and the assert, taken from `tasks/main.yml` as
shipped) with Ansible on this machine, against a scratch file, and judge what they do:

- `follow: false` on the look, so a link to a good file is a link and is refused (when the look
  follows the link it sees the target, a regular 0600 file, and passes it);
- `isreg` in the assert, so a directory or a pipe that carries mode 0600 is refused (a link to a
  good file has mode 0777 when it is not followed, so only a non-regular file with mode 0600 shows
  that `isreg` is there).

They touch no host and read no content. Each control was run red on a sabotaged copy and green on
the file as shipped (the pull request records both)."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import cast

from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
TASK_STARTS = ("Look at the credentials file", "Require a placed credentials file")
RUN_SECONDS = 120
ROOT_OWNER = "stat.uid == 0"


def ansible_playbook() -> str:
    """Return the path of the ansible-playbook that belongs to the interpreter running the tests.

    Raises:
        AssertionError: when there is none, which is a failure and never a skip.
    """
    beside = Path(sys.executable).parent / "ansible-playbook"
    found = str(beside) if beside.is_file() else shutil.which("ansible-playbook")
    if found is None:
        message = "no ansible-playbook beside the interpreter or on the path"
        raise AssertionError(message)
    return found


def credentials_tasks() -> list[dict[str, object]]:
    """Return the role's two credentials tasks as shipped, with the owner test made the runner's.

    The one change is the root owner. A scratch file belongs to whoever runs the test, so the test
    asks for that user's id where the role asks for root's. The change is refused if the condition
    is not there to change, so a role that dropped the owner check cannot pass unseen.

    Raises:
        AssertionError: when the tasks are not two, or the owner condition is not in the assert.
    """
    tasks = cast(
        "list[dict[str, object]]", YAML(typ="safe").load(TASKS.read_text(encoding="utf-8"))
    )
    picked = [t for t in tasks if str(t.get("name", "")).startswith(TASK_STARTS)]
    if len(picked) != len(TASK_STARTS):
        message = f"{len(picked)} credentials tasks, expected {len(TASK_STARTS)}"
        raise AssertionError(message)
    check = cast("dict[str, list[str]]", picked[1]["ansible.builtin.assert"])
    if not any(condition.endswith(ROOT_OWNER) for condition in check["that"]):
        message = "the credentials assert no longer asks for root's ownership"
        raise AssertionError(message)
    check["that"] = [
        condition.replace(ROOT_OWNER, f"stat.uid == {os.getuid()}") for condition in check["that"]
    ]
    return picked


class Run:
    """What one run of the two tasks did."""

    def __init__(self, returncode: int, output: str) -> None:
        self.returncode = returncode
        self.output = output

    @property
    def failed(self) -> bool:
        """Whether the run stopped."""
        return self.returncode != 0


class CredentialsCheckTests(unittest.TestCase):
    """A credentials file that is not a regular, closed file stops the run; a good one does not."""

    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="mail-collector-credentials-"))
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.path = self.home / "credentials.env"

    def run_check(self) -> Run:
        """Run the role's two tasks against the scratch path."""
        play = self.home / "play.yml"
        writer = YAML()
        writer.default_flow_style = False
        with play.open("w", encoding="utf-8") as handle:
            writer.dump(
                [
                    {
                        "name": "Credentials",
                        "hosts": "localhost",
                        "connection": "local",
                        "gather_facts": False,
                        "vars_files": [str(ROLE / "vars" / "main.yml")],
                        "tasks": credentials_tasks(),
                    }
                ],
                handle,
            )
        values = self.home / "values.json"
        values.write_text(
            json.dumps(
                {
                    "mail_collector_credentials_file": str(self.path),
                    "ansible_python_interpreter": sys.executable,
                }
            ),
            encoding="utf-8",
        )
        environment = {
            **os.environ,
            "ANSIBLE_HOME": str(self.home / "home"),
            "ANSIBLE_LOCAL_TEMP": str(self.home / "tmp"),
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_HOST_KEY_CHECKING": "false",
        }
        run = subprocess.run(  # noqa: S603
            [ansible_playbook(), "-i", "localhost,", str(play), "-e", f"@{values}"],
            capture_output=True,
            text=True,
            check=False,
            env=environment,
            timeout=RUN_SECONDS,
        )
        return Run(run.returncode, run.stdout + run.stderr)

    def good_file(self, name: str = "credentials.env") -> Path:
        """Make a regular file of mode 0600 in the scratch directory and return it."""
        path = self.home / name
        path.write_text("", encoding="utf-8")
        path.chmod(0o600)
        return path

    def assert_refused(self, run: Run) -> None:
        """Require the run to have stopped on the role's own refusal."""
        self.assertTrue(run.failed, run.output)
        self.assertIn("The credentials file is not a regular file", run.output)

    def test_a_regular_file_of_mode_0600_that_is_the_runners_passes(self) -> None:
        # The green side: the same run with a good file, so a refusal below is the file's fault.
        self.good_file()
        run = self.run_check()
        self.assertFalse(run.failed, run.output)

    def test_no_file_passes(self) -> None:
        # The owner has not placed it yet; the unit's start condition holds the collector off.
        run = self.run_check()
        self.assertFalse(run.failed, run.output)

    def test_a_file_that_others_can_read_is_refused(self) -> None:
        self.good_file().chmod(0o644)
        self.assert_refused(self.run_check())

    def test_a_link_to_a_good_file_is_refused_because_the_look_does_not_follow_links(self) -> None:
        # Red when `follow: false` is removed: the look then reports the target, a regular file
        # of mode 0600, and the assert passes it.
        target = self.good_file("target.env")
        self.path.symlink_to(target)
        self.assertTrue(self.path.is_symlink())
        self.assert_refused(self.run_check())

    def test_a_link_to_nothing_is_refused(self) -> None:
        self.path.symlink_to(self.home / "nothing.env")
        self.assert_refused(self.run_check())

    def test_a_directory_of_mode_0600_is_refused_because_the_assert_wants_a_regular_file(
        self,
    ) -> None:
        # Red when `isreg` is removed from the assert: owner and mode alone pass this directory.
        self.path.mkdir()
        self.path.chmod(0o600)
        self.assert_refused(self.run_check())

    def test_a_pipe_of_mode_0600_is_refused_because_the_assert_wants_a_regular_file(self) -> None:
        # Red when `isreg` is removed from the assert: owner and mode alone pass this pipe.
        os.mkfifo(self.path, 0o600)
        self.path.chmod(0o600)
        self.assert_refused(self.run_check())


if __name__ == "__main__":
    unittest.main()
