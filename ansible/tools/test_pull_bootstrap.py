"""Tests for the bootstrap record tool: what it writes, refuses, and how it matches Ansible.

The record is built from a temporary git repository that holds copies of this repository's own
files, so the pins, the hashes and the configuration are the real ones' shape. The parity test
runs the role's own task with ansible-playbook and compares bytes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

import pull_bootstrap as tool
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[2]
CLOUD_INIT = ROOT / "hetzner-host" / "cloudInit.ts"
COPIED = (*tool.INPUTS, *tool.FETCHED.values())

GIT_IDENTITY = (
    "-c",
    "user.name=Test",
    "-c",
    "user.email=test@example.invalid",
    "-c",
    "commit.gpgsign=false",
)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def entry_of(record: dict[str, object], name: str) -> dict[str, object]:
    """Return one file's entry of a record, for a test to change in place.

    Raises:
        TypeError: The record holds no entry of that name.
    """
    found = record[name]
    if not isinstance(found, dict):
        message = f"{name} is not an entry"
        raise TypeError(message)
    return found


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Repo:
    """A throwaway git repository holding copies of the files the tool reads.

    It has an ``origin`` of its own, a bare repository beside it, and a commit made on ``main``
    is pushed there at once, so ``origin``'s ``main`` is what the tool must bind a pin to. A
    commit on any other branch is not pushed.
    """

    def __init__(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        base = Path(self.directory.name).resolve()
        self.origin = base / "origin.git"
        self.path = base / "work"
        self.path.mkdir()
        subprocess.run(  # noqa: S603 - fixed argv built from this test's own values
            ["git", "init", "-q", "--bare", "-b", "main", str(self.origin)],  # noqa: S607
            check=True,
            stdin=subprocess.DEVNULL,
        )
        self.run("init", "-q", "-b", "main")
        self.run("remote", "add", "origin", str(self.origin))
        for relative in COPIED:
            target = self.path / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.commit("first: every file")

    def run(self, *args: str) -> str:
        done = subprocess.run(  # noqa: S603 - fixed argv built from this test's own values
            ["git", "-C", str(self.path), *GIT_IDENTITY, *args],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            stdin=subprocess.DEVNULL,
        )
        return done.stdout.strip()

    def commit(self, message: str) -> str:
        self.run("add", "-A")
        self.run("commit", "-q", "-m", message)
        if self.run("branch", "--show-current") == "main":
            self.run("push", "-q", "origin", "main")
        return self.head()

    def head(self) -> str:
        return self.run("rev-parse", "HEAD")

    def edit(self, relative: str, change: Callable[[str], str]) -> None:
        target = self.path / relative
        target.write_text(change(target.read_text(encoding="utf-8")), encoding="utf-8")

    def cleanup(self) -> None:
        self.directory.cleanup()


class RepoCase(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo()
        self.addCleanup(self.repo.cleanup)
        self.first = self.repo.head()

    def record(self) -> dict[str, object]:
        return tool.build_record(self.repo.path)

    def problems(self, record: object) -> list[str]:
        return tool.verify_record(self.repo.path, record)


class ConfigTexts:
    """The texts the tool renders the configuration from, taken from this repository."""

    tasks = read(tool.TASKS_PATH)
    defaults = read(tool.DEFAULTS_PATH)
    variables = read(tool.VARS_PATH)
    group = read(tool.GROUP_VARS_PATH)


def render(
    *,
    tasks: str | None = None,
    defaults: str | None = None,
    variables: str | None = None,
    group: str | None = None,
) -> str:
    return tool.render_config(
        ConfigTexts.tasks if tasks is None else tasks,
        ConfigTexts.defaults if defaults is None else defaults,
        ConfigTexts.variables if variables is None else variables,
        ConfigTexts.group if group is None else group,
    )


class RecordTest(RepoCase):
    def test_each_file_is_pinned_to_the_last_commit_that_changed_it(self) -> None:
        self.repo.edit(tool.FETCHED["lock"], lambda text: text + "# bumped\n")
        bumped = self.repo.commit("second: the lock only")
        record = self.record()
        entries = {name: record[name] for name in tool.FETCHED}
        pins = {name: entry["pin"] for name, entry in entries.items()}  # type: ignore[index]
        self.assertEqual({"wrapper": self.first, "program": self.first, "lock": bumped}, pins)

    def test_hashes_and_urls_are_of_the_file_at_the_pin(self) -> None:
        record = self.record()
        for name, path in tool.FETCHED.items():
            entry = entry_of(record, name)
            self.assertEqual(sha((ROOT / path).read_bytes()), entry["sha256"])
            self.assertEqual(
                f"https://raw.githubusercontent.com/branchLeft/shared-infra/{self.first}/{path}",
                entry["url"],
            )

    def test_the_record_is_current_against_the_repository_it_was_built_from(self) -> None:
        self.assertEqual([], self.problems(self.record()))

    def test_the_command_line_writes_a_record_that_the_command_line_accepts(self) -> None:
        out = self.repo.path.parent / "record.json"
        self.addCleanup(out.unlink, missing_ok=True)
        self.assertEqual(
            0, tool.main(["generate", "--repo", str(self.repo.path), "--out", str(out)])
        )
        self.assertEqual(self.record(), json.loads(out.read_text(encoding="utf-8")))
        self.assertEqual(
            0, tool.main(["verify", "--repo", str(self.repo.path), "--record", str(out)])
        )

    def test_an_uncommitted_change_to_a_pinned_file_is_refused(self) -> None:
        self.repo.edit(tool.FETCHED["wrapper"], lambda text: text + "# not committed\n")
        with self.assertRaisesRegex(tool.BootstrapError, "not committed"):
            self.record()

    def test_an_uncommitted_change_to_a_configuration_input_is_refused(self) -> None:
        self.repo.edit(tool.GROUP_VARS_PATH, lambda text: text + "# not committed\n")
        with self.assertRaisesRegex(tool.BootstrapError, "not committed"):
            self.record()


class VerifyTest(RepoCase):
    """C10: a record that is stale or wrong is red, and each check is the one that says so."""

    def test_group_variables_edited_without_rebuilding_is_red(self) -> None:
        record = self.record()
        self.repo.edit(
            tool.DEFAULTS_PATH, lambda text: text.replace("keep_runs: 50", "keep_runs: 60")
        )
        self.repo.commit("change the configuration only")
        self.assertEqual(
            ["config: differs from the one the repository's files give"], self.problems(record)
        )

    def test_a_pinned_file_changed_after_the_record_is_red_as_stale(self) -> None:
        record = self.record()
        self.repo.edit(tool.FETCHED["program"], lambda text: text + "# changed\n")
        self.repo.commit("change the program")
        self.assertEqual(
            ["program: a later commit changed the file, so the pin is stale"], self.problems(record)
        )

    def test_a_pin_that_is_an_earlier_commit_than_the_last_to_touch_the_file_is_red(self) -> None:
        self.repo.edit(tool.FETCHED["lock"], lambda text: text + "# bumped\n")
        self.repo.commit("bump the lock")
        record = self.record()
        lock = entry_of(record, "lock")
        pin = self.first
        lock["pin"] = pin
        lock["url"] = tool.raw_url(pin, tool.FETCHED["lock"])
        lock["sha256"] = sha(self.repo.run("show", f"{pin}:{tool.FETCHED['lock']}").encode())
        found = self.problems(record)
        self.assertIn("lock: a later commit changed the file, so the pin is stale", found)

    def test_a_pin_that_touches_nothing_is_red(self) -> None:
        self.repo.run("commit", "-q", "--allow-empty", "-m", "touches no file")
        self.repo.run("push", "-q", "origin", "main")
        record = self.record()
        wrapper = entry_of(record, "wrapper")
        empty = self.repo.head()
        wrapper["pin"] = empty
        wrapper["url"] = tool.raw_url(empty, tool.FETCHED["wrapper"])
        found = self.problems(record)
        self.assertIn("wrapper: a later commit changed the file, so the pin is stale", found)

    def pinned_to(self, record: dict[str, object], name: str, pin: str) -> None:
        """Point one entry of the record at a commit, with the hash and url that commit gives."""
        path = tool.FETCHED[name]
        entry = entry_of(record, name)
        entry["pin"] = pin
        entry["url"] = tool.raw_url(pin, path)
        entry["sha256"] = sha(self.repo.run("show", f"{pin}:{path}").encode())

    def test_a_pin_on_a_side_branch_is_red(self) -> None:
        self.repo.run("checkout", "-q", "-b", "side")
        self.repo.edit(tool.FETCHED["wrapper"], lambda text: text + "# on a side branch\n")
        side = self.repo.commit("side")
        self.repo.run("checkout", "-q", "main")
        record = self.record()
        self.pinned_to(record, "wrapper", side)
        self.assertEqual(
            ["wrapper: the pin is not an ancestor of origin/main"], self.problems(record)
        )

    def test_a_pin_on_a_local_main_that_origin_does_not_have_is_red(self) -> None:
        # The record's builder committed on a local main and never pushed it: HEAD holds the
        # pin, so a check against HEAD alone would pass; origin's main does not hold it.
        self.repo.edit(tool.FETCHED["wrapper"], lambda text: text + "# only on this machine\n")
        self.repo.run("add", "-A")
        self.repo.run("commit", "-q", "-m", "local only")
        local = self.repo.head()
        record = self.record_from_unpushed_head(local)
        self.assertEqual(
            ["wrapper: the pin is not an ancestor of origin/main"], self.problems(record)
        )

    def record_from_unpushed_head(self, local: str) -> dict[str, object]:
        """Return the record that HEAD alone gives, as a builder on a local main would make it."""
        record: dict[str, object] = {"schema": tool.SCHEMA}
        for name, path in tool.FETCHED.items():
            commit = tool.last_commit(self.repo.path, path)
            record[name] = {
                "pin": commit,
                "sha256": tool.blob_sha256(self.repo.path, commit, path),
                "url": tool.raw_url(commit, path),
            }
        record["config"] = tool.repository_config(self.repo.path)
        self.assertEqual(local, entry_of(record, "wrapper")["pin"])
        return record

    def test_a_pin_that_main_has_but_head_has_not_is_red(self) -> None:
        self.repo.edit(tool.FETCHED["wrapper"], lambda text: text + "# newer\n")
        newer = self.repo.commit("newer on main")
        record = self.record()
        self.repo.run("checkout", "-q", "--detach", self.first)
        self.assertEqual(newer, entry_of(record, "wrapper")["pin"])
        found = self.problems(record)
        self.assertIn("wrapper: the pin is not an ancestor of HEAD", found)

    def test_a_pin_the_repository_does_not_have_is_red(self) -> None:
        record = self.record()
        wrapper = entry_of(record, "wrapper")
        wrapper["pin"] = "f" * 40
        wrapper["url"] = tool.raw_url("f" * 40, tool.FETCHED["wrapper"])
        self.assertIn("wrapper: the pin is not an ancestor of origin/main", self.problems(record))

    def test_no_main_to_fetch_is_red(self) -> None:
        record = self.record()
        self.repo.run("remote", "set-url", "origin", str(self.repo.path.parent / "gone.git"))
        found = self.problems(record)
        self.assertEqual(1, len(found))
        self.assertIn("git fetch", found[0])

    def test_a_wrong_sha256_is_red(self) -> None:
        for wrong in ("0" * 64, "f" * 64):
            with self.subTest(wrong=wrong):
                record = self.record()
                lock = entry_of(record, "lock")
                lock["sha256"] = wrong
                self.assertEqual(
                    ["lock: the sha256 is not that of the file at the pin"], self.problems(record)
                )

    def test_a_url_that_names_another_commit_than_the_pin_is_red(self) -> None:
        record = self.record()
        program = entry_of(record, "program")
        program["url"] = tool.raw_url("e" * 40, tool.FETCHED["program"])
        self.assertEqual(
            ["program: the url does not name the recorded pin and the file"], self.problems(record)
        )

    def test_a_url_for_another_file_is_red(self) -> None:
        record = self.record()
        program = entry_of(record, "program")
        program["url"] = tool.raw_url(self.first, tool.FETCHED["wrapper"])
        self.assertEqual(
            ["program: the url does not name the recorded pin and the file"], self.problems(record)
        )

    def test_a_malformed_record_is_red(self) -> None:
        self.assertEqual(["the record is not schema 1"], self.problems({"schema": 2}))
        self.assertEqual(["the record is not schema 1"], self.problems([]))
        record = self.record()
        del record["lock"]
        self.assertIn("lock: the entry is not a pin, a sha256 and a url", self.problems(record))
        record = self.record()
        wrapper = entry_of(record, "wrapper")
        wrapper["pin"] = "main"
        self.assertIn("wrapper: the pin is not a full commit id", self.problems(record))


class MainBindingTest(RepoCase):
    """A record is built only from the tip of a freshly fetched main."""

    def test_a_branch_head_is_refused_and_the_command_writes_nothing(self) -> None:
        self.repo.run("checkout", "-q", "-b", "feature")
        self.repo.edit(tool.FETCHED["lock"], lambda text: text + "# on a branch\n")
        self.repo.commit("a branch commit")
        with self.assertRaisesRegex(tool.BootstrapError, "is not the tip of origin/main"):
            self.record()
        out = self.repo.path.parent / "record.json"
        self.assertEqual(
            1, tool.main(["generate", "--repo", str(self.repo.path), "--out", str(out)])
        )
        self.assertFalse(out.exists())

    def test_a_main_that_is_behind_origin_is_refused(self) -> None:
        self.repo.edit(tool.FETCHED["lock"], lambda text: text + "# newer\n")
        self.repo.commit("newer on main")
        self.repo.run("reset", "-q", "--hard", self.first)
        with self.assertRaisesRegex(tool.BootstrapError, "is not the tip of origin/main"):
            self.record()

    def test_a_local_main_ahead_of_origin_is_refused(self) -> None:
        self.repo.edit(tool.FETCHED["lock"], lambda text: text + "# not pushed\n")
        self.repo.run("add", "-A")
        self.repo.run("commit", "-q", "-m", "not pushed")
        with self.assertRaisesRegex(tool.BootstrapError, "is not the tip of origin/main"):
            self.record()

    def test_a_stale_remote_tracking_branch_does_not_stand_in_for_main(self) -> None:
        # An earlier fetch left origin/main at the first commit; origin has since moved on.
        self.repo.run("fetch", "-q", "origin", "main:refs/remotes/origin/main")
        self.repo.edit(tool.FETCHED["lock"], lambda text: text + "# newer\n")
        newer = self.repo.commit("newer on main")
        self.repo.run("update-ref", "refs/remotes/origin/main", self.first)
        self.assertEqual(newer, entry_of(self.record(), "lock")["pin"])

    def test_no_main_to_fetch_is_refused(self) -> None:
        self.repo.run("remote", "set-url", "origin", str(self.repo.path.parent / "gone.git"))
        with self.assertRaisesRegex(tool.BootstrapError, "git fetch"):
            self.record()


class ConfigRefusalTest(unittest.TestCase):
    """C9: each of these stops the build, so the first-boot document cannot carry it."""

    def refuses(self, pattern: str, **texts: str) -> None:
        with self.assertRaisesRegex(tool.BootstrapError, pattern):
            render(**texts)

    def test_the_repository_inputs_render(self) -> None:
        text = render()
        self.assertTrue(text.endswith("\n"))
        config = json.loads(text)
        self.assertEqual(tool.PLAYBOOK_PATH, config["playbook"])
        self.assertEqual([tool.PLAYBOOK_PATH], config["playbooks"])
        self.assertEqual(3600, config["timeout_seconds"])

    def test_a_missing_playbook_key_is_refused(self) -> None:
        group = re.sub(r"^pull_trigger_playbook: .*\n", "", ConfigTexts.group, flags=re.MULTILINE)
        self.refuses("pull_trigger_playbook, which no variable file sets", group=group)

    def test_a_playbook_that_is_not_on_the_allowlist_is_refused(self) -> None:
        group = ConfigTexts.group.replace(
            "pull_trigger_playbook: ansible/playbooks/edge1.yml",
            "pull_trigger_playbook: ansible/playbooks/db1.yml",
        )
        self.refuses("not on the playbook allowlist", group=group)

    def test_a_playbook_that_is_not_edge1_is_refused_even_when_allowlisted(self) -> None:
        group = ConfigTexts.group.replace("edge1.yml", "db1.yml")
        self.refuses("only ansible/playbooks/edge1.yml is allowed", group=group)

    def test_a_second_allowlisted_playbook_is_refused(self) -> None:
        group = ConfigTexts.group.replace(
            "pull_trigger_playbooks:\n  - ansible/playbooks/edge1.yml",
            "pull_trigger_playbooks:\n  - ansible/playbooks/edge1.yml"
            "\n  - ansible/playbooks/db1.yml",
        )
        self.refuses("only ansible/playbooks/edge1.yml is allowed", group=group)

    def test_an_empty_signer_list_is_refused(self) -> None:
        group = (
            ConfigTexts.group[: ConfigTexts.group.index("pull_trigger_signers:")]
            + "pull_trigger_signers: []\n"
        )
        self.refuses("signer allowlist is empty", group=group)

    def test_malformed_yaml_is_refused(self) -> None:
        for name in ("group", "defaults", "variables", "tasks"):
            with self.subTest(name=name):
                self.refuses("is not valid YAML", **{name: "key: [unclosed\n  - x: : :\n"})

    def test_a_variable_set_in_two_files_is_refused(self) -> None:
        group = ConfigTexts.group + "pull_trigger_keep_runs: 5\n"
        self.refuses("pull_trigger_keep_runs is set in", group=group)

    def test_a_task_that_no_longer_writes_to_nice_json_of_one_variable_is_refused(self) -> None:
        tasks = ConfigTexts.tasks.replace("ansible.builtin.to_nice_json", "ansible.builtin.to_json")
        self.refuses("no longer writes to_nice_json", tasks=tasks)

    def test_a_task_key_that_is_not_a_plain_variable_is_refused(self) -> None:
        tasks = ConfigTexts.tasks.replace(
            "remote_url: '{{ pull_trigger_remote_url }}'",
            "remote_url: '{{ pull_trigger_remote_url | upper }}'",
        )
        self.refuses("remote_url is not a plain variable", tasks=tasks)

    def test_a_task_key_that_names_an_unset_variable_is_refused(self) -> None:
        tasks = ConfigTexts.tasks.replace(
            "keep_runs: '{{ pull_trigger_keep_runs | int }}'",
            "keep_runs: '{{ pull_trigger_nothing | int }}'",
        )
        self.refuses("pull_trigger_nothing, which no variable file sets", tasks=tasks)

    def test_a_number_that_is_not_a_number_is_refused(self) -> None:
        defaults = ConfigTexts.defaults.replace(
            "pull_trigger_keep_runs: 50", "pull_trigger_keep_runs: many"
        )
        self.refuses("is not a number", defaults=defaults)

    def test_no_configuration_task_and_two_of_them_are_refused(self) -> None:
        none = ConfigTexts.tasks.replace("Write the configuration", "Write something else")
        self.refuses("has 0 tasks", tasks=none)
        two = ConfigTexts.tasks + ConfigTexts.tasks.split("---\n", 1)[1]
        self.refuses("has 2 tasks", tasks=two)

    def test_a_playbook_that_does_not_load_the_group_variables_is_refused(self) -> None:
        with self.assertRaisesRegex(tool.BootstrapError, "does not load"):
            tool.check_playbook("- hosts: all\n  roles: []\n")
        tool.check_playbook(read(tool.PLAYBOOK_PATH))


class ParityTest(unittest.TestCase):
    """C11: the tool writes the bytes that Ansible writes when it runs the role's own task."""

    def ansible_playbook(self) -> Path:
        return Path(sys.executable).parent / "ansible-playbook"

    def role_writes(self, group_text: str) -> str:
        """Run the role's configuration task under ansible-playbook and return the file it wrote."""
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            variable_files = []
            for name, text in (
                ("defaults.yml", ConfigTexts.defaults),
                ("vars.yml", ConfigTexts.variables),
                ("group.yml", group_text),
            ):
                (work / name).write_text(text, encoding="utf-8")
                variable_files.append(str(work / name))
            task = tool.config_task(YAML(typ="safe").load(ConfigTexts.tasks))
            written = work / "config.json"
            # Only where the file goes changes: no owner, group or mode, since this is not root.
            copy = tool.mapping(task["ansible.builtin.copy"], "the copy")
            task["ansible.builtin.copy"] = {
                "content": copy["content"],
                "dest": str(written),
            }
            play = [
                {
                    "name": "Run the role's configuration task",
                    "hosts": "localhost",
                    "gather_facts": False,
                    "vars_files": variable_files,
                    "tasks": [task],
                }
            ]
            playbook = work / "play.yml"
            yaml = YAML(typ="safe")
            with playbook.open("w", encoding="utf-8") as handle:
                yaml.dump(play, handle)
            done = subprocess.run(  # noqa: S603 - fixed argv built from this test's own values
                [str(self.ansible_playbook()), "-i", "localhost,", "-c", "local", str(playbook)],
                capture_output=True,
                text=True,
                check=False,
                stdin=subprocess.DEVNULL,
                env={
                    "PATH": os.environ["PATH"],
                    "ANSIBLE_HOME": str(work / "home"),
                    "ANSIBLE_LOCAL_TEMP": str(work / "tmp"),
                    "ANSIBLE_NOCOLOR": "1",
                },
            )
            self.assertEqual(0, done.returncode, done.stdout + done.stderr)
            return written.read_text(encoding="utf-8")

    def test_the_production_values_are_written_byte_for_byte(self) -> None:
        self.assertEqual(self.role_writes(ConfigTexts.group), render())

    def test_a_non_ascii_character_and_a_multi_line_key_are_written_byte_for_byte(self) -> None:
        group = ConfigTexts.group.replace(
            "mQINBGWmxXYBEACyN+4viFQM6QQoKr0A2W0rGdMobTJwOZso2QPpewbyBsuL3rNW",
            "mQINBGWmxXYBEACyN café — “quoted” 漢字 \U0001f512",
        )
        self.assertNotEqual(group, ConfigTexts.group)
        written = self.role_writes(group)
        self.assertEqual(written, render(group=group))
        self.assertIn("\\u00e9", written)
        self.assertIn("\\ud83d\\udd12", written)


class PackagesTest(unittest.TestCase):
    """The first-boot package list is the two roles' lists, not a third copy that can drift."""

    @staticmethod
    def ts_list(name: str) -> set[str]:
        match = re.search(
            rf"{name}\s*=\s*\[(.*?)\]", CLOUD_INIT.read_text(encoding="utf-8"), re.DOTALL
        )
        if match is None:
            message = f"{name} is not in cloudInit.ts"
            raise AssertionError(message)
        return set(re.findall(r"'([^']+)'", match.group(1)))

    @staticmethod
    def role_list(path: str, variable: str) -> set[str]:
        document = YAML(typ="safe").load(read(path))
        value = tool.sequence(document[variable], variable)
        return {str(item) for item in value}

    def test_the_enrolment_packages_are_the_two_roles_packages_less_the_base_ones(self) -> None:
        roles = self.role_list(
            "ansible/roles/ansible_runtime/vars/main.yml", "ansible_runtime_packages"
        ) | self.role_list("ansible/roles/pull_trigger/vars/main.yml", "pull_trigger_packages")
        base = self.ts_list("BASE_PACKAGES")
        self.assertEqual(roles - base, self.ts_list("ENROLMENT_PACKAGES"))

    def test_the_fetch_needs_curl_and_certificates_in_the_base_list(self) -> None:
        self.assertLessEqual({"curl", "ca-certificates"}, self.ts_list("BASE_PACKAGES"))

    def test_the_scan_finds_what_it_is_meant_to_find(self) -> None:
        # A control: an empty result on both sides would also be equal.
        self.assertIn("python3-venv", self.ts_list("ENROLMENT_PACKAGES"))
        self.assertIn("git", self.ts_list("ENROLMENT_PACKAGES"))


if __name__ == "__main__":
    unittest.main()
