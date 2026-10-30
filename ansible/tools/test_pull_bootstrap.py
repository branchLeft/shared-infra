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
from typing import Final
from unittest import mock

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
    common = read(tool.COMMON_PATH)
    trust = read(tool.TRUST_PATH)


def render(
    *,
    tasks: str | None = None,
    defaults: str | None = None,
    variables: str | None = None,
    common: str | None = None,
    trust: str | None = None,
) -> str:
    return tool.render_config(
        ConfigTexts.tasks if tasks is None else tasks,
        ConfigTexts.defaults if defaults is None else defaults,
        ConfigTexts.variables if variables is None else variables,
        ConfigTexts.common if common is None else common,
        ConfigTexts.trust if trust is None else trust,
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
        for path in (tool.COMMON_PATH, tool.TRUST_PATH):
            with self.subTest(path=path):
                self.repo.edit(path, lambda text: text + "# not committed\n")
                with self.assertRaisesRegex(tool.BootstrapError, "not committed"):
                    self.record()
                self.repo.run("checkout", "--", path)


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
        # pin, so a check against HEAD alone would pass; origin's main does not hold it. The
        # check refuses at HEAD, which is not the tip of origin's main.
        self.repo.edit(tool.FETCHED["wrapper"], lambda text: text + "# only on this machine\n")
        self.repo.run("add", "-A")
        self.repo.run("commit", "-q", "-m", "local only")
        local = self.repo.head()
        record = self.record_from_unpushed_head(local)
        found = self.problems(record)
        self.assertEqual(1, len(found))
        self.assertIn("is not the tip of origin/main", found[0])

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
        self.assertEqual(1, len(found))
        self.assertIn("is not the tip of origin/main", found[0])

    def test_a_checkout_behind_main_does_not_verify_a_pin_that_main_has_superseded(self) -> None:
        # The record was built from the first commit, then main changed the program. A checkout
        # still at the first commit sees the pin as the last change to the file, so a check that
        # read HEAD's history would call the record current. It must read main's.
        record = self.record()
        self.repo.edit(tool.FETCHED["program"], lambda text: text + "# changed on main\n")
        self.repo.commit("main changes the program")
        self.repo.run("checkout", "-q", "--detach", self.first)
        found = self.problems(record)
        self.assertEqual(1, len(found))
        self.assertIn("is not the tip of origin/main", found[0])
        self.assertEqual(1, self.verify_status(record))

    def test_a_checkout_behind_main_does_not_verify_a_configuration_main_has_changed(self) -> None:
        record = self.record()
        self.repo.edit(
            tool.DEFAULTS_PATH, lambda text: text.replace("keep_runs: 50", "keep_runs: 60")
        )
        self.repo.commit("main changes the configuration")
        self.repo.run("checkout", "-q", "--detach", self.first)
        found = self.problems(record)
        self.assertEqual(1, len(found))
        self.assertIn("is not the tip of origin/main", found[0])

    def test_a_checkout_at_the_tip_of_main_still_verifies_a_current_record(self) -> None:
        # A control for the two above: they are red because HEAD is behind, not because
        # verify refuses everything.
        record = self.record()
        self.repo.run("checkout", "-q", "--detach", "origin/main")
        self.assertEqual([], self.problems(record))

    def verify_status(self, record: dict[str, object]) -> int:
        """Return the exit status of the command line's verify for a record."""
        path = self.repo.path.parent / "record-to-verify.json"
        self.addCleanup(path.unlink, missing_ok=True)
        path.write_text(json.dumps(record), encoding="utf-8")
        return tool.main(["verify", "--repo", str(self.repo.path), "--record", str(path)])

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


class ShallowTest(RepoCase):
    """A shallow clone cannot say which commit last changed a file, so the tool refuses it."""

    def setUp(self) -> None:
        super().setUp()
        # A second commit on main that changes one file only, so that the first commit is the
        # real last change of the other two and a depth-1 clone cannot see it.
        self.repo.edit(tool.FETCHED["lock"], lambda text: text + "# newer\n")
        self.second = self.repo.commit("second: the lock only")
        self.shallow = self.clone(["--depth", "1"], "shallow")
        self.full = self.clone([], "full")

    def clone(self, options: list[str], name: str) -> Path:
        target = self.repo.path.parent / name
        subprocess.run(  # noqa: S603 - fixed argv built from this test's own values
            ["git", "clone", "-q", *options, f"file://{self.repo.origin}", str(target)],  # noqa: S607
            check=True,
            stdin=subprocess.DEVNULL,
        )
        return target

    def test_the_premise_a_shallow_clone_reads_every_pin_as_head(self) -> None:
        # A control for the refusals below: without them the tool would have written a pin that
        # is not the last change, and the stale-pin check would have had nothing to compare.
        self.assertEqual(self.second, tool.last_commit(self.shallow, tool.FETCHED["wrapper"]))
        self.assertEqual(self.first, tool.last_commit(self.full, tool.FETCHED["wrapper"]))

    def test_a_shallow_clone_is_refused_by_generate_and_writes_nothing(self) -> None:
        with self.assertRaisesRegex(tool.BootstrapError, "shallow clone"):
            tool.build_record(self.shallow)
        out = self.repo.path.parent / "record.json"
        self.assertEqual(1, tool.main(["generate", "--repo", str(self.shallow), "--out", str(out)]))
        self.assertFalse(out.exists())

    def test_a_shallow_clone_is_refused_by_verify_even_for_a_record_that_is_current(self) -> None:
        record = self.record()
        found = tool.verify_record(self.shallow, record)
        self.assertEqual(1, len(found))
        self.assertIn("shallow clone", found[0])
        path = self.repo.path.parent / "record-to-verify.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        self.assertEqual(
            1, tool.main(["verify", "--repo", str(self.shallow), "--record", str(path)])
        )

    def test_a_full_clone_of_the_same_history_builds_and_verifies(self) -> None:
        # A control: the refusals above are for the missing history, not for the clone.
        record = tool.build_record(self.full)
        self.assertEqual(self.record(), record)
        self.assertEqual([], tool.verify_record(self.full, record))

    def test_an_answer_other_than_false_from_git_is_a_refusal(self) -> None:
        # Fail closed: the tool accepts only a plain "false", so a git that says anything else
        # (or nothing) is not taken for a whole history.
        for answer in (b"true\n", b"\n", b"", b"False\n", b"no\n"):
            with self.subTest(answer=answer):
                said = subprocess.CompletedProcess([], 0, stdout=answer)
                with (
                    mock.patch.object(tool, "git", return_value=said),
                    self.assertRaisesRegex(tool.BootstrapError, "shallow clone"),
                ):
                    tool.refuse_shallow(self.full)
        tool.refuse_shallow(self.full)


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

    def test_the_playbook_and_its_allowlist_are_filled_from_the_host_name(self) -> None:
        # A control for the refusals below: the shared include holds a template, not the path.
        self.assertIn("{{ enrolled_host }}", ConfigTexts.common)
        self.assertNotIn(tool.PLAYBOOK_PATH, ConfigTexts.common)
        self.assertEqual(tool.PLAYBOOK_PATH, json.loads(render())["playbook"])

    def test_the_signers_are_those_of_the_trust_file(self) -> None:
        signers = tool.mapping(YAML(typ="safe").load(ConfigTexts.trust), tool.TRUST_PATH)
        self.assertEqual(signers["pull_trigger_signers"], json.loads(render())["signers"])

    def test_a_missing_playbook_key_is_refused(self) -> None:
        common = re.sub(r"^pull_trigger_playbook: .*\n", "", ConfigTexts.common, flags=re.MULTILINE)
        self.assertNotEqual(common, ConfigTexts.common)
        self.refuses("pull_trigger_playbook, which no variable file sets", common=common)

    def test_a_playbook_that_is_not_on_the_allowlist_is_refused(self) -> None:
        common = ConfigTexts.common.replace(
            "  - '{{ pull_trigger_playbook }}'", "  - ansible/playbooks/db1.yml"
        )
        self.assertNotEqual(common, ConfigTexts.common)
        self.refuses("not on the playbook allowlist", common=common)

    def test_a_playbook_that_is_not_edge1_is_refused_even_when_allowlisted(self) -> None:
        common = ConfigTexts.common.replace("{{ enrolled_host }}", "db1")
        self.assertNotEqual(common, ConfigTexts.common)
        self.refuses("only ansible/playbooks/edge1.yml is allowed", common=common)

    def test_a_second_allowlisted_playbook_is_refused(self) -> None:
        common = ConfigTexts.common + "  - ansible/playbooks/db1.yml\n"
        self.refuses("only ansible/playbooks/edge1.yml is allowed", common=common)

    def test_another_remote_is_refused(self) -> None:
        common = ConfigTexts.common.replace(tool.REMOTE_URL, "https://example.invalid/x.git")
        self.assertNotEqual(common, ConfigTexts.common)
        self.refuses("the remote is not", common=common)

    def test_an_empty_signer_list_is_refused(self) -> None:
        trust = (
            ConfigTexts.trust[: ConfigTexts.trust.index("pull_trigger_signers:")]
            + "pull_trigger_signers: []\n"
        )
        self.refuses("signer allowlist is empty", trust=trust)

    def test_malformed_yaml_is_refused(self) -> None:
        for name in ("common", "trust", "defaults", "variables", "tasks"):
            with self.subTest(name=name):
                self.refuses("is not valid YAML", **{name: "key: [unclosed\n  - x: : :\n"})

    def test_a_variable_set_in_two_files_is_refused(self) -> None:
        trust = ConfigTexts.trust + "pull_trigger_keep_runs: 5\n"
        self.refuses("pull_trigger_keep_runs is set in", trust=trust)

    def test_the_host_name_set_in_a_variable_file_is_refused(self) -> None:
        common = ConfigTexts.common + "enrolled_host: db1\n"
        self.refuses("enrolled_host is set in", common=common)

    def test_a_template_that_is_not_a_plain_variable_is_refused(self) -> None:
        for template in (
            "{{ enrolled_host | upper }}",
            "{{ enrolled_host }}{{ enrolled_host | upper }}",
            "{% if true %}x{% endif %}",
            "{# a comment #}",
        ):
            with self.subTest(template=template):
                common = ConfigTexts.common.replace(
                    "{{ enrolled_host }}", "ansible/playbooks/edge1" + template
                )
                self.refuses("holds a template that is not a plain variable", common=common)

    def test_a_template_inside_a_signer_is_refused(self) -> None:
        trust = ConfigTexts.trust.replace(
            "format: openpgp", "format: '{{ enrolled_host | upper }}'"
        )
        self.assertNotEqual(trust, ConfigTexts.trust)
        self.refuses("holds a template that is not a plain variable", trust=trust)

    def test_a_reference_to_an_unset_variable_is_refused(self) -> None:
        common = ConfigTexts.common.replace("{{ enrolled_host }}", "{{ some_other_host }}")
        self.refuses("some_other_host, which no variable file sets", common=common)

    def test_a_reference_to_a_variable_that_is_not_text_is_refused(self) -> None:
        common = ConfigTexts.common.replace("{{ enrolled_host }}", "{{ pull_trigger_keep_runs }}")
        self.refuses("which is not text", common=common)

    def test_references_that_lead_to_one_another_without_end_are_refused(self) -> None:
        common = ConfigTexts.common.replace(
            "pull_trigger_remote_url: https://github.com/branchLeft/shared-infra.git",
            "pull_trigger_remote_url: '{{ pull_trigger_remote_url }}'",
        )
        self.assertNotEqual(common, ConfigTexts.common)
        self.refuses("holds a template that is not a plain variable", common=common)

    def test_a_task_that_no_longer_writes_to_nice_json_of_one_variable_is_refused(self) -> None:
        tasks = ConfigTexts.tasks.replace("ansible.builtin.to_nice_json", "ansible.builtin.to_json")
        self.refuses("no longer writes to_nice_json", tasks=tasks)

    def written_content(self, tasks: str) -> object:
        task = tool.config_task(YAML(typ="safe").load(tasks))
        return tool.mapping(task["ansible.builtin.copy"], "the copy").get("content")

    def with_content(self, content: str) -> str:
        """Return the role's tasks with the configuration task writing ``content`` instead."""
        line = "    content: " + json.dumps(content, ensure_ascii=False)
        return re.sub(r"^    content: .*$", lambda _: line, ConfigTexts.tasks, flags=re.MULTILINE)

    def test_the_task_that_merges_in_the_source_renders_the_same_bytes_as_without_it(self) -> None:
        self.assertEqual(tool.SOURCE_CONTENT, self.written_content(ConfigTexts.tasks))
        plain = self.with_content(tool.CONFIG_CONTENT)
        self.assertNotEqual(plain, ConfigTexts.tasks)
        self.assertEqual(render(tasks=plain), render())
        self.assertNotIn("source", json.loads(render()))

    def test_a_different_template_that_merges_something_else_in_is_refused(self) -> None:
        for content in (
            tool.SOURCE_CONTENT.replace("pull_trigger_config_source", "pull_trigger_signers"),
            tool.SOURCE_CONTENT.replace("combine(", "combine({'a': 1}, "),
            tool.SOURCE_CONTENT.replace("to_nice_json", "to_json"),
        ):
            self.refuses("no longer writes to_nice_json", tasks=self.with_content(content))

    def test_a_source_expression_other_than_the_roles_is_refused(self) -> None:
        tasks = ConfigTexts.tasks.replace("{'source': 'bundle'}", "{'source': 'remote'}")
        self.assertNotEqual(tasks, ConfigTexts.tasks)
        self.refuses("is not the expression this tool reads", tasks=tasks)

    def test_a_bundle_list_that_is_not_a_list_of_names_is_refused(self) -> None:
        variables = ConfigTexts.variables.replace("  - demo1\n", "  - 1\n")
        self.assertNotEqual(variables, ConfigTexts.variables)
        self.refuses("is not a list of host names", variables=variables)

    def test_a_host_in_the_bundle_list_is_refused_as_a_host_that_must_pull(self) -> None:
        variables = ConfigTexts.variables.replace("  - demo1\n", f"  - {tool.ENROLLED_HOST}\n")
        self.assertNotEqual(variables, ConfigTexts.variables)
        self.refuses(
            "takes bundles, and this tool bootstraps a host that pulls", variables=variables
        )

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

    def test_a_playbook_that_does_not_load_the_variable_files_is_refused(self) -> None:
        with self.assertRaisesRegex(tool.BootstrapError, "does not load"):
            tool.check_playbook("- hosts: all\n  roles: []\n")
        tool.check_playbook(read(tool.PLAYBOOK_PATH))

    def test_a_playbook_that_loads_only_one_of_the_two_files_is_refused(self) -> None:
        playbook = read(tool.PLAYBOOK_PATH)
        for entry in tool.PLAYBOOK_VARS_ENTRIES:
            with self.subTest(entry=entry):
                changed = playbook.replace(f"    - '{entry}'\n", "")
                self.assertNotEqual(playbook, changed)
                with self.assertRaisesRegex(tool.BootstrapError, "does not load"):
                    tool.check_playbook(changed)

    def test_a_playbook_that_loads_another_file_of_the_same_name_is_refused(self) -> None:
        # The tail of the path matches, so a check on the tail alone passes it; the playbook
        # would then load a file the record's configuration was not read from.
        playbook = read(tool.PLAYBOOK_PATH)
        for entry, tail in zip(
            tool.PLAYBOOK_VARS_ENTRIES,
            ("includes/pull_trigger_common.yml", "trust/edge1.yml"),
            strict=True,
        ):
            self.assertIn(entry, playbook)
            for other in (
                "{{ playbook_dir }}/../other/" + tail,
                "/srv/x/" + tail,
                "{{ playbook_dir }}/staging/../" + tail,
                entry + " ",
            ):
                with self.subTest(other=other):
                    changed = playbook.replace(entry, other)
                    self.assertNotEqual(playbook, changed)
                    with self.assertRaisesRegex(tool.BootstrapError, "does not load"):
                        tool.check_playbook(changed)

    def test_a_playbook_that_sets_another_host_name_is_refused(self) -> None:
        playbook = read(tool.PLAYBOOK_PATH)
        self.assertIn("enrolled_host: edge1", playbook)
        for changed in (
            playbook.replace("enrolled_host: edge1", "enrolled_host: db1"),
            playbook.replace("    enrolled_host: edge1\n", ""),
        ):
            self.assertNotEqual(playbook, changed)
            with self.assertRaisesRegex(tool.BootstrapError, "does not load"):
                tool.check_playbook(changed)

    def test_the_entries_the_playbook_is_checked_for_are_the_ones_it_uses_today(self) -> None:
        self.assertEqual(
            (
                "{{ playbook_dir }}/includes/pull_trigger_common.yml",
                "{{ playbook_dir }}/../trust/edge1.yml",
            ),
            tool.PLAYBOOK_VARS_ENTRIES,
        )


class ParityTest(unittest.TestCase):
    """C11: the tool writes the bytes that Ansible writes when it runs the role's own task."""

    def ansible_playbook(self) -> Path:
        return Path(sys.executable).parent / "ansible-playbook"

    def role_writes(self, trust_text: str) -> str:
        """Run the role's configuration task under ansible-playbook and return the file it wrote."""
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            variable_files = []
            for name, text in (
                ("defaults.yml", ConfigTexts.defaults),
                ("vars.yml", ConfigTexts.variables),
                ("common.yml", ConfigTexts.common),
                ("trust.yml", trust_text),
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
                    "vars": {"enrolled_host": tool.ENROLLED_HOST},
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
        self.assertEqual(self.role_writes(ConfigTexts.trust), render())

    def test_a_non_ascii_character_and_a_multi_line_key_are_written_byte_for_byte(self) -> None:
        trust = ConfigTexts.trust.replace(
            "mQINBGWmxXYBEACyN+4viFQM6QQoKr0A2W0rGdMobTJwOZso2QPpewbyBsuL3rNW",
            "mQINBGWmxXYBEACyN café — “quoted” 漢字 \U0001f512",
        )
        self.assertNotEqual(trust, ConfigTexts.trust)
        written = self.role_writes(trust)
        self.assertEqual(written, render(trust=trust))
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


class LayoutTest(unittest.TestCase):
    """The first boot's paths are the two roles' paths, not a second spelling that can drift.

    The first boot writes the two command-restricted root keys with the pull program's path and
    puts the program, the configuration and the Ansible environment where the roles keep them. If
    a role moved one, a host enrolled by an older document would name a program the pull no longer
    maintains. Each path is held equal to the role variable that owns it, as the package list is.
    """

    # A key of cloudInit.ts's PRODUCTION_LAYOUT, then the role file and variable it must equal.
    PARITY: Final = (
        ("wrapperPath", "ansible/roles/pull_trigger/vars/main.yml", "pull_trigger_program_path"),
        ("configDir", "ansible/roles/pull_trigger/vars/main.yml", "pull_trigger_config_dir"),
        ("configPath", "ansible/roles/pull_trigger/vars/main.yml", "pull_trigger_config_path"),
        ("stateDir", "ansible/roles/pull_trigger/vars/main.yml", "pull_trigger_state_dir"),
        ("logDir", "ansible/roles/pull_trigger/vars/main.yml", "pull_trigger_log_dir"),
        ("runtimeRoot", "ansible/roles/ansible_runtime/defaults/main.yml", "ansible_runtime_root"),
        ("runtimeLink", "ansible/roles/ansible_runtime/defaults/main.yml", "ansible_runtime_link"),
    )

    @staticmethod
    def production_layout(source: str) -> dict[str, str]:
        """Return the string values of PRODUCTION_LAYOUT in the TypeScript text.

        Raises:
            AssertionError: The object is not in the text.
        """
        match = re.search(
            r"export const PRODUCTION_LAYOUT: EnrolmentLayout = \{(.*?)\n\};", source, re.DOTALL
        )
        if match is None:
            message = "PRODUCTION_LAYOUT is not in cloudInit.ts"
            raise AssertionError(message)
        return dict(re.findall(r"^\s+(\w+): '([^']*)',$", match.group(1), re.MULTILINE))

    def test_each_path_is_the_one_the_role_that_owns_it_sets(self) -> None:
        layout = self.production_layout(CLOUD_INIT.read_text(encoding="utf-8"))
        for key, path, variable in self.PARITY:
            with self.subTest(key=key):
                document = YAML(typ="safe").load(read(path))
                self.assertEqual(document[variable], layout.get(key))

    def test_the_scan_finds_what_it_is_meant_to_find(self) -> None:
        # A control: an empty layout on one side and a missing variable on the other would be equal.
        layout = self.production_layout(CLOUD_INIT.read_text(encoding="utf-8"))
        for key, _, _ in self.PARITY:
            with self.subTest(key=key):
                self.assertTrue(layout.get(key, "").startswith("/"))


class FixedValuesTest(unittest.TestCase):
    """The record's fixed values live once, in a file both languages read, and are true."""

    @staticmethod
    def values() -> list[str]:
        return [tool.RAW_BASE, tool.REMOTE_URL, tool.PLAYBOOK_PATH, *tool.FETCHED.values()]

    def test_the_typescript_imports_the_file_and_holds_no_copy_of_a_value(self) -> None:
        source = CLOUD_INIT.read_text(encoding="utf-8")
        self.assertIn(f"from './{tool.FIXED_PATH.name}'", source)
        for value in self.values():
            with self.subTest(value=value):
                self.assertFalse(value in source, f"cloudInit.ts writes {value} a second time")

    def test_the_tool_holds_no_copy_of_a_value(self) -> None:
        source = (ROOT / "ansible" / "tools" / "pull_bootstrap.py").read_text(encoding="utf-8")
        for value in self.values():
            with self.subTest(value=value):
                self.assertFalse(value in source, f"pull_bootstrap.py writes {value} a second time")

    def test_the_scan_finds_what_it_is_meant_to_find(self) -> None:
        # A control: a scan that read the wrong file would find no copy in any case.
        self.assertIn(tool.PLAYBOOK_PATH, tool.FIXED_PATH.read_text(encoding="utf-8"))
        self.assertIn("pullBootstrapFixed.json", CLOUD_INIT.read_text(encoding="utf-8"))

    def test_the_ansible_path_filter_runs_the_tools_when_the_file_changes(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ansible.yml").read_text(encoding="utf-8")
        match = re.search(r"watched=\(\n(.*?)\n\s*\)", workflow, re.DOTALL)
        self.assertIsNotNone(match, "the watched=( ... ) array is not found")
        watched = [line.strip() for line in (match.group(1) if match else "").splitlines()]
        self.assertIn(f"hetzner-host/{tool.FIXED_PATH.name}", watched)
        self.assertIn("hetzner-host/cloudInit.ts", watched)

    def test_every_fetched_file_and_the_playbook_exist_in_the_repository(self) -> None:
        for path in (*tool.FETCHED.values(), tool.PLAYBOOK_PATH):
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file())

    def test_the_raw_address_and_the_remote_name_one_repository(self) -> None:
        from_raw = "/".join(tool.RAW_BASE.split("/")[-2:])
        from_remote = "/".join(tool.REMOTE_URL.removesuffix(".git").split("/")[-2:])
        self.assertEqual(from_raw, from_remote)

    def test_the_required_keys_are_keys_the_roles_task_writes(self) -> None:
        task = tool.config_task(YAML(typ="safe").load(ConfigTexts.tasks))
        declared = tool.mapping(
            tool.mapping(task.get("vars"), "vars").get(tool.CONFIG_VARIABLE), tool.CONFIG_VARIABLE
        )
        self.assertTrue(tool.REQUIRED_CONFIG_KEYS)
        self.assertLessEqual(tool.REQUIRED_CONFIG_KEYS, set(declared))

    def test_a_file_that_is_not_an_object_or_lacks_a_value_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixed.json"
            for text, pattern in (
                ("[1]", "is not a JSON object"),
                ("{not json", "cannot be read as JSON"),
            ):
                with self.subTest(text=text):
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaisesRegex(tool.BootstrapError, pattern):
                        tool.load_fixed(path)
            with self.assertRaisesRegex(tool.BootstrapError, "cannot be read as JSON"):
                tool.load_fixed(Path(directory) / "absent.json")
        for read_value, key, value in (
            (tool.fixed_text, "rawBase", 3),
            (tool.fixed_strings, "fetched", {"a": 1}),
            (tool.fixed_names, "requiredConfigKeys", ["a", 1]),
        ):
            with self.subTest(key=key):
                with self.assertRaisesRegex(tool.BootstrapError, key):
                    read_value({key: value}, key)
                with self.assertRaisesRegex(tool.BootstrapError, key):
                    read_value({}, key)


if __name__ == "__main__":
    unittest.main()
