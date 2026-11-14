#!/usr/bin/env python3
"""Tests for check_ghost_pin_lag: a pinned ghost-platform consumer that has fallen behind main is reported.

The rules, the registry and the alert route are in check_ghost_pin_lag.md. Every case here
uses a fake fetch, so nothing reaches the network.
"""

from __future__ import annotations

import io
import json
import pathlib
import re
import tempfile
import unittest

import check_ghost_pin_lag as check
import yaml

SCRIPTS = pathlib.Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
REGISTRY = SCRIPTS / "ghost_pin_consumers.json"
WORKFLOW = ROOT / ".github" / "workflows" / "ghost-pin-lag.yml"
ROLES = ROOT / "ansible" / "roles"
SOURCE_URL = "raw.githubusercontent.com/branchLeft/ghost-platform"

OLD_PIN = "a" * 40
MAIN = "main"


def fake_fetch(contents: dict[tuple[str, str], bytes]) -> check.Fetch:
    """A fetch that serves only what the table holds, and None for any other file."""

    def fetch(ref: str, path: str) -> bytes | None:
        return contents.get((ref, path))

    return fetch


def write_fixture(base: pathlib.Path, *, pin: str = OLD_PIN) -> pathlib.Path:
    """One consumer with a list source, a keys source and a literal path; return the registry path."""
    (base / "vars.yml").write_text(
        yaml.safe_dump(
            {
                "demo_commit": pin,
                "demo_files": ["one.py", "two.py"],
                "demo_digests": {"three.py": "0" * 64},
                "demo_entries": [{"path": "four.mjs", "mode": "0644"}],
            }
        )
    )
    registry = base / "registry.json"
    registry.write_text(
        json.dumps(
            {
                "repository": "branchLeft/ghost-platform",
                "consumers": [
                    {
                        "name": "demo",
                        "host": "db1",
                        "commit": {"file": "vars.yml", "key": "demo_commit"},
                        "sources": [
                            {
                                "file": "vars.yml",
                                "key": "demo_files",
                                "shape": "strings",
                                "prefix": "db/",
                            },
                            {
                                "file": "vars.yml",
                                "key": "demo_digests",
                                "shape": "keys",
                                "prefix": "db/",
                            },
                            {
                                "file": "vars.yml",
                                "key": "demo_entries",
                                "shape": "path_field",
                                "prefix": "js/",
                            },
                            {"path": "registers/names.json"},
                        ],
                    }
                ],
            }
        )
    )
    return registry


PATHS = ["db/one.py", "db/two.py", "db/three.py", "js/four.mjs", "registers/names.json"]


def same_everywhere() -> dict[tuple[str, str], bytes]:
    table: dict[tuple[str, str], bytes] = {}
    for path in PATHS:
        table[(OLD_PIN, path)] = path.encode()
        table[(MAIN, path)] = path.encode()
    return table


class LoadingTheRegistry(unittest.TestCase):
    def test_every_source_shape_resolves_to_a_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            consumers = check.load_consumers(base, write_fixture(base))
        self.assertEqual(len(consumers), 1)
        self.assertEqual(consumers[0].pin, OLD_PIN)
        self.assertEqual(sorted(consumers[0].paths), sorted(PATHS))

    def test_a_pin_that_is_not_a_full_commit_is_refused(self) -> None:
        for bad in ("abc1234", "main", "A" * 40, "a" * 41, ""):
            with self.subTest(pin=bad), tempfile.TemporaryDirectory() as tmp:
                base = pathlib.Path(tmp)
                with self.assertRaises(check.CheckError):
                    check.load_consumers(base, write_fixture(base, pin=bad))

    def test_a_key_the_file_does_not_hold_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            registry = write_fixture(base)
            data = json.loads(registry.read_text())
            data["consumers"][0]["sources"][0]["key"] = "no_such_key"
            registry.write_text(json.dumps(data))
            with self.assertRaises(check.CheckError):
                check.load_consumers(base, registry)

    def test_an_unknown_shape_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            registry = write_fixture(base)
            data = json.loads(registry.read_text())
            data["consumers"][0]["sources"][0]["shape"] = "mystery"
            registry.write_text(json.dumps(data))
            with self.assertRaises(check.CheckError):
                check.load_consumers(base, registry)

    def test_a_consumer_with_no_path_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            registry = write_fixture(base)
            data = json.loads(registry.read_text())
            data["consumers"][0]["sources"] = []
            registry.write_text(json.dumps(data))
            with self.assertRaises(check.CheckError):
                check.load_consumers(base, registry)


class FindingLag(unittest.TestCase):
    def consumers(self) -> list[check.Consumer]:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            return check.load_consumers(base, write_fixture(base))

    def test_files_that_match_main_are_not_lag(self) -> None:
        self.assertEqual(
            check.find_lag(self.consumers(), fake_fetch(same_everywhere()), MAIN), []
        )

    def test_a_file_changed_on_main_is_reported_by_name(self) -> None:
        table = same_everywhere()
        table[(MAIN, "db/two.py")] = b"a later fix"
        lags = check.find_lag(self.consumers(), fake_fetch(table), MAIN)
        self.assertEqual(
            [(lag.consumer, lag.path, lag.kind) for lag in lags],
            [("demo", "db/two.py", "changed")],
        )

    def test_a_file_gone_from_main_is_reported(self) -> None:
        table = same_everywhere()
        del table[(MAIN, "js/four.mjs")]
        lags = check.find_lag(self.consumers(), fake_fetch(table), MAIN)
        self.assertEqual(
            [(lag.path, lag.kind) for lag in lags], [("js/four.mjs", "removed")]
        )

    def test_a_file_the_pin_never_had_stops_the_check(self) -> None:
        table = same_everywhere()
        del table[(OLD_PIN, "db/one.py")]
        with self.assertRaises(check.CheckError):
            check.find_lag(self.consumers(), fake_fetch(table), MAIN)

    def test_a_changed_then_restored_file_is_not_lag(self) -> None:
        table = same_everywhere()
        table[(MAIN, "db/one.py")] = table[(OLD_PIN, "db/one.py")]
        self.assertEqual(check.find_lag(self.consumers(), fake_fetch(table), MAIN), [])


class RunningTheCheck(unittest.TestCase):
    def run_check(
        self,
        table: dict[tuple[str, str], bytes],
        *,
        summary: pathlib.Path | None = None,
    ) -> tuple[int, str]:
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            registry = write_fixture(base)
            status = check.run(base, registry, fake_fetch(table), MAIN, summary, out)
        return status, out.getvalue()

    def test_current_pins_exit_zero(self) -> None:
        status, text = self.run_check(same_everywhere())
        self.assertEqual(status, check.EXIT_CURRENT)
        self.assertIn("current", text)

    def test_lag_exits_one_and_names_the_consumer_host_pin_and_file(self) -> None:
        table = same_everywhere()
        table[(MAIN, "db/three.py")] = b"newer"
        status, text = self.run_check(table)
        self.assertEqual(status, check.EXIT_LAG)
        for needle in ("demo", "db1", OLD_PIN[:12], "db/three.py", "changed"):
            self.assertIn(needle, text)

    def test_a_check_that_cannot_read_exits_two(self) -> None:
        table = same_everywhere()
        del table[(OLD_PIN, "db/one.py")]
        status, text = self.run_check(table)
        self.assertEqual(status, check.EXIT_ERROR)
        self.assertIn("db/one.py", text)

    def test_the_summary_file_gets_the_same_finding(self) -> None:
        table = same_everywhere()
        table[(MAIN, "db/three.py")] = b"newer"
        with tempfile.TemporaryDirectory() as tmp:
            summary = pathlib.Path(tmp) / "summary.md"
            status, _ = self.run_check(table, summary=summary)
            self.assertEqual(status, check.EXIT_LAG)
            self.assertIn("db/three.py", summary.read_text())


class FetchingFromGitHub(unittest.TestCase):
    def test_the_url_names_the_repository_the_ref_and_the_path(self) -> None:
        url = check.raw_url("branchLeft/ghost-platform", OLD_PIN, "db/provision/a b.py")
        self.assertEqual(
            url,
            f"https://raw.githubusercontent.com/branchLeft/ghost-platform/{OLD_PIN}/db/provision/a%20b.py",
        )


class TheRegistryCoversEveryPinnedRole(unittest.TestCase):
    """A role that fetches from ghost-platform at a pin must be listed, or its lag goes unseen."""

    def pinned_roles(self) -> set[str]:
        found: set[str] = set()
        for role in sorted(ROLES.iterdir()):
            for name in ("defaults", "vars"):
                path = role / name / "main.yml"
                if path.is_file() and SOURCE_URL in path.read_text():
                    found.add(role.name)
        return found

    def test_the_listed_roles_are_exactly_the_roles_that_pin_ghost_platform(
        self,
    ) -> None:
        listed = {c.name for c in check.load_consumers(ROOT, REGISTRY)}
        self.assertEqual(listed, self.pinned_roles())

    def test_every_listed_role_resolves_a_commit_and_at_least_one_path(self) -> None:
        for consumer in check.load_consumers(ROOT, REGISTRY):
            with self.subTest(consumer=consumer.name):
                self.assertRegex(consumer.pin, r"\A[0-9a-f]{40}\Z")
                self.assertTrue(consumer.paths)

    def test_db1_backup_programs_units_and_recovery_files_are_watched(self) -> None:
        by_name = {c.name: c for c in check.load_consumers(ROOT, REGISTRY)}
        paths = set(by_name["db1_backup_timers"].paths)
        for expected in (
            "db/provision/dump_nightly.py",
            "db/provision/ship_binlogs.py",
            "db/recovery/restore_drained.py",
            "db/provision/branchleft-db-dump.service",
        ):
            self.assertIn(expected, paths)

    def test_the_registry_names_no_work_item(self) -> None:
        self.assertIsNone(re.search(r"#\d{2,}", REGISTRY.read_text()))


class TheWorkflowIsTheAlert(unittest.TestCase):
    def workflow(self) -> dict:
        loaded = yaml.safe_load(WORKFLOW.read_text())
        # PyYAML reads the bare key `on` as the boolean True.
        loaded["triggers"] = loaded.pop(True, loaded.get("on"))
        return loaded

    def test_it_runs_on_a_schedule_and_by_hand_and_never_on_a_pull_request(
        self,
    ) -> None:
        triggers = self.workflow()["triggers"]
        self.assertIn("schedule", triggers)
        self.assertIn("workflow_dispatch", triggers)
        for forbidden in ("pull_request", "pull_request_target", "push", "merge_group"):
            self.assertNotIn(forbidden, triggers)

    def test_it_can_only_read_the_repository(self) -> None:
        workflow = self.workflow()
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        for job in workflow["jobs"].values():
            self.assertNotIn("permissions", job)

    def test_it_runs_the_check_with_the_summary_and_lets_every_nonzero_status_fail_the_job(
        self,
    ) -> None:
        steps = [s for job in self.workflow()["jobs"].values() for s in job["steps"]]
        runs = [
            s["run"]
            for s in steps
            if "run" in s and "check_ghost_pin_lag.py" in s["run"]
        ]
        self.assertEqual(len(runs), 1)
        self.assertIn("$GITHUB_STEP_SUMMARY", runs[0])
        self.assertNotIn("|| true", runs[0])
        self.assertNotIn("continue-on-error", WORKFLOW.read_text())

    def test_every_action_is_pinned_to_a_full_commit(self) -> None:
        for line in WORKFLOW.read_text().splitlines():
            if "uses:" in line:
                self.assertRegex(line, r"uses: [\w./-]+@[0-9a-f]{40}\b")


if __name__ == "__main__":
    unittest.main()
