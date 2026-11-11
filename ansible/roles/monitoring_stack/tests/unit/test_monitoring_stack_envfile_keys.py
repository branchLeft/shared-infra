"""Unit tests for the pager state check and the stale-line removal of monitoring_stack.

Covers monitoring_stack_envfile_keys (which keys a file holds a value for, names only, never a
line), the expression that picks the stale lines out of monitoring.env, and the flags the
removal and gauge tasks must carry. Run from the role's directory with library/ on PYTHONPATH,
the way ``ansible/checks/run_role_unit_tests.sh`` does. Every secret here is a throwaway.
"""

import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from typing import cast

import monitoring_stack_envfile_keys as keys_module
import yaml  # type: ignore[import-untyped]
from ansible.module_utils.testing import patch_module_args

ROLE = Path(__file__).resolve().parents[2]
MARKER = "THROWAWAY_KEYS_MARKER_0001"
KEYS = [
    "NTFY_PAGER_TOKEN",
    "NTFY_WATCHER_TOKEN",
    "NTFY_OWNER_PASSWORD_HASH",
    "NTFY_MACHINE_PASSWORD_HASH",
]


def full_file() -> str:
    return "".join(f"{key}={MARKER}-{index}\n" for index, key in enumerate(KEYS))


def run_main(
    path: str, keys: list[str], check_mode: bool = False
) -> tuple[bool, dict[str, object], str]:
    """Run main as Ansible would; return (failed, the JSON it printed, the raw text)."""
    args = {"path": path, "keys": keys, "_ansible_check_mode": check_mode}
    buffer = io.StringIO()
    with patch_module_args(args), contextlib.redirect_stdout(buffer):
        try:
            keys_module.main()
        except SystemExit:
            pass
    raw = buffer.getvalue()
    document = json.loads(raw)
    return bool(document.get("failed")), document, raw


class Workdir(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.write_text(text)
        return path


class MissingKeysTest(Workdir):
    def test_a_file_with_every_key_and_a_value_misses_none(self) -> None:
        path = self.write("pager.env", full_file())
        self.assertEqual([], keys_module.missing_keys(str(path), KEYS))

    def test_a_missing_file_misses_every_key(self) -> None:
        self.assertEqual(KEYS, keys_module.missing_keys(str(self.root / "absent.env"), KEYS))

    def test_an_empty_file_misses_every_key(self) -> None:
        path = self.write("empty.env", "")
        self.assertEqual(KEYS, keys_module.missing_keys(str(path), KEYS))

    def test_a_key_that_is_absent_is_named_and_the_others_are_not(self) -> None:
        lines = full_file().splitlines(keepends=True)
        path = self.write("pager.env", "".join(line for line in lines if "WATCHER" not in line))
        self.assertEqual(["NTFY_WATCHER_TOKEN"], keys_module.missing_keys(str(path), KEYS))

    def test_a_key_with_nothing_after_the_equals_sign_is_missing(self) -> None:
        for blank in ("", " ", "\t", "  \t "):
            with self.subTest(blank=blank):
                old = f"NTFY_PAGER_TOKEN={MARKER}-0"
                path = self.write(
                    "pager.env", full_file().replace(old, f"NTFY_PAGER_TOKEN={blank}")
                )
                self.assertEqual(["NTFY_PAGER_TOKEN"], keys_module.missing_keys(str(path), KEYS))

    def test_a_key_on_the_last_line_with_no_line_break_counts(self) -> None:
        path = self.write("pager.env", full_file().rstrip("\n"))
        self.assertEqual([], keys_module.missing_keys(str(path), KEYS))

    def test_only_a_line_that_starts_with_the_key_and_an_equals_sign_counts(self) -> None:
        near = [
            f"  NTFY_PAGER_TOKEN={MARKER}\n",
            f"XNTFY_PAGER_TOKEN={MARKER}\n",
            f"ntfy_pager_token={MARKER}\n",
            f"NTFY_PAGER_TOKEN_OLD={MARKER}\n",
            f"# NTFY_PAGER_TOKEN={MARKER}\n",
            "NTFY_PAGER_TOKEN\n",
        ]
        path = self.write("pager.env", "".join(near))
        result = keys_module.missing_keys(str(path), ["NTFY_PAGER_TOKEN"])
        self.assertEqual(["NTFY_PAGER_TOKEN"], result)

    def test_the_names_come_back_in_the_order_given(self) -> None:
        path = self.write("empty.env", "")
        reversed_keys = list(reversed(KEYS))
        self.assertEqual(reversed_keys, keys_module.missing_keys(str(path), reversed_keys))

    def test_bytes_that_are_not_text_are_read_without_decoding(self) -> None:
        path = self.root / "bytes.env"
        path.write_bytes(b"NTFY_PAGER_TOKEN=\xff\xfe\n")
        self.assertEqual([], keys_module.missing_keys(str(path), ["NTFY_PAGER_TOKEN"]))

    def test_a_key_that_is_not_a_plain_name_is_refused(self) -> None:
        path = self.write("pager.env", full_file())
        bad = ("", "ntfy_pager_token", "1NTFY", "NTFY TOKEN", "NTFY=", "NTFY\n", "NTFY-TOKEN")
        for key in bad:
            with self.subTest(key=key), self.assertRaises(keys_module.KeysError):
                keys_module.missing_keys(str(path), [key])

    def test_a_directory_is_refused(self) -> None:
        with self.assertRaises(keys_module.KeysError):
            keys_module.missing_keys(str(self.root), KEYS)


class ModuleTest(Workdir):
    def test_the_module_reports_configured_and_no_change(self) -> None:
        path = self.write("pager.env", full_file())
        failed, document, _raw = run_main(str(path), KEYS)
        self.assertFalse(failed)
        self.assertFalse(document["changed"])
        self.assertIs(True, document["configured"])
        self.assertEqual([], document["missing"])

    def test_the_module_reports_a_disabled_pager_for_a_missing_file(self) -> None:
        failed, document, _raw = run_main(str(self.root / "absent.env"), KEYS)
        self.assertFalse(failed)
        self.assertIs(False, document["configured"])
        self.assertEqual(KEYS, document["missing"])

    def test_the_output_holds_no_value_and_no_line(self) -> None:
        path = self.write("pager.env", full_file().replace("NTFY_OWNER_PASSWORD_HASH=", "#"))
        _failed, document, raw = run_main(str(path), KEYS)
        self.assertNotIn(MARKER, raw)
        self.assertEqual({"changed", "configured", "missing"}, set(document) - {"invocation"})

    def test_check_mode_gives_the_same_answer_and_leaves_the_file_as_it_was(self) -> None:
        text = full_file()
        path = self.write("pager.env", text)
        mode = path.stat().st_mode
        _f, apply_run, _r = run_main(str(path), KEYS)
        _f, check_run, _r = run_main(str(path), KEYS, check_mode=True)
        self.assertEqual(apply_run["configured"], check_run["configured"])
        self.assertEqual(apply_run["missing"], check_run["missing"])
        self.assertEqual(text, path.read_text())
        self.assertEqual(mode, path.stat().st_mode)

    def test_a_refusal_holds_no_line_of_the_file(self) -> None:
        path = self.write("secret.env", f"NTFY_PAGER_TOKEN={MARKER}\n")
        path.chmod(0o000)
        self.addCleanup(path.chmod, 0o600)
        if os.geteuid() == 0:
            self.skipTest("root reads a file whatever its mode, so the refusal cannot be shown")
        failed, _document, raw = run_main(str(path), KEYS)
        self.assertTrue(failed)
        self.assertNotIn(MARKER, raw)

    def test_a_bad_key_fails_with_the_named_message(self) -> None:
        path = self.write("pager.env", full_file())
        failed, document, _raw = run_main(str(path), ["ntfy"])
        self.assertTrue(failed)
        self.assertIn("each key must be", str(document["msg"]))


def load_mapping(path: Path) -> dict[str, object]:
    return cast("dict[str, object]", yaml.safe_load(path.read_text()))


def var_text(name: str) -> str:
    return str(load_mapping(ROLE / "vars" / "main.yml")[name])


def var_list(name: str) -> list[str]:
    return cast("list[str]", load_mapping(ROLE / "vars" / "main.yml")[name])


def task_named(fragment: str) -> dict[str, object]:
    tasks = cast(
        "list[dict[str, object]]", yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    )
    found = [task for task in tasks if fragment in str(task.get("name", ""))]
    if len(found) != 1:
        message = f"expected one task named like {fragment!r}, found {len(found)}"
        raise AssertionError(message)
    return found[0]


def task_body(task: dict[str, object], module: str) -> dict[str, object]:
    return cast("dict[str, object]", task[module])


class StaleLineFilterTest(unittest.TestCase):
    """The lines the removal drops, by the same expression lineinfile applies to each line."""

    def keeps(self, line: str) -> bool:
        pattern = re.compile(var_text("monitoring_stack_stale_key_regexp"), re.MULTILINE)
        return pattern.search(line) is None

    def test_every_pager_key_is_dropped(self) -> None:
        for key in var_list("monitoring_stack_ntfy_env_keys"):
            with self.subTest(key=key):
                self.assertFalse(self.keeps(f"{key}={MARKER}"))

    def test_a_stale_line_with_an_empty_value_is_dropped_too(self) -> None:
        self.assertFalse(self.keeps("NTFY_PAGER_TOKEN="))

    def test_the_seven_keys_the_role_writes_are_kept(self) -> None:
        items = cast("list[dict[str, str]]", var_list("monitoring_stack_env_keys"))
        self.assertEqual(7, len(items))
        for item in items:
            with self.subTest(key=item["key"]):
                self.assertTrue(self.keeps(f"{item['key']}={MARKER}"))

    def test_a_key_that_only_contains_the_prefix_is_kept(self) -> None:
        lines = (
            f"X_NTFY_PAGER_TOKEN={MARKER}",
            f" NTFY_PAGER_TOKEN={MARKER}",
            "# NTFY_PAGER_TOKEN=x",
        )
        for line in lines:
            with self.subTest(line=line):
                self.assertTrue(self.keeps(line))

    def test_a_value_that_mentions_the_prefix_is_kept(self) -> None:
        self.assertTrue(self.keeps("SMTP_USERNAME=NTFY_PAGER_TOKEN=x"))


class TaskFlagsTest(unittest.TestCase):
    """The removal handles secrets, so its flags are a control and are pinned here."""

    def test_the_removal_is_a_lineinfile_that_removes_and_hides_everything(self) -> None:
        task = task_named("Remove the stale NTFY_ lines")
        body = task_body(task, "ansible.builtin.lineinfile")
        self.assertEqual("absent", body["state"])
        self.assertEqual("{{ monitoring_stack_stale_key_regexp }}", body["regexp"])
        self.assertEqual("{{ monitoring_stack_env_file }}", body["path"])
        self.assertIs(True, task["no_log"])
        self.assertIs(False, task["diff"])
        self.assertNotIn("backup", body)

    def test_the_removal_waits_for_the_pager_file_to_hold_all_four_keys(self) -> None:
        conditions = cast("list[str]", task_named("Remove the stale NTFY_ lines")["when"])
        self.assertIn("monitoring_stack_pager_state.configured | bool", conditions)

    def test_the_pager_state_read_hides_and_changes_nothing(self) -> None:
        task = task_named("Check which pager keys")
        self.assertIs(True, task["no_log"])
        self.assertIs(False, task["diff"])
        self.assertIs(False, task["changed_when"])
        self.assertIs(False, task["check_mode"])

    def test_the_gauge_holds_no_value_and_is_world_readable_for_the_exporter(self) -> None:
        body = task_body(task_named("Write the pager gauge"), "ansible.builtin.copy")
        self.assertEqual("0644", body["mode"])
        self.assertEqual("{{ monitoring_stack_pager_gauge_file }}", body["dest"])
        content = str(body["content"])
        self.assertNotIn("monitoring_stack_ntfy_env_file", content)
        self.assertIn("monitoring_stack_pager_state.configured", content)

    def test_the_gauge_name_is_the_one_the_alert_queries(self) -> None:
        render = (ROLE.parents[2] / "hetzner" / "monitoring" / "render.ts").read_text()
        self.assertIn(f"expr: {var_text('monitoring_stack_pager_gauge')} == 0", render)

    def test_the_gauge_sits_in_the_directory_the_stack_mounts_for_the_exporter(self) -> None:
        compose = (ROLE / "files" / "stack" / "compose.yml").read_text()
        directory = var_text("monitoring_stack_textfile_dir")
        gauge_file = var_text("monitoring_stack_pager_gauge_file")
        self.assertIn(f"- {directory}:/etc/prometheus/textfile_collector:ro", compose)
        self.assertEqual(directory, str(Path(gauge_file).parent))
        self.assertTrue(gauge_file.endswith(".prom"))

    def test_the_pager_keys_match_the_ones_ntfy_pager_writes(self) -> None:
        theirs = load_mapping(ROLE.parent / "ntfy_pager" / "vars" / "main.yml")
        names = sorted(cast("dict[str, str]", theirs["ntfy_pager_env_names"]).values())
        self.assertEqual(names, sorted(var_list("monitoring_stack_ntfy_env_keys")))


if __name__ == "__main__":
    unittest.main()
