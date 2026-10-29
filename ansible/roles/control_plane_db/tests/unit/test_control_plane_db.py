"""Unit tests for the control_plane_db role's guards, read from the role's own files.

The container test proves what the steps do. These tests pin the structure that test
cannot see go missing: the closed list of step ids it shares with the gated pull, the
tags that keep a step off a plain apply, the removal of the administrator URL file on
every exit, the no_log on every task that runs a program with a mounted secret, and
the shape of every argument a container is started with. Each fails when the text it
reads changes, so a sabotaged copy of the role goes red here as well.
"""

import re
import unittest
from pathlib import Path
from typing import cast

from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
PULL_TRIGGER = ROLE.parent / "pull_trigger" / "files" / "pull_trigger.py"
STEPS = ("migrate", "identity", "provision")
Task = dict[str, object]


def _load(path: Path) -> object:
    """Return the parsed YAML of a role file."""
    return cast(object, YAML(typ="safe").load(path.read_text(encoding="utf-8")))


def _tasks(path: Path) -> list[Task]:
    """Return every task of a tasks file, with the tasks of its blocks, in file order."""
    found: list[Task] = []

    def walk(items: object) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            found.append(item)
            for key in ("block", "rescue", "always"):
                walk(item.get(key))

    walk(_load(path))
    return found


def _names(path: Path) -> list[str]:
    """Return the name of every task of a tasks file, in file order."""
    return [str(task.get("name")) for task in _tasks(path)]


def _vars() -> dict[str, object]:
    """Return the role's constants."""
    return cast(dict[str, object], _load(ROLE / "vars" / "main.yml"))


def _text(name: str) -> str:
    """Return the text of a tasks file."""
    return (ROLE / "tasks" / name).read_text(encoding="utf-8")


def _module(task: Task) -> str:
    """Return the short module name a task uses, or an empty string."""
    for key in task:
        if str(key).startswith("ansible.builtin."):
            return str(key).rsplit(".", 1)[-1]
    return ""


class StepListTests(unittest.TestCase):
    def test_the_role_and_the_gated_pull_hold_the_same_closed_list_of_steps(self) -> None:
        program = PULL_TRIGGER.read_text(encoding="utf-8")
        match = re.search(r"STEP_IDS: Final = frozenset\(\{([^}]*)\}\)", program)
        if match is None:
            self.fail("the program no longer names its step ids in one line")
        in_program = set(re.findall(r'"([a-z_]+)"', match.group(1)))
        self.assertEqual(in_program, set(STEPS), "the program's step ids and the role's differ")
        self.assertEqual(set(cast(list[str], _vars()["control_plane_db_step_ids"])), set(STEPS))

    def test_the_program_sets_the_tag_prefix_and_variable_this_role_reads(self) -> None:
        program = PULL_TRIGGER.read_text(encoding="utf-8")
        self.assertIn('STEP_TAG_PREFIX: Final = "control_plane_db_"', program)
        self.assertIn('STEP_VARIABLE: Final = "control_plane_db_step"', program)

    def test_the_argument_spec_offers_the_empty_value_and_exactly_those_steps(self) -> None:
        spec = cast(
            dict[str, dict[str, dict[str, dict[str, dict[str, object]]]]],
            _load(ROLE / "meta" / "argument_specs.yml"),
        )
        choices = cast(
            list[str], spec["argument_specs"]["main"]["options"]["control_plane_db_step"]["choices"]
        )
        self.assertEqual(sorted(choices), sorted(["", *STEPS]))


class TagTests(unittest.TestCase):
    def test_each_step_is_imported_with_the_never_tag_and_its_own_tag_and_no_other(self) -> None:
        imports = {
            str(task["name"]): task
            for task in _tasks(ROLE / "tasks" / "main.yml")
            if _module(task) == "import_tasks"
        }
        self.assertEqual(len(imports), len(STEPS))
        for step in STEPS:
            task = imports[f"Guarded step {step}"]
            self.assertEqual(task["tags"], ["never", f"control_plane_db_{step}"], step)
            self.assertEqual(task["ansible.builtin.import_tasks"], f"_{step}.yml")

    def test_no_task_of_the_role_carries_the_always_tag(self) -> None:
        for path in sorted((ROLE / "tasks").glob("*.yml")):
            for task in _tasks(path):
                tags = task.get("tags", [])
                self.assertNotIn("always", tags if isinstance(tags, list) else [tags], path.name)

    def test_a_plain_apply_reaches_no_task_that_runs_a_program(self) -> None:
        main = _tasks(ROLE / "tasks" / "main.yml")
        for task in main:
            if _module(task) != "import_tasks":
                self.assertNotIn(_module(task), {"command", "shell", "raw", "script"}, task["name"])
                self.assertNotIn("docker", str(task), task["name"])


class GuardTests(unittest.TestCase):
    def test_the_guard_compares_the_step_variable_with_the_step_and_checks_its_shape(self) -> None:
        text = _text("_guard.yml")
        self.assertIn("control_plane_db_step == control_plane_db_this_step", text)
        self.assertIn("control_plane_db_step is match(control_plane_db_step_pattern)", text)
        self.assertIn("REFUSED:", text)

    def test_the_guard_comes_before_anything_a_step_does(self) -> None:
        for step in STEPS:
            names = _names(ROLE / "tasks" / f"_{step}.yml")
            self.assertEqual(names[0], "Name the step and its marker", step)
            self.assertEqual(
                names[1], f"Check the request, the image and the marker of {step}", step
            )

    def test_each_step_names_itself_with_its_own_id(self) -> None:
        for step in STEPS:
            sets = [t for t in _tasks(ROLE / "tasks" / f"_{step}.yml") if _module(t) == "set_fact"]
            facts = cast(dict[str, str], sets[0]["ansible.builtin.set_fact"])
            self.assertEqual(facts["control_plane_db_this_step"], step)

    def test_a_step_is_skipped_when_its_marker_exists(self) -> None:
        for step in STEPS:
            text = _text(f"_{step}.yml")
            self.assertIn("when: not control_plane_db_marker_stat.stat.exists", text, step)

    def test_the_marker_is_written_only_after_the_effect_and_every_check_of_its_output(
        self,
    ) -> None:
        before = {
            "migrate": ["Apply the pending migrations", "Refuse a migrate that did not end clean"],
            "identity": [
                "Run the identity reconciler",
                "Refuse a reconciler run that failed or reported drift",
                "Install the identifiers the stack reads",
            ],
            "provision": [
                "Create the portal database, its roles and logins",
                "Refuse a provision that did not end clean",
                "Write the tenant portal's connection URL file",
                "Write the operator console's connection URL file",
            ],
        }
        for step, effects in before.items():
            names = _names(ROLE / "tasks" / f"_{step}.yml")
            marker = [n for n in names if n.startswith("Record that")]
            self.assertEqual(len(marker), 1, step)
            at = names.index(marker[0])
            for effect in effects:
                self.assertIn(effect, names, step)
                self.assertLess(names.index(effect), at, f"{step}: {effect} comes after the marker")
            for name in names[at + 1 :]:
                self.assertTrue(
                    name.startswith(("Remove", "Read whether")),
                    f"{step}: {name} follows the marker",
                )

    def test_the_marker_file_is_root_owned_and_holds_only_its_own_name(self) -> None:
        text = _text("_marker.yml")
        self.assertIn('content: "{{ control_plane_db_marker }}\\n"', text)
        self.assertIn("owner: root", text)
        self.assertIn("group: root", text)
        self.assertIn("mode: '0644'", text)


class CleanupTests(unittest.TestCase):
    def test_the_administrator_url_file_is_removed_in_an_always_section(self) -> None:
        for step in ("migrate", "provision"):
            blocks = [t for t in _tasks(ROLE / "tasks" / f"_{step}.yml") if "always" in t]
            self.assertEqual(len(blocks), 1, step)
            removals = cast(list[Task], blocks[0]["always"])
            first = removals[0]
            self.assertEqual(
                first["ansible.builtin.file"],
                {"path": "{{ control_plane_db_admin_url_file }}", "state": "absent"},
            )

    def test_the_passwords_are_removed_only_once_provision_is_recorded(self) -> None:
        always = next(t for t in _tasks(ROLE / "tasks" / "_provision.yml") if "always" in t)
        removal = cast(list[Task], always["always"])[-1]
        self.assertEqual(removal["when"], "control_plane_db_marker_after.stat.exists")
        self.assertEqual(len(cast(list[str], removal["loop"])), 3)

    def test_the_working_directory_is_removed_only_when_this_run_made_it(self) -> None:
        always = next(t for t in _tasks(ROLE / "tasks" / "_identity.yml") if "always" in t)
        removal = cast(list[Task], always["always"])[0]
        self.assertEqual(removal["when"], "control_plane_db_work_owned | default(false)")


class SecretHandlingTests(unittest.TestCase):
    def test_a_task_that_runs_a_program_with_a_mounted_secret_has_no_log_and_reads_its_own_exit(
        self,
    ) -> None:
        seen = 0
        for step in STEPS:
            for task in _tasks(ROLE / "tasks" / f"_{step}.yml"):
                text = str(task)
                if _module(task) == "command" and (
                    "provisionMain.js" in text or "dist/cli.js" in text
                ):
                    seen += 1
                    self.assertIs(task.get("no_log"), True, task["name"])
                    self.assertIs(task.get("failed_when"), False, task["name"])
        self.assertEqual(seen, 3)

    def test_every_task_that_reads_or_builds_a_password_has_no_log(self) -> None:
        seen = 0
        for task in _tasks(ROLE / "tasks" / "_provision.yml"):
            text = str(task)
            handles = _module(task) in {"slurp", "set_fact", "copy"} and (
                "password" in text.lower() or "_url" in text.lower() or "url_reads" in text
            )
            if handles and "marker" not in str(task.get("name")).lower():
                seen += 1
                self.assertIs(task.get("no_log"), True, task["name"])
        self.assertGreaterEqual(seen, 7)

    def test_the_url_file_writes_also_turn_the_diff_off(self) -> None:
        writes = [
            t
            for t in _tasks(ROLE / "tasks" / "_provision.yml")
            if "connection URL file" in str(t["name"]) and _module(t) == "copy"
        ]
        self.assertEqual(len(writes), 2)
        for task in writes:
            self.assertIs(task.get("diff"), False, task["name"])

    def test_no_environment_argument_carries_a_secret_by_value(self) -> None:
        allowed = {"NODE_OPTIONS", "ZITADEL_URL"}
        seen = 0
        for step in STEPS:
            for name in re.findall(r"'-e', '(\w+)=", _text(f"_{step}.yml")):
                seen += 1
                self.assertTrue(name.endswith("_FILE") or name in allowed, f"{step}: -e {name}")
        self.assertGreaterEqual(seen, 8)

    def test_a_mounted_secret_file_is_read_only(self) -> None:
        for step in STEPS:
            for mount in re.findall(r"'-v', (.*)", _text(f"_{step}.yml")):
                self.assertTrue(
                    mount.rstrip(",").rstrip().endswith(("':ro',", "':ro'"))
                    or ":ro'" in mount
                    or "/work'" in mount,
                    f"{step}: {mount}",
                )


class PrivilegeTests(unittest.TestCase):
    def test_every_container_runs_as_the_image_user_with_no_capability_and_no_new_privileges(
        self,
    ) -> None:
        limits = cast(list[str], _vars()["control_plane_db_container_limits"])
        self.assertEqual(limits[limits.index("--cap-drop") + 1], "ALL")
        self.assertIn("no-new-privileges:true", limits)
        self.assertEqual(limits[limits.index("--user") + 1], "{{ control_plane_db_image_user }}")
        self.assertEqual(_vars()["control_plane_db_image_user"], "1000:1000")
        for name in ("_migrate.yml", "_provision.yml", "_identity.yml", "_image.yml"):
            self.assertIn("+ control_plane_db_container_limits", _text(name), name)

    def test_no_task_asks_a_container_for_more_privilege(self) -> None:
        for path in sorted((ROLE / "tasks").glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            for flag in (
                "--privileged",
                "--cap-add",
                "--pid",
                "--ipc",
                "--device",
                "--userns",
                "docker.sock",
            ):
                self.assertNotIn(flag, text, f"{path.name} uses {flag}")

    def test_the_input_files_are_group_readable_for_the_image_and_closed_to_everyone_else(
        self,
    ) -> None:
        constants = _vars()
        self.assertEqual(constants["control_plane_db_input_owner"], "root")
        self.assertEqual(constants["control_plane_db_input_gid"], 1000)
        self.assertEqual(constants["control_plane_db_input_mode"], "0640")
        self.assertEqual(constants["control_plane_db_input_dir_mode"], "0750")
        self.assertEqual(int(str(constants["control_plane_db_input_mode"]), 8) & 0o037, 0)
        self.assertEqual(int(str(constants["control_plane_db_input_dir_mode"]), 8) & 0o027, 0)

    def test_the_input_check_compares_owner_group_mode_kind_and_size(self) -> None:
        text = _text("_inputs.yml")
        for needle in (
            "item.stat.isreg",
            "(item.stat.pw_name | default('')) == control_plane_db_input_owner",
            "item.stat.gid == control_plane_db_input_gid",
            "item.stat.mode == control_plane_db_input_mode",
            "item.stat.size > 0",
        ):
            self.assertIn(needle, text)

    def test_a_plain_apply_sets_the_input_directory_from_the_same_constants(self) -> None:
        directory = next(
            t
            for t in _tasks(ROLE / "tasks" / "main.yml")
            if "step inputs in" in str(t["name"]) and _module(t) == "file"
        )
        self.assertEqual(
            directory["ansible.builtin.file"],
            {
                "path": "{{ control_plane_db_input_dir }}",
                "state": "directory",
                "owner": "{{ control_plane_db_input_owner }}",
                "group": "{{ control_plane_db_input_gid }}",
                "mode": "{{ control_plane_db_input_dir_mode }}",
            },
        )

    def test_the_two_url_files_each_hold_their_own_login_and_nothing_reads_the_provisioner_login(
        self,
    ) -> None:
        text = _text("_provision.yml")
        self.assertIn("control_plane_db_tenant_login }}:{{ control_plane_db_passwords[0] }}", text)
        self.assertIn("control_plane_db_owner_login }}:{{ control_plane_db_passwords[1] }}", text)
        self.assertIn("control_plane_db_portal_url_file", text)
        self.assertIn('content: "{{ control_plane_db_portal_url }}\\n"', text)
        self.assertIn('content: "{{ control_plane_db_console_url }}\\n"', text)
        self.assertNotIn("provisioner_login", text)
        self.assertNotIn("passwords[2] }}@", text)


class PatternTests(unittest.TestCase):
    def _pattern(self, name: str) -> re.Pattern[str]:
        return re.compile(str(_vars()[name]))

    def test_an_image_must_carry_a_full_digest_and_nothing_after_it(self) -> None:
        pattern = self._pattern("control_plane_db_image_pattern")
        digest = "a" * 64
        self.assertTrue(pattern.match(f"example.invalid/app@sha256:{digest}"))
        for bad in (
            "example.invalid/app:latest",
            "",
            f"example.invalid/app@sha256:{digest[:63]}",
            f"example.invalid/app@sha256:{digest.upper()}",
            f"example.invalid/app@sha256:{digest}\n",
            f"example.invalid/app@sha256:{digest} extra",
            f"@sha256:{digest}",
        ):
            self.assertFalse(pattern.match(bad), bad)

    def test_a_password_must_be_made_of_url_safe_characters_and_long_enough(self) -> None:
        pattern = self._pattern("control_plane_db_password_pattern")
        self.assertTrue(pattern.match("a" * 24))
        self.assertTrue(pattern.match("Ab0._~-" * 4))
        for bad in (
            "a" * 23,
            "a" * 23 + "@",
            "a" * 23 + "/",
            "a" * 23 + ":",
            "a" * 23 + " ",
            "a" * 24 + "\n",
            "a" * 23 + "%",
        ):
            self.assertFalse(pattern.match(bad), repr(bad))

    def test_a_step_id_is_a_short_lower_case_word_with_no_line_break(self) -> None:
        pattern = self._pattern("control_plane_db_step_pattern")
        for good in STEPS:
            self.assertTrue(pattern.match(good))
        for bad in ("", "Migrate", "migrate\n", "migrate extra", "9migrate", "a" * 33):
            self.assertFalse(pattern.match(bad), repr(bad))

    def test_a_hostname_is_lower_case_labels_joined_by_dots(self) -> None:
        pattern = self._pattern("control_plane_db_hostname_pattern")
        self.assertTrue(pattern.match("identity.example.invalid"))
        for bad in (
            "",
            "UPPER.example",
            "a b",
            "host:8300",
            "a/b",
            "-a.example",
            "a.example\n",
            "a..b",
        ):
            self.assertFalse(pattern.match(bad), repr(bad))


class InterfaceTests(unittest.TestCase):
    def test_the_defaults_and_the_spec_hold_the_same_inputs_and_values(self) -> None:
        defaults = cast(dict[str, object], _load(ROLE / "defaults" / "main.yml"))
        spec = cast(
            dict[str, dict[str, dict[str, dict[str, dict[str, object]]]]],
            _load(ROLE / "meta" / "argument_specs.yml"),
        )
        options = spec["argument_specs"]["main"]["options"]
        self.assertEqual(set(defaults), set(options))
        for name, option in options.items():
            self.assertEqual(defaults[name], option["default"], name)
            self.assertIn("description", option, name)

    def test_no_input_is_a_secret_and_none_has_a_secret_default(self) -> None:
        for name in cast(dict[str, object], _load(ROLE / "defaults" / "main.yml")):
            self.assertNotRegex(name, r"password|token|secret|url_content|key")

    def test_no_work_item_reference_is_in_the_role(self) -> None:
        for path in sorted(ROLE.rglob("*")):
            if path.is_file() and path.suffix in {".yml", ".md", ".py"}:
                self.assertNotRegex(
                    path.read_text(encoding="utf-8"),
                    r"(?i)workspace#\d|issue #\d|\bws#\d",
                    str(path),
                )


if __name__ == "__main__":
    unittest.main()
