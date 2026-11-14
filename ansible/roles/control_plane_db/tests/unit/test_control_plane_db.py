"""Unit tests for the control_plane_db role's guards, read from the role's own files.

The container test proves what the steps do. These tests pin the structure that test
cannot see go missing: the closed list of step ids it shares with the gated pull, the
tags that keep a step off a plain apply, the removal of the administrator URL file on
every exit, the no_log on every task that runs a program with a mounted secret, and
the shape of every argument a container is started with. Each fails when the text it
reads changes, so a sabotaged copy of the role goes red here as well.
"""

import re
import subprocess
import tempfile
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
    def test_the_credential_url_file_a_step_is_given_is_removed_in_an_always_section(self) -> None:
        # migrate is given the migrator's URL and provision the administrator's, and each
        # removes the one it was given on every way out.
        given = {"migrate": "migrator", "provision": "admin"}
        for step, name in given.items():
            blocks = [t for t in _tasks(ROLE / "tasks" / f"_{step}.yml") if "always" in t]
            self.assertEqual(len(blocks), 1, step)
            removals = cast(list[Task], blocks[0]["always"])
            first = removals[0]
            self.assertEqual(
                first["ansible.builtin.file"],
                {"path": f"{{{{ control_plane_db_{name}_url_file }}}}", "state": "absent"},
            )

    def test_the_passwords_are_removed_only_once_provision_is_recorded(self) -> None:
        always = next(t for t in _tasks(ROLE / "tasks" / "_provision.yml") if "always" in t)
        removal = cast(list[Task], always["always"])[-1]
        self.assertEqual(removal["when"], "control_plane_db_marker_after.stat.exists")
        self.assertEqual(len(cast(list[str], removal["loop"])), 4)

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
        # The migrator's credential is in no standing file: provision writes no URL for it.
        self.assertNotIn("migrator_login", text)
        self.assertNotIn("passwords[3]", text)


REPOSITORY = ROLE.parents[2]
STACK = REPOSITORY / "hetzner" / "control-plane" / "stack"
HBA_CHECK = "Check the database runs on rules that admit the four portal logins"


def _hba_rule_pattern(login: str) -> re.Pattern[str]:
    """Return the pattern the role looks for a login's accepting rule with."""
    constants = _vars()
    return re.compile(
        str(constants["control_plane_db_hba_rule_prefix"])
        + re.escape(login)
        + str(constants["control_plane_db_hba_rule_suffix"])
    )


class DatabaseRulesTests(unittest.TestCase):
    def test_provision_checks_the_database_rules_before_it_looks_at_or_reads_any_input(self) -> None:
        names = _names(ROLE / "tasks" / "_provision.yml")
        check = names.index(HBA_CHECK)
        self.assertLess(check, names.index("Check the administrator URL file and the four password files"))
        self.assertLess(check, names.index("Read the four passwords"))
        self.assertLess(check, names.index("Look at the two connection URL files"))
        self.assertLess(check, names.index("Create the portal database, its roles and logins"))
        imported = next(t for t in _tasks(ROLE / "tasks" / "_provision.yml") if t["name"] == HBA_CHECK)
        self.assertEqual(imported["ansible.builtin.import_tasks"], "_hba.yml")

    def test_only_provision_imports_the_check(self) -> None:
        for step in ("migrate", "identity"):
            self.assertNotIn("_hba.yml", _text(f"_{step}.yml"), step)

    def test_the_check_reads_no_input_file_and_no_secret(self) -> None:
        tasks = _tasks(ROLE / "tasks" / "_hba.yml")
        for task in tasks:
            for needle in ("admin_url", "password", "input_dir", "input_files", "url_file"):
                self.assertNotIn(needle, str(task).lower(), f"{task['name']}: {needle}")
        reads = [t for t in tasks if _module(t) == "slurp"]
        self.assertEqual([t["ansible.builtin.slurp"] for t in reads], [{"src": "{{ control_plane_db_hba_file }}"}])

    def test_the_running_rules_are_read_from_the_container_and_compared_byte_for_byte(self) -> None:
        tasks = _tasks(ROLE / "tasks" / "_hba.yml")
        reads = [t for t in tasks if _module(t) == "command"]
        self.assertEqual(len(reads), 2)
        command = cast(dict[str, object], reads[0]["ansible.builtin.command"])
        self.assertEqual(
            command["argv"],
            [
                "docker",
                "exec",
                "{{ control_plane_db_hba_container }}",
                "cat",
                "{{ control_plane_db_hba_container_file }}",
            ],
        )
        self.assertIs(command["strip_empty_ends"], False)
        self.assertIs(reads[0]["changed_when"], False)
        text = _text("_hba.yml")
        self.assertIn(
            "control_plane_db_hba_running.stdout == (control_plane_db_hba_delivered.content | ansible.builtin.b64decode)",
            text,
        )
        self.assertIn("control_plane_db_hba_running.rc == 0", text)
        self.assertIn("REFUSED:", text)

    def test_each_of_the_four_logins_is_looked_for_in_the_delivered_file(self) -> None:
        checks = [t for t in _tasks(ROLE / "tasks" / "_hba.yml") if "accepting rule" in str(t["name"])]
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["loop"], "{{ control_plane_db_hba_logins }}")
        self.assertEqual(
            _vars()["control_plane_db_hba_logins"],
            [
                "{{ control_plane_db_tenant_login }}",
                "{{ control_plane_db_owner_login }}",
                "{{ control_plane_db_provisioner_login }}",
                "{{ control_plane_db_migrator_login }}",
            ],
        )
        constants = _vars()
        self.assertEqual(constants["control_plane_db_provisioner_login"], "portal_provisioner_login")

    def test_the_delivered_path_is_the_one_the_control_plane_role_delivers_to(self) -> None:
        control_plane = cast(dict[str, object], _load(ROLE.parent / "control_plane" / "vars" / "main.yml"))
        self.assertEqual(
            _vars()["control_plane_db_hba_file"],
            f"{control_plane['control_plane_project_dir']}/postgres/pg_hba.conf",
        )

    def test_the_container_and_its_path_are_the_ones_the_compose_file_makes(self) -> None:
        compose = (STACK / "compose.yml").read_text(encoding="utf-8")
        project = re.search(r"^name: (\S+)\s*$", compose, re.MULTILINE)
        mount = re.search(r"^\s+- \./postgres:(/\S+):ro\s*$", compose, re.MULTILINE)
        if project is None or mount is None:
            self.fail("the compose file no longer names its project or mounts the postgres directory")
        self.assertEqual(_vars()["control_plane_db_hba_container"], f"{project.group(1)}-db-1")
        self.assertEqual(_vars()["control_plane_db_hba_container_file"], f"{mount.group(1)}/pg_hba.conf")
        self.assertEqual(_vars()["control_plane_db_network"], f"{project.group(1)}_default")

    def test_the_logins_are_the_ones_the_stacks_file_admits_to_the_portal_database(self) -> None:
        text = (STACK / "postgres" / "pg_hba.conf").read_text(encoding="utf-8")
        constants = _vars()
        for name in ("tenant", "owner", "provisioner", "migrator"):
            login = str(constants[f"control_plane_db_{name}_login"])
            self.assertRegex(text, _hba_rule_pattern(login), login)

    def test_the_rule_pattern_matches_an_accepting_rule_and_nothing_else(self) -> None:
        login = "portal_provisioner_login"
        pattern = _hba_rule_pattern(login)
        for good in (
            "host     portal              portal_provisioner_login  samenet   scram-sha-256\n",
            "host portal portal_provisioner_login 10.0.0.0/8 scram-sha-256",
            "host\tportal,zitadel\tportal_provisioner_login\tsamenet\tscram-sha-256  \n",
            "# a comment\nhost zitadel,portal portal_provisioner_login samenet scram-sha-256\n",
        ):
            self.assertRegex(good, pattern)
        for bad in (
            "",
            "# host portal portal_provisioner_login samenet scram-sha-256\n",
            "host portal portal_provisioner_login samenet reject\n",
            "host portal portal_provisioner_login samenet trust\n",
            "host zitadel portal_provisioner_login samenet scram-sha-256\n",
            "host portalx portal_provisioner_login samenet scram-sha-256\n",
            "host portal portal_provisioner_login_x samenet scram-sha-256\n",
            "host portal xportal_provisioner_login samenet scram-sha-256\n",
            "local portal portal_provisioner_login scram-sha-256\n",
            "hostssl portal portal_provisioner_login samenet scram-sha-256\n",
            "host portal portal_owner_login samenet scram-sha-256\n",
        ):
            self.assertNotRegex(bad, pattern)

    def test_the_server_is_asked_what_it_loaded_after_the_container_is_shown_to_hold_the_file(self) -> None:
        tasks = _tasks(ROLE / "tasks" / "_hba.yml")
        names = [str(t["name"]) for t in tasks]
        asks = [t for t in tasks if _module(t) == "command" and "sh" in str(t["ansible.builtin.command"])]
        self.assertEqual(len(asks), 1)
        command = cast(dict[str, object], asks[0]["ansible.builtin.command"])
        self.assertEqual(
            command["argv"],
            [
                "docker",
                "exec",
                "-i",
                "{{ control_plane_db_hba_container }}",
                "sh",
                "-s",
                "--",
                "{{ control_plane_db_hba_container_file }}",
            ],
        )
        self.assertEqual(command["stdin"], "{{ lookup('ansible.builtin.file', 'server_loaded_hba.sh') }}")
        self.assertIs(asks[0]["changed_when"], False)
        self.assertEqual(asks[0]["when"], "not ansible_check_mode")
        verdict = next(t for t in tasks if _module(t) == "assert" and "loaded the delivered rules" in str(t["name"]))
        body = cast(dict[str, object], verdict["ansible.builtin.assert"])
        self.assertIn("control_plane_db_hba_loaded.rc == 0", cast(list[str], body["that"]))
        self.assertIn("control_plane_db_hba_loaded.stderr", str(body["fail_msg"]))
        self.assertTrue(str(body["fail_msg"]).startswith("REFUSED:"))
        self.assertEqual(verdict["when"], "not ansible_check_mode")
        self.assertLess(names.index(str(asks[0]["name"])), names.index(str(verdict["name"])))
        self.assertLess(
            names.index("Refuse a database that is not running or holds other rules than the delivered file"),
            names.index(str(asks[0]["name"])),
        )

    def test_the_server_read_uses_the_containers_own_credential_and_the_task_names_none(self) -> None:
        script = (ROLE / "files" / "server_loaded_hba.sh").read_text(encoding="utf-8")
        self.assertIn("${POSTGRES_PASSWORD:?", script)
        self.assertNotRegex(script, r"(?m)^\s*set -[a-z]*x|set -o xtrace")
        self.assertNotIn("POSTGRES_PASSWORD", _text("_hba.yml"))

    def test_the_check_names_a_refusal_for_each_way_it_can_stop(self) -> None:
        asserts = [t for t in _tasks(ROLE / "tasks" / "_hba.yml") if _module(t) == "assert"]
        self.assertEqual(len(asserts), 4)
        for task in asserts:
            body = cast(dict[str, object], task["ansible.builtin.assert"])
            self.assertTrue(str(body["fail_msg"]).startswith("REFUSED:"), task["name"])


FAKE_PSQL = """#!/bin/sh
# Answers the three questions the check asks, from the environment, as a server would.
for argument in "$@"; do
    case "$argument" in
        --command=*) text="${argument#--command=}" ;;
    esac
done
case "$text" in
    *pg_hba_file_rules*) printf '%s\\n' "$FAKE_ERRORS" ;;
    *pg_conf_load_time*) printf '%s\\n' "$FAKE_LOADED" ;;
    *hba_file*) printf '%s\\n' "$FAKE_HBA_FILE" ;;
    *) echo "fake psql: unexpected query: $text" >&2; exit 2 ;;
esac
"""
FAKE_STAT = """#!/bin/sh
# The container's stat, for the two times the check reads: modification and change.
case "$2" in
    %Y) printf '%s\\n' "$FAKE_MTIME" ;;
    %Z) printf '%s\\n' "$FAKE_CTIME" ;;
    *) echo "fake stat: unexpected format: $2" >&2; exit 2 ;;
esac
"""
CONTAINER_HBA = "/etc/postgresql-hba/pg_hba.conf"
STAND_IN_CREDENTIAL = "stand-in-credential-for-the-test"


def _run_the_check(environment: dict[str, str], arguments: list[str], programs: Path) -> "subprocess.CompletedProcess[str]":
    """Run the check the way the role does: `sh -s -- <file>`, the script on standard input."""
    for name, body in (("psql", FAKE_PSQL), ("stat", FAKE_STAT)):
        program = programs / name
        program.write_text(body, encoding="utf-8")
        program.chmod(0o755)
    script = (ROLE / "files" / "server_loaded_hba.sh").read_text(encoding="utf-8")
    return subprocess.run(  # noqa: S603 - a fixed shell and stand-in programs, in a temporary directory
        ["/bin/sh", "-s", "--", *arguments],
        input=script,
        capture_output=True,
        text=True,
        env={"PATH": f"{programs}:/usr/bin:/bin", **environment},
        check=False,
        timeout=30,
    )


def _ask_the_server(
    *,
    loaded: int,
    mtime: int = 900,
    ctime: int = 950,
    errors: int = 0,
    hba_file: str = CONTAINER_HBA,
    credential: str = STAND_IN_CREDENTIAL,
) -> "subprocess.CompletedProcess[str]":
    """Ask the check about a stand-in server that reloaded at `loaded`, for a file changed at mtime and ctime."""
    environment = {
        "FAKE_HBA_FILE": hba_file,
        "FAKE_ERRORS": str(errors),
        "FAKE_LOADED": str(loaded),
        "FAKE_MTIME": str(mtime),
        "FAKE_CTIME": str(ctime),
    }
    if credential:
        environment["POSTGRES_PASSWORD"] = credential
    with tempfile.TemporaryDirectory() as directory:
        return _run_the_check(environment, [CONTAINER_HBA], Path(directory))


class ServerLoadedRulesTests(unittest.TestCase):
    def test_a_server_that_reloaded_after_the_file_last_changed_is_accepted(self) -> None:
        done = _ask_the_server(loaded=1000, mtime=900, ctime=950)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("loaded", done.stdout)

    def test_a_file_delivered_and_not_yet_reloaded_is_refused_by_name(self) -> None:
        # The sabotage case of the issue: deliver, skip the reload.
        done = _ask_the_server(loaded=1000, mtime=1100, ctime=1100)
        self.assertEqual(done.returncode, 1)
        self.assertIn("has not reloaded", done.stderr)

    def test_a_file_whose_inode_changed_after_the_reload_is_refused(self) -> None:
        done = _ask_the_server(loaded=1000, mtime=900, ctime=1100)
        self.assertEqual(done.returncode, 1)
        self.assertIn("has not reloaded", done.stderr)

    def test_a_file_modified_after_the_reload_is_refused_though_its_inode_is_old(self) -> None:
        done = _ask_the_server(loaded=1000, mtime=1100, ctime=950)
        self.assertEqual(done.returncode, 1)
        self.assertIn("has not reloaded", done.stderr)

    def test_a_reload_in_the_same_second_as_the_change_is_refused_not_guessed(self) -> None:
        done = _ask_the_server(loaded=1100, mtime=1100, ctime=1100)
        self.assertEqual(done.returncode, 1)
        self.assertIn("has not reloaded", done.stderr)

    def test_a_file_the_server_cannot_parse_is_refused_though_the_reload_is_late_enough(self) -> None:
        done = _ask_the_server(loaded=2000, errors=2)
        self.assertEqual(done.returncode, 1)
        self.assertIn("does not parse", done.stderr)

    def test_a_server_reading_another_file_than_the_delivered_one_is_refused(self) -> None:
        done = _ask_the_server(loaded=2000, hba_file="/var/lib/postgresql/data/pg_hba.conf")
        self.assertEqual(done.returncode, 1)
        self.assertIn("reads another file", done.stderr)

    def test_a_container_without_its_own_credential_is_refused(self) -> None:
        done = _ask_the_server(loaded=2000, credential="")
        self.assertEqual(done.returncode, 1)
        self.assertIn("POSTGRES_PASSWORD", done.stderr)

    def test_the_credential_is_never_printed(self) -> None:
        for case in (
            _ask_the_server(loaded=2000),
            _ask_the_server(loaded=1000, mtime=1100, ctime=1100),
            _ask_the_server(loaded=2000, errors=1),
        ):
            self.assertNotIn(STAND_IN_CREDENTIAL, case.stdout + case.stderr)

    def test_a_call_with_no_file_path_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            done = _run_the_check({"POSTGRES_PASSWORD": STAND_IN_CREDENTIAL}, [], Path(directory))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("path of the rules file", done.stderr)


def _step_task(step: str, name: str) -> Task:
    """Return the task of a step with this name, which must be unique in its file."""
    found = [t for t in _tasks(ROLE / "tasks" / f"_{step}.yml") if t.get("name") == name]
    if len(found) != 1:
        raise AssertionError(f"{step}: expected one task named {name!r}, found {len(found)}")
    return found[0]


def _input_files(step: str, name: str) -> list[str]:
    """Return the input files a step's input check is given."""
    task = _step_task(step, name)
    return cast(dict[str, list[str]], task["vars"])["control_plane_db_input_files"]


def _image_needle(step: str, name: str) -> str:
    """Return the text a step requires the image's program to carry."""
    task = _step_task(step, name)
    return cast(dict[str, str], task["vars"])["control_plane_db_image_needle"]


class MigratorTests(unittest.TestCase):
    """The migration login is not the administrator, and the role never hands migrate the administrator."""

    def test_the_constants_name_the_login_its_two_inputs_and_the_provision_marker(self) -> None:
        constants = _vars()
        self.assertEqual(constants["control_plane_db_migrator_login"], "portal_migrator_login")
        self.assertEqual(constants["control_plane_db_migrator_password_name"], "migrator-password")
        self.assertEqual(constants["control_plane_db_migrator_url_name"], "migrator-url")
        for kind in ("password", "url"):
            self.assertEqual(
                constants[f"control_plane_db_migrator_{kind}_file"],
                f"{{{{ control_plane_db_input_dir }}}}/{{{{ control_plane_db_migrator_{kind}_name }}}}",
            )
        logins = [constants[f"control_plane_db_{n}_login"] for n in ("tenant", "owner", "provisioner", "migrator")]
        self.assertEqual(len(set(logins)), 4)
        sets = [t for t in _tasks(ROLE / "tasks" / "_provision.yml") if _module(t) == "set_fact"]
        facts = cast(dict[str, str], sets[0]["ansible.builtin.set_fact"])
        self.assertEqual(facts["control_plane_db_marker"], "provision-migrator")

    def test_migrate_is_given_the_migrator_url_file_alone_and_checks_nothing_else(self) -> None:
        self.assertEqual(
            _input_files("migrate", "Check the migrator URL file"),
            ["{{ control_plane_db_migrator_url_file }}"],
        )

    def test_migrate_names_no_administrator_input_anywhere_in_its_tasks(self) -> None:
        for task in _tasks(ROLE / "tasks" / "_migrate.yml"):
            self.assertNotIn("admin", str(task).lower(), str(task.get("name")))

    def test_migrate_mounts_one_read_only_file_and_names_one_input_variable(self) -> None:
        text = _text("_migrate.yml")
        mounts = re.findall(r"'-v', (.*)", text)
        self.assertEqual(len(mounts), 1)
        self.assertIn("control_plane_db_migrator_url_file", mounts[0])
        self.assertIn(":ro'", mounts[0])
        self.assertEqual(
            re.findall(r"'-e', '(\w+)=", text),
            ["PORTAL_MIGRATOR_URL_FILE", "NODE_OPTIONS"],
        )

    def test_the_image_must_carry_the_variable_each_step_reads_for_the_migrator(self) -> None:
        self.assertEqual(
            _image_needle("migrate", "Check the image carries the migrator login"), "PORTAL_MIGRATOR_URL_FILE"
        )
        self.assertEqual(
            _image_needle("provision", "Check the image carries the migrator login"),
            "PORTAL_MIGRATOR_PASSWORD_FILE",
        )

    def test_provision_checks_reads_mounts_and_names_the_migrator_password_with_the_others(self) -> None:
        files = _input_files("provision", "Check the administrator URL file and the four password files")
        self.assertEqual(files[-1], "{{ control_plane_db_migrator_password_file }}")
        self.assertEqual(len(files), 5)
        read = _step_task("provision", "Read the four passwords")
        self.assertEqual(read["loop"][-1], "{{ control_plane_db_migrator_password_file }}")  # type: ignore[index]
        self.assertEqual(len(cast(list[str], read["loop"])), 4)
        text = _text("_provision.yml")
        self.assertIn("'-v', control_plane_db_migrator_password_file", text)
        self.assertIn("'-e', 'PORTAL_MIGRATOR_PASSWORD_FILE=/provision/' ~ control_plane_db_migrator_password_name", text)
        self.assertEqual(text.count("'-v', "), 5)

    def test_provision_still_gives_the_program_the_administrator_url_it_needs_for_the_first_steps(self) -> None:
        # Out of scope for this change: the administrator creates the roles and the database.
        self.assertIn("'-e', 'PORTAL_ADMIN_URL_FILE=/provision/' ~ control_plane_db_admin_url_name", _text("_provision.yml"))


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
