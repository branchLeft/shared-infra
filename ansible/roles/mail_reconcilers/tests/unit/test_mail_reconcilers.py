"""Unit tests for the mail_reconcilers role's guards, read from the role's own files.

The container test proves what the steps do. These tests pin the structure it cannot see go
missing: the tags that keep a step off a plain apply and the tripwire that refuses a tag without
its confirmation, the closed table of credentials, the dry-run gate of the collector, the
preconditions on the root credential files, the no_log on every task that runs a program, and
the list of programs placed, which must stay off every file the mail host's stack role owns.
Each fails when the text it reads changes, so a sabotaged copy of the role goes red here too.
"""

import fnmatch
import re
import unittest
from pathlib import Path
from typing import cast

from jinja2 import Environment, select_autoescape
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
REPO = ROLE.parents[2]
PROGRAMS = REPO / "mail" / "provision"
STEPS = ("configure", "mailboxes", "mint", "collector")
COLLECTOR = "67-provision-collector-submission-credential.sh"
PROBE = ROLE / "files" / "check_stalwart_bootstrap_mode.py"
ROWS = {
    "website": "60-provision-website-submission-credential.sh",
    "blog": "61-provision-blog-submission-credential.sh",
    "shim": "62-provision-shim-submission-credential.sh",
    "alerting": "64-provision-alerting-submission-credential.sh",
    "nextcloud": "66-provision-nextcloud-submission-credential.sh",
    "zitadel": "68-provision-zitadel-submission-credential.sh",
    "portal": "69-provision-portal-submission-credential.py",
}
INSTALLED = (
    "configure_stalwart.py",
    "provision_mailboxes.py",
    "provision_sending_domain.py",
    "provision_website_submission_credential.py",
    "provision_zitadel_submission_credential.py",
    "provision_collector_submission_credential.py",
    "check_collector_sender_scope.py",
    "check_zitadel_sender_scope.py",
    "trigger_acme_renewal.py",
    "list_and_clear_blocked_ips.py",
    "40-configure-stalwart.sh",
    "50-provision-mailboxes.sh",
    *ROWS.values(),
    COLLECTOR,
)
# Every file the mail host's stack role owns. check_role_paths.py skips a destination that is a
# loop item, so it cannot stop this role writing one of them.
STACK_OWNED = (
    "30-deploy-stalwart.sh",
    "63-deploy-mailgun-shim.sh",
    "65-install-local-resolver.sh",
    "70-schedule-dnsbl-check.sh",
    "run-all.sh",
    "shim-compose.yml",
    "render_shim_env.py",
    "shim-env-contracts.json",
    "check_dnsbl_blocklist.py",
    "docker-compose.yml",
    "Caddyfile",
)
Task = dict[str, object]


def _load(path: Path) -> object:
    """Return the parsed YAML of a role file."""
    return cast(object, YAML(typ="safe").load(path.read_text(encoding="utf-8")))


def _tasks(name: str) -> list[Task]:
    """Return every task of a tasks file, with the tasks of its blocks, in file order."""
    found: list[Task] = []

    def walk(items: object) -> None:
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                found.append(item)
                for key in ("block", "rescue", "always"):
                    walk(item.get(key))

    walk(_load(ROLE / "tasks" / name))
    return found


def _vars() -> dict[str, object]:
    """Return the role's constants."""
    return cast(dict[str, object], _load(ROLE / "vars" / "main.yml"))


def _text(name: str) -> str:
    """Return the text of a tasks file."""
    return (ROLE / "tasks" / name).read_text(encoding="utf-8")


def _module(task: Task) -> str:
    """Return the short module name a task uses, or an empty string."""
    return next(
        (k.rsplit(".", 1)[-1] for k in map(str, task) if k.startswith("ansible.builtin.")), ""
    )


def _that(task: Task) -> list[str]:
    """Return the conditions of an assert task."""
    return cast(dict[str, list[str]], task["ansible.builtin.assert"])["that"]


def _assert_named(name: str, prefix: str) -> Task:
    """Return the one assert task of a tasks file whose name starts with the prefix."""
    found = [
        t for t in _tasks(name) if _module(t) == "assert" and str(t["name"]).startswith(prefix)
    ]
    if len(found) != 1:
        raise AssertionError(f"{len(found)} assert tasks in {name} start with {prefix!r}")
    return found[0]


def _holds(conditions: list[str], **context: object) -> bool:
    """Return whether every condition of an assert is true for the context, as Ansible reads them.

    The conditions are evaluated, not searched, so a test of one fails when its behaviour changes
    and passes when only its spelling does.
    """
    environment = Environment(autoescape=select_autoescape())
    return all(bool(environment.compile_expression(c)(**context)) for c in conditions)


def _all_tasks() -> list[tuple[str, Task]]:
    """Return every task of every tasks file, with the file it is in."""
    return [(p.name, t) for p in sorted((ROLE / "tasks").glob("*.yml")) for t in _tasks(p.name)]


class GuardTests(unittest.TestCase):
    def test_each_step_is_imported_with_the_never_tag_its_own_tag_and_its_own_condition(
        self,
    ) -> None:
        imports = {str(t["name"]): t for t in _tasks("main.yml") if _module(t) == "import_tasks"}
        for step in STEPS:
            task = imports[f"Guarded step {step}"]
            self.assertEqual(task["tags"], ["never", f"mail_reconcilers_{step}"], step)
            self.assertEqual(task["ansible.builtin.import_tasks"], f"_{step}.yml")
            self.assertEqual(task["when"], f"mail_reconcilers_step == '{step}'", step)
        self.assertEqual(_vars()["mail_reconcilers_step_ids"], list(STEPS))

    def test_the_tripwire_runs_on_any_step_tag_and_refuses_a_missing_wrong_or_unrequested_one(
        self,
    ) -> None:
        main = _tasks("main.yml")
        task = next(t for t in main if t.get("ansible.builtin.import_tasks") == "_tripwire.yml")
        self.assertEqual(task["tags"], ["never", *(f"mail_reconcilers_{s}" for s in STEPS)])
        self.assertNotIn("when", task)
        assertion = _tasks("_tripwire.yml")[0]
        self.assertEqual(
            _that(assertion),
            [
                "mail_reconcilers_step is string",
                "mail_reconcilers_step is match(mail_reconcilers_id_pattern)",
                "mail_reconcilers_step in mail_reconcilers_step_ids",
                "('mail_reconcilers_' ~ mail_reconcilers_step) in ansible_run_tags",
            ],
        )
        self.assertIn("REFUSED:", _text("_tripwire.yml"))

    def test_a_plain_apply_reaches_no_program_and_nothing_carries_the_always_tag(self) -> None:
        for task in _tasks("main.yml"):
            if _module(task) != "import_tasks":
                self.assertNotIn(_module(task), {"command", "shell", "raw", "script"}, task["name"])
                self.assertEqual(task.get("tags", []), [], task["name"])
        for name, task in _all_tasks():
            tags = task.get("tags", [])
            self.assertNotIn("always", tags if isinstance(tags, list) else [tags], name)


class CredentialTableTests(unittest.TestCase):
    def test_the_table_is_exactly_the_seven_credentials_and_every_wrapper_exists(self) -> None:
        table = cast(dict[str, str], _vars()["mail_reconcilers_credential_rows"])
        self.assertEqual(table, ROWS)
        for wrapper in table.values():
            self.assertTrue((PROGRAMS / wrapper).is_file(), wrapper)

    def test_mint_refuses_a_credential_outside_the_table_before_anything_else(self) -> None:
        first = _tasks("_mint.yml")[0]
        self.assertEqual(
            _that(first),
            [
                "mail_reconcilers_credential is string",
                "mail_reconcilers_credential is match(mail_reconcilers_id_pattern)",
                "mail_reconcilers_credential in mail_reconcilers_credential_rows",
            ],
        )
        self.assertIn("REFUSED:", str(first["ansible.builtin.assert"]))
        self.assertIn(
            "mail_reconcilers_credential_rows[mail_reconcilers_credential]", _text("_mint.yml")
        )


class CollectorGateTests(unittest.TestCase):
    def test_the_dry_run_comes_first_and_the_real_run_depends_on_it(self) -> None:
        tasks = _tasks("_collector.yml")
        self.assertEqual(
            [_module(t) for t in tasks], ["import_tasks", "command", "assert", "command", "assert"]
        )
        _, dry, gate, real, stored = tasks
        self.assertEqual(
            cast(dict[str, list[str]], dry["ansible.builtin.command"])["argv"][-1], "--dry-run"
        )
        self.assertIs(dry.get("check_mode"), False)
        self.assertEqual(
            _that(gate),
            [
                "mail_reconcilers_run.rc == 0",
                "'DRY RUN, nothing written' in mail_reconcilers_run.stdout",
            ],
        )
        self.assertNotIn("--dry-run", str(real))
        self.assertEqual(real["when"], "not ansible_check_mode")
        self.assertEqual(
            _that(stored),
            [
                "mail_reconcilers_run.rc == 0",
                "'sender scope stored' in mail_reconcilers_run.stdout",
            ],
        )
        self.assertIn("the collector dry run phase did not end clean", _text("_collector.yml"))
        self.assertIn("the collector real run phase did not store", _text("_collector.yml"))


class PreconditionTests(unittest.TestCase):
    def test_every_step_checks_the_preconditions_before_it_runs_a_program(self) -> None:
        for step in STEPS:
            tasks = _tasks(f"_{step}.yml")
            at = next(i for i, t in enumerate(tasks) if _module(t) == "import_tasks")
            self.assertEqual(tasks[at]["ansible.builtin.import_tasks"], "_preconditions.yml", step)
            self.assertLess(at, next(i for i, t in enumerate(tasks) if _module(t) == "command"))

    def test_the_three_files_are_checked_without_following_a_link_and_the_admin_one_is_required(
        self,
    ) -> None:
        constants = _vars()
        self.assertEqual(
            constants["mail_reconcilers_admin_credentials"], "/root/.stalwart-admin-credentials"
        )
        self.assertEqual(
            constants["mail_reconcilers_service_credentials"], "/root/.stalwart-service-credentials"
        )
        self.assertEqual(
            constants["mail_reconcilers_mailbox_credentials"], "/root/.stalwart-mailbox-credentials"
        )
        self.assertEqual(
            [
                f["required"]
                for f in cast(
                    list[dict[str, object]], constants["mail_reconcilers_credential_files"]
                )
            ],
            [True, False, False],
        )
        stats = [t for t in _tasks("_preconditions.yml") if _module(t) == "stat"]
        self.assertEqual(len(stats), 2)
        for stat in stats:
            self.assertIs(cast(dict[str, object], stat["ansible.builtin.stat"])["follow"], False)

    def test_every_precondition_refuses_by_name(self) -> None:
        asserts = [t for t in _tasks("_preconditions.yml") if _module(t) == "assert"]
        self.assertEqual(len(asserts), 3)
        for task in asserts:
            fail_msg = cast(dict[str, str], task["ansible.builtin.assert"])["fail_msg"]
            self.assertTrue(fail_msg.startswith("REFUSED:"), task["name"])

    def test_a_credential_file_passes_only_when_it_is_what_the_programs_need(self) -> None:
        """The check is run, not read: a loosened mode or owner test that keeps its text fails."""
        conditions = _that(_assert_named("_preconditions.yml", "Refuse a credential file that is"))

        def verdict(required: bool, **stat: object) -> bool:
            item = {"stat": stat, "item": {"required": required}}
            return _holds(conditions, item=item)

        present = {"exists": True, "isreg": True, "pw_name": "root", "mode": "0600"}
        self.assertTrue(verdict(True, **present))
        self.assertTrue(verdict(False, **present))
        self.assertFalse(verdict(True, exists=False))
        self.assertTrue(verdict(False, exists=False))
        for wrong in (
            {"mode": "0644"},
            {"mode": "0640"},
            {"mode": "0660"},
            {"mode": "0666"},
            {"mode": "0700"},
            {"mode": "0400"},
            {"mode": "0000"},
            {"isreg": False},
            {"pw_name": "nobody"},
            {"pw_name": "rootless"},
        ):
            for required in (True, False):
                self.assertFalse(verdict(required, **{**present, **wrong}), (wrong, required))
        self.assertFalse(verdict(True, exists=True, isreg=True, mode="0600"), "no owner is no root")
        self.assertFalse(
            verdict(False, exists=True, isreg=True, mode="0600"), "no owner is no root"
        )

    def test_the_install_directory_passes_only_as_a_root_directory_of_the_named_mode(self) -> None:
        conditions = _that(_assert_named("_preconditions.yml", "Refuse an install directory"))

        def verdict(**stat: object) -> bool:
            return _holds(
                conditions,
                mail_reconcilers_install_stat={"stat": stat},
                mail_reconcilers_install_dir_mode="0755",
            )

        good = {"exists": True, "isdir": True, "pw_name": "root", "mode": "0755"}
        self.assertTrue(verdict(**good))
        self.assertFalse(verdict(exists=False))
        for wrong in (
            {"mode": "0775"},
            {"mode": "0777"},
            {"mode": "0750"},
            {"isdir": False},
            {"pw_name": "nobody"},
        ):
            self.assertFalse(verdict(**{**good, **wrong}), wrong)

    def test_the_list_of_credential_files_passes_only_as_the_roles_own_three(self) -> None:
        """An extra variable outranks the constant, so an empty list must not skip the checks."""
        constants = _vars()
        admin, service, mailbox = (
            cast(str, constants[f"mail_reconcilers_{kind}_credentials"])
            for kind in ("admin", "service", "mailbox")
        )
        conditions = _that(_assert_named("_preconditions.yml", "Refuse a credential file list"))

        def verdict(files: object) -> bool:
            return _holds(
                conditions,
                mail_reconcilers_credential_files=files,
                mail_reconcilers_admin_credentials=admin,
                mail_reconcilers_service_credentials=service,
                mail_reconcilers_mailbox_credentials=mailbox,
            )

        def row(path: str, *, required: bool = False) -> dict[str, object]:
            return {"path": path, "required": required}

        own = [row(admin, required=True), row(service), row(mailbox)]
        self.assertTrue(verdict(own))
        for wrong in (
            [],
            "[]",
            "",
            None,
            own[:2],
            own[1:],
            [*own, row("/root/other")],
            [own[1], own[0], own[2]],
            [row(admin), row(service), row(mailbox)],
            [row(admin, required=True), row(service, required=True), row(mailbox)],
            [row(admin, required=True), row(service), row("/root/other")],
        ):
            self.assertFalse(verdict(wrong), wrong)

    def test_configure_asks_whether_stalwart_is_in_bootstrap_mode_before_it_runs_the_program(
        self,
    ) -> None:
        tasks = _tasks("_configure.yml")
        modules = [_module(t) for t in tasks]
        self.assertEqual(
            modules, ["import_tasks", "script", "assert", "command", "assert"], "order of the steps"
        )
        _, probe, refusal, run, _ = tasks
        self.assertEqual(cast(dict[str, str], probe["ansible.builtin.script"])["cmd"], PROBE.name)
        self.assertEqual(
            cast(dict[str, str], probe["ansible.builtin.script"])["executable"],
            "/usr/bin/python3 -I",
        )
        self.assertTrue((ROLE / "files" / PROBE.name).is_file())
        self.assertEqual(probe["environment"], "{{ mail_reconcilers_program_environment }}")
        # A read that writes nothing, so a check-mode request asks too and shows the refusal.
        self.assertIs(probe.get("check_mode"), False)
        self.assertNotIn("when", probe)
        self.assertNotIn("when", refusal)
        self.assertEqual(run["when"], "not ansible_check_mode")

    def test_the_refusal_lets_configure_go_on_only_when_the_probe_exited_0(self) -> None:
        conditions = _that(_assert_named("_configure.yml", "Refuse a configure while Stalwart"))

        def verdict(**probe: object) -> bool:
            return _holds(conditions, mail_reconcilers_bootstrap_probe=probe)

        self.assertTrue(verdict(rc=0))
        for rc in (1, 2, 3, 4, 126, 127, -1):
            self.assertFalse(verdict(rc=rc), rc)
        self.assertFalse(verdict(), "a probe that left no exit status is a refusal")
        self.assertFalse(verdict(rc=None))
        self.assertFalse(verdict(rc="0"))
        text = _text("_configure.yml")
        self.assertIn("REFUSED: Stalwart is in bootstrap mode", text)
        self.assertIn("40-configure-stalwart", text + str(_vars()["mail_reconcilers_wrappers"]))
        self.assertIn("RUNBOOK-mx1-provision.md", text)

    def test_the_probe_is_the_one_program_the_role_runs_without_placing_it(self) -> None:
        installed = {
            e["program"] for e in cast(list[dict[str, str]], _vars()["mail_reconcilers_installed"])
        }
        self.assertNotIn(PROBE.name, installed)
        self.assertEqual(sorted(p.name for p in (ROLE / "files").glob("*.py")), [PROBE.name])

    def test_a_program_reads_the_files_that_were_checked(self) -> None:
        env = cast(dict[str, str], _vars()["mail_reconcilers_program_environment"])
        self.assertEqual(
            env["STALWART_CREDENTIALS_PATH"], "{{ mail_reconcilers_admin_credentials }}"
        )
        self.assertEqual(
            env["SERVICE_CREDENTIALS_PATH"], "{{ mail_reconcilers_service_credentials }}"
        )
        self.assertEqual(
            env["MAILBOX_CREDENTIALS_PATH"], "{{ mail_reconcilers_mailbox_credentials }}"
        )
        for name, task in _all_tasks():
            if _module(task) in {"command", "script"}:
                self.assertEqual(
                    task["environment"], "{{ mail_reconcilers_program_environment }}", name
                )


class SecretHandlingTests(unittest.TestCase):
    def test_every_task_that_runs_a_program_has_no_log_and_reads_its_own_exit(self) -> None:
        seen = 0
        for name, task in _all_tasks():
            if _module(task) in {"command", "shell", "raw", "script"}:
                seen += 1
                self.assertIs(task.get("no_log"), True, f"{name}: {task['name']}")
                self.assertIs(task.get("failed_when"), False, f"{name}: {task['name']}")
        self.assertEqual(seen, 6)

    def test_the_role_never_reads_or_writes_a_secret_itself(self) -> None:
        for name, task in _all_tasks():
            self.assertNotIn(
                _module(task), {"slurp", "lineinfile", "blockinfile", "template"}, name
            )
            if _module(task) == "copy":
                self.assertIn("mail_reconcilers_programs_dir", str(task), name)
        for step in STEPS:
            self.assertNotRegex(
                _text(f"_{step}.yml"), r"lookup\(|slurp|password|secret|stdout_lines"
            )

    def test_a_refusal_shows_only_the_closed_refusal_lines_cut_short(self) -> None:
        shown = str(_vars()["mail_reconcilers_shown_lines"])
        self.assertIn("select('match', mail_reconcilers_refusal_line_pattern)", shown)
        self.assertIn("map('truncate', 200)", shown)

    def test_the_refusal_pattern_matches_the_lines_the_programs_print_and_not_an_api_error(
        self,
    ) -> None:
        pattern = re.compile(str(_vars()["mail_reconcilers_refusal_line_pattern"]))
        printed = (
            ("REFUSED, nothing written", "provision_collector_submission_credential"),
            ("DRY RUN, nothing written", "provision_collector_submission_credential"),
            ("WARNING --", "provision_website_submission_credential"),
        )
        for words, program in printed:
            self.assertIn(words, (PROGRAMS / f"{program}.py").read_text(encoding="utf-8"), words)
            self.assertTrue(pattern.match(f"{program}: {words}: a reason"), words)
        for line in (
            "provision_collector_submission_credential: HTTP 500 from the Stalwart API: {}",
            "provision_mailboxes: could not reach the Stalwart API at http://127.0.0.1:8080: x",
            "configure_stalwart: the Stalwart API at http://127.0.0.1:8080 answered HTTP 500",
            "  REFUSED, nothing written",
        ):
            self.assertIsNone(pattern.match(line), line)


class InstallListTests(unittest.TestCase):
    def _installed(self) -> list[dict[str, str]]:
        return cast(list[dict[str, str]], _vars()["mail_reconcilers_installed"])

    def test_the_install_list_is_exactly_the_twenty_programs_each_0755(self) -> None:
        self.assertEqual(sorted(e["program"] for e in self._installed()), sorted(INSTALLED))
        self.assertEqual({e["mode"] for e in self._installed()}, {"0755"})
        self.assertEqual(len(set(INSTALLED)), 20)

    def test_the_install_list_holds_no_file_the_host_stack_role_owns(self) -> None:
        names = {e["program"] for e in self._installed()}
        self.assertEqual(names & set(STACK_OWNED), set())
        classified = cast(dict[str, list[str]], _vars()["mail_reconcilers_not_installed"])
        self.assertEqual(set(classified["mx1_stack"]), set(STACK_OWNED))
        for name in names:
            self.assertFalse(fnmatch.fnmatch(name, "test_*.py") or name.endswith(".md"), name)

    def test_every_file_under_mail_provision_is_installed_or_classified(self) -> None:
        installed = {e["program"] for e in self._installed()}
        classified = cast(dict[str, list[str]], _vars()["mail_reconcilers_not_installed"])
        named = {n for group, items in classified.items() if group != "patterns" for n in items}
        for path in sorted(PROGRAMS.iterdir()):
            by_pattern = any(fnmatch.fnmatch(path.name, p) for p in classified["patterns"])
            self.assertTrue(
                path.name in installed or path.name in named or by_pattern,
                f"{path.name} is neither installed nor classified in vars/main.yml",
            )
            self.assertFalse(path.name in installed and path.name in named, path.name)
        for name in installed | named:
            self.assertTrue(
                (PROGRAMS / name).is_file(), f"{name} is named but not in mail/provision"
            )

    def test_the_programs_are_read_in_place_and_placed_with_the_explicit_mode(self) -> None:
        self.assertEqual(
            _vars()["mail_reconcilers_programs_dir"], "{{ role_path }}/../../../mail/provision"
        )
        places = [t for t in _tasks("main.yml") if _module(t) == "copy"]
        self.assertEqual(len(places), 2, "one task whose diff is hidden and one that shows it")
        for place in places:
            self.assertEqual(
                place["ansible.builtin.copy"],
                {
                    "src": "{{ mail_reconcilers_programs_dir }}/{{ item.program }}",
                    "dest": "{{ mail_reconcilers_install_dir }}/{{ item.program }}",
                    "owner": "root",
                    "group": "root",
                    "mode": "{{ item.mode }}",
                },
            )
        # files/ holds the probe alone; the reconcilers have one home, mail/provision.
        self.assertEqual([p.name for p in (ROLE / "files").glob("*.py")], [PROBE.name])

    def test_the_two_placing_tasks_split_the_install_list_and_only_one_hides_its_diff(self) -> None:
        hidden, shown = (t for t in _tasks("main.yml") if _module(t) == "copy")
        filtered = (
            "{{ mail_reconcilers_installed | %sattr('program', 'in', "
            "mail_reconcilers_installed_hidden) | list }}"
        )
        self.assertEqual(hidden["loop"], filtered % "select")
        self.assertEqual(shown["loop"], filtered % "reject")
        self.assertIs(hidden["diff"], False)
        self.assertNotIn("diff", shown)

    def test_the_hidden_list_names_only_installed_programs_once_each(self) -> None:
        names = cast(list[str], _vars()["mail_reconcilers_installed_hidden"])
        self.assertEqual(len(set(names)), len(names))
        self.assertLessEqual(set(names), {e["program"] for e in self._installed()})


if __name__ == "__main__":
    unittest.main()
