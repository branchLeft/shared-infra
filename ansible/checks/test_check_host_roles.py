"""Tests that an enrolled host playbook runs the pull roles, then only its own approved roles.

check_enrolment holds each enrolled playbook to ansible_runtime then pull_trigger, then only
plain `role: ../roles/NAME` entries from that host's list in ansible/checks/host_roles.yml. Each
test edits a copy of the real ansible/ tree. A positive case runs first for every host, so a
check that refused everything would not pass for a working one. A sabotage that matches nothing
fails the test.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from check_enrolment import HOST_ROLES_FILE, PLAY_KEYS, ROOT, check

ENROLLED = ("edge1", "ops1", "app1", "db1", "demo1")
SECOND_PLAY = "- name: Second play\n  hosts: all\n  roles:\n    - role: ../roles/host_baseline\n"
# Each text is one more key of the play, at the play's indent, appended after `roles`.
EXTRA_PLAY_KEYS = {
    "tasks": (
        "  tasks:\n    - name: Apply\n      ansible.builtin.include_role:\n        name: made_up\n"
    ),
    "post_tasks": (
        "  post_tasks:\n    - name: Apply\n      ansible.builtin.import_role:\n"
        "        name: made_up\n"
    ),
    "handlers": (
        "  handlers:\n    - name: Apply\n      ansible.builtin.include_role:\n"
        "        name: made_up\n"
    ),
    "environment": "  environment:\n    HARMLESS: '1'\n",
    "module_defaults": "  module_defaults:\n    ansible.builtin.debug:\n      msg: hello\n",
    "collections": "  collections:\n    - ansible.posix\n",
    "strategy": "  strategy: free\n",
    "become": "  become: true\n",
    "become_user": "  become_user: root\n",
    "import_playbook": "  import_playbook: other.yml\n",
    "include_vars": "  include_vars: other.yml\n",
    "vars_prompt": "  vars_prompt:\n    - name: answer\n      prompt: Answer\n",
}
# The four loaders a pre_tasks entry could use to run something else, with the text after the
# colon. A role loader takes a name on the next line, a task-file loader a file on the same line.
LOADERS = {
    "include_role": "\n        name: made_up\n",
    "import_role": "\n        name: made_up\n",
    "include_tasks": " other.yml\n",
    "import_tasks": " other.yml\n",
}
LOADER_ENTRY = "    - role: ../roles/host_inputs # noqa: role-name[path]\n"
REFUSE_LINE = "      ansible.builtin.include_tasks: includes/refuse_other_hosts.yml\n"
SIGNER_LINE = "      ansible.builtin.include_tasks: includes/require_signers.yml\n"


# The last pull role in every enrolled playbook. Whatever follows it is the host's own roles.
TRIGGER_ENTRY = "    - role: ../roles/pull_trigger # noqa: role-name[path]\n"
# The roles a real playbook applies after the pull roles: host_baseline (this change) and the
# roles main wired before it (status_page, ci_login, host_inputs, breakglass_mint_host,
# breakglass_grant_host), then edge1's deploy_tooling and edge_stack (last: it needs Docker from
# host_baseline and the compose unit and deploy wrapper that the deploy tooling installs),
# app1's host_inputs (the loader goes first, R11) and website_app1 (last, after host_baseline
# has installed Docker), db1's host_baseline, db1_stack and db1_backup_timers (after the
# loader, which goes first; db1_grants would follow the timers and is not applied), ops1's
# control_plane after the status page, and demo1's two build roles.
# One test holds the real playbooks to exactly these; the fixtures start from the pull roles alone.
APPLIED_ON_MAIN = {
    "edge1": ["host_baseline", "ci_login", "deploy_tooling", "edge_stack"],
    "ops1": ["host_baseline", "breakglass_mint_host", "status_page", "control_plane"],
    "app1": ["host_inputs", "host_baseline", "breakglass_grant_host", "website_app1"],
    "db1": ["host_inputs", "host_baseline", "db1_stack", "db1_backup_timers"],
    "demo1": ["demo1_build", "demo1_egress_spool"],
}
# The play-vars lines a playbook on main carries after enrolled_host (HOST_PLAY_VARS).
PINNED_PLAY_VARS = {"edge1": "    deploy_tooling_host_class: gateway\n"}


def _entry(name: str, extra: str = "") -> str:
    return f"    - role: ../roles/{name}\n{extra}"


class TriggerEntryCountError(ValueError):
    """The playbook text does not hold exactly one pull_trigger entry."""

    def __init__(self, count: int) -> None:
        super().__init__(f"expected one pull_trigger entry, found {count}")


def _pull_roles_only(text: str) -> str:
    """A real playbook cut after its pull_trigger entry, so the roles wired after it drop away.

    The fixtures add roles of their own to this text. Built on the whole real file, a fixture
    would apply a role twice, or put it before the trigger, once the real file applies it too.

    Raises:
        TriggerEntryCountError: the text holds no pull_trigger entry, or more than one.
    """
    count = text.count(TRIGGER_ENTRY)
    if count != 1:
        raise TriggerEntryCountError(count)
    return text[: text.index(TRIGGER_ENTRY) + len(TRIGGER_ENTRY)]


class PullRolesOnly(unittest.TestCase):
    PLAYBOOK = "  roles:\n    - role: ../roles/ansible_runtime\n" + TRIGGER_ENTRY

    def test_the_roles_after_the_trigger_are_dropped(self) -> None:
        wired = self.PLAYBOOK + _entry("host_baseline") + _entry("breakglass_mint_host")
        self.assertEqual(_pull_roles_only(wired), self.PLAYBOOK)

    def test_a_playbook_ending_at_the_trigger_is_unchanged(self) -> None:
        self.assertEqual(_pull_roles_only(self.PLAYBOOK), self.PLAYBOOK)

    def test_no_trigger_entry_fails_loudly(self) -> None:
        with self.assertRaisesRegex(ValueError, "found 0"):
            _pull_roles_only("  roles:\n" + _entry("host_baseline"))

    def test_two_trigger_entries_fail_loudly(self) -> None:
        with self.assertRaisesRegex(ValueError, "found 2"):
            _pull_roles_only(self.PLAYBOOK + TRIGGER_ENTRY)


def _applied_roles(playbook: str) -> list[str]:
    """The roles after the two pull roles that a host's playbook on main already applies."""
    entries = yaml.safe_load(playbook)[0]["roles"][2:]
    return [Path(entry["role"]).name for entry in entries]


class HostRoleLists(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        shutil.copytree(ROOT / "ansible", self.root / "ansible", symlinks=True)
        self.ansible = self.root / "ansible"
        # `real` is each playbook as it is on main, with whatever it applies after the pull
        # roles. `original` is the same text cut after pull_trigger: the base every fixture
        # builds on, so a role wired into a real playbook cannot collide with a fixture's own.
        self.real = {
            host: (self.ansible / "playbooks" / f"{host}.yml").read_text(encoding="utf-8")
            for host in ENROLLED
        }
        self.original = {host: _pull_roles_only(text) for host, text in self.real.items()}
        listed = yaml.safe_load((self.ansible / HOST_ROLES_FILE).read_text(encoding="utf-8"))
        self.listed: dict[str, list[str]] = listed

    def _playbook(self, host: str, extra: str, bare: bool = False) -> None:
        """Put every enrolled playbook back to its pull roles only, then add text to one. With
        bare, that one is first stripped of the loader entry it carries, so its roles can be
        re-listed."""
        for name, text in self.original.items():
            if bare and name == host:
                text = text.replace(LOADER_ENTRY, "")
            added = extra if name == host else ""
            (self.ansible / "playbooks" / f"{name}.yml").write_text(text + added, encoding="utf-8")

    def _replace_in(self, host: str, old: str, new: str) -> None:
        """Put every enrolled playbook back to its pull roles only, then change one text in one."""
        self._playbook(host, "")
        path = self.ansible / "playbooks" / f"{host}.yml"
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text, f"the sabotage matched nothing in {host}.yml")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def _list_file(self, text: str) -> None:
        (self.ansible / HOST_ROLES_FILE).write_text(text, encoding="utf-8")

    def _findings(self, label: str) -> list[str]:
        return [finding for finding in check(self.root) if finding.startswith(label)]

    def _assert_refused(self, host: str, contains: str) -> None:
        findings = self._findings(f"R2 {host}.yml")
        self.assertTrue(
            any(contains in finding for finding in findings),
            f"expected an R2 {host}.yml finding with {contains!r}, got {check(self.root)}",
        )

    def test_the_real_tree_passes(self) -> None:
        self.assertEqual(check(ROOT), [])

    # The playbooks on main apply exactly the roles named in APPLIED_ON_MAIN after the pull roles.
    def test_the_playbooks_on_main_apply_the_expected_roles(self) -> None:
        for host in ENROLLED:
            text = (self.ansible / "playbooks" / f"{host}.yml").read_text(encoding="utf-8")
            after = text[text.index(TRIGGER_ENTRY) + len(TRIGGER_ENTRY) :]
            expected = "".join(
                f"    - role: ../roles/{name} # noqa: role-name[path]\n"
                for name in APPLIED_ON_MAIN.get(host, [])
            )
            with self.subTest(host=host):
                self.assertEqual(after, expected)

    # Safety class: the page is published by a role the owner lists. Take it off ops1's list and the
    # playbook that applies it is refused. Red with the line removed from the list, green with it.
    def test_the_status_page_needs_its_place_on_ops1_list(self) -> None:
        path = self.ansible / HOST_ROLES_FILE
        text = path.read_text(encoding="utf-8")
        self.assertIn("  - status_page\n", text, "the sabotage matched nothing")
        self.assertEqual(self._findings("R2 ops1.yml"), [])
        self._list_file(text.replace("  - status_page\n", "", 1))
        self._assert_refused("ops1", "role status_page is not on ops1's list")

    # Safety class: db1 is the production database host. It applies the two pull roles, the loader
    # of its private inputs, the host baseline, the stack, then the backup timers, and none of the
    # other roles on its list, which R9 allows because a playbook may apply a subset. Red when any
    # role is added or moved, green with the six named in this order. db1_grants is held back and
    # would have to follow the timers.
    def test_db1_applies_the_pull_roles_the_loader_the_baseline_the_stack_then_the_timers(
        self,
    ) -> None:
        text = (ROOT / "ansible" / "playbooks" / "db1.yml").read_text(encoding="utf-8")
        names = [Path(entry["role"]).name for entry in yaml.safe_load(text)[0]["roles"]]
        self.assertEqual(
            names,
            [
                "ansible_runtime",
                "pull_trigger",
                "host_inputs",
                "host_baseline",
                "db1_stack",
                "db1_backup_timers",
            ],
        )
        for held_back in ("db1_grants", "tunnel_account"):
            self.assertNotIn(held_back, names)
        self.assertEqual(check(ROOT), [])

    # edge1 applies the edge stack last: after the baseline (Docker), the CI login and the deploy
    # tooling, which installs the compose unit and deploy wrapper the stack uses. Red when the
    # stack moves earlier or is dropped, green with the six named in this order.
    def test_edge1_applies_the_edge_stack_after_the_baseline_and_the_deploy_tooling(self) -> None:
        text = (ROOT / "ansible" / "playbooks" / "edge1.yml").read_text(encoding="utf-8")
        names = [Path(entry["role"]).name for entry in yaml.safe_load(text)[0]["roles"]]
        self.assertEqual(
            names,
            [
                "ansible_runtime",
                "pull_trigger",
                "host_baseline",
                "ci_login",
                "deploy_tooling",
                "edge_stack",
            ],
        )
        self.assertEqual(check(ROOT), [])

    # Safety class: demo1 is held off host_baseline, egress_nat and broker_deploy by its own
    # list in host_roles.yml. Green first: the real playbook applies exactly the pull roles then
    # its two build roles and the real tree passes. Red: each of the three roles added to the real
    # playbook is refused by name, and with demo1's line deleted from the list both build roles are.
    def test_demo1_applies_only_its_build_roles(self) -> None:
        text = (ROOT / "ansible" / "playbooks" / "demo1.yml").read_text(encoding="utf-8")
        names = [Path(entry["role"]).name for entry in yaml.safe_load(text)[0]["roles"]]
        self.assertEqual(
            names, ["ansible_runtime", "pull_trigger", "demo1_build", "demo1_egress_spool"]
        )
        self.assertEqual(check(ROOT), [])
        for name in ("host_baseline", "egress_nat", "broker_deploy"):
            with self.subTest(role=name):
                self.assertNotIn(name, self.listed["demo1"], "the case is a role on demo1's list")
                path = self.ansible / "playbooks" / "demo1.yml"
                path.write_text(self.real["demo1"] + _entry(name), encoding="utf-8")
                self._assert_refused("demo1", f"role {name} is not on demo1's list")
        (self.ansible / "playbooks" / "demo1.yml").write_text(self.real["demo1"], encoding="utf-8")
        path = self.ansible / HOST_ROLES_FILE
        listed = path.read_text(encoding="utf-8")
        line = "demo1:\n  - demo1_build\n  - demo1_egress_spool\n"
        self.assertIn(line, listed, "the sabotage matched nothing")
        self._list_file(listed.replace(line, "", 1))
        for name in ("demo1_build", "demo1_egress_spool"):
            with self.subTest(role=name, list="deleted"):
                self._assert_refused("demo1", f"role {name} is not on demo1's list")

    # Positive control: every role on a host's list, in the list's order and in reverse, passes.
    # Most of these roles have no directory on main, so a name with no role behind it passes too.
    # The loader is the one role whose place is fixed (R11): it goes first in every order.
    def test_every_listed_role_is_accepted_for_its_host(self) -> None:
        for host in ENROLLED:
            applied = _applied_roles(self.original[host])
            roles = [name for name in self.listed[host] if name not in applied]
            for order in (roles, list(reversed(roles)), roles[:1], roles[-1:]):
                first = sorted(order, key=lambda name: name != "host_inputs")
                with self.subTest(host=host, roles=first):
                    self._playbook(host, "".join(_entry(name) for name in first), bare=True)
                    self.assertEqual(check(self.root), [])

    # Rule: a role that is on no list is refused, on each host.
    def test_an_unlisted_role_is_refused(self) -> None:
        for host, name in (
            ("edge1", "made_up"),
            ("ops1", "signer_override"),
            ("app1", "x9"),
            ("db1", "made_up"),
            ("demo1", "made_up"),
        ):
            with self.subTest(host=host, role=name):
                self._playbook(host, _entry(name))
                self._assert_refused(host, f"role {name} is not on {host}'s list")

    # Rule: a listed role carrying anything beyond `role:` is refused, whatever the key.
    def test_a_listed_role_with_other_keys_is_refused(self) -> None:
        cases = (
            ("edge1", "monitoring_stack", "      vars:\n        pull_trigger_signers: [X]\n"),
            ("edge1", "host_baseline", "      vars:\n        harmless: 1\n"),
            ("ops1", "control_plane", "      tags: [never]\n"),
            ("ops1", "host_baseline", "      when: false\n"),
            ("app1", "website_app1", "      become: false\n"),
            ("app1", "deploy_tooling", "      environment:\n        A: b\n"),
            ("app1", "host_baseline", "      delegate_to: elsewhere\n"),
            ("db1", "db1_stack", "      vars:\n        db1_stack_exporter_password: x\n"),
            ("db1", "db1_grants", "      vars:\n        db1_grants_tenants: [x]\n"),
            ("db1", "db1_grants", "      when: false\n"),
            ("demo1", "demo1_build", "      vars:\n        demo1_build_slot_names: ['0']\n"),
            ("demo1", "demo1_egress_spool", "      when: false\n"),
        )
        for host, name, extra in cases:
            with self.subTest(host=host, role=name, extra=extra):
                self._playbook(host, _entry(name, extra))
                self._assert_refused(host, "must be only `role: ../roles/NAME`")

    # Rule: a role is named as `../roles/NAME`. Another spelling of any role is refused.
    def test_a_role_spelled_another_way_is_refused(self) -> None:
        spellings = (
            "    - host_baseline\n",
            "    - role: host_baseline\n",
            "    - role: ../roles/host_baseline/../pull_trigger\n",
            "    - role: ../roles/Host_Baseline\n",
            "    - role: /srv/roles/host_baseline\n",
            "    - role: ../roles/\n",
            "    - role: [../roles/host_baseline]\n",
            "    - name: ../roles/host_baseline\n",
            "    - 7\n",
        )
        for text in spellings:
            with self.subTest(text=text):
                self._playbook("ops1", text)
                self._assert_refused("ops1", "must be only `role: ../roles/NAME`")

    # Rule: the pull roles come first and in order. A swap, a listed role first, a missing
    # runtime entry and a changed runtime variable are each refused.
    def test_the_pull_roles_must_be_first_and_in_order(self) -> None:
        runtime = (
            "    - role: ../roles/ansible_runtime # noqa: role-name[path]\n"
            "      vars:\n"
            "        ansible_runtime_requirements_src: '{{ playbook_dir }}/../requirements.txt'\n"
        )
        trigger = "    - role: ../roles/pull_trigger # noqa: role-name[path]\n"
        head = "  roles:\n"
        for host in ENROLLED:
            text = self.original[host].replace(LOADER_ENTRY, "")
            body = text[text.index(head) + len(head) :]
            self.assertTrue(body.startswith(runtime + trigger), "the sabotage matched nothing")
            # The listed roles a host's playbook applies after the pull roles (ci_login on edge1).
            tail = body[len(runtime + trigger) :]
            variants = {
                "swapped": trigger + runtime + tail,
                "listed role first": _entry("host_baseline") + runtime + trigger + tail,
                "listed role between": runtime + _entry("host_baseline") + trigger + tail,
                "runtime missing": trigger + _entry("host_baseline") + tail,
                "runtime source changed": runtime.replace("/../requirements.txt", "/x.txt")
                + trigger
                + tail,
            }
            for name, new_roles in variants.items():
                with self.subTest(host=host, variant=name):
                    self._playbook(host, "")
                    path = self.ansible / "playbooks" / f"{host}.yml"
                    path.write_text(text.replace(body, new_roles), encoding="utf-8")
                    self._assert_refused(host, "roles must start with the runtime entry")
            with self.subTest(host=host, variant="trigger missing"):
                self._playbook(host, "")
                path = self.ansible / "playbooks" / f"{host}.yml"
                path.write_text(
                    text.replace(body, runtime + _entry("host_baseline") + tail), "utf-8"
                )
                found = self._findings(f"R7 {host}.yml") + self._findings(f"R4 trust/{host}.yml")
                self.assertTrue(found, check(self.root))

    # Rule: the pull roles carry nothing. A trigger with a var, a tag or a when is refused.
    def test_the_trigger_carries_nothing(self) -> None:
        trigger = "    - role: ../roles/pull_trigger # noqa: role-name[path]\n"
        for host, extra in (
            ("edge1", "      tags: [never]\n"),
            ("ops1", "      when: false\n"),
            ("app1", "      vars:\n        harmless: 1\n"),
        ):
            with self.subTest(host=host, extra=extra):
                self._replace_in(host, trigger, trigger + extra)
                self._assert_refused(host, "roles must start with the runtime entry")

    # Rule: one play per host. A second play is refused whatever it holds, and so is no play.
    def test_a_second_play_is_refused(self) -> None:
        for host in ENROLLED:
            with self.subTest(host=host):
                self._playbook(host, SECOND_PLAY)
                self._assert_refused(host, "expected one play, found 2")
        self._playbook("edge1", "- name: Third\n  hosts: all\n  tasks: []\n" + SECOND_PLAY)
        self._assert_refused("edge1", "expected one play, found 3")

    # Rule: a play holds only the allowed keys. Every other key is refused by name, on each host,
    # because `tasks`, `post_tasks` and `handlers` can apply any role as root, and the rest can
    # change how the pinned play runs. The role in the snippets is on no host's list.
    def test_a_play_key_outside_the_allowed_set_is_refused(self) -> None:
        self.assertEqual(
            PLAY_KEYS,
            {"name", "hosts", "gather_facts", "vars", "vars_files", "pre_tasks", "roles"},
        )
        for host in ENROLLED:
            for key, text in EXTRA_PLAY_KEYS.items():
                with self.subTest(host=host, key=key):
                    self.assertNotIn(key, PLAY_KEYS, "the case is an allowed key")
                    self._playbook(host, text)
                    self._assert_refused(host, f"play key {key} is not allowed")

    # Rule: the play's `vars` is exactly `enrolled_host: HOST`. Another variable is refused whether
    # it is plain, a templated lookup that runs a command on the controller, an `ansible_*`
    # setting, or an override of a listed role's variable.
    def test_a_variable_in_the_play_vars_is_refused(self) -> None:
        lookup = "\"{{ lookup('ansible.builtin.pipe', 'id') }}\""
        extras = {
            "plain": "    harmless: 1\n",
            "templated lookup": f"    ansible_python_interpreter: {lookup}\n",
            "ansible setting": "    ansible_connection: local\n",
            "role variable": "    ansible_runtime_requirements_src: /tmp/other.txt\n",
        }
        for host in ENROLLED:
            for kind, extra in extras.items():
                with self.subTest(host=host, kind=kind):
                    line = f"    enrolled_host: {host}\n"
                    self._replace_in(host, line, line + extra)
                    self._assert_refused(host, "vars must be exactly")

    # Rule: `vars` must also still hold the host name, and nothing else when it is empty or absent.
    def test_vars_without_the_host_name_is_refused(self) -> None:
        for host in ENROLLED:
            # The whole vars block, so edge1's pinned class line goes with it (HOST_PLAY_VARS).
            line = f"  vars:\n    enrolled_host: {host}\n{PINNED_PLAY_VARS.get(host, '')}"
            for kind, new in (
                ("absent", ""),
                ("empty", "  vars: {}\n"),
                ("other", "  vars:\n    enrolled_host: x\n"),
            ):
                with self.subTest(host=host, kind=kind):
                    self._replace_in(host, line, new)
                    self._assert_refused(host, "vars must be exactly")

    # Rule: every refused key in the play gets its own finding.
    def test_each_refused_play_key_gets_its_own_finding(self) -> None:
        self._playbook("edge1", EXTRA_PLAY_KEYS["tasks"] + EXTRA_PLAY_KEYS["post_tasks"])
        findings = self._findings("R2 edge1.yml")
        for key in ("tasks", "post_tasks"):
            self.assertTrue(
                any(f"play key {key} is not allowed" in finding for finding in findings),
                findings,
            )

    # Rule: pre_tasks is exactly the refusal include then the signer include. No role loader or
    # task-file loader is added after them or put in place of either.
    def test_pre_tasks_cannot_carry_a_loader(self) -> None:
        for host in ENROLLED:
            for loader, body in LOADERS.items():
                with self.subTest(host=host, loader=loader, where="appended"):
                    extra = f"    - name: Extra\n      ansible.builtin.{loader}:{body}"
                    self._replace_in(host, SIGNER_LINE, SIGNER_LINE + extra)
                    self._assert_refused(host, "pre_tasks must be exactly")
                for old in (REFUSE_LINE, SIGNER_LINE):
                    with self.subTest(host=host, loader=loader, where="replacing", old=old):
                        self._replace_in(host, old, f"      ansible.builtin.{loader}:{body}")
                        self._assert_refused(host, "pre_tasks must be exactly")

    # Rule: a role on another host's list is refused. host_baseline is on several lists, so each
    # case uses a role that is on no list of the host it is added to.
    def test_a_role_on_another_hosts_list_is_refused(self) -> None:
        cases = (
            ("edge1", "db1_stack"),
            ("edge1", "tunnel_account"),
            ("ops1", "deploy_tooling"),
            ("ops1", "monitoring_stack"),
            ("app1", "breakglass_mint_host"),
            ("app1", "control_plane"),
            ("ops1", "db1_stack"),
            ("db1", "control_plane"),
            ("db1", "egress_nat"),
            ("demo1", "host_baseline"),
            ("demo1", "control_plane"),
        )
        for host, name in cases:
            with self.subTest(host=host, role=name):
                self.assertNotIn(name, self.listed[host], "the case is not another host's role")
                self._playbook(host, _entry(name))
                self._assert_refused(host, f"role {name} is not on {host}'s list")

    # Rule: the roles a real playbook applies after the pull roles are held to the list too. The
    # fixtures above cut the real file after pull_trigger, so this is the case that keeps the
    # real wired tail under test: the whole real file, plus one role from another host's list.
    def test_an_off_list_role_after_the_wired_roles_is_refused(self) -> None:
        cases = (("ops1", "egress_nat"), ("edge1", "tunnel_account"), ("app1", "control_plane"))
        for host, name in cases:
            with self.subTest(host=host, role=name):
                self.assertNotIn(name, self.listed[host], "the case is not another host's role")
                for other, text in self.real.items():
                    (self.ansible / "playbooks" / f"{other}.yml").write_text(text, "utf-8")
                self.assertEqual(check(self.root), [], "the real playbooks must pass first")
                path = self.ansible / "playbooks" / f"{host}.yml"
                path.write_text(self.real[host] + _entry(name), encoding="utf-8")
                self._assert_refused(host, f"role {name} is not on {host}'s list")

    # Rule: a role is applied once. The pull roles are never listed, so they cannot be added back.
    def test_a_role_applied_twice_is_refused(self) -> None:
        self._playbook("edge1", _entry("host_baseline") + _entry("host_baseline"))
        self._assert_refused("edge1", "role host_baseline is applied twice")
        for name in ("pull_trigger", "ansible_runtime"):
            with self.subTest(role=name):
                self._playbook("ops1", _entry(name))
                self._assert_refused("ops1", f"role {name} is not on ops1's list")

    # Rule: a host with no entry in the list gets the pull roles and nothing else.
    def test_a_host_with_no_list_gets_only_the_pull_roles(self) -> None:
        trust = "---\npull_trigger_signers: []\n"
        new = self.original["ops1"].replace("ops1", "mx9")
        for extra, passes in (("", True), (_entry("host_baseline"), False)):
            with self.subTest(extra=extra):
                (self.ansible / "playbooks" / "mx9.yml").write_text(new + extra, encoding="utf-8")
                (self.ansible / "trust" / "mx9.yml").write_text(trust, encoding="utf-8")
                found = self._findings("R2 mx9.yml")
                self.assertEqual(found == [], passes, found)

    # R9: the list file must exist and be well formed, or no host gets a role beyond the pull roles.
    def test_a_missing_list_file_refuses_every_extra_role(self) -> None:
        (self.ansible / HOST_ROLES_FILE).unlink()
        self._playbook("edge1", _entry("host_baseline"))
        self.assertTrue(any(f.startswith("R9") for f in check(self.root)), check(self.root))
        self._assert_refused("edge1", "role host_baseline is not on edge1's list")

    def test_a_malformed_list_file_is_refused(self) -> None:
        bad_files = (
            "- edge1\n- ops1\n",
            "edge1: host_baseline\n",
            "edge1: [pull_trigger]\n",
            "edge1: [ansible_runtime, host_baseline]\n",
            "edge1: [host_baseline, host_baseline]\n",
            "edge1: ['../roles/host_baseline']\n",
            "edge1: [Host_Baseline]\n",
            "edge1: [1]\n",
            "Edge1: [host_baseline]\n",
            "edge1: [host_baseline\n",
            "",
        )
        for text in bad_files:
            with self.subTest(text=text):
                self._list_file(text)
                self._playbook("edge1", _entry("host_baseline"))
                findings = check(self.root)
                self.assertTrue(any(f.startswith("R9") for f in findings), findings)
                self._assert_refused("edge1", "role host_baseline is not on edge1's list")

    # Control: one bad host in the list does not take the others' lists with it.
    def test_one_bad_entry_does_not_refuse_another_hosts_roles(self) -> None:
        self._list_file("edge1: [pull_trigger]\nops1: [control_plane]\n")
        self._playbook("ops1", _entry("control_plane"))
        self.assertEqual(self._findings("R2 ops1.yml"), [])
        self.assertTrue(any(f.startswith("R9") for f in check(self.root)))

    # The scan that no role sets the trust settings still runs on a role named in a list.
    def test_a_listed_role_that_sets_the_signers_is_still_refused(self) -> None:
        self._playbook("edge1", _entry("host_baseline"))
        self.assertEqual(check(self.root), [])
        task = self.ansible / "roles" / "host_baseline" / "tasks" / "extra.yml"
        task.write_text(
            "---\n- name: Trust a key\n  ansible.builtin.set_fact:\n"
            "    pull_trigger_signers: [ATTACKERFPR]\n",
            encoding="utf-8",
        )
        findings = check(self.root)
        self.assertTrue(
            any(f.startswith("R6 ansible/roles/host_baseline/tasks/extra.yml") for f in findings),
            findings,
        )


if __name__ == "__main__":
    unittest.main()
