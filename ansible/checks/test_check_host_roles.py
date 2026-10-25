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
from check_enrolment import HOST_ROLES_FILE, ROOT, check

ENROLLED = ("edge1", "ops1", "app1")
SECOND_PLAY = "- name: Second play\n  hosts: all\n  roles:\n    - role: ../roles/host_baseline\n"


def _entry(name: str, extra: str = "") -> str:
    return f"    - role: ../roles/{name}\n{extra}"


class HostRoleLists(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        shutil.copytree(ROOT / "ansible", self.root / "ansible", symlinks=True)
        self.ansible = self.root / "ansible"
        self.original = {
            host: (self.ansible / "playbooks" / f"{host}.yml").read_text(encoding="utf-8")
            for host in ENROLLED
        }
        listed = yaml.safe_load((self.ansible / HOST_ROLES_FILE).read_text(encoding="utf-8"))
        self.listed: dict[str, list[str]] = listed

    def _playbook(self, host: str, extra: str) -> None:
        """Put every enrolled playbook back as it is on main, then add text to one."""
        for name, text in self.original.items():
            added = extra if name == host else ""
            (self.ansible / "playbooks" / f"{name}.yml").write_text(text + added, encoding="utf-8")

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

    # Positive control: every role on a host's list, in the list's order and in reverse, passes.
    # Most of these roles have no directory on main, so a name with no role behind it passes too.
    def test_every_listed_role_is_accepted_for_its_host(self) -> None:
        for host in ENROLLED:
            roles = self.listed[host]
            for order in (roles, list(reversed(roles)), roles[:1], roles[-1:]):
                with self.subTest(host=host, roles=order):
                    self._playbook(host, "".join(_entry(name) for name in order))
                    self.assertEqual(check(self.root), [])

    # Rule: a role that is on no list is refused, on each host.
    def test_an_unlisted_role_is_refused(self) -> None:
        for host, name in (("edge1", "made_up"), ("ops1", "signer_override"), ("app1", "x9")):
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
            text = self.original[host]
            body = text[text.index(head) + len(head) :]
            self.assertEqual(runtime + trigger, body, "the sabotage matched nothing")
            variants = {
                "swapped": trigger + runtime,
                "listed role first": _entry("host_baseline") + runtime + trigger,
                "listed role between": runtime + _entry("host_baseline") + trigger,
                "runtime missing": trigger + _entry("host_baseline"),
                "runtime source changed": runtime.replace("/../requirements.txt", "/x.txt")
                + trigger,
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
                path.write_text(text.replace(body, runtime + _entry("host_baseline")), "utf-8")
                found = self._findings(f"R7 {host}.yml") + self._findings(f"R4 trust/{host}.yml")
                self.assertTrue(found, check(self.root))

    # Rule: the pull roles carry nothing. A trigger with a var, a tag or a when is refused.
    def test_the_trigger_carries_nothing(self) -> None:
        for host, extra in (
            ("edge1", "      tags: [never]\n"),
            ("ops1", "      when: false\n"),
            ("app1", "      vars:\n        harmless: 1\n"),
        ):
            with self.subTest(host=host, extra=extra):
                self._playbook(host, extra)
                self._assert_refused(host, "roles must start with the runtime entry")

    # Rule: one play per host. A second play is refused whatever it holds, and so is no play.
    def test_a_second_play_is_refused(self) -> None:
        for host in ENROLLED:
            with self.subTest(host=host):
                self._playbook(host, SECOND_PLAY)
                self._assert_refused(host, "expected one play, found 2")
        self._playbook("edge1", "- name: Third\n  hosts: all\n  tasks: []\n" + SECOND_PLAY)
        self._assert_refused("edge1", "expected one play, found 3")

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
        )
        for host, name in cases:
            with self.subTest(host=host, role=name):
                self.assertNotIn(name, self.listed[host], "the case is not another host's role")
                self._playbook(host, _entry(name))
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
