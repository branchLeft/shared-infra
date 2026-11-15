"""mx1's playbook applies the mail host's three roles in the order they depend on, and no further.

check_enrolment.py (R2, R9) holds a playbook to the host's list in host_roles/<host>.yml but leaves the
order after the pull roles free. For the mail host the order carries meaning, so this file pins
it, and pins what keeps the mail reconcilers' steps off:

  * host_baseline first, because mx1_stack needs the Docker it installs;
  * mx1_stack before mail_reconcilers, the order the mail host has always been provisioned in;
  * the same three roles, in the same order, are mx1's file in host_roles/;
  * mx1_stack and mail_reconcilers are on no other host's row, because both are written for the
    mail host's paths and nothing else;
  * the host has no owner_vars file, so no step allow-list can reach mail_reconcilers through
    the pull.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]
from check_enrolment import ROOT, read_host_roles_raw

ANSIBLE = ROOT / "ansible"
PULL_ROLES = 2
MX1_ROLES = ["host_baseline", "mx1_stack", "mail_reconcilers"]
MAIL_ONLY = ("mx1_stack", "mail_reconcilers")

Rows = dict[str, list[str]]


def _text_of(relative: str) -> str:
    return (ANSIBLE / relative).read_text(encoding="utf-8")


def _applied_after_the_pull_roles() -> list[str]:
    plays = cast(
        list[dict[str, list[dict[str, str]]]], yaml.safe_load(_text_of("playbooks/mx1.yml"))
    )
    return [Path(entry["role"]).name for entry in plays[0]["roles"][PULL_ROLES:]]


def _host_roles() -> Rows:
    return cast(Rows, read_host_roles_raw(ANSIBLE))


class Mx1Playbook(unittest.TestCase):
    def test_the_playbook_applies_the_three_roles_in_order(self) -> None:
        self.assertEqual(_applied_after_the_pull_roles(), MX1_ROLES)

    def test_host_roles_lists_the_same_three(self) -> None:
        self.assertEqual(_host_roles()["mx1"], MX1_ROLES)

    def test_the_two_mail_roles_are_on_no_other_hosts_row(self) -> None:
        for host, roles in _host_roles().items():
            if host != "mx1":
                for role in MAIL_ONLY:
                    with self.subTest(host=host, role=role):
                        self.assertNotIn(role, roles)

    def test_no_playbook_but_mx1_applies_a_mail_role(self) -> None:
        for path in sorted((ANSIBLE / "playbooks").glob("*.yml")):
            if path.stem == "mx1":
                continue
            text = path.read_text(encoding="utf-8")
            for role in MAIL_ONLY:
                with self.subTest(playbook=path.name, role=role):
                    self.assertNotIn(f"../roles/{role}", text)

    def test_the_host_has_no_owner_file_so_no_step_can_be_requested(self) -> None:
        self.assertFalse((ANSIBLE / "owner_vars" / "mx1.yml").exists())
        self.assertNotIn("owner_vars", _text_of("playbooks/mx1.yml").replace("owner_vars file", ""))


if __name__ == "__main__":
    unittest.main()
