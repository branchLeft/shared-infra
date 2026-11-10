"""Check that a host which runs the deploy verifier also runs the deploy tooling.

The verifier checks images for the deploy wrapper, and the deploy_tooling role is the only role
that installs the wrapper and the compose template unit. A host that applies the verifier and not
the tooling gets its wrapper and unit from the hand-run installer, so a change to either reaches
it by hand, or not at all. This file holds each host's list in checks/host_roles.yml, and each
host's playbook, to the pair. A host is exempt only by a named entry in EXEMPT_HOSTS with its
reason, and an entry for a host that does not need it is itself a finding, so the list cannot go
stale. Each check returns the findings it made; the tests run it on the real files (none) and on
copies with one edit (the finding).
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from check_enrolment import HOST_ROLES_FILE, ROOT

ANSIBLE = ROOT / "ansible"
VERIFIER = "deploy_verifier"
TOOLING = "deploy_tooling"
# A host that applies the verifier without the tooling, with the reason. Empty: none is exempt.
EXEMPT_HOSTS: dict[str, str] = {}


def _lists(text: str) -> dict[str, list[str]]:
    """Return each host's role list from the text of host_roles.yml.

    Raises:
        TypeError: the file is not a mapping of lists.
    """
    document: object = yaml.safe_load(text)
    if not isinstance(document, dict):
        message = f"{HOST_ROLES_FILE} is not a mapping"
        raise TypeError(message)
    found: dict[str, list[str]] = {}
    for host, roles in document.items():
        if not isinstance(roles, list):
            message = f"{host}'s entry in {HOST_ROLES_FILE} is not a list"
            raise TypeError(message)
        found[str(host)] = [str(role) for role in roles]
    return found


def _playbook_roles(text: str) -> list[str]:
    """Return the role names a playbook applies, in order.

    Raises:
        TypeError: the playbook is not a list of plays.
    """
    document: object = yaml.safe_load(text)
    if not isinstance(document, list):
        message = "the playbook is not a list of plays"
        raise TypeError(message)
    names: list[str] = []
    for play in document:
        roles = play.get("roles") if isinstance(play, dict) else None
        for entry in roles if isinstance(roles, list) else []:
            value = entry.get("role") if isinstance(entry, dict) else entry
            if value:
                names.append(Path(str(value)).name)
    return names


def findings_for(source: str, roles: list[str], exempt: dict[str, str], host: str) -> list[str]:
    """Return a finding for a host that has the verifier and not the tooling, or a stale exemption.

    ``source`` names where the roles were read (the list file or the playbook).
    """
    has_pair = VERIFIER in roles and TOOLING in roles
    if VERIFIER in roles and TOOLING not in roles and host not in exempt:
        return [f"{host} applies {VERIFIER} and not {TOOLING} ({source})"]
    if host in exempt and (has_pair or VERIFIER not in roles):
        return [f"{host} is exempt from the pair but does not need it ({source})"]
    return []


def listed_findings(listed: dict[str, list[str]], exempt: dict[str, str]) -> list[str]:
    """Return the findings for every host in host_roles.yml, and for an exempt host not in it."""
    found: list[str] = []
    for host, roles in sorted(listed.items()):
        found.extend(findings_for(HOST_ROLES_FILE, roles, exempt, host))
    found.extend(
        f"{host} is exempt from the pair but is not in {HOST_ROLES_FILE}"
        for host in sorted(set(exempt) - set(listed))
    )
    return found


def playbook_findings(playbooks: dict[str, str], exempt: dict[str, str]) -> list[str]:
    """Return the findings for every playbook, keyed by the host it belongs to."""
    found: list[str] = []
    for host, text in sorted(playbooks.items()):
        found.extend(findings_for(f"playbooks/{host}.yml", _playbook_roles(text), exempt, host))
    return found


def _real_playbooks() -> dict[str, str]:
    return {
        path.stem: path.read_text(encoding="utf-8")
        for path in sorted((ANSIBLE / "playbooks").glob("*.yml"))
    }


class TestRealTree(unittest.TestCase):
    """The files as they stand have no host with the verifier and without the tooling."""

    def test_every_listed_host_with_the_verifier_has_the_tooling(self) -> None:
        text = (ANSIBLE / HOST_ROLES_FILE).read_text(encoding="utf-8")
        self.assertEqual(listed_findings(_lists(text), EXEMPT_HOSTS), [])

    def test_every_playbook_with_the_verifier_has_the_tooling(self) -> None:
        self.assertEqual(playbook_findings(_real_playbooks(), EXEMPT_HOSTS), [])

    def test_the_pair_is_not_vacuous(self) -> None:
        # A check over no host proves nothing: at least the five wrapper hosts carry the pair.
        text = (ANSIBLE / HOST_ROLES_FILE).read_text(encoding="utf-8")
        paired = {h for h, roles in _lists(text).items() if VERIFIER in roles and TOOLING in roles}
        self.assertGreaterEqual(paired, {"edge1", "app1", "ops1", "db1", "dbt1"})


class TestControls(unittest.TestCase):
    """Each way of leaving a host with the verifier and no tooling is found."""

    def setUp(self) -> None:
        self.text = (ANSIBLE / HOST_ROLES_FILE).read_text(encoding="utf-8")
        self.listed = _lists(self.text)

    def test_a_list_with_the_tooling_removed_is_found(self) -> None:
        # Sabotage: the tooling taken off ops1's list, as it stood before it was assigned.
        broken = {**self.listed, "ops1": [r for r in self.listed["ops1"] if r != TOOLING]}
        self.assertEqual(
            listed_findings(broken, EXEMPT_HOSTS),
            [f"ops1 applies {VERIFIER} and not {TOOLING} ({HOST_ROLES_FILE})"],
        )

    def test_a_playbook_with_the_tooling_removed_is_found(self) -> None:
        playbooks = _real_playbooks()
        entry = f"    - role: ../roles/{TOOLING} # noqa: role-name[path]\n"
        self.assertIn(entry, playbooks["dbt1"])
        playbooks["dbt1"] = playbooks["dbt1"].replace(entry, "", 1)
        self.assertEqual(
            playbook_findings(playbooks, EXEMPT_HOSTS),
            [f"dbt1 applies {VERIFIER} and not {TOOLING} (playbooks/dbt1.yml)"],
        )

    def test_a_named_exemption_clears_the_finding(self) -> None:
        broken = {**self.listed, "db1": [r for r in self.listed["db1"] if r != TOOLING]}
        self.assertEqual(listed_findings(broken, {"db1": "reason"}), [])

    def test_an_exemption_for_a_host_that_has_the_pair_is_found(self) -> None:
        self.assertEqual(
            listed_findings(self.listed, {"edge1": "reason"}),
            [f"edge1 is exempt from the pair but does not need it ({HOST_ROLES_FILE})"],
        )

    def test_an_exemption_for_a_host_not_listed_is_found(self) -> None:
        self.assertEqual(
            listed_findings(self.listed, {"mx9": "reason"}),
            [f"mx9 is exempt from the pair but is not in {HOST_ROLES_FILE}"],
        )

    def test_a_host_with_neither_role_is_no_finding(self) -> None:
        self.assertEqual(findings_for("x", ["host_baseline"], EXEMPT_HOSTS, "demo1"), [])


if __name__ == "__main__":
    unittest.main()
