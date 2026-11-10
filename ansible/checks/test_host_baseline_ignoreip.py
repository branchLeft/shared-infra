"""host_baseline's fail2ban ignore list may be empty, and an empty list writes no ignore line.

The role's one input, host_baseline_fail2ban_ignoreip, defaults to loopback and edge1's private
address. A host outside the estate's network sets it to the empty text in its owner_vars file
(mx1 does), and its jail then has to be the jail it already carries: the same lines and no
`ignoreip` line. This file holds the three parts of that to the role's own files:

  * the template renders the default input to the same jail as before;
  * the template renders the empty input with no ignoreip line at all;
  * the role's assert accepts the empty text and still refuses a newline, a host name and any
    other character outside hex digits, colon, dot, slash and space.

The assert's pattern is read out of the task file and applied with the same `re.match` the
`match` test of Ansible uses, so a loosened or tightened pattern in the role changes the result
here.
"""

from __future__ import annotations

import re
import unittest

import jinja2
import yaml  # type: ignore[import-untyped]
from check_enrolment import ROOT

ROLE = ROOT / "ansible" / "roles" / "host_baseline"
INPUT = "host_baseline_fail2ban_ignoreip"
DEFAULT = "127.0.0.1/8 ::1 10.20.1.10"
ASSERT_NAME = "Refuse an ignore list that is not one line of addresses"
PATTERN = re.compile(r"is ansible\.builtin\.match\('(?P<pattern>[^']+)'\)")

JAIL_WITHOUT_IGNORE = (
    "[sshd]\nenabled = true\nport = ssh\nbackend = systemd\nmaxretry = 5\nfindtime = 10m\n"
    "bantime = 1h\n"
)


def _render_jail(value: str) -> str:
    """Return the jail the template renders for the input, as Ansible's template module does.

    The module's defaults are trim_blocks on, lstrip_blocks off and the final newline kept.
    """
    environment = jinja2.Environment(  # noqa: S701
        trim_blocks=True,
        lstrip_blocks=False,
        keep_trailing_newline=True,
        undefined=jinja2.StrictUndefined,
    )
    text = (ROLE / "templates" / "jail.local.j2").read_text(encoding="utf-8")
    return environment.from_string(text).render({INPUT: value})


def _assert_pattern() -> str:
    """Return the regular expression the role's ignore-list assert applies.

    Raises:
        AssertionError: the task is missing, or does not apply one match pattern.
    """
    tasks = yaml.safe_load((ROLE / "tasks" / "_updates_fail2ban.yml").read_text(encoding="utf-8"))
    named = [task for task in tasks if task.get("name") == ASSERT_NAME]
    if len(named) != 1:
        message = f"expected one task named {ASSERT_NAME!r}, found {len(named)}"
        raise AssertionError(message)
    conditions = named[0]["ansible.builtin.assert"]["that"]
    found = [PATTERN.search(condition) for condition in conditions]
    patterns = [match["pattern"] for match in found if match is not None]
    if len(patterns) != 1:
        message = f"expected one match pattern in the assert, found {len(patterns)}"
        raise AssertionError(message)
    return patterns[0]


def _accepts(value: str) -> bool:
    return re.match(_assert_pattern(), value) is not None


class JailTemplate(unittest.TestCase):
    def test_the_default_input_renders_the_jail_with_its_ignore_line(self) -> None:
        self.assertEqual(
            _render_jail(DEFAULT),
            JAIL_WITHOUT_IGNORE + f"ignoreip = {DEFAULT}\n",
        )

    def test_the_empty_input_renders_the_jail_with_no_ignore_line(self) -> None:
        self.assertEqual(_render_jail(""), JAIL_WITHOUT_IGNORE)

    def test_the_default_in_the_role_is_the_one_this_file_pins(self) -> None:
        defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
        self.assertEqual(defaults[INPUT], DEFAULT)


class IgnoreListAssert(unittest.TestCase):
    def test_the_empty_text_is_accepted(self) -> None:
        self.assertTrue(_accepts(""))

    def test_the_default_and_other_address_lists_are_accepted(self) -> None:
        for value in (DEFAULT, "10.0.0.1", "2001:db8::/32 192.0.2.0/24"):
            with self.subTest(value=value):
                self.assertTrue(_accepts(value))

    def test_a_second_line_is_refused(self) -> None:
        for value in (DEFAULT + "\n", "10.0.0.1\nbantime = 0", "\n"):
            with self.subTest(value=value):
                self.assertFalse(_accepts(value))

    def test_a_host_name_or_other_character_is_refused(self) -> None:
        for value in ("example.org", "10.0.0.1;", "10.0.0.1 # x", "10.0.0.1\t10.0.0.2"):
            with self.subTest(value=value):
                self.assertFalse(_accepts(value))


if __name__ == "__main__":
    unittest.main()
