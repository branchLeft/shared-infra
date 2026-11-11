"""host_baseline's files are the bytes the provisioning scripts wrote on the hosts they built.

The scripts 00-harden-ssh.sh, 10-harden-updates-fail2ban.sh and 20-install-docker.sh built the
baseline on edge1, edget and db1. The role converges the same state from its own copies of the
files, so each copy must equal the heredoc the script writes, byte for byte, and the Docker apt
line the template renders must equal the line the script writes for amd64 on trixie. Without this
test the role's README claim that the two agree is only a claim. Each pin is red on a sabotaged
copy and green on the copy left alone.
"""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

import check_enrolment
import jinja2  # type: ignore[import-untyped]
import yaml  # type: ignore[import-untyped]
from check_enrolment import ROOT

PROVISION = ROOT / "hetzner" / "provision"
ROLE = ROOT / "ansible" / "roles" / "host_baseline"
HEREDOC_OPEN = "cat > \"$TMP\" <<'EOF'"
HEREDOC_CLOSE = "EOF"
DOCKER_ARCH = "amd64"
DOCKER_CODENAME = "trixie"
TEMPLATE_ARCH = "{{ host_baseline_docker_arch }}"
TEMPLATE_CODENAME = "{{ ansible_facts['distribution_release'] }}"

# Each role file, the script it was written by and the position of its heredoc in that script.
# The heredocs are numbered in the order the script writes them, counted from zero.
PAIRS = (
    ("files/01-branchleft-hardening.conf", "00-harden-ssh.sh", 0),
    ("files/20auto-upgrades", "10-harden-updates-fail2ban.sh", 0),
    ("files/51branchleft-unattended-origins", "10-harden-updates-fail2ban.sh", 1),
)

# The jail is a template now: its ignoreip value is the role input, so the test compares the
# script's jail heredoc with the template rendered at the role's default input.
JAIL_SCRIPT = "10-harden-updates-fail2ban.sh"
JAIL_POSITION = 2
JAIL_INPUT = "host_baseline_fail2ban_ignoreip"
JAIL_NONE_INPUT = "host_baseline_fail2ban_ignoreip_none"


def _heredocs(script: Path) -> list[str]:
    """Return the body of each heredoc that writes $TMP, in the order the script writes them.

    Raises:
        AssertionError: a heredoc is not closed before the end of the script.
    """
    lines = script.read_text(encoding="utf-8").splitlines(keepends=True)
    bodies: list[str] = []
    index = 0
    while index < len(lines):
        if lines[index].rstrip("\n") != HEREDOC_OPEN:
            index += 1
            continue
        body: list[str] = []
        index += 1
        while index < len(lines) and lines[index].rstrip("\n") != HEREDOC_CLOSE:
            body.append(lines[index])
            index += 1
        if index >= len(lines):
            message = f"{script.name}: a heredoc is not closed by EOF"
            raise AssertionError(message)
        bodies.append("".join(body))
        index += 1
    return bodies


def _script_value(script: Path, name: str) -> str:
    """Return the value of a plain `NAME=value` assignment in the script.

    Raises:
        AssertionError: the script does not assign the name.
    """
    prefix = f"{name}="
    for line in script.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    message = f"{script.name}: no assignment of {name}"
    raise AssertionError(message)


def _docker_line_of_script() -> str:
    """Return the apt source line 20-install-docker.sh writes, with its variables filled in.

    Raises:
        AssertionError: the script has no `want_list=` line.
    """
    script = PROVISION / "20-install-docker.sh"
    for line in script.read_text(encoding="utf-8").splitlines():
        if line.startswith('want_list="') and line.endswith('"'):
            want = line[len('want_list="') : -1]
            return (
                want.replace("${arch}", DOCKER_ARCH)
                .replace("${KEYRING}", _script_value(script, "KEYRING"))
                .replace("${codename}", DOCKER_CODENAME)
            )
    message = f"{script.name}: no want_list line"
    raise AssertionError(message)


def _rendered_docker_line() -> str:
    """Return the apt source line the role's template renders for amd64 on trixie.

    Raises:
        AssertionError: the template holds a placeholder the test does not fill.
    """
    text = (ROLE / "templates" / "docker.list.j2").read_text(encoding="utf-8")
    rendered = text.replace(TEMPLATE_ARCH, DOCKER_ARCH).replace(TEMPLATE_CODENAME, DOCKER_CODENAME)
    if "{{" in rendered:
        message = "docker.list.j2 holds a placeholder this test does not fill"
        raise AssertionError(message)
    return rendered


def _role_default(name: str) -> str:
    """Return the value of a plain `name: value` line in the role's defaults.

    Raises:
        AssertionError: the defaults do not assign the name.
    """
    prefix = f"{name}: "
    for line in (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    message = f"defaults/main.yml: no default of {name}"
    raise AssertionError(message)


def _rendered_jail(ignoreip_none: bool = False) -> str:
    """Return the jail the template renders at the role's default ignoreip input.

    The template holds a Jinja block (the opt-out), so it is rendered with Jinja, with the
    trim settings Ansible's template module uses, and no variable is left undefined.
    """
    env = jinja2.Environment(  # noqa: S701 - a plain-text template, not HTML
        trim_blocks=True,
        keep_trailing_newline=True,
        undefined=jinja2.StrictUndefined,
    )
    text = (ROLE / "templates" / "jail.local.j2").read_text(encoding="utf-8")
    variables = {
        JAIL_INPUT: _role_default(JAIL_INPUT),
        JAIL_NONE_INPUT: ignoreip_none,
    }
    return env.from_string(text).render(variables)


class HostBaselineMatchesScripts(unittest.TestCase):
    def test_each_role_file_is_byte_for_byte_its_script_heredoc(self) -> None:
        for relative, script_name, position in PAIRS:
            with self.subTest(file=relative, script=script_name):
                bodies = _heredocs(PROVISION / script_name)
                self.assertGreater(
                    len(bodies),
                    position,
                    f"{script_name} writes fewer than {position + 1} heredocs",
                )
                expected = bodies[position].encode("utf-8")
                actual = (ROLE / relative).read_bytes()
                self.assertEqual(
                    actual,
                    expected,
                    f"{relative} differs from heredoc {position} of {script_name}",
                )

    def test_the_jail_template_renders_to_the_scripts_heredoc_at_the_default_input(self) -> None:
        bodies = _heredocs(PROVISION / JAIL_SCRIPT)
        self.assertGreater(len(bodies), JAIL_POSITION)
        self.assertEqual(
            _rendered_jail(),
            bodies[JAIL_POSITION],
            "templates/jail.local.j2 at the default host_baseline_fail2ban_ignoreip "
            "differs from the script heredoc",
        )

    def test_the_script_writes_no_heredoc_the_role_does_not_carry(self) -> None:
        # The role carries one file per heredoc of the two scripts, and no other.
        self.assertEqual(len(_heredocs(PROVISION / "00-harden-ssh.sh")), 1)
        self.assertEqual(len(_heredocs(PROVISION / "10-harden-updates-fail2ban.sh")), 3)

    def test_the_docker_apt_line_renders_to_the_scripts_line_for_amd64_trixie(self) -> None:
        self.assertEqual(_rendered_docker_line(), _docker_line_of_script() + "\n")


MAIL_PROVISION = ROOT / "mail" / "provision"
MX1_JAIL_SHA256 = "51f4f2f5249a0daeb4f056185a2c8ebe47c58e28dbf922b7577b0c10eb40b257"
MX1_DROPIN_SHA256 = "6a481602fc503d4709e3c7ea43630e3c3c66cb6b91cc4709202163f213122bf8"
MX1_PLAYBOOK = ROOT / "ansible" / "playbooks" / "mx1.yml"
ASSERT_TASKS = ROLE / "tasks" / "_updates_fail2ban.yml"
ARGUMENT_SPECS = ROLE / "meta" / "argument_specs.yml"
OPT_OUT_KEY = "host_baseline_fail2ban_ignoreip_none"
IGNOREIP_PATTERN = "^[0-9A-Fa-f:./ ]+\\Z"


class Mx1OptOut(unittest.TestCase):
    """The mx1 jail is the mail script's jail: no ignoreip line, and the opt-out writes that.

    The mail host's scripts wrote the jail with no ignore list and the sshd drop-in as 99-.
    The role writes the same bytes as 01-, so mx1 holds an identical duplicate it keeps (the
    accepted duplicate is left in place). Each pin is red on a sabotaged template or task and
    green on the copy left alone.
    """

    def test_the_opt_out_renders_the_mail_scripts_jail_byte_for_byte(self) -> None:
        # The mail script writes two heredocs: the auto-upgrades file, then the jail (position 1).
        bodies = _heredocs(MAIL_PROVISION / "10-harden-updates-fail2ban.sh")
        self.assertEqual(len(bodies), 2)
        rendered = _rendered_jail(ignoreip_none=True)
        self.assertEqual(rendered, bodies[1])
        self.assertEqual(hashlib.sha256(rendered.encode("utf-8")).hexdigest(), MX1_JAIL_SHA256)

    def test_the_default_keeps_the_ignore_list_line(self) -> None:
        rendered = _rendered_jail(ignoreip_none=False)
        self.assertIn("ignoreip = " + _role_default(JAIL_INPUT) + "\n", rendered)

    def test_the_mail_sshd_drop_in_is_the_role_file_under_its_own_name(self) -> None:
        bodies = _heredocs(MAIL_PROVISION / "00-harden-ssh.sh")
        self.assertEqual(len(bodies), 1)
        role_file = (ROLE / "files" / "01-branchleft-hardening.conf").read_bytes()
        self.assertEqual(role_file, bodies[0].encode("utf-8"))
        self.assertEqual(hashlib.sha256(role_file).hexdigest(), MX1_DROPIN_SHA256)

    def test_the_ignore_list_is_asserted_on_every_host(self) -> None:
        # The assert has no `when`, so an empty input refuses whether or not the opt-out is set.
        tasks = yaml.safe_load(ASSERT_TASKS.read_text(encoding="utf-8"))
        asserts = [
            task
            for task in tasks
            if "ansible.builtin.assert" in task
            and "ignoreip" in str(task["ansible.builtin.assert"])
        ]
        self.assertEqual(len(asserts), 1)
        self.assertNotIn("when", asserts[0])
        expressions = asserts[0]["ansible.builtin.assert"]["that"]
        self.assertTrue(any(IGNOREIP_PATTERN in str(item) for item in expressions), expressions)

    def test_the_pattern_refuses_an_empty_ignore_list(self) -> None:
        self.assertIsNone(re.match(IGNOREIP_PATTERN, ""))

    def test_the_opt_out_is_declared_as_a_boolean_defaulting_to_false(self) -> None:
        specs = yaml.safe_load(ARGUMENT_SPECS.read_text(encoding="utf-8"))
        option = specs["argument_specs"]["main"]["options"][OPT_OUT_KEY]
        self.assertEqual(option["type"], "bool")
        self.assertIs(option["default"], False)

    def test_mx1_is_enrolled_and_the_opt_out_is_pinned_in_the_enrolment_check(self) -> None:
        # R2 holds the play's vars to exactly HOST_PLAY_VARS, so the playbook and the pin agree.
        play = yaml.safe_load(MX1_PLAYBOOK.read_text(encoding="utf-8"))[0]
        self.assertEqual(play["vars"], {"enrolled_host": "mx1", OPT_OUT_KEY: True})
        self.assertIs(check_enrolment.HOST_PLAY_VARS["mx1"][OPT_OUT_KEY], True)


if __name__ == "__main__":
    unittest.main()
