"""host_baseline's files are the bytes the provisioning scripts wrote on the hosts they built.

The scripts 00-harden-ssh.sh, 10-harden-updates-fail2ban.sh and 20-install-docker.sh built the
baseline on edge1, edget and db1. The role converges the same state from its own copies of the
files, so each copy must equal the heredoc the script writes, byte for byte, and the Docker apt
line the template renders must equal the line the script writes for amd64 on trixie. Without this
test the role's README claim that the two agree is only a claim. Each pin is red on a sabotaged
copy and green on the copy left alone.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from check_enrolment import ROOT

PROVISION = ROOT / "hetzner" / "provision"
ROLE = ROOT / "ansible" / "roles" / "host_baseline"
HEREDOC_OPEN = 'cat > "$TMP" <<\'EOF\''
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
    ("files/jail.local", "10-harden-updates-fail2ban.sh", 2),
)


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

    def test_the_script_writes_no_heredoc_the_role_does_not_carry(self) -> None:
        # The role carries one file per heredoc of the two scripts, and no other.
        self.assertEqual(len(_heredocs(PROVISION / "00-harden-ssh.sh")), 1)
        self.assertEqual(len(_heredocs(PROVISION / "10-harden-updates-fail2ban.sh")), 3)

    def test_the_docker_apt_line_renders_to_the_scripts_line_for_amd64_trixie(self) -> None:
        self.assertEqual(_rendered_docker_line(), _docker_line_of_script() + "\n")


if __name__ == "__main__":
    unittest.main()
