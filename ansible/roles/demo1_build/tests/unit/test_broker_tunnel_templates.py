"""Tests of the broker tunnel templates: the role writes the grant ghost-platform renders.

The role renders the account's authorized key and sshd drop-in from two templates and the
constants in vars/main.yml. The golden files in molecule/broker_tunnel/files/golden are the
output of ghost-platform's demo-host/provision/render_broker_tunnel.py for the scenario's test
key. These tests render the templates the way Ansible does (a trailing newline kept) and
require the golden bytes, then hold the grant itself: one destination, 127.0.0.1:8090, set on
the key and in sshd, and the read-back list naming every setting the drop-in writes.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import jinja2
import yaml

ROLE = Path(__file__).resolve().parent.parent.parent
TEMPLATES = ROLE / "templates"
GOLDEN = ROLE / "molecule" / "broker_tunnel" / "files" / "golden"
TEST_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
    " ops1-broker-tunnel"
)
BROKER = "127.0.0.1:8090"
VARS_NOT_A_MAPPING = "vars/main.yml is not a mapping"
SELF_REFERENCE = "a tunnel constant refers to itself"


def role_vars() -> dict[str, object]:
    """The role's tunnel constants with their own references resolved, as Ansible resolves them.

    Raises:
        TypeError: vars/main.yml is not a mapping.
    """
    raw = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(VARS_NOT_A_MAPPING)
    tunnel: dict[str, object] = {
        k: v for k, v in raw.items() if k.startswith("demo1_build_tunnel_")
    }
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)  # noqa: S701 - not HTML

    def resolve(value: object, depth: int = 0) -> object:
        if depth > 5:
            raise RecursionError(SELF_REFERENCE)
        if isinstance(value, str) and "{{" in value:
            return resolve(env.from_string(value).render(tunnel), depth + 1)
        if isinstance(value, dict):
            return {key: resolve(item, depth) for key, item in value.items()}
        return value

    return {key: resolve(value) for key, value in tunnel.items()}


def render(template: str, extra: dict[str, object] | None = None) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES)),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,  # noqa: S701 - an sshd file, not HTML
    )
    context = role_vars()
    context["demo1_build_tunnel_ops1_key"] = TEST_KEY
    context.update(extra or {})
    return env.get_template(template).render(context)


class GoldenTests(unittest.TestCase):
    def test_authorized_key_is_what_ghost_platform_renders(self) -> None:
        self.assertEqual(
            render("broker-tunnel-authorized_keys.j2"),
            (GOLDEN / "authorized_keys").read_text(encoding="utf-8"),
        )

    def test_sshd_dropin_is_what_ghost_platform_renders(self) -> None:
        self.assertEqual(
            render("broker-tunnel-sshd.conf.j2"),
            (GOLDEN / "50-branchleft-broker-tunnel.conf").read_text(encoding="utf-8"),
        )


class GrantTests(unittest.TestCase):
    def test_the_key_opens_only_the_broker(self) -> None:
        line = render("broker-tunnel-authorized_keys.j2")
        self.assertEqual(line.count("\n"), 1)
        options, _, key = line.rstrip("\n").partition(" ")
        self.assertEqual(
            options.split(","), ["restrict", "port-forwarding", f'permitopen="{BROKER}"']
        )
        self.assertEqual(key, TEST_KEY)

    def test_sshd_opens_only_the_broker_and_forwards_local_only(self) -> None:
        body = [
            line.strip()
            for line in render("broker-tunnel-sshd.conf.j2").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertEqual(
            [line for line in body if line.startswith("PermitOpen")], [f"PermitOpen {BROKER}"]
        )
        self.assertIn("AllowTcpForwarding local", body)
        self.assertIn("PermitListen none", body)
        self.assertEqual(body[0], "Match User brokertunnel")
        self.assertEqual(body[-1], "Match all")

    def test_the_read_back_names_every_setting_the_dropin_writes(self) -> None:
        body = [
            line.strip()
            for line in render("broker-tunnel-sshd.conf.j2").splitlines()
            if line.strip() and not line.startswith("#")
        ][1:-1]
        written = {line.split(" ", 1)[0].lower(): line.split(" ", 1)[1] for line in body}
        expected = role_vars()["demo1_build_tunnel_expected_effective"]
        self.assertEqual(written, expected)

    def test_the_key_pattern_refuses_options_and_a_second_line(self) -> None:
        pattern = role_vars()["demo1_build_tunnel_ed25519_pattern"]
        if not isinstance(pattern, str):
            self.fail("the key pattern is not a string")
        self.assertTrue(re.match(pattern, TEST_KEY))
        for bad in (
            f'permitopen="*:*" {TEST_KEY}',
            f"{TEST_KEY}\n{TEST_KEY}",
            f"{TEST_KEY}\n",
            TEST_KEY.replace("ssh-ed25519", "ssh-rsa"),
            TEST_KEY + ",x",
        ):
            with self.subTest(bad=bad):
                self.assertIsNone(re.match(pattern, bad))


if __name__ == "__main__":
    unittest.main()
