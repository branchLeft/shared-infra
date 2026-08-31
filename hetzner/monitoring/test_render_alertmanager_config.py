#!/usr/bin/env python3
"""Unit tests for `stack/render_alertmanager_config.py`'s pure `render()`
function. Imported by path rather than installed, matching how the other
provisioning scripts in this repo are tested (e.g.
`mail/provision/test_render_shim_env.py`).
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).resolve().parent / "stack" / "render_alertmanager_config.py"

_spec = importlib.util.spec_from_file_location("render_alertmanager_config", MODULE_PATH)
assert _spec is not None and _spec.loader is not None
render_alertmanager_config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render_alertmanager_config)

render = render_alertmanager_config.render

TEMPLATE = (
    "smtp_auth_username: '__SMTP_USERNAME__'\n"
    "smtp_auth_password: '__SMTP_PASSWORD__'\n"
    "ping: '__HEALTHCHECKS_PING_URL__'\n"
    "to: '__ALERT_RECIPIENT_EMAIL__'\n"
    "mailhost_ping: '__MAILHOST_PING_URL__'\n"
)

FULL_ENV = {
    "SMTP_USERNAME": "alerts@branchleft.co.uk",
    "SMTP_PASSWORD": "correct-horse-battery-staple",
    "HEALTHCHECKS_PING_URL": "https://hc-ping.com/deadbeef",
    "ALERT_RECIPIENT_EMAIL": "ops@branchleft.co.uk",
    "MAILHOST_PING_URL": "https://hc-ping.com/deadbeef/fail",
}


class RenderTests(unittest.TestCase):
    def test_substitutes_every_placeholder(self) -> None:
        rendered = render(TEMPLATE, FULL_ENV)
        for placeholder in render_alertmanager_config.PLACEHOLDERS:
            self.assertNotIn(placeholder, rendered)
        self.assertIn("alerts@branchleft.co.uk", rendered)
        self.assertIn("correct-horse-battery-staple", rendered)
        self.assertIn("https://hc-ping.com/deadbeef", rendered)
        self.assertIn("ops@branchleft.co.uk", rendered)
        self.assertIn("https://hc-ping.com/deadbeef/fail", rendered)

    def test_refuses_each_missing_variable_in_turn(self) -> None:
        for missing in FULL_ENV:
            env = {k: v for k, v in FULL_ENV.items() if k != missing}
            with self.assertRaises(ValueError) as ctx:
                render(TEMPLATE, env)
            self.assertIn(missing, str(ctx.exception))

    def test_refuses_a_blank_value_the_same_as_an_absent_one(self) -> None:
        env = dict(FULL_ENV, SMTP_PASSWORD="")
        with self.assertRaises(ValueError) as ctx:
            render(TEMPLATE, env)
        self.assertIn("SMTP_PASSWORD", str(ctx.exception))

    def test_a_value_containing_regex_and_shell_metacharacters_survives_literally(self) -> None:
        # The whole reason this is str.replace and not sed/envsubst: a
        # webhook URL's slashes and a password's `&`/`$`/backslash would each
        # be significant to a regex engine or a shell, and none of them
        # should be to a literal substitution.
        env = dict(
            FULL_ENV,
            SMTP_PASSWORD="p@ss/w0rd&with$pecial\\chars",
            HEALTHCHECKS_PING_URL="https://hc-ping.com/uuid?arg=a/b&c=d",
        )
        rendered = render(TEMPLATE, env)
        self.assertIn("p@ss/w0rd&with$pecial\\chars", rendered)
        self.assertIn("https://hc-ping.com/uuid?arg=a/b&c=d", rendered)

    def test_does_not_touch_text_outside_the_known_placeholders(self) -> None:
        rendered = render(TEMPLATE, FULL_ENV)
        self.assertIn("smtp_auth_username:", rendered)
        self.assertIn("ping:", rendered)



class OutputPermissionsTests(unittest.TestCase):
    """The rendered file must be readable by the process it exists for.

    Alertmanager reads it through a bind mount, which is read as the
    container-side user (`nobody`) regardless of who wrote the file on the host.
    A root-owned 0600 file is unreadable to it, and Alertmanager exits with
    `error loading configuration file: ... permission denied` on every start --
    while the unit still reports success, because `docker compose up -d --wait`
    does not catch a container that starts and then dies.

    So the mode must stay 0600 -- the file holds an SMTP password in plaintext,
    and 0644 would expose it to every other account on the host, including the
    CI deploy account -- *and* ownership must move to that uid. Both halves are
    asserted, because either alone leaves the file unreadable or the password
    over-exposed.
    """

    def _render_into(self, directory: pathlib.Path) -> pathlib.Path:
        """Run `main()` with the module rooted at `directory`."""
        (directory / "alertmanager").mkdir()
        (directory / "alertmanager" / render_alertmanager_config.TEMPLATE_NAME).write_text(
            TEMPLATE, encoding="utf-8"
        )
        with mock.patch.object(
            render_alertmanager_config, "__file__", str(directory / "render.py")
        ), mock.patch.dict(os.environ, FULL_ENV, clear=False):
            self.assertEqual(render_alertmanager_config.main([]), 0)
        # `.resolve()`: main() resolves its own path, and on macOS /var is a
        # symlink to /private/var, so an unresolved path here compares unequal
        # to the one the module actually used.
        return (
            directory / "alertmanager" / render_alertmanager_config.OUTPUT_NAME
        ).resolve()

    def test_the_rendered_file_is_0600(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = self._render_into(pathlib.Path(tmp))

            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_it_chowns_to_the_container_uid_when_running_as_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(os, "geteuid", return_value=0), mock.patch.object(
                os, "chown"
            ) as chown:
                output = self._render_into(pathlib.Path(tmp))

            chown.assert_called_once_with(
                output,
                render_alertmanager_config.ALERTMANAGER_UID,
                render_alertmanager_config.ALERTMANAGER_UID,
            )

    def test_it_does_not_chown_when_not_root(self) -> None:
        """CI and a local render have no container to read the file and no
        privilege to chown with; attempting it would fail the whole render."""
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(os, "geteuid", return_value=1000), mock.patch.object(
                os, "chown"
            ) as chown:
                self._render_into(pathlib.Path(tmp))

            chown.assert_not_called()

    def test_the_container_uid_is_nobody(self) -> None:
        """65534 is `nobody` in the prom/alertmanager image. If a future image
        changes its user, this is the one constant to move."""
        self.assertEqual(render_alertmanager_config.ALERTMANAGER_UID, 65534)

    def test_the_secret_never_becomes_world_readable(self) -> None:
        """The whole point of chowning rather than widening the mode."""
        with tempfile.TemporaryDirectory() as tmp:
            output = self._render_into(pathlib.Path(tmp))

            mode = stat.S_IMODE(output.stat().st_mode)
            self.assertEqual(mode & stat.S_IRGRP, 0)
            self.assertEqual(mode & stat.S_IROTH, 0)
            self.assertIn(FULL_ENV["SMTP_PASSWORD"], output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
