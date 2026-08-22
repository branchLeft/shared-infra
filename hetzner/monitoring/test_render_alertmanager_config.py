#!/usr/bin/env python3
"""Unit tests for `stack/render_alertmanager_config.py`'s pure `render()`
function. Imported by path rather than installed, matching how the other
provisioning scripts in this repo are tested (e.g.
`mail/provision/test_render_shim_env.py`).
"""

from __future__ import annotations

import importlib.util
import pathlib
import unittest

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
)

FULL_ENV = {
    "SMTP_USERNAME": "alerts@branchleft.co.uk",
    "SMTP_PASSWORD": "correct-horse-battery-staple",
    "HEALTHCHECKS_PING_URL": "https://hc-ping.com/deadbeef",
    "ALERT_RECIPIENT_EMAIL": "ops@branchleft.co.uk",
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


if __name__ == "__main__":
    unittest.main()
