#!/usr/bin/env python3
"""Unit tests for `stack/render_alertmanager_config.py`'s pure `render()`
function. Imported by path rather than installed, matching how the other
provisioning scripts in this repo are tested (e.g.
`mail/provision/test_render_shim_env.py`).
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import io
import os
import pathlib
import re
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
    "pager: '__NTFY_PAGER_TOKEN__'\n"
    "watcher: '__NTFY_WATCHER_TOKEN__'\n"
    "owner: '__NTFY_OWNER_PASSWORD_HASH__'\n"
    "machine: '__NTFY_MACHINE_PASSWORD_HASH__'\n"
)

FULL_ENV = {
    "SMTP_USERNAME": "alerts@branchleft.co.uk",
    "SMTP_PASSWORD": "correct-horse-battery-staple",
    "HEALTHCHECKS_PING_URL": "https://hc-ping.com/deadbeef",
    "ALERT_RECIPIENT_EMAIL": "ops@branchleft.co.uk",
    "MAILHOST_PING_URL": "https://hc-ping.com/deadbeef/fail",
    "NTFY_PAGER_TOKEN": "tk_" + "a" * 29,
    "NTFY_WATCHER_TOKEN": "tk_" + "b" * 29,
    "NTFY_OWNER_PASSWORD_HASH": "$2a$10$" + "O" * 53,
    "NTFY_MACHINE_PASSWORD_HASH": "$2a$10$" + "M" * 53,
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
        for missing in (k for k in FULL_ENV if not k.startswith("NTFY_")):
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



class NtfyCredentialTests(unittest.TestCase):
    """The pager is optional: a missing or malformed credential disables it
    with a warning and never stops the rest of monitoring.

    Stopping the whole stack for a pager problem would take email alerting
    down with it, so each problem is reported by variable name and the pager's
    own config is locked instead.
    """

    def test_substitutes_all_four_ntfy_credentials(self) -> None:
        rendered = render(TEMPLATE, FULL_ENV)
        for var in render_alertmanager_config.NTFY_PLACEHOLDERS.values():
            self.assertIn(FULL_ENV[var], rendered)
        self.assertEqual(render_alertmanager_config.ntfy_problems(FULL_ENV), [])

    def test_a_missing_credential_never_raises_and_disables_every_ntfy_placeholder(self) -> None:
        for var in render_alertmanager_config.NTFY_PLACEHOLDERS.values():
            env = {k: v for k, v in FULL_ENV.items() if k != var}
            rendered = render(TEMPLATE, env)
            self.assertNotIn("__NTFY_", rendered)
            self.assertIn(render_alertmanager_config.NTFY_DISABLED_VALUE, rendered)
            for other in render_alertmanager_config.NTFY_PLACEHOLDERS.values():
                if other != var:
                    self.assertNotIn(FULL_ENV[other], rendered)
            problems = render_alertmanager_config.ntfy_problems(env)
            self.assertEqual(len(problems), 1)
            self.assertIn(var, problems[0])

    def test_a_malformed_token_or_hash_disables_the_pager_without_echoing_it(self) -> None:
        cases = {
            "NTFY_PAGER_TOKEN": ["", "tk_short", "tk_" + "A" * 29, "tk_" + "a" * 30, "x_" + "a" * 29],
            "NTFY_WATCHER_TOKEN": ["tk_" + "a" * 28 + "-"],
            "NTFY_OWNER_PASSWORD_HASH": ["plaintext-owner-pw", "$2a$10$tooshort", "!"],
            "NTFY_MACHINE_PASSWORD_HASH": ["hunter2-plaintext"],
        }
        for var, bads in cases.items():
            for bad in bads:
                env = dict(FULL_ENV, **{var: bad})
                problems = render_alertmanager_config.ntfy_problems(env)
                self.assertTrue(problems, msg=f"{var}={bad!r}")
                self.assertIn(var, " ".join(problems))
                if bad:
                    self.assertNotIn(bad, " ".join(problems))
                    self.assertNotIn(bad, render(TEMPLATE, env))

    def test_two_publishers_sharing_one_token_disables_the_pager(self) -> None:
        env = dict(FULL_ENV, NTFY_WATCHER_TOKEN=FULL_ENV["NTFY_PAGER_TOKEN"])
        self.assertTrue(render_alertmanager_config.ntfy_problems(env))

    def test_machine_users_sharing_the_owner_hash_disables_the_pager(self) -> None:
        env = dict(FULL_ENV, NTFY_MACHINE_PASSWORD_HASH=FULL_ENV["NTFY_OWNER_PASSWORD_HASH"])
        self.assertTrue(render_alertmanager_config.ntfy_problems(env))

    def test_the_locked_config_keeps_deny_all_and_drops_every_user_grant_and_token(self) -> None:
        template = (
            pathlib.Path(MODULE_PATH).parent / "ntfy" / "server.yml.tmpl"
        ).read_text(encoding="utf-8")
        locked = render_alertmanager_config.lock_ntfy_config(template)
        self.assertIn("auth-default-access: deny-all", locked)
        self.assertIn("auth-file:", locked)
        for key in ("auth-users:", "auth-access:", "auth-tokens:", "__NTFY_", "write-only"):
            self.assertNotIn(key, locked)
        active = "\n".join(l for l in locked.split("\n") if not l.lstrip().startswith("#"))
        self.assertNotIn("upstream-base-url", active)


class Mx1TokenTests(unittest.TestCase):
    """The mail host's publish-only grant is optional and independent of the pager.

    The real ntfy template is rendered, so a change to the grant's lines in it
    is what these tests see.
    """

    TOKEN = "tk_" + "m" * 29

    @staticmethod
    def _template() -> str:
        return (pathlib.Path(MODULE_PATH).parent / "ntfy" / "server.yml.tmpl").read_text(
            encoding="utf-8"
        )

    def _active(self, env: dict[str, str]) -> str:
        rendered = render(self._template(), env)
        return "\n".join(l for l in rendered.split("\n") if not l.lstrip().startswith("#"))

    def test_the_template_grants_the_mail_host_write_only_on_its_own_topic(self) -> None:
        active = "\n".join(
            l for l in self._template().split("\n") if not l.lstrip().startswith("#")
        )
        self.assertIn("'mx1:branchleft-abuse:write-only'", active)
        self.assertIn("'owner:branchleft-abuse:read-only'", active)
        mx1_grants = [l for l in active.split("\n") if l.strip().startswith("- 'mx1:")]
        self.assertEqual(
            len(mx1_grants), 3, msg="one user, one grant and one token for the mail host"
        )
        for line in mx1_grants:
            self.assertNotIn("branchleft-pages", line)
            self.assertNotIn("read", line.replace("branchleft-abuse", ""))

    def test_a_token_is_placed_on_the_mail_host_user_only(self) -> None:
        env = dict(FULL_ENV, NTFY_MX1_TOKEN=self.TOKEN)
        active = self._active(env)
        self.assertIn(f"'mx1:{self.TOKEN}:mx1-abuse-report'", active)
        self.assertEqual(active.count(self.TOKEN), 1)
        self.assertNotIn("__NTFY_", active)

    def test_no_token_drops_only_the_mail_hosts_token_line(self) -> None:
        active = self._active(FULL_ENV)
        self.assertNotIn("mx1-abuse-report", active)
        self.assertNotIn("__NTFY_", active)
        self.assertIn(f"'alertmanager:{FULL_ENV['NTFY_PAGER_TOKEN']}:alertmanager'", active)
        self.assertIn(f"'watcher:{FULL_ENV['NTFY_WATCHER_TOKEN']}:release-watcher'", active)
        self.assertEqual(render_alertmanager_config.mx1_token_problems(FULL_ENV), [])

    def test_a_malformed_or_reused_token_is_dropped_and_never_echoed(self) -> None:
        for bad in ("tk_short", "tk_" + "M" * 29, "plain-text-secret", FULL_ENV["NTFY_PAGER_TOKEN"],
                    FULL_ENV["NTFY_WATCHER_TOKEN"]):
            env = dict(FULL_ENV, NTFY_MX1_TOKEN=bad)
            problems = render_alertmanager_config.mx1_token_problems(env)
            self.assertTrue(problems, msg=bad)
            self.assertNotIn(bad, " ".join(problems))
            active = self._active(env)
            self.assertNotIn("mx1-abuse-report", active)
            # The pager's own tokens are still in place, once each.
            self.assertEqual(active.count(FULL_ENV["NTFY_PAGER_TOKEN"]), 1)
            self.assertEqual(active.count(FULL_ENV["NTFY_WATCHER_TOKEN"]), 1)

    def test_a_disabled_pager_leaves_no_token_behind(self) -> None:
        env = {k: v for k, v in FULL_ENV.items() if k != "NTFY_PAGER_TOKEN"}
        env["NTFY_MX1_TOKEN"] = self.TOKEN
        locked = render_alertmanager_config.lock_ntfy_config(self._template())
        self.assertNotIn(self.TOKEN, render(locked, env))
        self.assertNotIn(self.TOKEN, render(self._template(), env))

    def test_main_warns_for_a_bad_mail_host_token_without_disabling_the_pager(self) -> None:
        template = self._template()
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / "alertmanager").mkdir()
            (directory / "alertmanager" / render_alertmanager_config.TEMPLATE_NAME).write_text(
                TEMPLATE, encoding="utf-8"
            )
            (directory / "ntfy").mkdir()
            (directory / "ntfy" / render_alertmanager_config.NTFY_TEMPLATE_NAME).write_text(
                template, encoding="utf-8"
            )
            env = dict(FULL_ENV, NTFY_MX1_TOKEN="tk_short")
            stderr = io.StringIO()
            with (
                mock.patch.object(
                    render_alertmanager_config, "__file__", str(directory / "render.py")
                ),
                mock.patch.dict(os.environ, env, clear=True),
                contextlib.redirect_stderr(stderr),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(render_alertmanager_config.main([]), 0)
            self.assertIn("NTFY_MX1_TOKEN is malformed", stderr.getvalue())
            self.assertNotIn("tk_short", stderr.getvalue())
            self.assertNotIn("pager is DISABLED", stderr.getvalue())
            written = (directory / "ntfy" / "server.yml").read_text(encoding="utf-8")
            self.assertIn(FULL_ENV["NTFY_PAGER_TOKEN"], written)
            self.assertNotIn("mx1-abuse-report", written)


class NtfyOutputTests(unittest.TestCase):
    def test_writes_server_yml_0600_beside_its_template_with_no_chown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / "alertmanager").mkdir()
            (directory / "ntfy").mkdir()
            (directory / "alertmanager" / render_alertmanager_config.TEMPLATE_NAME).write_text(
                TEMPLATE, encoding="utf-8"
            )
            (directory / "ntfy" / render_alertmanager_config.NTFY_TEMPLATE_NAME).write_text(
                TEMPLATE, encoding="utf-8"
            )
            with mock.patch.object(
                render_alertmanager_config, "__file__", str(directory / "render.py")
            ), mock.patch.dict(os.environ, FULL_ENV, clear=False), mock.patch.object(
                os, "geteuid", return_value=0
            ), mock.patch.object(os, "chown") as chown:
                self.assertEqual(render_alertmanager_config.main([]), 0)
            output = (directory / "ntfy" / render_alertmanager_config.NTFY_OUTPUT_NAME).resolve()
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertIn(FULL_ENV["NTFY_PAGER_TOKEN"], output.read_text(encoding="utf-8"))
            chowned = [call.args[0] for call in chown.call_args_list]
            self.assertNotIn(output, chowned)

    def test_clears_the_empty_directory_docker_leaves_at_the_mount_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / "alertmanager").mkdir()
            (directory / "ntfy" / "server.yml").mkdir(parents=True)
            (directory / "alertmanager" / render_alertmanager_config.TEMPLATE_NAME).write_text(
                TEMPLATE, encoding="utf-8"
            )
            (directory / "ntfy" / render_alertmanager_config.NTFY_TEMPLATE_NAME).write_text(
                TEMPLATE, encoding="utf-8"
            )
            with mock.patch.object(
                render_alertmanager_config, "__file__", str(directory / "render.py")
            ), mock.patch.dict(os.environ, FULL_ENV, clear=False):
                self.assertEqual(render_alertmanager_config.main([]), 0)
            self.assertTrue((directory / "ntfy" / "server.yml").is_file())

    def test_main_with_no_ntfy_secrets_still_succeeds_warns_and_writes_a_locked_config(
        self,
    ) -> None:
        ntfy_template = (
            pathlib.Path(MODULE_PATH).parent / "ntfy" / "server.yml.tmpl"
        ).read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / "alertmanager").mkdir()
            (directory / "ntfy").mkdir()
            (directory / "alertmanager" / render_alertmanager_config.TEMPLATE_NAME).write_text(
                TEMPLATE, encoding="utf-8"
            )
            (directory / "ntfy" / render_alertmanager_config.NTFY_TEMPLATE_NAME).write_text(
                ntfy_template, encoding="utf-8"
            )
            env = {k: v for k, v in FULL_ENV.items() if not k.startswith("NTFY_")}
            stderr = io.StringIO()
            with mock.patch.object(
                render_alertmanager_config, "__file__", str(directory / "render.py")
            ), mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stderr(stderr):
                self.assertEqual(render_alertmanager_config.main([]), 0)
            self.assertIn("DISABLED", stderr.getvalue())
            self.assertIn("NTFY_PAGER_TOKEN is not set", stderr.getvalue())
            alertmanager = directory / "alertmanager" / render_alertmanager_config.OUTPUT_NAME
            self.assertTrue(alertmanager.exists())
            self.assertIn(FULL_ENV["SMTP_PASSWORD"], alertmanager.read_text(encoding="utf-8"))
            ntfy = (directory / "ntfy" / "server.yml").read_text(encoding="utf-8")
            self.assertIn("auth-default-access: deny-all", ntfy)
            self.assertNotIn("auth-tokens", ntfy)
            self.assertNotIn("__NTFY_", ntfy)


class OutputPermissionsTests(unittest.TestCase):
    """The rendered file must be readable by the process it exists for, and
    no one else: mode 0600 and the container's uid. Why both halves are
    asserted is in `stack/render_alertmanager_config.md`.
    """

    def _render_into(self, directory: pathlib.Path) -> pathlib.Path:
        """Run `main()` with the module rooted at `directory`."""
        (directory / "alertmanager").mkdir()
        (directory / "ntfy").mkdir()
        (directory / "alertmanager" / render_alertmanager_config.TEMPLATE_NAME).write_text(
            TEMPLATE, encoding="utf-8"
        )
        (directory / "ntfy" / render_alertmanager_config.NTFY_TEMPLATE_NAME).write_text(
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


class PrometheusPasswordTests(unittest.TestCase):
    """The mx1 scrape credential, written beside the config that names it.

    `basic_auth.password_file` rather than an inline password because
    `stack/prometheus/prometheus.yml` is committed to a public repository, and
    a file rather than an environment variable because Prometheus, unlike
    Caddy, has no way to read one from inside its config.
    """

    def _write(self, directory: pathlib.Path, env: dict[str, str]) -> pathlib.Path:
        (directory / "prometheus").mkdir(exist_ok=True)
        render_alertmanager_config.write_prometheus_password(directory, env)
        return directory / "prometheus" / "mx1-metrics-password"

    def test_writes_the_secret_verbatim_with_no_trailing_newline(self) -> None:
        """Prometheus sends the file's bytes as the password. A trailing
        newline authenticates as a different string and the endpoint answers
        401 -- with nothing in the config to look wrong."""
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(pathlib.Path(tmp), {"STALWART_PROMETHEUS_SECRET": "s3cr3t"})

            self.assertEqual(path.read_bytes(), b"s3cr3t")

    def test_the_written_file_is_0600_and_never_group_or_world_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(pathlib.Path(tmp), {"STALWART_PROMETHEUS_SECRET": "s3cr3t"})

            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)
            self.assertEqual(mode & stat.S_IRGRP, 0)
            self.assertEqual(mode & stat.S_IROTH, 0)

    def test_it_chowns_to_the_prometheus_uid_when_running_as_root(self) -> None:
        """Same bind-mount reasoning as the Alertmanager render above: the
        container reads the file as its own user, so a root-owned 0600 file is
        unreadable to the one process it exists for."""
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(os, "geteuid", return_value=0), mock.patch.object(
                os, "chown"
            ) as chown:
                path = self._write(pathlib.Path(tmp), {"STALWART_PROMETHEUS_SECRET": "s3cr3t"})

            chown.assert_called_once_with(
                path,
                render_alertmanager_config.PROMETHEUS_UID,
                render_alertmanager_config.PROMETHEUS_UID,
            )

    def test_the_prometheus_uid_is_nobody(self) -> None:
        """65534 is `nobody` in the prom/prometheus image. Read from its own
        constant rather than ALERTMANAGER_UID: the two images are pinned and
        upgraded independently, so a shared constant would carry one image's
        user onto the other on the next bump."""
        self.assertEqual(render_alertmanager_config.PROMETHEUS_UID, 65534)

    def test_an_unset_secret_is_not_fatal(self) -> None:
        """Alertmanager cannot start without its config; Prometheus starts fine
        without this file and simply fails one scrape, which up == 0 turns into
        a page. Refusing to start would trade one dead target for no alerting
        at all across the estate -- including the alert that reports it."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / "prometheus").mkdir()

            self.assertIsNone(
                render_alertmanager_config.write_prometheus_password(directory, {})
            )

    def test_main_still_succeeds_with_no_stalwart_secret_in_the_environment(self) -> None:
        """The end-to-end shape of the rule above: this runs as an
        ExecStartPre, so a non-zero exit here is a monitoring stack that does
        not start."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / "alertmanager").mkdir()
            (directory / "ntfy").mkdir()
            (directory / "alertmanager" / render_alertmanager_config.TEMPLATE_NAME).write_text(
                TEMPLATE, encoding="utf-8"
            )
            (directory / "ntfy" / render_alertmanager_config.NTFY_TEMPLATE_NAME).write_text(
                TEMPLATE, encoding="utf-8"
            )
            env = dict(FULL_ENV)
            env.pop("STALWART_PROMETHEUS_SECRET", None)
            with mock.patch.object(
                render_alertmanager_config, "__file__", str(directory / "render.py")
            ), mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(render_alertmanager_config.main([]), 0)

    def test_an_unset_secret_removes_a_previously_written_one(self) -> None:
        """monitoring.env is the single source for this value, so a secret
        rotated out of it must not stay readable on disk."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            path = self._write(directory, {"STALWART_PROMETHEUS_SECRET": "old-secret"})
            self.assertTrue(path.exists())

            self._write(directory, {})

            self.assertFalse(path.exists())

    def test_a_blank_secret_is_treated_as_unset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            path = self._write(directory, {"STALWART_PROMETHEUS_SECRET": "old-secret"})

            self._write(directory, {"STALWART_PROMETHEUS_SECRET": ""})

            self.assertFalse(path.exists())

    def test_it_clears_the_directory_docker_leaves_behind(self) -> None:
        """Docker creates an empty directory at a bind-mount source that does
        not exist. Without this, every later run raises IsADirectoryError out of
        the systemd ExecStartPre and the monitoring stack stops starting at all
        -- turning a missing scrape credential into a total loss of alerting."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / "prometheus").mkdir()
            (directory / "prometheus" / "mx1-metrics-password").mkdir()

            path = self._write(directory, {"STALWART_PROMETHEUS_SECRET": "s3cr3t"})

            self.assertTrue(path.is_file())
            self.assertEqual(path.read_bytes(), b"s3cr3t")

    def test_it_leaves_a_non_empty_directory_alone_rather_than_deleting_data(self) -> None:
        """rmdir, never rmtree: whatever is in there was not put there by this
        script, and a credential writer is the last place to be recursively
        deleting paths on a production host."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / "prometheus").mkdir()
            occupied = directory / "prometheus" / "mx1-metrics-password"
            occupied.mkdir()
            (occupied / "something").write_text("do not delete me")

            self.assertIsNone(
                render_alertmanager_config.write_prometheus_password(
                    directory, {"STALWART_PROMETHEUS_SECRET": "s3cr3t"}
                )
            )
            self.assertTrue((occupied / "something").exists())

    def test_the_password_path_matches_the_mount_the_compose_file_declares(self) -> None:
        """render.ts's STALWART_METRICS_PASSWORD_FILE is the container-side
        path, compose.yml maps this host-side one onto it, and prometheus.yml
        names the container-side one. All three have to agree; this asserts the
        two that live in this repo's non-TypeScript half."""
        stack = pathlib.Path(__file__).resolve().parent / "stack"
        host_relative = "/".join(render_alertmanager_config.PROMETHEUS_PASSWORD_PATH)
        compose = (stack / "compose.yml").read_text(encoding="utf-8")
        prometheus_yml = (stack / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")

        self.assertIn(f"./{host_relative}:/etc/prometheus/mx1-metrics-password:ro", compose)
        self.assertIn("password_file: /etc/prometheus/mx1-metrics-password", prometheus_yml)

    def test_the_secret_is_never_written_into_the_committed_config(self) -> None:
        """The reason this file exists at all."""
        stack = pathlib.Path(__file__).resolve().parent / "stack"
        prometheus_yml = (stack / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")

        self.assertNotIn("password:", prometheus_yml.replace("password_file:", ""))


TEMPLATE_PATH = (
    pathlib.Path(__file__).resolve().parent / "stack" / "alertmanager" / "alertmanager.yml.tmpl"
)
HEARTBEAT_FIXTURE_URL = "https://example.invalid/ping/fixture-heartbeat"
MAX_HEARTBEAT_REPEAT_SECONDS = 300
DURATION_UNITS = {"s": 1, "m": 60, "h": 3600}


def _duration_seconds(text: str) -> int:
    match = re.fullmatch(r"(\d+)([smh])", text)
    assert match is not None, f"unparseable duration: {text!r}"
    return int(match.group(1)) * DURATION_UNITS[match.group(2)]


def _child_routes(template: str) -> list[str]:
    """Each direct child of the root `routes:` list as one text block."""
    route = template[template.index("\nroute:\n") : template.index("\ninhibit_rules:")]
    blocks: list[str] = []
    for line in route.splitlines():
        if line.startswith("    - "):
            blocks.append(line + "\n")
        elif blocks and line.startswith("      "):
            blocks[-1] += line + "\n"
    return blocks


def _receiver_block(text: str, name: str) -> str:
    receivers = text[text.index("\nreceivers:\n") :]
    for part in receivers.split("\n  - name: "):
        if part.startswith(name + "\n"):
            return part
    raise AssertionError(f"no receiver named {name!r}")


class HeartbeatRouteTests(unittest.TestCase):
    """The Watchdog heartbeat is the only signal that survives a silent stack
    (RUNBOOK-monitoring.md section 11). Asserted against the real template."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.template = TEMPLATE_PATH.read_text(encoding="utf-8")
        cls.routes = _child_routes(cls.template)
        cls.watchdog = [block for block in cls.routes if 'alertname = "Watchdog"' in block]

    def test_watchdog_is_routed_to_heartbeat_and_nowhere_else(self) -> None:
        self.assertEqual(len(self.watchdog), 1)
        self.assertIn('alertname = "Watchdog"', self.routes[0])
        self.assertIn("      receiver: heartbeat\n", self.watchdog[0])
        for block in self.routes:
            if block is not self.watchdog[0]:
                self.assertNotIn("receiver: heartbeat", block)

    def test_heartbeat_repeat_interval_is_at_most_five_minutes(self) -> None:
        match = re.search(r"^      repeat_interval: (\S+)$", self.watchdog[0], re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertLessEqual(_duration_seconds(match.group(1)), MAX_HEARTBEAT_REPEAT_SECONDS)

    def test_heartbeat_receiver_posts_the_secret_input_and_no_literal_url(self) -> None:
        receiver = _receiver_block(self.template, "heartbeat")
        self.assertIn("      - url: '__HEALTHCHECKS_PING_URL__'\n", receiver)
        self.assertNotIn("http", receiver)

        env = dict(
            FULL_ENV,
            HEALTHCHECKS_PING_URL=HEARTBEAT_FIXTURE_URL,
            MAILHOST_PING_URL="https://example.invalid/ping/fixture-mailhost",
        )
        rendered = render(self.template, env)
        self.assertIn(
            f"      - url: '{HEARTBEAT_FIXTURE_URL}'",
            _receiver_block(rendered, "heartbeat"),
        )
        self.assertEqual(rendered.count(HEARTBEAT_FIXTURE_URL), 1)
        self.assertNotIn("hc-ping.com", self.template)
        self.assertNotIn("hc-ping.com", rendered)


DEMO_TEMPLATE_PATH = MODULE_PATH.parent / "prometheus" / "demo_tls_probe.yml.tmpl"
COMPOSE_PATH = MODULE_PATH.parent / "compose.yml"
PROMETHEUS_CONFIG_PATH = MODULE_PATH.parent / "prometheus" / "prometheus.yml"


class DemoTlsProbeTests(unittest.TestCase):
    """The demo wildcard probe is rendered on the host from the monitoring env.

    The base never reaches a committed file: an unset or empty base writes an
    empty scrape file, and a set one fills the template's token.
    """

    def setUp(self) -> None:
        self.template = DEMO_TEMPLATE_PATH.read_text()
        self.render = render_alertmanager_config.render_demo_tls_probe

    def test_an_unset_or_empty_base_renders_no_scrape_config(self) -> None:
        self.assertEqual("scrape_configs: []\n", self.render(self.template, None))
        self.assertEqual("scrape_configs: []\n", self.render(self.template, ""))

    def test_a_set_base_probes_the_fixed_label_under_it_over_tls(self) -> None:
        rendered = self.render(self.template, "example.test")
        self.assertIn("job_name: blackbox_demo_tls", rendered)
        self.assertIn("- probe.example.test:443", rendered)
        self.assertIn("module: ['tls_connect']", rendered)
        self.assertNotIn("__DEMO_WILDCARD_BASE__", rendered)

    def test_a_base_that_is_not_a_lower_case_domain_is_refused(self) -> None:
        for bad in ("*.example.test", "Example.test", "localhost", "a b.test", "example.test."):
            with self.subTest(base=bad), self.assertRaises(ValueError):
                self.render(self.template, bad)

    def test_the_committed_template_is_the_tls_probe_with_a_token_for_the_base(self) -> None:
        self.assertIn("job_name: blackbox_demo_tls", self.template)
        self.assertIn("module: ['tls_connect']", self.template)
        self.assertIn("__DEMO_WILDCARD_BASE__", self.template)


class DemoTlsProbeWiringTests(unittest.TestCase):
    """Each link in the chain from monitoring.env to the running Prometheus."""

    def test_the_rendered_file_is_mounted_read_only_where_prometheus_reads_it(self) -> None:
        compose = COMPOSE_PATH.read_text()
        self.assertIn(
            "./prometheus/demo_tls_probe.yml:/etc/prometheus/demo_tls_probe.yml:ro", compose
        )

    def test_the_prometheus_config_names_the_mounted_file(self) -> None:
        self.assertIn("  - /etc/prometheus/demo_tls_probe.yml", PROMETHEUS_CONFIG_PATH.read_text())

    def test_the_host_writes_the_file_and_a_bad_base_disables_rather_than_failing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stack_dir = pathlib.Path(tmp)
            (stack_dir / "prometheus").mkdir()
            (stack_dir / "prometheus" / "demo_tls_probe.yml.tmpl").write_text(
                DEMO_TEMPLATE_PATH.read_text()
            )
            output = stack_dir / "prometheus" / "demo_tls_probe.yml"
            with contextlib.redirect_stdout(io.StringIO()):
                render_alertmanager_config.write_demo_tls_probe(
                    stack_dir, {"DEMO_WILDCARD_BASE": "example.test"}
                )
            self.assertIn("- probe.example.test:443", output.read_text())
            self.assertEqual(0o644, stat.S_IMODE(output.stat().st_mode))

            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                render_alertmanager_config.write_demo_tls_probe(
                    stack_dir, {"DEMO_WILDCARD_BASE": "*.bad"}
                )
            self.assertEqual("scrape_configs: []\n", output.read_text())
            self.assertIn("DEMO_WILDCARD_BASE", err.getvalue())

    def test_a_directory_left_at_the_output_path_is_cleared_and_the_probe_renders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stack_dir = pathlib.Path(tmp)
            (stack_dir / "prometheus").mkdir()
            (stack_dir / "prometheus" / "demo_tls_probe.yml.tmpl").write_text(
                DEMO_TEMPLATE_PATH.read_text()
            )
            (stack_dir / "prometheus" / "demo_tls_probe.yml").mkdir()
            with contextlib.redirect_stdout(io.StringIO()):
                render_alertmanager_config.write_demo_tls_probe(stack_dir, {})
            output = stack_dir / "prometheus" / "demo_tls_probe.yml"
            self.assertTrue(output.is_file())
            self.assertEqual("scrape_configs: []\n", output.read_text())
@dataclasses.dataclass(frozen=True)
class _Delivery:
    """One route an alert reached: where it goes and how its group is kept."""

    receiver: str
    group_by: tuple[str, ...]
    group_wait_seconds: int
    group_interval_seconds: int
    group_key: tuple[tuple[str, str], ...]


def _matcher_holds(matcher: str, labels: dict[str, str]) -> bool:
    parsed = re.fullmatch(r'(\w+) (=~|!~|!=|=) "(.*)"', matcher)
    assert parsed is not None, f"unparseable matcher: {matcher!r}"
    name, operator, expected = parsed.groups()
    actual = labels.get(name, "")
    if operator == "=":
        return actual == expected
    if operator == "!=":
        return actual != expected
    matched = re.fullmatch(expected, actual) is not None
    return matched if operator == "=~" else not matched


def _route_setting(text: str, key: str, indent: str) -> str | None:
    found = re.search(rf"^{indent}{key}: (.+)$", text, re.MULTILINE)
    return found.group(1) if found else None


def _group_by(text: str, indent: str) -> tuple[str, ...] | None:
    raw = _route_setting(text, "group_by", indent)
    return None if raw is None else tuple(re.findall(r"'([^']+)'", raw))


def _walk_routes(template: str, labels: dict[str, str]) -> list[_Delivery]:
    """Alertmanager's route walk for `labels`: every child in order, the first
    match wins unless it says `continue`, and the root receiver applies only
    when no child matched. Settings a child leaves out come from the root."""
    root = template[template.index("\nroute:\n") : template.index("\n  routes:\n")]
    root_group_by = _group_by(root, "  ")
    root_wait = _route_setting(root, "group_wait", "  ")
    root_interval = _route_setting(root, "group_interval", "  ")
    root_receiver = _route_setting(root, "receiver", "  ")
    assert root_group_by and root_wait and root_interval and root_receiver

    def delivery(receiver: str, block: str) -> _Delivery:
        group_by = _group_by(block, "      ") or root_group_by
        wait = _route_setting(block, "group_wait", "      ") or root_wait
        interval = _route_setting(block, "group_interval", "      ") or root_interval
        return _Delivery(
            receiver=receiver,
            group_by=group_by,
            group_wait_seconds=_duration_seconds(wait),
            group_interval_seconds=_duration_seconds(interval),
            group_key=tuple((name, labels.get(name, "")) for name in group_by),
        )

    reached: list[_Delivery] = []
    for block in _child_routes(template):
        if not _block_matches(block, labels):
            continue
        receiver = _route_setting(block, "receiver", "      ")
        assert receiver is not None
        reached.append(delivery(receiver, block))
        if _route_setting(block, "continue", "      ") != "true":
            return reached
    return reached or [delivery(root_receiver, "")]


def _receivers(template: str, labels: dict[str, str]) -> set[str]:
    return {step.receiver for step in _walk_routes(template, labels)}


OWNED_BAN_SECONDS_BOUND = 300
EDGE_BAN_SCENARIOS = ("crowdsecurity/http-probing", "branchleft/ghost-admin-login-bruteforce")
def _block_matches(block: str, labels: dict[str, str]) -> bool:
    matchers = re.findall(r"^        - (.+)$", block, re.MULTILINE)
    return all(_matcher_holds(matcher, labels) for matcher in matchers)


def _classifier_off(template: str) -> bool:
    """Whether the template is in the classifier-off mode, read from the template itself.
    The discard route and the discard receiver are written as a pair, so a template with
    only one of them is in neither mode and fails here."""
    route_present = any("      receiver: discard\n" in block for block in _child_routes(template))
    receiver_present = "\n  - name: discard\n" in template
    if route_present != receiver_present:
        raise AssertionError(
            "template is in neither classifier mode: discard route present "
            f"{route_present}, discard receiver present {receiver_present}"
        )
    return route_present


class OwnedEdgeBanRouteTests(unittest.TestCase):
    """Who is paged for a CrowdSec ban, walked over the real rendered tree."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.template = TEMPLATE_PATH.read_text(encoding="utf-8")
        cls.routes = _child_routes(cls.template)

    def owned_ban(
        self, reason: str = EDGE_BAN_SCENARIOS[0], decision_id: str = "101"
    ) -> dict[str, str]:
        return {
            "alertname": "EdgeBanIssued",
            "severity": "page",
            "reason": reason,
            "decision_id": decision_id,
        }

    def test_owned_ban_reaches_ntfy_page_and_nothing_else(self) -> None:
        self.assertEqual(_receivers(self.template, self.owned_ban()), {"ntfy-page"})

    def test_unowned_ban_reaches_email_and_never_ntfy_page(self) -> None:
        labels = {
            "alertname": "EdgeBanUnowned",
            "severity": "warning",
            "owner_action": "true",
            "reason": EDGE_BAN_SCENARIOS[0],
        }
        reached = _receivers(self.template, labels)
        self.assertIn("email", reached)
        self.assertNotIn("ntfy-page", reached)

    def test_a_ban_with_no_decision_id_still_reaches_ntfy_page(self) -> None:
        labels = {"alertname": "EdgeBanIssued", "severity": "page", "reason": EDGE_BAN_SCENARIOS[0]}
        self.assertEqual(_receivers(self.template, labels), {"ntfy-page"})

    def test_template_is_in_one_consistent_classifier_mode(self) -> None:
        _classifier_off(self.template)
        receiver_renamed = self.template.replace("\n  - name: discard\n", "\n  - name: other\n")
        with self.assertRaisesRegex(AssertionError, "neither classifier mode"):
            _classifier_off(receiver_renamed)
        route_retargeted = self.template.replace("      receiver: discard\n", "      receiver: email\n")
        with self.assertRaisesRegex(AssertionError, "neither classifier mode"):
            _classifier_off(route_retargeted)

    def test_stale_classifier_follows_the_mode_the_template_is_in(self) -> None:
        """Installed: the staleness alert pages through the generic route. Not installed: it
        would fire for ever, so it goes to the discard receiver, and the generic route must
        not also take it."""
        labels = {"alertname": "EdgeBanOwnerStale", "severity": "page"}
        generic = next(
            block
            for block in self.routes
            if "alertname =~ " in block and "TierTwoSafetyMatch" in block
        )
        if _classifier_off(self.template):
            self.assertEqual(_receivers(self.template, labels), {"discard"})
            self.assertFalse(_block_matches(generic, labels))
            return
        self.assertEqual(_receivers(self.template, labels), {"ntfy-page"})
        self.assertTrue(_block_matches(generic, labels))

    def test_discard_receiver_exists_only_while_the_classifier_is_off_and_has_no_integration(
        self,
    ) -> None:
        if not _classifier_off(self.template):
            self.assertNotIn("discard", self.template)
            return
        self.assertEqual(_receiver_block(self.template, "discard").strip(), "discard")

    def test_discard_route_comes_before_the_generic_page_route(self) -> None:
        discard = [index for index, block in enumerate(self.routes) if "receiver: discard" in block]
        generic = [
            index
            for index, block in enumerate(self.routes)
            if "alertname =~ " in block and "TierTwoSafetyMatch" in block
        ]
        self.assertEqual(len(generic), 1)
        if not _classifier_off(self.template):
            self.assertEqual(discard, [])
            return
        self.assertEqual(len(discard), 1)
        self.assertLess(discard[0], generic[0])
        self.assertNotIn("continue", self.routes[discard[0]])

    def test_owned_ban_child_comes_before_the_generic_page_route(self) -> None:
        owned = [
            index
            for index, block in enumerate(self.routes)
            if 'alertname = "EdgeBanIssued"' in block
        ]
        generic = [
            index
            for index, block in enumerate(self.routes)
            if "alertname =~ " in block and "TierTwoSafetyMatch" in block
        ]
        self.assertEqual(len(owned), 1)
        self.assertEqual(len(generic), 1)
        self.assertLess(owned[0], generic[0])

    def test_owned_ban_child_does_not_continue_to_the_generic_route(self) -> None:
        owned = [block for block in self.routes if 'alertname = "EdgeBanIssued"' in block]
        self.assertEqual(len(owned), 1)
        self.assertNotIn("continue", owned[0])
        self.assertEqual(len(_walk_routes(self.template, self.owned_ban())), 1)

    def test_owned_ban_groups_by_reason_so_a_second_scenario_is_a_new_group(self) -> None:
        first, second = (
            _walk_routes(self.template, self.owned_ban(reason))[0] for reason in EDGE_BAN_SCENARIOS
        )
        self.assertEqual(first.group_by, ("alertname", "reason"))
        self.assertNotEqual(first.group_key, second.group_key)

    def test_second_owned_ban_notifies_within_five_minutes(self) -> None:
        step = _walk_routes(self.template, self.owned_ban(EDGE_BAN_SCENARIOS[1]))[0]
        self.assertLessEqual(step.group_wait_seconds, OWNED_BAN_SECONDS_BOUND)
        self.assertLessEqual(step.group_interval_seconds, OWNED_BAN_SECONDS_BOUND)

    def test_second_ban_of_the_same_scenario_joins_the_group_and_notifies_within_five_minutes(
        self,
    ) -> None:
        """A second ban is a different alert by decision_id (the rule test proves that), so it
        lands in the first ban's group, and the group notifies again within its interval."""
        first = _walk_routes(self.template, self.owned_ban(decision_id="101"))[0]
        second = _walk_routes(self.template, self.owned_ban(decision_id="102"))[0]
        self.assertEqual(first.group_key, second.group_key)
        self.assertNotIn("decision_id", second.group_by)
        self.assertLessEqual(second.group_interval_seconds, OWNED_BAN_SECONDS_BOUND)

    def test_tenant_scoped_pages_keep_tenant_grouping_and_the_root_interval(self) -> None:
        labels = {"alertname": "TierTwoSafetyMatch", "severity": "page", "tenant": "acme"}
        (step,) = _walk_routes(self.template, labels)
        self.assertEqual(step.receiver, "ntfy-page")
        self.assertEqual(step.group_by, ("tenant",))
        self.assertEqual(step.group_interval_seconds, _duration_seconds("1h"))

    def test_walker_is_not_vacuous_a_page_for_an_unknown_alert_reaches_email_only(self) -> None:
        labels = {"alertname": "SomeUnregisteredPagingAlert", "severity": "page"}
        self.assertEqual(_receivers(self.template, labels), {"email"})


if __name__ == "__main__":
    unittest.main()
