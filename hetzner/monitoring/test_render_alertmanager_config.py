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



class NtfyCredentialTests(unittest.TestCase):
    """The pager's secrets are checked for shape before anything is written.

    A malformed token or a plaintext password in the hash slot makes ntfy exit
    at start, which takes the pager down while the rest of the stack looks
    healthy -- so each is refused here, by name, instead.
    """

    def test_substitutes_all_four_ntfy_credentials(self) -> None:
        rendered = render(TEMPLATE, FULL_ENV)
        for var in (
            "NTFY_PAGER_TOKEN",
            "NTFY_WATCHER_TOKEN",
            "NTFY_OWNER_PASSWORD_HASH",
            "NTFY_MACHINE_PASSWORD_HASH",
        ):
            self.assertIn(FULL_ENV[var], rendered)

    def test_refuses_a_token_that_is_not_tk_plus_29_lowercase_alphanumerics(self) -> None:
        for bad in ("", "tk_short", "tk_" + "A" * 29, "tk_" + "a" * 30, "x_" + "a" * 29,
                    "tk_" + "a" * 28 + "-"):
            for var in ("NTFY_PAGER_TOKEN", "NTFY_WATCHER_TOKEN"):
                with self.assertRaises(ValueError, msg=f"{var}={bad!r}"):
                    render(TEMPLATE, dict(FULL_ENV, **{var: bad}))

    def test_refuses_a_plaintext_password_in_a_hash_slot(self) -> None:
        for var in ("NTFY_OWNER_PASSWORD_HASH", "NTFY_MACHINE_PASSWORD_HASH"):
            for bad in ("correct-horse-battery-staple", "$2a$10$tooshort", "!"):
                with self.assertRaises(ValueError, msg=f"{var}={bad!r}") as ctx:
                    render(TEMPLATE, dict(FULL_ENV, **{var: bad}))
                self.assertIn(var, str(ctx.exception))

    def test_the_error_never_echoes_the_rejected_value(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            render(TEMPLATE, dict(FULL_ENV, NTFY_OWNER_PASSWORD_HASH="hunter2-plaintext"))
        self.assertNotIn("hunter2-plaintext", str(ctx.exception))

    def test_refuses_two_publishers_sharing_one_token(self) -> None:
        with self.assertRaises(ValueError):
            render(TEMPLATE, dict(FULL_ENV, NTFY_WATCHER_TOKEN=FULL_ENV["NTFY_PAGER_TOKEN"]))

    def test_refuses_machine_users_sharing_the_owner_hash(self) -> None:
        with self.assertRaises(ValueError):
            render(
                TEMPLATE,
                dict(FULL_ENV, NTFY_MACHINE_PASSWORD_HASH=FULL_ENV["NTFY_OWNER_PASSWORD_HASH"]),
            )


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

    def test_main_fails_without_writing_when_a_credential_is_malformed(self) -> None:
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
            env = dict(FULL_ENV, NTFY_PAGER_TOKEN="nope")
            with mock.patch.object(
                render_alertmanager_config, "__file__", str(directory / "render.py")
            ), mock.patch.dict(os.environ, env, clear=False):
                self.assertEqual(render_alertmanager_config.main([]), 1)
            self.assertFalse((directory / "ntfy" / "server.yml").exists())


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


if __name__ == "__main__":
    unittest.main()
