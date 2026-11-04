#!/usr/bin/env python3
"""The sign-in service's database login, as `zitadel init` makes it, has no privileged attribute.

The control-plane stack's README names this login as bounded by pg_hba alone. Nothing else showed
it is not a superuser or that it lacks createrole, createdb and bypassrls. This runs the pinned
sign-in image's init phase against a throwaway Postgres (the stack's own pinned image) and reads
the four attributes from pg_roles. In CI a missing Docker or image fails; locally it skips.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import time
import unittest
import uuid

HETZNER = pathlib.Path(__file__).resolve().parent.parent
COMPOSE = HETZNER / "control-plane" / "stack" / "compose.yml"

REQUIRED = os.environ.get("CI") == "true" or os.environ.get("ZITADEL_INIT_DOCKER") == "required"
LOGIN = "zitadel"
ATTRIBUTES = ("rolsuper", "rolcreaterole", "rolcreatedb", "rolbypassrls")
# What ALTER ROLE would grant each attribute (the sabotage the test must see).
GRANTS = {
    "rolsuper": "SUPERUSER",
    "rolcreaterole": "CREATEROLE",
    "rolcreatedb": "CREATEDB",
    "rolbypassrls": "BYPASSRLS",
}
ADMIN_PASSWORD = "throwaway-admin-pwd"
LOGIN_PASSWORD = "throwaway-login-pwd"


def pinned(service: str) -> str:
    """The image reference a service is pinned to in the stack's compose file."""
    text = COMPOSE.read_text(encoding="utf-8")
    block = re.search(rf"(?m)^  {service}:\n(?:(?:    .*|)\n)*?    image: (\S+)\n", text)
    if block is None:
        raise AssertionError(f"{COMPOSE} names no image for {service}")
    return block.group(1)


def attributes_from(row: str) -> dict[str, bool]:
    """`t|f|f|f` (psql -tA output) as the four attribute names and their values."""
    values = row.strip().split("|")
    if len(values) != len(ATTRIBUTES) or any(value not in ("t", "f") for value in values):
        raise AssertionError(f"not four t/f values: {row!r}")
    return {name: value == "t" for name, value in zip(ATTRIBUTES, values)}


def privileged(row: str) -> list[str]:
    """The attributes of the login that are true."""
    return [name for name, value in attributes_from(row).items() if value]


class AttributeCheck(unittest.TestCase):
    """No Docker: the reading of pg_roles output and the pins."""

    def test_an_all_false_row_has_no_privileged_attribute(self) -> None:
        self.assertEqual([], privileged("f|f|f|f\n"))

    def test_each_true_attribute_is_named(self) -> None:
        for index, name in enumerate(ATTRIBUTES):
            row = "|".join("t" if i == index else "f" for i in range(len(ATTRIBUTES)))
            with self.subTest(attribute=name):
                self.assertEqual([name], privileged(row))

    def test_a_row_that_is_not_four_booleans_is_refused(self) -> None:
        for row in ("", "f|f|f", "f|f|f|f|f", "f|f|f|x", "0|0|0|0"):
            with self.subTest(row=row):
                with self.assertRaises(AssertionError):
                    attributes_from(row)

    def test_both_images_are_pinned_by_digest_in_the_compose_file(self) -> None:
        self.assertRegex(pinned("zitadel"), r"^ghcr\.io/zitadel/zitadel@sha256:[0-9a-f]{64}$")
        self.assertRegex(pinned("db"), r"@sha256:[0-9a-f]{64}$")


def _unavailable(reason: str) -> None:
    if REQUIRED:
        raise AssertionError(reason)
    raise unittest.SkipTest(reason)


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


class ZitadelInitLogin(unittest.TestCase):
    """The pinned images, the real init phase and a real Postgres."""

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("docker") is None:
            _unavailable("docker is not installed")
        if _docker("info", check=False).returncode != 0:
            _unavailable("docker is not running")
        suffix = uuid.uuid4().hex[:8]
        cls.network = f"zitadel-init-{suffix}"
        cls.database = f"zitadel-init-db-{suffix}"
        cls.addClassCleanup(lambda: _docker("rm", "-f", cls.database, check=False))
        cls.addClassCleanup(lambda: _docker("network", "rm", cls.network, check=False))
        _docker("network", "create", cls.network)
        started = _docker(
            "run", "-d", "--name", cls.database, "--network", cls.network,
            "-e", f"POSTGRES_PASSWORD={ADMIN_PASSWORD}", pinned("db"), check=False,
        )
        if started.returncode != 0:
            _unavailable(f"cannot start {pinned('db')}: {started.stderr.strip()}")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if cls.psql("SELECT 1", host=True).returncode == 0:
                break
            time.sleep(1)
        else:
            raise AssertionError("the throwaway Postgres never answered over TCP")
        init = _docker(
            "run", "--rm", "--network", cls.network,
            "-e", f"ZITADEL_DATABASE_POSTGRES_HOST={cls.database}",
            "-e", "ZITADEL_DATABASE_POSTGRES_PORT=5432",
            "-e", "ZITADEL_DATABASE_POSTGRES_DATABASE=zitadel",
            "-e", f"ZITADEL_DATABASE_POSTGRES_USER_USERNAME={LOGIN}",
            "-e", f"ZITADEL_DATABASE_POSTGRES_USER_PASSWORD={LOGIN_PASSWORD}",
            "-e", "ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE=disable",
            "-e", "ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME=postgres",
            "-e", f"ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD={ADMIN_PASSWORD}",
            "-e", "ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE=disable",
            pinned("zitadel"), "init", check=False,
        )
        if init.returncode != 0:
            raise AssertionError(f"zitadel init failed: {init.stderr[-800:]}")

    @classmethod
    def psql(cls, sql: str, *, host: bool = False) -> subprocess.CompletedProcess:
        transport = ["-h", "127.0.0.1"] if host else []
        return _docker(
            "exec", "-e", f"PGPASSWORD={ADMIN_PASSWORD}", cls.database,
            "psql", "-U", "postgres", *transport, "-tA", "-c", sql, check=False,
        )

    def login_row(self) -> str:
        result = self.psql(
            f"SELECT {', '.join(ATTRIBUTES)} FROM pg_roles WHERE rolname = '{LOGIN}'", host=True
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotEqual("", result.stdout.strip(), f"init made no login named {LOGIN}")
        return result.stdout

    def test_the_login_init_makes_has_none_of_the_four_attributes(self) -> None:
        self.assertEqual([], privileged(self.login_row()))

    def test_a_granted_attribute_is_seen_and_removing_it_clears_it(self) -> None:
        # The sabotage the control must catch: grant each attribute, see it named, take it away.
        for name, grant in GRANTS.items():
            with self.subTest(attribute=name):
                self.addCleanup(self.psql, f"ALTER ROLE {LOGIN} NO{grant}", host=True)
                self.assertEqual(0, self.psql(f"ALTER ROLE {LOGIN} {grant}", host=True).returncode)
                self.assertEqual([name], privileged(self.login_row()))
                self.assertEqual(0, self.psql(f"ALTER ROLE {LOGIN} NO{grant}", host=True).returncode)
                self.assertEqual([], privileged(self.login_row()))


if __name__ == "__main__":
    unittest.main()
