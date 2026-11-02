"""Unit tests for mx1_stack_envfile: the two environment files, and that no secret leaves the host.

Run from the role's directory with library/ on PYTHONPATH, the way
``ansible/checks/run_role_unit_tests.sh`` does. Every secret here is a throwaway made for the test.
"""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import module_runner
import mx1_stack_envfile as envfile

TOKEN = "THROWAWAY-DRAIN-TOKEN_0001"  # noqa: S105
OTHER_TOKEN = "THROWAWAY-DRAIN-TOKEN_0002"  # noqa: S105
HAND_SECRET = "pasted-by-hand"  # noqa: S105
KEY = "STALWART_PROMETHEUS_SECRET"
LABEL = "shim-drain-token"


class Workdir(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.env_path = self.root / "env"
        self.credentials = self.root / "credentials"

    def mode(self, path: Path) -> int:
        return stat.S_IMODE(path.stat().st_mode)

    def credentials_with(self, *lines: str) -> None:
        self.credentials.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


class RenderTest(unittest.TestCase):
    def test_the_shim_file_is_the_four_lines_the_hand_route_renders(self) -> None:
        self.assertEqual(
            "PORT=8080\nSHIM_DB_PATH=/data/shim.db\nSHIM_THROTTLE_PATH=/data/throttle.json\n"
            f"SHIM_DRAIN_TOKEN={TOKEN}\n",
            envfile.render_shim_env(TOKEN),
        )


class TokenTest(Workdir):
    def test_the_token_is_found_by_label_among_other_labels(self) -> None:
        self.credentials_with("website:aaa", f"{LABEL}:{TOKEN}", "blog:bbb")
        self.assertEqual(TOKEN, envfile.drain_token(str(self.credentials), LABEL))

    def test_a_secret_may_hold_a_colon(self) -> None:
        self.credentials_with(f"{LABEL}:a:b")
        self.assertEqual("a:b", envfile.drain_token(str(self.credentials), LABEL))

    def test_an_absent_file_or_label_is_not_found(self) -> None:
        self.assertIsNone(envfile.drain_token(str(self.credentials), LABEL))
        self.credentials_with("website:aaa")
        self.assertIsNone(envfile.drain_token(str(self.credentials), LABEL))

    def test_a_malformed_line_is_refused_by_number_and_never_quoted(self) -> None:
        self.credentials_with("website:aaa", f"nocolon{TOKEN}")
        with self.assertRaises(envfile.EnvFileError) as caught:
            envfile.drain_token(str(self.credentials), LABEL)
        self.assertIn("line 2", str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_an_empty_or_spaced_token_is_refused_without_quoting_it(self) -> None:
        for line in (f"{LABEL}:", f"{LABEL}:has a space{TOKEN}", f"{LABEL}:tab\there"):
            with self.subTest(line=line[:14]):
                self.credentials_with(line)
                with self.assertRaises(envfile.EnvFileError) as caught:
                    envfile.drain_token(str(self.credentials), LABEL)
                self.assertNotIn(TOKEN, str(caught.exception))


class MintTest(Workdir):
    def test_a_missing_file_is_made_closed_with_a_48_character_secret(self) -> None:
        result = envfile.mint(str(self.env_path), KEY, check_mode=False)
        self.assertTrue(result["created"])
        self.assertEqual(0o600, self.mode(self.env_path))
        text = self.env_path.read_text(encoding="utf-8")
        self.assertRegex(text, rf"\A{KEY}=[A-Za-z0-9]{{48}}\n\Z")

    def test_an_existing_file_is_never_replaced(self) -> None:
        self.env_path.write_text(f"{KEY}={HAND_SECRET}\n", encoding="utf-8")
        before = self.env_path.stat().st_mtime_ns
        result = envfile.mint(str(self.env_path), KEY, check_mode=False)
        self.assertFalse(result["changed"])
        self.assertTrue(result["valid"])
        self.assertEqual(f"{KEY}={HAND_SECRET}\n", self.env_path.read_text(encoding="utf-8"))
        self.assertEqual(before, self.env_path.stat().st_mtime_ns)

    def test_a_hand_pasted_secret_of_any_length_or_characters_is_valid(self) -> None:
        for value in ("x", "a" * 400, "with-dashes_and.dots/and+slash=eq"):
            with self.subTest(length=len(value)):
                self.env_path.write_text(f"# note\n{KEY}={value}\nOTHER=1\n", encoding="utf-8")
                self.assertTrue(envfile.mint(str(self.env_path), KEY, check_mode=False)["valid"])

    def test_a_file_without_exactly_one_non_empty_line_for_the_key_is_refused(self) -> None:
        for label, text in (
            ("empty value", f"{KEY}=\n"),
            ("blank value", f"{KEY}=   \n"),
            ("absent key", f"OTHER={HAND_SECRET}\n"),
            ("two lines", f"{KEY}={HAND_SECRET}\n{KEY}={HAND_SECRET}2\n"),
            ("empty file", ""),
            ("key only", f"{KEY}\n"),
        ):
            with self.subTest(label):
                self.env_path.write_text(text, encoding="utf-8")
                with self.assertRaises(envfile.EnvFileError) as caught:
                    envfile.mint(str(self.env_path), KEY, check_mode=False)
                self.assertIn(KEY, str(caught.exception))
                self.assertNotIn(HAND_SECRET, str(caught.exception))

    def test_a_link_is_refused_as_the_file(self) -> None:
        target = self.root / "target"
        target.write_text(f"{KEY}=x\n", encoding="utf-8")
        self.env_path.symlink_to(target)
        with self.assertRaises(envfile.EnvFileError):
            envfile.mint(str(self.env_path), KEY, check_mode=False)

    def test_a_key_that_is_not_a_variable_name_is_refused(self) -> None:
        with self.assertRaises(envfile.EnvFileError):
            envfile.mint(str(self.env_path), "not a key", check_mode=False)

    def test_the_file_is_never_opened_wider_than_closed(self) -> None:
        calls: list[int] = []
        real_open = os.open

        def spy(path: str, flags: int, mode: int = 0o777) -> int:
            calls.append(mode)
            return real_open(path, flags, mode)

        with mock.patch.object(os, "open", side_effect=spy):
            envfile.mint(str(self.env_path), KEY, check_mode=False)
        self.assertEqual([0o600], calls)

    def test_a_file_that_appears_while_it_is_made_is_not_replaced(self) -> None:
        self.env_path.write_text(f"{KEY}={HAND_SECRET}\n", encoding="utf-8")
        with self.assertRaises(envfile.EnvFileError):
            envfile.create_exclusive(str(self.env_path), "x\n")
        self.assertEqual(f"{KEY}={HAND_SECRET}\n", self.env_path.read_text(encoding="utf-8"))

    def test_two_secrets_differ(self) -> None:
        self.assertNotEqual(envfile.new_secret(), envfile.new_secret())


class ShimTest(Workdir):
    def test_the_file_is_written_closed_from_the_token(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        result = envfile.shim(str(self.env_path), str(self.credentials), LABEL, check_mode=False)
        self.assertTrue(result["changed"])
        self.assertEqual(envfile.render_shim_env(TOKEN), self.env_path.read_text(encoding="utf-8"))
        self.assertEqual(0o600, self.mode(self.env_path))
        self.assertEqual(["credentials", "env"], sorted(os.listdir(self.root)))

    def test_a_second_run_changes_nothing_and_keeps_the_mtime(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        envfile.shim(str(self.env_path), str(self.credentials), LABEL, check_mode=False)
        before = self.env_path.stat().st_mtime_ns
        result = envfile.shim(str(self.env_path), str(self.credentials), LABEL, check_mode=False)
        self.assertFalse(result["changed"])
        self.assertEqual(before, self.env_path.stat().st_mtime_ns)

    def test_a_new_token_or_a_wider_mode_is_put_right(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        envfile.shim(str(self.env_path), str(self.credentials), LABEL, check_mode=False)
        self.credentials_with(f"{LABEL}:{OTHER_TOKEN}")
        self.assertTrue(
            envfile.shim(str(self.env_path), str(self.credentials), LABEL, check_mode=False)[
                "changed"
            ]
        )
        self.env_path.chmod(0o644)
        self.assertTrue(
            envfile.shim(str(self.env_path), str(self.credentials), LABEL, check_mode=False)[
                "changed"
            ]
        )
        self.assertEqual(0o600, self.mode(self.env_path))

    def test_an_absent_token_is_the_owners_step_and_the_role_never_makes_one(self) -> None:
        self.credentials_with("website:aaa")
        with self.assertRaises(envfile.EnvFileError) as caught:
            envfile.shim(str(self.env_path), str(self.credentials), LABEL, check_mode=False)
        self.assertIn(LABEL, str(caught.exception))
        self.assertIn("never makes it", str(caught.exception))
        self.assertFalse(self.env_path.exists())
        self.assertEqual("website:aaa\n", self.credentials.read_text(encoding="utf-8"))

    def test_a_failed_replace_leaves_the_old_file_and_no_temporary_one(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        envfile.shim(str(self.env_path), str(self.credentials), LABEL, check_mode=False)
        self.credentials_with(f"{LABEL}:{OTHER_TOKEN}")
        with mock.patch.object(os, "replace", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                envfile.shim(str(self.env_path), str(self.credentials), LABEL, check_mode=False)
        self.assertEqual(envfile.render_shim_env(TOKEN), self.env_path.read_text(encoding="utf-8"))
        self.assertEqual(["credentials", "env"], sorted(os.listdir(self.root)))


class ReservedKeysTest(Workdir):
    def test_the_keys_are_named_and_the_values_are_not(self) -> None:
        self.env_path.write_text(
            f"{KEY}={HAND_SECRET}\nCOMPOSE_FILE={HAND_SECRET}\nexport COMPOSE_PROFILES=x\n"
            f"# COMPOSE_COMMENT=1\nNOT_COMPOSE_X=1\n",
            encoding="utf-8",
        )
        failed, document, raw = module_runner.run_module(
            envfile.main, {"action": "reserved_keys", "path": str(self.env_path)}, check_mode=True
        )
        self.assertFalse(failed)
        self.assertEqual(["COMPOSE_FILE", "COMPOSE_PROFILES"], document["found_keys"])
        self.assertNotIn(HAND_SECRET, raw)

    def test_an_absent_file_has_no_reserved_keys(self) -> None:
        self.assertEqual([], envfile.reserved_keys(str(self.env_path), "COMPOSE_")["found_keys"])


class CheckTokenTest(Workdir):
    def test_found_and_not_found(self) -> None:
        self.assertFalse(envfile.check_token(str(self.credentials), LABEL)["found"])
        self.credentials_with(f"{LABEL}:{TOKEN}")
        self.assertTrue(envfile.check_token(str(self.credentials), LABEL)["found"])


class ModuleTest(Workdir):
    """The module as Ansible runs it: check mode writes nothing and no secret is returned."""

    def test_check_mode_writes_nothing_for_every_action(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        before = module_runner.listing(str(self.root))
        for params in (
            {"action": "mint", "path": str(self.env_path)},
            {
                "action": "shim",
                "path": str(self.env_path),
                "credentials_path": str(self.credentials),
            },
            {"action": "check_token", "credentials_path": str(self.credentials)},
        ):
            with self.subTest(action=params["action"]):
                failed, _document, _raw = module_runner.run_module(
                    envfile.main, params, check_mode=True
                )
                self.assertFalse(failed)
                self.assertEqual(before, module_runner.listing(str(self.root)))
                self.assertEqual(["credentials"], os.listdir(self.root))

    def test_no_action_returns_a_secret_in_check_mode_or_out_of_it(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        results = []
        for check_mode in (True, False):
            for params in (
                {
                    "action": "shim",
                    "path": str(self.env_path),
                    "credentials_path": str(self.credentials),
                },
                {"action": "check_token", "credentials_path": str(self.credentials)},
                {"action": "mint", "path": str(self.root / "stalwart.env")},
            ):
                _failed, _document, raw = module_runner.run_module(
                    envfile.main, params, check_mode=check_mode
                )
                results.append(raw)
        minted = (self.root / "stalwart.env").read_text(encoding="utf-8").split("=", 1)[1].strip()
        for raw in results:
            self.assertNotIn(TOKEN, raw)
            self.assertNotIn(minted, raw)

    def test_a_refusal_does_not_echo_the_credentials_file(self) -> None:
        self.credentials_with(f"broken{TOKEN}", f"{LABEL}:{TOKEN}")
        failed, document, raw = module_runner.run_module(
            envfile.main,
            {"action": "check_token", "credentials_path": str(self.credentials)},
        )
        self.assertTrue(failed)
        self.assertIn("mx1 check_token", str(document["msg"]))
        self.assertNotIn(TOKEN, raw)

    def test_the_shim_action_through_the_module_writes_the_same_file(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        failed, document, _raw = module_runner.run_module(
            envfile.main,
            {
                "action": "shim",
                "path": str(self.env_path),
                "credentials_path": str(self.credentials),
            },
        )
        self.assertFalse(failed)
        self.assertTrue(document["changed"])
        self.assertEqual(envfile.render_shim_env(TOKEN), self.env_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
