"""Unit tests for mx1_stack_envfile: the two environment files, and that no secret leaves the host.

Run from the role's directory with library/ on PYTHONPATH, the way
``ansible/checks/run_role_unit_tests.sh`` does. Every secret here is a throwaway made for the test.
"""

import copy
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest import mock

import module_runner
import mx1_stack_envfile as envfile

TOKEN = "THROWAWAY-SHIM-SECRET_0001"  # noqa: S105
OTHER_TOKEN = "THROWAWAY-SHIM-SECRET_0002"  # noqa: S105
HAND_SECRET = "pasted-by-hand"  # noqa: S105
KEY = "STALWART_PROMETHEUS_SECRET"
SMTP_LABEL = "blog-shim-bulk-submission"
DRAIN_LABEL = "shim-drain-token"
LABEL = SMTP_LABEL
SHIM_IMAGE_NAME = "ghcr.io/branchleft/mailgun-shim"
PINNED_DIGEST = "sha256:37c60999cd3bad612f5f1d4947ddf88716e138b17ddf9dd29a23964b88b7c21d"
DRAIN_DIGEST = "sha256:" + "d" * 64
UNLISTED_DIGEST = "sha256:" + "e" * 64
IMAGE = f"{SHIM_IMAGE_NAME}@{PINNED_DIGEST}"
DRAIN_IMAGE = f"{SHIM_IMAGE_NAME}@{DRAIN_DIGEST}"
UNLISTED_IMAGE = f"{SHIM_IMAGE_NAME}@{UNLISTED_DIGEST}"
# The role reads the table through its link to the one file in mail/provision.
TABLE_PATH = Path(__file__).resolve().parents[2] / "files" / "shim-env-contracts.json"


def real_table() -> dict[str, object]:
    return cast("dict[str, object]", json.loads(TABLE_PATH.read_text(encoding="utf-8")))


def table_with_a_drain_image() -> dict[str, object]:
    """The real table, plus a digest that reads the drain contract (none does today)."""
    table = copy.deepcopy(real_table())
    table["digests"][DRAIN_DIGEST] = "drain"  # type: ignore[index]
    return table


SMTP_ENV = (
    "PORT=8080\nSHIM_DB_PATH=/data/shim.db\nSHIM_THROTTLE_PATH=/data/throttle.json\n"
    "SMTP_HOST=mx1.branchleft.co.uk\nSMTP_PORT=587\nSMTP_SECURE=false\n"
    f"SMTP_USER=blog@branchleft.co.uk\nSMTP_PASS={TOKEN}\n"
)
DRAIN_ENV = (
    "PORT=8080\nSHIM_DB_PATH=/data/shim.db\nSHIM_THROTTLE_PATH=/data/throttle.json\n"
    f"SHIM_DRAIN_OUTCOMES=true\nSHIM_DRAIN_TOKEN={TOKEN}\n"
)


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

    def shim(
        self,
        image: str = IMAGE,
        table: dict[str, object] | None = None,
        *,
        check_mode: bool = False,
    ) -> dict[str, object]:
        return envfile.shim(
            str(self.env_path),
            str(self.credentials),
            image,
            real_table() if table is None else table,
            check_mode=check_mode,
        )


class RenderTest(unittest.TestCase):
    def test_the_smtp_delivery_file_is_the_eight_lines_the_hand_route_renders(self) -> None:
        self.assertEqual(
            SMTP_ENV,
            envfile.render_shim_env(real_table()["contracts"]["smtp-delivery"], TOKEN),  # type: ignore[index]
        )

    def test_the_drain_file_is_the_four_lines_the_drain_image_reads(self) -> None:
        self.assertEqual(
            DRAIN_ENV,
            envfile.render_shim_env(real_table()["contracts"]["drain"], TOKEN),  # type: ignore[index]
        )


class ContractForImageTest(unittest.TestCase):
    def test_the_pinned_digest_selects_smtp_delivery(self) -> None:
        contract = envfile.contract_for_image(IMAGE, real_table())
        self.assertEqual(SMTP_LABEL, contract["secret_label"])

    def test_a_drain_digest_selects_the_drain_contract(self) -> None:
        contract = envfile.contract_for_image(DRAIN_IMAGE, table_with_a_drain_image())
        self.assertEqual(DRAIN_LABEL, contract["secret_label"])

    def test_an_unlisted_digest_is_refused_by_digest_and_nothing_is_guessed(self) -> None:
        with self.assertRaises(envfile.EnvFileError) as caught:
            envfile.contract_for_image(UNLISTED_IMAGE, real_table())
        self.assertIn(UNLISTED_DIGEST, str(caught.exception))
        self.assertIn("shim-env-contracts.json", str(caught.exception))

    def test_an_image_that_is_not_the_shim_pinned_by_digest_is_refused(self) -> None:
        for image in (
            f"{SHIM_IMAGE_NAME}:latest",
            f"{SHIM_IMAGE_NAME}@sha256:IMAGE_DIGEST_PLACEHOLDER",
            f"other/shim@{PINNED_DIGEST}",
            f"{IMAGE}\n",
            "",
        ):
            with self.subTest(image=image[:40]), self.assertRaises(envfile.EnvFileError):
                envfile.contract_for_image(image, real_table())

    def test_a_malformed_table_is_refused(self) -> None:
        broken: dict[str, object] = copy.deepcopy(real_table())
        broken["contracts"]["smtp-delivery"]["env_lines"] = ["PORT=8080"]  # type: ignore[index]
        tables: list[dict[str, object]] = [{}, {"contracts": [], "digests": {}}, broken]
        for table in tables:
            with self.subTest(table=str(table)[:30]), self.assertRaises(envfile.EnvFileError):
                envfile.contract_for_image(IMAGE, table)


class TokenTest(Workdir):
    def test_the_token_is_found_by_label_among_other_labels(self) -> None:
        self.credentials_with("website:aaa", f"{LABEL}:{TOKEN}", "blog:bbb")
        self.assertEqual(TOKEN, envfile.recorded_secret(str(self.credentials), LABEL))

    def test_a_secret_may_hold_a_colon(self) -> None:
        self.credentials_with(f"{LABEL}:a:b")
        self.assertEqual("a:b", envfile.recorded_secret(str(self.credentials), LABEL))

    def test_an_absent_file_or_label_is_not_found(self) -> None:
        self.assertIsNone(envfile.recorded_secret(str(self.credentials), LABEL))
        self.credentials_with("website:aaa")
        self.assertIsNone(envfile.recorded_secret(str(self.credentials), LABEL))

    def test_a_malformed_line_is_refused_by_number_and_never_quoted(self) -> None:
        self.credentials_with("website:aaa", f"nocolon{TOKEN}")
        with self.assertRaises(envfile.EnvFileError) as caught:
            envfile.recorded_secret(str(self.credentials), LABEL)
        self.assertIn("line 2", str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_an_empty_or_spaced_token_is_refused_without_quoting_it(self) -> None:
        for line in (f"{LABEL}:", f"{LABEL}:has a space{TOKEN}", f"{LABEL}:tab\there"):
            with self.subTest(line=line[:14]):
                self.credentials_with(line)
                with self.assertRaises(envfile.EnvFileError) as caught:
                    envfile.recorded_secret(str(self.credentials), LABEL)
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
    def test_the_file_is_written_closed_from_the_secret(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        result = self.shim()
        self.assertTrue(result["changed"])
        self.assertEqual(SMTP_ENV, self.env_path.read_text(encoding="utf-8"))
        self.assertEqual(0o600, self.mode(self.env_path))
        self.assertEqual(["credentials", "env"], sorted(os.listdir(self.root)))

    def test_a_drain_image_reads_the_drain_label_and_renders_the_drain_file(self) -> None:
        self.credentials_with(f"{SMTP_LABEL}:{OTHER_TOKEN}", f"{DRAIN_LABEL}:{TOKEN}")
        self.shim(DRAIN_IMAGE, table_with_a_drain_image())
        self.assertEqual(DRAIN_ENV, self.env_path.read_text(encoding="utf-8"))

    def test_an_unlisted_digest_writes_nothing_and_leaves_a_live_file_alone(self) -> None:
        # Sabotage: make contract_for_image fall back to a contract for an unknown digest and this
        # goes red. The failure it guards is a guessed environment for an image nobody described.
        self.credentials_with(f"{LABEL}:{TOKEN}")
        self.env_path.write_text("LIVE=untouched\n", encoding="utf-8")
        with self.assertRaises(envfile.EnvFileError) as caught:
            self.shim(UNLISTED_IMAGE)
        self.assertIn(UNLISTED_DIGEST, str(caught.exception))
        self.assertEqual("LIVE=untouched\n", self.env_path.read_text(encoding="utf-8"))

    def test_the_secret_of_the_other_contract_is_not_used(self) -> None:
        # Only the drain label is recorded, but the pinned image reads the SMTP one.
        self.credentials_with(f"{DRAIN_LABEL}:{TOKEN}")
        with self.assertRaises(envfile.EnvFileError) as caught:
            self.shim()
        self.assertIn(SMTP_LABEL, str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertFalse(self.env_path.exists())

    def test_a_second_run_changes_nothing_and_keeps_the_mtime(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        self.shim()
        before = self.env_path.stat().st_mtime_ns
        result = self.shim()
        self.assertFalse(result["changed"])
        self.assertEqual(before, self.env_path.stat().st_mtime_ns)

    def test_a_new_secret_or_a_wider_mode_is_put_right(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        self.shim()
        self.credentials_with(f"{LABEL}:{OTHER_TOKEN}")
        self.assertTrue(self.shim()["changed"])
        self.env_path.chmod(0o644)
        self.assertTrue(self.shim()["changed"])
        self.assertEqual(0o600, self.mode(self.env_path))

    def test_an_absent_secret_is_the_owners_step_and_the_role_never_makes_one(self) -> None:
        for image, table in ((IMAGE, real_table()), (DRAIN_IMAGE, table_with_a_drain_image())):
            with self.subTest(image=image[-8:]):
                self.credentials_with("website:aaa")
                with self.assertRaises(envfile.EnvFileError) as caught:
                    self.shim(image, table)
                self.assertIn("never makes it", str(caught.exception))
                self.assertFalse(self.env_path.exists())
                self.assertEqual("website:aaa\n", self.credentials.read_text(encoding="utf-8"))

    def test_a_failed_replace_leaves_the_old_file_and_no_temporary_one(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        self.shim()
        self.credentials_with(f"{LABEL}:{OTHER_TOKEN}")
        with mock.patch.object(os, "replace", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                self.shim()
        self.assertEqual(SMTP_ENV, self.env_path.read_text(encoding="utf-8"))
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
    def check(
        self, image: str = IMAGE, table: dict[str, object] | None = None
    ) -> dict[str, object]:
        return envfile.check_token(
            str(self.credentials), image, real_table() if table is None else table
        )

    def test_found_and_not_found(self) -> None:
        self.assertFalse(self.check()["found"])
        self.credentials_with(f"{LABEL}:{TOKEN}")
        self.assertTrue(self.check()["found"])

    def test_it_names_the_label_of_the_images_contract_and_never_the_secret(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        result = self.check()
        self.assertEqual(SMTP_LABEL, result["label"])
        self.assertNotIn(TOKEN, str(result))
        self.assertEqual(DRAIN_LABEL, self.check(DRAIN_IMAGE, table_with_a_drain_image())["label"])

    def test_only_the_secret_the_image_reads_counts(self) -> None:
        self.credentials_with(f"{DRAIN_LABEL}:{TOKEN}")
        self.assertFalse(self.check()["found"])
        self.assertTrue(self.check(DRAIN_IMAGE, table_with_a_drain_image())["found"])

    def test_an_unlisted_digest_is_refused(self) -> None:
        with self.assertRaises(envfile.EnvFileError):
            self.check(UNLISTED_IMAGE)


class ModuleTest(Workdir):
    """The module as Ansible runs it: check mode writes nothing and no secret is returned."""

    def shim_params(self, action: str = "shim", image: str = IMAGE) -> dict[str, object]:
        params: dict[str, object] = {
            "action": action,
            "credentials_path": str(self.credentials),
            "image": image,
            "contracts": real_table(),
        }
        if action == "shim":
            params["path"] = str(self.env_path)
        return params

    def test_check_mode_writes_nothing_for_every_action(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        before = module_runner.listing(str(self.root))
        for params in (
            {"action": "mint", "path": str(self.env_path)},
            self.shim_params("shim"),
            self.shim_params("check_token"),
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
                self.shim_params("shim"),
                self.shim_params("check_token"),
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
            envfile.main, self.shim_params("check_token")
        )
        self.assertTrue(failed)
        self.assertIn("mx1 check_token", str(document["msg"]))
        self.assertNotIn(TOKEN, raw)

    def test_an_unlisted_digest_fails_the_module_before_it_writes(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        for action in ("shim", "check_token"):
            with self.subTest(action=action):
                failed, document, _raw = module_runner.run_module(
                    envfile.main, self.shim_params(action, UNLISTED_IMAGE)
                )
                self.assertTrue(failed)
                self.assertIn(UNLISTED_DIGEST, str(document["msg"]))
        self.assertFalse(self.env_path.exists())

    def test_the_shim_action_through_the_module_writes_the_same_file(self) -> None:
        self.credentials_with(f"{LABEL}:{TOKEN}")
        failed, document, _raw = module_runner.run_module(envfile.main, self.shim_params("shim"))
        self.assertFalse(failed)
        self.assertTrue(document["changed"])
        self.assertEqual(SMTP_ENV, self.env_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
