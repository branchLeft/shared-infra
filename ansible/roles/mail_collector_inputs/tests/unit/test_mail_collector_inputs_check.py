"""Unit tests for mail_collector_inputs_check, the read-only check of the collector's input file.

Every file here is made by the test in a temporary directory and holds a made-up value. The
real file is never read. The owner check takes the test's own uid and gid, because the test
does not run as root; a test pins that the module's defaults are root's.

Sabotage controls (each goes red when the named line of the module is broken, and the README
gives the commands): test_heartbeat_with_no_descriptor_is_refused for the host-named guard,
test_group_readable_file_is_refused for the mode check, test_unknown_key_is_refused for the
key namespace, and test_no_result_carries_a_value for the rule that no value is returned.
"""

import contextlib
import inspect
import json
import os
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path

import mail_collector_inputs_check as check

UID = os.getuid()
GID = os.getgid()

# Made-up values. Each is long and distinctive so a leak into a result is found by a substring.
VALUE_A = "CANARYdrainVALUE_A0123456789abcdefghijklmnop"
VALUE_B = "CANARYsmtpVALUE_B0123456789"
USER = "CANARYsmtpUSER"
URL = "https://hc-ping.com/00000000-0000-4000-8000-000000000000"
CANARIES = (VALUE_A, VALUE_B, USER, "00000000-0000-4000-8000")

GOOD = {
    "COLLECTOR_DRAIN_TOKEN": VALUE_A,
    "COLLECTOR_HEARTBEAT_URL": URL,
    "COLLECTOR_SMTP_USER": USER,
    "COLLECTOR_SMTP_PASS": VALUE_B,
}


class Fixture:
    """A temporary directory with an input file and a descriptor directory."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.directory = root / "collector"
        self.directory.mkdir(mode=0o755)
        self.directory.chmod(0o755)
        self.descriptors = self.directory / "descriptors"
        self.descriptors.mkdir(mode=0o755)
        self.secrets = self.directory / "secrets.env"

    def write(self, values: dict[str, str], *, mode: int = 0o600, extra: str = "") -> None:
        """Write the input file with these keys and this mode."""
        text = "".join(f"{key}={value}\n" for key, value in values.items()) + extra
        self.secrets.write_text(text)
        self.secrets.chmod(mode)

    def name_a_host(self) -> None:
        """Put one descriptor file in the descriptor directory."""
        (self.descriptors / "demo.json").write_text("{}")

    def run(self) -> check.Result:
        """Run the check as the test's own user."""
        return check.check_inputs(
            str(self.secrets), str(self.descriptors), owner_uid=UID, owner_gid=GID
        )


@contextlib.contextmanager
def fixture() -> Iterator[Fixture]:
    """Yield a fresh fixture and remove it afterwards."""
    with tempfile.TemporaryDirectory() as name:
        yield Fixture(Path(name))


class AbsentTest(unittest.TestCase):
    """An absent file is not a fault: the collector is not meant to run yet."""

    def test_absent_file_is_present_false_with_no_problem(self) -> None:
        with fixture() as f:
            result = f.run()
        self.assertFalse(result.present)
        self.assertEqual([], result.problems)

    def test_absent_file_with_no_descriptor_is_still_not_a_fault(self) -> None:
        with fixture() as f:
            f.descriptors.rmdir()
            result = f.run()
        self.assertEqual([], result.problems)


class ValidTest(unittest.TestCase):
    """A good file with a host named passes."""

    def test_good_file_and_one_host_has_no_problem(self) -> None:
        with fixture() as f:
            f.write(GOOD)
            f.name_a_host()
            result = f.run()
        self.assertTrue(result.present)
        self.assertEqual([], result.problems)
        self.assertEqual(1, result.descriptor_count)

    def test_comments_blank_lines_and_other_collector_keys_are_allowed(self) -> None:
        with fixture() as f:
            f.write(GOOD, extra="\n# a note\nCOLLECTOR_SHIM_PORT=8080\n")
            f.name_a_host()
            result = f.run()
        self.assertEqual([], result.problems)

    def test_ping_key_and_slug_form_is_allowed(self) -> None:
        with fixture() as f:
            f.write({**GOOD, "COLLECTOR_HEARTBEAT_URL": "https://hc-ping.com/abcDEF123/collector"})
            f.name_a_host()
            result = f.run()
        self.assertEqual([], result.problems)


class HostNamedTest(unittest.TestCase):
    """A real heartbeat with an empty drain list would page, so it is refused."""

    def test_heartbeat_with_no_descriptor_is_refused(self) -> None:
        with fixture() as f:
            f.write(GOOD)
            result = f.run()
        self.assertIn(check.E_NO_HOST, result.problems)

    def test_a_directory_named_like_a_descriptor_does_not_count(self) -> None:
        with fixture() as f:
            f.write(GOOD)
            (f.descriptors / "demo.json").mkdir()
            result = f.run()
        self.assertIn(check.E_NO_HOST, result.problems)

    def test_a_link_named_like_a_descriptor_does_not_count(self) -> None:
        with fixture() as f:
            f.write(GOOD)
            (f.root / "elsewhere.json").write_text("{}")
            (f.descriptors / "demo.json").symlink_to(f.root / "elsewhere.json")
            result = f.run()
        self.assertIn(check.E_NO_HOST, result.problems)

    def test_other_suffix_does_not_count(self) -> None:
        with fixture() as f:
            f.write(GOOD)
            (f.descriptors / "demo.txt").write_text("{}")
            result = f.run()
        self.assertIn(check.E_NO_HOST, result.problems)

    def test_missing_descriptor_directory_is_named(self) -> None:
        with fixture() as f:
            f.write(GOOD)
            f.descriptors.rmdir()
            result = f.run()
        self.assertIn(check.E_DESCRIPTORS, result.problems)


class FileTest(unittest.TestCase):
    """The file must be the owner's, mode 0600, a plain file with one name."""

    def test_group_readable_file_is_refused(self) -> None:
        with fixture() as f:
            f.write(GOOD, mode=0o640)
            f.name_a_host()
            result = f.run()
        self.assertEqual([check.E_FILE], result.problems)

    def test_world_readable_file_is_refused(self) -> None:
        with fixture() as f:
            f.write(GOOD, mode=0o644)
            f.name_a_host()
            result = f.run()
        self.assertEqual([check.E_FILE], result.problems)

    def test_owner_read_only_file_is_refused(self) -> None:
        with fixture() as f:
            f.write(GOOD, mode=0o400)
            f.name_a_host()
            result = f.run()
        self.assertEqual([check.E_FILE], result.problems)

    def test_link_to_a_good_file_is_refused(self) -> None:
        with fixture() as f:
            real = f.root / "real.env"
            real.write_text("".join(f"{k}={v}\n" for k, v in GOOD.items()))
            real.chmod(0o600)
            f.secrets.symlink_to(real)
            f.name_a_host()
            result = f.run()
        self.assertEqual([check.E_FILE], result.problems)

    def test_second_hard_link_is_refused(self) -> None:
        with fixture() as f:
            f.write(GOOD)
            os.link(f.secrets, f.root / "second.env")
            f.name_a_host()
            result = f.run()
        self.assertEqual([check.E_FILE], result.problems)

    def test_directory_in_place_of_the_file_is_refused(self) -> None:
        with fixture() as f:
            f.secrets.mkdir()
            result = f.run()
        self.assertEqual([check.E_FILE], result.problems)

    def test_fifo_in_place_of_the_file_is_refused_without_blocking(self) -> None:
        with fixture() as f:
            os.mkfifo(f.secrets, 0o600)
            result = f.run()
        self.assertEqual([check.E_FILE], result.problems)

    def test_wrong_owner_is_refused(self) -> None:
        with fixture() as f:
            f.write(GOOD)
            f.name_a_host()
            result = check.check_inputs(
                str(f.secrets), str(f.descriptors), owner_uid=UID + 1, owner_gid=GID
            )
        self.assertIn(check.E_FILE, result.problems)

    def test_group_writable_directory_is_named(self) -> None:
        with fixture() as f:
            f.write(GOOD)
            f.name_a_host()
            f.directory.chmod(0o775)
            result = f.run()
        self.assertEqual([check.E_DIRECTORY], result.problems)

    def test_defaults_are_root(self) -> None:
        defaults = inspect.signature(check.check_inputs).parameters
        self.assertEqual(0, defaults["owner_uid"].default)
        self.assertEqual(0, defaults["owner_gid"].default)
        self.assertEqual(0o600, check.FILE_MODE)


class ContentTest(unittest.TestCase):
    """The keys the collector cannot run without, and the shape of each."""

    def run_with(self, values: dict[str, str], extra: str = "") -> list[str]:
        """Return the problems for a file with these keys."""
        with fixture() as f:
            f.write(values, extra=extra)
            f.name_a_host()
            return f.run().problems

    def test_each_required_key_is_required(self) -> None:
        for key in check.REQUIRED_KEYS:
            values = {k: v for k, v in GOOD.items() if k != key}
            self.assertEqual([f"{check.E_MISSING}:{key}"], self.run_with(values), key)

    def test_an_empty_value_counts_as_missing(self) -> None:
        values = {**GOOD, "COLLECTOR_SMTP_PASS": ""}
        self.assertEqual([f"{check.E_MISSING}:COLLECTOR_SMTP_PASS"], self.run_with(values))

    def test_short_drain_token_is_refused(self) -> None:
        values = {**GOOD, "COLLECTOR_DRAIN_TOKEN": "x" * (check.MIN_TOKEN_LENGTH - 1)}
        self.assertEqual([check.E_SHORT], self.run_with(values))

    def test_token_of_minimum_length_is_allowed(self) -> None:
        values = {**GOOD, "COLLECTOR_DRAIN_TOKEN": "x" * check.MIN_TOKEN_LENGTH}
        self.assertEqual([], self.run_with(values))

    def test_other_heartbeat_hosts_are_refused(self) -> None:
        for url in (
            "https://example.com/00000000-0000-4000-8000-000000000000",
            "http://hc-ping.com/00000000-0000-4000-8000-000000000000",
            "https://hc-ping.com/00000000-0000-4000-8000-000000000000/fail",
            "https://hc-ping.com/",
            "https://hc-ping.com.example.com/abc",
        ):
            values = {**GOOD, "COLLECTOR_HEARTBEAT_URL": url}
            self.assertEqual([check.E_URL], self.run_with(values), url)

    def test_value_with_a_dollar_sign_or_quote_is_refused_by_key(self) -> None:
        for bad in ("pa$word", 'pa"ss', "pa'ss", "pa ss", "pa\\ss", "pa`ss"):
            values = {**GOOD, "COLLECTOR_SMTP_PASS": bad}
            self.assertEqual([f"{check.E_VALUE}:COLLECTOR_SMTP_PASS"], self.run_with(values), bad)

    def test_unknown_key_is_refused(self) -> None:
        self.assertEqual([f"{check.E_UNKNOWN}:5"], self.run_with(GOOD, extra="NODE_OPTIONS=x\n"))

    def test_lower_case_key_is_a_line_shape_fault(self) -> None:
        self.assertEqual([f"{check.E_LINE}:5"], self.run_with(GOOD, extra="collector_x=1\n"))

    def test_line_without_equals_is_a_line_shape_fault_by_number(self) -> None:
        self.assertEqual([f"{check.E_LINE}:5"], self.run_with(GOOD, extra="notakeyvalue\n"))

    def test_duplicate_key_is_named(self) -> None:
        extra = "COLLECTOR_SMTP_USER=other\n"
        self.assertEqual([f"{check.E_DUPLICATE}:COLLECTOR_SMTP_USER"], self.run_with(GOOD, extra))


class NoValueTest(unittest.TestCase):
    """Nothing returned carries a value: not in a fault, not in a pass."""

    def test_no_result_carries_a_value(self) -> None:
        cases: list[tuple[dict[str, str], str]] = [
            (GOOD, ""),
            ({**GOOD, "COLLECTOR_HEARTBEAT_URL": URL + "/fail"}, ""),
            ({**GOOD, "COLLECTOR_DRAIN_TOKEN": VALUE_A[:10]}, ""),
            ({**GOOD, "COLLECTOR_SMTP_PASS": VALUE_B + "$"}, ""),
            (GOOD, f"{VALUE_A}\n"),
            (GOOD, f"not a line {VALUE_B}\n"),
            (GOOD, f"NODE_OPTIONS={VALUE_B}\n"),
            (GOOD, f"COLLECTOR_SMTP_USER={USER}\n"),
            ({k: v for k, v in GOOD.items() if k != "COLLECTOR_SMTP_USER"}, ""),
        ]
        for values, extra in cases:
            with fixture() as f:
                f.write(values, extra=extra)
                f.name_a_host()
                result = f.run()
            text = json.dumps(
                {
                    "present": result.present,
                    "problems": result.problems,
                    "descriptor_count": result.descriptor_count,
                }
            )
            for canary in CANARIES:
                self.assertNotIn(canary, text)

    def test_a_file_with_no_host_returns_that_one_code_only(self) -> None:
        with fixture() as f:
            f.write(GOOD)
            result = f.run()
        self.assertEqual({check.E_NO_HOST}, set(result.problems))


if __name__ == "__main__":
    unittest.main()
