#!/usr/bin/env python3
"""Unit tests for check-crowdsec-hub-pin.

The failure mode this guards against is silent: a stale pin does not crash
anything, it just serves an older agent hub content built for a newer one.
So the case that matters most is not "does it detect a stale pin" alone but
"does it stay quiet on every shape of *not* stale" -- a checker that cries
wolf on a current pin gets ignored by the time it is ever right. Each test
below is aimed at one of those two directions.

No network. `_fetch_latest_release` is the only thing that makes a request,
and it is a thin, mechanical wrapper around urllib -- same reasoning as
`mail/provision/rotate_admin_credential.py`'s equivalent -- so it is not
exercised here; `_parse_latest_payload` carries the logic and is.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import unittest


def _load_module():
    """Import the script by path: its filename has hyphens, so it is not a
    legal module name for a plain import."""
    path = pathlib.Path(__file__).resolve().parent / "check-crowdsec-hub-pin.py"
    spec = importlib.util.spec_from_file_location("check_crowdsec_hub_pin", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


chp = _load_module()


def _compose(image_line: str) -> str:
    return (
        "services:\n"
        "  crowdsec:\n"
        f"    {image_line}\n"
        "    restart: unless-stopped\n"
    )


REAL_PIN = "image: docker.io/crowdsecurity/crowdsec:v1.7.8@sha256:2f527c9bb8b367120eb08b82890aa912ce96bfa1ada93dda0721700e4b4e0dde"


class CompareTests(unittest.TestCase):
    """`compare` has to reproduce chooseBranch's own ordering, not a
    plausible-looking approximation of it."""

    def test_equal_versions(self):
        self.assertEqual(chp.compare("v1.7.8", "v1.7.8"), 0)

    def test_older_is_less(self):
        self.assertEqual(chp.compare("v1.7.7", "v1.7.8"), -1)

    def test_newer_is_greater(self):
        self.assertEqual(chp.compare("v1.7.8", "v1.7.7"), 1)

    def test_double_digit_patch_does_not_sort_as_a_string(self):
        # 'v1.7.10' < 'v1.7.8' as a string. A comparator that forgot to parse
        # the numeric components would report the newer release as older.
        self.assertEqual(chp.compare("v1.7.10", "v1.7.8"), 1)
        self.assertEqual(chp.compare("v1.7.8", "v1.7.10"), -1)

    def test_minor_version_dominates_patch(self):
        self.assertEqual(chp.compare("v1.8.0", "v1.7.99"), 1)

    def test_release_outranks_its_own_prerelease(self):
        self.assertEqual(chp.compare("v1.8.0", "v1.8.0-rc2"), 1)
        self.assertEqual(chp.compare("v1.8.0-rc2", "v1.8.0"), -1)

    def test_unparsable_version_raises(self):
        with self.assertRaises(chp.CheckError):
            chp.compare("not-a-version", "v1.7.8")

    def test_double_digit_prerelease_does_not_sort_as_a_string(self):
        # Same trap as the release triple, one level down: 'rc10' < 'rc2' as
        # a string, but rc10 is the later candidate.
        self.assertEqual(chp.compare("v1.8.0-rc10", "v1.8.0-rc2"), 1)
        self.assertEqual(chp.compare("v1.8.0-rc2", "v1.8.0-rc10"), -1)


class IsPinStaleTests(unittest.TestCase):
    """The exact condition this whole check exists to catch, and the two
    ways it must stay quiet."""

    def test_stale_when_upstream_is_newer(self):
        self.assertTrue(chp.is_pin_stale("v1.7.7", "v1.7.8"))

    def test_not_stale_when_current(self):
        self.assertFalse(chp.is_pin_stale("v1.7.8", "v1.7.8"))

    def test_not_stale_when_pinned_is_ahead(self):
        # Mirrors chooseBranch's semver.Compare(csVersion, latest) == 1
        # branch: a pinned pre-release ahead of the stable "latest" the
        # endpoint reports is still correctly on master, not behind it.
        self.assertFalse(chp.is_pin_stale("v1.8.0-rc2", "v1.7.8"))


class PinnedVersionTests(unittest.TestCase):
    def test_extracts_the_pinned_tag(self):
        self.assertEqual(chp.pinned_version(_compose(REAL_PIN)), "v1.7.8")

    def test_missing_image_line_raises(self):
        with self.assertRaises(chp.CheckError):
            chp.pinned_version(_compose("image: docker.io/crowdsecurity/nope:latest"))

    def test_untagged_reference_raises(self):
        # No '@sha256:...' -- the pattern requires the digest pin the house
        # convention always carries, so a bare tag does not silently match.
        with self.assertRaises(chp.CheckError):
            chp.pinned_version(_compose("image: docker.io/crowdsecurity/crowdsec:v1.7.8"))

    def test_reads_the_committed_compose_file(self):
        # Builds nothing: runs against this repository's own compose.yml, so
        # that file's image line drifting out of the pattern this check
        # expects is itself a test failure, not something only the scheduled
        # workflow discovers weeks later.
        text = chp.COMPOSE_PATH.read_text(encoding="utf-8")
        version = chp.pinned_version(text)
        self.assertRegex(version, r"^v\d+\.\d+\.\d+")

    def test_commented_out_pin_above_the_live_line_does_not_win(self):
        # An unanchored search takes the first match in file order. A
        # previous pin left commented out above the live line -- the exact
        # residue an image bump tends to leave -- must not silently become
        # "the" pin.
        text = _compose(f"# was: {REAL_PIN}") + _compose(
            "image: docker.io/crowdsecurity/crowdsec:v1.7.9@sha256:"
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        self.assertEqual(chp.pinned_version(text), "v1.7.9")

    def test_two_distinct_live_pins_is_ambiguous_not_a_guess(self):
        text = _compose(REAL_PIN) + _compose(
            "image: docker.io/crowdsecurity/crowdsec:v1.7.9@sha256:"
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        with self.assertRaises(chp.CheckError):
            chp.pinned_version(text)


class ParseLatestPayloadTests(unittest.TestCase):
    def test_parses_the_documented_shape(self):
        raw = b'{"name":"v1.7.8", "tag_name":"v1.7.8", "published_at":"2026-05-11T12:33:30Z"}'
        self.assertEqual(chp._parse_latest_payload(raw), "v1.7.8")

    def test_not_json_raises(self):
        with self.assertRaises(chp.CheckError):
            chp._parse_latest_payload(b"not json")

    def test_missing_name_field_raises(self):
        with self.assertRaises(chp.CheckError):
            chp._parse_latest_payload(b'{"tag_name":"v1.7.8"}')

    def test_json_array_raises(self):
        # A malformed-but-valid-JSON response must not be treated as "no
        # findings" -- there is no report to extract a name from.
        with self.assertRaises(chp.CheckError):
            chp._parse_latest_payload(b"[]")

    def test_name_and_tag_name_disagreeing_raises(self):
        # The two fields have never been observed to differ. A response
        # where they do is closer to a schema change than a release, and
        # trusting `name` alone would silently pick one of two answers.
        raw = b'{"name":"v1.7.8", "tag_name":"v1.7.9"}'
        with self.assertRaises(chp.CheckError):
            chp._parse_latest_payload(raw)

    def test_tag_name_absent_is_fine(self):
        self.assertEqual(chp._parse_latest_payload(b'{"name":"v1.7.8"}'), "v1.7.8")


class ReportTests(unittest.TestCase):
    """The message and the exit code together: a passing exit code paired
    with a message that still says "stale" would be worse than either
    mistake alone, because nothing downstream re-checks the text."""

    def _run(self, pinned: str, latest: str) -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            status = chp.report(pinned, latest)
        return status, buffer.getvalue()

    def test_stale_reports_both_versions_and_fails(self):
        status, output = self._run("v1.7.7", "v1.7.8")
        self.assertEqual(status, 1)
        self.assertIn("v1.7.7", output)
        self.assertIn("v1.7.8", output)
        self.assertIn("::error::", output)

    def test_current_reports_ok_and_passes(self):
        status, output = self._run("v1.7.8", "v1.7.8")
        self.assertEqual(status, 0)
        self.assertIn("OK", output)
        self.assertNotIn("::error::", output)


class MainTests(unittest.TestCase):
    """`--pinned-version` is what demonstrates the guard firing without
    waiting for a real upstream release -- prove it actually overrides the
    compose file rather than being ignored. `_fetch_latest_release` is
    monkeypatched rather than called for real: this test file makes no
    network request, on the same reasoning as the rest of this suite."""

    def test_pinned_version_override_can_report_stale(self):
        original = chp._fetch_latest_release
        chp._fetch_latest_release = lambda: "v1.7.8"
        try:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                status = chp.main(["--pinned-version", "v0.0.1"])
        finally:
            chp._fetch_latest_release = original
        self.assertEqual(status, 1)
        self.assertIn("v0.0.1", buffer.getvalue())

    def test_pinned_version_override_can_report_current(self):
        original = chp._fetch_latest_release
        chp._fetch_latest_release = lambda: "v1.7.8"
        try:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                status = chp.main(["--pinned-version", "v1.7.8"])
        finally:
            chp._fetch_latest_release = original
        self.assertEqual(status, 0)
        self.assertIn("OK", buffer.getvalue())

    def test_unparsable_pinned_version_override_is_exit_2_not_1(self):
        # Regression: report() used to sit outside main()'s try/except, so a
        # CheckError raised inside is_pin_stale() -> compare() ->
        # _parse_release() -- reachable from an override this script never
        # validates, or from a latest-release name that only passed "is a
        # non-empty string" -- went uncaught and the interpreter's own exit
        # status (1) was indistinguishable from a genuine stale finding.
        original = chp._fetch_latest_release
        chp._fetch_latest_release = lambda: "v1.7.8"
        try:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                status = chp.main(["--pinned-version", "not-a-version"])
        finally:
            chp._fetch_latest_release = original
        self.assertEqual(status, 2)
        self.assertNotEqual(status, 1)

    def test_unreadable_compose_file_is_exit_2_not_a_crash(self):
        # Regression: COMPOSE_PATH.read_text() raised a bare OSError that
        # `except CheckError` could not catch, so main() (and the CLI's
        # `sys.exit`) surfaced Python's own exit code for an uncaught
        # exception -- 1, the same code as a genuine stale finding -- for a
        # compose file that was simply missing or moved.
        original_path = chp.COMPOSE_PATH
        chp.COMPOSE_PATH = pathlib.Path("/nonexistent/does-not-exist/compose.yml")
        original_fetch = chp._fetch_latest_release
        chp._fetch_latest_release = lambda: "v1.7.8"
        try:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                status = chp.main([])
        finally:
            chp.COMPOSE_PATH = original_path
            chp._fetch_latest_release = original_fetch
        self.assertEqual(status, 2)
        self.assertNotEqual(status, 1)


if __name__ == "__main__":
    unittest.main()
