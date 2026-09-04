#!/usr/bin/env python3
"""Unit tests for `stack/snds/collect_snds_metrics.py`. Imported by path,
matching `test_render_alertmanager_config.py`'s convention.

The parsing tests are the load-bearing half: `parse_snds_response` consumes
text from an external network response with no committed schema (Microsoft's
2026 migration removed the one that existed), so it is exercised here against
well-formed input, a header row, and -- per workspace CLAUDE.md's standard for
security-sensitive input parsing -- malformed and adversarial input that a
naive parser would mishandle.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock

MODULE_PATH = (
    pathlib.Path(__file__).resolve().parent / "stack" / "snds" / "collect_snds_metrics.py"
)

_spec = importlib.util.spec_from_file_location("collect_snds_metrics", MODULE_PATH)
assert _spec is not None and _spec.loader is not None
collect_snds_metrics = importlib.util.module_from_spec(_spec)
# Registered before exec so the module's own `from __future__ import
# annotations` dataclass fields can resolve their string annotations against
# it -- dataclasses looks the defining module up via sys.modules, which a
# path-loaded module is not in unless this is done explicitly.
sys.modules[_spec.name] = collect_snds_metrics
_spec.loader.exec_module(collect_snds_metrics)

parse_snds_response = collect_snds_metrics.parse_snds_response
render_prometheus_text = collect_snds_metrics.render_prometheus_text
IpReputation = collect_snds_metrics.IpReputation


class ParseWellFormedTests(unittest.TestCase):
    def test_parses_a_full_row(self) -> None:
        records = parse_snds_response("203.0.113.5,green,0.05%,12000")
        self.assertEqual(
            records,
            [IpReputation(ip="203.0.113.5", status="green", complaint_rate=0.0005, volume=12000)],
        )

    def test_parses_multiple_rows(self) -> None:
        records = parse_snds_response(
            "203.0.113.5,green,0.05%,12000\n" "198.51.100.9,red,1.2%,300\n"
        )
        self.assertEqual([r.ip for r in records], ["203.0.113.5", "198.51.100.9"])
        self.assertEqual(records[1].status, "red")
        self.assertAlmostEqual(records[1].complaint_rate, 0.012)

    def test_skips_an_optional_header_row(self) -> None:
        records = parse_snds_response(
            "IP Address,Status,Complaint Rate,Volume\n203.0.113.5,green,0.05%,12000"
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].ip, "203.0.113.5")

    def test_skips_blank_lines(self) -> None:
        records = parse_snds_response("203.0.113.5,green,0.05%,12000\n\n\n")
        self.assertEqual(len(records), 1)

    def test_empty_input_yields_no_records(self) -> None:
        self.assertEqual(parse_snds_response(""), [])

    def test_a_fractional_complaint_rate_with_no_percent_sign_is_taken_literally(self) -> None:
        # Not a percentage without the sign -- 0.0005 here means 0.05%, not 0.05%.
        records = parse_snds_response("203.0.113.5,green,0.0005,12000")
        self.assertAlmostEqual(records[0].complaint_rate, 0.0005)


class NoRateTokenTests(unittest.TestCase):
    """SNDS reports 'None' (or blank) when volume was too low to compute a
    rate. That must not become a rate of 0.0 -- a computed zero and "nothing
    computed" are different claims about the same IP.
    """

    def test_none_token_yields_no_complaint_rate(self) -> None:
        records = parse_snds_response("203.0.113.5,green,None,4")
        self.assertIsNone(records[0].complaint_rate)

    def test_blank_field_yields_no_complaint_rate(self) -> None:
        records = parse_snds_response("203.0.113.5,green,,4")
        self.assertIsNone(records[0].complaint_rate)

    def test_case_and_whitespace_insensitive(self) -> None:
        records = parse_snds_response("203.0.113.5,green, NONE ,4")
        self.assertIsNone(records[0].complaint_rate)

    def test_a_computed_zero_is_not_confused_with_absent(self) -> None:
        records = parse_snds_response("203.0.113.5,green,0%,500")
        self.assertEqual(records[0].complaint_rate, 0.0)


class MalformedAndAdversarialInputTests(unittest.TestCase):
    """The parser must isolate one bad row rather than losing the whole feed,
    and must never let unvalidated input reach a metric label -- this is the
    property the exposition-format sabotage in the PR record breaks and
    re-proves.
    """

    def test_an_invalid_ip_is_skipped_not_raised(self) -> None:
        records = parse_snds_response("not-an-ip,green,0.05%,12000")
        self.assertEqual(records, [])

    def test_one_bad_row_does_not_drop_the_good_rows_around_it(self) -> None:
        records = parse_snds_response(
            "203.0.113.5,green,0.05%,12000\n"
            "garbage-row-not-an-ip\n"
            "198.51.100.9,red,1.2%,300\n"
        )
        self.assertEqual([r.ip for r in records], ["203.0.113.5", "198.51.100.9"])

    def test_an_unrecognised_status_is_treated_as_absent_not_fatal(self) -> None:
        records = parse_snds_response("203.0.113.5,purple,0.05%,12000")
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].status)

    def test_an_unparseable_complaint_rate_is_treated_as_absent_not_fatal(self) -> None:
        records = parse_snds_response("203.0.113.5,green,not-a-number,12000")
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].complaint_rate)

    def test_an_unparseable_volume_is_treated_as_absent_not_fatal(self) -> None:
        records = parse_snds_response("203.0.113.5,green,0.05%,not-a-number")
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].volume)

    def test_a_short_row_yields_a_status_only_record(self) -> None:
        records = parse_snds_response("203.0.113.5,green")
        self.assertEqual(records, [IpReputation(ip="203.0.113.5", status="green", complaint_rate=None, volume=None)])

    def test_an_ip_only_row_yields_a_bare_record(self) -> None:
        records = parse_snds_response("203.0.113.5")
        self.assertEqual(records, [IpReputation(ip="203.0.113.5", status=None, complaint_rate=None, volume=None)])

    def test_an_injected_field_cannot_smuggle_a_second_metric_line(self) -> None:
        # A naive f-string render of an unvalidated IP field would let a
        # crafted value break out of the label value and append its own
        # metric line to the exposition text. ip_address() round-tripping
        # rejects anything that is not a real address before it ever reaches
        # render_prometheus_text, so the attempted injection is dropped
        # entirely rather than rendered.
        hostile = '1.2.3.4"} 999\nsnds_complaint_rate{ip="5.6.7.8'
        records = parse_snds_response(f"{hostile},green,0.05%,12000")
        self.assertEqual(records, [])
        rendered = render_prometheus_text(records, now=1_700_000_000.0)
        self.assertNotIn("999", rendered)
        self.assertEqual(rendered.count("snds_complaint_rate{"), 0)


class RenderPrometheusTextTests(unittest.TestCase):
    def test_renders_all_four_metric_families(self) -> None:
        records = [IpReputation(ip="203.0.113.5", status="green", complaint_rate=0.0005, volume=12000)]
        rendered = render_prometheus_text(records, now=1_700_000_000.0)
        self.assertIn('snds_complaint_rate{ip="203.0.113.5"} 0.0005', rendered)
        self.assertIn('snds_message_volume{ip="203.0.113.5"} 12000', rendered)
        self.assertIn('snds_reputation_status{ip="203.0.113.5",status="green"} 1', rendered)
        self.assertIn("snds_collector_last_success_timestamp_seconds 1700000000.0", rendered)

    def test_a_record_with_no_computed_rate_emits_no_complaint_rate_series(self) -> None:
        records = [IpReputation(ip="203.0.113.5", status="green", complaint_rate=None, volume=4)]
        rendered = render_prometheus_text(records, now=1_700_000_000.0)
        self.assertNotIn("snds_complaint_rate{", rendered)
        self.assertIn('snds_message_volume{ip="203.0.113.5"} 4', rendered)

    def test_the_freshness_gauge_is_always_present_even_with_no_records(self) -> None:
        rendered = render_prometheus_text([], now=1_700_000_000.0)
        self.assertIn("snds_collector_last_success_timestamp_seconds 1700000000.0", rendered)

    def test_output_is_well_formed_exposition_text(self) -> None:
        records = [IpReputation(ip="203.0.113.5", status="red", complaint_rate=0.01, volume=50)]
        rendered = render_prometheus_text(records, now=1_700_000_000.0)
        for line in rendered.splitlines():
            self.assertTrue(line.startswith("#") or "{" in line or " " in line)
        self.assertTrue(rendered.endswith("\n"))


class WriteTextfileAtomicallyTests(unittest.TestCase):
    def test_writes_content_and_leaves_no_tmp_file_behind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "snds.prom"
            collect_snds_metrics.write_textfile_atomically(path, "hello\n")
            self.assertEqual(path.read_text(), "hello\n")
            self.assertFalse(path.with_suffix(".prom.tmp").exists())

    def test_the_output_is_world_readable_regardless_of_umask(self) -> None:
        # node-exporter's container reads this bind mount as its own
        # container-side user (65534), not as whoever wrote the file --
        # explicit 0644 is what makes that read succeed on a host whose
        # umask would otherwise leave it group/other-unreadable.
        import stat

        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "snds.prom"
            old_umask = collect_snds_metrics.os.umask(0o077)
            try:
                collect_snds_metrics.write_textfile_atomically(path, "hello\n")
            finally:
                collect_snds_metrics.os.umask(old_umask)
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o644)

    def test_a_second_write_replaces_the_first_rather_than_appending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "snds.prom"
            collect_snds_metrics.write_textfile_atomically(path, "first\n")
            collect_snds_metrics.write_textfile_atomically(path, "second\n")
            self.assertEqual(path.read_text(), "second\n")


class MainFailureLeavesPreviousOutputTests(unittest.TestCase):
    """A fetch failure (network error, expired bearer token) must not blank
    out the previous day's snapshot -- that would turn a transient failure
    into a false "no complaints on record" reading. Proven here by seeding an
    existing textfile, forcing the fetch to fail, and asserting the file is
    byte-for-byte untouched.
    """

    def test_a_fetch_failure_leaves_the_existing_textfile_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = pathlib.Path(tmp) / "snds.prom"
            output_path.write_text("previous-content\n")

            with mock.patch.dict(
                collect_snds_metrics.os.environ,
                {"SNDS_BEARER_TOKEN": "token", "SNDS_OUTPUT_PATH": str(output_path)},
                clear=False,
            ), mock.patch.object(
                collect_snds_metrics,
                "fetch_snds_data",
                side_effect=collect_snds_metrics.urllib.error.URLError("boom"),
            ):
                exit_code = collect_snds_metrics.main([])

            self.assertEqual(exit_code, 1)
            self.assertEqual(output_path.read_text(), "previous-content\n")

    def test_a_missing_token_makes_no_network_call_and_leaves_output_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = pathlib.Path(tmp) / "snds.prom"
            output_path.write_text("previous-content\n")

            env = {k: v for k, v in collect_snds_metrics.os.environ.items() if k != "SNDS_BEARER_TOKEN"}
            env["SNDS_OUTPUT_PATH"] = str(output_path)
            with mock.patch.dict(collect_snds_metrics.os.environ, env, clear=True), mock.patch.object(
                collect_snds_metrics, "fetch_snds_data"
            ) as fetch:
                exit_code = collect_snds_metrics.main([])
                fetch.assert_not_called()

            self.assertEqual(exit_code, 1)
            self.assertEqual(output_path.read_text(), "previous-content\n")

    def test_a_successful_run_writes_fresh_content_and_advances_the_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = pathlib.Path(tmp) / "snds.prom"
            output_path.write_text("stale-content\n")

            with mock.patch.dict(
                collect_snds_metrics.os.environ,
                {"SNDS_BEARER_TOKEN": "token", "SNDS_OUTPUT_PATH": str(output_path)},
                clear=False,
            ), mock.patch.object(
                collect_snds_metrics,
                "fetch_snds_data",
                return_value="203.0.113.5,green,0.05%,12000",
            ):
                before = time.time()
                exit_code = collect_snds_metrics.main([])

            self.assertEqual(exit_code, 0)
            content = output_path.read_text()
            self.assertIn('snds_complaint_rate{ip="203.0.113.5"} 0.0005', content)
            self.assertNotIn("stale-content", content)
            # The freshness gauge is a real, current timestamp -- not a
            # constant carried over from the module's import time.
            written_ts = float(
                [
                    line
                    for line in content.splitlines()
                    if line.startswith("snds_collector_last_success_timestamp_seconds ")
                ][0].split()[-1]
            )
            self.assertGreaterEqual(written_ts, before)


class FetchSndsDataTests(unittest.TestCase):
    def test_sends_the_bearer_token_as_an_authorization_header(self) -> None:
        captured: dict[str, object] = {}

        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *exc: object) -> None:
                return None

            def read(self) -> bytes:
                return b"203.0.113.5,green,0.05%,12000"

        def fake_urlopen(request: object, timeout: float) -> FakeResponse:
            captured["headers"] = dict(request.header_items())  # type: ignore[attr-defined]
            captured["url"] = request.full_url  # type: ignore[attr-defined]
            return FakeResponse()

        with mock.patch.object(collect_snds_metrics.urllib.request, "urlopen", fake_urlopen):
            body = collect_snds_metrics.fetch_snds_data("https://example.test/ipstatus", "s3cr3t")

        self.assertEqual(body, "203.0.113.5,green,0.05%,12000")
        self.assertEqual(captured["headers"].get("Authorization"), "Bearer s3cr3t")
        self.assertEqual(captured["url"], "https://example.test/ipstatus")


if __name__ == "__main__":
    unittest.main()
