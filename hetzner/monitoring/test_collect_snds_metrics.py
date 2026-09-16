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
import urllib.error
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


def _run_main(tmp: str, *, url: str | None = "https://example.test/data?key=abc", **patches):
    """Runs `main` against a temporary output directory, with `SNDS_DATA_URL`
    either set or deliberately absent. Returns `(exit_code, output_dir)`.
    """
    output_dir = pathlib.Path(tmp)
    env = {
        k: v
        for k, v in collect_snds_metrics.os.environ.items()
        if k not in ("SNDS_DATA_URL", "SNDS_OUTPUT_DIR")
    }
    env["SNDS_OUTPUT_DIR"] = str(output_dir)
    if url is not None:
        env["SNDS_DATA_URL"] = url
    with mock.patch.dict(collect_snds_metrics.os.environ, env, clear=True):
        with mock.patch.object(collect_snds_metrics, "fetch_snds_data", **patches):
            return collect_snds_metrics.main([]), output_dir


class MainFailureLeavesPreviousOutputTests(unittest.TestCase):
    """A fetch failure (network error, expired access link) must not blank
    out the previous day's snapshot -- that would turn a transient failure
    into a false "no complaints on record" reading. Proven here by seeding an
    existing textfile, forcing the fetch to fail, and asserting the file is
    byte-for-byte untouched.
    """

    def test_a_fetch_failure_leaves_the_existing_textfile_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = pathlib.Path(tmp) / collect_snds_metrics.REPUTATION_FILENAME
            output_path.write_text("previous-content\n")

            exit_code, _ = _run_main(
                tmp, side_effect=collect_snds_metrics.urllib.error.URLError("boom")
            )

            self.assertEqual(exit_code, 1)
            self.assertEqual(output_path.read_text(), "previous-content\n")

    def test_a_missing_url_makes_no_network_call_and_leaves_output_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = pathlib.Path(tmp) / collect_snds_metrics.REPUTATION_FILENAME
            output_path.write_text("previous-content\n")

            output_dir = pathlib.Path(tmp)
            env = {
                k: v
                for k, v in collect_snds_metrics.os.environ.items()
                if k != "SNDS_DATA_URL"
            }
            env["SNDS_OUTPUT_DIR"] = str(output_dir)
            with mock.patch.dict(
                collect_snds_metrics.os.environ, env, clear=True
            ), mock.patch.object(collect_snds_metrics, "fetch_snds_data") as fetch:
                exit_code = collect_snds_metrics.main([])
                fetch.assert_not_called()

            self.assertEqual(exit_code, 1)
            self.assertEqual(output_path.read_text(), "previous-content\n")

    def test_a_successful_run_writes_fresh_content_and_advances_the_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = pathlib.Path(tmp) / collect_snds_metrics.REPUTATION_FILENAME
            output_path.write_text("stale-content\n")

            before = time.time()
            exit_code, _ = _run_main(tmp, return_value="203.0.113.5,green,0.05%,12000")

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
    def test_requests_the_url_verbatim_and_sends_no_authorization_header(self) -> None:
        """The access key lives in the URL's own query string -- there is no
        header to set. Asserting the absence of `Authorization` is what would
        catch a half-finished revert to the old bearer-token mechanism, which
        would send a credential this deployment no longer holds.
        """
        captured: dict[str, object] = {}

        class FakeHeaders:
            def get_content_type(self) -> str:
                return "text/plain"

        class FakeResponse:
            headers = FakeHeaders()

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

        url = "https://example.test/snds/data.aspx?key=00000000-0000-0000-0000-000000000000"
        with mock.patch.object(collect_snds_metrics.urllib.request, "urlopen", fake_urlopen):
            body = collect_snds_metrics.fetch_snds_data(url)

        self.assertEqual(body, "203.0.113.5,green,0.05%,12000")
        self.assertEqual(captured["url"], url)
        self.assertNotIn(
            "authorization", {k.lower() for k in captured["headers"]}  # type: ignore[union-attr]
        )


class AccessLinkStatusCodeTests(unittest.TestCase):
    """Microsoft documents exactly two status codes about the key itself, and
    the operator response differs from a generic network failure: both are
    cleared by regenerating the link, neither by waiting. 404 is doubly
    important because Microsoft overloads it -- expired key AND no-data-today
    share it -- so the message has to say that rather than assert one cause.
    """

    def _raise_http(self, code: int, msg: str = "Not Found") -> object:
        return urllib.error.HTTPError(
            url="https://example.test/snds/data.aspx?key=SUPERSECRETKEYVALUE",
            code=code,
            msg=msg,
            hdrs=None,  # type: ignore[arg-type]
            fp=None,
        )

    def test_404_is_reported_as_an_access_link_problem_naming_both_causes(self) -> None:
        with mock.patch.object(
            collect_snds_metrics.urllib.request, "urlopen", side_effect=self._raise_http(404)
        ):
            with self.assertRaises(collect_snds_metrics.AccessLinkRejectedError) as ctx:
                collect_snds_metrics.fetch_snds_data("https://example.test/snds/data.aspx?key=x")
        message = str(ctx.exception)
        self.assertIn("404", message)
        self.assertIn("expired", message)
        # The ambiguity itself must survive into the message -- an operator
        # told only "expired" would regenerate a link that was never the
        # problem, and one told only "no data" would ignore a dead link.
        self.assertIn("no data", message)

    def test_400_is_reported_as_a_malformed_link(self) -> None:
        with mock.patch.object(
            collect_snds_metrics.urllib.request, "urlopen", side_effect=self._raise_http(400)
        ):
            with self.assertRaises(collect_snds_metrics.AccessLinkRejectedError) as ctx:
                collect_snds_metrics.fetch_snds_data("https://example.test/snds/data.aspx?key=x")
        self.assertIn("400", str(ctx.exception))

    def test_an_unmapped_status_code_stays_a_plain_url_error(self) -> None:
        with mock.patch.object(
            collect_snds_metrics.urllib.request, "urlopen", side_effect=self._raise_http(503)
        ):
            with self.assertRaises(urllib.error.URLError) as ctx:
                collect_snds_metrics.fetch_snds_data("https://example.test/snds/data.aspx?key=x")
        self.assertNotIsInstance(ctx.exception, collect_snds_metrics.AccessLinkRejectedError)

    def test_no_status_code_path_leaks_the_key_into_its_message(self) -> None:
        """The reason phrase is the server's text, not this collector's, and
        it lands in a message that must stay free of the access key.

        The key is planted in `msg` deliberately: `HTTPError.__str__` happens
        not to include the request URL, so a test that only checked
        `str(exc)` would pass even against code that interpolated the whole
        exception -- proven by sabotage, which survived exactly that test
        before this one replaced it. Feeding the secret through the one
        server-controlled field the message legitimately quotes is what makes
        the redaction load-bearing rather than incidental.
        """
        url = "https://example.test/snds/data.aspx?key=SUPERSECRETKEYVALUE"
        for code in (404, 400, 503):
            with self.subTest(code=code):
                with mock.patch.object(
                    collect_snds_metrics.urllib.request,
                    "urlopen",
                    side_effect=self._raise_http(
                        code, msg="rejected key SUPERSECRETKEYVALUE"
                    ),
                ):
                    with self.assertRaises(Exception) as ctx:
                        collect_snds_metrics.fetch_snds_data(url)
                self.assertNotIn("SUPERSECRETKEYVALUE", str(ctx.exception))


def _fake_response(body: bytes, content_type: str = "text/plain") -> "mock.Mock":
    """A minimal stand-in for `http.client.HTTPResponse`: a context manager
    whose `.headers.get_content_type()` and `.read()` are what
    `fetch_snds_data` actually calls.
    """
    response = mock.MagicMock()
    response.__enter__.return_value = response
    response.headers.get_content_type.return_value = content_type
    response.read.return_value = body
    return response


class FetchSndsDataShapeValidationTests(unittest.TestCase):
    """SNDS can answer HTTP 200 with an HTML page (a login, consent, or
    portal-side error screen), which `urlopen` does not treat as an error --
    and the per-line-tolerant parser turns every line of markup into a
    silently skipped row rather than a raised fault. These prove
    `fetch_snds_data` itself refuses that shape before it ever reaches the
    parser -- both by the header SNDS is expected to send, and by the bytes
    themselves, since a header cannot be relied on alone.
    """

    def test_an_html_content_type_is_rejected_even_with_a_200(self) -> None:
        html = "<!DOCTYPE html><html><body>Sign in</body></html>"
        with mock.patch.object(
            collect_snds_metrics.urllib.request,
            "urlopen",
            return_value=_fake_response(html.encode("utf-8"), content_type="text/html"),
        ):
            with self.assertRaises(collect_snds_metrics.UnexpectedResponseShapeError) as ctx:
                collect_snds_metrics.fetch_snds_data("https://example.test/ipstatus")
        self.assertIn("text/html", str(ctx.exception))

    def test_html_shaped_bytes_are_rejected_even_under_a_misleading_content_type(self) -> None:
        # A portal-side proxy that mislabels its error page -- the header
        # says text/plain, but the body is still markup. The shape check on
        # the bytes themselves is what still catches this.
        html = "<html><head></head><body>Please sign in again</body></html>"
        with mock.patch.object(
            collect_snds_metrics.urllib.request,
            "urlopen",
            return_value=_fake_response(html.encode("utf-8"), content_type="text/plain"),
        ):
            with self.assertRaises(collect_snds_metrics.UnexpectedResponseShapeError):
                collect_snds_metrics.fetch_snds_data("https://example.test/ipstatus")

    def test_a_well_formed_csv_response_with_rows_passes_through_unchanged(self) -> None:
        body = "203.0.113.5,green,0.05%,12000\n198.51.100.9,red,1.2%,300\n"
        with mock.patch.object(
            collect_snds_metrics.urllib.request,
            "urlopen",
            return_value=_fake_response(body.encode("utf-8"), content_type="text/plain"),
        ):
            fetched = collect_snds_metrics.fetch_snds_data("https://example.test/ipstatus")
        self.assertEqual(fetched, body)

    def test_a_well_formed_empty_response_passes_through_unchanged(self) -> None:
        # A legitimately quiet day -- zero rows, but the right shape. This
        # must not be rejected: only a wrong *shape* is a fetch failure,
        # never a right-shaped response that happens to carry no data.
        with mock.patch.object(
            collect_snds_metrics.urllib.request,
            "urlopen",
            return_value=_fake_response(b"", content_type="text/plain"),
        ):
            fetched = collect_snds_metrics.fetch_snds_data("https://example.test/ipstatus")
        self.assertEqual(fetched, "")


class MainShapeFailureIsNotSuccessTests(unittest.TestCase):
    """The exact regression this fixes: an HTML response must not stamp
    `snds_collector_last_success_timestamp_seconds`, or `SNDSCollectorStale`
    (`(time() - snds_collector_last_success_timestamp_seconds > 129600) or
    absent(...)`, `hetzner/monitoring/stack/prometheus/alerts.yml`) can never
    see the gap it exists to detect.
    """

    def test_an_html_response_leaves_the_existing_textfile_untouched_and_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = pathlib.Path(tmp) / collect_snds_metrics.REPUTATION_FILENAME
            output_path.write_text("previous-content\n")

            exit_code, _ = _run_main(
                tmp,
                side_effect=collect_snds_metrics.UnexpectedResponseShapeError(
                    "expected the SNDS CSV/plain-text feed, got what looks like an HTML page"
                ),
            )

            self.assertEqual(exit_code, 1)
            # The prior good snapshot survives byte-for-byte, same guarantee
            # as a network failure -- a bad-shape response is not a
            # successful fetch, so it must not overwrite last-known-good.
            self.assertEqual(output_path.read_text(), "previous-content\n")


class MainZeroRecordsIsStillSuccessTests(unittest.TestCase):
    """The case the fix must not overcorrect into: a well-formed response
    that legitimately parses to zero rows (a freshly-registered sender with
    no SNDS history yet, or a genuinely quiet day) is a successful fetch and
    must still advance `snds_collector_last_success_timestamp_seconds` --
    otherwise a normal quiet day pages `SNDSCollectorStale` exactly as
    wrongly as the HTML case previously suppressed it.
    """

    def test_a_well_formed_empty_response_stamps_success_and_writes_zero_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = pathlib.Path(tmp) / collect_snds_metrics.REPUTATION_FILENAME
            output_path.write_text("stale-content\n")

            before = time.time()
            exit_code, _ = _run_main(tmp, return_value="")

            self.assertEqual(exit_code, 0)
            content = output_path.read_text()
            self.assertNotIn("stale-content", content)
            written_ts = float(
                [
                    line
                    for line in content.splitlines()
                    if line.startswith("snds_collector_last_success_timestamp_seconds ")
                ][0].split()[-1]
            )
            self.assertGreaterEqual(written_ts, before)




class RedactTests(unittest.TestCase):
    """`SNDS_DATA_URL` is the credential -- the access key is a query
    parameter, so any log line carrying the URL carries the key. These prove
    the redaction the failure paths depend on, including the case where only
    the key (not the whole URL) appears in text this module did not write.
    """

    URL = "https://example.test/snds/data.aspx?key=9f3c1d2e-aaaa-bbbb-cccc-1234567890ab"
    KEY = "9f3c1d2e-aaaa-bbbb-cccc-1234567890ab"

    def test_the_whole_url_is_replaced(self) -> None:
        out = collect_snds_metrics.redact(f"fetch of {self.URL} failed", self.URL)
        self.assertNotIn(self.URL, out)
        self.assertNotIn(self.KEY, out)

    def test_the_key_alone_is_replaced_when_the_url_is_not_quoted_whole(self) -> None:
        # A portal-side message echoing only the key back, or a proxy that
        # rewrites the host -- the full-URL replacement alone would miss both.
        out = collect_snds_metrics.redact(f"invalid key: {self.KEY}", self.URL)
        self.assertNotIn(self.KEY, out)

    def test_ordinary_text_is_left_alone(self) -> None:
        out = collect_snds_metrics.redact("connection reset by peer", self.URL)
        self.assertEqual(out, "connection reset by peer")

    def test_a_short_query_value_is_not_used_as_a_replacement_needle(self) -> None:
        # Replacing a 1-3 character value would corrupt unrelated prose
        # without protecting anything -- "data" appearing in a message is not
        # a credential leak.
        out = collect_snds_metrics.redact(
            "no data for that date", "https://example.test/d?fmt=csv&v=1"
        )
        self.assertEqual(out, "no data for that date")

    def test_an_empty_url_is_a_no_op_rather_than_an_error(self) -> None:
        self.assertEqual(collect_snds_metrics.redact("some message", ""), "some message")


class MainRedactionTests(unittest.TestCase):
    """The end-to-end property: no failure path may print the URL. Proven
    against `main`'s own stderr rather than against `redact` in isolation,
    because the defect this prevents is a *missed call* to `redact`, which a
    unit test of `redact` itself cannot catch.
    """

    URL = "https://example.test/snds/data.aspx?key=SECRETKEY1234567890"

    def _stderr_of_failing_run(self, exc: Exception) -> str:
        import io
        import contextlib

        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                exit_code, _ = _run_main(tmp, url=self.URL, side_effect=exc)
            self.assertEqual(exit_code, 1)
            return buf.getvalue()

    def test_a_url_error_quoting_the_url_is_redacted_before_it_reaches_stderr(self) -> None:
        err = self._stderr_of_failing_run(
            urllib.error.URLError(f"failed to open {self.URL}")
        )
        self.assertNotIn("SECRETKEY1234567890", err)
        self.assertIn(collect_snds_metrics.REDACTED, err)

    def test_an_access_link_rejection_reaches_stderr_without_the_key(self) -> None:
        err = self._stderr_of_failing_run(
            collect_snds_metrics.AccessLinkRejectedError("HTTP 404 -- expired, or no data")
        )
        self.assertNotIn("SECRETKEY1234567890", err)
        self.assertIn("404", err)


class HealthTextfileTests(unittest.TestCase):
    """The half of the output that makes a failing collector visible in one
    scrape instead of 36 hours. The reputation file is deliberately preserved
    across a failure, which is exactly what makes a dashboard read green
    while the collector is dead -- so health must be published separately and
    unconditionally.
    """

    def test_a_failed_run_publishes_health_with_success_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, output_dir = _run_main(
                tmp, side_effect=collect_snds_metrics.urllib.error.URLError("boom")
            )
            self.assertEqual(exit_code, 1)
            health = (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text()
            self.assertIn("snds_collector_last_run_success 0", health)
            self.assertIn("snds_collector_last_attempt_timestamp_seconds ", health)

    def test_a_successful_run_publishes_health_with_success_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, output_dir = _run_main(tmp, return_value="203.0.113.5,green,0.05%,12000")
            self.assertEqual(exit_code, 0)
            health = (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text()
            self.assertIn("snds_collector_last_run_success 1", health)

    def test_health_is_published_even_when_the_url_is_missing_entirely(self) -> None:
        # The worst case for silent failure: nothing configured at all. The
        # reputation file may not exist, but health must still say so.
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = pathlib.Path(tmp)
            env = {
                k: v
                for k, v in collect_snds_metrics.os.environ.items()
                if k != "SNDS_DATA_URL"
            }
            env["SNDS_OUTPUT_DIR"] = str(output_dir)
            with mock.patch.dict(collect_snds_metrics.os.environ, env, clear=True):
                exit_code = collect_snds_metrics.main([])
            self.assertEqual(exit_code, 1)
            health = (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text()
            self.assertIn("snds_collector_last_run_success 0", health)

    def test_a_failed_run_does_not_write_the_reputation_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, output_dir = _run_main(
                tmp, side_effect=collect_snds_metrics.urllib.error.URLError("boom")
            )
            self.assertFalse((output_dir / collect_snds_metrics.REPUTATION_FILENAME).exists())

    def test_the_two_files_are_separate_so_a_failure_cannot_blank_reputation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # A good run, then a failing one: the reputation values from the
            # good run must survive the failure untouched.
            _run_main(tmp, return_value="203.0.113.5,green,0.05%,12000")
            reputation_after_success = (
                pathlib.Path(tmp) / collect_snds_metrics.REPUTATION_FILENAME
            ).read_text()

            _run_main(tmp, side_effect=collect_snds_metrics.urllib.error.URLError("boom"))

            self.assertEqual(
                (pathlib.Path(tmp) / collect_snds_metrics.REPUTATION_FILENAME).read_text(),
                reputation_after_success,
            )
            health = (pathlib.Path(tmp) / collect_snds_metrics.HEALTH_FILENAME).read_text()
            self.assertIn("snds_collector_last_run_success 0", health)


class LinkFirstSeenTests(unittest.TestCase):
    """Microsoft expires each access link 30 days after it is generated and
    puts that date in no response, so the age is observed here. The point of
    observing it rather than having an operator record it is that an observed
    age cannot drift out of sync with the URL actually in use.
    """

    URL_A = "https://example.test/snds/data.aspx?key=aaaaaaaa-1111-2222-3333-444444444444"
    URL_B = "https://example.test/snds/data.aspx?key=bbbbbbbb-5555-6666-7777-888888888888"

    def test_the_first_sighting_records_now(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp) / collect_snds_metrics.LINK_STATE_FILENAME
            first = collect_snds_metrics.read_link_first_seen(state, self.URL_A, 1000.0)
            self.assertEqual(first, 1000.0)

    def test_the_same_url_keeps_its_original_first_seen_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp) / collect_snds_metrics.LINK_STATE_FILENAME
            collect_snds_metrics.read_link_first_seen(state, self.URL_A, 1000.0)
            later = collect_snds_metrics.read_link_first_seen(state, self.URL_A, 9999.0)
            self.assertEqual(later, 1000.0)

    def test_a_rotated_url_resets_the_clock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp) / collect_snds_metrics.LINK_STATE_FILENAME
            collect_snds_metrics.read_link_first_seen(state, self.URL_A, 1000.0)
            rotated = collect_snds_metrics.read_link_first_seen(state, self.URL_B, 9999.0)
            self.assertEqual(rotated, 9999.0)

    def test_the_state_file_never_contains_the_url_or_its_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp) / collect_snds_metrics.LINK_STATE_FILENAME
            collect_snds_metrics.read_link_first_seen(state, self.URL_A, 1000.0)
            content = state.read_text()
            self.assertNotIn(self.URL_A, content)
            self.assertNotIn("aaaaaaaa-1111-2222-3333-444444444444", content)

    def test_a_corrupt_state_file_is_treated_as_a_first_sighting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp) / collect_snds_metrics.LINK_STATE_FILENAME
            state.write_text("{not json at all")
            self.assertEqual(
                collect_snds_metrics.read_link_first_seen(state, self.URL_A, 4242.0), 4242.0
            )

    def test_the_age_gauge_is_published_in_the_health_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, output_dir = _run_main(
                tmp, url=self.URL_A, return_value="203.0.113.5,green,0.05%,12000"
            )
            health = (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text()
            self.assertIn("snds_access_link_first_seen_timestamp_seconds ", health)

    def test_the_age_gauge_survives_a_failing_run_so_expiry_stays_visible(self) -> None:
        # The run that matters most for this gauge is a failing one: if the
        # link has expired, the expiry alert must still have an age to read.
        with tempfile.TemporaryDirectory() as tmp:
            _, output_dir = _run_main(
                tmp,
                url=self.URL_A,
                side_effect=collect_snds_metrics.AccessLinkRejectedError("HTTP 404"),
            )
            health = (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text()
            self.assertIn("snds_access_link_first_seen_timestamp_seconds ", health)


class EveryLineSkippedIsNotAQuietDayTests(unittest.TestCase):
    """The defect the review found: a 200 whose every row fails validation
    used to blank the reputation file AND stamp success, so all five alerts
    in the group went silent at once and the dashboard read clean.

    The likeliest trigger is not a quiet day but a column reorder -- if the
    first field stops being an address, every row is skipped individually and
    nothing raises. A genuinely empty feed must still be a success, or a quiet
    day pages.
    """

    REORDERED = "2026-09-16,203.0.113.5,green,0.05%\n2026-09-16,198.51.100.9,red,1.2%\n"

    def test_the_parser_reports_that_it_discarded_everything(self) -> None:
        feed = collect_snds_metrics.parse_snds_feed(self.REORDERED)
        self.assertEqual(feed.records, [])
        self.assertEqual(feed.data_lines, 2)
        self.assertEqual(feed.skipped_lines, 2)
        self.assertTrue(feed.every_line_was_skipped)

    def test_an_empty_feed_is_not_reported_as_everything_skipped(self) -> None:
        feed = collect_snds_metrics.parse_snds_feed("")
        self.assertFalse(feed.every_line_was_skipped)

    def test_a_header_only_feed_is_not_reported_as_everything_skipped(self) -> None:
        feed = collect_snds_metrics.parse_snds_feed("IP Address,Status,Complaint Rate,Volume\n")
        self.assertEqual(feed.data_lines, 0)
        self.assertFalse(feed.every_line_was_skipped)

    def test_a_partial_skip_is_not_reported_as_everything_skipped(self) -> None:
        feed = collect_snds_metrics.parse_snds_feed("203.0.113.5,green,0.05%,1\nnot-an-ip,green\n")
        self.assertEqual(len(feed.records), 1)
        self.assertFalse(feed.every_line_was_skipped)

    def test_an_all_skipped_response_preserves_the_previous_reputation_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _run_main(tmp, return_value="203.0.113.5,green,0.05%,12000")
            good = (pathlib.Path(tmp) / collect_snds_metrics.REPUTATION_FILENAME).read_text()

            exit_code, output_dir = _run_main(tmp, return_value=self.REORDERED)

            self.assertEqual(exit_code, 1)
            self.assertEqual(
                (output_dir / collect_snds_metrics.REPUTATION_FILENAME).read_text(), good
            )

    def test_an_all_skipped_response_publishes_failure_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, output_dir = _run_main(tmp, return_value=self.REORDERED)
            health = (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text()
            self.assertIn("snds_collector_last_run_success 0", health)

    def test_a_genuinely_empty_feed_is_still_a_success(self) -> None:
        # The overcorrection this must not become: a quiet day, or a
        # freshly-registered sender SNDS has no history for, is not a fault.
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, output_dir = _run_main(tmp, return_value="")
            self.assertEqual(exit_code, 0)
            health = (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text()
            self.assertIn("snds_collector_last_run_success 1", health)


class MalformedUrlTests(unittest.TestCase):
    """A truncated paste into monitoring.env -- the operator error the 400
    message itself anticipates. The subset that never reaches the server used
    to raise an uncaught ValueError carrying the whole URL, so the one path
    that logged the live key was the one the runbook warns about.
    """

    TRUNCATED = "sendersupport.olc.protection.outlook.com/snds/data.aspx?key=SUPERSECRETKEY123456"

    def test_a_url_with_no_scheme_is_refused_before_any_network_call(self) -> None:
        with mock.patch.object(collect_snds_metrics.urllib.request, "urlopen") as urlopen:
            with self.assertRaises(collect_snds_metrics.MalformedDataUrlError):
                collect_snds_metrics.fetch_snds_data(self.TRUNCATED)
            urlopen.assert_not_called()

    def test_the_refusal_does_not_carry_the_key(self) -> None:
        with self.assertRaises(collect_snds_metrics.MalformedDataUrlError) as ctx:
            collect_snds_metrics.fetch_snds_data(self.TRUNCATED)
        self.assertNotIn("SUPERSECRETKEY123456", str(ctx.exception))

    def test_main_publishes_health_and_leaks_nothing_on_a_malformed_url(self) -> None:
        import io
        import contextlib

        with tempfile.TemporaryDirectory() as tmp:
            output_dir = pathlib.Path(tmp)
            env = {
                k: v
                for k, v in collect_snds_metrics.os.environ.items()
                if k not in ("SNDS_DATA_URL", "SNDS_OUTPUT_DIR")
            }
            env["SNDS_OUTPUT_DIR"] = str(output_dir)
            env["SNDS_DATA_URL"] = self.TRUNCATED
            buf = io.StringIO()
            with mock.patch.dict(collect_snds_metrics.os.environ, env, clear=True):
                with contextlib.redirect_stderr(buf):
                    exit_code = collect_snds_metrics.main([])

            self.assertEqual(exit_code, 1)
            self.assertNotIn("SUPERSECRETKEY123456", buf.getvalue())
            health = (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text()
            self.assertIn("snds_collector_last_run_success 0", health)


class UnexpectedCrashStillPublishesHealthTests(unittest.TestCase):
    """`snds_collector_last_run_success` frozen at 1 by a crash is worse than
    no gauge at all: it affirmatively asserts health, and every alert in the
    group believes it. So no way of dying may skip the health write.
    """

    def test_an_unexpected_exception_publishes_failure_rather_than_propagating(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Seed a success first, so the gauge has a 1 to be wrongly left at.
            _run_main(tmp, return_value="203.0.113.5,green,0.05%,12000")
            self.assertIn(
                "snds_collector_last_run_success 1",
                (pathlib.Path(tmp) / collect_snds_metrics.HEALTH_FILENAME).read_text(),
            )

            exit_code, output_dir = _run_main(tmp, side_effect=RuntimeError("something unforeseen"))

            self.assertEqual(exit_code, 1)
            self.assertIn(
                "snds_collector_last_run_success 0",
                (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text(),
            )

    def test_an_unexpected_exception_does_not_leak_the_url(self) -> None:
        import io
        import contextlib

        url = "https://example.test/snds/data.aspx?key=SECRETKEY1234567890"
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                _run_main(tmp, url=url, side_effect=RuntimeError(f"failed on {url}"))
            self.assertNotIn("SECRETKEY1234567890", buf.getvalue())

    def test_a_failure_writing_the_reputation_file_still_publishes_health(self) -> None:
        # A full or read-only /var/lib: the reputation write raises OSError,
        # which used to escape before the health write next to it. Only the
        # FIRST write is broken -- the health write that follows has to do its
        # real work, or this test would pass against a collector that never
        # wrote health at all.
        real_write = collect_snds_metrics.write_textfile_atomically
        calls: list[int] = []

        def fail_first(path, content):  # type: ignore[no-untyped-def]
            calls.append(1)
            if len(calls) == 1:
                raise OSError("No space left on device")
            return real_write(path, content)

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                collect_snds_metrics, "write_textfile_atomically", fail_first
            ):
                exit_code, output_dir = _run_main(
                    tmp, return_value="203.0.113.5,green,0.05%,12000"
                )
            self.assertEqual(exit_code, 1)
            self.assertIn(
                "snds_collector_last_run_success 0",
                (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text(),
            )


class RedactEncodedKeyTests(unittest.TestCase):
    """`parse_qsl` percent-decodes, so the decoded value alone is a needle
    that never matches a server echoing the request line back verbatim. A
    base64-shaped key contains `/`, `+` and `=`, all of which travel encoded.
    """

    URL = "https://example.test/snds/data.aspx?key=AAAA%2FBBBB%2BCCCC%3DDDDD"

    def test_the_encoded_form_is_redacted(self) -> None:
        out = collect_snds_metrics.redact(
            "Not Found: /snds/data.aspx?key=AAAA%2FBBBB%2BCCCC%3DDDDD", self.URL
        )
        self.assertNotIn("AAAA%2FBBBB", out)

    def test_the_decoded_form_is_still_redacted(self) -> None:
        out = collect_snds_metrics.redact("bad key AAAA/BBBB+CCCC=DDDD", self.URL)
        self.assertNotIn("AAAA/BBBB", out)


class RealColumnOrderTests(unittest.TestCase):
    """The reorder that actually happens, and the one the first guard missed.

    SNDS's automated-access CSV carries activity timestamps and command
    counts between the address and the filter result. Every row still starts
    with a valid IP, so nothing is skipped and `every_line_was_skipped` stays
    false -- while the two columns every reputation alert reads come back
    empty and a command count lands in `snds_message_volume`, which also
    satisfies (and so disables) SNDSComplaintRateHigh's `unless on(ip)`
    fallback. Before this guard the run reported success.
    """

    REAL = (
        "91.99.1.2,9/15/2026 12:00 AM,9/15/2026 11:59 PM,1200,1180,1180,GREEN,< 0.1%\n"
        "91.99.1.3,9/15/2026 12:00 AM,9/15/2026 11:59 PM,90,88,88,YELLOW,0.4%\n"
    )

    def test_the_first_guard_does_not_catch_it(self) -> None:
        # Pinned deliberately: this is why the second guard has to exist.
        feed = collect_snds_metrics.parse_snds_feed(self.REAL)
        self.assertFalse(feed.every_line_was_skipped)
        self.assertEqual(len(feed.records), 2)

    def test_the_alert_column_guard_does_catch_it(self) -> None:
        feed = collect_snds_metrics.parse_snds_feed(self.REAL)
        self.assertTrue(feed.yielded_nothing_the_alerts_can_read)

    def test_a_run_against_it_fails_rather_than_publishing_silence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _run_main(tmp, return_value="203.0.113.5,green,0.05%,12000")
            good = (pathlib.Path(tmp) / collect_snds_metrics.REPUTATION_FILENAME).read_text()

            exit_code, output_dir = _run_main(tmp, return_value=self.REAL)

            self.assertEqual(exit_code, 1)
            self.assertEqual(
                (output_dir / collect_snds_metrics.REPUTATION_FILENAME).read_text(), good
            )
            self.assertIn(
                "snds_collector_last_run_success 0",
                (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text(),
            )

    def test_a_good_feed_is_not_caught_by_the_alert_column_guard(self) -> None:
        feed = collect_snds_metrics.parse_snds_feed("203.0.113.5,green,0.05%,12000")
        self.assertFalse(feed.yielded_nothing_the_alerts_can_read)

    def test_a_status_alone_is_enough_to_pass_the_guard(self) -> None:
        # A record carrying a status but no computed rate is a real shape --
        # a low-volume IP. It must not read as a schema failure.
        feed = collect_snds_metrics.parse_snds_feed("203.0.113.5,green,None,4")
        self.assertFalse(feed.yielded_nothing_the_alerts_can_read)

    def test_an_empty_feed_is_not_caught_by_the_alert_column_guard(self) -> None:
        self.assertFalse(
            collect_snds_metrics.parse_snds_feed("").yielded_nothing_the_alerts_can_read
        )


class HeaderShapeTests(unittest.TestCase):
    """A header spelled anything other than the two literals the first version
    listed was counted as a data line, skipped for not being an address, and
    on a quiet day that made `every_line_was_skipped` true -- a schema alarm
    raised by a header.
    """

    def test_alternative_header_spellings_are_not_data(self) -> None:
        for header in ("ip_address,status", "Sending IP,Filter result", "IP,Status"):
            with self.subTest(header=header):
                feed = collect_snds_metrics.parse_snds_feed(header)
                self.assertEqual(feed.data_lines, 0)
                self.assertFalse(feed.every_line_was_skipped)

    def test_a_header_only_response_is_a_quiet_day_not_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, _ = _run_main(tmp, return_value="ip_address,filter_result\n")
            self.assertEqual(exit_code, 0)

    def test_a_genuine_bad_row_is_still_counted_as_skipped(self) -> None:
        # The header rule must not swallow real garbage: it applies to the
        # first row only, and a later non-address row is still a skip.
        feed = collect_snds_metrics.parse_snds_feed("203.0.113.5,green\nnot-an-ip,green\n")
        self.assertEqual(feed.skipped_lines, 1)

    def test_a_non_name_shaped_first_field_is_data_not_a_header(self) -> None:
        feed = collect_snds_metrics.parse_snds_feed("999.999.999.999,green\n")
        self.assertEqual(feed.data_lines, 1)
        self.assertEqual(feed.skipped_lines, 1)


class BoundedComplaintRateTests(unittest.TestCase):
    """`< 0.1%` is what SNDS reports for a healthy IP -- its most common
    value, and one float() cannot parse. Mapping it to None would put every
    clean IP in the "no rate computed" bucket, the opposite of what SNDS said.
    """

    def test_a_less_than_bound_parses_to_the_bound(self) -> None:
        self.assertAlmostEqual(collect_snds_metrics._parse_complaint_rate("< 0.1%"), 0.001)

    def test_a_greater_than_bound_parses_to_the_bound(self) -> None:
        self.assertAlmostEqual(collect_snds_metrics._parse_complaint_rate("> 1%"), 0.01)

    def test_the_bound_does_not_trip_the_high_complaint_threshold(self) -> None:
        # SNDSComplaintRateHigh is `> 0.001`, so a healthy "< 0.1%" must sit
        # exactly on the line and not over it.
        self.assertFalse(collect_snds_metrics._parse_complaint_rate("< 0.1%") > 0.001)

    def test_genuine_garbage_is_still_absent(self) -> None:
        self.assertIsNone(collect_snds_metrics._parse_complaint_rate("< not-a-number"))


class LinkStateUnwritableTests(unittest.TestCase):
    """A state file that cannot be written restarts the age on every run, so
    the only pre-emptive alert never reaches its threshold -- never, not late.
    """

    def test_an_unwritable_state_file_reports_none_rather_than_now(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp) / "nope" / collect_snds_metrics.LINK_STATE_FILENAME
            with mock.patch.object(
                collect_snds_metrics.pathlib.Path, "mkdir", side_effect=OSError("read-only")
            ):
                self.assertIsNone(
                    collect_snds_metrics.read_link_first_seen(state, "https://x.test/?key=abcdefgh", 1000.0)
                )

    def test_the_health_file_publishes_the_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                collect_snds_metrics, "read_link_first_seen", return_value=None
            ):
                _, output_dir = _run_main(tmp, return_value="203.0.113.5,green,0.05%,12000")
            health = (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text()
            self.assertIn("snds_link_state_readable 0", health)
            self.assertNotIn("snds_access_link_first_seen_timestamp_seconds ", health)

    def test_a_working_state_file_publishes_readable_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, output_dir = _run_main(tmp, return_value="203.0.113.5,green,0.05%,12000")
            health = (output_dir / collect_snds_metrics.HEALTH_FILENAME).read_text()
            self.assertIn("snds_link_state_readable 1", health)
            self.assertIn("snds_access_link_first_seen_timestamp_seconds ", health)


class CtrlCIsNotARunFailureTests(unittest.TestCase):
    """`except BaseException` would turn an operator's Ctrl-C into a written
    "last run failed". Narrowing it was invisible to every other test, which
    is why this one exists.
    """

    def test_a_keyboard_interrupt_propagates_rather_than_being_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(KeyboardInterrupt):
                _run_main(tmp, side_effect=KeyboardInterrupt())

    def test_a_system_exit_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                _run_main(tmp, side_effect=SystemExit(2))


if __name__ == "__main__":
    unittest.main()
