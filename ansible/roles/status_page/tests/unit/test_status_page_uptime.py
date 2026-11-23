"""Unit tests for the 90-day uptime of the status page.

Gatus keeps uptime for 30 days at most, so the 90-day figure comes from samples that
branchleft_status_uptime records itself. These tests prove the figure against a count made
here, from the same samples, by a separate loop that shares no code with the program, and
prove a seeded gap of known length gives the percentage worked out by hand.
"""

import contextlib
import io
import json
import threading
import unittest
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

import branchleft_status_uptime as uptime

NOW = 1_800_000_000
DAY = 86_400
MINUTE = 60
WINDOW_SAMPLES = 90 * 24 * 60


def _stamp(unix_time: int, nanoseconds: int = 195_683_651) -> str:
    """Return the instant the way Gatus writes it, with nine fraction digits and a Z."""
    base = datetime.fromtimestamp(unix_time, UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{nanoseconds:09d}Z"


def _body(results: dict[str, list[tuple[int, bool]]]) -> list[dict[str, object]]:
    """Return a statuses body in the shape the page answers."""
    return [
        {
            "name": key,
            "key": key,
            "results": [
                {"status": 200, "success": ok, "timestamp": _stamp(when)} for when, ok in series
            ],
        }
        for key, series in results.items()
    ]


def _minutes(start: int, count: int, *, failing: range = range(0)) -> list[tuple[int, bool]]:
    """Return `count` probes a minute apart from `start`; those at `failing` positions fail."""
    return [(start + index * MINUTE, index not in failing) for index in range(count)]


def _store_with(case: unittest.TestCase, results: dict[str, list[tuple[int, bool]]]) -> Path:
    """Return a sample directory holding these samples, removed when the test ends."""
    tmp = TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    directory = uptime.open_store(Path(tmp.name) / "samples")
    uptime.record(
        directory,
        [uptime.Sample(key, when, ok) for key, series in results.items() for when, ok in series],
    )
    return directory


class ParseTest(unittest.TestCase):
    """The body of the statuses API is read into samples, or refused."""

    def test_reads_a_gatus_timestamp_with_nine_fraction_digits(self) -> None:
        samples = uptime.parse_statuses(_body({"sites_a": [(NOW, True), (NOW + 60, False)]}))
        self.assertEqual(
            samples,
            [uptime.Sample("sites_a", NOW, True), uptime.Sample("sites_a", NOW + 60, False)],
        )

    def test_a_live_shaped_result_is_read(self) -> None:
        body = [
            {
                "name": "blog.branchleft.co.uk",
                "group": "sites",
                "key": "sites_blog-branchleft-co-uk",
                "results": [
                    {
                        "status": 200,
                        "hostname": "blog.branchleft.co.uk",
                        "duration": 36553713,
                        "conditionResults": [{"condition": "[CONNECTED] == true", "success": True}],
                        "success": True,
                        "timestamp": "2026-11-18T22:47:32.195683651Z",
                    }
                ],
            }
        ]
        self.assertEqual(
            uptime.parse_statuses(body),
            [uptime.Sample("sites_blog-branchleft-co-uk", 1_795_042_052, True)],
        )

    def test_refuses_what_is_not_a_status_list(self) -> None:
        bads: list[object] = [
            {},
            [1],
            [{"key": "k"}],
            [{"key": "k", "results": [{"success": True}]}],
            [{"key": "k", "results": [{"timestamp": _stamp(NOW), "success": "yes"}]}],
        ]
        for bad in bads:
            with self.subTest(bad=bad), self.assertRaises(uptime.StatusPayloadError):
                uptime.parse_statuses(bad)


class RecordTest(unittest.TestCase):
    """A probe sample is held once."""

    def test_the_same_result_read_twice_is_recorded_once(self) -> None:
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = uptime.open_store(Path(tmp.name) / "samples")
        samples = uptime.parse_statuses(_body({"k": _minutes(NOW - 600, 10)}))
        self.assertEqual(uptime.record(store, samples), 10)
        self.assertEqual(uptime.record(store, samples), 0)
        self.assertEqual(uptime.record(store, samples[5:] + samples[:2]), 0)

    def test_the_first_reading_of_a_sample_stands(self) -> None:
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = uptime.open_store(Path(tmp.name) / "samples")
        uptime.record(store, [uptime.Sample("k", NOW, True)])
        uptime.record(store, [uptime.Sample("k", NOW, False)])
        (only,) = uptime.uptimes(store, NOW)
        self.assertEqual((only.samples, only.successes), (1, 1))


class StoreTest(unittest.TestCase):
    """A damaged sample file stops the run, so a wrong figure is never printed."""

    def test_a_line_that_is_not_a_sample_is_refused(self) -> None:
        store = _store_with(self, {"k": [(NOW, True)]})
        with (store / "k.tsv").open("a", encoding="ascii") as handle:
            handle.write("not a sample\n")
        with self.assertRaises(uptime.StoreError):
            uptime.uptimes(store, NOW)
        with self.assertRaises(uptime.StoreError):
            uptime.record(store, [uptime.Sample("k", NOW + 60, True)])

    def test_an_unsafe_endpoint_key_is_refused(self) -> None:
        with self.assertRaises(uptime.StatusPayloadError):
            uptime.parse_statuses([{"key": "../x", "results": []}])


class UptimeTest(unittest.TestCase):
    """The figure matches an independent count, and a seeded gap shows the expected percentage."""

    def test_matches_an_independent_count_of_the_stored_samples(self) -> None:
        # A deterministic, irregular pattern: two endpoints, 100 days of one-minute probes, so
        # the oldest ten days fall outside the window. Endpoint "b" starts 40 days in.
        start = NOW - 100 * DAY
        series_a = [(start + i * MINUTE, (i * 7919) % 211 != 0) for i in range(100 * 24 * 60 + 1)]
        series_b = [(when, ok) for when, ok in series_a if when >= NOW - 60 * DAY]
        store = _store_with(self, {"a": series_a, "b": series_b})

        for key, series in (("a", series_a), ("b", series_b)):
            # The independent count: its own loop over the raw list, the window written out.
            total = 0
            passed = 0
            for when, ok in series:
                if NOW - 90 * DAY < when <= NOW:
                    total += 1
                    if ok:
                        passed += 1
            found = {item.endpoint_key: item for item in uptime.uptimes(store, NOW)}[key]
            self.assertEqual((found.samples, found.successes), (total, passed), key)
            self.assertAlmostEqual(found.uptime_percent, 100 * passed / total, places=4)

    def test_a_seeded_gap_of_known_length_shows_the_expected_percentage(self) -> None:
        # 90 days of passing probes with one outage of exactly 90 failed probes (90 minutes):
        # (129 600 - 90) / 129 600 = 99.930 555...%.
        start = NOW - WINDOW_SAMPLES * MINUTE + MINUTE
        store = _store_with(
            self, {"gap": _minutes(start, WINDOW_SAMPLES, failing=range(40_000, 40_090))}
        )
        (found,) = uptime.uptimes(store, NOW)
        self.assertEqual(found.samples, WINDOW_SAMPLES)
        self.assertEqual(found.successes, WINDOW_SAMPLES - 90)
        self.assertEqual(found.uptime_percent, 99.9306)
        self.assertEqual(found.coverage_percent, 100.0)

    def test_the_window_is_ninety_days_not_thirty(self) -> None:
        self.assertEqual(uptime.WINDOW_DAYS, 90)
        # A failure 60 days old is outside Gatus's 30 days and inside ours.
        store = _store_with(
            self, {"k": [(NOW - 60 * DAY, False), (NOW - 91 * DAY, False), (NOW - 5 * DAY, True)]}
        )
        (found,) = uptime.uptimes(store, NOW)
        self.assertEqual((found.samples, found.successes), (2, 1))
        self.assertEqual(found.uptime_percent, 50.0)

    def test_the_window_edges_are_after_the_start_and_up_to_now(self) -> None:
        store = _store_with(
            self,
            {
                "k": [
                    (NOW - 90 * DAY, False),  # exactly 90 days old: out
                    (NOW - 90 * DAY + 1, True),  # in
                    (NOW, True),  # now: in
                    (NOW + 1, False),  # after now: out
                ]
            },
        )
        (found,) = uptime.uptimes(store, NOW)
        self.assertEqual((found.samples, found.successes), (2, 2))

    def test_failed_probes_count_against_the_figure(self) -> None:
        store = _store_with(self, {"k": _minutes(NOW - 3 * MINUTE, 4, failing=range(2))})
        (found,) = uptime.uptimes(store, NOW)
        self.assertEqual((found.samples, found.successes, found.uptime_percent), (4, 2, 50.0))

    def test_a_stretch_with_no_samples_lowers_coverage_and_leaves_the_figure(self) -> None:
        # One whole day was never recorded: the figure stays 100 and the coverage shows it.
        series = [
            (when, ok)
            for when, ok in _minutes(NOW - WINDOW_SAMPLES * MINUTE + MINUTE, WINDOW_SAMPLES)
            if not NOW - 10 * DAY < when <= NOW - 9 * DAY
        ]
        store = _store_with(self, {"k": series})
        (found,) = uptime.uptimes(store, NOW)
        self.assertEqual(found.uptime_percent, 100.0)
        self.assertEqual(found.samples, WINDOW_SAMPLES - 1440)
        self.assertEqual(
            found.coverage_percent, round(100 * (WINDOW_SAMPLES - 1440) / WINDOW_SAMPLES, 2)
        )

    def test_an_endpoint_with_no_sample_in_the_window_is_absent_not_a_hundred(self) -> None:
        store = _store_with(self, {"old": [(NOW - 200 * DAY, True)]})
        self.assertEqual(uptime.uptimes(store, NOW), [])


class _Page(BaseHTTPRequestHandler):
    """A stand-in for the page that answers the statuses path with a fixed body."""

    body: bytes = b"[]"
    seen_paths: list[str] = []  # noqa: RUF012 - a test double shared with its server thread

    def do_GET(self) -> None:  # noqa: N802 - the name http.server calls
        self.seen_paths.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Stay quiet."""


class CommandTest(unittest.TestCase):
    """`collect` and `report`, end to end against a stand-in page."""

    def test_collect_then_report(self) -> None:
        _Page.body = json.dumps(
            _body({"sites_a": _minutes(NOW - 4 * MINUTE, 5, failing=range(4, 5))})
        ).encode()
        _Page.seen_paths = []
        server = HTTPServer(("127.0.0.1", 0), _Page)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/api/v1/endpoints/statuses"
            with TemporaryDirectory() as tmp:
                db = Path(tmp) / "nested" / "samples"
                first = io.StringIO()
                with contextlib.redirect_stdout(first):
                    self.assertEqual(uptime.main(["collect", "--url", url, "--dir", str(db)]), 0)
                self.assertEqual(first.getvalue().strip(), "read 5 samples, recorded 5 new")
                second = io.StringIO()
                with contextlib.redirect_stdout(second):
                    uptime.main(["collect", "--url", url, "--dir", str(db)])
                self.assertEqual(second.getvalue().strip(), "read 5 samples, recorded 0 new")
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    uptime.main(["report", "--dir", str(db), "--now", str(NOW)])
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(_Page.seen_paths[0], "/api/v1/endpoints/statuses?page=1&pageSize=100")
        report = json.loads(out.getvalue())
        self.assertEqual(report["window_days"], 90)
        self.assertEqual(report["generated_at"], _stamp(NOW)[:19] + "Z")
        (endpoint,) = report["endpoints"]
        self.assertEqual(endpoint["endpoint_key"], "sites_a")
        self.assertEqual((endpoint["samples"], endpoint["successes"]), (5, 4))
        self.assertEqual(endpoint["uptime_percent"], 80.0)

    def test_report_out_writes_the_same_document_to_a_world_readable_file(self) -> None:
        # The route to the figure on the host is this file: the timer's service writes it, and
        # whatever shows it reads it. It must be the whole document, replaced in one step.
        directory = _store_with(
            self, {"sites_a": _minutes(NOW - 4 * MINUTE, 5, failing=range(4, 5))}
        )
        out = directory.parent / "report.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(
                uptime.main(
                    ["report", "--dir", str(directory), "--now", str(NOW), "--out", str(out)]
                ),
                0,
            )
            self.assertEqual(
                uptime.main(
                    ["report", "--dir", str(directory), "--now", str(NOW), "--out", str(out)]
                ),
                0,
            )
        self.assertEqual(stdout.getvalue(), "", "with --out nothing goes to stdout")
        (endpoint,) = json.loads(out.read_text(encoding="ascii"))["endpoints"]
        self.assertEqual((endpoint["samples"], endpoint["successes"]), (5, 4))
        self.assertEqual(out.stat().st_mode & 0o777, 0o644)
        self.assertEqual(
            sorted(path.name for path in directory.parent.iterdir()), ["report.json", "samples"]
        )

    def test_collect_fails_loudly_on_a_body_that_is_not_statuses(self) -> None:
        _Page.body = b'{"error": "x"}'
        server = HTTPServer(("127.0.0.1", 0), _Page)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp, self.assertRaises(uptime.StatusPayloadError):
                uptime.main(
                    [
                        "collect",
                        "--url",
                        f"http://127.0.0.1:{server.server_port}/x",
                        "--dir",
                        str(Path(tmp) / "s"),
                    ]
                )
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
