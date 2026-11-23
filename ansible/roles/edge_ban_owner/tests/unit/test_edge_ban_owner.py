"""Unit tests for the edge ban owner program: what it reads, decides, writes and refuses.

Most tests run the program in this process with a fake container runtime that serves files and
cscli output and records what it was asked. One test runs the real docker client wrapper against
`fake_docker.py`, so the exact argument lists are proven too. No test reaches docker, a host or a
real address: every address is from RFC 5737 or RFC 3849. A control is proven by sabotage: each
refusal below goes red when the line that makes it is broken (the role README lists the edits).
"""

import argparse
import contextlib
import functools
import gzip
import io
import ipaddress
import itertools
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest import mock

import branchleft_edge_ban_owner as program

ROLE = Path(__file__).resolve().parents[2]
REPOSITORY = ROLE.parents[2]
FAKE_DOCKER = Path(__file__).resolve().parent / "fake_docker.py"

NOW = 1_800_000_000.0
DAY = 86400.0
LOG_DIR = "/var/log/caddy"
SCENARIO = "crowdsecurity/http-probing"
OWNER_ADDRESS = "192.0.2.10"
SCANNER_ADDRESS = "198.51.100.7"
RANGE_NETWORK = "203.0.113.0/24"
RANGE_MEMBER = "203.0.113.25"
IPV4_LITERAL = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
ADDRESS_CANDIDATE = re.compile(r"[0-9A-Fa-f:.]{2,}")
SAMPLE = re.compile(
    r'^edge_ban_owned\{reason="([^"]*)",owned="(true|false)"(?:,decision_id="([^"]*)")?\} (\d+)$'
)
DECISION_IDS = itertools.count(1000)


def access_line(address: str, *, trusted: object = "1", seen: float = NOW - 3600) -> bytes:
    """One Caddy access line as the edge writes it."""
    entry: dict[str, object] = {
        "level": "info",
        "ts": seen,
        "logger": "http.log.access",
        "request": {"remote_ip": address, "method": "GET", "uri": "/ghost/api/admin/users/me/"},
        "status": 200,
    }
    if trusted is not None:
        entry["edge_trusted"] = trusted
    return json.dumps(entry).encode() + b"\n"


def rolled_name(seen: float, *, reason: str = "time", compressed: bool = False) -> str:
    stamp = datetime.fromtimestamp(seen, tz=UTC).strftime("%Y-%m-%dT%H-%M-%S.000")
    return f"access-{stamp}-{reason}.log" + (".gz" if compressed else "")


def decision(
    value: str,
    *,
    scope: str = "Ip",
    scenario: str | None = SCENARIO,
    kind: str = "ban",
    simulated: object = False,
    ident: object = None,
) -> dict[str, object]:
    """A decision; without `ident` it gets the next number, so each one is a different ban."""
    found: dict[str, object] = {
        "id": next(DECISION_IDS) if ident is None else ident,
        "origin": "crowdsec",
        "scope": scope,
        "value": value,
        "type": kind,
        "duration": "3h59m",
        "simulated": simulated,
    }
    if scenario is not None:
        found["scenario"] = scenario
    return found


def alert(*decisions: dict[str, object], scenario: str = SCENARIO) -> dict[str, object]:
    return {"id": 7, "scenario": scenario, "decisions": list(decisions)}


def cscli_text(*alerts: dict[str, object]) -> str:
    return json.dumps(list(alerts))


def samples(text: str) -> dict[tuple[str, str, str | None], int]:
    """Every edge_ban_owned sample as (reason, owned, decision id or None) to its value."""
    found: dict[tuple[str, str, str | None], int] = {}
    for line in text.splitlines():
        match = SAMPLE.match(line)
        if match is not None:
            key = (match[1], match[2], match[3])
            if key in found:
                raise AssertionError(f"duplicate series: {line}")
            found[key] = int(match[4])
    return found


def totals(text: str) -> dict[tuple[str, str], int]:
    """The samples summed per scenario and owned flag, whichever ids they carry."""
    found: dict[tuple[str, str], int] = {}
    for (reason, owned, _), count in samples(text).items():
        found[(reason, owned)] = found.get((reason, owned), 0) + count
    return found


def address_literals(text: str) -> list[str]:
    """Every IPv4 or IPv6 literal in the text, found by pattern and by parsing candidates."""
    found = IPV4_LITERAL.findall(text)
    for candidate in ADDRESS_CANDIDATE.findall(text):
        with contextlib.suppress(ValueError):
            found.append(str(ipaddress.ip_address(candidate)))
    return found


class FakeRuntime:
    """Serves the log directory and cscli from memory and records what the program opened."""

    def __init__(
        self,
        *,
        files: dict[str, bytes] | None = None,
        cscli: str = "[]",
        directory_listing_fails: int = 0,
        caddy_missing: bool = False,
        crowdsec_missing: bool = False,
        cscli_fails: bool = False,
        broken_files: Sequence[str] = (),
    ) -> None:
        self.files = files if files is not None else {}
        self.cscli = cscli
        self.directory_listing_fails = directory_listing_fails
        self.caddy_missing = caddy_missing
        self.crowdsec_missing = crowdsec_missing
        self.cscli_fails = cscli_fails
        self.broken_files = set(broken_files)
        self.opened: list[str] = []
        self.listings = 0

    def find_container(self, project: str, service: str) -> str:
        if (service == "caddy" and self.caddy_missing) or (
            service == "crowdsec" and self.crowdsec_missing
        ):
            raise program.ContainerRuntimeError(program.Problem.DOCKER_NOT_COMPLETED)
        return f"{project}-{service}"

    def list_directory(self, container: str, directory: str) -> list[str]:
        self.listings += 1
        if self.directory_listing_fails > 0:
            self.directory_listing_fails -= 1
            raise program.ContainerRuntimeError(program.Problem.DOCKER_NOT_COMPLETED)
        if directory != LOG_DIR:
            raise AssertionError(directory)
        return sorted([*self.files, "probe.log", "probe-2027-01-01T00-00-00.000-time.log.gz"])

    def open_file(self, container: str, path: str) -> contextlib.AbstractContextManager[io.BytesIO]:
        name = path.rsplit("/", 1)[1]
        self.opened.append(name)
        if name in self.broken_files:
            raise program.ContainerRuntimeError(program.Problem.DOCKER_NOT_COMPLETED)
        return contextlib.nullcontext(io.BytesIO(self.files[name]))

    def run_cscli(self, container: str) -> str:
        if self.cscli_fails:
            raise program.ContainerRuntimeError(program.Problem.DOCKER_NOT_COMPLETED)
        return self.cscli


class RuntimeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.scratch = Path(scratch.name)
        self.state_dir = self.scratch / "state"
        self.state_dir.mkdir(mode=0o700)
        self.textfile_dir = self.scratch / "textfile"
        self.textfile_dir.mkdir()
        self.state_file = self.state_dir / "trusted.json"
        self.textfile = self.textfile_dir / "edge_ban_owner.prom"

    def options(self, extra: Sequence[str] = ()) -> list[str]:
        return [
            "--state-file",
            str(self.state_file),
            "--textfile",
            str(self.textfile),
            *extra,
        ]

    def invoke(
        self, runtime: program.ContainerRuntime, extra: Sequence[str] = ()
    ) -> tuple[int, str]:
        """Runs the program once at the fixed time and returns its exit status and stderr."""
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            status = program.main(self.options(extra), runtime, lambda: NOW, lambda: 0.0)
        return status, errors.getvalue()

    def textfile_samples(self) -> dict[tuple[str, str, str | None], int]:
        return samples(self.textfile.read_text())

    def textfile_totals(self) -> dict[tuple[str, str], int]:
        return totals(self.textfile.read_text())

    def write_state(self, addresses: dict[str, float], generated_at: float = NOW - 300) -> None:
        document = {
            "schema_version": 1,
            "generated_at": int(generated_at),
            "addresses": {key: int(value) for key, value in addresses.items()},
        }
        self.state_file.write_text(json.dumps(document))
        self.state_file.chmod(0o600)


class ClassificationTests(RuntimeTestCase):
    def owner_log(self, *addresses: str) -> dict[str, bytes]:
        return {"access.log": b"".join(access_line(address) for address in addresses)}

    def test_owned_address_is_owned_true(self) -> None:
        runtime = FakeRuntime(
            files=self.owner_log(OWNER_ADDRESS),
            cscli=cscli_text(alert(decision(OWNER_ADDRESS))),
        )
        status, _ = self.invoke(runtime)
        self.assertEqual(status, 0)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "true"): 1})

    def test_address_outside_trusted_set_is_owned_false(self) -> None:
        runtime = FakeRuntime(
            files=self.owner_log(OWNER_ADDRESS),
            cscli=cscli_text(alert(decision(SCANNER_ADDRESS))),
        )
        status, _ = self.invoke(runtime)
        self.assertEqual(status, 0)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "false"): 1})

    def test_range_decision_containing_owned_address_is_owned_true(self) -> None:
        runtime = FakeRuntime(
            files=self.owner_log(RANGE_MEMBER),
            cscli=cscli_text(alert(decision(RANGE_NETWORK, scope="Range"))),
        )
        status, _ = self.invoke(runtime)
        self.assertEqual(status, 0)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "true"): 1})

    def test_range_decision_without_owned_address_is_owned_false(self) -> None:
        runtime = FakeRuntime(
            files=self.owner_log(OWNER_ADDRESS),
            cscli=cscli_text(alert(decision(RANGE_NETWORK, scope="Range"))),
        )
        self.invoke(runtime)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "false"): 1})

    def test_ipv6_range_contains_ipv6_owner_and_never_matches_ipv4(self) -> None:
        runtime = FakeRuntime(
            files=self.owner_log("2001:db8:1::5", OWNER_ADDRESS),
            cscli=cscli_text(
                alert(
                    decision("2001:db8:1::/48", scope="Range"),
                    decision("2001:db8:2::/48", scope="Range"),
                    decision("2001:db8:1::5"),
                )
            ),
        )
        self.invoke(runtime)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "true"): 2, (SCENARIO, "false"): 1})

    def test_ipv4_mapped_ipv6_matches_ipv4(self) -> None:
        runtime = FakeRuntime(
            files=self.owner_log("::ffff:192.0.2.10"),
            cscli=cscli_text(alert(decision(OWNER_ADDRESS))),
        )
        self.invoke(runtime)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "true"): 1})

    def test_unparseable_value_and_other_scopes_are_owned(self) -> None:
        runtime = FakeRuntime(
            files=self.owner_log(OWNER_ADDRESS),
            cscli=cscli_text(
                alert(
                    decision("not-an-address"),
                    decision("203.0.113.0/99", scope="Range"),
                    decision("GB", scope="Country"),
                )
            ),
        )
        self.invoke(runtime)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "true"): 3})

    def test_only_json_true_marks_a_decision_simulated(self) -> None:
        self.invoke(
            FakeRuntime(
                files=self.owner_log(OWNER_ADDRESS),
                cscli=cscli_text(alert(decision(SCANNER_ADDRESS, simulated=True))),
            )
        )
        self.assertEqual(self.textfile_totals(), {})
        real: list[object] = [
            False,
            None,
            0,
            1,
            "true",
            "yes",
            "0.0",
            [],
            {},
            [1],
        ]
        for flag in real:
            with self.subTest(simulated=flag):
                self.invoke(
                    FakeRuntime(
                        files=self.owner_log(OWNER_ADDRESS),
                        cscli=cscli_text(alert(decision(SCANNER_ADDRESS, simulated=flag))),
                    )
                )
                self.assertEqual(self.textfile_totals(), {(SCENARIO, "false"): 1})

    def test_decision_without_a_simulated_field_is_a_real_ban(self) -> None:
        bare = decision(SCANNER_ADDRESS)
        del bare["simulated"]
        self.invoke(FakeRuntime(files=self.owner_log(OWNER_ADDRESS), cscli=cscli_text(alert(bare))))
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "false"): 1})

    def test_simulated_and_non_ban_decisions_are_skipped(self) -> None:
        runtime = FakeRuntime(
            files=self.owner_log(OWNER_ADDRESS),
            cscli=cscli_text(
                alert(
                    decision(SCANNER_ADDRESS, simulated=True),
                    decision("198.51.100.8", kind="captcha"),
                    decision("198.51.100.9"),
                )
            ),
        )
        self.invoke(runtime)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "false"): 1})

    def test_alert_nested_flat_empty_and_null_cscli_output(self) -> None:
        flat = json.dumps([decision(SCANNER_ADDRESS)])
        for text, expected in [
            (cscli_text(alert(decision(SCANNER_ADDRESS))), {(SCENARIO, "false"): 1}),
            (flat, {(SCENARIO, "false"): 1}),
            ("null", {}),
            ("", {}),
            ("  \n", {}),
            ("[]", {}),
            (cscli_text(alert()), {}),
        ]:
            with self.subTest(text=text):
                self.invoke(FakeRuntime(files=self.owner_log(OWNER_ADDRESS), cscli=text))
                self.assertEqual(self.textfile_totals(), expected)

    def test_reason_comes_from_the_decision_then_the_alert_then_unknown(self) -> None:
        bare = {"id": 3, "decisions": [decision("198.51.100.9", scenario=None)]}
        runtime = FakeRuntime(
            files=self.owner_log(OWNER_ADDRESS),
            cscli=cscli_text(
                alert(decision("198.51.100.8", scenario="crowdsecurity/ssh-bf"), scenario="other"),
                alert(decision("198.51.100.7", scenario=None), scenario="crowdsecurity/nginx-dos"),
                bare,
            ),
        )
        self.invoke(runtime)
        self.assertEqual(
            self.textfile_totals(),
            {
                ("crowdsecurity/ssh-bf", "false"): 1,
                ("crowdsecurity/nginx-dos", "false"): 1,
                ("unknown", "false"): 1,
            },
        )

    def test_duplicate_reason_aggregates_to_one_sample(self) -> None:
        runtime = FakeRuntime(
            files=self.owner_log(OWNER_ADDRESS),
            cscli=cscli_text(
                alert(
                    decision("198.51.100.1"),
                    decision("198.51.100.2"),
                    decision(OWNER_ADDRESS),
                )
            ),
        )
        self.invoke(runtime)
        text = self.textfile.read_text()
        self.assertEqual(totals(text), {(SCENARIO, "false"): 2, (SCENARIO, "true"): 1})
        series = [line.rsplit(" ", 1)[0] for line in text.splitlines() if line.startswith("edge_")]
        self.assertEqual(len(series), len(set(series)))

    def test_second_owned_ban_of_the_same_scenario_gets_its_own_sample(self) -> None:
        first = decision(OWNER_ADDRESS, ident=41)
        second = decision(OWNER_ADDRESS, ident=42)
        log = self.owner_log(OWNER_ADDRESS)
        self.invoke(FakeRuntime(files=log, cscli=cscli_text(alert(first))))
        self.assertEqual(self.textfile_samples(), {(SCENARIO, "true", "41"): 1})
        self.invoke(FakeRuntime(files=log, cscli=cscli_text(alert(first), alert(second))))
        self.assertEqual(
            self.textfile_samples(),
            {(SCENARIO, "true", "41"): 1, (SCENARIO, "true", "42"): 1},
        )

    def test_owned_decision_without_usable_id_is_aggregated(self) -> None:
        bare_one = decision(OWNER_ADDRESS)
        bare_two = decision("2001:db8::10")
        del bare_one["id"]
        bare_two["id"] = None
        self.invoke(
            FakeRuntime(
                files=self.owner_log(OWNER_ADDRESS, "2001:db8::10"),
                cscli=cscli_text(alert(bare_one, bare_two, decision(OWNER_ADDRESS, ident=43))),
            )
        )
        self.assertEqual(
            self.textfile_samples(), {(SCENARIO, "true", None): 2, (SCENARIO, "true", "43"): 1}
        )

    def test_the_alert_id_is_never_used_for_its_decisions(self) -> None:
        bare = decision(OWNER_ADDRESS)
        del bare["id"]
        self.invoke(FakeRuntime(files=self.owner_log(OWNER_ADDRESS), cscli=cscli_text(alert(bare))))
        self.assertEqual(self.textfile_samples(), {(SCENARIO, "true", None): 1})

    def test_decision_id_label_is_digits_only(self) -> None:
        rejected: list[object] = [
            -5,
            3.0,
            1.5,
            "192.0.2.4",
            "abc12",
            "12\n",
            "١٢",
            "",
            True,
            False,
            10**18,
            "1000000000000000000",
            [4],
        ]
        accepted: list[object] = [0, "007", "123", 10**18 - 1]
        decisions = [decision(OWNER_ADDRESS, ident=value) for value in [*accepted, *rejected]]
        null_id = decision(OWNER_ADDRESS)
        null_id["id"] = None
        decisions.append(null_id)
        self.invoke(
            FakeRuntime(files=self.owner_log(OWNER_ADDRESS), cscli=cscli_text(alert(*decisions)))
        )
        self.assertEqual(
            self.textfile_samples(),
            {
                (SCENARIO, "true", "0"): 1,
                (SCENARIO, "true", "007"): 1,
                (SCENARIO, "true", "123"): 1,
                (SCENARIO, "true", str(10**18 - 1)): 1,
                (SCENARIO, "true", None): len(rejected) + 1,
            },
        )

    def test_decision_id_is_read_from_a_flat_decision_too(self) -> None:
        flat = json.dumps([decision(OWNER_ADDRESS, ident=44), decision(OWNER_ADDRESS, ident="45")])
        self.invoke(FakeRuntime(files=self.owner_log(OWNER_ADDRESS), cscli=flat))
        self.assertEqual(
            self.textfile_samples(),
            {(SCENARIO, "true", "44"): 1, (SCENARIO, "true", "45"): 1},
        )

    def test_the_same_decision_listed_twice_is_one_sample_with_a_count(self) -> None:
        twice = decision(OWNER_ADDRESS, ident=46)
        self.invoke(
            FakeRuntime(
                files=self.owner_log(OWNER_ADDRESS), cscli=cscli_text(alert(twice), alert(twice))
            )
        )
        self.assertEqual(self.textfile_samples(), {(SCENARIO, "true", "46"): 2})

    def test_unowned_bans_stay_aggregated(self) -> None:
        self.invoke(
            FakeRuntime(
                files=self.owner_log(OWNER_ADDRESS),
                cscli=cscli_text(
                    alert(
                        decision(SCANNER_ADDRESS, ident=47),
                        decision("198.51.100.8", ident=48),
                        decision(RANGE_NETWORK, scope="Range", ident=49),
                    )
                ),
            )
        )
        self.assertEqual(self.textfile_samples(), {(SCENARIO, "false", None): 3})
        unowned_lines = [
            line for line in self.textfile.read_text().splitlines() if 'owned="false"' in line
        ]
        self.assertEqual(len(unowned_lines), 1)
        self.assertNotIn("decision_id", unowned_lines[0])

    def test_reason_that_could_hold_an_address_becomes_unknown(self) -> None:
        runtime = FakeRuntime(
            files=self.owner_log(OWNER_ADDRESS),
            cscli=cscli_text(
                alert(
                    decision("198.51.100.1", scenario="manual ban of 198.51.100.1"),
                    decision("198.51.100.2", scenario='quote"and\\slash\nnewline'),
                    decision("198.51.100.3", scenario="crowdsecurity/with-1.2.3-version"),
                    decision("198.51.100.4", scenario="crowdsecurity/probe-198.51.100.4"),
                )
            ),
        )
        self.invoke(runtime)
        self.assertEqual(
            self.textfile_totals(),
            {("unknown", "false"): 3, ("crowdsecurity/with-1.2.3-version", "false"): 1},
        )
        self.assertEqual(address_literals(self.textfile.read_text()), [])


class FailClosedTests(RuntimeTestCase):
    def ban(self) -> str:
        return cscli_text(alert(decision(SCANNER_ADDRESS)))

    def assert_every_ban_owned(self, runtime: FakeRuntime) -> None:
        status, _ = self.invoke(runtime)
        self.assertEqual(status, 0)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "true"): 1})

    def test_fail_closed_output_labels_each_ban_with_its_decision_id(self) -> None:
        runtime = FakeRuntime(
            files={},
            cscli=cscli_text(
                alert(
                    decision(SCANNER_ADDRESS, ident=51),
                    decision("198.51.100.8", ident=52),
                    decision(RANGE_NETWORK, scope="Range", ident=53),
                )
            ),
        )
        status, _ = self.invoke(runtime)
        self.assertEqual(status, 0)
        self.assertEqual(
            self.textfile_samples(),
            {(SCENARIO, "true", "51"): 1, (SCENARIO, "true", "52"): 1, (SCENARIO, "true", "53"): 1},
        )
        self.assertEqual(address_literals(self.textfile.read_text()), [])

    def test_no_log_file_marks_every_ban_owned(self) -> None:
        self.assert_every_ban_owned(FakeRuntime(files={}, cscli=self.ban()))

    def test_empty_trusted_set_marks_every_ban_owned(self) -> None:
        log = access_line(OWNER_ADDRESS, trusted="0") + access_line(SCANNER_ADDRESS, trusted=None)
        self.assert_every_ban_owned(FakeRuntime(files={"access.log": log}, cscli=self.ban()))

    def test_trusted_lines_older_than_the_window_leave_the_set_empty(self) -> None:
        old = access_line(OWNER_ADDRESS, seen=NOW - 31 * DAY)
        self.assert_every_ban_owned(FakeRuntime(files={"access.log": old}, cscli=self.ban()))

    def test_unusable_signal_never_rewrites_the_state_file(self) -> None:
        self.write_state({OWNER_ADDRESS: NOW - 60})
        before = self.state_file.read_bytes()
        self.invoke(FakeRuntime(files={}, cscli=self.ban()))
        self.assertEqual(self.state_file.read_bytes(), before)

    def test_prior_state_is_not_a_fallback_when_the_log_cannot_be_read(self) -> None:
        self.write_state({SCANNER_ADDRESS: NOW - 60})
        runtime = FakeRuntime(
            files={"access.log": access_line(OWNER_ADDRESS)},
            cscli=self.ban(),
            directory_listing_fails=5,
        )
        self.assert_every_ban_owned(runtime)

    def test_missing_caddy_container_fails_closed(self) -> None:
        self.assert_every_ban_owned(FakeRuntime(caddy_missing=True, cscli=self.ban()))

    def test_corrupt_gzip_sibling_fails_closed(self) -> None:
        name = rolled_name(NOW - DAY, compressed=True)
        files = {
            "access.log": access_line(OWNER_ADDRESS),
            name: gzip.compress(access_line(SCANNER_ADDRESS))[:-12],
        }
        self.assert_every_ban_owned(FakeRuntime(files=files, cscli=self.ban()))

    def test_one_listing_failure_is_retried_once(self) -> None:
        runtime = FakeRuntime(
            files={"access.log": access_line(OWNER_ADDRESS)},
            cscli=self.ban(),
            directory_listing_fails=1,
        )
        status, _ = self.invoke(runtime)
        self.assertEqual(status, 0)
        self.assertEqual(runtime.listings, 2)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "false"): 1})

    def test_a_failure_of_the_retry_too_is_fail_closed(self) -> None:
        runtime = FakeRuntime(
            files={"access.log": access_line(OWNER_ADDRESS)},
            cscli=self.ban(),
            directory_listing_fails=2,
        )
        self.assert_every_ban_owned(runtime)
        self.assertEqual(runtime.listings, 2)

    def test_read_deadline_fails_closed(self) -> None:
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli=self.ban())
        errors = io.StringIO()
        ticks = iter([0.0])
        late = program.READ_DEADLINE_SECONDS + 1.0
        with contextlib.redirect_stderr(errors):
            status = program.main(self.options(), runtime, lambda: NOW, lambda: next(ticks, late))
        self.assertEqual(status, 0)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "true"): 1})
        self.assertIn("deadline", errors.getvalue())


class CscliFailureTests(RuntimeTestCase):
    def test_cscli_failure_writes_no_textfile_and_exits_non_zero(self) -> None:
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli_fails=True)
        status, _ = self.invoke(runtime)
        self.assertEqual(status, program.EXIT_CROWDSEC)
        self.assertNotEqual(status, 0)
        self.assertFalse(self.textfile.exists())
        self.assertFalse(self.state_file.exists())
        self.assertEqual(sorted(os.listdir(self.textfile_dir)), [])

    def test_cscli_failure_leaves_the_previous_textfile_byte_identical(self) -> None:
        self.textfile.write_bytes(b"previous run\n")
        os.utime(self.textfile, (1, 1))
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli_fails=True)
        status, _ = self.invoke(runtime)
        self.assertEqual(status, program.EXIT_CROWDSEC)
        self.assertEqual(self.textfile.read_bytes(), b"previous run\n")
        self.assertEqual(self.textfile.stat().st_mtime, 1)

    def test_missing_crowdsec_container_is_a_cscli_failure(self) -> None:
        runtime = FakeRuntime(
            files={"access.log": access_line(OWNER_ADDRESS)}, crowdsec_missing=True
        )
        status, _ = self.invoke(runtime)
        self.assertEqual(status, program.EXIT_CROWDSEC)
        self.assertFalse(self.textfile.exists())

    def test_invalid_cscli_json_is_a_cscli_failure(self) -> None:
        for text in ["{not json", '{"decisions": []}', '["a string"]', '[{"decisions": "x"}]']:
            with self.subTest(text=text):
                runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli=text)
                status, _ = self.invoke(runtime)
                self.assertEqual(status, program.EXIT_CROWDSEC)
                self.assertFalse(self.textfile.exists())

    def test_parse_decisions_raises_crowdsec_query_error(self) -> None:
        with self.assertRaises(program.CrowdSecQueryError):
            program.parse_decisions("{not json")


class TrustedLineTests(RuntimeTestCase):
    def trusted_after(self, log: bytes) -> dict[str, int]:
        runtime = FakeRuntime(
            files={"access.log": access_line("192.0.2.99") + log}, cscli=cscli_text()
        )
        self.invoke(runtime)
        document = json.loads(self.state_file.read_text())
        addresses = cast(dict[str, int], document["addresses"])
        return {key: value for key, value in addresses.items() if key != "192.0.2.99"}

    def test_edge_trusted_accepts_string_and_number_one(self) -> None:
        log = (
            access_line("192.0.2.1", trusted="1")
            + access_line("192.0.2.2", trusted=1)
            + access_line("192.0.2.3", trusted=1.0)
        )
        self.assertEqual(sorted(self.trusted_after(log)), ["192.0.2.1", "192.0.2.2", "192.0.2.3"])

    def test_edge_trusted_rejects_everything_else(self) -> None:
        log = b"".join(
            access_line(f"192.0.2.{index}", trusted=value)
            for index, value in enumerate(
                ["0", 0, True, "true", "01", 2, None, [1], {"a": 1}, ""], 1
            )
        )
        self.assertEqual(self.trusted_after(log), {})

    def test_bad_lines_are_counted_not_fatal(self) -> None:
        overlong = b'{"edge_trusted":"1","pad":"' + b"x" * (program.MAX_LINE_BYTES + 10) + b'"}\n'
        log = (
            b"not json at all\n"
            + b"[1, 2]\n"
            + b"\n"
            + b'{"edge_trusted":"1"\n'
            + overlong
            + access_line("192.0.2.1")
            + access_line("192.0.2.2").rstrip(b"\n")
        )
        self.assertEqual(sorted(self.trusted_after(log)), ["192.0.2.1", "192.0.2.2"])

    def test_bad_line_count_is_reported_without_content(self) -> None:
        log = b"not json at all\n[1, 2]\n" + access_line("192.0.2.1")
        runtime = FakeRuntime(files={"access.log": log}, cscli=cscli_text())
        _, errors = self.invoke(runtime)
        self.assertIn("bad_lines=2", errors)
        self.assertNotIn("not json", errors)

    def test_lines_with_an_unusable_address_or_time_are_skipped(self) -> None:
        def raw(request: object, seen: object) -> bytes:
            return (
                json.dumps({"ts": seen, "request": request, "edge_trusted": "1"}).encode() + b"\n"
            )

        log = (
            raw({"remote_ip": "not-an-address"}, NOW - 5)
            + raw({"remote_ip": 5}, NOW - 5)
            + raw({}, NOW - 5)
            + raw("text", NOW - 5)
            + raw({"remote_ip": "192.0.2.1"}, "yesterday")
            + raw({"remote_ip": "192.0.2.2"}, True)
            + raw({"remote_ip": "192.0.2.3"}, NOW + 10 * DAY)
            + raw({"remote_ip": "192.0.2.4"}, NOW - 31 * DAY)
            + raw({"remote_ip": "192.0.2.5"}, NOW - 5)
        )
        self.assertEqual(sorted(self.trusted_after(log)), ["192.0.2.5"])

    def test_last_seen_is_the_newest_line_and_zones_are_dropped(self) -> None:
        log = (
            access_line("192.0.2.1", seen=NOW - 9000)
            + access_line("192.0.2.1", seen=NOW - 100)
            + access_line("192.0.2.1", seen=NOW - 5000)
            + access_line("2001:db8::1%eth0", seen=NOW - 50)
        )
        self.assertEqual(
            self.trusted_after(log), {"192.0.2.1": int(NOW - 100), "2001:db8::1": int(NOW - 50)}
        )


class LogFileSelectionTests(RuntimeTestCase):
    def test_gz_sibling_is_read(self) -> None:
        name = rolled_name(NOW - 2 * DAY, compressed=True)
        files = {
            "access.log": access_line(SCANNER_ADDRESS, trusted="0"),
            name: gzip.compress(access_line(OWNER_ADDRESS, seen=NOW - 2 * DAY)),
        }
        runtime = FakeRuntime(files=files, cscli=cscli_text(alert(decision(OWNER_ADDRESS))))
        self.invoke(runtime)
        self.assertIn(name, runtime.opened)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "true"): 1})

    def test_uncompressed_roll_and_size_suffix_are_read(self) -> None:
        names = [
            rolled_name(NOW - 2 * DAY),
            rolled_name(NOW - 3 * DAY, reason="size_1"),
            rolled_name(NOW - 4 * DAY, reason="size", compressed=True),
        ]
        files = {name: access_line(OWNER_ADDRESS, seen=NOW - 2 * DAY) for name in names[:2]}
        files[names[2]] = gzip.compress(access_line(OWNER_ADDRESS))
        runtime = FakeRuntime(files=files, cscli=cscli_text())
        self.invoke(runtime)
        self.assertEqual(sorted(runtime.opened), sorted(names))

    def test_old_rolled_file_is_skipped(self) -> None:
        old = rolled_name(NOW - 60 * DAY, compressed=True)
        files = {
            "access.log": access_line(OWNER_ADDRESS),
            old: gzip.compress(access_line(SCANNER_ADDRESS, seen=NOW - 60 * DAY)),
        }
        runtime = FakeRuntime(files=files, cscli=cscli_text(alert(decision(SCANNER_ADDRESS))))
        self.invoke(runtime)
        self.assertEqual(runtime.opened, ["access.log"])
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "false"): 1})

    def test_only_the_access_stem_is_ever_opened(self) -> None:
        files = {
            "access.log": access_line(OWNER_ADDRESS),
            "access.log.1": access_line(SCANNER_ADDRESS),
            "access-notes.log": access_line(SCANNER_ADDRESS),
            "accessX.log": access_line(SCANNER_ADDRESS),
            "access-2027-01-01T00-00-00.000-time.log.bak": access_line(SCANNER_ADDRESS),
            "access-2027-01-01T00-00-00.000-time.log.gz.tmp": access_line(SCANNER_ADDRESS),
            "XXaccess-2027-01-01T00-00-00.000-time.log": access_line(SCANNER_ADDRESS),
        }
        runtime = FakeRuntime(files=files, cscli=cscli_text())
        self.invoke(runtime)
        self.assertEqual(runtime.opened, ["access.log"])

    def test_probe_log_is_never_opened(self) -> None:
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli=cscli_text())
        self.invoke(runtime)
        self.assertEqual(runtime.opened, ["access.log"])

    def test_incremental_skips_files_older_than_state(self) -> None:
        self.write_state({"192.0.2.77": NOW - 3 * DAY}, generated_at=NOW - 300)
        old = rolled_name(NOW - 10 * DAY, compressed=True)
        recent = rolled_name(NOW - 600, compressed=True)
        files = {
            "access.log": access_line(OWNER_ADDRESS),
            old: gzip.compress(access_line("192.0.2.88", seen=NOW - 10 * DAY)),
            recent: gzip.compress(access_line("192.0.2.66", seen=NOW - 900)),
        }
        runtime = FakeRuntime(files=files, cscli=cscli_text())
        self.invoke(runtime)
        self.assertEqual(sorted(runtime.opened), sorted(["access.log", recent]))
        addresses = json.loads(self.state_file.read_text())["addresses"]
        self.assertEqual(sorted(addresses), sorted(["192.0.2.66", "192.0.2.77", OWNER_ADDRESS]))

    def test_without_state_every_file_in_the_window_is_read(self) -> None:
        old = rolled_name(NOW - 10 * DAY, compressed=True)
        files = {
            "access.log": access_line(OWNER_ADDRESS),
            old: gzip.compress(access_line("192.0.2.88", seen=NOW - 10 * DAY)),
        }
        runtime = FakeRuntime(files=files, cscli=cscli_text())
        self.invoke(runtime)
        self.assertEqual(sorted(runtime.opened), sorted(["access.log", old]))

    def test_corrupt_state_is_read_as_absent_and_replaced(self) -> None:
        self.state_file.write_text("{ this is not json")
        self.state_file.chmod(0o600)
        old = rolled_name(NOW - 10 * DAY, compressed=True)
        files = {
            "access.log": access_line(OWNER_ADDRESS),
            old: gzip.compress(access_line("192.0.2.88", seen=NOW - 10 * DAY)),
        }
        runtime = FakeRuntime(files=files, cscli=cscli_text())
        status, _ = self.invoke(runtime)
        self.assertEqual(status, 0)
        self.assertIn(old, runtime.opened)
        addresses = json.loads(self.state_file.read_text())["addresses"]
        self.assertEqual(sorted(addresses), sorted(["192.0.2.88", OWNER_ADDRESS]))

    def test_state_entries_past_the_window_are_pruned(self) -> None:
        self.write_state({"192.0.2.55": NOW - 40 * DAY, "192.0.2.56": NOW - 2 * DAY})
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli=cscli_text())
        self.invoke(runtime)
        addresses = json.loads(self.state_file.read_text())["addresses"]
        self.assertEqual(sorted(addresses), sorted(["192.0.2.56", OWNER_ADDRESS]))


class StateTests(RuntimeTestCase):
    def test_state_document_has_the_documented_shape(self) -> None:
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli=cscli_text())
        self.invoke(runtime)
        document = json.loads(self.state_file.read_text())
        self.assertEqual(
            document,
            {
                "schema_version": 1,
                "generated_at": int(NOW),
                "addresses": {OWNER_ADDRESS: int(NOW - 3600)},
            },
        )

    def test_state_file_is_mode_0600_and_textfile_0644(self) -> None:
        self.addCleanup(os.umask, os.umask(0o077))
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli=cscli_text())
        self.invoke(runtime)
        self.assertEqual(stat.S_IMODE(self.state_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.textfile.stat().st_mode), 0o644)
        self.assertEqual(self.state_file.stat().st_uid, os.geteuid())

    def test_replacing_a_loose_state_file_makes_it_0600_again(self) -> None:
        self.write_state({"192.0.2.55": NOW - 60})
        self.state_file.chmod(0o666)
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli=cscli_text())
        self.invoke(runtime)
        self.assertEqual(stat.S_IMODE(self.state_file.stat().st_mode), 0o600)

    def test_symlink_state_file_is_refused(self) -> None:
        target = self.scratch / "elsewhere.json"
        target.write_text("original")
        self.state_file.symlink_to(target)
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli=cscli_text())
        status, _ = self.invoke(runtime)
        self.assertEqual(status, program.EXIT_OUTPUT)
        self.assertEqual(target.read_text(), "original")
        self.assertFalse(self.textfile.exists())
        with self.assertRaises(program.UnsafePathError):
            program.read_state(self.state_file)

    def test_fifo_state_file_is_refused_without_blocking(self) -> None:
        os.mkfifo(self.state_file)
        with self.assertRaises(program.UnsafePathError):
            program.read_state(self.state_file)

    def test_state_file_owned_by_someone_else_is_refused(self) -> None:
        self.write_state({OWNER_ADDRESS: NOW})
        with (
            mock.patch("os.geteuid", return_value=os.geteuid() + 1),
            self.assertRaises(program.UnsafePathError),
        ):
            program.read_state(self.state_file)

    def test_missing_state_file_reads_as_none(self) -> None:
        self.assertIsNone(program.read_state(self.state_file))

    def test_read_state_raises_state_format_error_for_every_malformed_form(self) -> None:
        good: dict[str, object] = {
            "schema_version": 1,
            "generated_at": 5,
            "addresses": {OWNER_ADDRESS: 5},
        }
        malformed: list[object] = [
            "text",
            [],
            {**good, "schema_version": 2},
            {**good, "schema_version": True},
            {**good, "generated_at": "5"},
            {**good, "generated_at": False},
            {**good, "addresses": []},
            {**good, "addresses": {"not-an-address": 5}},
            {**good, "addresses": {OWNER_ADDRESS: "5"}},
            {**good, "addresses": {OWNER_ADDRESS: True}},
            {key: value for key, value in good.items() if key != "addresses"},
        ]
        for document in malformed:
            with self.subTest(document=document):
                self.state_file.write_text(json.dumps(document))
                with self.assertRaises(program.StateFormatError):
                    program.read_state(self.state_file)
        self.state_file.write_text("{ truncated")
        with self.assertRaises(program.StateFormatError):
            program.read_state(self.state_file)
        self.state_file.write_bytes(b"\xff\xfe")
        with self.assertRaises(program.StateFormatError):
            program.read_state(self.state_file)

    def test_a_well_formed_state_reads_back(self) -> None:
        self.write_state({OWNER_ADDRESS: NOW - 5, "::ffff:192.0.2.11": NOW - 6}, generated_at=NOW)
        state = program.read_state(self.state_file)
        if state is None:
            self.fail("the state file reads as absent")
        self.assertEqual(state.generated_at, int(NOW))
        self.assertEqual(
            state.addresses,
            {
                ipaddress.ip_address(OWNER_ADDRESS): int(NOW - 5),
                ipaddress.ip_address("192.0.2.11"): int(NOW - 6),
            },
        )


class TextfileTests(RuntimeTestCase):
    def busy_runtime(self) -> FakeRuntime:
        return FakeRuntime(
            files={
                "access.log": access_line(OWNER_ADDRESS)
                + access_line("2001:db8::10")
                + access_line(RANGE_MEMBER)
            },
            cscli=cscli_text(
                alert(
                    decision(OWNER_ADDRESS, ident=11),
                    decision(SCANNER_ADDRESS, ident=12),
                    decision("2001:db8::10", ident=13),
                    decision("2001:db8:ffff::1", ident=14),
                    decision(RANGE_NETWORK, scope="Range", ident="15"),
                    decision("2001:db8:ffff::/48", scope="Range", ident=16),
                )
            ),
        )

    def test_textfile_contains_no_ip_literal(self) -> None:
        status, errors = self.invoke(self.busy_runtime())
        self.assertEqual(status, 0)
        text = self.textfile.read_text()
        self.assertEqual(address_literals(text), [])
        self.assertEqual(address_literals(errors), [])
        self.assertEqual(sum(totals(text).values()), 6)
        self.assertNotIn("192.0.2", text + errors)

    def test_the_address_scan_itself_finds_addresses(self) -> None:
        self.assertEqual(address_literals("x 192.0.2.10 y"), ["192.0.2.10", "192.0.2.10"])
        self.assertTrue(address_literals("v 2001:db8::10 w"))

    def test_textfile_has_the_documented_lines(self) -> None:
        self.invoke(self.busy_runtime())
        lines = self.textfile.read_text().splitlines()
        names = [line.split()[2] for line in lines if line.startswith("# TYPE")]
        self.assertEqual(names, [program.OWNED_METRIC, program.LAST_RUN_METRIC])
        self.assertEqual(lines[-1], f"{program.LAST_RUN_METRIC} {int(NOW)}")
        prefix = f'{program.OWNED_METRIC}{{reason="{SCENARIO}"'
        self.assertEqual(
            [line for line in lines if line.startswith(program.OWNED_METRIC + "{")],
            [
                f'{prefix},owned="false"}} 3',
                f'{prefix},owned="true",decision_id="11"}} 1',
                f'{prefix},owned="true",decision_id="13"}} 1',
                f'{prefix},owned="true",decision_id="15"}} 1',
            ],
        )
        help_line = next(line for line in lines if line.startswith("# HELP edge_ban_owned "))
        self.assertIn("One sample per owned ban", help_line)

    def test_no_bans_still_writes_the_timestamp(self) -> None:
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli="null")
        self.invoke(runtime)
        text = self.textfile.read_text()
        self.assertEqual(totals(text), {})
        self.assertIn(f"{program.LAST_RUN_METRIC} {int(NOW)}\n", text)

    def test_textfile_target_symlink_is_refused(self) -> None:
        target = self.scratch / "elsewhere.prom"
        target.write_text("original")
        self.textfile.symlink_to(target)
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli=cscli_text())
        status, _ = self.invoke(runtime)
        self.assertEqual(status, program.EXIT_OUTPUT)
        self.assertEqual(target.read_text(), "original")
        with self.assertRaises(program.UnsafePathError):
            program.write_atomically(self.textfile, b"x", 0o644)

    def test_write_atomically_leaves_no_temporary_file_and_replaces(self) -> None:
        self.textfile.write_bytes(b"old")
        program.write_atomically(self.textfile, b"new", 0o644)
        self.assertEqual(self.textfile.read_bytes(), b"new")
        self.assertEqual(os.listdir(self.textfile_dir), [self.textfile.name])

    def test_a_failed_write_keeps_the_old_file_and_cleans_up(self) -> None:
        self.textfile.write_bytes(b"old")
        with (
            mock.patch("os.replace", side_effect=OSError("disk gone")),
            self.assertRaises(program.OutputWriteError),
        ):
            program.write_atomically(self.textfile, b"new", 0o644)
        self.assertEqual(self.textfile.read_bytes(), b"old")
        self.assertEqual(os.listdir(self.textfile_dir), [self.textfile.name])

    def test_a_missing_output_directory_is_an_output_write_error(self) -> None:
        shutil.rmtree(self.textfile_dir)
        runtime = FakeRuntime(files={"access.log": access_line(OWNER_ADDRESS)}, cscli=cscli_text())
        status, _ = self.invoke(runtime)
        self.assertEqual(status, program.EXIT_OUTPUT)
        with self.assertRaises(program.OutputWriteError):
            program.write_atomically(self.textfile, b"x", 0o644)

    def test_a_directory_in_place_of_the_textfile_is_refused(self) -> None:
        self.textfile.mkdir()
        with self.assertRaises(program.UnsafePathError):
            program.write_atomically(self.textfile, b"x", 0o644)

    def test_temporary_name_is_ignored_by_node_exporter(self) -> None:
        seen: list[str] = []
        original = os.replace

        def spy(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
            seen.append(os.fspath(source))
            original(source, target)

        with mock.patch("os.replace", spy):
            program.write_atomically(self.textfile, b"x", 0o644)
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0].endswith(".tmp"))
        self.assertEqual(Path(seen[0]).parent, self.textfile_dir)


class CommandLineTests(RuntimeTestCase):
    def test_check_reads_no_files_and_calls_no_runtime(self) -> None:
        runtime = mock.Mock(spec=program.ContainerRuntime)
        status = program.main(["--check"], runtime, lambda: NOW, lambda: 0.0)
        self.assertEqual(status, 0)
        self.assertEqual(runtime.mock_calls, [])

    def test_check_accepts_every_option_the_unit_passes(self) -> None:
        status = program.main(
            [
                "--check",
                "--docker-binary",
                "/usr/bin/docker",
                "--compose-project",
                "edge",
                "--caddy-service",
                "caddy",
                "--crowdsec-service",
                "crowdsec",
                "--log-dir",
                "/var/log/caddy",
                "--log-stem",
                "access",
                "--window-days",
                "30",
                "--state-file",
                "/var/lib/branchleft/edge-ban-owner/trusted.json",
                "--textfile",
                "/var/lib/branchleft/snds-exporter/edge_ban_owner.prom",
            ],
            mock.Mock(spec=program.ContainerRuntime),
            lambda: NOW,
            lambda: 0.0,
        )
        self.assertEqual(status, 0)

    def test_bad_options_are_a_usage_error(self) -> None:
        for arguments in [
            ["--window-days", "0"],
            ["--window-days", "x"],
            ["--log-stem", "../access"],
            ["--log-stem", "*"],
            ["--log-dir", "relative/dir"],
            ["--compose-project", "bad project"],
            ["--state-file", "relative.json"],
            ["--textfile", "relative.prom"],
            ["--no-such-option"],
        ]:
            with (
                self.subTest(arguments=arguments),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                program.main(
                    arguments, mock.Mock(spec=program.ContainerRuntime), lambda: NOW, lambda: 0.0
                )
            self.assertEqual(raised.exception.code, program.EXIT_USAGE)

    def test_defaults_match_the_documented_contract(self) -> None:
        config = program.parse_config([])
        self.assertEqual(
            (
                str(config.docker_binary),
                config.compose_project,
                config.caddy_service,
                config.crowdsec_service,
                config.log_dir,
                config.log_stem,
                config.window_days,
                str(config.state_file),
                str(config.textfile),
            ),
            (
                "/usr/bin/docker",
                "edge",
                "caddy",
                "crowdsec",
                "/var/log/caddy",
                "access",
                30,
                "/var/lib/branchleft/edge-ban-owner/trusted.json",
                "/var/lib/branchleft/snds-exporter/edge_ban_owner.prom",
            ),
        )

    def test_the_program_installs_with_its_own_check(self) -> None:
        done = subprocess.run(  # noqa: S603 -- a fixed list, no shell
            ["/usr/bin/env", "python3", "-I", str(program.__file__), "--check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))


class ErrorClassTests(unittest.TestCase):
    def test_every_error_is_an_edge_ban_owner_error(self) -> None:
        for error in [
            program.LogReadError,
            program.StateFormatError,
            program.CrowdSecQueryError,
            program.UnsafePathError,
            program.OutputWriteError,
            program.ContainerRuntimeError,
        ]:
            with self.subTest(error=error.__name__):
                self.assertTrue(issubclass(error, program.EdgeBanOwnerError))

    def test_collect_trusted_raises_log_read_error(self) -> None:
        config = program.parse_config([])
        for runtime in [
            FakeRuntime(files={}),
            FakeRuntime(caddy_missing=True),
            FakeRuntime(files={"access.log": b""}, broken_files=["access.log"]),
            FakeRuntime(files={"access.log": b""}, directory_listing_fails=2),
        ]:
            with self.subTest(runtime=vars(runtime)), self.assertRaises(program.LogReadError):
                program.collect_trusted(config, runtime, NOW, lambda: 0.0, None)

    def test_collect_trusted_raises_log_read_error_for_a_bad_gzip_stream(self) -> None:
        config = program.parse_config([])
        name = rolled_name(NOW - DAY, compressed=True)
        for blob in [b"plain text, not gzip", gzip.compress(b"x" * 5000)[:30]]:
            runtime = FakeRuntime(files={name: blob})
            with self.subTest(blob=blob[:10]), self.assertRaises(program.LogReadError):
                program.collect_trusted(config, runtime, NOW, lambda: 0.0, None)

    def test_find_single_container_raises_for_zero_or_many(self) -> None:
        for output in ["", "\n", "a\nb\n"]:
            with self.subTest(output=output), self.assertRaises(program.ContainerRuntimeError):
                program.single_container_id(output)
        self.assertEqual(program.single_container_id("abc123\n"), "abc123")


class ProblemTests(RuntimeTestCase):
    """Each failure carries the problem that names its cause, so a wrong branch is visible."""

    def problem_of(self, error: type[program.EdgeBanOwnerError], call: Callable[[], object]) -> str:
        with self.assertRaises(error) as raised:
            call()
        return str(raised.exception.problem.name)

    def test_decision_shapes_name_their_problem(self) -> None:
        cases = {
            "{not json": "CSCLI_NOT_JSON",
            '{"a": 1}': "CSCLI_NOT_LIST",
            '["text"]': "ENTRY_NOT_OBJECT",
            '[{"decisions": 5}]': "DECISIONS_NOT_LIST",
            '[{"decisions": [5]}]': "DECISION_NOT_OBJECT",
        }
        for text, name in cases.items():
            with self.subTest(text=text):
                self.assertEqual(
                    self.problem_of(
                        program.CrowdSecQueryError, functools.partial(program.parse_decisions, text)
                    ),
                    name,
                )

    def test_state_shapes_name_their_problem(self) -> None:
        self.state_file.write_text("{ truncated")
        self.assertEqual(
            self.problem_of(program.StateFormatError, lambda: program.read_state(self.state_file)),
            "STATE_NOT_JSON",
        )
        self.state_file.write_text('{"schema_version": 9}')
        self.assertEqual(
            self.problem_of(program.StateFormatError, lambda: program.read_state(self.state_file)),
            "STATE_SCHEMA",
        )
        self.state_file.write_text('{"schema_version": 1, "generated_at": 1}')
        self.assertEqual(
            self.problem_of(program.StateFormatError, lambda: program.read_state(self.state_file)),
            "STATE_FIELDS",
        )
        self.state_file.write_text('{"schema_version":1,"generated_at":1,"addresses":{"x":1}}')
        self.assertEqual(
            self.problem_of(program.StateFormatError, lambda: program.read_state(self.state_file)),
            "STATE_ENTRY",
        )

    def test_state_that_is_too_large_or_unreachable_names_its_problem(self) -> None:
        self.write_state({OWNER_ADDRESS: NOW})
        with mock.patch.object(program, "MAX_STATE_BYTES", 10):
            self.assertEqual(
                self.problem_of(
                    program.StateFormatError, lambda: program.read_state(self.state_file)
                ),
                "STATE_TOO_LARGE",
            )
        beneath_a_file = self.state_file / "child.json"
        self.assertEqual(
            self.problem_of(program.StateFormatError, lambda: program.read_state(beneath_a_file)),
            "STATE_UNOPENABLE",
        )

    def test_unsafe_and_unwritable_paths_name_their_problem(self) -> None:
        link = self.scratch / "link"
        link.symlink_to(self.scratch)
        self.assertEqual(
            self.problem_of(program.UnsafePathError, lambda: program.read_state(link)),
            "SYMBOLIC_LINK",
        )
        os.mkfifo(self.scratch / "fifo")
        self.assertEqual(
            self.problem_of(
                program.UnsafePathError, lambda: program.read_state(self.scratch / "fifo")
            ),
            "NOT_OWN_REGULAR_FILE",
        )
        self.assertEqual(
            self.problem_of(
                program.UnsafePathError, lambda: program.write_atomically(link, b"x", 0o644)
            ),
            "NOT_REGULAR_FILE",
        )
        beneath_a_file = self.textfile_dir / "plain" / "child.prom"
        (self.textfile_dir / "plain").write_text("x")
        self.assertEqual(
            self.problem_of(
                program.OutputWriteError,
                lambda: program.write_atomically(beneath_a_file, b"x", 0o644),
            ),
            "PATH_UNINSPECTABLE",
        )
        missing = self.scratch / "absent" / "file.prom"
        self.assertEqual(
            self.problem_of(
                program.OutputWriteError, lambda: program.write_atomically(missing, b"x", 0o644)
            ),
            "NO_TEMPORARY_FILE",
        )
        with mock.patch("os.replace", side_effect=OSError("disk gone")):
            self.assertEqual(
                self.problem_of(
                    program.OutputWriteError,
                    lambda: program.write_atomically(self.textfile, b"x", 0o644),
                ),
                "WRITE_FAILED",
            )

    def test_log_failures_name_their_problem(self) -> None:
        config = program.parse_config([])

        def collect(runtime: FakeRuntime) -> Callable[[], object]:
            return lambda: program.collect_trusted(config, runtime, NOW, lambda: 0.0, None)

        gz_name = rolled_name(NOW - DAY, compressed=True)
        cases = [
            (FakeRuntime(files={}), "NO_LOG_FILES"),
            (FakeRuntime(caddy_missing=True), "LISTING_FAILED"),
            (
                FakeRuntime(files={"access.log": b""}, broken_files=["access.log"]),
                "LOG_FILE_UNREADABLE",
            ),
            (FakeRuntime(files={gz_name: b"not gzip"}), "LOG_FILE_CORRUPT"),
        ]
        for runtime, name in cases:
            with self.subTest(name=name):
                self.assertEqual(self.problem_of(program.LogReadError, collect(runtime)), name)
        late = program.READ_DEADLINE_SECONDS + 1.0
        ticks = iter([0.0])
        runtime = FakeRuntime(files={"access.log": b""})
        self.assertEqual(
            self.problem_of(
                program.LogReadError,
                lambda: program.collect_trusted(
                    config, runtime, NOW, lambda: next(ticks, late), None
                ),
            ),
            "DEADLINE_PASSED",
        )

    def test_option_checks_name_their_problem(self) -> None:
        for check, text, name in [
            (program.label_value, "a b", "NOT_PLAIN_NAME"),
            (program.log_stem, "a/b", "NOT_PLAIN_NAME"),
            (program.absolute_directory, "relative", "NOT_ABSOLUTE_PATH"),
            (program.absolute_directory, "/a/../b", "NOT_ABSOLUTE_PATH"),
            (program.absolute_path, "relative", "NOT_ABSOLUTE_PATH"),
            (program.positive_days, "0", "NOT_POSITIVE_NUMBER"),
            (program.positive_days, "-3", "NOT_POSITIVE_NUMBER"),
        ]:
            with (
                self.subTest(text=text),
                self.assertRaisesRegex(
                    argparse.ArgumentTypeError, re.escape(str(program.Problem[name]))
                ),
            ):
                check(text)


class DockerCommandRuntimeTests(RuntimeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.docker_dir = self.scratch / "docker"
        self.docker_dir.mkdir()
        self.docker = self.docker_dir / "docker"
        shutil.copy(FAKE_DOCKER, self.docker)
        self.docker.chmod(0o755)
        self.fake_root = self.docker_dir / "fake-root"
        (self.fake_root / "var" / "log" / "caddy").mkdir(parents=True)

    def put_log(self, name: str, content: bytes) -> None:
        (self.fake_root / "var" / "log" / "caddy" / name).write_bytes(content)

    def put_cscli(self, text: str, status: int = 0) -> None:
        (self.fake_root / "cscli.json").write_text(text)
        (self.fake_root / "cscli.rc").write_text(f"{status}\n")

    def docker_options(self) -> list[str]:
        return ["--docker-binary", str(self.docker)]

    def test_real_docker_runtime_argv_against_fake_docker(self) -> None:
        self.put_log("access.log", access_line(OWNER_ADDRESS))
        self.put_log(
            rolled_name(NOW - DAY, compressed=True), gzip.compress(access_line("192.0.2.12"))
        )
        self.put_log("probe.log", access_line(SCANNER_ADDRESS))
        self.put_cscli(cscli_text(alert(decision(OWNER_ADDRESS), decision(SCANNER_ADDRESS))))
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            status = program.main(
                self.options(self.docker_options()), None, lambda: NOW, lambda: 0.0
            )
        self.assertEqual(status, 0, errors.getvalue())
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "true"): 1, (SCENARIO, "false"): 1})
        addresses = json.loads(self.state_file.read_text())["addresses"]
        self.assertEqual(sorted(addresses), sorted([OWNER_ADDRESS, "192.0.2.12"]))

    def test_real_docker_runtime_cscli_failure_exits_three(self) -> None:
        self.put_log("access.log", access_line(OWNER_ADDRESS))
        self.put_cscli("[]", status=1)
        with contextlib.redirect_stderr(io.StringIO()):
            status = program.main(
                self.options(self.docker_options()), None, lambda: NOW, lambda: 0.0
            )
        self.assertEqual(status, program.EXIT_CROWDSEC)
        self.assertFalse(self.textfile.exists())

    def test_real_docker_runtime_without_log_files_marks_ban_owned(self) -> None:
        self.put_cscli(cscli_text(alert(decision(SCANNER_ADDRESS))))
        with contextlib.redirect_stderr(io.StringIO()):
            status = program.main(
                self.options(self.docker_options()), None, lambda: NOW, lambda: 0.0
            )
        self.assertEqual(status, 0)
        self.assertEqual(self.textfile_totals(), {(SCENARIO, "true"): 1})

    def test_runtime_methods_raise_container_runtime_error(self) -> None:
        runtime = program.DockerCommandRuntime(self.docker)
        self.assertEqual(runtime.find_container("edge", "caddy"), "fakecaddy")
        with self.assertRaises(program.ContainerRuntimeError):
            runtime.find_container("edge", "nosuch")
        with self.assertRaises(program.ContainerRuntimeError):
            runtime.find_container("other", "caddy")
        with self.assertRaises(program.ContainerRuntimeError):
            runtime.list_directory("fakecaddy", "/var/log/absent")
        with (
            self.assertRaises(program.ContainerRuntimeError),
            runtime.open_file("fakecaddy", "/var/log/caddy/absent.log") as stream,
        ):
            stream.read()
        with self.assertRaises(program.ContainerRuntimeError):
            runtime.run_cscli("fakecaddy")
        with self.assertRaises(program.ContainerRuntimeError):
            program.DockerCommandRuntime(self.scratch / "no-such-docker").find_container("e", "c")

    def test_open_file_reads_raw_bytes_and_a_plain_file_lists(self) -> None:
        self.put_log("access.log", b"line one\nline two\n")
        runtime = program.DockerCommandRuntime(self.docker)
        self.assertEqual(runtime.list_directory("fakecaddy", "/var/log/caddy"), ["access.log"])
        with runtime.open_file("fakecaddy", "/var/log/caddy/access.log") as stream:
            self.assertEqual(stream.read(), b"line one\nline two\n")

    def write_docker(self, script: str) -> Path:
        hanging = self.docker_dir / "hanging-docker"
        hanging.write_text("#!/bin/sh\n" + script + "\n")
        hanging.chmod(0o755)
        return hanging

    def test_a_docker_call_that_never_answers_times_out(self) -> None:
        runtime = program.DockerCommandRuntime(self.write_docker("exec sleep 30"))
        with mock.patch.object(program, "DOCKER_TIMEOUT_SECONDS", 1):
            with self.assertRaises(program.ContainerRuntimeError) as raised:
                runtime.find_container("edge", "caddy")
        self.assertEqual(raised.exception.problem, program.Problem.DOCKER_NOT_COMPLETED)

    def test_a_cat_that_closes_its_output_but_never_exits_times_out(self) -> None:
        runtime = program.DockerCommandRuntime(self.write_docker("exec 1>&-\nexec sleep 30"))
        with mock.patch.object(program, "DOCKER_TIMEOUT_SECONDS", 1):
            with self.assertRaises(program.ContainerRuntimeError) as raised:
                with runtime.open_file("fakecaddy", "/var/log/caddy/access.log") as stream:
                    stream.read()
        self.assertEqual(raised.exception.problem, program.Problem.DOCKER_NOT_FINISHED)

    def test_a_missing_docker_binary_cannot_start_cat(self) -> None:
        runtime = program.DockerCommandRuntime(self.scratch / "no-such-docker")
        with self.assertRaises(program.ContainerRuntimeError) as raised:
            with runtime.open_file("fakecaddy", "/var/log/caddy/access.log"):
                self.fail("the file must not open")
        self.assertEqual(raised.exception.problem, program.Problem.DOCKER_NOT_STARTED)

    def test_a_cscli_answer_that_is_not_text_fails_the_run(self) -> None:
        self.put_log("access.log", access_line(OWNER_ADDRESS))
        (self.fake_root / "cscli.json").write_bytes(b"\xff\xfe")
        with contextlib.redirect_stderr(io.StringIO()):
            status = program.main(
                self.options(self.docker_options()), None, lambda: NOW, lambda: 0.0
            )
        self.assertEqual(status, program.EXIT_CROWDSEC)
        self.assertFalse(self.textfile.exists())

    def test_fake_docker_refuses_any_other_argument_list(self) -> None:
        for arguments in [
            ["ps"],
            ["ps", "-q"],
            ["ps", "-a", "--filter", "label=a=b", "--filter", "label=c=d"],
            ["exec", "fakecaddy", "ls", "/var/log/caddy"],
            ["exec", "fakecaddy", "cat", "/var/log/caddy/access.log"],
            ["exec", "fakecaddy", "zcat", "--", "/var/log/caddy/access.log"],
            ["exec", "fakecrowdsec", "cscli", "decisions", "list", "-o", "json"],
            [
                "exec",
                "fakecrowdsec",
                "cscli",
                "decisions",
                "list",
                "-a",
                "-o",
                "json",
                "--limit",
                "0",
            ],
            ["exec", "fakecaddy", "cscli", "decisions", "list", "-o", "json", "--limit", "0"],
            ["exec", "fakecrowdsec", "ls", "-1", "--", "/"],
            ["exec", "fakecaddy"],
            ["run", "image"],
            [],
        ]:
            with self.subTest(arguments=arguments):
                done = subprocess.run(  # noqa: S603 -- the fake, an argument list, no shell
                    [str(self.docker), *arguments], capture_output=True, check=False
                )
                self.assertEqual(done.returncode, 64)


class RuleCoherenceTests(unittest.TestCase):
    def test_alert_rules_read_the_names_and_labels_the_program_writes(self) -> None:
        rules = (
            REPOSITORY / "hetzner" / "monitoring" / "stack" / "prometheus" / "alerts.yml"
        ).read_text()
        self.assertIn(f'{program.OWNED_METRIC}{{owned="true"}}', rules)
        self.assertIn(f'{program.OWNED_METRIC}{{owned="false"}}', rules)
        self.assertIn(program.LAST_RUN_METRIC, rules)
        self.assertIn("by (reason)", rules)
        self.assertIn("by (reason, decision_id)", rules)

    def test_the_textfile_default_is_a_name_no_other_role_writes(self) -> None:
        name = program.DEFAULT_TEXTFILE.name
        self.assertEqual(name, "edge_ban_owner.prom")
        others = [
            path
            for path in (REPOSITORY / "ansible" / "roles").glob("*/tasks/**/*.yml")
            if name in path.read_text() and "edge_ban_owner" not in path.parts
        ]
        self.assertEqual(others, [])


if __name__ == "__main__":
    unittest.main()
