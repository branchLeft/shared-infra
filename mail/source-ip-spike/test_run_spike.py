"""Tests for the source-IP spike: the verdict logic, the refusal guards and the sink and sender.

The Docker experiments themselves run only with SPIKE_DOCKER=1 (last class). Everything
else is pure or uses loopback sockets, so this file runs anywhere Python does.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import run_spike
import sender
import sink

IP1 = "10.77.0.2"
IP2 = "10.77.0.3"
EXPECTED = {run_spike.LANE_NL: IP2, run_spike.LANE_TX: IP1}
OK = run_spike.SendResult(ok=True, stage="done", error="", errno=None)


def seen(mail_from: str, peer: str) -> run_spike.Observation:
    return run_spike.Observation(peer=peer, ehlo="e", mail_from=mail_from, rcpt_to=("r@x.test",))


class ParseSinkLog(unittest.TestCase):
    def test_reads_messages_and_ignores_other_lines(self) -> None:
        text = '{"listening": ["0.0.0.0", 2525]}\nnot json\n' + json.dumps(
            {"peer": IP2, "ehlo": "h", "mail_from": "a@x.test", "rcpt_to": ["b@x.test"]}
        )
        found = run_spike.parse_sink_log(text)
        self.assertEqual(
            [(IP2, "h", "a@x.test", ("b@x.test",))],
            [(o.peer, o.ehlo, o.mail_from, o.rcpt_to) for o in found],
        )

    def test_empty_log_is_no_messages(self) -> None:
        self.assertEqual([], run_spike.parse_sink_log(""))


class ParseSendResult(unittest.TestCase):
    def test_reads_the_last_json_line(self) -> None:
        result = run_spike.parse_send_result(
            'noise\n{"ok": false, "stage": "connect", "error": "x", "errno": 99}\n'
        )
        self.assertEqual((False, "connect", 99), (result.ok, result.stage, result.errno))

    def test_garbage_is_a_failed_send(self) -> None:
        result = run_spike.parse_send_result("Traceback ...")
        self.assertFalse(result.ok)
        self.assertIn("no result line", result.error)


class JudgePeer(unittest.TestCase):
    def test_expected_peer_is_green(self) -> None:
        verdict = run_spike.judge_peer(OK, [seen("a@x.test", IP2)], "a@x.test", IP2)
        self.assertEqual(run_spike.GREEN, verdict.status)

    def test_wrong_peer_is_red_and_names_both(self) -> None:
        verdict = run_spike.judge_peer(OK, [seen("a@x.test", IP1)], "a@x.test", IP2)
        self.assertEqual(run_spike.RED, verdict.status)
        self.assertIn(IP1, verdict.reason)
        self.assertIn(IP2, verdict.reason)

    def test_address_not_available_is_red(self) -> None:
        failed = run_spike.SendResult(
            ok=False, stage="connect", error="Address not available", errno=99
        )
        verdict = run_spike.judge_peer(failed, [], "a@x.test", IP2)
        self.assertEqual(run_spike.RED, verdict.status)
        self.assertIn("not available", verdict.reason)

    def test_a_message_that_never_arrived_is_red(self) -> None:
        verdict = run_spike.judge_peer(OK, [seen("other@x.test", IP2)], "a@x.test", IP2)
        self.assertEqual(run_spike.RED, verdict.status)

    def test_a_failed_send_is_red_at_its_stage(self) -> None:
        failed = run_spike.SendResult(ok=False, stage="auth", error="535", errno=None)
        self.assertIn("auth", run_spike.judge_peer(failed, [], "a@x.test", IP2).reason)


class JudgeLanePair(unittest.TestCase):
    def test_both_lanes_right_is_green(self) -> None:
        verdict = run_spike.judge_lane_pair(
            {run_spike.LANE_NL: IP2, run_spike.LANE_TX: IP1}, EXPECTED
        )
        self.assertEqual(run_spike.GREEN, verdict.status)

    def test_swapped_lanes_are_reported_as_a_swap(self) -> None:
        verdict = run_spike.judge_lane_pair(
            {run_spike.LANE_NL: IP1, run_spike.LANE_TX: IP2}, EXPECTED
        )
        self.assertEqual(run_spike.SWAPPED, verdict.status)

    def test_both_on_one_address_is_red_not_a_swap(self) -> None:
        verdict = run_spike.judge_lane_pair(
            {run_spike.LANE_NL: IP1, run_spike.LANE_TX: IP1}, EXPECTED
        )
        self.assertEqual(run_spike.RED, verdict.status)
        self.assertIn(run_spike.LANE_NL, verdict.reason)

    def test_a_missing_lane_is_red(self) -> None:
        verdict = run_spike.judge_lane_pair(
            {run_spike.LANE_NL: None, run_spike.LANE_TX: IP1}, EXPECTED
        )
        self.assertEqual(run_spike.RED, verdict.status)
        self.assertIn(run_spike.LANE_NL, verdict.reason)

    def test_the_verdict_takes_no_configuration(self) -> None:
        parameters = list(inspect.signature(run_spike.judge_lane_pair).parameters)
        self.assertEqual(["observed", "expected"], parameters)

    def test_a_swapped_rule_changes_the_config_but_the_verdict_reads_the_sink(self) -> None:
        straight = run_spike.build_outbound_update(swap_domains=False)["connection"]
        swapped = run_spike.build_outbound_update(swap_domains=True)["connection"]
        self.assertNotEqual(straight, swapped)
        self.assertEqual("'lane-nl'", straight["match"]["0"]["then"])
        self.assertEqual("'lane-tx'", swapped["match"]["0"]["then"])
        # What the sink saw under the swapped rule, judged against the fixed expectation.
        observed = {run_spike.LANE_NL: IP1, run_spike.LANE_TX: IP2}
        self.assertEqual(run_spike.SWAPPED, run_spike.judge_lane_pair(observed, EXPECTED).status)


class JudgeNetworkCreate(unittest.TestCase):
    def test_accepted(self) -> None:
        self.assertEqual(run_spike.GREEN, run_spike.judge_network_create(0, "abc", "29.9.3").status)

    def test_rejected_option_is_unsupported_with_version_and_text(self) -> None:
        text = "Error response from daemon: invalid option: com.docker.network.host_ipv4"
        verdict = run_spike.judge_network_create(1, text, "26.1.0")
        self.assertEqual(run_spike.UNSUPPORTED, verdict.status)
        self.assertIn("26.1.0", verdict.reason)
        self.assertIn(text, verdict.reason)

    def test_other_failure_is_red_not_unsupported(self) -> None:
        verdict = run_spike.judge_network_create(1, "Cannot connect to the Docker daemon", "29.9.3")
        self.assertEqual(run_spike.RED, verdict.status)


class Decide(unittest.TestCase):
    @staticmethod
    def results(**statuses: str) -> dict[str, run_spike.Verdict]:
        return {name: run_spike.Verdict(status, "") for name, status in statuses.items()}

    def test_host_networking_is_preferred_when_both_pass(self) -> None:
        verdicts = self.results(
            E1=run_spike.RED, E2=run_spike.GREEN, E3=run_spike.GREEN, E4=run_spike.GREEN
        )
        self.assertEqual("host networking", run_spike.decide(verdicts))
        self.assertTrue(run_spike.red_then_green(verdicts))

    def test_host_networking_needs_stalwart_to_pass_too(self) -> None:
        verdicts = self.results(E2=run_spike.GREEN, E3=run_spike.GREEN, E4=run_spike.RED)
        self.assertIn("second Docker network", run_spike.decide(verdicts))

    def test_snat_is_the_fallback(self) -> None:
        verdicts = self.results(E2=run_spike.RED, E3=run_spike.UNSUPPORTED, E3b=run_spike.GREEN)
        self.assertIn("SNAT", run_spike.decide(verdicts))

    def test_nothing_green_is_none(self) -> None:
        verdicts = self.results(
            E1=run_spike.RED, E2=run_spike.RED, E3=run_spike.RED, E4=run_spike.RED
        )
        self.assertEqual("none works", run_spike.decide(verdicts))
        self.assertFalse(run_spike.red_then_green(verdicts))


class ExitCode(unittest.TestCase):
    def test_red_e1_alone_is_a_clean_run(self) -> None:
        verdicts = {
            "E1": run_spike.Verdict(run_spike.RED, ""),
            "E2": run_spike.Verdict(run_spike.GREEN, ""),
        }
        self.assertEqual(0, run_spike.exit_code(verdicts))

    def test_a_red_or_swapped_later_experiment_fails_the_run(self) -> None:
        for status in (run_spike.RED, run_spike.SWAPPED):
            with self.subTest(status=status):
                self.assertEqual(1, run_spike.exit_code({"E4": run_spike.Verdict(status, "")}))

    def test_unsupported_and_unproven_are_information(self) -> None:
        verdicts = {
            "E3": run_spike.Verdict(run_spike.UNSUPPORTED, ""),
            "E5": run_spike.Verdict(run_spike.UNPROVEN, ""),
        }
        self.assertEqual(0, run_spike.exit_code(verdicts))


class Guards(unittest.TestCase):
    DESKTOP = "unix:///Users/someone/.docker/run/docker.sock"

    def test_local_desktop_socket_is_allowed(self) -> None:
        run_spike.check_docker_target({}, self.DESKTOP)
        run_spike.check_docker_target({}, "unix:///var/run/docker.sock")

    def test_docker_host_set_is_refused(self) -> None:
        with self.assertRaises(run_spike.RefusedError):
            run_spike.check_docker_target({"DOCKER_HOST": "tcp://203.0.113.5:2375"}, self.DESKTOP)

    def test_remote_contexts_are_refused(self) -> None:
        for endpoint in (
            "tcp://203.0.113.5:2375",
            "ssh://root@203.0.113.5",
            "unix:///tmp/other.sock",
            "",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(run_spike.RefusedError):
                run_spike.check_docker_target({}, endpoint)

    def test_overlapping_subnet_is_refused(self) -> None:
        with self.assertRaises(run_spike.RefusedError):
            run_spike.check_subnet_free("10.77.0.0/24", ["172.17.0.0/16", "10.77.0.128/25"])
        run_spike.check_subnet_free("10.77.0.0/24", ["172.17.0.0/16"])

    def test_only_spike_objects_may_be_removed(self) -> None:
        run_spike.check_spike_names(["spike-host", "spike-sink", "spike-lab"])
        with self.assertRaises(run_spike.RefusedError):
            run_spike.check_spike_names(["spike-host", "postgres"])

    def test_outer_host_networking_is_refused(self) -> None:
        for argv in (
            ["run", "--network", "host", "x"],
            ["create", "--network=host", "x"],
            ["run", "--net=host", "x"],
        ):
            with self.subTest(argv=argv), self.assertRaises(run_spike.RefusedError):
                run_spike.check_outer_argv(argv)
        run_spike.check_outer_argv(["run", "--network", "spike-lab", "x"])
        run_spike.check_outer_argv(["exec", "spike-host", "ip", "addr"])

    def test_small_or_ipv6_subnets_are_refused(self) -> None:
        for subnet in ("10.77.0.0/28", "fd00::/64", "not-a-network"):
            with self.subTest(subnet=subnet), self.assertRaises(run_spike.RefusedError):
                run_spike.Addresses.from_subnet(subnet)

    def test_addresses_follow_the_subnet(self) -> None:
        addresses = run_spike.Addresses.from_subnet("10.88.4.0/24")
        self.assertEqual(
            ("10.88.4.2", "10.88.4.3", "10.88.4.50"), (addresses.ip1, addresses.ip2, addresses.sink)
        )

    def test_the_run_refuses_without_the_switch(self) -> None:
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=False), contextlib.redirect_stderr(stderr):
            os.environ.pop("SPIKE_DOCKER", None)
            self.assertEqual(2, run_spike.main(["--experiments", "e1"]))
        self.assertIn("SPIKE_DOCKER=1", stderr.getvalue())


class StalwartHelpers(unittest.TestCase):
    def test_delivery_connect_lines_give_sender_and_local_ip(self) -> None:
        log = (
            "2026-11-11T23:47:22Z INFO Connecting to remote server (delivery.connect) queueId = 1, "
            'from = "nl@bounce-nl.spike.test", to = ["r@x.test"], size = 35, localIp = 10.77.0.3, remoteIp = 10.77.0.50'
        )
        self.assertEqual(
            [("nl@bounce-nl.spike.test", "10.77.0.3")],
            run_spike.parse_delivery_connect(log + "\nother line"),
        )

    def test_bootstrap_password_is_read_from_the_banner(self) -> None:
        self.assertEqual("abc123", run_spike.parse_bootstrap_password("x\n   password: abc123\ny"))
        with self.assertRaises(run_spike.RefusedError):
            run_spike.parse_bootstrap_password("no banner")

    def test_rejections_are_found(self) -> None:
        bad = {
            "methodResponses": [["x:Domain/set", {"notCreated": {"a": {"type": "invalid"}}}, "0"]]
        }
        good = {"methodResponses": [["x:Domain/set", {"created": {"a": {"id": "b"}}}, "0"]]}
        self.assertEqual(1, len(run_spike.find_rejections(bad)))
        self.assertEqual([], run_spike.find_rejections(good))
        self.assertEqual(
            1,
            len(
                run_spike.find_rejections(
                    {"methodResponses": [["error", {"type": "forbidden"}, "0"]]}
                )
            ),
        )

    def test_field_search_is_case_blind_and_can_miss(self) -> None:
        self.assertEqual(
            "ehloHostname", run_spike.find_field(["name", "ehloHostname"], "ehlo", "helo")
        )
        self.assertIsNone(run_spike.find_field(["name", "sourceIps"], "ehlo", "helo"))

    def test_strategies_carry_the_two_addresses_and_helo_names(self) -> None:
        strategies = run_spike.build_strategies(run_spike.Addresses.from_subnet("10.77.0.0/24"))
        self.assertEqual(IP2, strategies["nl"]["sourceIps"]["0"]["sourceIp"])
        self.assertEqual(IP1, strategies["tx"]["sourceIps"]["0"]["sourceIp"])
        self.assertNotEqual(strategies["nl"]["ehloHostname"], strategies["tx"]["ehloHostname"])


class SinkSession(unittest.TestCase):
    def test_parse_path_takes_the_address_in_brackets(self) -> None:
        self.assertEqual("a@b.test", sink.parse_path("FROM:<a@b.test> SIZE=12"))
        self.assertEqual("raw", sink.parse_path(" raw "))

    def test_a_message_is_recorded_when_data_ends(self) -> None:
        session = sink.Session("10.0.0.9")
        finished = None
        for line in (
            "EHLO h.test",
            "MAIL FROM:<a@b.test>",
            "RCPT TO:<c@d.test>",
            "DATA",
            "body",
            ".",
        ):
            _, done, _ = session.handle(line)
            finished = done or finished
        self.assertEqual(
            {
                "peer": "10.0.0.9",
                "ehlo": "h.test",
                "mail_from": "a@b.test",
                "rcpt_to": ["c@d.test"],
            },
            finished,
        )

    def test_quit_closes(self) -> None:
        self.assertTrue(sink.Session("p").handle("QUIT")[2])


class LoopbackSenderAndSink(unittest.TestCase):
    """The sender and sink against each other on loopback: the sink reports the bound address."""

    def setUp(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.server = self.loop.run_until_complete(
            asyncio.start_server(sink.serve_connection, "127.0.0.1", 0)
        )
        self.port = self.server.sockets[0].getsockname()[1]
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.loop.call_soon_threadsafe(self.server.close)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()

    def run_sender(self, *extra: str) -> dict[str, object]:
        args = sender.build_parser().parse_args(
            ["--host", "127.0.0.1", "--port", str(self.port), "--mail-from", "a@x.test", *extra]
        )
        return sender.send(args)

    def test_sends_and_the_sink_logs_the_peer(self) -> None:
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            result = self.run_sender("--source", "127.0.0.1")
        self.assertTrue(result["ok"], result)
        record = json.loads(captured.getvalue().splitlines()[-1])
        self.assertEqual(("127.0.0.1", "a@x.test"), (record["peer"], record["mail_from"]))

    def test_binding_an_address_the_host_does_not_have_reports_an_errno(self) -> None:
        result = self.run_sender("--source", "192.0.2.77")
        self.assertFalse(result["ok"])
        self.assertIsNotNone(result["errno"])
        self.assertEqual("connect", result["stage"])


@unittest.skipUnless(
    os.environ.get("SPIKE_DOCKER") == "1", "set SPIKE_DOCKER=1 to run the Docker lab"
)
class DockerLab(unittest.TestCase):
    def test_default_bridge_is_red_and_host_networking_is_green(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = run_spike.main(["--experiments", "e1,e2", "--json", str(report)])
            results = json.loads(report.read_text(encoding="utf-8"))["results"]
        self.assertEqual(0, code)
        self.assertEqual(run_spike.RED, results["E1"]["status"])
        self.assertEqual(run_spike.GREEN, results["E2"]["status"])


if __name__ == "__main__":
    unittest.main()
