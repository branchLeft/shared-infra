"""Unit tests for mx1_stack_probe: each action, and that no environment or raw output escapes.

Run from the role's directory with library/ on PYTHONPATH, the way
``ansible/checks/run_role_unit_tests.sh`` does. Every marker here is a throwaway made for the test.
"""

import json
import os
import stat
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import module_runner
import mx1_stack_probe as probe

ENV_MARKER = "THROWAWAY_ENV_VALUE_0001"
RAW_MARKER = "THROWAWAY_RAW_OUTPUT_0002"
IMAGE = "example.invalid/stalwart@sha256:" + "a" * 64
NS = probe.NS_PER_SECOND
BASE_NS = 1_700_000_000 * NS


def stamp_text(nanoseconds: int) -> str:
    """Return a time in the shape Docker prints it."""
    seconds, fraction = divmod(nanoseconds, NS)
    import time

    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds)) + f".{fraction:09d}Z"


class Fake:
    """A docker that answers inspect and exec from a table, and keeps every call."""

    def __init__(self) -> None:
        self.containers: dict[str, dict[str, object]] = {}
        self.exec_hashes: dict[tuple[str, str], str] = {}
        self.calls: list[list[str]] = []

    def add(
        self,
        name: str,
        *,
        created: int = BASE_NS,
        started: int = BASE_NS + NS,
        status: str = "running",
        health: str = "none",
        image: str = IMAGE,
    ) -> None:
        self.containers[name] = {
            "created": created,
            "started": started,
            "status": status,
            "health": health,
            "image": image,
        }

    def run(self, argv: Sequence[str], data: str | None) -> tuple[int, str, str]:
        del data
        self.calls.append(list(argv))
        if argv[1] == "inspect":
            return self.inspect(argv)
        if argv[1] == "exec":
            held = self.exec_hashes.get((argv[2], argv[4]))
            if held is None or self.containers.get(argv[2], {}).get("status") != "running":
                return 1, "", f"Error: {RAW_MARKER}"
            return 0, f"{held}  {argv[4]}\n", ""
        return 127, "", "unexpected call"

    def inspect(self, argv: Sequence[str]) -> tuple[int, str, str]:
        if "--format" not in argv:
            # A full inspect would print the whole container, environment included.
            return 0, json.dumps([{"Config": {"Env": [f"SECRET={ENV_MARKER}"]}}]), ""
        container = self.containers.get(argv[-1])
        if container is None:
            return 1, "", f"Error: No such object: {argv[-1]} {RAW_MARKER}"
        fields = (
            stamp_text(int(str(container["created"]))),
            stamp_text(int(str(container["started"]))),
            str(container["status"]),
            str(container["health"]),
            str(container["image"]),
        )
        return 0, "|".join(fields) + "\n", ""


def no_sleep(_seconds: float) -> None:
    return


class TimestampTest(unittest.TestCase):
    def test_nanoseconds_are_kept(self) -> None:
        self.assertEqual(
            1_700_000_000 * NS + 123_456_789,
            probe.parse_timestamp_ns("2023-11-14T22:13:20.123456789Z"),
        )

    def test_a_short_fraction_and_none_are_read(self) -> None:
        self.assertEqual(
            1_700_000_000 * NS + 500_000_000, probe.parse_timestamp_ns("2023-11-14T22:13:20.5Z")
        )
        self.assertEqual(1_700_000_000 * NS, probe.parse_timestamp_ns("2023-11-14T22:13:20Z"))

    def test_the_time_of_a_never_started_container_is_before_everything(self) -> None:
        self.assertLess(probe.parse_timestamp_ns("0001-01-01T00:00:00Z"), 0)

    def test_a_malformed_time_is_refused(self) -> None:
        for text in ("", "yesterday", "2023-11-14 22:13:20Z", "2023-11-14T22:13:20+01:00"):
            with self.subTest(text=text), self.assertRaises(probe.ProbeError):
                probe.parse_timestamp_ns(text)


class InspectTest(unittest.TestCase):
    def test_the_format_names_five_fields_and_never_the_environment(self) -> None:
        self.assertNotIn("Env", probe.INSPECT_FORMAT)
        self.assertEqual(5, probe.INSPECT_FORMAT.count("|") + 1)

    def test_a_missing_container_is_none_and_the_call_asks_for_the_format(self) -> None:
        fake = Fake()
        self.assertIsNone(probe.inspect_container(fake.run, "docker", "absent"))
        self.assertEqual(
            ["docker", "inspect", "--format", probe.INSPECT_FORMAT, "absent"], fake.calls[0]
        )

    def test_a_line_of_the_wrong_shape_is_refused_without_quoting_it(self) -> None:
        with self.assertRaises(probe.ProbeError) as caught:
            probe.parse_inspect(f"one|two{RAW_MARKER}", "c")
        self.assertNotIn(RAW_MARKER, str(caught.exception))


class FreshTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.fake = Fake()

    def host_file(self, name: str, text: str, mtime_ns: int) -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        os.utime(path, ns=(mtime_ns, mtime_ns))
        return path

    def entry(self, path: Path, kind: str, **more: str) -> dict[str, str]:
        base = {
            "name": "caddyfile" if kind == "bind_file" else "env",
            "service": "caddy" if kind == "bind_file" else "app",
            "container": "caddy-container" if kind == "bind_file" else "app-container",
            "path": str(path),
            "kind": kind,
            "container_path": "/etc/caddy/Caddyfile",
        }
        return {**base, **more}

    def read(self, *entries: dict[str, str]) -> dict[str, object]:
        return probe.container_fresh(entries, self.fake.run, "docker")

    def mounted(
        self, mtime_ns: int, *, seen: str | None = None, **container: object
    ) -> dict[str, object]:
        path = self.host_file("Caddyfile", "config\n", mtime_ns)
        self.fake.add("caddy-container", **container)  # type: ignore[arg-type]
        import hashlib

        self.fake.exec_hashes[("caddy-container", "/etc/caddy/Caddyfile")] = (
            seen or hashlib.sha256(b"config\n").hexdigest()
        )
        return self.read(self.entry(path, "bind_file"))

    def test_a_mounted_file_the_container_has_is_fresh(self) -> None:
        answer = self.mounted(BASE_NS - NS)
        self.assertTrue(answer["ok"])
        self.assertEqual([], answer["stale_services"])

    def test_a_mounted_file_the_container_reads_differently_is_stale_whatever_the_time(
        self,
    ) -> None:
        answer = self.mounted(BASE_NS - NS, seen="b" * 64)
        self.assertEqual(["caddy"], answer["stale_services"])
        result = answer["results"][0]  # type: ignore[index]
        self.assertIn("different content", result["reason"])

    def test_a_mounted_file_written_after_the_container_started_is_stale(self) -> None:
        answer = self.mounted(BASE_NS + 2 * NS)
        self.assertEqual(["caddy"], answer["stale_services"])
        self.assertIn("newer", answer["results"][0]["reason"])  # type: ignore[index]

    def test_a_stopped_container_cannot_vouch_for_a_mounted_file(self) -> None:
        answer = self.mounted(BASE_NS - NS, status="exited")
        self.assertEqual(["caddy"], answer["stale_services"])
        self.assertNotIn(RAW_MARKER, json.dumps(answer))

    def test_a_missing_container_is_stale_and_the_raw_error_is_not_returned(self) -> None:
        path = self.host_file("Caddyfile", "x", BASE_NS)
        answer = self.read(self.entry(path, "bind_file"))
        self.assertEqual(["caddy"], answer["stale_services"])
        self.assertNotIn(RAW_MARKER, json.dumps(answer))

    def test_a_missing_host_file_is_stale(self) -> None:
        self.fake.add("caddy-container")
        answer = self.read(self.entry(self.root / "gone", "bind_file"))
        self.assertEqual(["caddy"], answer["stale_services"])

    def test_a_create_time_file_is_judged_by_the_containers_creation(self) -> None:
        self.fake.add("app-container", created=BASE_NS, started=BASE_NS + 10 * NS)
        older = self.host_file("older", "x", BASE_NS - NS)
        newer = self.host_file("newer", "x", BASE_NS + NS)
        self.assertTrue(self.read(self.entry(older, "create_env"))["ok"])
        self.assertEqual(["app"], self.read(self.entry(newer, "create_env"))["stale_services"])

    def test_a_restart_does_not_make_a_create_time_file_fresh(self) -> None:
        # The file was written after the container was created, and the container was
        # started again afterwards: it still holds the old environment.
        self.fake.add("app-container", created=BASE_NS, started=BASE_NS + 10 * NS)
        edited = self.host_file("edited", "x", BASE_NS + 5 * NS)
        self.assertEqual(["app"], self.read(self.entry(edited, "create_env"))["stale_services"])

    def test_the_services_that_are_stale_are_named_once_and_sorted(self) -> None:
        self.fake.add("app-container", created=BASE_NS)
        first = self.host_file("first", "x", BASE_NS + NS)
        second = self.host_file("second", "x", BASE_NS + NS)
        answer = self.read(
            self.entry(second, "create_env", name="two"),
            self.entry(first, "create_env", name="one"),
        )
        self.assertEqual(["app"], answer["stale_services"])

    def test_a_malformed_input_is_refused(self) -> None:
        path = self.host_file("x", "x", BASE_NS)
        for label, entry in (
            ("unknown kind", self.entry(path, "bind_dir")),
            ("no container path", self.entry(path, "bind_file", container_path="")),
            ("no service", self.entry(path, "create_env", service="")),
        ):
            with self.subTest(label), self.assertRaises(probe.ProbeError):
                self.read(entry)

    def test_the_container_is_read_once_per_name_and_never_with_a_full_inspect(self) -> None:
        self.fake.add("app-container")
        path = self.host_file("x", "x", BASE_NS - NS)
        self.read(
            self.entry(path, "create_env", name="a"), self.entry(path, "create_env", name="b")
        )
        inspects = [call for call in self.fake.calls if call[1] == "inspect"]
        self.assertEqual(1, len(inspects))
        self.assertIn("--format", inspects[0])


class HealthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = Fake()

    def read(self, tries: int = 1, sleep: probe.Sleeper = no_sleep) -> dict[str, object]:
        return probe.docker_health(
            [{"name": "stalwart", "image": IMAGE}], self.fake.run, "docker", tries, 2, sleep
        )

    def test_running_healthy_on_the_pinned_image_is_ok(self) -> None:
        self.fake.add("stalwart", health="healthy")
        self.assertTrue(self.read()["ok"])

    def test_a_container_with_no_healthcheck_is_ok_when_running(self) -> None:
        self.fake.add("stalwart", health="none")
        self.assertTrue(self.read()["ok"])

    def test_each_way_to_be_not_ok_is_named(self) -> None:
        for label, kwargs in (
            ("exited", {"status": "exited"}),
            ("unhealthy", {"health": "unhealthy"}),
            ("starting", {"health": "starting"}),
            ("wrong image", {"image": "example.invalid/other@sha256:" + "b" * 64}),
        ):
            with self.subTest(label):
                self.fake = Fake()
                self.fake.add("stalwart", **kwargs)  # type: ignore[arg-type]
                answer = self.read()
                self.assertFalse(answer["ok"])
                self.assertNotEqual("", answer["containers"][0]["reason"])  # type: ignore[index]

    def test_a_missing_container_is_not_ok(self) -> None:
        self.assertFalse(self.read()["ok"])

    def test_a_container_that_is_starting_is_read_again_until_healthy(self) -> None:
        self.fake.add("stalwart", health="starting")
        sleeps: list[float] = []

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            self.fake.add("stalwart", health="healthy")

        self.assertTrue(self.read(tries=5, sleep=sleep)["ok"])
        self.assertEqual([2], sleeps)

    def test_the_reads_stop_at_the_tries_and_fail(self) -> None:
        self.fake.add("stalwart", health="starting")
        sleeps: list[float] = []
        self.assertFalse(self.read(tries=3, sleep=sleeps.append)["ok"])
        self.assertEqual(2, len(sleeps))

    def test_no_environment_value_or_raw_output_reaches_the_answer_on_any_path(self) -> None:
        for label, setup in (
            ("success", {"health": "healthy"}),
            ("failure", {"status": "exited"}),
            ("absent", None),
        ):
            with self.subTest(label):
                self.fake = Fake()
                if setup is not None:
                    self.fake.add("stalwart", **setup)  # type: ignore[arg-type]
                text = json.dumps(self.read())
                self.assertNotIn(ENV_MARKER, text)
                self.assertNotIn(RAW_MARKER, text)

    def test_an_exception_path_does_not_carry_the_environment_either(self) -> None:
        def broken(argv: Sequence[str], data: str | None) -> tuple[int, str, str]:
            del argv, data
            return 0, f"SECRET={ENV_MARKER}|{RAW_MARKER}", ""

        with self.assertRaises(probe.ProbeError) as caught:
            probe.inspect_container(broken, "docker", "stalwart")
        self.assertNotIn(ENV_MARKER, str(caught.exception))
        self.assertNotIn(RAW_MARKER, str(caught.exception))

    def test_the_probe_never_calls_a_full_inspect(self) -> None:
        self.fake.add("stalwart")
        self.read()
        for call in self.fake.calls:
            self.assertIn("--format", call)


class RecursionTest(unittest.TestCase):
    def runner(self, outputs: Sequence[str]) -> tuple[probe.Runner, list[list[str]]]:
        calls: list[list[str]] = []
        answers = list(outputs)

        def run(argv: Sequence[str], data: str | None) -> tuple[int, str, str]:
            del data
            calls.append(list(argv))
            return 0, answers.pop(0) if answers else "", ""

        return run, calls

    def test_an_address_in_the_answer_is_success(self) -> None:
        run, calls = self.runner(["151.101.2.132\n"])
        self.assertTrue(probe.recursion(run, "dig", "deb.debian.org", 5, 2, no_sleep)["ok"])
        self.assertEqual(
            ["dig", "+short", "+time=3", "+tries=1", "@127.0.0.1", "A", "deb.debian.org"], calls[0]
        )

    def test_a_cname_chain_ending_in_an_address_is_success(self) -> None:
        run, _calls = self.runner(["debian.map.fastlydns.net.\n151.101.2.132\n"])
        self.assertTrue(probe.recursion(run, "dig", "deb.debian.org", 1, 2, no_sleep)["ok"])

    def test_an_empty_answer_fails(self) -> None:
        run, _calls = self.runner([""])
        with self.assertRaises(probe.ProbeError) as caught:
            probe.recursion(run, "dig", "deb.debian.org", 1, 2, no_sleep)
        self.assertIn("recursion is not working", str(caught.exception))

    def test_dig_error_text_is_not_an_answer(self) -> None:
        run, _calls = self.runner([";; connection timed out; no servers could be reached\n"])
        with self.assertRaises(probe.ProbeError):
            probe.recursion(run, "dig", "deb.debian.org", 1, 2, no_sleep)

    def test_the_tries_are_used_up_with_a_pause_between_and_none_after_the_last(self) -> None:
        run, calls = self.runner([])
        sleeps: list[float] = []
        with self.assertRaises(probe.ProbeError):
            probe.recursion(run, "dig", "deb.debian.org", 5, 2, sleeps.append)
        self.assertEqual(5, len(calls))
        self.assertEqual([2, 2, 2, 2], sleeps)

    def test_an_answer_on_a_later_try_is_success(self) -> None:
        run, calls = self.runner(["", "", "192.0.2.1\n"])
        self.assertTrue(probe.recursion(run, "dig", "deb.debian.org", 5, 2, no_sleep)["ok"])
        self.assertEqual(3, len(calls))


class StandInDigTest(unittest.TestCase):
    """The same checks through the module, with a stand-in dig on PATH."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.bin = Path(self.directory.name) / "bin"
        self.bin.mkdir()
        self.answer = Path(self.directory.name) / "answer"
        self.answer.write_text("", encoding="utf-8")

    def install_dig(self) -> None:
        dig = self.bin / "dig"
        dig.write_text(f"#!/bin/sh\n/bin/cat {self.answer}\n", encoding="utf-8")
        dig.chmod(dig.stat().st_mode | stat.S_IXUSR)

    def run_probe(self) -> tuple[bool, dict[str, object]]:
        with module_runner.environment(PATH=str(self.bin)):
            failed, document, _raw = module_runner.run_module(
                probe.main, {"action": "recursion", "name": "deb.debian.org", "tries": 1}
            )
        return failed, document

    def test_dig_missing_fails_and_names_the_package(self) -> None:
        failed, document = self.run_probe()
        self.assertTrue(failed)
        self.assertIn("bind9-dnsutils", str(document["msg"]))

    def test_an_empty_answer_fails(self) -> None:
        self.install_dig()
        failed, document = self.run_probe()
        self.assertTrue(failed)
        self.assertIn("recursion is not working", str(document["msg"]))

    def test_an_address_passes(self) -> None:
        self.install_dig()
        self.answer.write_text("192.0.2.7\n", encoding="utf-8")
        failed, _document = self.run_probe()
        self.assertFalse(failed)


class CertTest(unittest.TestCase):
    def runner(self, output: str) -> tuple[probe.Runner, list[list[str]]]:
        calls: list[list[str]] = []

        def run(argv: Sequence[str], data: str | None) -> tuple[int, str, str]:
            self.assertEqual("", data)
            calls.append(list(argv))
            return 0, output, ""

        return run, calls

    def test_a_verified_certificate_for_the_name_is_ok(self) -> None:
        run, calls = self.runner("subject=CN=mx1.example.invalid\nVerify return code: 0 (ok)\n")
        answer = probe.shim_cert(run, "openssl", "127.0.0.1", 8443, "mx1.example.invalid")
        self.assertTrue(answer["ok"])
        self.assertEqual(1, len(calls))
        self.assertEqual(
            [
                "openssl",
                "s_client",
                "-connect",
                "127.0.0.1:8443",
                "-servername",
                "mx1.example.invalid",
            ],
            calls[0],
        )

    def test_anything_else_is_a_warning_and_never_a_failure(self) -> None:
        for output in (
            "",
            "Verify return code: 18 (self signed)",
            "CN=other\nVerify return code: 0",
        ):
            with self.subTest(output=output[:12]):
                run, _calls = self.runner(output)
                answer = probe.shim_cert(run, "openssl", "127.0.0.1", 443, "mx1.example.invalid")
                self.assertFalse(answer["ok"])
                self.assertIn("443", str(answer["warning"]))

    def test_a_missing_openssl_is_a_warning(self) -> None:
        run, calls = self.runner("")
        answer = probe.shim_cert(run, None, "127.0.0.1", 443, "mx1.example.invalid")
        self.assertFalse(answer["ok"])
        self.assertEqual([], calls)


class CheckconfTest(unittest.TestCase):
    def test_acceptance_and_rejection(self) -> None:
        def accept(argv: Sequence[str], data: str | None) -> tuple[int, str, str]:
            del data
            self.assertEqual(["unbound-checkconf"], list(argv))
            return 0, "unbound-checkconf: no errors in /etc/unbound/unbound.conf\n", ""

        self.assertTrue(probe.unbound_checkconf(accept, "unbound-checkconf")["ok"])

        def reject(argv: Sequence[str], data: str | None) -> tuple[int, str, str]:
            del argv, data
            return 1, "", "x.conf:3: error: unknown option\n" + "padding " * 200

        with self.assertRaises(probe.ProbeError) as caught:
            probe.unbound_checkconf(reject, "unbound-checkconf")
        self.assertIn("unknown option", str(caught.exception))
        self.assertLess(len(str(caught.exception)), 600)


class Port53Test(unittest.TestCase):
    HEADER = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
        "   uid  timeout inode\n"
    )

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "net").mkdir()
        self.rows: dict[str, list[str]] = {"tcp": [], "udp": [], "tcp6": [], "udp6": []}

    def row(self, table: str, address: str, port: int, state: str, inode: int) -> None:
        self.rows[table].append(
            f"   0: {address}:{port:04X} 00000000:0000 {state} 00000000:00000000 00:00000000"
            f" 00000000     0        0 {inode} 1 0000000000000000 100 0 0 10 0\n"
        )

    def process(self, pid: int, comm: str, inode: int) -> None:
        directory = self.root / str(pid)
        (directory / "fd").mkdir(parents=True)
        (directory / "comm").write_text(comm + "\n", encoding="utf-8")
        (directory / "fd" / "3").symlink_to(f"socket:[{inode}]")

    def read(self) -> dict[str, object]:
        for table, rows in self.rows.items():
            (self.root / "net" / table).write_text(self.HEADER + "".join(rows), encoding="utf-8")
        return probe.port53(str(self.root))

    def test_nothing_on_port_53_is_ok(self) -> None:
        answer = self.read()
        self.assertTrue(answer["ok"])
        self.assertEqual([], answer["holders"])

    def test_unbound_on_loopback_over_both_protocols_is_ok(self) -> None:
        self.row("udp", "0100007F", 53, "07", 101)
        self.row("tcp", "0100007F", 53, "0A", 102)
        self.row("udp6", "00000000000000000000000001000000", 53, "07", 103)
        self.process(10, "unbound", 101)
        self.process(11, "unbound", 102)
        self.process(12, "unbound", 103)
        answer = self.read()
        self.assertTrue(answer["ok"])
        holders = cast(list[dict[str, str]], answer["holders"])
        self.assertEqual(3, len(holders))
        self.assertIn("::1", [holder["address"] for holder in holders])

    def test_the_system_stub_resolver_is_allowed_whoever_holds_it(self) -> None:
        self.row("udp", "3500007F", 53, "07", 201)
        self.process(20, "systemd-resolve", 201)
        self.assertTrue(self.read()["ok"])

    def test_another_program_on_the_port_is_a_conflict(self) -> None:
        self.row("udp", "00000000", 53, "07", 301)
        self.process(30, "dnsmasq", 301)
        answer = self.read()
        self.assertFalse(answer["ok"])
        self.assertEqual("dnsmasq", answer["conflicts"][0]["holder"])  # type: ignore[index]

    def test_a_holder_that_cannot_be_found_is_a_conflict(self) -> None:
        self.row("tcp", "0100007F", 53, "0A", 401)
        answer = self.read()
        self.assertFalse(answer["ok"])
        self.assertEqual("unknown", answer["conflicts"][0]["holder"])  # type: ignore[index]

    def test_other_ports_and_connected_sockets_are_ignored(self) -> None:
        self.row("udp", "0100007F", 5353, "07", 501)
        self.row("tcp", "0100007F", 53, "01", 502)
        self.process(50, "dnsmasq", 501)
        self.process(51, "dnsmasq", 502)
        self.assertTrue(self.read()["ok"])

    def test_the_module_reads_a_fixture_tree_through_proc_root(self) -> None:
        self.row("udp", "00000000", 53, "07", 601)
        self.process(60, "dnsmasq", 601)
        for table, rows in self.rows.items():
            (self.root / "net" / table).write_text(self.HEADER + "".join(rows), encoding="utf-8")
        failed, document, _raw = module_runner.run_module(
            probe.main, {"action": "port53", "proc_root": str(self.root)}, check_mode=True
        )
        self.assertFalse(failed)
        self.assertFalse(document["ok"])

    def test_a_bad_address_is_refused(self) -> None:
        with self.assertRaises(probe.ProbeError):
            probe.decode_address("zz")
        with self.assertRaises(probe.ProbeError):
            probe.decode_address("0100")


class DispatchTest(unittest.TestCase):
    def find_nothing(self, _name: str) -> str | None:
        return None

    def params(self, **more: object) -> Mapping[str, object]:
        return {"tries": 1, "interval": 2, **more}

    def test_a_missing_dig_is_refused_naming_its_package(self) -> None:
        with self.assertRaises(probe.ProbeError) as caught:
            probe.dispatch(
                self.params(action="recursion", name="deb.debian.org"),
                Fake().run,
                self.find_nothing,
                no_sleep,
            )
        self.assertIn("bind9-dnsutils", str(caught.exception))

    def test_a_missing_docker_or_checkconf_is_refused(self) -> None:
        for action in ("docker_health", "container_fresh", "unbound_checkconf"):
            with self.subTest(action), self.assertRaises(probe.ProbeError):
                probe.dispatch(
                    self.params(action=action, containers=[], inputs=[]),
                    Fake().run,
                    self.find_nothing,
                    no_sleep,
                )

    def test_every_action_the_module_offers_is_dispatched(self) -> None:
        self.assertEqual(
            {
                "recursion",
                "shim_cert",
                "docker_health",
                "container_fresh",
                "unbound_checkconf",
                "port53",
            },
            set(probe.ACTIONS),
        )


if __name__ == "__main__":
    unittest.main()
