#!/usr/bin/env python3
"""Tests for probe-edget-gateway: a model of a gateway host (edge-t or edge1) under the script, plus copies of it with a check broken.

A check that cannot fail is not a check, so MutationTests breaks the script and expects red.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import re
import socket
import sys
import threading
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SCRIPT = HERE / "probe-edget-gateway.py"


def load(source: str, name: str = "probe_edget_gateway"):
    spec = importlib.util.spec_from_loader(name, loader=None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(source, str(SCRIPT), "exec"), module.__dict__)  # noqa: S102 - the script under test
    return module


SOURCE = SCRIPT.read_text(encoding="utf-8")
probe = load(SOURCE)

UPLINK = "eth0"
TARGET = "9.9.9.9:53"
SUBNET = "10.20.1.0/24"


# What each gateway host looks like to the probe: its public address (a documentation
# address) and its private address from the register.
HOSTS = {
    "edge-t": ["203.0.113.10", "10.20.1.210"],
    "edge1": ["203.0.113.11", "10.20.1.10"],
}


class FakeGateway:
    """A gateway host as the probe sees it (edge-t unless named). Knobs are attributes; `calls` records every command."""

    def __init__(self, module, host="edge-t"):
        self.m = module
        self.calls: list[list[str]] = []
        self.hostname = host
        self.addresses = list(HOSTS[host])
        self.default_routes = [{"dst": "default", "gateway": "172.31.1.1", "dev": UPLINK}]
        self.forward = "1"
        self.unit_enabled = "enabled"
        self.unit_active = "active"
        self.docker_user = True
        self.docker_active = True
        self.missing_tools: set[str] = set()
        self.root = True
        # The three rules, as counters. None is "not there".
        self.masq: int | None = 0
        self.out: int | None = 0
        self.ret: int | None = 0
        self.duplicate_masq = False
        self.netns: set[str] = set()
        self.links: dict[str, int] = {}
        # What the world does.
        self.launder_outside = False  # the outside source gets answered
        self.garbage_probe = False  # the in-namespace probe prints nonsense
        self.reply_without_masq = False  # a reply even though the masquerade is gone
        self.busy = False  # another source keeps moving the counters
        self.veth_silent = False  # the veth never receives anything
        self.fail_link_add = False
        self.netns_del_fails = False
        self.delete_does_not_take = False
        self.restart_works = True
        self.raise_on_probe: BaseException | None = None
        self.raise_on_probe_after_delete: BaseException | None = None
        self.probes: list[tuple[str, str]] = []

    # -- plumbing seams -------------------------------------------------------
    def install(self, stack: contextlib.ExitStack):
        stack.enter_context(mock.patch.object(self.m, "run", self.handle))
        stack.enter_context(mock.patch.object(self.m, "which", self.which))
        stack.enter_context(mock.patch.object(self.m, "is_root", lambda: self.root))
        stack.enter_context(mock.patch.object(self.m, "sleep", self.sleep))
        stack.enter_context(mock.patch.object(self.m.signal, "signal", lambda *a: None))

    def which(self, tool):
        return None if tool in self.missing_tools else f"/usr/sbin/{tool}"

    def sleep(self, _seconds):
        if self.busy and self.masq is not None:
            self.masq += 1

    # -- the model ------------------------------------------------------------
    def rules_present(self):
        return self.masq is not None and self.out is not None and self.ret is not None

    def source_of(self, ns):
        for source in (self.m.INSIDE, self.m.OUTSIDE):
            if source.netns == ns:
                return source
        raise AssertionError(f"probe in unknown namespace {ns}")

    def probe_in(self, ns):
        source = self.source_of(ns)
        self.probes.append((source.key, "after-delete" if self.masq is None else "normal"))
        if self.raise_on_probe is not None:
            raise self.raise_on_probe
        if self.raise_on_probe_after_delete is not None and self.masq is None:
            raise self.raise_on_probe_after_delete
        if not self.veth_silent and source.host_if in self.links:
            self.links[source.host_if] += 3
        if self.garbage_probe:
            return 0, "Traceback: something else\n", ""
        inside = source.key == "inside"
        if not inside:
            if self.launder_outside:
                return 0, "REPLY connected\n", ""
            return 0, "NOREPLY timeout\n", ""
        replies = (
            self.forward == "1"
            and self.out is not None
            and self.ret is not None
            and (self.masq is not None or self.reply_without_masq)
        )
        if self.out is not None and self.forward == "1":
            self.out += 3
        if replies:
            if self.masq is not None:
                self.masq += 1
            self.ret += 2
            return 0, "REPLY connected\n", ""
        return 0, "NOREPLY timeout\n", ""

    def iptables_listing(self, table, chain):
        header = (
            f"Chain {chain} (policy ACCEPT 0 packets, 0 bytes)\n"
            "    pkts      bytes target     prot opt in     out     source               destination         \n"
        )
        rows = []
        if table == "nat" and chain == "POSTROUTING":
            rows.append("       4      240 MASQUERADE  all  --  *      !docker0  172.17.0.0/16        0.0.0.0/0")
            if self.masq is not None:
                row = f"{self.masq:8d} {self.masq * 60:8d} MASQUERADE  all  --  *      {UPLINK}    {SUBNET}         0.0.0.0/0"
                rows.append(row)
                if self.duplicate_masq:
                    rows.append(row)
        elif table == "filter" and chain in ("DOCKER-USER", "FORWARD"):
            if self.ret is not None:
                rows.append(
                    f"{self.ret:8d} {self.ret * 60:8d} ACCEPT     all  --  {UPLINK}   *       0.0.0.0/0            {SUBNET}"
                    "         ctstate RELATED,ESTABLISHED"
                )
            if self.out is not None:
                rows.append(
                    f"{self.out:8d} {self.out * 60:8d} ACCEPT     all  --  *      {UPLINK}    {SUBNET}         0.0.0.0/0"
                )
            rows.append("      90     5400 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0")
        return header + "\n".join(rows) + "\n"

    def handle(self, argv, timeout=30):
        self.calls.append(list(argv))
        a = argv
        if a[0] == "hostname":
            return 0, self.hostname + "\n", ""
        if a[:3] == ["ip", "-j", "-4"] and a[3] == "addr":
            info = [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": x, "prefixlen": 32} for x in self.addresses]}]
            return 0, json.dumps(info), ""
        if a[:3] == ["ip", "-j", "-4"] and a[3] == "route":
            return 0, json.dumps(self.default_routes), ""
        if a[:4] == ["ip", "-j", "-s", "link"]:
            if a[-1] not in self.links:
                return 1, "", f'Device "{a[-1]}" does not exist.'
            return 0, json.dumps([{"ifname": a[-1], "stats64": {"rx": {"packets": self.links[a[-1]]}}}]), ""
        if a[:3] == ["ip", "netns", "list"]:
            return 0, "".join(f"{n} (id: 0)\n" for n in sorted(self.netns)), ""
        if a[:3] == ["ip", "netns", "add"]:
            self.netns.add(a[3])
            return 0, "", ""
        if a[:3] == ["ip", "netns", "del"]:
            if self.netns_del_fails:
                return 1, "", "Device or resource busy"
            self.netns.discard(a[3])
            return 0, "", ""
        if a[:3] == ["ip", "netns", "exec"]:
            return self.probe_in(a[3])
        if a[:3] == ["ip", "link", "add"]:
            if self.fail_link_add:
                return 2, "", "RTNETLINK answers: Operation not permitted"
            self.links[a[3]] = 0
            return 0, "", ""
        if a[:3] == ["ip", "link", "del"]:
            self.links.pop(a[3], None)
            return 0, "", ""
        if a[:3] == ["ip", "link", "show"]:
            return (0, "", "") if a[-1] in self.links else (1, "", "does not exist")
        if a[:2] == ["ip", "-n"]:
            return 0, "", ""
        if a[0] == "ip":
            return 0, "", ""
        if a[0] == "sysctl" and a[1:] == ["-n", "net.ipv4.ip_forward"]:
            return 0, self.forward + "\n", ""
        if a[0] == "systemctl":
            if a[1] == "is-enabled":
                return (0 if self.unit_enabled == "enabled" else 1), self.unit_enabled + "\n", ""
            if a[1] == "is-active" and a[2] == "docker.service":
                return (0 if self.docker_active else 3), ("active" if self.docker_active else "inactive") + "\n", ""
            if a[1] == "is-active":
                return (0 if self.unit_active == "active" else 3), self.unit_active + "\n", ""
            if a[1] == "restart":
                if self.restart_works:
                    self.masq = 0 if self.masq is None else self.masq
                    self.duplicate_masq = False
                return 0, "", ""
        if a[0] == "iptables":
            rest = a[1:]
            if rest[0] == "-w":
                rest = rest[1:]
            if rest[:2] == ["-t", "filter"] and rest[2:4] == ["-S", "DOCKER-USER"]:
                return (0 if self.docker_user else 1), "", ""
            if "-vxnL" in rest:
                return 0, self.iptables_listing(rest[1], rest[-1]), ""
            masq_spec = ["-t", "nat", None, "POSTROUTING", "-s", SUBNET, "-o", UPLINK, "-j", "MASQUERADE"]
            if rest[:2] == masq_spec[:2] and rest[3:] == masq_spec[3:] and rest[2] in ("-C", "-D"):
                if rest[2] == "-C":
                    return (0 if self.masq is not None else 1), "", ""
                if self.masq is None:
                    return 1, "", "Bad rule (does a matching rule exist in that chain?)."
                if not self.delete_does_not_take:
                    self.masq = None
                return 0, "", ""
        raise AssertionError(f"the fake edge-t was asked for something unmodelled: {a}")

    # -- running the script ---------------------------------------------------
    def run_main(self, module, argv):
        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            self.install(stack)
            stack.enter_context(contextlib.redirect_stdout(out))
            code = module.main(argv)
        return code, out.getvalue()

    def mutations(self):
        """Every command that is not a pure read."""
        found = []
        for a in self.calls:
            if a[0] == "iptables" and any(f in a for f in ("-D", "-I", "-A", "-F", "-P", "-N", "-X", "-R")):
                found.append(a)
            elif a[0] == "systemctl" and a[1] not in ("is-enabled", "is-active"):
                found.append(a)
            elif a[0] == "sysctl" and "-w" in a:
                found.append(a)
        return found

    def route_writes_outside_a_namespace(self):
        found = []
        for a in self.calls:
            if a[0] == "ip" and "route" in a and any(v in a for v in ("add", "del", "replace", "change", "append", "flush")):
                if a[1] != "-n":
                    found.append(a)
        return found


def verdicts(output):
    return [line for line in output.splitlines() if line.startswith(("GREEN ", "RED "))]


# ---------------------------------------------------------------------------- scenarios
# Each takes a module and raises AssertionError when the script misbehaves. The test
# cases call them with the real script; MutationTests call them with a broken copy.


def scenario_all_green(module, name="edge-t"):
    host = FakeGateway(module, name)
    code, out = host.run_main(module, ["gateway"])
    assert code == 0, (code, out)
    lines = verdicts(out)
    assert len(lines) == 2, out
    assert lines[0].startswith("GREEN inside-subnet-egress-via-masquerade"), out
    assert lines[1].startswith("GREEN outside-subnet-no-reply"), out
    assert out.strip().splitlines()[-1] == "RESULT PASS", out
    assert f" on {name}, uplink {UPLINK}," in out.splitlines()[0], out
    assert host.netns == set() and host.links == {}, "the namespaces and veths were not removed"
    return host, out


def wrong_host_cases(name):
    """(hostname, addresses) a host named `name` must be refused with."""
    other = "edge1" if name == "edge-t" else "edge-t"
    own, theirs = HOSTS[name], HOSTS[other]
    return (
        (other, own),  # the other host's name on this host's addresses
        ("edge2", own),  # a name with no profile, this host's addresses
        ("edge2", theirs),  # a name with no profile, the other host's addresses
        ("", own),  # no name at all
        (name, [own[0]]),  # right name, its private address missing
        (name, [own[0], theirs[1]]),  # right name, only the other host's private address
        (name, own + [theirs[1]]),  # right name and address, and the other host's address too
    )


def scenario_wrong_host_is_refused(module):
    for name in HOSTS:
        for hostname, addresses in wrong_host_cases(name):
            host = FakeGateway(module, name)
            host.hostname, host.addresses = hostname, list(addresses)
            code, out = host.run_main(module, ["gateway"])
            assert code == 2, (name, hostname, addresses, code, out)
            assert "REFUSED" in out, out
            assert not [c for c in host.calls if c[:3] == ["ip", "netns", "add"]], "it built a lab on the wrong host"
            assert not verdicts(out), out


def scenario_sabotage_is_refused_on_edge1(module):
    host = FakeGateway(module, "edge1")
    code, out = host.run_main(module, ["gateway", "--sabotage"])
    assert code == 2, (code, out)
    assert "REFUSED: --sabotage is refused on edge1" in out, out
    assert not verdicts(out), out
    assert not [c for c in host.calls if c[:3] == ["ip", "netns", "add"]], "it built a lab before refusing"
    assert host.mutations() == [], host.mutations()
    assert host.masq is not None


def scenario_masquerade_counter_must_rise(module):
    host = FakeGateway(module)

    original = host.probe_in

    def reply_without_counting(ns):
        before = host.masq
        result = original(ns)
        host.masq = before
        return result

    host.probe_in = reply_without_counting
    code, out = host.run_main(module, ["gateway"])
    assert code == 1, out
    assert verdicts(out)[0].startswith("RED inside-subnet-egress-via-masquerade"), out
    assert "MASQUERADE" in verdicts(out)[0] and "did not rise" in verdicts(out)[0], out


def scenario_outside_reply_is_red(module):
    host = FakeGateway(module)
    host.launder_outside = True
    code, out = host.run_main(module, ["gateway"])
    assert code == 1, out
    outside = verdicts(out)[1]
    assert outside.startswith("RED outside-subnet-no-reply"), out
    assert "GOT A REPLY" in outside, out


def scenario_garbage_probe_is_not_silence(module):
    """Output that is neither a reply nor a clean timeout must not read as 'no reply'."""
    host = FakeGateway(module)
    original = host.probe_in

    def garbage_for_outside(ns):
        if host.source_of(ns).key == "outside":
            host.links[host.source_of(ns).host_if] += 3
            return 0, "Traceback: nonsense\n", ""
        return original(ns)

    host.probe_in = garbage_for_outside
    code, out = host.run_main(module, ["gateway"])
    assert code == 1, out
    assert verdicts(out)[1].startswith("RED outside-subnet-no-reply"), out
    assert "unexpected probe result" in verdicts(out)[1], out


def scenario_silent_veth_is_not_a_clean_control(module):
    host = FakeGateway(module)
    host.veth_silent = True
    code, out = host.run_main(module, ["gateway"])
    assert code == 1, out
    assert verdicts(out)[1].startswith("RED outside-subnet-no-reply"), out
    assert "received no packets" in verdicts(out)[1], out


def scenario_outside_needs_the_inside_positive(module):
    host = FakeGateway(module)
    host.masq = None
    code, out = host.run_main(module, ["gateway"])
    assert code == 1, out
    lines = verdicts(out)
    assert lines[0].startswith("RED inside-subnet-egress-via-masquerade"), out
    assert lines[1].startswith("RED outside-subnet-no-reply") and "not established" in lines[1], out


def scenario_cleanup_on_interrupt(module):
    for exc in (KeyboardInterrupt(), SystemExit(143), RuntimeError("boom")):
        host = FakeGateway(module)
        host.raise_on_probe = exc
        try:
            host.run_main(module, ["gateway"])
        except BaseException as caught:  # noqa: BLE001 - the point is what it leaves behind
            assert caught is exc, caught
        else:
            raise AssertionError("the interruption was swallowed")
        assert host.netns == set() and host.links == {}, f"{exc!r} left a namespace or veth behind"


def scenario_sabotage_red_then_green(module):
    host = FakeGateway(module)
    code, out = host.run_main(module, ["gateway", "--sabotage"])
    assert code == 0, out
    lines = verdicts(out)
    assert [line.split(" ")[0] for line in lines] == ["GREEN", "GREEN", "RED", "GREEN"], out
    assert "[masquerade rule deleted]" in lines[2] and "MASQUERADE rule" in lines[2], out
    assert "restored by restarting branchleft-nat.service" in lines[3], out
    assert "RECORD red-then-green" in out, out
    assert host.masq is not None, "the masquerade was left deleted"
    deletes = [i for i, c in enumerate(host.calls) if c[0] == "iptables" and "-D" in c]
    restarts = [i for i, c in enumerate(host.calls) if c[:2] == ["systemctl", "restart"]]
    assert len(deletes) == 1 and len(restarts) == 1 and deletes[0] < restarts[0], host.calls
    assert host.calls[restarts[0]] == ["systemctl", "restart", "branchleft-nat.service"], host.calls[restarts[0]]
    assert host.netns == set() and host.links == {}
    return host, out


def scenario_nothing_is_deleted_without_the_flag(module):
    host = FakeGateway(module)
    code, out = host.run_main(module, ["gateway"])
    assert code == 0, out
    assert host.mutations() == [], host.mutations()
    assert host.route_writes_outside_a_namespace() == []
    assert host.masq is not None


def scenario_restore_on_any_exit_after_delete(module):
    for exc in (KeyboardInterrupt(), SystemExit(143), RuntimeError("boom")):
        host = FakeGateway(module)
        host.raise_on_probe_after_delete = exc
        try:
            host.run_main(module, ["gateway", "--sabotage"])
        except BaseException as caught:  # noqa: BLE001
            assert caught is exc, caught
        else:
            raise AssertionError("the interruption was swallowed")
        assert host.masq is not None, f"{exc!r} left the masquerade deleted"
        assert any(c[:2] == ["systemctl", "restart"] for c in host.calls), "no restart on the way out"
        assert host.netns == set() and host.links == {}


def scenario_sabotage_refuses_on_a_red_baseline(module):
    host = FakeGateway(module)
    host.out = None
    code, out = host.run_main(module, ["gateway", "--sabotage"])
    assert code == 1, out
    assert not [c for c in host.calls if c[0] == "iptables" and "-D" in c], "it deleted a rule on a red baseline"
    assert "proves nothing" in out, out


def scenario_failed_restore_is_loud(module):
    host = FakeGateway(module)
    host.restart_works = False
    code, out = host.run_main(module, ["gateway", "--sabotage"])
    assert code == 3, (code, out)
    assert "RESTORE FAILED" in out and "systemctl restart branchleft-nat.service" in out, out
    assert "RESULT PASS" not in out, out


def scenario_unreadable_unit_state_after_restore_is_loud(module):
    """If `systemctl is-active` itself times out during the restore, say so and exit 3, not 2."""
    host = FakeGateway(module)
    original = host.handle

    def is_active_times_out(argv, timeout=30):
        if argv[:2] == ["systemctl", "is-active"] and argv[2] == module.UNIT and host.restarted:
            raise module.Refused("systemctl is-active branchleft-nat.service did not finish in 30s")
        result = original(argv, timeout)
        if argv[:2] == ["systemctl", "restart"]:
            host.restarted = True
        return result

    host.restarted = False
    host.handle = is_active_times_out
    code, out = host.run_main(module, ["gateway", "--sabotage"])
    assert code == 3, (code, out)
    assert "RESTORE FAILED" in out and "systemctl restart branchleft-nat.service" in out, out


def scenario_proof_that_cannot_go_red_fails(module):
    host = FakeGateway(module)
    host.reply_without_masq = True
    code, out = host.run_main(module, ["gateway", "--sabotage"])
    assert code == 1, (code, out)
    assert "RESULT PASS" not in out, out
    assert host.masq is not None, "restored anyway"


class GatewayTests(unittest.TestCase):
    def test_every_control_green_on_a_healthy_gateway(self):
        host, out = scenario_all_green(probe)
        self.assertIn("MASQUERADE 0->1", out)
        self.assertIn("DOCKER-USER out 0->3", out)
        self.assertIn("DOCKER-USER return 0->2", out)

    def test_read_only_by_default_and_never_the_default_route(self):
        scenario_nothing_is_deleted_without_the_flag(probe)

    def test_the_namespace_routes_are_set_inside_the_namespace_only(self):
        host, _ = scenario_all_green(probe)
        routes = [c for c in host.calls if "route" in c and "add" in c]
        self.assertEqual(len(routes), 2)
        for call in routes:
            self.assertEqual(call[:2], ["ip", "-n"], call)
            self.assertEqual(call[3:6], ["route", "add", "default"], call)

    def test_a_host_that_is_not_edge_t_is_refused_before_anything_is_built(self):
        scenario_wrong_host_is_refused(probe)

    def test_each_missing_prerequisite_is_a_refusal_not_a_pass(self):
        cases = {
            "root": lambda h: setattr(h, "root", False),
            "a tool": lambda h: h.missing_tools.add("iptables"),
            "ip": lambda h: h.missing_tools.add("ip"),
            "systemctl": lambda h: h.missing_tools.add("systemctl"),
            "two default routes": lambda h: h.default_routes.append(dict(h.default_routes[0], metric=200)),
            "no default route": lambda h: setattr(h, "default_routes", []),
            "docker without DOCKER-USER": lambda h: setattr(h, "docker_user", False),
            "duplicate masquerade": lambda h: setattr(h, "duplicate_masq", True),
        }
        for name, bend in cases.items():
            with self.subTest(name):
                host = FakeGateway(probe)
                bend(host)
                code, out = host.run_main(probe, ["gateway"])
                self.assertEqual(code, 2, out)
                self.assertIn("REFUSED", out)
                self.assertNotIn("GREEN", out)
                self.assertEqual(host.netns, set())

    def test_no_docker_falls_back_to_forward_like_the_reconciler(self):
        host = FakeGateway(probe)
        host.docker_user = False
        host.docker_active = False
        code, out = host.run_main(probe, ["gateway"])
        self.assertEqual(code, 0, out)
        self.assertIn("forwarding chain FORWARD", out)
        self.assertIn("FORWARD out 0->3", out)

    def test_malformed_target_and_unparseable_reads_are_refusals(self):
        for argv in (["gateway", "--target", "example.com:53"], ["gateway", "--target", "9.9.9.9"], ["gateway", "--target", "9.9.9.9:0"]):
            host = FakeGateway(probe)
            code, out = host.run_main(probe, argv)
            self.assertEqual(code, 2, (argv, out))
        host = FakeGateway(probe)
        host.iptables_listing = lambda table, chain: "Chain x (policy ACCEPT)\n"
        code, out = host.run_main(probe, ["gateway"])
        self.assertEqual(code, 2, out)
        self.assertIn("no pkts/bytes header", out)

    def test_each_missing_rule_or_state_is_red_and_names_it(self):
        cases = {
            "the nat/POSTROUTING MASQUERADE": lambda h: setattr(h, "masq", None),
            "the DOCKER-USER accept for 10.20.1.0/24 out": lambda h: setattr(h, "out", None),
            "the DOCKER-USER return accept": lambda h: setattr(h, "ret", None),
            "net.ipv4.ip_forward is 0": lambda h: setattr(h, "forward", "0"),
            "is disabled, not enabled": lambda h: setattr(h, "unit_enabled", "disabled"),
            "is inactive, not active": lambda h: setattr(h, "unit_active", "inactive"),
        }
        for needle, bend in cases.items():
            with self.subTest(needle):
                host = FakeGateway(probe)
                bend(host)
                code, out = host.run_main(probe, ["gateway"])
                self.assertEqual(code, 1, out)
                self.assertTrue(verdicts(out)[0].startswith("RED inside-subnet-egress-via-masquerade"), out)
                self.assertIn(needle, verdicts(out)[0])
                self.assertTrue(verdicts(out)[1].startswith("RED outside-subnet-no-reply"), out)

    def test_the_inside_probe_needs_the_masquerade_counter_to_rise(self):
        scenario_masquerade_counter_must_rise(probe)

    def test_a_reply_to_the_outside_source_is_red(self):
        scenario_outside_reply_is_red(probe)

    def test_the_outside_control_needs_the_veth_to_have_carried_packets(self):
        scenario_silent_veth_is_not_a_clean_control(probe)

    def test_the_outside_control_needs_the_inside_positive(self):
        scenario_outside_needs_the_inside_positive(probe)

    def test_probe_output_that_is_not_a_clean_timeout_is_not_silence(self):
        scenario_garbage_probe_is_not_silence(probe)

    def test_a_counter_that_moves_during_the_outside_probe_is_red(self):
        host = FakeGateway(probe)
        original = host.probe_in

        def moves_the_out_counter(ns):
            result = original(ns)
            if host.source_of(ns).key == "outside":
                host.out += 1
            return result

        host.probe_in = moves_the_out_counter
        code, out = host.run_main(probe, ["gateway"])
        self.assertEqual(code, 1, out)
        self.assertIn("counter moved by 1", verdicts(out)[1])

    def test_a_gateway_that_never_goes_quiet_is_a_refusal(self):
        host = FakeGateway(probe)
        with contextlib.ExitStack() as stack:
            host.install(stack)
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            original = host.probe_in

            def go_busy_after_inside(ns):
                result = original(ns)
                host.busy = True
                return result

            host.probe_in = go_busy_after_inside
            code = probe.main(["gateway"])
        self.assertEqual(code, 2)

    def test_the_lab_is_removed_on_every_exit(self):
        scenario_cleanup_on_interrupt(probe)

    def test_a_failure_building_the_lab_removes_what_was_built(self):
        host = FakeGateway(probe)
        host.fail_link_add = True
        code, out = host.run_main(probe, ["gateway"])
        self.assertEqual(code, 2, out)
        self.assertEqual(host.netns, set())

    def test_a_leftover_lab_from_a_killed_run_is_cleared_first(self):
        host = FakeGateway(probe)
        host.netns.add(probe.INSIDE.netns)
        host.links[probe.INSIDE.host_if] = 0
        code, out = host.run_main(probe, ["gateway"])
        self.assertEqual(code, 0, out)

    def test_a_lab_that_cannot_be_removed_is_loud_and_never_a_pass(self):
        host = FakeGateway(probe)
        code, out = 0, ""
        host.netns_del_fails = True
        code, out = host.run_main(probe, ["gateway"])
        self.assertNotEqual(code, 0, out)
        self.assertNotIn("RESULT PASS", out)

    def test_two_runs_do_not_disturb_each_other_or_the_register(self):
        host = FakeGateway(probe)
        for _ in range(2):
            code, out = host.run_main(probe, ["gateway"])
            self.assertEqual(code, 0, out)


class SabotageTests(unittest.TestCase):
    def test_red_then_green_with_the_restore_by_unit_restart(self):
        scenario_sabotage_red_then_green(probe)

    def test_the_restore_runs_on_any_exit_after_the_delete(self):
        scenario_restore_on_any_exit_after_delete(probe)

    def test_it_refuses_to_delete_anything_on_a_red_baseline(self):
        scenario_sabotage_refuses_on_a_red_baseline(probe)

    def test_a_restore_that_did_not_take_exits_3_and_names_the_command(self):
        scenario_failed_restore_is_loud(probe)

    def test_a_unit_state_that_cannot_be_read_after_the_restore_exits_3(self):
        scenario_unreadable_unit_state_after_restore_is_loud(probe)

    def test_a_probe_that_cannot_go_red_is_a_failure_not_a_pass(self):
        scenario_proof_that_cannot_go_red_fails(probe)

    def test_it_refuses_when_another_source_is_using_the_gateway(self):
        host = FakeGateway(probe)
        original = host.probe_in

        def go_busy_after_outside(ns):
            result = original(ns)
            if host.source_of(ns).key == "outside":
                host.busy = True
            return result

        host.probe_in = go_busy_after_outside
        code, out = host.run_main(probe, ["gateway", "--sabotage"])
        self.assertEqual(code, 2, out)
        self.assertFalse([c for c in host.calls if c[0] == "iptables" and "-D" in c])

    def test_a_delete_that_does_not_take_is_a_refusal_and_still_restores(self):
        host = FakeGateway(probe)
        host.delete_does_not_take = True
        code, out = host.run_main(probe, ["gateway", "--sabotage"])
        self.assertEqual(code, 2, out)
        self.assertIn("still present", out)
        self.assertTrue(any(c[:2] == ["systemctl", "restart"] for c in host.calls))

    def test_the_only_commands_that_write_are_the_delete_and_the_unit_restart(self):
        host, _ = scenario_sabotage_red_then_green(probe)
        self.assertEqual(
            [" ".join(c) for c in host.mutations()],
            [
                "iptables -w -t nat -D POSTROUTING -s 10.20.1.0/24 -o eth0 -j MASQUERADE",
                "systemctl restart branchleft-nat.service",
            ],
        )
        self.assertEqual(host.route_writes_outside_a_namespace(), [])

    def test_the_recovery_command_is_printed_before_the_delete(self):
        host, out = scenario_sabotage_red_then_green(probe)
        self.assertLess(out.index("if this process is killed"), out.index("RED inside-subnet"))
        self.assertIn("systemctl restart branchleft-nat.service", out)


class ProfileTests(unittest.TestCase):
    """Table-driven over the host profiles: each host gets the same proof and the same interlock."""

    def test_the_table_is_exactly_edge_t_and_edge1(self):
        self.assertEqual(set(probe.PROFILES), {"edge-t", "edge1"})
        self.assertEqual(set(probe.PROFILES), set(HOSTS))
        for key, profile in probe.PROFILES.items():
            self.assertEqual(key, profile.hostname)
            self.assertEqual(profile.private_address, HOSTS[key][1])

    def test_each_host_proves_green_and_names_itself_in_the_header(self):
        for name in HOSTS:
            with self.subTest(name):
                host, out = scenario_all_green(probe, name)
                self.assertIn("MASQUERADE 0->1", out)
                self.assertIn("DOCKER-USER out 0->3", out)
                self.assertIn("forwarding chain DOCKER-USER, target 9.9.9.9:53", out.splitlines()[0])

    def test_each_host_is_read_only_without_the_sabotage_flag(self):
        for name in HOSTS:
            with self.subTest(name):
                host = FakeGateway(probe, name)
                code, out = host.run_main(probe, ["gateway"])
                self.assertEqual(code, 0, out)
                self.assertEqual(host.mutations(), [])
                self.assertEqual(host.route_writes_outside_a_namespace(), [])
                self.assertIsNotNone(host.masq)

    def test_each_host_fails_red_and_refuses_the_same_way(self):
        for name in HOSTS:
            with self.subTest(name, case="missing masquerade"):
                host = FakeGateway(probe, name)
                host.masq = None
                code, out = host.run_main(probe, ["gateway"])
                self.assertEqual(code, 1, out)
                self.assertTrue(verdicts(out)[0].startswith("RED inside-subnet-egress-via-masquerade"), out)
            with self.subTest(name, case="two default routes"):
                host = FakeGateway(probe, name)
                host.default_routes.append(dict(host.default_routes[0], metric=200))
                code, out = host.run_main(probe, ["gateway"])
                self.assertEqual(code, 2, out)
                self.assertEqual(host.netns, set())

    def test_a_host_that_matches_no_profile_or_the_wrong_one_is_refused_before_anything_is_built(self):
        scenario_wrong_host_is_refused(probe)

    def test_the_refusal_names_the_mismatch(self):
        host = FakeGateway(probe, "edge-t")
        host.hostname = "edge2"
        code, out = host.run_main(probe, ["gateway"])
        self.assertEqual(code, 2)
        self.assertIn("edge2, which has no profile", out)
        host = FakeGateway(probe, "edge1")
        host.addresses = ["203.0.113.11"]
        code, out = host.run_main(probe, ["gateway"])
        self.assertEqual(code, 2)
        self.assertIn("holds no 10.20.1.10, which is edge1's private address", out)
        host = FakeGateway(probe, "edge1")
        host.addresses = HOSTS["edge1"] + ["10.20.1.210"]
        code, out = host.run_main(probe, ["gateway"])
        self.assertEqual(code, 2)
        self.assertIn("holds 10.20.1.210, which is edge-t's address", out)

    def test_sabotage_is_refused_on_edge1_and_still_works_on_edge_t(self):
        scenario_sabotage_is_refused_on_edge1(probe)
        host, out = scenario_sabotage_red_then_green(probe)
        self.assertIn("RECORD red-then-green", out)
        self.assertFalse(probe.PROFILES["edge1"].sabotage_allowed)
        self.assertTrue(probe.PROFILES["edge-t"].sabotage_allowed)

    def test_there_is_no_flag_that_names_a_host_or_a_profile(self):
        parser = probe.build_parser()
        flags: set[str] = set()
        for action in parser._actions:
            flags.update(action.option_strings)
            if isinstance(getattr(action, "choices", None), dict):
                for sub in action.choices.values():
                    for inner in sub._actions:
                        flags.update(inner.option_strings)
        self.assertEqual(flags, {"-h", "--help", "--target", "--sabotage", "--expect"})
        for argv in (["gateway", "--host", "edge1"], ["gateway", "--hostname", "edge1"], ["gateway", "--profile", "edge1"]):
            with self.subTest(argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                probe.build_parser().parse_args(argv)


class SshProbeTests(unittest.TestCase):
    """The refusal probe, over real loopback sockets where a socket can say it and a stub where it cannot."""

    def run_ssh(self, argv, stub=None, ssh_port=None, reach_port=None):
        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(mock.patch.object(probe, "SSH_TIMEOUT", 0.5))
            if ssh_port:
                stack.enter_context(mock.patch.object(probe, "SSH_PORT", ssh_port))
            if reach_port:
                stack.enter_context(mock.patch.object(probe, "REACHABILITY_PORT", reach_port))
            if stub:
                stack.enter_context(mock.patch.object(probe, "tcp_connect", stub))
            code = probe.main(argv)
        return code, out.getvalue()

    @staticmethod
    def listener(banner: bytes | None):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        held = []

        def serve():
            try:
                while True:
                    conn, _ = server.accept()
                    held.append(conn)
                    if banner:
                        conn.sendall(banner)
            except OSError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        def close():
            server.close()
            for conn in held:
                conn.close()

        return server.getsockname()[1], close

    @staticmethod
    def closed_port():
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def test_accepted_is_green_only_when_an_ssh_banner_comes_back(self):
        port, close = self.listener(b"SSH-2.0-OpenSSH_10.0\r\n")
        self.addCleanup(close)
        code, out = self.run_ssh(["ssh", "--target", "127.0.0.1", "--expect", "accepted"], ssh_port=port)
        self.assertEqual(code, 0, out)
        self.assertTrue(out.startswith("GREEN ssh-to-edge-t-accepted-from-edge1"), out)
        self.assertIn("SSH-2.0-OpenSSH_10.0", out)

    def test_accepted_is_red_for_a_closed_port_a_silent_listener_and_a_non_ssh_banner(self):
        silent, close_silent = self.listener(None)
        self.addCleanup(close_silent)
        http, close_http = self.listener(b"HTTP/1.1 400 Bad Request\r\n")
        self.addCleanup(close_http)
        for name, port in (("closed", self.closed_port()), ("silent", silent), ("not ssh", http)):
            with self.subTest(name):
                code, out = self.run_ssh(["ssh", "--target", "127.0.0.1", "--expect", "accepted"], ssh_port=port)
                self.assertEqual(code, 1, out)
                self.assertTrue(out.startswith("RED ssh-to-edge-t-accepted-from-edge1"), out)

    @staticmethod
    def stub(states):
        def connect(host, port, timeout, want_banner):
            return states[port]

        return connect

    def test_refused_is_green_on_a_timeout_when_443_answers(self):
        for reach in (("refused", "an RST came back"), ("connected", "connected")):
            with self.subTest(reach):
                code, out = self.run_ssh(
                    ["ssh", "--target", "203.0.113.7", "--expect", "refused"],
                    stub=self.stub({22: ("timeout", "no answer"), 443: reach}),
                )
                self.assertEqual(code, 0, out)
                lines = verdicts(out)
                self.assertTrue(lines[0].startswith("GREEN edge-t-reachable-on-443"), out)
                self.assertTrue(lines[1].startswith("GREEN ssh-to-edge-t-refused-from-non-edge1"), out)

    def test_refused_is_red_when_443_is_silent_too_because_a_timeout_then_proves_nothing(self):
        code, out = self.run_ssh(
            ["ssh", "--target", "203.0.113.7", "--expect", "refused"],
            stub=self.stub({22: ("timeout", "no answer"), 443: ("timeout", "no answer")}),
        )
        self.assertEqual(code, 1, out)
        self.assertTrue(verdicts(out)[0].startswith("RED edge-t-reachable-on-443"), out)
        self.assertTrue(verdicts(out)[1].startswith("RED ssh-to-edge-t-refused-from-non-edge1"), out)

    def test_refused_is_red_when_ssh_answers_or_resets_or_errors(self):
        for state, needle in (
            (("ssh", "SSH-2.0-OpenSSH_10.0"), "SSH IS ACCEPTED"),
            (("refused", "rst"), "did not drop it"),
            (("error", "errno 101"), "not a clean timeout"),
            (("connected-no-banner", "x"), "not a clean timeout"),
        ):
            with self.subTest(state):
                code, out = self.run_ssh(
                    ["ssh", "--target", "203.0.113.7", "--expect", "refused"],
                    stub=self.stub({22: state, 443: ("refused", "rst")}),
                )
                self.assertEqual(code, 1, out)
                self.assertIn(needle, verdicts(out)[1])

    def test_a_name_is_refused_because_dns_would_hide_which_address_was_probed(self):
        code, out = self.run_ssh(["ssh", "--target", "edge-t.example", "--expect", "refused"])
        self.assertEqual(code, 2, out)
        self.assertIn("REFUSED", out)

    def test_refused_over_real_sockets_a_closed_ssh_port_is_not_a_timeout(self):
        code, out = self.run_ssh(
            ["ssh", "--target", "127.0.0.1", "--expect", "refused"],
            ssh_port=self.closed_port(),
            reach_port=self.closed_port(),
        )
        self.assertEqual(code, 1, out)
        self.assertIn("did not drop it", out)


class PinTests(unittest.TestCase):
    """The script runs on a host with no checkout, so its copies of the plan are pinned here."""

    plan = (ROOT / "hetzner-host" / "addressPlan.ts").read_text(encoding="utf-8")

    def constant(self, name):
        match = re.search(rf"export const {name}\s*=\s*'([^']+)'", self.plan)
        self.assertIsNotNone(match, name)
        return match.group(1)

    def entry(self, block, key):
        body = re.search(rf"export const {block}\s*=\s*\{{(.*?)\}}\s*as const", self.plan, re.S)
        self.assertIsNotNone(body, block)
        match = re.search(rf"\b{key}\s*:\s*'([^']+)'", body.group(1))
        self.assertIsNotNone(match, f"{block}.{key}")
        return match.group(1)

    def test_the_subnet_and_the_two_hosts_are_the_plans(self):
        self.assertEqual(probe.SUBNET, self.constant("SUBNET_CIDR"))
        self.assertEqual(probe.EDGET_PRIVATE, self.entry("TENANTS_HOST_IPS", "edgeT"))
        self.assertEqual(probe.EDGE1_PRIVATE, self.entry("HOST_IPS", "edge1"))

    def test_every_profile_is_the_plans_subnet_and_address(self):
        self.assertEqual(probe.PROFILES["edge-t"].private_address, self.entry("TENANTS_HOST_IPS", "edgeT"))
        self.assertEqual(probe.PROFILES["edge1"].private_address, self.entry("HOST_IPS", "edge1"))
        for profile in probe.PROFILES.values():
            self.assertEqual(profile.subnet, self.constant("SUBNET_CIDR"))

    def test_the_profiles_are_the_hosts_the_playbooks_make_gateways(self):
        playbooks = ROOT / "ansible" / "playbooks"
        gateways = {
            path.stem
            for path in playbooks.glob("*.yml")
            if re.search(r"^\s+egress_nat_gateway_enabled:\s*true\s*$", path.read_text(encoding="utf-8"), re.M)
        }
        names = {"edge1": "edge1", "edget": "edge-t"}  # playbook name -> the name `hostname` prints
        self.assertEqual(gateways, set(names), "a gateway playbook has no profile, or a profile has no gateway playbook")
        self.assertEqual({names[g] for g in gateways}, set(probe.PROFILES))

    def test_the_subnet_is_the_nat_reconcilers(self):
        nat = (HERE.parent / "provision" / "branchleft_nat.sh").read_text(encoding="utf-8")
        match = re.search(r'^SUBNET="\$\{BRANCHLEFT_NAT_SUBNET:-([^}]+)\}"$', nat, re.M)
        self.assertEqual(match.group(1), probe.SUBNET)

    def test_the_unit_is_the_one_the_role_installs(self):
        self.assertTrue((HERE.parent / "provision" / probe.UNIT).is_file())

    def test_the_lab_addresses_collide_with_no_registered_host_and_sit_on_the_right_side(self):
        import ipaddress

        registered = set(re.findall(r"'(10\.20\.\d+\.\d+)'", self.plan))
        subnet = ipaddress.ip_network(probe.SUBNET)
        for source in (probe.INSIDE, probe.OUTSIDE):
            self.assertNotIn(source.address, registered)
            self.assertNotIn(source.host_address, registered)
        for address in (probe.INSIDE.address, probe.INSIDE.host_address):
            self.assertIn(ipaddress.ip_address(address), subnet)
        for address in (probe.OUTSIDE.address, probe.OUTSIDE.host_address):
            self.assertNotIn(ipaddress.ip_address(address), subnet)
        self.assertTrue(ipaddress.ip_address(probe.OUTSIDE.address).is_private)  # RFC 5737, never routed

    def test_interface_names_fit_the_kernels_fifteen_characters(self):
        for source in (probe.INSIDE, probe.OUTSIDE):
            for name in (source.host_if, source.ns_if):
                self.assertLessEqual(len(name), 15, name)

    def test_the_default_target_is_a_public_ipv4_with_a_port(self):
        import ipaddress

        host, port = probe.split_target(probe.DEFAULT_TARGET)
        self.assertTrue(ipaddress.ip_address(host).is_global)
        self.assertEqual(port, 53)


class RunbookTests(unittest.TestCase):
    """Every command the runbook tells the owner to run must parse against the script."""

    runbook = ROOT / "hetzner" / "tenants" / "RUNBOOK-edget-gateway-proof.md"

    def commands(self):
        text = self.runbook.read_text(encoding="utf-8")
        blocks = re.findall(r"```bash\n(.*?)```", text, re.S)
        return [b for b in blocks if "probe-edget-gateway.py" in b]

    def test_the_runbook_runs_the_script_in_every_mode(self):
        joined = "\n".join(self.commands())
        for needle in ("gateway", "gateway --sabotage", "ssh --target", "--expect refused", "--expect accepted"):
            self.assertIn(needle, joined)

    def test_every_invocation_in_the_runbook_parses(self):
        parser = probe.build_parser()
        seen = 0
        for block in self.commands():
            joined = block.replace("\\\n", " ")
            for match in re.finditer(r"(?:python3 - |probe-edget-gateway\.py )((?:gateway|ssh)[^<\n]*?)\s*(?:<|$)", joined, re.M):
                words = match.group(1).replace('"', "").replace("${", "").replace("}", "").split()
                # Values threaded through variables are substituted before the parser sees them.
                words = ["203.0.113.7" if re.fullmatch(r"\$?[A-Z0-9_]+", w) else w for w in words]
                parser.parse_args(words)
                seen += 1
        self.assertEqual(seen, 5)

    def test_the_address_checks_fail_on_any_empty_or_malformed_value(self):
        import subprocess

        text = self.runbook.read_text(encoding="utf-8")
        checks = [b.strip() for b in re.findall(r"```bash\n(case \"\$\{EDGE[^`]*?)```", text, re.S)]
        self.assertEqual(len(checks), 2)
        good = {"EDGET_IPV4": "203.0.113.7", "EDGE1_IPV4": "198.51.100.9"}
        for check in checks:
            for bad in ("", "edge1.example", "1.2.3.4;x"):
                for name in good:
                    env = dict(good, **{name: bad})
                    done = subprocess.run(["bash", "-c", check], env=env, capture_output=True, text=True)
                    expected_fail = f"${{{name}}}" in check and bad != good[name]
                    self.assertEqual(done.returncode != 0, expected_fail, (check, name, bad))
            done = subprocess.run(["bash", "-c", check], env=good, capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, check)

    def test_the_sabotage_flag_appears_once_and_only_in_its_own_block(self):
        blocks = [b for b in self.commands() if "--sabotage" in b]
        self.assertEqual(len(blocks), 1)
        self.assertNotIn("--expect", blocks[0])


class Edge1RunbookTests(unittest.TestCase):
    """The edge1 runbook's one probe command parses against the script, and never carries the sabotage flag."""

    runbook = ROOT / "hetzner" / "RUNBOOK-edge1-gateway-proof.md"

    def blocks(self):
        return re.findall(r"```bash\n(.*?)```", self.runbook.read_text(encoding="utf-8"), re.S)

    def test_the_probe_command_parses_and_targets_edge1_only(self):
        runs = [b for b in self.blocks() if "probe-edget-gateway.py" in b]
        self.assertEqual(len(runs), 1)
        match = re.search(r"python3 - (gateway[^;\n]*)", runs[0])
        self.assertIsNotNone(match)
        args = probe.build_parser().parse_args(match.group(1).split())
        self.assertEqual(args.command, "gateway")
        self.assertFalse(args.sabotage)
        self.assertIn('root@"${EDGE1_IPV4}"', runs[0])
        self.assertNotIn("ProxyCommand", runs[0])
        self.assertNotIn("EDGET", runs[0])

    def test_the_sabotage_flag_is_never_in_a_command(self):
        for block in self.blocks():
            self.assertNotIn("--sabotage", block)

    def test_the_address_check_fails_on_any_empty_or_malformed_value(self):
        import subprocess

        checks = [b.strip() for b in self.blocks() if b.strip().startswith("case ")]
        self.assertEqual(len(checks), 1)
        for bad in ("", "edge1.example", "1.2.3.4;x"):
            done = subprocess.run(["bash", "-c", checks[0]], env={"EDGE1_IPV4": bad}, capture_output=True, text=True, check=False)
            self.assertNotEqual(done.returncode, 0, bad)
        done = subprocess.run(["bash", "-c", checks[0]], env={"EDGE1_IPV4": "198.51.100.9"}, capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0)

    def test_the_expected_output_is_what_the_script_prints(self):
        text = self.runbook.read_text(encoding="utf-8")
        _host, out = scenario_all_green(probe, "edge1")
        for line in verdicts(out):
            control = line.split(" ")[1]
            self.assertIn(f"GREEN {control} [live]", text)
        self.assertIn("on edge1, uplink", text)
        self.assertIn("RESULT PASS", text)


# ----------------------------------------------------------------------------- mutations


def broken(old: str, new: str) -> str:
    """The script with exactly one piece of one check replaced."""
    assert SOURCE.count(old) == 1, f"the broken copy needs {old!r} to appear exactly once"
    return SOURCE.replace(old, new)


MUTATIONS = {
    "accepts any hostname": (
        "profile = PROFILES.get(name) if code == 0 else None",
        "profile = PROFILES.get(name, PROFILES[EDGE1_HOSTNAME])",
        scenario_wrong_host_is_refused,
    ),
    "drops the check that the host's own private address is present": (
        "if profile.private_address not in addresses:",
        "if False:",
        scenario_wrong_host_is_refused,
    ),
    "drops the refusal on the other gateway's address": (
        "if other is not profile and other.private_address in addresses:",
        "if False:",
        scenario_wrong_host_is_refused,
    ),
    "drops the sabotage refusal on edge1": (
        "if sabotage and not profile.sabotage_allowed:",
        "if False:",
        scenario_sabotage_is_refused_on_edge1,
    ),
    "allows the sabotage on edge1 in the table": (
        "EDGE1_PRIVATE, SUBNET, sabotage_allowed=False",
        "EDGE1_PRIVATE, SUBNET, sabotage_allowed=True",
        scenario_sabotage_is_refused_on_edge1,
    ),
    "stops requiring the masquerade counter to rise": (
        "        elif moved < 1:\n            fails.append(f\"the counter of {name} did not rise",
        "        elif False:\n            fails.append(f\"the counter of {name} did not rise",
        scenario_masquerade_counter_must_rise,
    ),
    "reads any reply on the outside source as silence": (
        "    if reply is not False:\n        fails.append(\n            f\"expected no reply",
        "    if False:\n        fails.append(\n            f\"expected no reply",
        scenario_outside_reply_is_red,
    ),
    "reads unparseable probe output as silence": (
        '    return None, f"unexpected probe result',
        '    return False, f"unexpected probe result',
        scenario_garbage_probe_is_not_silence,
    ),
    "drops the check that the veth carried the packets": (
        "    if rx_after - rx_before < 1:",
        "    if False:",
        scenario_silent_veth_is_not_a_clean_control,
    ),
    "scores the outside control without the inside positive": (
        "    if not inside_ok:\n        return Verdict(",
        "    if False:\n        return Verdict(",
        scenario_outside_needs_the_inside_positive,
    ),
    "never removes the namespaces": (
        "        self.problems.extend(teardown(self.source))\n\n    def probe",
        "        pass\n\n    def probe",
        scenario_cleanup_on_interrupt,
    ),
    "deletes the masquerade without the flag": (
        "        elif args.sabotage:\n            with Lab",
        "        else:\n            with Lab",
        scenario_nothing_is_deleted_without_the_flag,
    ),
    "skips the restore": (
        "        if not self.began or self.restored:\n            return True",
        "        if True:\n            return True",
        scenario_restore_on_any_exit_after_delete,
    ),
    "deletes the rule even when the baseline is red": (
        "        if args.sabotage and not (inside.ok and outside.ok):",
        "        if False:",
        scenario_sabotage_refuses_on_a_red_baseline,
    ),
    "treats a failed restore as a success": (
        "        if code == 0 and back and active.strip() == \"active\":",
        "        if True:",
        scenario_failed_restore_is_loud,
    ),
    "leaves the unit-state read after the restore unguarded": (
        "            except (Refused, OSError):\n                active = \"\"",
        "            except KeyError:\n                active = \"\"",
        scenario_unreadable_unit_state_after_restore_is_loud,
    ),
    "counts a probe that stays green after the delete as red": (
        "    if reply is False and counters.masquerade is None:",
        "    if True:",
        scenario_proof_that_cannot_go_red_fails,
    ),
}


class MutationTests(unittest.TestCase):
    """Red against a copy with its check broken, green against the real script."""

    def test_each_scenario_is_green_on_the_real_script(self):
        for scenario in {s for _, _, s in MUTATIONS.values()}:
            with self.subTest(scenario.__name__):
                scenario(probe)

    def test_each_broken_copy_is_caught(self):
        for name, (old, new, scenario) in MUTATIONS.items():
            with self.subTest(name):
                module = load(broken(old, new), "probe_edget_gateway_broken")
                with self.assertRaises(
                    AssertionError, msg=f"{scenario.__name__} did not notice that the script {name}"
                ):
                    scenario(module)

    def test_the_mutations_are_real_edits(self):
        for name, (old, new, _) in MUTATIONS.items():
            self.assertNotEqual(old, new, name)
            self.assertNotEqual(broken(old, new), SOURCE, name)


if __name__ == "__main__":
    unittest.main()
