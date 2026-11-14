#!/usr/bin/env python3
"""Tests for probe-app1-mailspool: a model of an app host under the script, plus copies of it with a check broken.

A check that cannot fail is not a check, so MutationTests breaks the script and expects red.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import re
import sys
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SCRIPT = HERE / "probe-app1-mailspool.py"
POLICY = ROOT / "ansible" / "roles" / "deploy_tooling" / "files" / "branchleft_docker_user_policy.py"
FIXTURES = ROOT / "ansible" / "roles" / "deploy_tooling" / "tests" / "unit" / "fixtures"
RUNBOOK = ROOT / "hetzner" / "RUNBOOK-provision-host.md"


def load(source: str, name: str = "probe_app1_mailspool"):
    spec = importlib.util.spec_from_loader(name, loader=None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(source, str(SCRIPT), "exec"), module.__dict__)  # noqa: S102 - the script under test
    return module


SOURCE = SCRIPT.read_text(encoding="utf-8")
probe = load(SOURCE)

IMAGE = "node@sha256:" + "a" * 64
SUFFIX = "t3st01"
BLOCKED = f"zz-probe-mailspool-{SUFFIX}"
CONTROL = f"zz-probe-mailspool-{SUFFIX}-control"
NETWORK = f"zz-probe-mailspool-net-{SUFFIX}"
V4 = (FIXTURES / "v4-standard.txt").read_text(encoding="utf-8").splitlines()
V6 = (FIXTURES / "v6-standard.txt").read_text(encoding="utf-8").splitlines()
FORWARD_DROP = "-A DOCKER-USER -i br-mailspool ! -o br-mailspool -j DROP"
INPUT_DROP = "-A INPUT -i br-mailspool -j DROP"
INPUT_REPLIES = "-A INPUT -i br-mailspool -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
DB_ACCEPT = "-A DOCKER-USER -d 10.20.1.20/32 -p tcp -m tcp --dport 3306 -j ACCEPT"


def check(condition: object, message: str) -> None:
    """An assertion that survives `python -O` and names what was expected."""
    if not condition:
        raise AssertionError(message)


class FakeApp1:
    """An app host as the probe sees it. Knobs are attributes; `calls` records every command."""

    def __init__(self, module):
        self.m = module
        self.calls: list[list[str]] = []
        self.hostname = "app1"
        self.addresses = ["203.0.113.20", "10.20.1.100"]
        self.root = True
        self.missing_tools: set[str] = set()
        self.images = {IMAGE}
        self.v4 = list(V4)
        self.v6 = list(V6)
        self.bridge_exists = False
        self.stray: list[str] = []  # names left by an earlier run
        self.containers: dict[str, str] = {}  # name -> network
        self.networks: dict[str, dict] = {}
        self.drop_pkts = 7
        # What the world does.
        self.blocked_behaviour = "drop"  # drop | reached | refused | silent | error
        self.control_internet = "connected"
        self.control_db = "connected"
        self.node_missing = False
        self.subnet = "172.18.0.0/16"
        self.container_stops = False  # a started container is not running
        self.rm_fails = False
        self.run_fails = False
        self.raise_on_blocked_exec: BaseException | None = None
        self.duplicate_drop_row = False
        self.garbage_listing = False
        self.foreign_drop_row = False

    # -- plumbing seams -------------------------------------------------------
    def install(self, stack: contextlib.ExitStack):
        stack.enter_context(mock.patch.object(self.m, "run", self.handle))
        stack.enter_context(mock.patch.object(self.m, "which", self.which))
        stack.enter_context(mock.patch.object(self.m, "is_root", lambda: self.root))
        stack.enter_context(mock.patch.object(self.m, "new_suffix", lambda: SUFFIX))
        stack.enter_context(mock.patch.object(self.m.signal, "signal", lambda *a: None))

    def which(self, tool):
        return None if tool in self.missing_tools else f"/usr/sbin/{tool}"

    def writes(self) -> list[list[str]]:
        """Every command that changes the host: containers and networks, never a firewall rule."""
        found = []
        for argv in self.calls:
            if argv[0] == "docker" and argv[1:3] in (["network", "create"], ["network", "rm"]):
                found.append(argv)
            elif argv[0] == "docker" and argv[1] in ("run", "rm"):
                found.append(argv)
            elif argv[0] in ("iptables", "ip6tables") and not any(a in ("-S", "-vxnL") for a in argv):
                found.append(argv)
        return found

    def present(self) -> list[str]:
        return sorted(self.containers) + sorted(self.networks) + sorted(self.stray)

    # -- the model ------------------------------------------------------------
    def handle(self, argv, timeout=30):
        self.calls.append(list(argv))
        tool = argv[0]
        if tool == "hostname":
            return 0, self.hostname + "\n", ""
        if tool == "ip":
            return self.ip(argv)
        if tool in ("iptables", "ip6tables"):
            return self.iptables(argv)
        if tool == "docker":
            return self.docker(argv)
        raise AssertionError(f"the probe ran an unexpected command: {argv}")

    def ip(self, argv):
        if argv[1:5] == ["-j", "-4", "addr", "show"]:
            rows = [{"ifname": "x", "addr_info": [{"family": "inet", "local": a}]} for a in self.addresses]
            return 0, json.dumps(rows), ""
        if argv[1:4] == ["-o", "link", "show"]:
            if self.bridge_exists or any(n["bridge"] == "br-mailspool" for n in self.networks.values()):
                return 0, "5: br-mailspool: <BROADCAST,MULTICAST,UP> mtu 1500\n", ""
            return 1, "", 'Device "br-mailspool" does not exist.\n'
        raise AssertionError(f"unexpected ip command {argv}")

    def listing(self):
        header = (
            "Chain DOCKER-USER (1 references)\n"
            "    pkts      bytes target     prot opt in     out     source               destination\n"
        )
        if self.garbage_listing:
            return header + "this is not a rule line\n"
        rows = []
        if self.foreign_drop_row:
            rows.append("      99      9900 DROP       all  --  br-other !br-other  0.0.0.0/0            0.0.0.0/0")
        for line in self.v4:
            if not line.startswith("-A DOCKER-USER "):
                continue
            if line == FORWARD_DROP:
                row = (
                    f"{self.drop_pkts:>8} {self.drop_pkts * 60:>9} DROP       all  --  "
                    "br-mailspool !br-mailspool  0.0.0.0/0            0.0.0.0/0"
                )
                rows.append(row)
                if self.duplicate_drop_row:
                    rows.append(row)
            elif "ctstate" in line:
                rows.append(
                    "       9       900 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0 ctstate RELATED,ESTABLISHED"
                )
            elif "--dport 3306" in line:
                rows.append(
                    "       0         0 ACCEPT     tcp  --  *      *       0.0.0.0/0            10.20.1.20           tcp dpt:3306"
                )
            elif "-d 10.20.1.0/24" in line:
                rows.append("       0         0 DROP       all  --  *      *       0.0.0.0/0            10.20.1.0/24")
            elif "169.254.169.254" in line:
                rows.append(
                    "       0         0 DROP       all  --  *      *       0.0.0.0/0            169.254.169.254"
                )
            else:
                rows.append("      30      1800 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0")
        return header + "\n".join(rows) + "\n"

    def iptables(self, argv):
        rules = self.v4 if argv[0] == "iptables" else self.v6
        if "-vxnL" in argv:
            return 0, self.listing(), ""
        if "-S" in argv:
            chain = argv[argv.index("-S") + 1]
            if not any(line == f"-N {chain}" or line.startswith(f"-A {chain} ") for line in rules):
                return 1, "", "iptables: No chain/target/match by that name.\n"
            return 0, "\n".join(line for line in rules if line.startswith(f"-A {chain} ")) + "\n", ""
        raise AssertionError(f"the probe wrote to the firewall: {argv}")

    def named(self, kind, flt):
        pool = self.containers if kind == "container" else self.networks
        names = [n for n in pool if flt in n] + [
            s.split(" ", 1)[1] for s in self.stray if s.startswith(kind) and flt in s
        ]
        return 0, "".join(f"{n}\n" for n in names), ""

    def docker(self, argv):
        sub = argv[1:3]
        if sub == ["image", "inspect"]:
            return (0, "sha256:abc\n", "") if argv[-1] in self.images else (1, "", "Error: No such image\n")
        if argv[1] == "ps":
            return self.named("container", argv[argv.index("--filter") + 1].split("=", 1)[1])
        if sub == ["network", "ls"]:
            return self.named("network", argv[argv.index("--filter") + 1].split("=", 1)[1])
        if sub == ["network", "create"]:
            bridge = [a.split("=", 1)[1] for a in argv if a.startswith("com.docker.network.bridge.name=")]
            self.networks[argv[-1]] = {"bridge": bridge[0] if bridge else "", "subnet": self.subnet}
            return 0, "deadbeef\n", ""
        if sub == ["network", "inspect"]:
            net = self.networks[argv[-1]]
            info = {
                "Options": {"com.docker.network.bridge.name": net["bridge"]},
                "IPAM": {"Config": [{"Subnet": net["subnet"]}]},
            }
            return 0, json.dumps(info) + "\n", ""
        if sub == ["network", "rm"]:
            name = argv[-1]
            if any(net == name for net in self.containers.values()):
                return 1, "", "network has active endpoints\n"
            self.networks.pop(name, None)
            return 0, name + "\n", ""
        if argv[1] == "run":
            return self.docker_run(argv)
        if argv[1] == "inspect":
            running = argv[-1] in self.containers and not self.container_stops
            return 0, ("true" if running else "false") + "\n", ""
        if argv[1] == "exec":
            return self.docker_exec(argv)
        if argv[1] == "rm":
            if self.rm_fails:
                return 1, "", "cannot remove\n"
            self.containers.pop(argv[-1], None)
            return 0, argv[-1] + "\n", ""
        raise AssertionError(f"unexpected docker command {argv}")

    def docker_run(self, argv):
        if self.run_fails:
            return 125, "", "docker: Error response from daemon\n"
        name = argv[argv.index("--name") + 1]
        network = argv[argv.index("--network") + 1]
        if network != "bridge" and network not in self.networks:
            return 125, "", f"network {network} not found\n"
        self.containers[name] = network
        return 0, "c0ffee\n", ""

    def docker_exec(self, argv):
        env = {}
        i = 2
        while argv[i] == "-e":
            key, _, value = argv[i + 1].partition("=")
            env[key] = value
            i += 2
        name = argv[i]
        if name not in self.containers:
            return 1, "", "Error: No such container\n"
        if self.node_missing:
            return 127, "", 'OCI runtime exec failed: exec: "node": executable file not found in $PATH\n'
        host = env["PROBE_HOST"]
        if self.containers[name] == "bridge":
            word = self.control_db if host == "10.20.1.20" else self.control_internet
            return 0, {"connected": "CONNECTED", "timeout": "TIMEOUT", "refused": "ERROR ECONNREFUSED"}[word] + "\n", ""
        if self.raise_on_blocked_exec is not None:
            raise self.raise_on_blocked_exec
        behaviour = self.blocked_behaviour
        if behaviour == "drop":
            self.drop_pkts += 3
            return 0, "TIMEOUT\n", ""
        if behaviour == "silent":
            return 0, "TIMEOUT\n", ""
        if behaviour == "reached":
            return 0, "CONNECTED\n", ""
        # The counter moves for these two so that only the state check can tell them from a drop.
        self.drop_pkts += 3
        if behaviour == "refused":
            return 0, "ERROR ECONNREFUSED\n", ""
        return 0, "ERROR EHOSTUNREACH\n", ""


def run_main(fake: FakeApp1, *extra: str, module=None, image: str = IMAGE) -> tuple[int, str]:
    """Run the script's main under the fake; return its exit code and everything it printed."""
    module = module or fake.m
    out = io.StringIO()
    with contextlib.ExitStack() as stack:
        fake.install(stack)
        stack.enter_context(contextlib.redirect_stdout(out))
        try:
            code = module.main([f"--image={image}", *extra])
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        except KeyboardInterrupt:
            code = 130
        except Exception as exc:  # a crash is never a pass, and the scenario must say so
            code = 99
            out.write(f"CRASH {type(exc).__name__}: {exc}\n")
    return code, out.getvalue()


def lines_of(text: str, kind: str, name: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(f"{kind} {name} ")]


# ---------------------------------------------------------------------------- scenarios
# Each takes a module (the real script or a broken copy), runs one situation and raises
# AssertionError if the module does not behave as the real script must.


def scenario_all_green(module):
    fake = FakeApp1(module)
    code, text = run_main(fake)
    check(code == 0, f"a healthy host should pass, exit {code}:\n{text}")
    for name in (
        "spool-rules-present",
        "control-default-bridge-internet-reachable",
        "drain-bridge-internet-blocked",
        "drain-bridge-subnet-blocked",
    ):
        check(len(lines_of(text, "GREEN", name)) == 1, f"no GREEN {name}:\n{text}")
    check(len(lines_of(text, "INFO", "control-default-bridge-subnet-reachable")) == 1, text)
    check("RESULT PASS" in text, text)
    check("counted 3 more packet(s) (7 to 10)" in text, f"the counter evidence is missing:\n{text}")
    check("CLEANUP ok" in text, text)
    check(fake.present() == [], f"left on the host: {fake.present()}")


def scenario_blocked_reached_is_red(module):
    fake = FakeApp1(module)
    fake.blocked_behaviour = "reached"
    code, text = run_main(fake)
    check(code == 1, f"a blocked case that connected must exit 1, got {code}:\n{text}")
    for name in ("drain-bridge-internet-blocked", "drain-bridge-subnet-blocked"):
        check(len(lines_of(text, "RED", name)) == 1, f"no RED {name}:\n{text}")
    check("THE CONNECTION WAS MADE" in text, text)
    check("RESULT FAIL" in text and "RESULT PASS" not in text, text)
    check(fake.present() == [], f"left on the host: {fake.present()}")


def scenario_refusal_by_rst_is_red(module):
    fake = FakeApp1(module)
    fake.blocked_behaviour = "refused"
    code, text = run_main(fake)
    check(code == 1, f"an RST from a DROP rule's bridge must exit 1, got {code}:\n{text}")
    check("a DROP answers nothing" in text, text)


def scenario_other_error_is_red(module):
    fake = FakeApp1(module)
    fake.blocked_behaviour = "error"
    code, text = run_main(fake)
    check(code == 1 and len(lines_of(text, "RED", "drain-bridge-internet-blocked")) == 1, text)


def scenario_counter_must_rise(module):
    fake = FakeApp1(module)
    fake.blocked_behaviour = "silent"
    code, text = run_main(fake)
    check(code == 1, f"a timeout with no counter movement must exit 1, got {code}:\n{text}")
    check("counter did not rise (7 to 7)" in text, text)


def scenario_control_unreachable_is_inconclusive(module):
    fake = FakeApp1(module)
    fake.control_internet = "timeout"
    code, text = run_main(fake)
    check(code == 2, f"a control that cannot connect must exit non-zero, got {code}:\n{text}")
    check(len(lines_of(text, "INCONCLUSIVE", "control-default-bridge-internet-reachable")) == 1, text)
    check("RESULT INCONCLUSIVE" in text and "RESULT PASS" not in text, text)
    check("GREEN drain-bridge" not in text, f"a blocked case was scored without a control:\n{text}")
    check(
        not [c for c in fake.calls if c[:3] == ["docker", "network", "create"]],
        "the bridge was made though the control failed",
    )
    check(fake.present() == [], f"left on the host: {fake.present()}")


def scenario_control_tool_missing_is_inconclusive(module):
    fake = FakeApp1(module)
    fake.node_missing = True
    code, text = run_main(fake)
    check(code == 2 and "RESULT INCONCLUSIVE" in text, f"exit {code}:\n{text}")
    check("tool-error" in text, text)


def scenario_control_subnet_is_only_a_note(module):
    fake = FakeApp1(module)
    fake.control_db = "timeout"
    code, text = run_main(fake)
    check(code == 0 and "RESULT PASS" in text, f"a silent db1 must not fail the run, exit {code}:\n{text}")
    check("does not change the verdict" in text, text)


def scenario_control_and_blocked_networks(module):
    fake = FakeApp1(module)
    code, _ = run_main(fake)
    runs = [c for c in fake.calls if c[:2] == ["docker", "run"]]
    check(len(runs) == 2, f"expected exactly two containers, saw {len(runs)}")
    by_name = {c[c.index("--name") + 1]: c[c.index("--network") + 1] for c in runs}
    check(by_name == {CONTROL: "bridge", BLOCKED: NETWORK}, f"unexpected networks {by_name}")
    creates = [c for c in fake.calls if c[:3] == ["docker", "network", "create"]]
    check(len(creates) == 1 and "com.docker.network.bridge.name=br-mailspool" in creates[0], f"{creates}")


def scenario_container_flags(module):
    fake = FakeApp1(module)
    run_main(fake)
    runs = [c for c in fake.calls if c[:2] == ["docker", "run"]]
    check(runs, "no container was started")
    for argv in runs:
        for flag, value in (("--pull", "never"), ("--cap-drop", "ALL"), ("--entrypoint", "node")):
            check(flag in argv and argv[argv.index(flag) + 1] == value, f"{flag} {value} missing in {argv}")
        for banned in (
            "--privileged",
            "-v",
            "--volume",
            "--mount",
            "-p",
            "--publish",
            "-P",
            "--cap-add",
            "--network=host",
        ):
            check(banned not in argv, f"{banned} in {argv}")
        check("--rm" in argv and "--read-only" in argv and "no-new-privileges" in argv, f"{argv}")
        check(argv[-3] == IMAGE, f"the image must come right before the command: {argv}")


def scenario_never_writes_the_firewall(module):
    fake = FakeApp1(module)
    run_main(fake)
    for argv in fake.calls:
        if argv[0] in ("iptables", "ip6tables"):
            check("-S" in argv or "-vxnL" in argv, f"a firewall write or unknown call: {argv}")
    check(not [c for c in fake.calls if c[:2] == ["docker", "pull"]], "the probe pulled an image")


def _refused(module, mutate, expect, *, image=IMAGE):
    fake = FakeApp1(module)
    mutate(fake)
    code, text = run_main(fake, image=image)
    check(code == 2, f"expected a refusal (exit 2), got {code}:\n{text}")
    check(re.search(rf"^REFUSED: .*{expect}", text, re.M), f"expected REFUSED naming {expect!r}:\n{text}")
    check("RESULT PASS" not in text, text)
    check(fake.writes() == [], f"a refused run changed the host: {fake.writes()}")


def scenario_wrong_host_is_refused(module):
    _refused(module, lambda f: setattr(f, "hostname", "edge1"), "not one of app1")
    _refused(module, lambda f: setattr(f, "hostname", "db1"), "not one of app1")
    _refused(module, lambda f: setattr(f, "addresses", ["203.0.113.20"]), "holds no 10.20.1.100")
    _refused(module, lambda f: f.addresses.append("10.20.1.10"), "edge1's address")
    _refused(module, lambda f: f.addresses.append("10.20.1.20"), "db1's address")
    _refused(module, lambda f: f.addresses.append("10.20.1.50"), "ops1's address")


def scenario_missing_image_is_refused(module):
    fake = FakeApp1(module)
    fake.images = set()
    code, text = run_main(fake)
    check(code == 2 and "never pulls" in text, f"exit {code}:\n{text}")
    check(fake.writes() == [], f"a refused run changed the host: {fake.writes()}")
    check(not [c for c in fake.calls if c[1:2] == ["run"] or c[1:2] == ["pull"]], "it tried to start or pull")


def scenario_missing_rules_are_refused(module):
    def drop(rule, family):
        def mutate(fake):
            setattr(fake, family, [line for line in getattr(fake, family) if line != rule])

        return mutate

    for family in ("v4", "v6"):
        for rule in (FORWARD_DROP, INPUT_DROP, INPUT_REPLIES):
            _refused(module, drop(rule, family), "not once")
    _refused(module, drop(DB_ACCEPT, "v4"), "db1:3306 accept")
    _refused(module, lambda f: setattr(f, "v6", [r for r in f.v6 if "DOCKER-USER" not in r]), "ip6tables")
    _refused(module, lambda f: f.v4.append(FORWARD_DROP), "present 2 times")


def scenario_only_the_drop_rule_counts(module):
    def other_interface(fake):
        fake.v4 = [line.replace("-i br-mailspool ! -o br-mailspool", "-i br-other ! -o br-other") for line in fake.v4]

    fake = FakeApp1(module)
    fake.foreign_drop_row = True
    code, text = run_main(fake)
    check(code == 0 and "(7 to 10)" in text, f"another bridge's drop row must not be read as the spool's:\n{text}")
    _refused(module, other_interface, "spool forward drop is present 0 times")
    _refused(
        module,
        lambda f: setattr(f, "v4", [r.replace("-j DROP", "-j REJECT") if r == FORWARD_DROP else r for r in f.v4]),
        "not once",
    )


def scenario_unreadable_counter_is_refused(module):
    _refused(module, lambda f: setattr(f, "garbage_listing", True), "did not parse")
    _refused(module, lambda f: setattr(f, "duplicate_drop_row", True), "appears 2 times")


def scenario_existing_bridge_is_refused(module):
    _refused(module, lambda f: setattr(f, "bridge_exists", True), "already exists")


def scenario_leftovers_are_refused(module):
    _refused(
        module, lambda f: f.stray.append("container zz-probe-mailspool-old"), "left container zz-probe-mailspool-old"
    )
    _refused(
        module,
        lambda f: f.stray.append("network zz-probe-mailspool-net-old"),
        "left network zz-probe-mailspool-net-old",
    )


def scenario_bad_arguments_are_refused(module):
    _refused(module, lambda f: None, "not an image name", image="--privileged")
    fake = FakeApp1(module)
    code, text = run_main(fake, "--target", "10.20.1.20:3306")
    check(code == 2 and "not a public address" in text, f"exit {code}:\n{text}")
    code, text = run_main(FakeApp1(module), "--target", "9.9.9.9")
    check(code == 2 and "IPV4:PORT" in text, text)


def scenario_prerequisites_are_refused(module):
    _refused(module, lambda f: setattr(f, "root", False), "run as root")
    for tool in ("docker", "iptables", "ip6tables"):
        _refused(module, lambda f, t=tool: f.missing_tools.add(t), f"{tool} is not installed")


def scenario_overlapping_subnet_is_refused_and_cleaned(module):
    fake = FakeApp1(module)
    fake.subnet = "10.20.1.0/24"
    code, text = run_main(fake)
    check(code == 2 and "overlapping" in text, f"exit {code}:\n{text}")
    check("RESULT PASS" not in text, text)
    check(fake.present() == [], f"left on the host: {fake.present()}")


def scenario_cleanup_on_failure(module):
    for failure in (module.Refused("docker exec did not finish"), KeyboardInterrupt(), SystemExit(143)):
        fake = FakeApp1(module)
        fake.raise_on_blocked_exec = failure
        code, text = run_main(fake)
        check(code != 0, f"a failed run must not exit 0 ({type(failure).__name__}):\n{text}")
        check("RESULT PASS" not in text, text)
        check(fake.present() == [], f"{type(failure).__name__}: left on the host: {fake.present()}")
        check("CLEANUP ok: removed" in text, f"the clean-up was not reported:\n{text}")
        check(BLOCKED in text and NETWORK in text, text)


def scenario_failed_start_is_cleaned(module):
    fake = FakeApp1(module)
    fake.container_stops = True
    code, text = run_main(fake)
    check(code == 2 and "did not stay up" in text, f"exit {code}:\n{text}")
    check(fake.present() == [], f"left on the host: {fake.present()}")


def scenario_cleanup_failure_is_loud(module):
    fake = FakeApp1(module)
    fake.rm_fails = True
    code, text = run_main(fake)
    check(code == 3, f"a host left dirty must exit 3, got {code}:\n{text}")
    check("CLEANUP FAILED" in text and CONTROL in text, text)
    check("RESULT FAIL: the host was not left clean" in text and "RESULT PASS" not in text, text)
    check("docker rm -f -v" in text and "docker network rm" in text, "the recovery commands are not printed")


SCENARIOS = [
    scenario_all_green,
    scenario_blocked_reached_is_red,
    scenario_refusal_by_rst_is_red,
    scenario_other_error_is_red,
    scenario_counter_must_rise,
    scenario_control_unreachable_is_inconclusive,
    scenario_control_tool_missing_is_inconclusive,
    scenario_control_subnet_is_only_a_note,
    scenario_control_and_blocked_networks,
    scenario_container_flags,
    scenario_never_writes_the_firewall,
    scenario_wrong_host_is_refused,
    scenario_missing_image_is_refused,
    scenario_missing_rules_are_refused,
    scenario_only_the_drop_rule_counts,
    scenario_unreadable_counter_is_refused,
    scenario_existing_bridge_is_refused,
    scenario_leftovers_are_refused,
    scenario_bad_arguments_are_refused,
    scenario_prerequisites_are_refused,
    scenario_overlapping_subnet_is_refused_and_cleaned,
    scenario_cleanup_on_failure,
    scenario_failed_start_is_cleaned,
    scenario_cleanup_failure_is_loud,
]


class ScenarioTests(unittest.TestCase):
    def test_each_scenario_on_the_real_script(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario.__name__):
                scenario(probe)


class OutputTests(unittest.TestCase):
    def test_a_pass_prints_one_line_per_case_in_the_edge_probe_style(self):
        code, text = run_main(FakeApp1(probe))
        self.assertEqual(code, 0)
        shape = re.compile(r"^(GREEN|RED|INFO|SKIPPED|INCONCLUSIVE) [a-z0-9-]+ \[live\]: .+$")
        verdicts = [line for line in text.splitlines() if shape.match(line)]
        self.assertEqual(len(verdicts), 5, text)
        self.assertEqual(text.splitlines()[-1], "RESULT PASS")

    def test_the_header_names_the_host_image_targets_and_containers(self):
        _, text = run_main(FakeApp1(probe))
        header = text.splitlines()[0]
        for needle in ("on app1", f"image {IMAGE}", "9.9.9.9:53", "10.20.1.20:3306", BLOCKED, CONTROL):
            self.assertIn(needle, header)

    def test_the_cleanup_line_says_what_was_removed(self):
        _, text = run_main(FakeApp1(probe))
        line = next(line for line in text.splitlines() if line.startswith("CLEANUP"))
        for needle in (f"container {BLOCKED}", f"container {CONTROL}", f"network {NETWORK}"):
            self.assertIn(needle, line)

    def test_a_refusal_before_anything_started_says_nothing_was_removed(self):
        fake = FakeApp1(probe)
        fake.control_internet = "timeout"
        fake.container_stops = False
        _, text = run_main(fake)
        self.assertNotIn(f"network {NETWORK}", next(line for line in text.splitlines() if line.startswith("CLEANUP")))

    def test_a_custom_target_is_used_for_the_internet_case(self):
        fake = FakeApp1(probe)
        code, text = run_main(fake, "--target", "1.1.1.1:443")
        self.assertEqual(code, 0, text)
        hosts = {a for c in fake.calls for a in c if a.startswith("PROBE_HOST=")}
        self.assertEqual(hosts, {"PROBE_HOST=1.1.1.1", "PROBE_HOST=10.20.1.20"})


class ParsingTests(unittest.TestCase):
    """The pieces that read real tool output, on text shaped like the real thing."""

    def test_the_negated_out_interface_parses_with_or_without_a_space_after_the_bang(self):
        for spelling in ("!br-mailspool", "! br-mailspool"):
            listing = (
                "Chain DOCKER-USER (1 references)\n"
                "    pkts      bytes target     prot opt in     out     source               destination\n"
                f"       4       240 DROP       all  --  br-mailspool {spelling}  0.0.0.0/0            0.0.0.0/0\n"
            )
            with mock.patch.object(probe, "run", lambda argv, timeout=30, text=listing: (0, text, "")):
                self.assertEqual(probe.drop_counter(), 4, spelling)

    def test_a_drop_for_another_bridge_is_not_the_spool_rule(self):
        listing = (
            "Chain DOCKER-USER (1 references)\n"
            "    pkts      bytes target     prot opt in     out     source               destination\n"
            "       4       240 DROP       all  --  br-other !br-other  0.0.0.0/0            0.0.0.0/0\n"
        )
        with (
            mock.patch.object(probe, "run", lambda argv, timeout=30: (0, listing, "")),
            self.assertRaises(probe.Refused),
        ):
            probe.drop_counter()

    def test_the_client_prints_one_word_for_every_outcome(self):
        for word in ("CONNECTED", "TIMEOUT", "ERROR '"):
            self.assertIn(word, probe.CLIENT_CODE)
        self.assertIn(str(probe.CONNECT_SECONDS * 1000), probe.CLIENT_CODE)

    def test_an_expectation_follows_the_rule_target(self):
        # The rule is a DROP, so the blocked case must be a timeout; a REJECT would be a refusal.
        self.assertTrue(FORWARD_DROP.endswith("-j DROP"))
        self.assertEqual(probe.EXPECTED_STATE, "timeout")


class PinTests(unittest.TestCase):
    """The script runs on a host with no checkout, so its copies of the plan and the policy are pinned here."""

    plan = (ROOT / "hetzner-host" / "addressPlan.ts").read_text(encoding="utf-8")
    policy = POLICY.read_text(encoding="utf-8")

    def constant(self, name):
        match = re.search(rf"export const {name}\s*=\s*'([^']+)'", self.plan)
        self.assertIsNotNone(match, name)
        return match.group(1)

    def block(self, block):
        body = re.search(rf"export const {block}\s*=\s*\{{(.*?)\}}\s*as const", self.plan, re.S)
        self.assertIsNotNone(body, block)
        return dict(re.findall(r"\b(\w+)\s*:\s*'([^']+)'", body.group(1)))

    def policy_default(self, name):
        match = re.search(rf'^{name} = "([^"]+)"', self.policy, re.M)
        self.assertIsNotNone(match, name)
        return match.group(1)

    def test_the_subnet_and_the_hosts_are_the_plans(self):
        self.assertEqual(probe.SUBNET, self.constant("SUBNET_CIDR"))
        self.assertEqual(probe.APP_HOSTS, self.block("APP_HOST_IPS"))
        self.assertEqual(probe.OTHER_HOSTS, self.block("HOST_IPS"))

    def test_the_database_and_the_bridge_are_the_policys(self):
        self.assertEqual(probe.DB_HOST, self.policy_default("DEFAULT_DB_HOST"))
        self.assertEqual(str(probe.DB_PORT), self.policy_default("DEFAULT_DB_PORT"))
        self.assertEqual(probe.BRIDGE, self.policy_default("DEFAULT_MAIL_SPOOL_BRIDGE"))
        self.assertEqual(probe.SUBNET, self.policy_default("DEFAULT_SUBNET"))

    def test_the_rules_are_the_ones_the_policys_fixtures_hold(self):
        v4, v6 = set(V4), set(V6)
        for rule in (FORWARD_DROP, INPUT_DROP, INPUT_REPLIES, DB_ACCEPT):
            self.assertIn(rule, v4)
        for rule in (FORWARD_DROP, INPUT_DROP, INPUT_REPLIES):
            self.assertIn(rule, v6)
        self.assertEqual(probe.FORWARD_DROP, FORWARD_DROP)
        self.assertEqual(probe.INPUT_DROP, INPUT_DROP)
        self.assertEqual(probe.DB_ACCEPT, DB_ACCEPT)
        self.assertTrue(probe.INPUT_REPLIES.fullmatch(INPUT_REPLIES))
        self.assertTrue(
            probe.INPUT_REPLIES.fullmatch(INPUT_REPLIES.replace("RELATED,ESTABLISHED", "ESTABLISHED,RELATED"))
        )

    def test_the_forward_drop_is_a_drop_in_the_policy(self):
        self.assertIn('"-i", bridge, "!", "-o", bridge, "-j", "DROP"', self.policy)

    def test_the_default_target_is_a_public_ipv4_with_a_port(self):
        host, port = probe.split_target(probe.DEFAULT_TARGET)
        self.assertEqual((host, port), ("9.9.9.9", 53))

    def test_every_name_the_probe_makes_fits_docker_and_shares_one_prefix(self):
        lab = probe.Lab("abcdef", IMAGE)
        for name in (lab.blocked, lab.control, lab.network):
            self.assertTrue(name.startswith(probe.NAME_PREFIX), name)
            self.assertLess(len(name), 64)
        self.assertEqual(len({lab.blocked, lab.control, lab.network}), 3)


class RunbookTests(unittest.TestCase):
    """Every command the runbook tells the owner to run must parse against the script."""

    def blocks(self):
        text = RUNBOOK.read_text(encoding="utf-8")
        return [b for b in re.findall(r"```bash\n(.*?)```", text, re.S) if "probe-app1-mailspool.py" in b]

    def test_the_runbook_pipes_the_script_to_app1_with_an_image(self):
        blocks = self.blocks()
        self.assertEqual(len(blocks), 1)
        block = blocks[0]
        self.assertIn("root@10.20.1.100", block)
        self.assertIn("ProxyCommand", block)
        self.assertIn("python3 - --image", block)
        self.assertIn("git -C", block)

    def test_the_invocation_in_the_runbook_parses(self):
        joined = self.blocks()[0].replace("\\\n", " ")
        match = re.search(r"python3 - ([^;\n]*)", joined)
        self.assertIsNotNone(match)
        words = [w.replace('"', "") for w in match.group(1).split()]
        words = ["node:25-slim" if re.fullmatch(r"\$\{?[A-Z0-9_]+\}?", w) else w for w in words]
        args = probe.build_parser().parse_args(words)
        self.assertEqual(args.image, "node:25-slim")

    def test_the_image_listing_command_is_read_only(self):
        text = RUNBOOK.read_text(encoding="utf-8")
        listing = re.findall(r"docker image ls[^\n]*", text)
        self.assertTrue(listing)
        for command in listing:
            self.assertNotIn("pull", command)
            self.assertNotIn("rm", command.split())


# ----------------------------------------------------------------------------- mutations


def broken(old: str, new: str) -> str:
    """The script with exactly one piece of one check replaced."""
    assert SOURCE.count(old) == 1, f"the broken copy needs {old!r} to appear exactly once"
    return SOURCE.replace(old, new)


MUTATIONS = {
    "treats a connection from the drain bridge as blocked": (
        "    if state != EXPECTED_STATE:\n        reading",
        '    if state not in (EXPECTED_STATE, "connected"):\n        reading',
        scenario_blocked_reached_is_red,
    ),
    "treats a refusal from the drain bridge as blocked": (
        "    if state != EXPECTED_STATE:\n        reading",
        '    if state not in (EXPECTED_STATE, "refused"):\n        reading',
        scenario_refusal_by_rst_is_red,
    ),
    "scores any non-timeout as blocked": (
        "    if state != EXPECTED_STATE:\n        reading",
        "    if False:\n        reading",
        scenario_other_error_is_red,
    ),
    "stops requiring the drop counter to rise": (
        "    if after - before < 1:",
        "    if False:",
        scenario_counter_must_rise,
    ),
    "skips the control (reads it as connected)": (
        '    if state == "connected":\n        internet = Verdict(',
        "    if True:\n        internet = Verdict(",
        scenario_control_unreachable_is_inconclusive,
    ),
    "runs the blocked cases whatever the control says": (
        '            if verdicts[0].kind == "GREEN":',
        "            if True:",
        scenario_control_unreachable_is_inconclusive,
    ),
    "never reports a control that could not run": (
        '    if any(v.kind == "INCONCLUSIVE" for v in verdicts):',
        "    if False:",
        scenario_control_unreachable_is_inconclusive,
    ),
    "runs the control on the drain network": (
        'lab.start(lab.control, "bridge")',
        "lab.start(lab.control, lab.network)",
        scenario_control_and_blocked_networks,
    ),
    "skips the clean-up": (
        "            left = lab.clean()\n",
        "            left = []\n",
        scenario_cleanup_on_failure,
    ),
    "does not read back that the clean-up took": (
        "    return leftovers(self.suffix)",
        "    return []",
        scenario_cleanup_failure_is_loud,
    ),
    "removes the containers but not the network": (
        '        run(["docker", "network", "rm", self.network])\n',
        "",
        scenario_all_green,
    ),
    "calls a dirty host a pass": (
        '    if left:\n        say("RESULT FAIL: the host was not left clean")\n        return 3',
        "    if False:\n        return 3",
        scenario_cleanup_failure_is_loud,
    ),
    "drops the hostname guard": (
        "    if code != 0 or name not in APP_HOSTS:",
        "    if False:",
        scenario_wrong_host_is_refused,
    ),
    "drops the check that the host's own address is present": (
        "    if APP_HOSTS[name] not in addresses:",
        "    if False:",
        scenario_wrong_host_is_refused,
    ),
    "drops the refusal on another host's address": (
        "        if address in addresses:",
        "        if False:",
        scenario_wrong_host_is_refused,
    ),
    "does not refuse an image that is not here": (
        '    if code != 0:\n        raise Refused(\n            f"image {image} is not present',
        '    if False:\n        raise Refused(\n            f"image {image} is not present',
        scenario_missing_image_is_refused,
    ),
    "lets docker pull a missing image": (
        '"--pull", "never"',
        '"--pull", "missing"',
        scenario_container_flags,
    ),
    "keeps the capabilities": (
        '"--cap-drop", "ALL"',
        '"--cap-add", "ALL"',
        scenario_container_flags,
    ),
    "does not refuse when a rule is missing": (
        "        if found != 1:",
        "        if False:",
        scenario_missing_rules_are_refused,
    ),
    "does not insist on the db1 accept": (
        "    if with_db:\n        wanted.append(",
        "    if False:\n        wanted.append(",
        scenario_missing_rules_are_refused,
    ),
    "counts any DROP for any bridge as the spool rule": (
        'if fields[2] == "DROP" and fields[5] == BRIDGE and fields[6] == f"!{BRIDGE}":',
        'if fields[2] == "DROP":',
        scenario_only_the_drop_rule_counts,
    ),
    "does not refuse a bridge that already exists": (
        '    if code == 0:\n        raise Refused(\n            f"{BRIDGE} already exists',
        '    if False:\n        raise Refused(\n            f"{BRIDGE} already exists',
        scenario_existing_bridge_is_refused,
    ),
    "does not refuse another run's leftovers": (
        '    if left:\n        raise Refused(\n            "a probe run left "',
        '    if False:\n        raise Refused(\n            "a probe run left "',
        scenario_leftovers_are_refused,
    ),
    "accepts a private address as the internet": (
        "    if not address.is_global:",
        "    if False:",
        scenario_bad_arguments_are_refused,
    ),
    "lets an overlapping subnet through": (
        "        if any(s.overlaps(ipaddress.ip_network(SUBNET)) for s in subnets):",
        "        if False:",
        scenario_overlapping_subnet_is_refused_and_cleaned,
    ),
    "trusts a container that is not running": (
        '        if out.strip() != "true":',
        "        if False:",
        scenario_failed_start_is_cleaned,
    ),
}


class MutationTests(unittest.TestCase):
    """Red against a copy with its check broken, green against the real script."""

    def test_each_broken_copy_is_caught(self):
        for name, (old, new, scenario) in MUTATIONS.items():
            with self.subTest(name):
                module = load(broken(old, new), "probe_app1_mailspool_broken")
                with self.assertRaises(
                    AssertionError, msg=f"{scenario.__name__} did not notice that the script {name}"
                ):
                    scenario(module)

    def test_the_mutations_are_real_edits(self):
        for name, (old, new, _) in MUTATIONS.items():
            self.assertNotEqual(old, new, name)
            self.assertNotEqual(broken(old, new), SOURCE, name)

    def test_every_scenario_a_mutation_relies_on_is_green_on_the_real_script(self):
        for scenario in {s for _, _, s in MUTATIONS.values()}:
            with self.subTest(scenario.__name__):
                scenario(probe)


if __name__ == "__main__":
    unittest.main()
