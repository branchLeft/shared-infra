"""Unit tests for the drain-port rule program: what it asks iptables, and when it refuses.

The program is run for real, as a child process, with a fake `iptables` first on its PATH. The
fake keeps a chain in a file, answers `-S`, `-C` and `-I` as the real one does (it prints an
address with its /32, as iptables -S does), and logs every call, so a test can say what the
program did and did not do. Nothing here touches a real firewall.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import branchleft_sweego_drain_rule as program

ROLE = Path(__file__).resolve().parents[2]
PROGRAM = ROLE / "files" / "branchleft_sweego_drain_rule.py"

ADDRESS = "10.20.1.10"
PORT = "8081"
SOURCE = "10.20.1.50"

FAKE_IPTABLES = """#!{python}
import os
import sys

state = os.environ["FAKE_STATE"]
log = os.environ["FAKE_LOG"]
args = sys.argv[1:]
with open(log, "a", encoding="utf-8") as handle:
    handle.write(" ".join(args) + "\\n")
chain_exit = int(os.environ.get("FAKE_CHAIN_EXIT", "0"))
check_exit = os.environ.get("FAKE_CHECK_EXIT")


def canonical(rule):
    out = []
    previous = ""
    for item in rule:
        if previous in ("-s", "--ctorigdst") and "/" not in item:
            item = item + "/32"
        out.append(item)
        previous = item
    return " ".join(out)


def rules():
    if not os.path.exists(state):
        return []
    with open(state, encoding="utf-8") as handle:
        return [line.rstrip("\\n") for line in handle if line.strip()]


assert args[:2] == ["-t", "filter"], args
action = args[2]
if action == "-S":
    if chain_exit != 0:
        sys.stderr.write("iptables: No chain/target/match by that name.\\n")
        sys.exit(chain_exit)
    print("-N DOCKER-USER")
    for rule in rules():
        print("-A DOCKER-USER " + rule)
    sys.exit(0)
if action == "-C":
    if check_exit is not None:
        sys.exit(int(check_exit))
    wanted = canonical(args[4:])
    sys.exit(0 if wanted in rules() else 1)
if action == "-I":
    if os.environ.get("FAKE_INSERT_EXIT"):
        sys.exit(int(os.environ["FAKE_INSERT_EXIT"]))
    position = int(args[4])
    current = rules()
    current.insert(position - 1, canonical(args[5:]))
    with open(state, "w", encoding="utf-8") as handle:
        handle.write("\\n".join(current) + "\\n")
    sys.exit(0)
sys.stderr.write("fake iptables: call not expected: " + " ".join(args) + "\\n")
sys.exit(64)
"""


def canonical_rule(address: str = ADDRESS, port: str = PORT, source: str = SOURCE) -> str:
    """The rule as `iptables -S` prints it: every address carries its /32."""
    return (
        f"-p tcp -m conntrack --ctorigdst {address}/32 --ctorigdstport {port} "
        f"--ctdir ORIGINAL ! -s {source}/32 -j DROP"
    )


class Run:
    """One run of the program against a fake iptables."""

    def __init__(self, test: unittest.TestCase, *, with_iptables: bool = True) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        test.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.bin = root / "bin"
        self.bin.mkdir()
        self.state = root / "chain"
        self.log = root / "calls"
        if with_iptables:
            fake = self.bin / "iptables"
            fake.write_text(FAKE_IPTABLES.format(python=sys.executable), encoding="utf-8")
            fake.chmod(0o755)

    def put_chain(self, *rules: str) -> None:
        """Start the chain with these rules, in order."""
        self.state.write_text("\n".join(rules) + "\n", encoding="utf-8")

    def chain(self) -> list[str]:
        """The rules now in the chain, in order."""
        if not self.state.exists():
            return []
        return [line for line in self.state.read_text(encoding="utf-8").splitlines() if line]

    def calls(self) -> list[str]:
        """Every call the fake iptables received."""
        if not self.log.exists():
            return []
        return self.log.read_text(encoding="utf-8").splitlines()

    def inserts(self) -> list[str]:
        """The calls that changed the chain."""
        return [call for call in self.calls() if " -I " in f" {call} "]

    def go(
        self,
        *arguments: str,
        **environment: str,
    ) -> subprocess.CompletedProcess[str]:
        """Run the program with the arguments and return its result."""
        env = {
            "PATH": str(self.bin),
            "FAKE_STATE": str(self.state),
            "FAKE_LOG": str(self.log),
            **environment,
        }
        return subprocess.run(  # noqa: S603 -- a fixed list, no shell
            [sys.executable, "-I", str(PROGRAM), *arguments],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=60,
        )

    def standard(self, **environment: str) -> subprocess.CompletedProcess[str]:
        """Run the program with the estate's three values."""
        return self.go(
            "--address", ADDRESS, "--port", PORT, "--allow-source", SOURCE, **environment
        )


class RuleIsInstalled(unittest.TestCase):
    """The rule goes in once, first, and drops every source but the one."""

    def test_absent_rule_is_inserted_first_with_every_piece(self) -> None:
        run = Run(self)
        result = run.standard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(run.chain(), [canonical_rule()])
        insert = run.inserts()
        self.assertEqual(len(insert), 1)
        for piece in (
            "-I DOCKER-USER 1",
            "-p tcp",
            "-m conntrack",
            f"--ctorigdst {ADDRESS}",
            f"--ctorigdstport {PORT}",
            "--ctdir ORIGINAL",
            f"! -s {SOURCE}",
            "-j DROP",
        ):
            self.assertIn(piece, insert[0])

    def test_rule_goes_above_an_existing_rule(self) -> None:
        run = Run(self)
        run.put_chain("-j RETURN")
        self.assertEqual(run.standard().returncode, 0)
        self.assertEqual(run.chain(), [canonical_rule(), "-j RETURN"])

    def test_the_rule_drops_and_never_accepts(self) -> None:
        run = Run(self)
        run.standard()
        self.assertTrue(run.chain()[0].endswith("-j DROP"))
        self.assertNotIn("ACCEPT", " ".join(run.calls()))

    def test_a_second_run_inserts_nothing(self) -> None:
        run = Run(self)
        self.assertEqual(run.standard().returncode, 0)
        self.assertEqual(run.standard().returncode, 0)
        self.assertEqual(len(run.inserts()), 1)
        self.assertEqual(run.chain(), [canonical_rule()])

    def test_the_rule_names_only_the_source_it_is_given(self) -> None:
        run = Run(self)
        result = run.go("--address", ADDRESS, "--port", "9100", "--allow-source", "10.20.1.99")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(run.chain(), [canonical_rule(port="9100", source="10.20.1.99")])


class RuleIsNotTrustedWhereItIsNotFirst(unittest.TestCase):
    """A rule under an accept is not a rule: the program says so and stops."""

    def test_present_but_second_is_refused_and_nothing_is_inserted(self) -> None:
        run = Run(self)
        run.put_chain("-s 172.17.0.0/16 -j ACCEPT", canonical_rule())
        result = run.standard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not its first rule", result.stderr)
        self.assertEqual(run.inserts(), [])

    def test_a_longer_port_is_not_taken_for_the_rule(self) -> None:
        run = Run(self)
        run.put_chain(canonical_rule(port="80810"))
        self.assertEqual(run.standard().returncode, 0)
        self.assertEqual(run.chain()[0], canonical_rule())

    def test_a_longer_source_is_not_taken_for_the_rule(self) -> None:
        self.assertFalse(
            program.is_the_rule(canonical_rule(source="10.20.1.500"), ADDRESS, PORT, SOURCE)
        )
        self.assertTrue(program.is_the_rule(canonical_rule(), ADDRESS, PORT, SOURCE))

    def test_a_rule_that_allows_the_source_instead_of_dropping_the_rest_is_not_the_rule(
        self,
    ) -> None:
        allow = (
            f"-p tcp -m conntrack --ctorigdst {ADDRESS}/32 --ctorigdstport {PORT} "
            f"--ctdir ORIGINAL -s {SOURCE}/32 -j DROP"
        )
        self.assertFalse(program.is_the_rule(allow, ADDRESS, PORT, SOURCE))

    def test_a_rule_that_accepts_is_not_the_rule(self) -> None:
        accept = canonical_rule().replace("-j DROP", "-j ACCEPT")
        self.assertFalse(program.is_the_rule(accept, ADDRESS, PORT, SOURCE))

    def test_a_rule_for_both_directions_is_not_the_rule(self) -> None:
        both = canonical_rule().replace("--ctdir ORIGINAL ", "")
        self.assertFalse(program.is_the_rule(both, ADDRESS, PORT, SOURCE))


class ProgramRefusesWhenItCannotKnow(unittest.TestCase):
    """No answer is not a yes: the program stops with nothing inserted."""

    def test_no_chain_stops_without_inserting(self) -> None:
        run = Run(self)
        result = run.standard(FAKE_CHAIN_EXIT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no DOCKER-USER chain", result.stderr)
        self.assertEqual(run.inserts(), [])

    def test_an_unknown_check_status_stops_without_inserting(self) -> None:
        run = Run(self)
        result = run.standard(FAKE_CHECK_EXIT="2")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing rather than guess", result.stderr)
        self.assertEqual(run.inserts(), [])

    def test_a_failed_insert_is_a_failure(self) -> None:
        run = Run(self)
        result = run.standard(FAKE_INSERT_EXIT="4")
        self.assertEqual(result.returncode, 4)

    def test_missing_iptables_stops(self) -> None:
        run = Run(self, with_iptables=False)
        result = run.standard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("iptables is not installed", result.stderr)


class ProgramRefusesBadArguments(unittest.TestCase):
    """Every value is checked before iptables is asked anything."""

    def refused(self, *arguments: str) -> None:
        """Assert the arguments are refused with status 2 and no call to iptables."""
        run = Run(self)
        result = run.go(*arguments)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(run.calls(), [])

    def test_a_wildcard_source_is_refused(self) -> None:
        self.refused("--address", ADDRESS, "--port", PORT, "--allow-source", "0.0.0.0")  # noqa: S104 -- the value being refused

    def test_a_network_for_a_source_is_refused(self) -> None:
        self.refused("--address", ADDRESS, "--port", PORT, "--allow-source", "10.20.1.0/24")

    def test_a_loopback_source_is_refused(self) -> None:
        self.refused("--address", ADDRESS, "--port", PORT, "--allow-source", "127.0.0.1")

    def test_a_wildcard_address_is_refused(self) -> None:
        self.refused("--address", "0.0.0.0", "--port", PORT, "--allow-source", SOURCE)  # noqa: S104

    def test_a_privileged_port_is_refused(self) -> None:
        self.refused("--address", ADDRESS, "--port", "80", "--allow-source", SOURCE)

    def test_a_port_out_of_range_is_refused(self) -> None:
        self.refused("--address", ADDRESS, "--port", "65536", "--allow-source", SOURCE)

    def test_a_port_that_is_not_a_number_is_refused(self) -> None:
        self.refused("--address", ADDRESS, "--port", "8081; reboot", "--allow-source", SOURCE)

    def test_a_source_equal_to_the_address_is_refused(self) -> None:
        self.refused("--address", ADDRESS, "--port", PORT, "--allow-source", ADDRESS)

    def test_a_missing_argument_is_refused(self) -> None:
        self.refused("--address", ADDRESS, "--port", PORT)

    def test_a_hostname_is_refused(self) -> None:
        self.refused("--address", "edge1", "--port", PORT, "--allow-source", SOURCE)


class ProgramIsRunAsRoot(unittest.TestCase):
    """The file a boot unit runs as root has the shape such a file needs."""

    def test_isolated_python_shebang(self) -> None:
        first = PROGRAM.read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(first, "#!/usr/bin/python3 -I")

    def test_no_shell_is_used(self) -> None:
        text = PROGRAM.read_text(encoding="utf-8")
        self.assertNotIn("shell=True", text)
        self.assertNotIn("os.system", text)

    def test_the_program_reads_no_environment(self) -> None:
        text = PROGRAM.read_text(encoding="utf-8")
        self.assertNotIn("os.environ", text)
        self.assertNotIn("getenv", text)
        self.assertTrue(os.access(PROGRAM, os.R_OK))


if __name__ == "__main__":
    unittest.main()
