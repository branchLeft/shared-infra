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
CONTAINER = "172.29.250.2"
CONTAINER_PORT = "8081"

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
        if previous in ("-s", "-d", "--ctorigdst") and "/" not in item:
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


def canonical_original(address: str = ADDRESS, port: str = PORT, source: str = SOURCE) -> str:
    """The original-destination rule as `iptables -S` prints it: every address carries its /32."""
    return (
        f"-p tcp -m conntrack --ctorigdst {address}/32 --ctorigdstport {port} "
        f"--ctdir ORIGINAL ! -s {source}/32 -j DROP"
    )


def canonical_after_dnat(
    container: str = CONTAINER, port: str = CONTAINER_PORT, source: str = SOURCE
) -> str:
    """The post-DNAT rule as `iptables -S` prints it."""
    return f"-p tcp -d {container}/32 --dport {port} ! -s {source}/32 -j DROP"


def canonical_rules() -> list[str]:
    """Both rules, in the order the program leaves them: post-DNAT first."""
    return [canonical_after_dnat(), canonical_original()]


def standard_arguments(**replace: str) -> list[str]:
    """The five options of the estate's values; a keyword replaces one by its option name."""
    values = {
        "address": ADDRESS,
        "port": PORT,
        "allow-source": SOURCE,
        "container-address": CONTAINER,
        "container-port": CONTAINER_PORT,
    }
    values.update({key.replace("_", "-"): value for key, value in replace.items()})
    return [item for key, value in values.items() for item in (f"--{key}", value)]


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
        return self.go(*standard_arguments(), **environment)


class RuleIsInstalled(unittest.TestCase):
    """Both rules go in once, as the first two, and drop every source but the one."""

    def test_absent_rules_are_inserted_first_and_second_with_every_piece(self) -> None:
        run = Run(self)
        result = run.standard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(run.chain(), canonical_rules())
        insert = run.inserts()
        self.assertEqual(len(insert), 2)
        for piece in (
            "-I DOCKER-USER 1",
            "-p tcp",
            f"-d {CONTAINER}",
            f"--dport {CONTAINER_PORT}",
            f"! -s {SOURCE}",
            "-j DROP",
        ):
            self.assertIn(piece, insert[0])
        for piece in (
            "-I DOCKER-USER 2",
            "-m conntrack",
            f"--ctorigdst {ADDRESS}",
            f"--ctorigdstport {PORT}",
            "--ctdir ORIGINAL",
            f"! -s {SOURCE}",
            "-j DROP",
        ):
            self.assertIn(piece, insert[1])

    def test_the_post_dnat_destination_is_matched(self) -> None:
        """A connection sent straight to the container's address is dropped as well.

        Without this rule only a connection made to the published address is judged, and a host
        that routes to the container address (the default route of the platform network leads to
        this host, which forwards) reaches the drain listener with the token as its only guard.
        """
        run = Run(self)
        run.standard()
        direct = [rule for rule in run.chain() if f"-d {CONTAINER}/32" in rule]
        self.assertEqual(len(direct), 1)
        self.assertIn(f"--dport {CONTAINER_PORT}", direct[0])
        self.assertIn(f"! -s {SOURCE}/32", direct[0])
        self.assertTrue(direct[0].endswith("-j DROP"))

    def test_the_rules_go_above_an_existing_rule(self) -> None:
        run = Run(self)
        run.put_chain("-j RETURN")
        self.assertEqual(run.standard().returncode, 0)
        self.assertEqual(run.chain(), [*canonical_rules(), "-j RETURN"])

    def test_the_rules_drop_and_never_accept(self) -> None:
        run = Run(self)
        run.standard()
        for rule in run.chain():
            self.assertTrue(rule.endswith("-j DROP"))
        self.assertNotIn("ACCEPT", " ".join(run.calls()))

    def test_a_second_run_inserts_nothing(self) -> None:
        run = Run(self)
        self.assertEqual(run.standard().returncode, 0)
        self.assertEqual(run.standard().returncode, 0)
        self.assertEqual(len(run.inserts()), 2)
        self.assertEqual(run.chain(), canonical_rules())

    def test_the_rules_name_only_the_values_they_are_given(self) -> None:
        run = Run(self)
        result = run.go(
            *standard_arguments(port="9100", allow_source="10.20.1.99", container_port="9101")
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            run.chain(),
            [
                canonical_after_dnat(port="9101", source="10.20.1.99"),
                canonical_original(port="9100", source="10.20.1.99"),
            ],
        )

    def test_a_chain_with_only_the_old_rule_gains_the_new_one_above_it(self) -> None:
        """The rule an earlier version left (the original destination alone) is kept as rule 2."""
        run = Run(self)
        run.put_chain(canonical_original(), "-j RETURN")
        result = run.standard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(run.chain(), [*canonical_rules(), "-j RETURN"])
        self.assertEqual(len(run.inserts()), 1)

    def test_a_deleted_second_rule_is_put_back_as_the_second(self) -> None:
        run = Run(self)
        run.put_chain(canonical_after_dnat(), "-j RETURN")
        self.assertEqual(run.standard().returncode, 0)
        self.assertEqual(run.chain(), [*canonical_rules(), "-j RETURN"])


class RuleIsNotTrustedWhereItIsNotFirst(unittest.TestCase):
    """A rule under an accept is not a rule: the program says so and stops."""

    def test_present_but_below_an_accept_is_refused_and_nothing_is_inserted(self) -> None:
        run = Run(self)
        run.put_chain("-s 172.17.0.0/16 -j ACCEPT", *canonical_rules())
        result = run.standard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not rule 1", result.stderr)
        self.assertEqual(run.inserts(), [])

    def test_the_second_rule_below_an_accept_is_refused(self) -> None:
        run = Run(self)
        run.put_chain(canonical_after_dnat(), "-s 172.17.0.0/16 -j ACCEPT", canonical_original())
        result = run.standard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not rule 2", result.stderr)
        self.assertEqual(run.inserts(), [])

    def test_the_two_rules_in_the_wrong_order_are_refused(self) -> None:
        run = Run(self)
        run.put_chain(canonical_original(), canonical_after_dnat())
        result = run.standard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not rule 1", result.stderr)
        self.assertEqual(run.inserts(), [])

    def test_a_longer_port_is_not_taken_for_the_rule(self) -> None:
        run = Run(self)
        run.put_chain(canonical_original(port="80810"))
        self.assertEqual(run.standard().returncode, 0)
        self.assertEqual(run.chain()[:2], canonical_rules())

    def test_a_longer_container_port_is_not_taken_for_the_rule(self) -> None:
        rule = program.after_dnat_rule(CONTAINER, CONTAINER_PORT, SOURCE)
        self.assertTrue(rule.matches(canonical_after_dnat()))
        self.assertFalse(rule.matches(canonical_after_dnat(port="80810")))

    def test_a_longer_container_address_is_not_taken_for_the_rule(self) -> None:
        rule = program.after_dnat_rule(CONTAINER, CONTAINER_PORT, SOURCE)
        self.assertFalse(rule.matches(canonical_after_dnat(container="172.29.250.22")))

    def test_a_longer_source_is_not_taken_for_the_rule(self) -> None:
        original = program.original_destination_rule(ADDRESS, PORT, SOURCE)
        after = program.after_dnat_rule(CONTAINER, CONTAINER_PORT, SOURCE)
        self.assertFalse(original.matches(canonical_original(source="10.20.1.500")))
        self.assertFalse(after.matches(canonical_after_dnat(source="10.20.1.500")))
        self.assertTrue(original.matches(canonical_original()))
        self.assertTrue(after.matches(canonical_after_dnat()))

    def test_a_rule_that_allows_the_source_instead_of_dropping_the_rest_is_not_the_rule(
        self,
    ) -> None:
        for rule, line in (
            (
                program.original_destination_rule(ADDRESS, PORT, SOURCE),
                canonical_original().replace("! -s", "-s"),
            ),
            (
                program.after_dnat_rule(CONTAINER, CONTAINER_PORT, SOURCE),
                canonical_after_dnat().replace("! -s", "-s"),
            ),
        ):
            self.assertFalse(rule.matches(line))

    def test_a_rule_that_accepts_is_not_the_rule(self) -> None:
        for rule, line in (
            (program.original_destination_rule(ADDRESS, PORT, SOURCE), canonical_original()),
            (program.after_dnat_rule(CONTAINER, CONTAINER_PORT, SOURCE), canonical_after_dnat()),
        ):
            self.assertFalse(rule.matches(line.replace("-j DROP", "-j ACCEPT")))

    def test_a_rule_for_both_directions_is_not_the_rule(self) -> None:
        both = canonical_original().replace("--ctdir ORIGINAL ", "")
        self.assertFalse(program.original_destination_rule(ADDRESS, PORT, SOURCE).matches(both))

    def test_a_negated_destination_or_port_is_not_the_post_dnat_rule(self) -> None:
        """`! -d` and `! --dport` drop everything else, which leaves the drain port open."""
        rule = program.after_dnat_rule(CONTAINER, CONTAINER_PORT, SOURCE)
        self.assertFalse(rule.matches(canonical_after_dnat().replace("-d ", "! -d ")))
        self.assertFalse(rule.matches(canonical_after_dnat().replace("--dport", "! --dport")))


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

    def refused(self, **replace: str) -> None:
        """Assert the values are refused with status 2 and no call to iptables."""
        run = Run(self)
        result = run.go(*standard_arguments(**replace))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(run.calls(), [])

    def test_a_wildcard_source_is_refused(self) -> None:
        self.refused(allow_source="0.0.0.0")  # noqa: S104 -- the value being refused

    def test_a_network_for_a_source_is_refused(self) -> None:
        self.refused(allow_source="10.20.1.0/24")

    def test_a_loopback_source_is_refused(self) -> None:
        self.refused(allow_source="127.0.0.1")

    def test_a_wildcard_address_is_refused(self) -> None:
        self.refused(address="0.0.0.0")  # noqa: S104 -- the value being refused

    def test_a_wildcard_container_address_is_refused(self) -> None:
        self.refused(container_address="0.0.0.0")  # noqa: S104 -- the value being refused

    def test_a_network_for_the_container_address_is_refused(self) -> None:
        self.refused(container_address="172.29.250.0/29")

    def test_a_privileged_port_is_refused(self) -> None:
        self.refused(port="80")

    def test_a_privileged_container_port_is_refused(self) -> None:
        self.refused(container_port="80")

    def test_a_port_out_of_range_is_refused(self) -> None:
        self.refused(port="65536")

    def test_a_port_that_is_not_a_number_is_refused(self) -> None:
        self.refused(port="8081; reboot")
        self.refused(container_port="8081; reboot")

    def test_a_source_equal_to_the_address_is_refused(self) -> None:
        self.refused(allow_source=ADDRESS)

    def test_a_source_equal_to_the_container_address_is_refused(self) -> None:
        self.refused(allow_source=CONTAINER)

    def test_the_two_addresses_being_one_is_refused(self) -> None:
        self.refused(container_address=ADDRESS)

    def test_a_missing_argument_is_refused(self) -> None:
        run = Run(self)
        result = run.go("--address", ADDRESS, "--port", PORT, "--allow-source", SOURCE)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(run.calls(), [])

    def test_a_hostname_is_refused(self) -> None:
        self.refused(address="edge1")
        self.refused(container_address="receiver")


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
