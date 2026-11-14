"""The dead-man revert of the demo host's egress table: no confirm reverts, a confirm does not.

The host is a fake: it keeps a filter table per family, applies a `*filter` ruleset the way
`iptables-restore --noflush` does (a declared chain is emptied, no other chain is touched), and
holds one timer that a test fires by hand. The real iptables and systemd are the Molecule
scenario's. Each test starts from a table an earlier apply confirmed.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import threading
import unittest
from pathlib import Path

import demo_egress_revert as revert
from demo_egress_revert import FAMILIES, Host, RevertError, Store, Table

FORWARD = revert.FORWARD_CHAIN
INPUT = revert.INPUT_CHAIN

DOCKER_OWN = (
    ":DOCKER-USER - [0:0]",
    "-A DOCKER-USER -j RETURN",
    ":FORWARD DROP [0:0]",
    "-A FORWARD -j DOCKER-USER",
)

GOOD = (
    f":{FORWARD} - [7:420]",
    f":{INPUT} - [0:0]",
    f"-A {FORWARD} -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
    f"-A {FORWARD} -i docker0 ! -o docker0 -j REJECT --reject-with icmp-port-unreachable",
    f"-A {FORWARD} -i br-+ ! -o br-+ -j REJECT --reject-with icmp-port-unreachable",
    f"-A {INPUT} -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
    f"-A {INPUT} -j REJECT --reject-with icmp-port-unreachable",
)
GOOD_JUMPS = (
    f"-A DOCKER-USER -j {FORWARD}",
    f"-A INPUT -i docker0 -j {INPUT}",
    f"-A INPUT -i br-+ -j {INPUT}",
)
# A changed table that is still whole: one more rule in the input chain.
CHANGED = (
    *GOOD[:5],
    f"-A {INPUT} -p tcp --dport 9 -j REJECT --reject-with tcp-reset",
    *GOOD[5:],
)
# The table a bad apply could leave: both chains accept everything.
OPEN = (
    f":{FORWARD} - [0:0]",
    f":{INPUT} - [0:0]",
    f"-A {FORWARD} -j ACCEPT",
    f"-A {INPUT} -j ACCEPT",
)
EMPTY: tuple[str, ...] = ()


def chains_of(lines: tuple[str, ...]) -> tuple[str, ...]:
    """Return the lines with the counters of a declaration dropped, as the program reads them."""
    return Table_of(lines).chain_lines


def Table_of(lines: tuple[str, ...]) -> Table:  # noqa: N802
    """Return the program's reading of a list of saved lines."""
    return revert.parse_table("\n".join(lines))


class FakeFailureError(RevertError):
    """A command of the fake host that was told to fail."""

    def __init__(self, what: str) -> None:
        """Name what failed."""
        super().__init__(f"{what} failed")


class FakeHost:
    """A host with a filter table per family and one timer. It satisfies `Host`."""

    def __init__(self) -> None:
        """Start with Docker's chains and the confirmed table in both families."""
        self.lines: dict[str, list[str]] = {}
        for family in FAMILIES:
            self.lines[family] = [*DOCKER_OWN, *GOOD, *GOOD_JUMPS]
        self.timer: int | None = None
        self.fail_restore = False
        self.restores: list[str] = []

    def load(self, own: tuple[str, ...], jumps: tuple[str, ...] = GOOD_JUMPS) -> None:
        """Replace the egress program's part of the table in every family."""
        for family in FAMILIES:
            self.lines[family] = [*DOCKER_OWN, *own, *jumps]

    def save(self, family: str) -> str:
        """Return the table as iptables-save prints it."""
        return "*filter\n" + "\n".join(self.lines[family]) + "\nCOMMIT\n"

    def restore(self, family: str, text: str) -> None:
        """Apply a `*filter` ruleset the way `iptables-restore --noflush` does.

        Raises:
            FakeFailureError: when the test told the host to fail.
        """
        self.restores.append(family)
        if self.fail_restore:
            raise FakeFailureError("iptables-restore")
        wanted = [line.strip() for line in text.splitlines() if line.startswith((":", "-A "))]
        declared = {line.split()[0][1:] for line in wanted if line.startswith(":")}
        kept = [
            line
            for line in self.lines[family]
            if not (
                (line.startswith(":") and line.split()[0][1:] in declared)
                or (line.startswith("-A ") and line.split()[1] in declared)
            )
        ]
        self.lines[family] = [*kept, *wanted]

    def jump_present(self, family: str, rule: str) -> bool:
        """Return whether the jump is in the table."""
        return rule in self.lines[family]

    def insert_jump(self, family: str, rule: str) -> None:
        """Put the jump first among the rules of its chain."""
        chain = rule.split()[1]
        index = next(
            (i for i, line in enumerate(self.lines[family]) if line.startswith(f"-A {chain} ")),
            len(self.lines[family]),
        )
        self.lines[family].insert(index, rule)

    def timer_active(self) -> bool:
        """Return whether the timer waits."""
        return self.timer is not None

    def start_timer(self, seconds: int) -> None:
        """Start the timer.

        Raises:
            FakeFailureError: when a timer of that name already exists, as systemd-run does.
        """
        if self.timer is not None:
            raise FakeFailureError("systemd-run")
        self.timer = seconds

    def stop_timer(self) -> None:
        """Stop the timer."""
        self.timer = None


class RevertTest(unittest.TestCase):
    """Each test runs the program's own `main` against the fake host and a real state dir."""

    def setUp(self) -> None:
        """Make a state directory and a host whose table an earlier apply confirmed."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state_dir = Path(directory.name) / "state"
        self.store = Store(self.state_dir)
        self.host = FakeHost()
        self.assertEqual(self.run_command("confirm"), 0)

    def run_command(self, *argv: str, host: Host | None = None) -> int:
        """Run the program with its output captured and return its exit status."""
        with contextlib.redirect_stdout(io.StringIO()):
            return revert.main(list(argv), host=host or self.host, store=self.store)

    def output_of(self, *argv: str) -> str:
        """Run the program and return what it printed."""
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            revert.main(list(argv), host=self.host, store=self.store)
        return buffer.getvalue()

    def fire(self) -> None:
        """Let the timer run, as systemd does when it elapses: once, then it is gone."""
        if self.host.timer is not None:
            self.host.timer = None
            self.run_command("revert")

    def own_lines(self, family: str = "iptables") -> tuple[str, ...]:
        """Return the egress program's chains of the live table, read as the program reads."""
        return Table_of(tuple(self.host.lines[family])).chain_lines

    def assert_whole_and_closed(self) -> None:
        """Fail unless every family holds both chains, with REJECT, and the jumps."""
        for family in FAMILIES:
            table = Table_of(tuple(self.host.lines[family]))
            self.assertEqual(table.problem(), "", family)
            self.assertFalse(any("ACCEPT" in line for line in table.chain_lines), family)

    # --- the two properties ---------------------------------------------------------------

    def test_no_confirm_means_a_revert(self) -> None:
        """An apply that loads a changed table and never confirms is put back by the timer."""
        self.assertEqual(self.run_command("arm", "--seconds", "300"), 0)
        self.assertEqual(self.host.timer, 300)
        self.host.load(OPEN)
        self.fire()
        for family in FAMILIES:
            self.assertEqual(self.own_lines(family), chains_of(GOOD), family)
        self.assert_whole_and_closed()
        self.assertEqual(self.store.state(), "reverted")

    def test_a_confirm_means_no_revert(self) -> None:
        """An apply that confirms keeps its table: the timer is gone and nothing is put back."""
        self.assertEqual(self.run_command("arm", "--seconds", "300"), 0)
        self.host.load(CHANGED)
        self.assertEqual(self.run_command("confirm"), 0)
        self.assertIsNone(self.host.timer)
        self.fire()
        for family in FAMILIES:
            self.assertEqual(self.own_lines(family), chains_of(CHANGED), family)
        self.assertEqual(self.store.state(), "")
        self.assertEqual(self.store.last_good("iptables"), Table_of(CHANGED + GOOD_JUMPS))

    # --- a revert never leaves an empty or an open table ---------------------------------

    def test_a_failed_restore_leaves_the_table_it_found(self) -> None:
        """A restore that fails changes nothing, and the record is not marked reverted."""
        self.run_command("arm", "--seconds", "300")
        self.host.load(CHANGED)
        self.host.fail_restore = True
        self.fire()
        self.assertEqual(self.own_lines(), chains_of(CHANGED))
        self.assertEqual(self.store.state(), "armed")

    def test_no_known_good_table_means_no_timer_and_no_revert(self) -> None:
        """The first table has nothing earlier: it is not armed, and a revert changes nothing."""
        for name in ("last-good.iptables", "last-good.ip6tables"):
            (self.state_dir / name).unlink()
        self.host.load(CHANGED)
        self.assertEqual(self.run_command("arm", "--seconds", "300"), 0)
        self.assertIsNone(self.host.timer)
        self.assertEqual(self.run_command("revert"), revert.NOTHING_TO_RESTORE)
        self.assertEqual(self.own_lines(), chains_of(CHANGED))
        self.assertEqual(self.host.restores, [])

    def test_a_snapshot_that_is_not_whole_is_never_restored(self) -> None:
        """An empty or REJECT-less snapshot is refused, so a revert cannot open the table."""
        self.host.load(CHANGED)
        for broken in (EMPTY, OPEN, GOOD[:2], GOOD[:5]):
            with self.subTest(broken=broken):
                (self.state_dir / "last-good.iptables").write_text(
                    "".join(f"{line}\n" for line in (*broken, *GOOD_JUMPS)), encoding="utf-8"
                )
                self.assertEqual(self.run_command("revert"), revert.NOTHING_TO_RESTORE)
                self.assertEqual(self.own_lines(), chains_of(CHANGED))
        self.assertEqual(self.host.restores, [])

    def test_a_snapshot_with_no_jump_is_never_restored(self) -> None:
        """A table nothing jumps to would filter nothing, so it is not a known-good one."""
        (self.state_dir / "last-good.iptables").write_text(
            "".join(f"{line}\n" for line in GOOD), encoding="utf-8"
        )
        self.host.load(CHANGED)
        self.assertEqual(self.run_command("revert"), revert.NOTHING_TO_RESTORE)
        self.assertEqual(self.own_lines(), chains_of(CHANGED))

    def test_confirm_refuses_an_open_table_and_the_timer_stays(self) -> None:
        """An apply that loaded an open table cannot confirm it; the timer then reverts it."""
        self.run_command("arm", "--seconds", "300")
        self.host.load(OPEN)
        self.assertEqual(self.run_command("confirm"), revert.FAILED)
        self.assertEqual(self.host.timer, 300)
        self.assertEqual(self.store.last_good("iptables"), Table_of(GOOD + GOOD_JUMPS))
        self.fire()
        self.assertEqual(self.own_lines(), chains_of(GOOD))

    def test_confirm_refuses_an_empty_table(self) -> None:
        """No chains at all is not a table to keep."""
        self.run_command("arm", "--seconds", "300")
        self.host.load(EMPTY, jumps=())
        self.assertEqual(self.run_command("confirm"), revert.FAILED)
        self.assertEqual(self.host.timer, 300)

    def test_a_revert_puts_a_missing_jump_back_first(self) -> None:
        """A bad apply that took the jump out is repaired with the chains."""
        self.run_command("arm", "--seconds", "300")
        self.host.load(OPEN, jumps=())
        self.fire()
        self.assertIn(f"-A DOCKER-USER -j {FORWARD}", self.host.lines["iptables"])
        self.assertLess(
            self.host.lines["iptables"].index(f"-A DOCKER-USER -j {FORWARD}"),
            self.host.lines["iptables"].index("-A DOCKER-USER -j RETURN"),
        )
        self.assert_whole_and_closed()

    def test_a_revert_leaves_every_other_chain_alone(self) -> None:
        """Docker's own chains and rules are not part of a snapshot, so they are not rewritten."""
        self.run_command("arm", "--seconds", "300")
        self.host.load(OPEN)
        self.host.lines["iptables"].append("-A DOCKER-USER -s 192.0.2.1 -j DROP")
        self.fire()
        self.assertIn("-A DOCKER-USER -s 192.0.2.1 -j DROP", self.host.lines["iptables"])
        for line in DOCKER_OWN:
            self.assertIn(line, self.host.lines["iptables"])

    # --- the lock -------------------------------------------------------------------------

    def test_a_revert_waits_for_a_confirm_that_is_running(self) -> None:
        """A confirm and a revert never run at once: the later one waits for the lock.

        The confirm is held inside its lock by a host whose first read blocks. A revert started
        meanwhile must not finish until the confirm is let go. Without the shared lock the
        revert runs at once, and the table it restores is read while the confirm is half done.
        """

        class BlockingHost(FakeHost):
            def __init__(self) -> None:
                """Hold the first read of the table until the test lets it go."""
                super().__init__()
                self.inside = threading.Event()
                self.release = threading.Event()

            def save(self, family: str) -> str:
                """Report that the confirm is inside its lock, then wait to be released."""
                self.inside.set()
                self.release.wait(timeout=10)
                return super().save(family)

        blocking = BlockingHost()
        reverted = threading.Event()

        def confirm_slowly() -> None:
            revert.main(["confirm"], host=blocking, store=self.store)

        def revert_meanwhile() -> None:
            revert.main(["revert"], host=FakeHost(), store=self.store)
            reverted.set()

        with contextlib.redirect_stdout(io.StringIO()):
            first = threading.Thread(target=confirm_slowly)
            second = threading.Thread(target=revert_meanwhile)
            first.start()
            self.assertTrue(blocking.inside.wait(timeout=10))
            second.start()
            waited_while_held = not reverted.wait(timeout=0.5)
            blocking.release.set()
            first.join(timeout=10)
            second.join(timeout=10)
        self.assertTrue(waited_while_held, "the revert ran while the confirm held the lock")
        self.assertTrue(reverted.is_set())

    # --- the record and the timer --------------------------------------------------------

    def test_a_confirm_after_a_revert_is_refused(self) -> None:
        """A slow apply whose timer already fired learns it, and does not call it good."""
        self.run_command("arm", "--seconds", "300")
        self.host.load(OPEN)
        self.fire()
        self.assertEqual(self.run_command("confirm"), revert.FAILED)
        self.assertEqual(self.own_lines(), chains_of(GOOD))
        self.assertEqual(self.store.last_good("iptables"), Table_of(GOOD + GOOD_JUMPS))

    def test_arming_again_replaces_the_timer(self) -> None:
        """Two unconfirmed applies in a row hold one timer, with the later window."""
        self.run_command("arm", "--seconds", "300")
        self.assertEqual(self.run_command("arm", "--seconds", "60"), 0)
        self.assertEqual(self.host.timer, 60)

    def test_the_window_is_bounded(self) -> None:
        """A window of zero, or of a day, is refused and arms nothing."""
        for seconds in ("0", "9", "3601", "86400", "-5"):
            with self.subTest(seconds=seconds):
                self.assertEqual(self.run_command("arm", "--seconds", seconds), revert.FAILED)
                self.assertIsNone(self.host.timer)

    def test_a_timer_that_does_not_start_fails_the_arm(self) -> None:
        """The role must not go on to load a table that has no timer behind it."""

        class NoTimer(FakeHost):
            def start_timer(self, seconds: int) -> None:
                """Accept the call and start nothing."""

        silent = NoTimer()
        self.assertEqual(self.run_command("arm", "--seconds", "300", host=silent), revert.FAILED)

    def test_the_record_is_left_for_the_next_run(self) -> None:
        """Armed, then no confirm: the record stays, so the role applies again."""
        self.run_command("arm", "--seconds", "300")
        self.assertEqual(self.store.state(), "armed")
        self.assertIn("state=armed", self.output_of("status"))

    def test_confirm_reports_a_change_once(self) -> None:
        """The role's second run changes nothing: a confirm of a confirmed table is silent."""
        self.assertIn("confirm: unchanged", self.output_of("confirm"))
        self.run_command("arm", "--seconds", "300")
        self.host.load(CHANGED)
        self.assertIn("confirm: changed", self.output_of("confirm"))
        self.assertIn("confirm: unchanged", self.output_of("confirm"))

    def test_counters_are_not_a_change(self) -> None:
        """Two reads of one table with different packet counts are the same table."""
        first = revert.parse_table("\n".join([f":{FORWARD} - [1:2]", *GOOD[2:], *GOOD_JUMPS]))
        second = revert.parse_table("\n".join([f":{FORWARD} - [9:9]", *GOOD[2:], *GOOD_JUMPS]))
        self.assertEqual(first.chain_lines[0], second.chain_lines[0])


if __name__ == "__main__":
    unittest.main()
