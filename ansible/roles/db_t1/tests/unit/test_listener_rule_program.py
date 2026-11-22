"""Unit tests for the database port rule program: what it asks iptables, and when it refuses.

The program is run for real, as a child process, with the fake `iptables` and `iptables-restore`
of `netfilter_fake.py` first on its PATH, so a test can say what the program did and did not do.
Nothing here touches a real firewall.
"""

import subprocess
import sys
import unittest
from pathlib import Path

import branchleft_dbt1_listener_rule as program
from netfilter_fake import FakeTable

ROLE = Path(__file__).resolve().parents[2]
PROGRAM = ROLE / "files" / "branchleft_dbt1_listener_rule.py"

SOURCE = "10.20.1.201"
PORT = "3306"
CHAIN = "BRANCHLEFT-DBT1-IN"
ACCEPT = f"-A {CHAIN} -s {SOURCE}/32 -p tcp -m tcp --dport {PORT} -j ACCEPT"
DROP = f"-A {CHAIN} -p tcp -m tcp --dport {PORT} -j DROP"
JUMP = "-A INPUT -j BRANCHLEFT-DBT1-IN"
F2B = "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd"
SSH = "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"


class Run(FakeTable):
    """One run of the program against the fakes."""

    def run(
        self, *extra: str, source: str = SOURCE, port: str = PORT, **env: str
    ) -> subprocess.CompletedProcess[str]:
        """Run the program with the fakes first on PATH; env names are the fakes' switches."""
        return subprocess.run(  # noqa: S603 -- a fixed argument list, the interpreter running the tests
            [sys.executable, str(PROGRAM), "--allow-source", source, "--port", port, *extra],
            capture_output=True,
            text=True,
            check=False,
            env=self.environment(**env),
            timeout=60,
        )


class Apply(unittest.TestCase):
    """What a run does to a table."""

    def test_a_fresh_table_gets_the_chain_in_order_and_the_jump_first(self) -> None:
        run = Run(self)
        run.put(input_rules=[F2B, SSH], chain=None)
        done = run.run()
        self.assertEqual(done.returncode, 0, done.stderr)
        table = run.table()
        self.assertEqual(table["chain"], [ACCEPT, DROP])
        self.assertEqual(table["input"], [JUMP, F2B, SSH])

    def test_the_chain_is_loaded_in_one_restore_that_names_no_other_chain(self) -> None:
        run = Run(self)
        run.put(input_rules=[], chain=None)
        self.assertEqual(run.run().returncode, 0)
        restores = [c for c in run.calls() if c["tool"] == "iptables-restore"]
        self.assertEqual(len(restores), 1)
        text = str(restores[0]["stdin"])
        self.assertEqual(text, program.restore_text(SOURCE, PORT))
        lines = text.splitlines()
        self.assertEqual(lines[0], "*filter")
        # standards-allow-next-line DB-1 COMMIT ends an iptables-restore transaction and is not SQL
        self.assertEqual(lines[-1], "COMMIT")
        for line in lines[1:-1]:
            self.assertIn(CHAIN, line)
        self.assertNotIn("INPUT", text)
        self.assertNotIn("-P ", text)

    def test_only_the_database_port_is_matched(self) -> None:
        run = Run(self)
        self.assertEqual(run.run().returncode, 0)
        for rule in run.table()["chain"] or []:
            self.assertIn(f"--dport {PORT} ", rule + " ")
            self.assertNotIn("--dport 22", rule)
        self.assertEqual(len(run.table()["chain"] or []), 2)

    def test_every_other_source_is_dropped_by_the_last_rule_and_one_source_is_accepted(
        self,
    ) -> None:
        run = Run(self)
        self.assertEqual(run.run().returncode, 0)
        accept, drop = run.table()["chain"] or ["", ""]
        self.assertTrue(accept.endswith("-j ACCEPT"))
        self.assertIn(f"-s {SOURCE}/32", accept)
        self.assertTrue(drop.endswith("-j DROP"))
        self.assertNotIn("-s ", drop)

    def test_a_second_run_changes_nothing_and_writes_nothing(self) -> None:
        run = Run(self)
        run.put(input_rules=[F2B], chain=None)
        self.assertEqual(run.run().returncode, 0)
        before = run.table()
        count = len(run.writes())
        again = run.run()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(run.table(), before)
        self.assertEqual(len(run.writes()), count)

    def test_other_rules_of_input_are_left_exactly_as_they_were(self) -> None:
        run = Run(self)
        run.put(input_rules=[F2B, SSH], chain=None)
        self.assertEqual(run.run().returncode, 0)
        self.assertEqual((run.table()["input"] or [])[1:], [F2B, SSH])

    def test_a_chain_that_admits_another_source_is_corrected_to_the_one(self) -> None:
        run = Run(self)
        stray = f"-A {CHAIN} -s 10.20.1.99/32 -p tcp -m tcp --dport {PORT} -j ACCEPT"
        run.put(input_rules=[JUMP], chain=[stray, DROP])
        self.assertEqual(run.run().returncode, 0)
        self.assertEqual(run.table()["chain"], [ACCEPT, DROP])

    def test_a_chain_with_an_extra_accept_for_everyone_is_corrected(self) -> None:
        run = Run(self)
        everyone = f"-A {CHAIN} -p tcp -m tcp --dport {PORT} -j ACCEPT"
        run.put(input_rules=[JUMP], chain=[ACCEPT, everyone, DROP])
        self.assertEqual(run.run().returncode, 0)
        self.assertEqual(run.table()["chain"], [ACCEPT, DROP])

    def test_the_drop_above_the_accept_is_put_right(self) -> None:
        run = Run(self)
        run.put(input_rules=[JUMP], chain=[DROP, ACCEPT])
        self.assertEqual(run.run().returncode, 0)
        self.assertEqual(run.table()["chain"], [ACCEPT, DROP])

    def test_a_present_chain_with_no_jump_gets_only_the_jump_inserted(self) -> None:
        run = Run(self)
        run.put(input_rules=[F2B], chain=[ACCEPT, DROP])
        self.assertEqual(run.run().returncode, 0)
        self.assertEqual(run.table()["input"], [JUMP, F2B])
        self.assertEqual([c["tool"] for c in run.writes()], ["iptables"])

    def test_a_jump_below_fail2bans_jumps_is_accepted_where_it_is(self) -> None:
        run = Run(self)
        second = "-A INPUT -p tcp -m multiport --dports 2222 -j f2b-sshd-alt"
        run.put(input_rules=[F2B, second, JUMP], chain=[ACCEPT, DROP])
        done = run.run()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(run.writes(), [])

    def test_the_restore_is_not_repeated_when_the_chain_is_already_right(self) -> None:
        run = Run(self)
        run.put(input_rules=[JUMP], chain=[ACCEPT, DROP])
        self.assertEqual(run.run().returncode, 0)
        self.assertEqual(run.writes(), [])


class Check(unittest.TestCase):
    """--check changes nothing and says what a run would change."""

    def test_a_fresh_table_differs_and_the_diff_names_the_chain_the_rules_and_the_jump(
        self,
    ) -> None:
        run = Run(self)
        done = run.run("--check")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.assertIn(f"+ chain {CHAIN}", done.stdout)
        self.assertIn(f"+ {' '.join(program.wanted_rules(SOURCE, PORT)[0])}", done.stdout)
        self.assertIn(f"+ {' '.join(program.wanted_rules(SOURCE, PORT)[1])}", done.stdout)
        self.assertIn(f"+ {JUMP}", done.stdout)
        self.assertEqual(run.writes(), [])
        self.assertEqual(run.table(), {"input": [], "chain": None})

    def test_a_table_that_is_right_exits_zero(self) -> None:
        run = Run(self)
        run.put(input_rules=[JUMP], chain=[ACCEPT, DROP])
        done = run.run("--check")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(run.writes(), [])

    def test_another_admitted_source_is_a_difference_naming_both_rules(self) -> None:
        run = Run(self)
        stray = f"-A {CHAIN} -s 10.20.1.99/32 -p tcp -m tcp --dport {PORT} -j ACCEPT"
        run.put(input_rules=[JUMP], chain=[stray, DROP])
        done = run.run("--check")
        self.assertEqual(done.returncode, 3)
        self.assertIn("- -A BRANCHLEFT-DBT1-IN -s 10.20.1.99/32", done.stdout)
        self.assertIn(f"+ {' '.join(program.wanted_rules(SOURCE, PORT)[0])}", done.stdout)

    def test_a_different_port_is_a_difference(self) -> None:
        run = Run(self)
        run.put(input_rules=[JUMP], chain=[ACCEPT, DROP])
        self.assertEqual(run.run("--check", port="3307").returncode, 3)

    def test_the_wrong_order_is_a_difference(self) -> None:
        run = Run(self)
        run.put(input_rules=[JUMP], chain=[DROP, ACCEPT])
        done = run.run("--check")
        self.assertEqual(done.returncode, 3)
        self.assertIn("not in order", done.stdout)


class Refusals(unittest.TestCase):
    """Anything the program cannot decide, or must not repair, stops it with the table as it was."""

    def refused(self, run: Run, done: subprocess.CompletedProcess[str], fragment: str) -> None:
        """Assert a refusal that wrote nothing."""
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn(fragment, done.stderr)
        self.assertEqual(run.writes(), [])

    def test_a_jump_under_another_rule_is_refused_not_moved(self) -> None:
        for mode in ((), ("--check",)):
            run = Run(self)
            run.put(input_rules=[SSH, JUMP], chain=[ACCEPT, DROP])
            self.refused(run, run.run(*mode), "is rule 2 of INPUT")

    def test_a_second_copy_of_the_jump_is_refused(self) -> None:
        run = Run(self)
        run.put(input_rules=[JUMP, JUMP], chain=[ACCEPT, DROP])
        self.refused(run, run.run(), "2 times")

    def test_a_filter_table_that_cannot_be_read_is_refused(self) -> None:
        run = Run(self)
        self.refused(run, run.run("--retry-delay", "0", FAKE_LIST_EXIT="4"), "exited 4")

    def test_a_missing_iptables_is_refused_and_names_the_role_that_installs_it(self) -> None:
        run = Run(self, tools=("iptables-restore",))
        self.refused(run, run.run(), "iptables is not installed")
        self.assertIn("host_baseline", run.run().stderr)

    def test_a_missing_iptables_restore_is_refused(self) -> None:
        run = Run(self, tools=("iptables",))
        self.refused(run, run.run(), "iptables-restore is not installed")

    def test_a_failed_restore_stops_before_the_jump_and_keeps_its_status(self) -> None:
        run = Run(self)
        done = run.run("--retry-delay", "0", FAKE_RESTORE_EXIT="2")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(run.table(), {"input": [], "chain": None})
        self.assertEqual({c["tool"] for c in run.writes()}, {"iptables-restore"})

    def test_a_failed_insert_is_refused(self) -> None:
        run = Run(self)
        done = run.run("--retry-delay", "0", FAKE_INSERT_EXIT="4")
        self.assertEqual(done.returncode, 4)
        self.assertIn("exited 4", done.stderr)

    def test_a_load_that_did_not_take_effect_is_caught_by_the_read_back(self) -> None:
        run = Run(self)
        done = run.run(FAKE_RESTORE_NOOP="1")
        self.assertEqual(done.returncode, 1)
        self.assertIn("still differs", done.stderr)


def restores(run: Run) -> int:
    """How many restores the program asked for."""
    return len([c for c in run.calls() if c["tool"] == "iptables-restore"])


def listings(run: Run) -> int:
    """How many times the program read the filter table."""
    return len([c for c in run.calls() if c["tool"] == "iptables" and "-S" in str(c["args"])])


class Retries(unittest.TestCase):
    """A boot that meets a transient failure tries again, a bounded number of times."""

    def test_the_attempts_are_five(self) -> None:
        self.assertEqual(program.ATTEMPTS, 5)

    def test_a_restore_that_fails_twice_and_then_works_ends_with_the_rule_loaded(self) -> None:
        run = Run(self)
        run.put(input_rules=[F2B], chain=None)
        done = run.run("--retry-delay", "1", FAKE_RESTORE_FAIL_FIRST="2")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(restores(run), 3)
        self.assertEqual(run.table(), {"input": [JUMP, F2B], "chain": [ACCEPT, DROP]})
        self.assertIn("attempt 1 of 5 failed", done.stderr)
        self.assertIn("trying again in 1s", done.stderr)
        self.assertIn("trying again in 2s", done.stderr)

    def test_a_table_read_that_fails_once_and_then_works_ends_with_the_rule_loaded(self) -> None:
        run = Run(self)
        done = run.run("--retry-delay", "0", FAKE_LIST_FAIL_FIRST="1")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(run.table()["chain"], [ACCEPT, DROP])

    def test_a_restore_that_never_works_is_tried_five_times_and_then_stops_with_its_status(
        self,
    ) -> None:
        run = Run(self)
        done = run.run("--retry-delay", "0", FAKE_RESTORE_EXIT="2")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(restores(run), 5)
        self.assertIn("gave up after 5 attempts", done.stderr)
        self.assertEqual(run.table(), {"input": [], "chain": None})

    def test_a_restore_that_fails_four_times_still_works_on_the_fifth(self) -> None:
        run = Run(self)
        done = run.run("--retry-delay", "0", FAKE_RESTORE_FAIL_FIRST="4")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(restores(run), 5)

    def test_a_restore_that_fails_five_times_is_given_up_on(self) -> None:
        run = Run(self)
        done = run.run("--retry-delay", "0", FAKE_RESTORE_FAIL_FIRST="5")
        self.assertEqual(done.returncode, 4)
        self.assertEqual(restores(run), 5)

    def test_a_refusal_is_never_retried(self) -> None:
        run = Run(self)
        run.put(input_rules=[SSH, JUMP], chain=[ACCEPT, DROP])
        done = run.run("--retry-delay", "0")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(listings(run), 1)

    def test_a_load_that_did_not_take_effect_is_not_retried(self) -> None:
        run = Run(self)
        done = run.run("--retry-delay", "0", FAKE_RESTORE_NOOP="1")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(restores(run), 1)

    def test_check_mode_does_not_retry(self) -> None:
        run = Run(self)
        done = run.run("--check", "--retry-delay", "0", FAKE_LIST_EXIT="4")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(listings(run), 1)

    def test_a_second_run_after_a_recovered_one_changes_nothing(self) -> None:
        run = Run(self)
        self.assertEqual(run.run("--retry-delay", "0", FAKE_RESTORE_FAIL_FIRST="1").returncode, 0)
        before = restores(run)
        self.assertEqual(run.run().returncode, 0)
        self.assertEqual(restores(run), before)


class Arguments(unittest.TestCase):
    """The inputs are checked before anything runs."""

    def bad(self, **kwargs: str) -> None:
        """Assert a status 2 refusal that called no tool at all."""
        run = Run(self)
        done = run.run(**kwargs)
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertEqual(run.calls(), [])

    def test_a_source_that_does_not_name_one_peer_is_refused(self) -> None:
        for value in ("0.0.0.0", "127.0.0.1", "224.0.0.1", "10.20.1.0/24", "10.20.1", "any", ""):  # noqa: S104
            with self.subTest(value):
                self.bad(source=value)

    def test_a_port_outside_the_unprivileged_range_is_refused(self) -> None:
        for value in ("22", "1023", "65536", "0", "-1", "33x", "", "3306 ", "０３３０６"):
            with self.subTest(value):
                self.bad(port=value)

    def test_a_retry_delay_that_is_not_a_whole_number_of_seconds_up_to_thirty_is_refused(
        self,
    ) -> None:
        for value in ("31", "-1", "1.5", "x", "", "٣"):
            with self.subTest(value):
                run = Run(self)
                done = run.run("--retry-delay", value)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertEqual(run.calls(), [])

    def test_a_missing_option_is_refused(self) -> None:
        done = subprocess.run(  # noqa: S603 -- the interpreter running the tests and the role's own file
            [sys.executable, str(PROGRAM), "--port", PORT],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(done.returncode, 2)


class Forms(unittest.TestCase):
    """The pure helpers."""

    def test_a_rule_prints_the_same_whichever_way_iptables_wrote_it(self) -> None:
        plain = program.normal(f"-A {CHAIN} -s {SOURCE} -p tcp --dport {PORT} -j ACCEPT")
        printed = program.normal(ACCEPT)
        self.assertEqual(plain, printed)

    def test_the_two_rules_are_accept_one_source_then_drop_the_rest(self) -> None:
        accept, drop = program.wanted_rules(SOURCE, PORT)
        self.assertEqual(accept[-2:], ("-j", "ACCEPT"))
        self.assertIn(f"{SOURCE}/32", accept)
        self.assertEqual(drop[-2:], ("-j", "DROP"))
        self.assertNotIn("-s", drop)

    def test_the_restore_text_holds_the_chain_and_nothing_else(self) -> None:
        self.assertEqual(
            program.restore_text(SOURCE, PORT).splitlines(),
            [
                "*filter",
                f":{CHAIN} - [0:0]",
                f"-F {CHAIN}",
                f"-A {CHAIN} -s {SOURCE} -p tcp --dport {PORT} -j ACCEPT",
                f"-A {CHAIN} -p tcp --dport {PORT} -j DROP",
                # standards-allow-next-line DB-1 COMMIT ends an iptables-restore transaction, no SQL
                "COMMIT",
            ],
        )


if __name__ == "__main__":
    unittest.main()
