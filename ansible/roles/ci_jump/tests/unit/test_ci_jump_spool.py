"""Unit tests for the second account of ci_jump: the spool account on edge-t, whose key opens the
spool hosts' private addresses on the far host's ssh port and nothing else.

Two things are held here, and each has its own class.

The CI account's output is the first. The role gained a second account without changing the
first, so the text the module makes for the CI account (its key lines, its drop-in, its plan, its
read-back line and its report) is spelled out below as literal text, as the module made it before
the second account existed. A change that moves one byte of it is red.

The spool account is the second. Every refusal has a case that must fail with its own code and a
control beside it that must be accepted, so a module that refused everything or accepted everything
would not pass. Placeholders only: the keys are made up and no value is a real name.
"""

import unittest
from collections.abc import Callable
from functools import partial

import ci_jump_authorized_keys as jump
from test_ci_jump_authorized_keys import (
    KEY_A,
    KEY_B,
    NOLOGIN,
    OWNED,
    FakeHost,
    body,
    delivered_settings,
    live_file,
    refusal_code,
    root_file,
    wanted_dropin,
    wanted_line,
)

SPOOL_FILE = "/etc/ssh/authorized_keys.d/branchleft-jump-spool"
SPOOL_DROPIN = "/etc/ssh/sshd_config.d/41-branchleft-jump-spool.conf"
OWN = "10.20.1.210"
SPOOL_HOST = "10.20.1.201"
SPOOL_USER = "spool-hopper"
CI_USER = "jumper"
FIXED = "restrict,port-forwarding"
COMMAND = 'command="/usr/sbin/nologin"'


def spool_profile(port: int = 22) -> jump.Profile:
    """The spool profile for a port."""
    return jump.make_profile("spool", port)


def spool_line(destinations: list[str], key: str, port: int = 22) -> str:
    """The exact line the role must write for the spool account, spelled out here."""
    permits = ",".join(f'permitopen="{item}:{port}"' for item in destinations)
    return f"{FIXED},{permits},{COMMAND} {key}"


def spool_dropin(destinations: list[str], user: str = SPOOL_USER, port: int = 22) -> str:
    """The exact drop-in the role must write for the spool account, spelled out here."""
    permit = " ".join(f"{item}:{port}" for item in destinations)
    return (
        "# Written by the ci_jump role. Change the owner's variables, not this file.\n"
        f"Match User {user}\n"
        f"    AuthorizedKeysFile {SPOOL_FILE}\n"
        "    AuthenticationMethods publickey\n"
        "    AllowTcpForwarding local\n"
        f"    PermitOpen {permit}\n"
        "    GatewayPorts no\n"
        "    AllowAgentForwarding no\n"
        "    AllowStreamLocalForwarding no\n"
        "    X11Forwarding no\n"
        "    PermitTTY no\n"
        "    PermitTunnel no\n"
        "    PermitUserRC no\n"
        "    ForceCommand /usr/sbin/nologin\n"
        "Match all\n"
    )


def spool_settings(destinations: list[str], port: int = 22) -> dict[str, list[str]]:
    """What sshd -T -C prints for the spool account once its drop-in is in place."""
    settings = delivered_settings([])
    settings["authorizedkeysfile"] = [SPOOL_FILE]
    settings["permitopen"] = [" ".join(f"{item}:{port}" for item in destinations)]
    return settings


class SpoolHost(FakeHost):
    """The fake host with a second account, and the answers sshd gives for each of the two."""

    def __init__(self) -> None:
        super().__init__()
        self.account_list.append(jump.Account(SPOOL_USER, 1002, "/nonexistent", NOLOGIN))

    def deliver_ci(self, destinations: list[str], keys: list[str]) -> None:
        """Make the host as a successful run for the ci account leaves it, with sshd's answer
        held to that account alone, as a Match block does, and not to every account."""
        defaults = dict(self.settings)
        self.deliver(destinations, keys)
        self.per_user[CI_USER] = self.settings
        self.settings = defaults

    def deliver_spool(self, destinations: list[str], keys: list[str], port: int = 22) -> None:
        """Make the host as a successful run for the spool account leaves it."""
        self.put(SPOOL_FILE, live_file(*[spool_line(destinations, key, port) for key in keys]))
        self.put(SPOOL_DROPIN, spool_dropin(destinations, port=port))
        self.infos["/etc/ssh/authorized_keys.d"] = jump.FileInfo(0, 0, 0o755, False, True)
        self.per_user[SPOOL_USER] = spool_settings(destinations, port)


class CiAccountIsUnchanged(unittest.TestCase):
    """The text made for the CI account is what it was before the second account existed."""

    DESTINATIONS = ["10.0.0.2", "10.0.0.5"]

    def test_the_key_line_options_and_the_drop_in_are_the_old_text(self) -> None:
        self.assertEqual(
            jump.wanted_options(self.DESTINATIONS),
            'restrict,port-forwarding,permitopen="10.0.0.2:22",permitopen="10.0.0.5:22",'
            'command="/usr/sbin/nologin"',
        )
        self.assertEqual(
            jump.wanted_lines(self.DESTINATIONS, [("ssh-ed25519", "AAAA")]),
            [
                'restrict,port-forwarding,permitopen="10.0.0.2:22",permitopen="10.0.0.5:22",'
                'command="/usr/sbin/nologin" ssh-ed25519 AAAA'
            ],
        )
        self.assertEqual(
            jump.wanted_dropin(CI_USER, self.DESTINATIONS),
            wanted_dropin(self.DESTINATIONS, CI_USER),
        )
        self.assertEqual(jump.CI_PROFILE.key_file, "/etc/ssh/authorized_keys.d/branchleft-jump")
        self.assertEqual(
            jump.CI_PROFILE.dropin_file, "/etc/ssh/sshd_config.d/40-branchleft-jump.conf"
        )
        self.assertEqual(jump.CI_PROFILE.port, 22)

    def test_a_delivered_host_plans_and_reads_back_as_before(self) -> None:
        host = FakeHost()
        host.deliver(self.DESTINATIONS, [KEY_A, KEY_B])
        lines, pending = jump.plan_result(
            host, CI_USER, "10.0.0.2", self.DESTINATIONS, [KEY_A, KEY_B], OWNED, ()
        )
        self.assertFalse(pending)
        self.assertEqual(
            lines,
            [
                "ci_jump plan for the jump account: every key line is wanted with the options "
                "restrict, port-forwarding, one permitopen per destination and a forced command, "
                "and sshd gets the same list as its PermitOpen",
                "key file has 2 key line(s) and 0 line(s) not understood, root-owned yes",
                "sshd drop-in is identical to the wanted text",
                "0 file(s) of the earlier hand-made layout present",
                "destination 10.0.0.2 port 22 key file live yes wanted yes, sshd PermitOpen live "
                "yes wanted yes",
                "destination 10.0.0.5 port 22 key file live yes wanted yes, sshd PermitOpen live "
                "yes wanted yes",
                f"key ssh-ed25519 fingerprint {jump.fingerprint(body(KEY_A))} live yes wanted "
                "yes, live options match the wanted options",
                f"key ssh-ed25519 fingerprint {jump.fingerprint(body(KEY_B))} live yes wanted "
                "yes, live options match the wanted options",
            ],
        )
        self.assertEqual(
            jump.do_verify(
                host, CI_USER, "10.0.0.2", self.DESTINATIONS, [KEY_A, KEY_B], OWNED, (), False
            ),
            [
                "ci_jump read back 2 key line(s) and the sshd drop-in, each exactly the wanted "
                "text for 2 destination(s) on port 22; sshd applies local forwarding only, with "
                "the same list as its PermitOpen"
            ],
        )

    def test_the_report_of_a_ci_only_host_is_as_before(self) -> None:
        host = SpoolHost()
        host.account_list.pop()
        host.deliver_ci(self.DESTINATIONS, [KEY_A])
        lines, accounts = jump.do_report(host, OWNED, self.DESTINATIONS, "10.0.0.2")
        self.assertEqual(
            [
                line
                for line in lines
                if line.startswith("account")
                and ("destination" in line or "key file managed" in line)
            ],
            [
                "account 1 shell class nologin owned by role none, 1 key line(s) with "
                "forwarding options, key file managed, root-owned yes",
                "account 1 destination 10.0.0.2 port 22 in key lines yes, in sshd PermitOpen "
                "yes, in the owner's list yes",
                "account 1 destination 10.0.0.5 port 22 in key lines yes, in sshd PermitOpen "
                "yes, in the owner's list yes",
            ],
        )
        self.assertEqual([item["index"] for item in accounts], [1])

    def test_the_ci_profile_pins_its_port_and_takes_no_other(self) -> None:
        self.assertIs(jump.make_profile("ci", 22), jump.CI_PROFILE)
        self.assertEqual(refusal_code(lambda: jump.make_profile("ci", 2222)), "E-PORT-PINNED")

    def test_the_ci_account_still_must_list_the_jump_hosts_own_address(self) -> None:
        self.assertEqual(
            refusal_code(lambda: jump.check_own_address("10.0.0.2", ["10.0.0.5"])), "E-DEST-OWN"
        )
        self.assertEqual(jump.check_own_address("10.0.0.2", ["10.0.0.2"]), "10.0.0.2")


class SpoolProfile(unittest.TestCase):
    """The profile's two files, its port, and the guards that keep its list to the spool hosts."""

    def test_the_spool_account_has_its_own_two_files_and_never_the_ci_accounts(self) -> None:
        profile = spool_profile()
        self.assertEqual(profile.key_file, SPOOL_FILE)
        self.assertEqual(profile.dropin_file, SPOOL_DROPIN)
        self.assertNotIn(profile.key_file, (jump.KEY_FILE, jump.DROPIN_FILE))
        self.assertNotIn(profile.dropin_file, (jump.KEY_FILE, jump.DROPIN_FILE))
        # Neither path is made from an account's name: the names are held out of the repository.
        self.assertNotIn(SPOOL_USER, profile.key_file + profile.dropin_file)

    def test_the_lines_and_the_drop_in_are_spelled_out_and_carry_the_spool_list_only(self) -> None:
        profile = spool_profile()
        self.assertEqual(
            jump.wanted_lines([SPOOL_HOST], [("ssh-ed25519", "AAAA")], profile=profile),
            [spool_line([SPOOL_HOST], "ssh-ed25519 AAAA")],
        )
        self.assertEqual(
            jump.wanted_dropin(SPOOL_USER, [SPOOL_HOST], profile), spool_dropin([SPOOL_HOST])
        )
        text = jump.wanted_dropin(SPOOL_USER, [SPOOL_HOST], profile)
        self.assertIn(f"PermitOpen {SPOOL_HOST}:22\n", text)
        self.assertNotIn(OWN, text)

    def test_the_port_is_the_one_the_owner_names_and_in_both_files(self) -> None:
        profile = spool_profile(2200)
        self.assertEqual(
            jump.wanted_options([SPOOL_HOST], profile),
            f'{FIXED},permitopen="{SPOOL_HOST}:2200",{COMMAND}',
        )
        self.assertIn(
            f"PermitOpen {SPOOL_HOST}:2200\n", jump.wanted_dropin("x-y", [SPOOL_HOST], profile)
        )

    def test_a_port_that_is_not_one_port_number_is_refused(self) -> None:
        for port in (0, -1, 65536, True, "22", None, 22.5):
            with self.subTest(port=port):
                self.assertEqual(
                    refusal_code(partial(jump.make_profile, "spool", port)), "E-PORT-SHAPE"
                )
        self.assertEqual(spool_profile(65535).port, 65535)
        self.assertEqual(spool_profile(1).port, 1)

    def test_an_unknown_profile_is_refused(self) -> None:
        self.assertEqual(refusal_code(lambda: jump.make_profile("other", 22)), "E-PROFILE-UNKNOWN")

    def test_the_jump_hosts_own_address_must_not_be_on_the_spool_list(self) -> None:
        profile = spool_profile()
        self.assertEqual(
            refusal_code(lambda: jump.check_own_address(OWN, [SPOOL_HOST, OWN], profile)),
            "E-SPOOL-OWN",
        )
        # The control: the same call with the own address left off is accepted, and an own
        # address that is not private is still refused as it is for the ci account.
        self.assertEqual(jump.check_own_address(OWN, [SPOOL_HOST], profile), OWN)
        self.assertEqual(
            refusal_code(lambda: jump.check_own_address("8.8.8.8", [SPOOL_HOST], profile)),
            "E-OWN-PRIVATE",
        )
        self.assertEqual(
            refusal_code(lambda: jump.check_own_address("", [SPOOL_HOST], profile)), "E-OWN-EMPTY"
        )

    def test_each_wrong_spool_destination_has_its_own_code(self) -> None:
        cases = {
            "db-t1": "E-SPOOL-ADDRESS",
            "spool.internal.example": "E-SPOOL-ADDRESS",
            "8.8.8.8": "E-SPOOL-ADDRESS",
            "203.0.113.5": "E-SPOOL-ADDRESS",
            "010.020.001.201": "E-SPOOL-ADDRESS",
            "10.020.1.201": "E-SPOOL-ADDRESS",
            "10.20.1": "E-SPOOL-ADDRESS",
            "127.0.0.1": "E-SPOOL-LOOPBACK",
            "127.0.0.9": "E-SPOOL-LOOPBACK",
        }
        for text, code in cases.items():
            with self.subTest(text=text):
                self.assertEqual(
                    refusal_code(partial(jump.check_spool_destinations, [text], False)), code
                )

    def test_control_private_addresses_pass_and_loopback_only_for_a_loopback_jump_host(
        self,
    ) -> None:
        jump.check_spool_destinations(["10.20.1.201", "172.16.0.9", "192.168.4.5"], False)
        jump.check_spool_destinations(["127.0.0.2"], True)

    def test_the_whole_input_check_applies_the_spool_rules_in_order(self) -> None:
        profile = spool_profile()

        def check(
            own: str, destinations: list[str]
        ) -> Callable[[], object]:
            return partial(
                jump._checked_inputs,  # noqa: SLF001
                SPOOL_USER,
                own,
                destinations,
                [KEY_A],
                OWNED,
                profile,
            )

        self.assertEqual(check(OWN, [SPOOL_HOST])()[2], [SPOOL_HOST])
        self.assertEqual(refusal_code(check(OWN, [OWN, SPOOL_HOST])), "E-SPOOL-OWN")
        self.assertEqual(refusal_code(check(OWN, ["db-t1"])), "E-SPOOL-ADDRESS")
        self.assertEqual(refusal_code(check(OWN, ["127.0.0.1"])), "E-SPOOL-LOOPBACK")
        self.assertEqual(refusal_code(check(OWN, [])), "E-DEST-EMPTY")
        # A loopback jump host (a test host) may list a loopback spool address.
        self.assertEqual(check("127.0.0.4", ["127.0.0.2"])()[2], ["127.0.0.2"])
        # The same host with a real jump host's address refuses the loopback one.
        self.assertEqual(refusal_code(check(OWN, ["127.0.0.2"])), "E-SPOOL-LOOPBACK")

    def test_the_spool_account_may_not_be_the_ci_account_or_another_roles(self) -> None:
        owned = {**OWNED, "ci_jump": CI_USER}
        profile = spool_profile()
        self.assertEqual(
            refusal_code(
                lambda: jump._checked_inputs(  # noqa: SLF001
                    CI_USER, OWN, [SPOOL_HOST], [KEY_A], owned, profile
                )
            ),
            "E-USER-FORBIDDEN",
        )
        self.assertEqual(
            jump._checked_inputs(SPOOL_USER, OWN, [SPOOL_HOST], [KEY_A], owned, profile)[0],  # noqa: SLF001
            SPOOL_USER,
        )


class SpoolPlanAndReadBack(unittest.TestCase):
    """The plan shows live against wanted, and the read-back holds sshd to the spool list."""

    def test_a_fresh_host_plans_a_write_and_names_neither_account(self) -> None:
        host = SpoolHost()
        lines, pending = jump.plan_result(
            host, SPOOL_USER, OWN, [SPOOL_HOST], [KEY_A], OWNED, (), spool_profile()
        )
        self.assertTrue(pending)
        text = "\n".join(lines)
        self.assertIn("ci_jump plan for the spool account", text)
        self.assertIn("key file is absent and would be created", text)
        self.assertIn("sshd drop-in is absent and would be created", text)
        self.assertIn(f"destination {SPOOL_HOST} port 22 key file live no wanted yes", text)
        self.assertNotIn("earlier hand-made layout", text)
        self.assertNotIn(SPOOL_USER, text)

    def test_a_delivered_host_reads_back_and_is_not_pending(self) -> None:
        host = SpoolHost()
        host.deliver_spool([SPOOL_HOST], [KEY_A])
        profile = spool_profile()
        lines, pending = jump.plan_result(
            host, SPOOL_USER, OWN, [SPOOL_HOST], [KEY_A], OWNED, (), profile
        )
        self.assertFalse(pending)
        self.assertIn("sshd drop-in is identical to the wanted text", lines)
        verified = jump.do_verify(
            host, SPOOL_USER, OWN, [SPOOL_HOST], [KEY_A], OWNED, (), False, profile
        )
        self.assertEqual(len(verified), 1)
        self.assertIn("for 1 destination(s) on port 22", verified[0])

    def test_the_two_accounts_are_judged_against_their_own_files(self) -> None:
        host = SpoolHost()
        host.deliver(["10.20.1.210", "10.20.1.200"], [KEY_A])
        host.deliver_spool([SPOOL_HOST], [KEY_B])
        ci = ["10.20.1.210", "10.20.1.200"]
        jump.do_verify(host, CI_USER, OWN, ci, [KEY_A], OWNED, (), False)
        jump.do_verify(
            host, SPOOL_USER, OWN, [SPOOL_HOST], [KEY_B], OWNED, (), False, spool_profile()
        )
        # Each account read through the other's profile is not what was written.
        self.assertEqual(
            refusal_code(
                lambda: jump.check_files(
                    host, CI_USER, ci, [("ssh-ed25519", body(KEY_A))], profile=spool_profile()
                )
            ),
            "E-READBACK-MISMATCH",
        )

    def test_control_sshd_applying_exactly_the_spool_list_is_accepted(self) -> None:
        jump.check_effective(spool_settings([SPOOL_HOST]), [SPOOL_HOST], spool_profile())

    def test_sshd_allowing_a_destination_off_the_spool_list_is_refused(self) -> None:
        # This is the module's read-back of a destination that is not on the list: sshd's own
        # answer holds one more address than the owner's list, or another port.
        wider = spool_settings([SPOOL_HOST, "10.20.1.200"])
        self.assertEqual(
            refusal_code(lambda: jump.check_effective(wider, [SPOOL_HOST], spool_profile())),
            "E-SSHD-PERMITOPEN",
        )
        other_port = spool_settings([SPOOL_HOST], 2200)
        self.assertEqual(
            refusal_code(lambda: jump.check_effective(other_port, [SPOOL_HOST], spool_profile())),
            "E-SSHD-PERMITOPEN",
        )
        unlimited = spool_settings([SPOOL_HOST])
        unlimited["permitopen"] = ["any"]
        self.assertEqual(
            refusal_code(lambda: jump.check_effective(unlimited, [SPOOL_HOST], spool_profile())),
            "E-SSHD-PERMITOPEN",
        )

    def test_remote_forwarding_is_refused_for_the_spool_account_too(self) -> None:
        settings = spool_settings([SPOOL_HOST])
        settings["allowtcpforwarding"] = ["yes"]
        self.assertEqual(
            refusal_code(lambda: jump.check_effective(settings, [SPOOL_HOST], spool_profile())),
            "E-SSHD-FORWARDING",
        )

    def test_sshd_naming_the_ci_key_file_for_the_spool_account_is_refused(self) -> None:
        settings = spool_settings([SPOOL_HOST])
        settings["authorizedkeysfile"] = [jump.KEY_FILE]
        self.assertEqual(
            refusal_code(lambda: jump.check_effective(settings, [SPOOL_HOST], spool_profile())),
            "E-SSHD-FILE",
        )

    def test_a_file_that_is_not_exactly_the_wanted_text_is_a_mismatch(self) -> None:
        host = SpoolHost()
        host.deliver_spool([SPOOL_HOST], [KEY_A])
        host.put(SPOOL_FILE, live_file(spool_line([SPOOL_HOST, "10.20.1.200"], KEY_A)))
        self.assertEqual(
            refusal_code(
                lambda: jump.check_files(
                    host, SPOOL_USER, [SPOOL_HOST], [("ssh-ed25519", body(KEY_A))], profile=spool_profile()
                )
            ),
            "E-READBACK-MISMATCH",
        )
        host.deliver_spool([SPOOL_HOST], [KEY_A])
        host.put(SPOOL_DROPIN, spool_dropin([SPOOL_HOST]), root_file(0o666))
        self.assertEqual(
            refusal_code(
                lambda: jump.check_files(
                    host, SPOOL_USER, [SPOOL_HOST], [("ssh-ed25519", body(KEY_A))], profile=spool_profile()
                )
            ),
            "E-READBACK-MISMATCH",
        )


class SpoolReport(unittest.TestCase):
    """The report reads the spool account's key file as a managed one, with its own port."""

    def test_both_accounts_are_reported_as_managed_and_by_index_only(self) -> None:
        host = SpoolHost()
        ci = ["10.20.1.210", "10.20.1.200"]
        host.deliver_ci(ci, [KEY_A])
        host.deliver_spool([SPOOL_HOST], [KEY_B])
        lines, accounts = jump.do_report(host, OWNED, [*ci, SPOOL_HOST], OWN)
        text = "\n".join(lines)
        self.assertEqual(text.count("key file managed"), 2)
        self.assertEqual(text.count("AuthorizedKeysFile managed"), 2)
        self.assertIn(
            f"destination {SPOOL_HOST} port 22 in key lines yes, in sshd PermitOpen yes, "
            "in the owner's list yes",
            text,
        )
        self.assertNotIn(SPOOL_USER, text)
        self.assertNotIn(CI_USER, text)
        self.assertEqual(len([a for a in accounts if a["shell_class"] == "nologin"]), 2)

    def test_a_spool_port_that_is_not_22_is_printed_as_it_is(self) -> None:
        host = SpoolHost()
        host.deliver_spool([SPOOL_HOST], [KEY_B], 2200)
        lines, _ = jump.do_report(host, OWNED, [SPOOL_HOST], OWN)
        self.assertIn(f"destination {SPOOL_HOST} port 2200 in key lines yes", "\n".join(lines))


class SpoolLinesNameNoOne(unittest.TestCase):
    """What the module prints is made of the closed vocabulary: no account, no key body."""

    def test_the_plan_and_the_read_back_hold_no_name_and_no_key(self) -> None:
        host = SpoolHost()
        host.deliver_spool([SPOOL_HOST], [KEY_A])
        profile = spool_profile()
        lines, _ = jump.plan_result(
            host, SPOOL_USER, OWN, [SPOOL_HOST], [KEY_A], OWNED, (), profile
        )
        lines += jump.do_verify(
            host, SPOOL_USER, OWN, [SPOOL_HOST], [KEY_A], OWNED, (), False, profile
        )
        text = "\n".join(lines)
        self.assertNotIn(SPOOL_USER, text)
        self.assertNotIn(body(KEY_A), text)

    def test_a_refusal_carries_a_code_and_never_a_value(self) -> None:
        try:
            jump.check_spool_destinations(["EXAMPLE_HOSTILE_NAME"], False)
        except jump.RefusalError as error:
            self.assertTrue(str(error).startswith("E-SPOOL-ADDRESS: destination 1"))
            self.assertNotIn("EXAMPLE_HOSTILE_NAME", str(error))
        else:
            self.fail("a host name was accepted")
        # The spool profile's wanted line is the wanted text for no one but its own list.
        self.assertEqual(wanted_line([SPOOL_HOST], KEY_A).count("permitopen"), 1)


class SpoolKeyOwnList(unittest.TestCase):
    """A spool key may carry a list of its own, which must be a subset of the spool list."""

    SPOOL_LIST = ["10.20.1.201", "10.20.1.202"]

    def test_a_spool_key_with_a_narrower_list_is_accepted(self) -> None:
        keys = [{"key": KEY_A, "destinations": ["10.20.1.201"]}]
        self.assertEqual(
            refusal_code(
                lambda: jump._checked_inputs(  # noqa: SLF001
                    SPOOL_USER, OWN, self.SPOOL_LIST, keys, OWNED, spool_profile()
                )
            ),
            "accepted",
        )
        parsed = jump._checked_inputs(  # noqa: SLF001
            SPOOL_USER, OWN, self.SPOOL_LIST, keys, OWNED, spool_profile()
        )
        self.assertEqual(parsed[4], [["10.20.1.201"]])

    def test_a_spool_key_with_a_wider_list_is_refused(self) -> None:
        keys = [{"key": KEY_A, "destinations": ["10.20.1.201", "10.20.1.203"]}]
        self.assertEqual(
            refusal_code(
                lambda: jump._checked_inputs(  # noqa: SLF001
                    SPOOL_USER, OWN, self.SPOOL_LIST, keys, OWNED, spool_profile()
                )
            ),
            "E-SPOOL-KEY-WIDER",
        )

    def test_a_spool_key_with_no_list_keeps_the_spool_list(self) -> None:
        keys = [KEY_A]
        parsed = jump._checked_inputs(  # noqa: SLF001
            SPOOL_USER, OWN, self.SPOOL_LIST, keys, OWNED, spool_profile()
        )
        self.assertEqual(parsed[4], [None])


if __name__ == "__main__":
    unittest.main()
