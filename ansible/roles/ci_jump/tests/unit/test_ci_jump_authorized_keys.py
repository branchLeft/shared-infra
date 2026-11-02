"""Unit tests for ci_jump_authorized_keys, the one home of the jump account's key-line rules.

The host is a fake that answers as sshd -T and the passwd database would. Every refusal has a
case that must fail with its own code, and a control that must be accepted beside it, so a
module that refused everything or accepted everything would not pass. Placeholders only: the
keys are made up for the test and no value is a real name. The README gives the command, with
the library directory on PYTHONPATH.
"""

import base64
import unittest
from collections.abc import Callable
from functools import partial

import ci_jump_authorized_keys as jump

HOME = "/home/jumper"
MANAGED = f"{HOME}/.ssh/authorized_keys"
SECOND = f"{HOME}/.ssh/authorized_keys2"
OWNED = {"root": "root", "ci_login": "ansible-ci", "tunnel_account": "dbtunnel"}
NOLOGIN = "/usr/sbin/nologin"


def make_key(number: int, key_type: str = "ssh-ed25519") -> str:
    """Return a well-formed public key made for the test, `number` apart from others."""
    if key_type == "ssh-ed25519":
        fields = [bytes([number]) * 32]
    elif key_type == "ecdsa-sha2-nistp256":
        fields = [b"nistp256", bytes([number]) * 65]
    else:
        fields = [bytes([number]) * 3, bytes([number]) * 256]
    blob = b"".join(len(part).to_bytes(4, "big") + part for part in [key_type.encode(), *fields])
    return f"{key_type} {base64.b64encode(blob).decode('ascii')}"


KEY_A = make_key(1)
KEY_B = make_key(2)
KEY_C = make_key(3)


def body(key: str) -> str:
    """The base64 body of a key."""
    return key.split(" ")[1]


def wanted_line(destinations: list[str], key: str) -> str:
    """The exact line the role must write, spelled out here and not taken from the module."""
    options = ",".join(
        ["restrict", "port-forwarding"] + [f'permitopen="{item}:22"' for item in destinations]
    )
    return f"{options} {key}"


class FakeHost:
    """An in-memory host: accounts, files and the answers of sshd -T."""

    def __init__(self) -> None:
        self.account_list = [
            jump.Account("root", 0, "/root", "/bin/bash"),
            jump.Account("jumper", 1001, HOME, NOLOGIN),
        ]
        self.files: dict[str, str] = {}
        self.settings: dict[str, list[str]] = {
            "allowtcpforwarding": ["yes"],
            "disableforwarding": ["no"],
            "authorizedkeyscommand": ["none"],
            "permitopen": ["any"],
            "authorizedkeysfile": [".ssh/authorized_keys .ssh/authorized_keys2"],
        }
        self.per_user: dict[str, dict[str, list[str]]] = {}
        self.sshd_fails = False
        self.asked: list[str | None] = []

    def accounts(self) -> list[jump.Account]:
        """The accounts."""
        return self.account_list

    def read(self, path: str) -> str | None:
        """The file, or None."""
        return self.files.get(path)

    def sshd_test(self, user: str | None) -> dict[str, list[str]]:
        """The settings, or a failure.

        Raises:
            HostError: when the fake is told sshd fails.
        """
        self.asked.append(user)
        if self.sshd_fails:
            raise jump.HostError
        merged = dict(self.settings)
        if user is not None:
            merged.update(self.per_user.get(user, {}))
        return merged


def refusal_code(call: Callable[[], object]) -> str:
    """Run a call and return the code at the start of its refusal, or "accepted"."""
    try:
        call()
    except jump.RefusalError as error:
        return str(error).split(":")[0]
    return "accepted"


class DestinationTests(unittest.TestCase):
    """Each way a destination can be wrong has its own code; a good list passes."""

    def test_control_host_names_and_addresses_pass(self) -> None:
        listed = ["db-t1", "app-t1.internal.example", "10.0.0.5", "EDGE-T"]
        self.assertEqual(jump.check_destinations(listed), listed)

    def test_each_wrong_form_has_its_own_code(self) -> None:
        cases = {
            "*": "E-DEST-WILDCARD",
            "10.0.0.*": "E-DEST-WILDCARD",
            "db?-t1": "E-DEST-WILDCARD",
            'db-t1"': "E-DEST-QUOTE",
            "db'-t1": "E-DEST-QUOTE",
            "db\\t1": "E-DEST-QUOTE",
            "db-t1,db-t2": "E-DEST-COMMA",
            'db-t1",permitopen="*': "E-DEST-QUOTE",
            "db-t1 db-t2": "E-DEST-SPACE",
            "db-t1\n": "E-DEST-SPACE",
            "db-t1\tx": "E-DEST-SPACE",
            "[::1]": "E-DEST-IPV6",
            "::1": "E-DEST-IPV6",
            "fe80::1": "E-DEST-IPV6",
            "10.0.0.5:22": "E-DEST-PORT",
            "db-t1:2222": "E-DEST-PORT",
            "10.0.0": "E-DEST-SHAPE",
            "300.1.1.1": "E-DEST-SHAPE",
            "-db": "E-DEST-SHAPE",
            "db_t1": "E-DEST-SHAPE",
            "": "E-DEST-SHAPE",
            "!db-t1": "E-DEST-SHAPE",
        }
        for text, code in cases.items():
            with self.subTest(text=text):
                self.assertEqual(refusal_code(partial(jump.check_destinations, [text])), code)

    def test_empty_list_is_refused_and_never_read_as_allow_all(self) -> None:
        self.assertEqual(refusal_code(lambda: jump.check_destinations([])), "E-DEST-EMPTY")
        self.assertEqual(refusal_code(lambda: jump.check_destinations(None)), "E-DEST-EMPTY")

    def test_a_duplicate_is_refused_whatever_its_case(self) -> None:
        self.assertEqual(
            refusal_code(lambda: jump.check_destinations(["db-t1", "DB-T1"])), "E-DEST-DUPLICATE"
        )

    def test_an_entry_that_is_not_text_is_refused(self) -> None:
        self.assertEqual(refusal_code(lambda: jump.check_destinations([22])), "E-DEST-TYPE")

    def test_a_refusal_names_the_entry_and_never_its_text(self) -> None:
        try:
            jump.check_destinations(["db-t1", "EXAMPLE_HOSTILE*"])
        except jump.RefusalError as error:
            self.assertIn("destination 2", str(error))
            self.assertNotIn("EXAMPLE_HOSTILE", str(error))
        else:
            self.fail("the wildcard was accepted")


class KeyTests(unittest.TestCase):
    """A key is one plain public key whose blob decodes to its own type."""

    def test_control_known_types_pass_and_a_comment_is_allowed(self) -> None:
        keys = [KEY_A, make_key(2, "ecdsa-sha2-nistp256"), make_key(3, "ssh-rsa"), f"{KEY_B} x y"]
        parsed = jump.check_keys(keys)
        self.assertEqual(
            [item[0] for item in parsed][:3], ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]
        )
        self.assertEqual(parsed[3], ("ssh-ed25519", body(KEY_B)))

    def test_wrong_shapes_are_refused(self) -> None:
        wrong_type_blob = "ssh-rsa " + body(KEY_A)
        truncated = KEY_A[:-8] + "AAAA"
        cases = {
            "unknown type": "ssh-dss " + body(KEY_A),
            "options in front": 'command="x" ' + KEY_A,
            "restrict in front": "restrict " + KEY_A,
            "type only": "ssh-ed25519",
            "blob of another type": wrong_type_blob,
            "blob not base64": "ssh-ed25519 !!!!",
            "line break": KEY_A + "\n" + KEY_B,
            "carriage return": KEY_A + "\r",
            "tab": KEY_A + "\tx",
            "non ascii": KEY_A + " café",
            "truncated blob": truncated,
            "empty": "",
            "ed25519 of the wrong length": "ssh-ed25519 "
            + base64.b64encode(
                (11).to_bytes(4, "big") + b"ssh-ed25519" + (3).to_bytes(4, "big") + b"abc"
            ).decode(),
        }
        for label, text in cases.items():
            with self.subTest(label=label):
                self.assertEqual(refusal_code(partial(jump.check_keys, [text])), "E-KEY-SHAPE")

    def test_empty_list_is_refused_and_never_read_as_remove_all(self) -> None:
        self.assertEqual(refusal_code(lambda: jump.check_keys([])), "E-KEY-EMPTY")
        self.assertEqual(refusal_code(lambda: jump.check_keys(None)), "E-KEY-EMPTY")

    def test_the_same_key_twice_is_refused_even_with_another_comment(self) -> None:
        self.assertEqual(
            refusal_code(lambda: jump.check_keys([KEY_A, f"{KEY_A} other"])), "E-KEY-DUPLICATE"
        )

    def test_an_entry_that_is_not_text_is_refused(self) -> None:
        self.assertEqual(refusal_code(lambda: jump.check_keys([5])), "E-KEY-TYPE")

    def test_a_refusal_never_carries_the_key(self) -> None:
        try:
            jump.check_keys(["ssh-ed25519 EXAMPLE_NOT_A_KEY"])
        except jump.RefusalError as error:
            self.assertNotIn("EXAMPLE_NOT_A_KEY", str(error))
        else:
            self.fail("a bad key was accepted")


class AccountTests(unittest.TestCase):
    """The account is named, plain, not another role's, present and unable to run a command."""

    def test_control_a_nologin_account_passes(self) -> None:
        host = FakeHost()
        self.assertEqual(jump.check_user("jumper", OWNED), "jumper")
        account = jump.check_account(jump.find_account(host, "jumper"))
        self.assertEqual(account.home, HOME)

    def test_each_wrong_account_has_its_own_code(self) -> None:
        self.assertEqual(refusal_code(lambda: jump.check_user("", OWNED)), "E-USER-EMPTY")
        self.assertEqual(refusal_code(lambda: jump.check_user(None, OWNED)), "E-USER-EMPTY")
        self.assertEqual(refusal_code(lambda: jump.check_user("A B", OWNED)), "E-USER-SHAPE")
        self.assertEqual(refusal_code(lambda: jump.check_user("a,b", OWNED)), "E-USER-SHAPE")
        for name in OWNED.values():
            with self.subTest(name=name):
                self.assertEqual(
                    refusal_code(partial(jump.check_user, name, OWNED)), "E-USER-FORBIDDEN"
                )

    def test_an_absent_account_is_refused_not_made(self) -> None:
        host = FakeHost()
        self.assertEqual(
            refusal_code(lambda: jump.check_account(jump.find_account(host, "ghost"))),
            "E-USER-ABSENT",
        )

    def test_a_shell_that_can_run_a_command_is_refused(self) -> None:
        for shell in ("/bin/bash", "/bin/sh", "/usr/bin/zsh", "", "/usr/sbin/nologinx"):
            with self.subTest(shell=shell):
                account = jump.Account("jumper", 1001, HOME, shell)
                self.assertEqual(refusal_code(partial(jump.check_account, account)), "E-USER-SHELL")
        for shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"):
            with self.subTest(shell=shell):
                jump.check_account(jump.Account("jumper", 1001, HOME, shell))


class SshdTests(unittest.TestCase):
    """What sshd would do to the key line is read before and after the write."""

    def account(self) -> jump.Account:
        """The jump account of the fake host."""
        return jump.Account("jumper", 1001, HOME, NOLOGIN)

    def test_control_the_defaults_pass_and_return_both_key_files(self) -> None:
        files = jump.check_sshd(FakeHost(), self.account())
        self.assertEqual(files, [MANAGED, SECOND])

    def test_forwarding_off_is_refused_in_each_spelling(self) -> None:
        for keyword, value in (
            ("allowtcpforwarding", "no"),
            ("allowtcpforwarding", "remote"),
            ("disableforwarding", "yes"),
        ):
            with self.subTest(keyword=keyword, value=value):
                host = FakeHost()
                host.settings[keyword] = [value]
                self.assertEqual(
                    refusal_code(partial(jump.check_sshd, host, self.account())),
                    "E-SSHD-FORWARDING",
                )

    def test_forwarding_off_by_a_match_block_for_the_user_is_seen(self) -> None:
        host = FakeHost()
        host.per_user["jumper"] = {"allowtcpforwarding": ["no"]}
        self.assertEqual(
            refusal_code(lambda: jump.check_sshd(host, self.account())), "E-SSHD-FORWARDING"
        )
        self.assertIn("jumper", host.asked)

    def test_a_keys_command_is_refused(self) -> None:
        host = FakeHost()
        host.settings["authorizedkeyscommand"] = ["/usr/local/bin/EXAMPLE %u"]
        self.assertEqual(
            refusal_code(lambda: jump.check_sshd(host, self.account())), "E-SSHD-KEYSCOMMAND"
        )

    def test_a_permitopen_of_sshd_is_refused(self) -> None:
        host = FakeHost()
        host.settings["permitopen"] = ["db-t1:22"]
        self.assertEqual(
            refusal_code(lambda: jump.check_sshd(host, self.account())), "E-SSHD-PERMITOPEN"
        )

    def test_a_managed_file_sshd_does_not_read_is_refused(self) -> None:
        host = FakeHost()
        host.settings["authorizedkeysfile"] = ["/etc/ssh/keys/%u"]
        self.assertEqual(refusal_code(lambda: jump.check_sshd(host, self.account())), "E-SSHD-FILE")
        host.settings["authorizedkeysfile"] = ["none"]
        self.assertEqual(refusal_code(lambda: jump.check_sshd(host, self.account())), "E-SSHD-FILE")

    def test_a_second_key_file_with_key_lines_is_refused_and_an_empty_one_is_not(self) -> None:
        host = FakeHost()
        host.files[SECOND] = "# nothing here\n\n"
        jump.check_sshd(host, self.account())
        host.files[SECOND] = KEY_A + "\n"
        self.assertEqual(
            refusal_code(lambda: jump.check_sshd(host, self.account())), "E-SSHD-KEYS2"
        )
        host.files[SECOND] = 'command="x" ' + KEY_A + "\n"
        self.assertEqual(
            refusal_code(lambda: jump.check_sshd(host, self.account())), "E-SSHD-KEYS2"
        )

    def test_sshd_that_cannot_answer_is_a_refusal(self) -> None:
        host = FakeHost()
        host.sshd_fails = True
        self.assertEqual(
            refusal_code(lambda: jump.check_sshd(host, self.account())), "E-SSHD-UNAVAILABLE"
        )

    def test_key_file_tokens_expand_as_sshd_expands_them(self) -> None:
        account = jump.Account("jumper", 1001, HOME, NOLOGIN)
        self.assertEqual(jump.expand_key_file("%h/k/%u", account), f"{HOME}/k/jumper")
        self.assertEqual(jump.expand_key_file("/etc/k/%U%%", account), "/etc/k/1001%")
        self.assertEqual(jump.expand_key_file(".ssh/authorized_keys", account), MANAGED)
        self.assertIsNone(jump.expand_key_file("/etc/k/%z", account))


class RealHostTests(unittest.TestCase):
    """The parser of sshd -T output and the command line the real host runs."""

    def test_sshd_output_is_read_by_keyword_and_the_stand_in_connection_is_asked_for(self) -> None:
        calls: list[list[str]] = []

        def run(command: list[str]) -> tuple[int, str]:
            calls.append(command)
            return (
                0,
                "port 22\npermitopen any\nlistenaddress 192.0.2.10\nlistenaddress 2001:db8::1\n",
            )

        settings = jump.RealHost(run).sshd_test("jumper")
        self.assertEqual(settings["listenaddress"], ["192.0.2.10", "2001:db8::1"])
        self.assertEqual(settings["permitopen"], ["any"])
        self.assertEqual(calls[0][:3], ["/usr/sbin/sshd", "-T", "-C"])
        self.assertEqual(calls[0][3], "user=jumper,host=ci-jump-check.invalid,addr=192.0.2.1")
        calls.clear()
        jump.RealHost(run).sshd_test(None)
        self.assertEqual(calls[0], ["/usr/sbin/sshd", "-T"])

    def test_a_failing_sshd_raises_a_host_error(self) -> None:
        with self.assertRaises(jump.HostError):
            jump.RealHost(lambda _command: (255, "")).sshd_test(None)


class ParserTests(unittest.TestCase):
    """The reader of live lines understands quoted option values and ignores what it cannot read."""

    def parsed(self, text: str) -> jump.KeyLine:
        """Parse a line that must be a key line."""
        line = jump.parse_line(text)
        if line is None:
            self.fail("the line was not read as a key line")
        return line

    def test_options_with_quoted_commas_and_escaped_quotes_are_one_option_each(self) -> None:
        line = self.parsed(
            'restrict,command="a,b \\"c\\" d",permitopen="db-t1:22" ' + KEY_A + " a comment"
        )
        self.assertEqual([name for name, _ in line.options], ["restrict", "command", "permitopen"])
        self.assertEqual(jump.permitopen_set(line), frozenset(["db-t1:22"]))
        self.assertEqual(line.key_type, "ssh-ed25519")
        self.assertEqual(line.body, body(KEY_A))

    def test_a_line_with_no_options_and_the_lines_that_are_not_keys(self) -> None:
        line = self.parsed(KEY_A)
        self.assertEqual(line.options, ())
        self.assertIsNone(jump.parse_line("# a comment"))
        self.assertIsNone(jump.parse_line(""))
        self.assertIsNone(jump.parse_line("not a key line at all"))
        lines, bad = jump.parse_file("# c\n\nrestrict " + KEY_A + "\nnonsense\n")
        self.assertEqual((len(lines), bad), (1, 1))


def live_file(*lines: str) -> str:
    """A file of the given lines."""
    return "\n".join(lines) + "\n"


class PlanTests(unittest.TestCase):
    """The plan judges inputs before the host and shows live against wanted."""

    def host(self) -> FakeHost:
        """A host whose managed file holds one line for each of two destinations."""
        host = FakeHost()
        host.files[MANAGED] = live_file(wanted_line(["db-t1", "app-t1"], KEY_A))
        return host

    def test_control_a_good_plan_shows_each_destination_and_key(self) -> None:
        lines = jump.do_plan(self.host(), "jumper", ["db-t1", "edge-t"], [KEY_A, KEY_B], OWNED)
        text = "\n".join(lines)
        self.assertIn("destination db-t1 port 22 live yes wanted yes", text)
        self.assertIn("destination edge-t port 22 live no wanted yes", text)
        self.assertIn("destination app-t1 live yes wanted no, so it would be removed", text)
        self.assertIn(f"fingerprint {jump.fingerprint(body(KEY_A))} live yes wanted yes", text)
        self.assertIn("live options differ from the wanted options", text)
        self.assertIn(f"fingerprint {jump.fingerprint(body(KEY_B))} live no wanted yes", text)

    def test_a_matching_live_file_says_the_options_match(self) -> None:
        lines = jump.do_plan(self.host(), "jumper", ["db-t1", "app-t1"], [KEY_A], OWNED)
        self.assertIn("live options match the wanted options", "\n".join(lines))

    def test_the_plan_never_prints_a_key_body_or_a_comment(self) -> None:
        host = self.host()
        host.files[MANAGED] += f"{KEY_C} EXAMPLE_COMMENT_TEXT\n"
        text = "\n".join(jump.do_plan(host, "jumper", ["db-t1"], [KEY_A], OWNED))
        for secret in (body(KEY_A), body(KEY_C), "EXAMPLE_COMMENT_TEXT"):
            self.assertNotIn(secret, text)

    def test_inputs_are_refused_before_the_host_is_read(self) -> None:
        host = FakeHost()
        host.sshd_fails = True
        self.assertEqual(
            refusal_code(lambda: jump.do_plan(host, "jumper", ["*"], [KEY_A], OWNED)),
            "E-DEST-WILDCARD",
        )
        self.assertEqual(host.asked, [])

    def test_a_forbidden_or_absent_or_login_account_is_refused(self) -> None:
        host = self.host()
        self.assertEqual(
            refusal_code(lambda: jump.do_plan(host, "root", ["db-t1"], [KEY_A], OWNED)),
            "E-USER-FORBIDDEN",
        )
        self.assertEqual(
            refusal_code(lambda: jump.do_plan(host, "ghost", ["db-t1"], [KEY_A], OWNED)),
            "E-USER-ABSENT",
        )
        host.account_list[1] = jump.Account("jumper", 1001, HOME, "/bin/bash")
        self.assertEqual(
            refusal_code(lambda: jump.do_plan(host, "jumper", ["db-t1"], [KEY_A], OWNED)),
            "E-USER-SHELL",
        )

    def test_a_missing_managed_file_is_planned_as_created(self) -> None:
        host = FakeHost()
        text = "\n".join(jump.do_plan(host, "jumper", ["db-t1"], [KEY_A], OWNED))
        self.assertIn("live file is absent and would be created", text)

    def test_owned_accounts_must_be_a_plain_mapping(self) -> None:
        self.assertEqual(jump.owned_from({"root": "root"}), {"root": "root"})
        self.assertEqual(refusal_code(lambda: jump.owned_from([])), "E-OWNED-SHAPE")
        self.assertEqual(refusal_code(lambda: jump.owned_from({"root": 1})), "E-OWNED-SHAPE")
        self.assertEqual(refusal_code(lambda: jump.owned_from({"root": "A B"})), "E-OWNED-SHAPE")


class VerifyTests(unittest.TestCase):
    """The read-back compares the file with the wanted lines exactly."""

    DESTINATIONS = ["db-t1", "app-t1"]

    def host(self, *lines: str) -> FakeHost:
        """A host whose managed file holds the given lines."""
        host = FakeHost()
        host.files[MANAGED] = live_file(*lines)
        return host

    def verify(self, host: FakeHost) -> list[str]:
        """Verify the host against the two destinations and two keys."""
        return jump.do_verify(host, "jumper", self.DESTINATIONS, [KEY_A, KEY_B], OWNED)

    def good(self) -> list[str]:
        """The two exact lines."""
        return [wanted_line(self.DESTINATIONS, KEY_A), wanted_line(self.DESTINATIONS, KEY_B)]

    def test_control_the_exact_file_is_accepted_in_either_order(self) -> None:
        self.verify(self.host(*self.good()))
        self.verify(self.host(*reversed(self.good())))

    def test_each_way_the_file_can_differ_is_a_mismatch(self) -> None:
        good = self.good()
        cases = {
            "a line removed": [good[0]],
            "an extra key": [*good, wanted_line(self.DESTINATIONS, KEY_C)],
            "an extra destination": [good[0], wanted_line([*self.DESTINATIONS, "edge-t"], KEY_B)],
            "a missing destination": [good[0], wanted_line(["db-t1"], KEY_B)],
            "a wildcard destination": [good[0], wanted_line(["*"], KEY_B)],
            "a command option added": [good[0], 'command="x",' + good[1]],
            "the options removed": [good[0], KEY_B],
            "a comment on the key": [good[0], good[1] + " EXAMPLE"],
            "a comment line": ["# EXAMPLE", *good],
            "a duplicate line": [*good, good[0]],
            "the other port": [good[0], good[1].replace(":22", ":2222", 1)],
        }
        for label, lines in cases.items():
            with self.subTest(label=label):
                self.assertEqual(
                    refusal_code(partial(self.verify, self.host(*lines))),
                    "E-READBACK-MISMATCH",
                )

    def test_a_file_that_cannot_be_read_is_a_mismatch(self) -> None:
        self.assertEqual(refusal_code(lambda: self.verify(FakeHost())), "E-READBACK-MISMATCH")

    def test_sshd_is_read_again_after_the_write(self) -> None:
        host = self.host(*self.good())
        host.settings["allowtcpforwarding"] = ["no"]
        self.assertEqual(refusal_code(lambda: self.verify(host)), "E-SSHD-FORWARDING")


class ReportTests(unittest.TestCase):
    """The report describes what the host holds in a closed vocabulary and never a secret."""

    def host(self) -> FakeHost:
        """A host with the jump account, the pipeline account and an ordinary account."""
        host = FakeHost()
        host.account_list += [
            jump.Account("ansible-ci", 1002, "/home/ansible-ci", "/bin/bash"),
            jump.Account("plain", 1003, "/home/plain", "/bin/bash"),
        ]
        host.files[MANAGED] = live_file(
            wanted_line(["db-t1", "app-t1"], KEY_A), wanted_line(["db-t1", "app-t1"], KEY_B)
        )
        host.files["/home/ansible-ci/.ssh/authorized_keys"] = live_file(
            'restrict,command="sudo /usr/local/sbin/pull-trigger --mode apply" ' + KEY_C
        )
        host.files["/home/plain/.ssh/authorized_keys"] = live_file(KEY_C)
        return host

    def report(self, host: FakeHost) -> str:
        """The report as one text."""
        lines, _ = jump.do_report(host, OWNED)
        return "\n".join(lines)

    def test_it_lists_accounts_with_forwarding_options_and_no_others(self) -> None:
        text = self.report(self.host())
        self.assertIn(
            "account jumper shell /usr/sbin/nologin owned by role none, 2 key line(s)", text
        )
        self.assertIn("account jumper line 1 in authorized_keys key ssh-ed25519 fingerprint", text)
        self.assertIn("permitopen db-t1 port 22", text)
        self.assertIn("account jumper all key lines carry the same permitopen set yes", text)
        self.assertNotIn("account plain", text)
        self.assertNotIn("account root", text)

    def test_a_pipeline_account_is_not_listed_for_a_forced_command_alone(self) -> None:
        self.assertNotIn("ansible-ci", self.report(self.host()))

    def test_it_says_when_the_jump_account_is_the_pipeline_account(self) -> None:
        host = self.host()
        host.files["/home/ansible-ci/.ssh/authorized_keys"] = live_file(
            wanted_line(["db-t1"], KEY_C)
        )
        text = self.report(host)
        self.assertIn("account ansible-ci shell /bin/bash owned by role ci_login", text)

    def test_it_says_when_the_lines_do_not_carry_the_same_destinations(self) -> None:
        host = self.host()
        host.files[MANAGED] = live_file(
            wanted_line(["db-t1", "app-t1"], KEY_A), wanted_line(["db-t1"], KEY_B)
        )
        self.assertIn(
            "account jumper all key lines carry the same permitopen set no", self.report(host)
        )

    def test_it_prints_the_keys_command_and_both_key_files_from_sshd(self) -> None:
        host = self.host()
        host.settings["authorizedkeyscommand"] = ["/usr/local/bin/EXAMPLE_PROGRAM"]
        text = self.report(host)
        self.assertIn("sshd globally AuthorizedKeysCommand /usr/local/bin/EXAMPLE_PROGRAM", text)
        self.assertIn("AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2", text)
        self.assertIn("AllowTcpForwarding yes", text)

    def test_a_key_in_the_second_key_file_is_reported_by_its_file(self) -> None:
        host = self.host()
        host.files[SECOND] = live_file(wanted_line(["edge-t"], KEY_C))
        self.assertIn("in authorized_keys2 key ssh-ed25519", self.report(host))

    def test_it_says_so_when_nothing_carries_forwarding_options(self) -> None:
        host = FakeHost()
        self.assertIn("no account has key lines with forwarding options", self.report(host))

    def test_it_falls_back_to_the_default_files_when_sshd_cannot_answer(self) -> None:
        host = self.host()
        host.sshd_fails = True
        text = self.report(host)
        self.assertIn("sshd -T could not be read", text)
        self.assertIn("account jumper line 1", text)
        self.assertIn("sshd could not be evaluated for this account", text)

    def test_no_key_body_comment_or_option_value_is_printed(self) -> None:
        host = self.host()
        host.files[MANAGED] = live_file(
            'restrict,command="EXAMPLE_COMMAND_VALUE",from="EXAMPLE_FROM_VALUE",'
            'environment="EXAMPLE_ENV_VALUE",weird-option="EXAMPLE_ODD_VALUE",'
            'permitopen="db-t1:22" ' + KEY_A + " EXAMPLE_COMMENT_TEXT"
        )
        text = self.report(host)
        for hidden in (
            body(KEY_A),
            "EXAMPLE_COMMENT_TEXT",
            "EXAMPLE_COMMAND_VALUE",
            "EXAMPLE_FROM_VALUE",
            "EXAMPLE_ENV_VALUE",
            "EXAMPLE_ODD_VALUE",
            "weird-option",
        ):
            self.assertNotIn(hidden, text)
        for shown in (
            "command",
            "from",
            "environment",
            "1 option(s) with a name not in the vocabulary",
        ):
            self.assertIn(shown, text)

    def test_hostile_values_never_read_as_a_credential_assignment(self) -> None:
        host = FakeHost()
        host.account_list[1] = jump.Account("password", 1001, HOME, "/usr/sbin/nologin=EXAMPLE")
        host.files[MANAGED] = live_file(
            'restrict,permitopen="secret:2222",permitopen="token=abcdefgh:22",'
            'command="password=EXAMPLE_VALUE",from="api_key:EXAMPLE_VALUE" ' + KEY_A,
            'permitlisten="credential:12345" ' + KEY_B,
        )
        host.settings["authorizedkeyscommand"] = ["/usr/local/bin/x --secret=EXAMPLE_VALUE"]
        text = self.report(host)
        self.assertNotRegex(text, jump.SCAN_PATTERN)
        self.assertNotIn(jump.WITHHELD_LINE, text)
        self.assertIn("permitopen secret port 2222", text)

    def test_the_last_guard_withholds_a_line_the_scan_would_read(self) -> None:
        self.assertEqual(jump.safe_line("token=abcdefgh"), jump.WITHHELD_LINE)
        self.assertEqual(jump.safe_line("secret: EXAMPLE"), jump.WITHHELD_LINE)
        self.assertEqual(
            jump.safe_line("account jumper shell /usr/sbin/nologin"),
            "account jumper shell /usr/sbin/nologin",
        )

    def test_the_report_returns_the_accounts_as_data(self) -> None:
        _, accounts = jump.do_report(self.host(), OWNED)
        self.assertEqual(
            accounts,
            [
                {
                    "account": "jumper",
                    "shell": NOLOGIN,
                    "owner": "none",
                    "lines": 2,
                    "same_permitopen": True,
                }
            ],
        )


class WantedLineTests(unittest.TestCase):
    """The lines the role must write are the fixed pair, one permitopen each, and the key."""

    def test_the_exact_shape(self) -> None:
        self.assertEqual(
            jump.wanted_options(["db-t1", "10.0.0.5"]),
            'restrict,port-forwarding,permitopen="db-t1:22",permitopen="10.0.0.5:22"',
        )
        self.assertEqual(
            jump.wanted_lines(["db-t1"], [("ssh-ed25519", "AAAA")]),
            ['restrict,port-forwarding,permitopen="db-t1:22" ssh-ed25519 AAAA'],
        )

    def test_the_pinned_values(self) -> None:
        self.assertEqual(jump.PINNED_PORT, 22)
        self.assertEqual(jump.PINNED_FIXED_OPTIONS, ("restrict", "port-forwarding"))


if __name__ == "__main__":
    unittest.main()
