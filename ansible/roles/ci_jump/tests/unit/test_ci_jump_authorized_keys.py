"""Unit tests for ci_jump_authorized_keys, the one home of the jump account's key-line rules.

The host is a fake that answers as sshd -T and the passwd database would. Every refusal has a
case that must fail with its own code, and a control that must be accepted beside it, so a
module that refused everything or accepted everything would not pass. Placeholders only: the
keys are made up for the test and no value is a real name. The README gives the command, with
the library directory on PYTHONPATH.
"""

import base64
import os
import re
import tempfile
import unittest
from collections.abc import Callable
from functools import partial
from pathlib import Path

import ci_jump_authorized_keys as jump

HOME = "/nonexistent"
MANAGED = "/etc/ssh/authorized_keys.d/branchleft-jump"
DROPIN = "/etc/ssh/sshd_config.d/40-branchleft-jump.conf"
OWN = "10.0.0.2"
OWNED = {"root": "root", "ci_login": "ansible-ci", "tunnel_account": "dbtunnel"}
NOLOGIN = "/usr/sbin/nologin"
# The files of the earlier hand-made layout: their paths are made from the account's name, so the
# module is given them and only counts them.
LEGACY = ("/etc/ssh/sshd_config.d/50-branchleft-jumper.conf", "/etc/ssh/jumper/authorized_keys")


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
        ["restrict", "port-forwarding"]
        + [f'permitopen="{item}:22"' for item in destinations]
        + ['command="/usr/sbin/nologin"']
    )
    return f"{options} {key}"


def wanted_dropin(destinations: list[str], user: str = "jumper") -> str:
    """The exact drop-in the role must write, spelled out here and not taken from the module."""
    permit = " ".join(f"{item}:22" for item in destinations)
    return (
        "# Written by the ci_jump role. Change the owner's variables, not this file.\n"
        f"Match User {user}\n"
        "    AuthorizedKeysFile /etc/ssh/authorized_keys.d/branchleft-jump\n"
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


def delivered_settings(destinations: list[str]) -> dict[str, list[str]]:
    """What sshd -T -C prints for the jump account once the role's drop-in is in place."""
    return {
        "authenticationmethods": ["publickey"],
        "authorizedkeyscommand": ["none"],
        "authorizedkeysfile": [MANAGED],
        "allowtcpforwarding": ["local"],
        "disableforwarding": ["no"],
        "gatewayports": ["no"],
        "allowagentforwarding": ["no"],
        "allowstreamlocalforwarding": ["no"],
        "x11forwarding": ["no"],
        "permittty": ["no"],
        "permittunnel": ["no"],
        "permituserrc": ["no"],
        "forcecommand": ["/usr/sbin/nologin"],
        "permitopen": [" ".join(f"{item}:22" for item in destinations)],
    }


def root_file(mode: int = 0o644) -> jump.FileInfo:
    """A regular file owned by root."""
    return jump.FileInfo(0, 0, mode, True, False)


def live_file(*lines: str) -> str:
    """A file of the given lines."""
    return "\n".join(lines) + "\n"


class FakeHost:
    """An in-memory host: accounts, files, their owners and the answers of sshd -T."""

    def __init__(self) -> None:
        self.account_list = [
            jump.Account("root", 0, "/root", "/bin/bash"),
            jump.Account("jumper", 1001, HOME, NOLOGIN),
        ]
        self.files: dict[str, str] = {}
        self.infos: dict[str, jump.FileInfo] = {}
        # The defaults of sshd before the role: forwarding on, the account's home keys.
        self.settings: dict[str, list[str]] = {
            "allowtcpforwarding": ["yes"],
            "disableforwarding": ["no"],
            "authorizedkeyscommand": ["none"],
            "permitopen": ["any"],
            "authorizedkeysfile": [".ssh/authorized_keys .ssh/authorized_keys2"],
        }
        self.per_user: dict[str, dict[str, list[str]]] = {}
        self.sshd_fails = False
        self.asked: list[tuple[str | None, str]] = []

    def put(self, path: str, text: str, info: jump.FileInfo | None = None) -> None:
        """Put a file on the host, root's at 0644 unless told."""
        self.files[path] = text
        self.infos[path] = info or root_file()

    def deliver(self, destinations: list[str], keys: list[str]) -> None:
        """Make the host as a successful run leaves it."""
        self.put(MANAGED, live_file(*[wanted_line(destinations, key) for key in keys]))
        self.put(DROPIN, wanted_dropin(destinations))
        self.infos["/etc/ssh/authorized_keys.d"] = jump.FileInfo(0, 0, 0o755, False, True)
        self.settings = delivered_settings(destinations)

    def accounts(self) -> list[jump.Account]:
        """The accounts."""
        return self.account_list

    def read(self, path: str) -> str | None:
        """The file, or None."""
        return self.files.get(path)

    def info(self, path: str) -> jump.FileInfo | None:
        """The owner and mode, or None."""
        return self.infos.get(path)

    def sshd_test(self, user: str | None, address: str) -> dict[str, list[str]]:
        """The settings, or a failure.

        Raises:
            HostError: when the fake is told sshd fails.
        """
        self.asked.append((user, address))
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


class OwnAddressTests(unittest.TestCase):
    """The destination list must hold the jump host's own address, because the runner reaches
    that host through the jump as well."""

    def test_control_a_list_that_holds_it_passes(self) -> None:
        self.assertEqual(jump.check_own_address(OWN, ["db-t1", OWN]), OWN)
        self.assertEqual(jump.check_own_address(OWN, ["db-t1", "10.0.0.2"]), OWN)

    def test_a_list_without_it_is_refused(self) -> None:
        self.assertEqual(
            refusal_code(lambda: jump.check_own_address(OWN, ["db-t1", "app-t1"])), "E-DEST-OWN"
        )

    def test_an_unset_or_wrong_address_is_refused(self) -> None:
        self.assertEqual(refusal_code(lambda: jump.check_own_address("", [OWN])), "E-OWN-EMPTY")
        self.assertEqual(refusal_code(lambda: jump.check_own_address(None, [OWN])), "E-OWN-EMPTY")
        for text in ("edge1", "10.0.0", "10.0.0.256", "10.0.0.2:22", "::1", "10.0.0.*"):
            with self.subTest(text=text):
                self.assertEqual(
                    refusal_code(partial(jump.check_own_address, text, [text])), "E-OWN-SHAPE"
                )

    def test_control_each_private_range_passes(self) -> None:
        for text in ("10.0.0.2", "10.255.255.254", "172.16.0.1", "172.31.255.1", "192.168.1.9"):
            with self.subTest(text=text):
                self.assertEqual(jump.check_own_address(text, [text]), text)

    def test_a_loopback_address_passes_for_a_test_host(self) -> None:
        self.assertEqual(jump.check_own_address("127.0.0.4", ["127.0.0.4"]), "127.0.0.4")

    def test_an_address_outside_the_private_ranges_is_refused_before_the_list_is_read(self) -> None:
        for text in (
            "203.0.113.5",
            "8.8.8.8",
            "172.15.0.1",
            "172.32.0.1",
            "192.169.0.1",
            "11.0.0.1",
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    refusal_code(partial(jump.check_own_address, text, [text])), "E-OWN-PRIVATE"
                )
        self.assertEqual(
            refusal_code(partial(jump.check_own_address, "203.0.113.5", ["db-t1"])), "E-OWN-PRIVATE"
        )


class EffectiveTests(unittest.TestCase):
    """What sshd says it applies to the account is read after the write, and must be exactly what
    the role means. Remote forwarding is the setting that matters most."""

    DESTINATIONS = ["db-t1", OWN]

    def settings(self) -> dict[str, list[str]]:
        """The settings sshd prints for the delivered account."""
        return delivered_settings(self.DESTINATIONS)

    def check(self, settings: dict[str, list[str]]) -> str:
        """Run the check and return the code of its refusal, or "accepted"."""
        return refusal_code(lambda: jump.check_effective(settings, self.DESTINATIONS))

    def test_control_the_delivered_settings_pass(self) -> None:
        self.assertEqual(self.check(self.settings()), "accepted")

    def test_control_permitopen_may_be_one_line_or_many_and_in_any_order(self) -> None:
        settings = self.settings()
        settings["permitopen"] = [f"{OWN}:22", "DB-T1:22"]
        self.assertEqual(self.check(settings), "accepted")

    def test_forwarding_that_is_not_local_is_refused_in_each_spelling(self) -> None:
        for value in ("yes", "all", "remote", "no"):
            with self.subTest(value=value):
                settings = self.settings()
                settings["allowtcpforwarding"] = [value]
                self.assertEqual(self.check(settings), "E-SSHD-FORWARDING")
        settings = self.settings()
        settings["disableforwarding"] = ["yes"]
        self.assertEqual(self.check(settings), "E-SSHD-FORWARDING")

    def test_a_missing_forwarding_line_is_refused_too(self) -> None:
        settings = self.settings()
        del settings["allowtcpforwarding"]
        self.assertEqual(self.check(settings), "E-SSHD-FORWARDING")

    def test_a_keys_command_is_refused(self) -> None:
        settings = self.settings()
        settings["authorizedkeyscommand"] = ["/usr/local/bin/EXAMPLE %u"]
        self.assertEqual(self.check(settings), "E-SSHD-KEYSCOMMAND")

    def test_a_key_file_other_than_the_managed_one_is_refused(self) -> None:
        for value in (".ssh/authorized_keys", "none", f"{MANAGED} .ssh/authorized_keys"):
            with self.subTest(value=value):
                settings = self.settings()
                settings["authorizedkeysfile"] = [value]
                self.assertEqual(self.check(settings), "E-SSHD-FILE")

    def test_a_permitopen_that_is_not_the_owners_list_is_refused(self) -> None:
        for value in ("any", f"{OWN}:22", f"db-t1:22 {OWN}:22 extra:22", f"db-t1:22 {OWN}:2222"):
            with self.subTest(value=value):
                settings = self.settings()
                settings["permitopen"] = [value]
                self.assertEqual(self.check(settings), "E-SSHD-PERMITOPEN")

    def test_every_other_setting_of_the_runbook_is_held(self) -> None:
        for keyword, bad in (
            ("authenticationmethods", "any"),
            ("gatewayports", "yes"),
            ("allowagentforwarding", "yes"),
            ("allowstreamlocalforwarding", "yes"),
            ("x11forwarding", "yes"),
            ("permittty", "yes"),
            ("permittunnel", "yes"),
            ("permituserrc", "yes"),
            ("forcecommand", "none"),
        ):
            with self.subTest(keyword=keyword):
                settings = self.settings()
                settings[keyword] = [bad]
                self.assertEqual(self.check(settings), "E-SSHD-EFFECTIVE")

    def test_before_the_write_only_what_the_drop_in_cannot_fix_is_refused(self) -> None:
        jump.check_unfixable({"allowtcpforwarding": ["yes"], "authorizedkeyscommand": ["none"]})
        jump.check_unfixable({})
        self.assertEqual(
            refusal_code(lambda: jump.check_unfixable({"disableforwarding": ["yes"]})),
            "E-SSHD-FORWARDING",
        )
        self.assertEqual(
            refusal_code(lambda: jump.check_unfixable({"authorizedkeyscommand": ["/x"]})),
            "E-SSHD-KEYSCOMMAND",
        )

    def test_key_file_tokens_expand_as_sshd_expands_them(self) -> None:
        account = jump.Account("jumper", 1001, "/home/jumper", NOLOGIN)
        self.assertEqual(jump.expand_key_file("%h/k/%u", account), "/home/jumper/k/jumper")
        self.assertEqual(jump.expand_key_file("/etc/k/%U%%", account), "/etc/k/1001%")
        self.assertEqual(
            jump.expand_key_file(".ssh/authorized_keys", account),
            "/home/jumper/.ssh/authorized_keys",
        )
        self.assertIsNone(jump.expand_key_file("/etc/k/%z", account))


class RealHostTests(unittest.TestCase):
    """The parser of sshd -T output, the command line, and the reader that refuses a link."""

    def test_sshd_output_is_read_by_keyword_and_the_connection_is_asked_for(self) -> None:
        calls: list[list[str]] = []

        def run(command: list[str]) -> tuple[int, str]:
            calls.append(command)
            return (
                0,
                "port 22\npermitopen any\nlistenaddress 192.0.2.10\nlistenaddress 2001:db8::1\n",
            )

        settings = jump.RealHost(run).sshd_test("jumper", OWN)
        self.assertEqual(settings["listenaddress"], ["192.0.2.10", "2001:db8::1"])
        self.assertEqual(settings["permitopen"], ["any"])
        self.assertEqual(calls[0][:3], ["/usr/sbin/sshd", "-T", "-C"])
        self.assertEqual(calls[0][3], f"user=jumper,host=jump-check.invalid,addr={OWN}")
        calls.clear()
        jump.RealHost(run).sshd_test(None, OWN)
        self.assertEqual(calls[0], ["/usr/sbin/sshd", "-T"])

    def test_a_failing_sshd_raises_a_host_error(self) -> None:
        with self.assertRaises(jump.HostError):
            jump.RealHost(lambda _command: (255, "")).sshd_test(None, OWN)

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.host = jump.RealHost(lambda _command: (0, ""))

    def test_control_a_regular_file_is_read(self) -> None:
        path = self.root / "keys"
        path.write_text("a line\n", encoding="utf-8")
        self.assertEqual(self.host.read(str(path)), "a line\n")

    def test_a_link_is_refused_even_to_a_good_file(self) -> None:
        target = self.root / "target"
        target.write_text("EXAMPLE_SECRET_TEXT\n", encoding="utf-8")
        link = self.root / "link"
        link.symlink_to(target)
        self.assertIsNone(self.host.read(str(link)))

    def test_a_dangling_link_a_directory_and_a_missing_file_are_refused(self) -> None:
        (self.root / "dangling").symlink_to(self.root / "nowhere")
        (self.root / "dir").mkdir()
        for name in ("dangling", "dir", "missing"):
            with self.subTest(name=name):
                self.assertIsNone(self.host.read(str(self.root / name)))

    def test_a_pipe_is_refused_without_waiting_for_a_writer(self) -> None:
        pipe = self.root / "pipe"
        os.mkfifo(pipe)
        self.assertIsNone(self.host.read(str(pipe)))

    def test_a_file_over_the_limit_is_refused(self) -> None:
        path = self.root / "big"
        path.write_bytes(b"x" * (jump.MAX_FILE_BYTES + 1))
        self.assertIsNone(self.host.read(str(path)))

    def test_info_does_not_follow_a_link(self) -> None:
        target = self.root / "target"
        target.write_text("x", encoding="utf-8")
        link = self.root / "link"
        link.symlink_to(target)
        info = self.host.info(str(link))
        self.assertIsNotNone(info)
        self.assertFalse(info.regular if info else True)
        self.assertIsNone(self.host.info(str(self.root / "missing")))


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


class PlanTests(unittest.TestCase):
    """The plan judges inputs before the host and shows live against wanted."""

    def host(self) -> FakeHost:
        """A host as the runbook's hand-made layout leaves it: the key file and sshd's answer
        for two destinations, and no drop-in of the role's own yet."""
        host = FakeHost()
        host.put(MANAGED, live_file(wanted_line(["db-t1", "app-t1"], KEY_A)))
        host.settings = delivered_settings(["db-t1", "app-t1"])
        return host

    def plan(self, host: FakeHost, **changes: object) -> list[str]:
        """Plan against the host with the good inputs, as changed."""
        arguments: dict[str, object] = {
            "user": "jumper",
            "own": OWN,
            "destinations": ["db-t1", OWN],
            "keys": [KEY_A, KEY_B],
        }
        arguments.update(changes)
        return jump.do_plan(
            host,
            arguments["user"],
            arguments["own"],
            arguments["destinations"],
            arguments["keys"],
            OWNED,
        )

    def test_control_a_good_plan_shows_each_destination_and_key(self) -> None:
        text = "\n".join(self.plan(self.host()))
        self.assertIn("destination db-t1 port 22 key file live yes wanted yes", text)
        self.assertIn("sshd PermitOpen live yes wanted yes", text)
        self.assertIn(f"destination {OWN} port 22 key file live no wanted yes", text)
        self.assertIn("destination app-t1 live yes wanted no, so it would be removed", text)
        self.assertIn(f"fingerprint {jump.fingerprint(body(KEY_A))} live yes wanted yes", text)
        self.assertIn("live options differ from the wanted options", text)
        self.assertIn(f"fingerprint {jump.fingerprint(body(KEY_B))} live no wanted yes", text)
        self.assertIn("sshd drop-in is absent and would be created", text)

    def test_the_drop_in_is_compared_with_the_wanted_text(self) -> None:
        host = self.host()
        host.put(DROPIN, wanted_dropin(["db-t1", OWN]))
        self.assertIn("sshd drop-in is identical to the wanted text", "\n".join(self.plan(host)))
        host.put(DROPIN, wanted_dropin(["db-t1"]))
        self.assertIn("sshd drop-in differs from the wanted text", "\n".join(self.plan(host)))

    def test_a_matching_live_file_says_the_options_match(self) -> None:
        host = self.host()
        host.put(MANAGED, live_file(wanted_line(["db-t1", OWN], KEY_A)))
        self.assertIn("live options match the wanted options", "\n".join(self.plan(host)))

    def test_the_plan_never_prints_the_account_a_key_body_or_a_comment(self) -> None:
        host = self.host()
        host.put(MANAGED, host.files[MANAGED] + f"{KEY_C} EXAMPLE_COMMENT_TEXT\n")
        text = "\n".join(self.plan(host))
        for secret in (body(KEY_A), body(KEY_C), "EXAMPLE_COMMENT_TEXT", "jumper"):
            self.assertNotIn(secret, text)

    def test_inputs_are_refused_before_the_host_is_read(self) -> None:
        host = FakeHost()
        host.sshd_fails = True
        self.assertEqual(
            refusal_code(lambda: self.plan(host, destinations=["*"])), "E-DEST-WILDCARD"
        )
        self.assertEqual(refusal_code(lambda: self.plan(host, own="")), "E-OWN-EMPTY")
        self.assertEqual(
            refusal_code(lambda: self.plan(host, destinations=["db-t1"])), "E-DEST-OWN"
        )
        self.assertEqual(host.asked, [])

    def test_a_forbidden_or_absent_or_login_account_is_refused(self) -> None:
        host = self.host()
        self.assertEqual(refusal_code(lambda: self.plan(host, user="root")), "E-USER-FORBIDDEN")
        self.assertEqual(refusal_code(lambda: self.plan(host, user="ghost")), "E-USER-ABSENT")
        self.assertEqual(refusal_code(lambda: self.plan(host, user="")), "E-USER-EMPTY")
        host.account_list[1] = jump.Account("jumper", 1001, HOME, "/bin/bash")
        self.assertEqual(refusal_code(lambda: self.plan(host)), "E-USER-SHELL")

    def test_sshd_is_asked_about_the_account_from_the_jump_hosts_own_address(self) -> None:
        host = self.host()
        self.plan(host)
        self.assertEqual(host.asked, [("jumper", OWN)])

    def test_sshd_that_cannot_answer_is_a_refusal(self) -> None:
        host = self.host()
        host.sshd_fails = True
        self.assertEqual(refusal_code(lambda: self.plan(host)), "E-SSHD-UNAVAILABLE")

    def test_what_the_drop_in_cannot_fix_is_refused_before_the_write(self) -> None:
        host = self.host()
        host.settings["authorizedkeyscommand"] = ["/usr/local/bin/EXAMPLE"]
        self.assertEqual(refusal_code(lambda: self.plan(host)), "E-SSHD-KEYSCOMMAND")
        host = self.host()
        host.settings["disableforwarding"] = ["yes"]
        self.assertEqual(refusal_code(lambda: self.plan(host)), "E-SSHD-FORWARDING")

    def test_a_missing_key_file_is_planned_as_created(self) -> None:
        text = "\n".join(self.plan(FakeHost()))
        self.assertIn("key file is absent and would be created", text)

    def test_owned_accounts_must_be_a_plain_mapping(self) -> None:
        self.assertEqual(jump.owned_from({"root": "root"}), {"root": "root"})
        self.assertEqual(refusal_code(lambda: jump.owned_from([])), "E-OWNED-SHAPE")
        self.assertEqual(refusal_code(lambda: jump.owned_from({"root": 1})), "E-OWNED-SHAPE")
        self.assertEqual(refusal_code(lambda: jump.owned_from({"root": "A B"})), "E-OWNED-SHAPE")


class VerifyTests(unittest.TestCase):
    """The read-back compares both files with the wanted text exactly, then asks sshd."""

    DESTINATIONS = ["db-t1", OWN]

    def host(self) -> FakeHost:
        """A host as a successful run leaves it."""
        host = FakeHost()
        host.deliver(self.DESTINATIONS, [KEY_A, KEY_B])
        return host

    def verify(self, host: FakeHost) -> list[str]:
        """Verify the host against the two destinations and two keys."""
        return jump.do_verify(host, "jumper", OWN, self.DESTINATIONS, [KEY_A, KEY_B], OWNED)

    def good(self) -> list[str]:
        """The two exact lines."""
        return [wanted_line(self.DESTINATIONS, KEY_A), wanted_line(self.DESTINATIONS, KEY_B)]

    def test_control_the_exact_files_are_accepted_in_either_order(self) -> None:
        host = self.host()
        self.verify(host)
        host.put(MANAGED, live_file(*reversed(self.good())))
        self.verify(host)

    def test_the_result_names_no_account(self) -> None:
        self.assertNotIn("jumper", "\n".join(self.verify(self.host())))

    def test_each_way_the_key_file_can_differ_is_a_mismatch(self) -> None:
        good = self.good()
        cases = {
            "a line removed": [good[0]],
            "an extra key": [*good, wanted_line(self.DESTINATIONS, KEY_C)],
            "an extra destination": [good[0], wanted_line([*self.DESTINATIONS, "edge-t"], KEY_B)],
            "a missing destination": [good[0], wanted_line(["db-t1"], KEY_B)],
            "a wildcard destination": [good[0], wanted_line(["*"], KEY_B)],
            "a command option replaced": [good[0], good[1].replace("/usr/sbin/nologin", "/bin/sh")],
            "the forced command removed": [
                good[0],
                good[1].replace(',command="/usr/sbin/nologin"', ""),
            ],
            "the options removed": [good[0], KEY_B],
            "a comment on the key": [good[0], good[1] + " EXAMPLE"],
            "a comment line": ["# EXAMPLE", *good],
            "a duplicate line": [*good, good[0]],
            "the other port": [good[0], good[1].replace(":22", ":2222", 1)],
        }
        for label, lines in cases.items():
            with self.subTest(label=label):
                host = self.host()
                host.put(MANAGED, live_file(*lines))
                self.assertEqual(refusal_code(partial(self.verify, host)), "E-READBACK-MISMATCH")

    def test_a_drop_in_that_differs_is_a_mismatch(self) -> None:
        host = self.host()
        host.put(DROPIN, wanted_dropin(["db-t1"]))
        self.assertEqual(refusal_code(partial(self.verify, host)), "E-READBACK-MISMATCH")
        host.put(DROPIN, wanted_dropin(self.DESTINATIONS, user="someoneelse"))
        self.assertEqual(refusal_code(partial(self.verify, host)), "E-READBACK-MISMATCH")

    def test_files_that_cannot_be_read_are_a_mismatch(self) -> None:
        for path in (MANAGED, DROPIN):
            with self.subTest(path=path):
                host = self.host()
                del host.files[path]
                self.assertEqual(refusal_code(partial(self.verify, host)), "E-READBACK-MISMATCH")

    def test_the_files_must_be_root_owned_and_closed_to_everyone_else(self) -> None:
        cases = {
            "key file owned by the account": (
                MANAGED,
                jump.FileInfo(1001, 1001, 0o644, True, False),
            ),
            "key file writable by its group": (MANAGED, root_file(0o664)),
            "key file private": (MANAGED, root_file(0o600)),
            "key file a link": (MANAGED, jump.FileInfo(0, 0, 0o644, False, False)),
            "drop-in owned by the account": (DROPIN, jump.FileInfo(1001, 0, 0o644, True, False)),
            "drop-in writable by others": (DROPIN, root_file(0o666)),
            "key directory owned by the account": (
                "/etc/ssh/authorized_keys.d",
                jump.FileInfo(1001, 0, 0o755, False, True),
            ),
            "key directory writable by others": (
                "/etc/ssh/authorized_keys.d",
                jump.FileInfo(0, 0, 0o777, False, True),
            ),
        }
        for label, (path, info) in cases.items():
            with self.subTest(label=label):
                host = self.host()
                host.infos[path] = info
                self.assertEqual(refusal_code(partial(self.verify, host)), "E-READBACK-MISMATCH")

    def test_sshd_is_read_again_after_the_write_and_remote_forwarding_is_refused(self) -> None:
        for value in ("yes", "remote", "no"):
            with self.subTest(value=value):
                host = self.host()
                host.settings["allowtcpforwarding"] = [value]
                self.assertEqual(refusal_code(partial(self.verify, host)), "E-SSHD-FORWARDING")

    def test_a_match_block_that_outranks_the_drop_in_is_seen(self) -> None:
        host = self.host()
        host.per_user["jumper"] = {"allowtcpforwarding": ["yes"]}
        self.assertEqual(refusal_code(partial(self.verify, host)), "E-SSHD-FORWARDING")
        self.assertIn(("jumper", OWN), host.asked)


class MigrationTests(unittest.TestCase):
    """The earlier hand-made files are counted, never named; a write is owed while any remains or
    while a managed file differs; and the final read-back can require them gone."""

    DESTINATIONS = ["db-t1", OWN]
    KEYS = [KEY_A, KEY_B]

    def delivered(self) -> FakeHost:
        host = FakeHost()
        host.deliver(self.DESTINATIONS, self.KEYS)
        return host

    def legacy(self, host: FakeHost) -> None:
        for path in LEGACY:
            host.put(path, "hand-made\n")

    def plan(self, host: FakeHost, legacy: tuple[str, ...] = LEGACY) -> tuple[list[str], bool]:
        return jump.plan_result(host, "jumper", OWN, self.DESTINATIONS, self.KEYS, OWNED, legacy)

    def verify(self, host: FakeHost, gone: bool) -> list[str]:
        return jump.do_verify(
            host, "jumper", OWN, self.DESTINATIONS, self.KEYS, OWNED, LEGACY, gone
        )

    def test_control_a_finished_host_is_not_pending(self) -> None:
        self.assertFalse(self.plan(self.delivered())[1])

    def test_a_host_with_no_managed_files_is_pending(self) -> None:
        host = FakeHost()
        host.settings = delivered_settings(self.DESTINATIONS)
        self.assertTrue(self.plan(host)[1])

    def test_each_way_a_managed_file_differs_is_pending(self) -> None:
        for change in ("key", "dropin", "mode", "directory"):
            with self.subTest(change=change):
                host = self.delivered()
                if change == "key":
                    host.put(MANAGED, live_file(wanted_line(["db-t1"], KEY_A)))
                elif change == "dropin":
                    host.put(DROPIN, wanted_dropin(self.DESTINATIONS) + "# note\n")
                elif change == "mode":
                    host.infos[MANAGED] = root_file(0o664)
                else:
                    del host.infos["/etc/ssh/authorized_keys.d"]
                self.assertTrue(self.plan(host)[1])

    def test_a_legacy_file_alone_keeps_the_host_pending(self) -> None:
        host = self.delivered()
        self.legacy(host)
        self.assertTrue(self.plan(host)[1])
        host = self.delivered()
        host.put(LEGACY[1], "hand-made\n")
        self.assertTrue(self.plan(host)[1])

    def test_the_plan_counts_the_legacy_files_and_prints_no_path_of_them(self) -> None:
        host = self.delivered()
        self.legacy(host)
        text = "\n".join(self.plan(host)[0])
        self.assertIn("2 file(s) of the earlier hand-made layout present", text)
        self.assertNotIn("jumper", text)
        self.assertNotIn(LEGACY[0], text)
        self.assertIn(
            "0 file(s) of the earlier hand-made layout present",
            "\n".join(self.plan(self.delivered())[0]),
        )

    def test_the_final_read_back_requires_the_legacy_files_gone_and_the_first_does_not(
        self,
    ) -> None:
        host = self.delivered()
        self.legacy(host)
        self.verify(host, gone=False)
        self.assertEqual(refusal_code(partial(self.verify, host, True)), "E-LEGACY-PRESENT")
        host.files.pop(LEGACY[0])
        host.infos.pop(LEGACY[0])
        self.assertEqual(refusal_code(partial(self.verify, host, True)), "E-LEGACY-PRESENT")
        host.files.pop(LEGACY[1])
        host.infos.pop(LEGACY[1])
        self.verify(host, gone=True)

    def test_the_refusal_names_no_path_and_no_account(self) -> None:
        host = self.delivered()
        self.legacy(host)
        try:
            self.verify(host, gone=True)
        except jump.RefusalError as error:
            self.assertNotIn("jumper", str(error))
            self.assertNotIn(LEGACY[0], str(error))
        else:
            self.fail("the legacy files were not refused")

    def test_the_legacy_check_is_independent_of_the_managed_files_being_wrong(self) -> None:
        host = self.delivered()
        host.put(MANAGED, live_file(wanted_line(["db-t1"], KEY_A)))
        self.assertEqual(refusal_code(partial(self.verify, host, False)), "E-READBACK-MISMATCH")


class ReportTests(unittest.TestCase):
    """The report describes what the host holds in a closed vocabulary, names no account and
    never prints a secret."""

    LISTED = ["db-t1", OWN]

    def host(self) -> FakeHost:
        """The runbook's layout: the jump account with a root-owned key file outside its home and
        a Match block for it, a pipeline account and an ordinary account."""
        host = FakeHost()
        host.account_list += [
            jump.Account("ansible-ci", 1002, "/home/ansible-ci", "/bin/bash"),
            jump.Account("plain", 1003, "/home/plain", "/bin/bash"),
        ]
        host.per_user["jumper"] = delivered_settings(["db-t1", "app-t1"])
        host.put(
            MANAGED,
            live_file(
                wanted_line(["db-t1", "app-t1"], KEY_A), wanted_line(["db-t1", "app-t1"], KEY_B)
            ),
        )
        host.put(
            "/home/ansible-ci/.ssh/authorized_keys",
            live_file('restrict,command="sudo /usr/local/sbin/pull-trigger --mode apply" ' + KEY_C),
        )
        host.put("/home/plain/.ssh/authorized_keys", live_file(KEY_C))
        host.settings["authorizedkeysfile"] = [".ssh/authorized_keys"]
        return host

    def report(self, host: FakeHost) -> str:
        """The report as one text."""
        lines, _ = jump.do_report(host, OWNED, self.LISTED, OWN)
        return "\n".join(lines)

    def test_it_finds_the_account_through_its_match_block_and_numbers_it(self) -> None:
        text = self.report(self.host())
        self.assertIn(
            "account 1 shell class nologin owned by role none, 2 key line(s) with forwarding"
            " options, key file managed, root-owned yes",
            text,
        )
        self.assertIn("account 1 line 1 key ssh-ed25519 fingerprint", text)
        self.assertIn("permitopen db-t1 port 22", text)
        self.assertIn("account 1 all key lines carry the same permitopen set yes", text)
        self.assertNotIn("account 2", text)

    def test_it_prints_no_account_name_anywhere(self) -> None:
        host = self.host()
        host.account_list.append(jump.Account("tenant-admin", 1004, "/home/t", NOLOGIN))
        host.put("/home/t/.ssh/authorized_keys", live_file(wanted_line(["x"], KEY_C)))
        lines, accounts = jump.do_report(host, OWNED, self.LISTED, OWN)
        everything = "\n".join(lines) + repr(accounts)
        for name in (
            "jumper",
            "tenant-admin",
            "ansible-ci",
            "plain",
            "/root",
            "/home/",
            "someoneelse",
        ):
            self.assertNotIn(name, everything)

    def test_it_says_for_each_destination_whether_the_owners_list_has_it(self) -> None:
        text = self.report(self.host())
        self.assertIn(
            "account 1 destination db-t1 port 22 in key lines yes, in sshd PermitOpen yes,"
            " in the owner's list yes",
            text,
        )
        self.assertIn(
            "account 1 destination app-t1 port 22 in key lines yes, in sshd PermitOpen yes,"
            " in the owner's list no",
            text,
        )
        self.assertIn(
            f"account 1 destination {OWN} is in the owner's list and not in its key lines", text
        )

    def test_it_says_when_sshd_and_the_key_lines_disagree(self) -> None:
        host = self.host()
        host.per_user["jumper"]["permitopen"] = ["db-t1:22 edge-t:22"]
        text = self.report(host)
        self.assertIn("destination edge-t port 22 in key lines no, in sshd PermitOpen yes", text)
        self.assertIn("destination app-t1 port 22 in key lines yes, in sshd PermitOpen no", text)

    def test_a_pipeline_account_is_not_listed_for_a_forced_command_alone(self) -> None:
        self.assertIn("1 carry forwarding options", self.report(self.host()))

    def test_it_says_when_a_pipeline_account_carries_forwarding_options(self) -> None:
        host = self.host()
        host.put("/home/ansible-ci/.ssh/authorized_keys", live_file(wanted_line(["db-t1"], KEY_C)))
        text = self.report(host)
        self.assertIn("owned by role ci_login", text)
        self.assertIn("shell class login", text)

    def test_it_says_when_the_lines_do_not_carry_the_same_destinations(self) -> None:
        host = self.host()
        host.put(
            MANAGED,
            live_file(wanted_line(["db-t1", "app-t1"], KEY_A), wanted_line(["db-t1"], KEY_B)),
        )
        self.assertIn("all key lines carry the same permitopen set no", self.report(host))

    def test_it_says_when_a_key_file_is_not_root_owned_or_not_the_managed_one(self) -> None:
        host = self.host()
        host.infos[MANAGED] = jump.FileInfo(1001, 1001, 0o644, True, False)
        self.assertIn("root-owned no", self.report(host))
        host = self.host()
        host.per_user["jumper"]["authorizedkeysfile"] = [".ssh/authorized_keys"]
        host.put("/nonexistent/.ssh/authorized_keys", live_file(wanted_line(["db-t1"], KEY_A)))
        text = self.report(host)
        self.assertIn("key file other", text)
        self.assertNotIn("nonexistent", text)

    def test_it_prints_the_keys_command_and_forwarding_from_sshd(self) -> None:
        host = self.host()
        host.per_user["jumper"]["authorizedkeyscommand"] = ["/usr/local/bin/EXAMPLE_PROGRAM"]
        text = self.report(host)
        self.assertIn("AuthorizedKeysCommand /usr/local/bin/EXAMPLE_PROGRAM", text)
        self.assertIn("AllowTcpForwarding local", text)

    def test_it_says_so_when_nothing_carries_forwarding_options(self) -> None:
        text = self.report(FakeHost())
        self.assertIn("0 carry forwarding options", text)

    def test_it_counts_the_accounts_sshd_could_not_evaluate(self) -> None:
        host = self.host()
        host.sshd_fails = True
        text = self.report(host)
        self.assertIn("examined 0 account(s), 4 could not be evaluated by sshd", text)

    def test_no_key_body_comment_or_option_value_is_printed(self) -> None:
        host = self.host()
        host.put(
            MANAGED,
            live_file(
                'restrict,command="EXAMPLE_COMMAND_VALUE",from="EXAMPLE_FROM_VALUE",'
                'environment="EXAMPLE_ENV_VALUE",weird-option="EXAMPLE_ODD_VALUE",'
                'permitopen="db-t1:22" ' + KEY_A + " EXAMPLE_COMMENT_TEXT"
            ),
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
        host = self.host()
        host.account_list[1] = jump.Account("password", 1001, HOME, "/usr/sbin/nologin=EXAMPLE")
        host.per_user["password"] = host.per_user.pop("jumper")
        host.per_user["password"]["authorizedkeyscommand"] = [
            "/usr/local/bin/x --secret=EXAMPLE_VALUE"
        ]
        host.put(
            MANAGED,
            live_file(
                'restrict,permitopen="secret:2222",permitopen="token=abcdefgh:22",'
                'command="password=EXAMPLE_VALUE",from="api_key:EXAMPLE_VALUE" ' + KEY_A,
                'permitlisten="credential:12345" ' + KEY_B,
            ),
        )
        text = self.report(host)
        self.assertNotRegex(text, jump.SCAN_PATTERN)
        self.assertNotIn(jump.WITHHELD_LINE, text)
        self.assertIn("permitopen secret port 2222", text)

    def test_the_last_guard_withholds_a_line_the_scan_would_read(self) -> None:
        self.assertEqual(jump.safe_line("token=abcdefgh"), jump.WITHHELD_LINE)
        self.assertEqual(jump.safe_line("secret: EXAMPLE"), jump.WITHHELD_LINE)
        self.assertEqual(
            jump.safe_line("account 1 shell class nologin"), "account 1 shell class nologin"
        )

    def test_the_report_returns_the_accounts_as_data_with_no_name(self) -> None:
        _, accounts = jump.do_report(self.host(), OWNED, self.LISTED, OWN)
        self.assertEqual(
            accounts,
            [
                {
                    "index": 1,
                    "shell_class": "nologin",
                    "owner": "none",
                    "lines": 2,
                    "same_permitopen": True,
                    "allowtcpforwarding": ["local"],
                }
            ],
        )


class WantedTextTests(unittest.TestCase):
    """The lines and the drop-in the role must write, spelled out apart from the module."""

    def test_the_exact_line_shape(self) -> None:
        self.assertEqual(
            jump.wanted_options(["db-t1", "10.0.0.5"]),
            'restrict,port-forwarding,permitopen="db-t1:22",permitopen="10.0.0.5:22",'
            'command="/usr/sbin/nologin"',
        )
        self.assertEqual(
            jump.wanted_lines(["db-t1"], [("ssh-ed25519", "AAAA")]),
            [wanted_line(["db-t1"], "ssh-ed25519 AAAA")],
        )

    def test_the_exact_drop_in(self) -> None:
        self.assertEqual(
            jump.wanted_dropin("jumper", ["db-t1", "10.0.0.5"]),
            wanted_dropin(["db-t1", "10.0.0.5"]),
        )

    def test_the_lines_and_the_drop_in_are_made_from_one_list(self) -> None:
        destinations = ["db-t1", "app-t1", "10.0.0.5"]
        options = jump.wanted_options(destinations)
        dropin = jump.wanted_dropin("jumper", destinations)
        in_keys = re.findall(r'permitopen="([^"]+)"', options)
        permit = next(
            line.split()[1:]
            for line in dropin.splitlines()
            if line.strip().startswith("PermitOpen")
        )
        self.assertEqual(in_keys, permit)
        self.assertEqual(in_keys, [f"{item}:22" for item in destinations])

    def test_the_drop_in_closes_its_match_block(self) -> None:
        self.assertEqual(jump.wanted_dropin("jumper", ["db-t1"]).splitlines()[-1], "Match all")

    def test_the_pinned_values(self) -> None:
        self.assertEqual(jump.PINNED_PORT, 22)
        self.assertEqual(jump.PINNED_FIXED_OPTIONS, ("restrict", "port-forwarding"))
        self.assertEqual(jump.PINNED_COMMAND, "/usr/sbin/nologin")
        self.assertEqual(jump.KEY_FILE, "/etc/ssh/authorized_keys.d/branchleft-jump")
        self.assertEqual(jump.EXPECTED_EFFECTIVE["allowtcpforwarding"], "local")


if __name__ == "__main__":
    unittest.main()
