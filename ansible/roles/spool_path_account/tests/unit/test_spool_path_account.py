"""Tests that hold the far-host account to the design: one key, one port, no command.

Four things are judged, none against a host. The listener check, which reads where the drain port
listens. The role's own input and write tasks, taken from `tasks/main.yml` as shipped and run with
Ansible against a scratch tree. The settings the rendered sshd file gives the account, read back
with a real `sshd -T`. And the key line it writes, used against a real sshd on a loopback port: it
may open the drain port and no other, may not be used from another address, and runs no command.

Each control a test names was run red on a sabotaged copy and green on the file as shipped (the
pull request records both).
"""

import grp
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from getpass import getuser
from pathlib import Path
from typing import cast

import spool_path_listener_check as listener
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
LOOPBACK = "127.0.0.1"
RUN_SECONDS = 120
FROM = "198.51.100.7"
WILDCARD = "0.0.0" + ".0"
BODY = "AAAAC3NzaC1lZDI1NTE5AAAAI" + "Fake" * 10 + "Fak"
PUBLIC_KEY = f"ssh-ed25519 {BODY}"
# The tasks that read the inputs and write the files, by the start of their names. The tasks that
# need a real account database, a real sshd service or a real listener are left to the Molecule
# scenario and to the read-back on the host.
TASK_STARTS = (
    "Refuse a drain port that is not a whole number",
    "Look at the inputs directory's parent",
    "Refuse a parent",
    "Refuse an inputs directory",
    "Look at each input file",
    "Note which inputs",
    "Refuse one input",
    "Refuse an input file",
    "Remove the account's key file",
    "Read the inputs into memory",
    "Hold the inputs by name",
    "Refuse a from address",
    "Refuse a public key",
    "Make the directory of the account's key file",
    "Write the account's key and sshd settings",
)
# The tasks inside that block the scratch run leaves out: the whole-configuration check needs the
# host's own sshd keys, so the real sshd test below reads the rendered file instead.
LEFT_OUT = ("Check the whole sshd configuration",)


def tool(name: str, candidates: tuple[str, ...]) -> str:
    """Return the path of a program that must exist, or fail the test.

    Raises:
        AssertionError: when it is nowhere, which is a failure and never a skip.
    """
    found = shutil.which(name)
    if found is not None:
        return found
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    message = f"{name} is needed for this test and was not found"
    raise AssertionError(message)


def reap(process: "subprocess.Popen[str] | subprocess.Popen[bytes]") -> None:
    """Kill a process the test started, wait for it and close its pipes."""
    if process.poll() is None:
        process.kill()
    process.wait()
    if process.stderr is not None:
        process.stderr.close()


def free_port() -> int:
    """Return a loopback port nothing is listening on."""
    with socket.socket() as probe:
        probe.bind((LOOPBACK, 0))
        return int(probe.getsockname()[1])


class ListenerCheck(unittest.TestCase):
    """The listener check reads `ss -H -ltn` and says whether the bind is loopback only."""

    LOOPBACK_ONLY = "LISTEN 0 4096 127.0.0.1:8095 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"

    def test_a_loopback_bind_is_accepted(self) -> None:
        found = listener.parse(self.LOOPBACK_ONLY, 8095, LOOPBACK)
        self.assertEqual((found.loopback, found.others), (True, []))

    # Control: the wildcard bind is named. Red when the check ignores any address but the loopback.
    def test_a_wildcard_bind_is_named(self) -> None:
        text = self.LOOPBACK_ONLY + "LISTEN 0 4096 0.0.0.0:8095 0.0.0.0:*\n"
        found = listener.parse(text, 8095, LOOPBACK)
        self.assertEqual((found.loopback, found.others), (True, [WILDCARD]))

    def test_a_public_or_v6_bind_is_named(self) -> None:
        text = (
            "LISTEN 0 4096 192.0.2.5:8095 0.0.0.0:*\n"
            "LISTEN 0 4096 *:8095 *:*\n"
            "LISTEN 0 4096 [::]:8095 [::]:*\n"
        )
        found = listener.parse(text, 8095, LOOPBACK)
        self.assertEqual((found.loopback, found.others), (False, ["*", "192.0.2.5", "[::]"]))

    def test_no_listener_is_not_loopback(self) -> None:
        found = listener.parse("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", 8095, LOOPBACK)
        self.assertEqual((found.loopback, found.others), (False, []))

    def test_a_port_that_only_ends_the_same_is_not_matched(self) -> None:
        found = listener.parse("LISTEN 0 4096 0.0.0.0:18095 0.0.0.0:*\n", 8095, LOOPBACK)
        self.assertEqual((found.loopback, found.others), (False, []))


def clean(task: dict[str, object], *, keep_check: bool = False) -> dict[str, object]:
    """Return the task, and any task inside it, adjusted only for a scratch run.

    The whole-configuration check needs the host's own sshd keys, so it is left out unless a test
    keeps it, to run it against a stand-in that refuses and watch the rollback.
    """
    for key, value in list(task.items()):
        if isinstance(value, dict):
            value.pop("owner", None)
            value.pop("group", None)
            source = value.get("src")
            if key == "ansible.builtin.template" and isinstance(source, str):
                value["src"] = str(ROLE / "templates" / source)
    task.pop("notify", None)
    inner = task.get("block")
    if isinstance(inner, list):
        task["block"] = [
            clean(item, keep_check=keep_check)
            for item in inner
            if keep_check or not str(item.get("name", "")).startswith(LEFT_OUT)
        ]
        if keep_check:
            rescue = cast("list[dict[str, object]]", task.get("rescue", []))
            task["rescue"] = [clean(item, keep_check=True) for item in rescue]
        else:
            task.pop("rescue", None)
    return task


def play_tasks(*, as_current_user: bool, keep_check: bool = False) -> list[dict[str, object]]:
    """Return the role's input and write tasks as shipped, adjusted only for a scratch run.

    A scratch tree belongs to whoever runs the test, so the owner and group the role sets are
    dropped and, when asked, the checks for root's ownership name the current user instead. A test
    of a refusal that is not about ownership uses that, so the check itself is exercised unchanged
    by the rest.
    """
    loaded = cast(
        "list[dict[str, object]]", YAML(typ="safe").load(TASKS.read_text(encoding="utf-8"))
    )
    picked = [
        clean(task, keep_check=keep_check)
        for task in loaded
        if str(task.get("name", "")).startswith(TASK_STARTS)
    ]
    if as_current_user:
        group = grp.getgrgid(os.getgid()).gr_name
        text = json.dumps(picked)
        text = text.replace("pw_name == 'root'", f"pw_name == '{getuser()}'")
        text = text.replace("gr_name == 'root'", f"gr_name == '{group}'")
        text = text.replace("stat.uid == 0", f"stat.uid == {os.getuid()}")
        picked = cast("list[dict[str, object]]", json.loads(text))
    return picked


class Result:
    """What one run of the play did."""

    def __init__(self, returncode: int, output: str) -> None:
        self.returncode = returncode
        self.output = output

    @property
    def failed(self) -> bool:
        """Whether the run stopped."""
        return self.returncode != 0

    def recap(self, name: str) -> int:
        """Return the number in the recap line for the name, such as changed."""
        recap = [line for line in self.output.splitlines() if line.startswith("localhost ")][-1]
        return int(recap.split(f"{name}=", 1)[1].split()[0])


class Scratch:
    """A scratch tree standing in for the far host, and the play that runs the role's tasks."""

    def __init__(self, test: unittest.TestCase) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="spool-path-account-"))
        test.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.parent = self.home / "branchleft"
        self.inputs = self.parent / "spool-path-account"
        self.keys = self.home / "ssh" / "branchleft-spool-path"
        self.dropin = self.home / "ssh" / "sshd_config.d" / "42-branchleft-spool-path.conf"
        self.parent.mkdir(mode=0o755)
        self.keys.parent.mkdir()
        self.dropin.parent.mkdir()
        self.parent.chmod(0o755)

    def place(
        self, from_address: str | None = FROM, key: str | None = PUBLIC_KEY, mode: int = 0o600
    ) -> None:
        """Place the input files the owner places, or leave one out by passing None."""
        self.inputs.mkdir(mode=0o700, exist_ok=True)
        self.inputs.chmod(0o700)
        for name, value in (("from_address", from_address), ("public_key", key)):
            if value is not None:
                path = self.inputs / name
                path.write_text(f"{value}\n", encoding="utf-8")
                path.chmod(mode)

    def run(
        self, *, port: int = 8095, as_current_user: bool = True, sshd: str | None = None
    ) -> Result:
        """Run the play once and return what it did.

        With a stand-in for sshd given, the whole-configuration check runs against it.
        """
        variables: dict[str, object] = {
            "spool_path_account_spool_port": port,
            "spool_path_account_inputs_parent": str(self.parent),
            "spool_path_account_inputs_dir": str(self.inputs),
            "spool_path_account_authorized_keys_dir": str(self.keys),
            "spool_path_account_authorized_keys_file": str(self.keys / "authorized_keys"),
            "spool_path_account_sshd_dropin": str(self.dropin),
            "spool_path_account_sshd_config_dir": str(self.dropin.parent),
        }
        if sshd is not None:
            variables["spool_path_account_sshd"] = sshd
        writer = YAML()
        writer.default_flow_style = False
        play = [
            {
                "name": "Spool path account",
                "hosts": "localhost",
                "connection": "local",
                "gather_facts": False,
                "vars_files": [
                    str(ROLE / "defaults" / "main.yml"),
                    str(ROLE / "vars" / "main.yml"),
                ],
                "tasks": play_tasks(as_current_user=as_current_user, keep_check=sshd is not None),
            }
        ]
        with (self.home / "play.yml").open("w", encoding="utf-8") as handle:
            writer.dump(play, handle)
        with (self.home / "vars.json").open("w", encoding="utf-8") as handle:
            json.dump(variables, handle)
        beside = Path(sys.executable).parent / "ansible-playbook"
        playbook = str(beside) if beside.is_file() else tool("ansible-playbook", ())
        environment = {
            **os.environ,
            "ANSIBLE_LIBRARY": str(ROLE / "library"),
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_HOME": str(self.home / "ansible-home"),
            "ANSIBLE_LOCAL_TEMP": str(self.home / "tmp"),
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_VERBOSITY": "3",
        }
        done = subprocess.run(  # noqa: S603 - argv list, a path from the interpreter's own prefix
            [
                playbook,
                "-i",
                "localhost,",
                "-e",
                f"@{self.home / 'vars.json'}",
                str(self.home / "play.yml"),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=RUN_SECONDS,
            env=environment,
            cwd=self.home,
        )
        return Result(done.returncode, done.stdout + done.stderr)

    @property
    def key_file(self) -> Path:
        """Return the account's key file."""
        return self.keys / "authorized_keys"


class WhatTheRoleWrites(unittest.TestCase):
    """The role is inert until both inputs are placed, then writes one key line and one block."""

    # Control: with no input placed the role writes nothing and removes what it wrote. Red when it
    # writes a key without an input or leaves one behind.
    def test_with_no_input_it_writes_nothing(self) -> None:
        scratch = Scratch(self)
        done = scratch.run()
        self.assertFalse(done.failed, done.output)
        self.assertFalse(scratch.key_file.exists())
        self.assertFalse(scratch.dropin.exists())

    def test_with_no_input_it_takes_down_what_it_wrote(self) -> None:
        scratch = Scratch(self)
        scratch.place()
        self.assertFalse(scratch.run().failed)
        self.assertTrue(scratch.key_file.exists())
        shutil.rmtree(scratch.inputs)
        self.assertFalse(scratch.run().failed)
        self.assertFalse(scratch.key_file.exists())
        self.assertFalse(scratch.dropin.exists())

    # Control: the key line carries every restriction the design names, and the port is the
    # configured one. Red when any option is dropped or the port widened.
    def test_the_key_line_is_restricted_to_one_port_and_one_source(self) -> None:
        scratch = Scratch(self)
        scratch.place()
        done = scratch.run(port=8099)
        self.assertFalse(done.failed, done.output)
        line = scratch.key_file.read_text(encoding="utf-8").strip()
        self.assertEqual(
            line,
            "restrict,port-forwarding,"
            'permitopen="127.0.0.1:8099",'
            f'from="{FROM}",'
            'command="/usr/sbin/nologin" '
            f"ssh-ed25519 {BODY}",
        )

    def test_the_key_comment_is_dropped(self) -> None:
        scratch = Scratch(self)
        scratch.place(key=f"{PUBLIC_KEY} root@elsewhere")
        self.assertFalse(scratch.run().failed)
        self.assertNotIn("elsewhere", scratch.key_file.read_text(encoding="utf-8"))

    def test_a_second_run_changes_nothing(self) -> None:
        scratch = Scratch(self)
        scratch.place()
        self.assertFalse(scratch.run().failed)
        again = scratch.run()
        self.assertFalse(again.failed, again.output)
        self.assertEqual(again.recap("changed"), 0)

    # Control: no value reaches the run's output, even at the highest verbosity.
    def test_no_input_value_is_shown(self) -> None:
        scratch = Scratch(self)
        scratch.place()
        done = scratch.run()
        self.assertFalse(done.failed, done.output)
        for value in (FROM, BODY):
            self.assertNotIn(value, done.output)


class WhenSshdRefuses(unittest.TestCase):
    """A configuration sshd refuses leaves the account closed, not half open."""

    # Control: red when the rescue is dropped, because the key file is then left behind.
    def test_a_refused_configuration_takes_the_key_and_the_settings_back_out(self) -> None:
        scratch = Scratch(self)
        scratch.place()
        done = scratch.run(sshd=tool("false", ("/usr/bin/false", "/bin/false")))
        self.assertTrue(done.failed, done.output)
        self.assertFalse(scratch.key_file.exists())
        self.assertFalse(scratch.dropin.exists())

    # Control: green case, so the check above is not red for another reason.
    def test_an_accepted_configuration_keeps_both(self) -> None:
        scratch = Scratch(self)
        scratch.place()
        done = scratch.run(sshd=tool("true", ("/usr/bin/true", "/bin/true")))
        self.assertFalse(done.failed, done.output)
        self.assertTrue(scratch.key_file.is_file())
        self.assertTrue(scratch.dropin.is_file())

    def test_a_refusal_removes_a_key_that_was_good_before(self) -> None:
        scratch = Scratch(self)
        scratch.place()
        self.assertFalse(scratch.run(sshd=tool("true", ("/usr/bin/true", "/bin/true"))).failed)
        done = scratch.run(sshd=tool("false", ("/usr/bin/false", "/bin/false")))
        self.assertTrue(done.failed, done.output)
        self.assertFalse(scratch.key_file.exists())


class Refusals(unittest.TestCase):
    """A bad input stops the run before anything is written, and the message shows no value."""

    def assert_refused(
        self, scratch: Scratch, expected: str, *, as_current_user: bool = True
    ) -> None:
        """Run once and require a refusal that wrote nothing and shows no input value."""
        done = scratch.run(as_current_user=as_current_user)
        self.assertTrue(done.failed, done.output)
        self.assertIn(expected, done.output)
        self.assertFalse(scratch.key_file.exists())
        self.assertFalse(scratch.dropin.exists())
        for value in (FROM, BODY):
            self.assertNotIn(value, done.output)

    def test_one_input_without_the_other(self) -> None:
        scratch = Scratch(self)
        scratch.place(key=None)
        self.assert_refused(scratch, "One of the two input files is there")

    def test_a_from_address_that_is_not_ipv4(self) -> None:
        scratch = Scratch(self)
        scratch.place(from_address="0.0.0.0/0")
        self.assert_refused(scratch, "The from address must be one IPv4 address")

    def test_a_key_that_is_not_one_ed25519_line(self) -> None:
        scratch = Scratch(self)
        scratch.place(key=f"{PUBLIC_KEY}\nssh-ed25519 {BODY}")
        self.assert_refused(scratch, "The public key must be one line")

    def test_an_input_anyone_can_read(self) -> None:
        scratch = Scratch(self)
        scratch.place(mode=0o644)
        self.assert_refused(scratch, "not a regular file owned by root with mode 0600")

    def test_an_inputs_directory_that_is_not_closed(self) -> None:
        scratch = Scratch(self)
        scratch.place()
        scratch.inputs.chmod(0o755)
        self.assert_refused(scratch, "inputs directory must be owned by root")

    def test_an_input_that_is_a_link(self) -> None:
        scratch = Scratch(self)
        scratch.place(key=None)
        target = scratch.home / "elsewhere"
        target.write_text(f"{PUBLIC_KEY}\n", encoding="utf-8")
        target.chmod(0o600)
        (scratch.inputs / "public_key").symlink_to(target)
        self.assert_refused(scratch, "not a regular file owned by root with mode 0600")

    # Control: a directory above the inputs that others can write is refused, so the path to the
    # inputs cannot be swapped by whoever owns a parent. Red when the group and other write checks
    # are dropped.
    def test_a_parent_others_can_write_is_refused(self) -> None:
        scratch = Scratch(self)
        scratch.place()
        scratch.parent.chmod(0o775)
        self.assert_refused(scratch, "The directory above the inputs directory")

    def test_a_port_that_is_not_a_port(self) -> None:
        scratch = Scratch(self)
        scratch.place()
        done = scratch.run(port=70000)
        self.assertTrue(done.failed)
        self.assertIn("spool_path_account_spool_port must be a whole number", done.output)


class RealSshd(unittest.TestCase):
    """The rendered files, read by a real sshd."""

    def rendered(self) -> Scratch:
        """Have the role write its files and return the scratch tree."""
        scratch = Scratch(self)
        scratch.place(from_address=LOOPBACK)
        done = scratch.run()
        self.assertFalse(done.failed, done.output)
        return scratch

    def host_key(self, scratch: Scratch) -> Path:
        """Make a host key for the sshd under test."""
        path = scratch.home / "hostkey"
        subprocess.run(  # noqa: S603 - argv list, a program found by name, scratch paths
            [
                tool("ssh-keygen", ("/usr/bin/ssh-keygen",)),
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(path),
            ],
            check=True,
            capture_output=True,
        )
        return path

    # Control: the settings sshd reads back for the account are exactly the ones the design names.
    # Red when any is loosened in the file.
    def test_sshd_reports_the_confinement_for_the_account(self) -> None:
        scratch = self.rendered()
        config = scratch.home / "sshd_config"
        config.write_text(
            f"HostKey {self.host_key(scratch)}\nInclude {scratch.dropin}\n", encoding="utf-8"
        )
        sshd = tool("sshd", ("/usr/sbin/sshd",))
        done = subprocess.run(  # noqa: S603 - argv list, a program found by name, scratch paths
            [sshd, "-T", "-f", str(config), "-C", "user=spoolpath,host=localhost,addr=127.0.0.1"],
            capture_output=True,
            text=True,
            check=True,
            timeout=RUN_SECONDS,
        )
        report = {
            line.partition(" ")[0]: line.partition(" ")[2] for line in done.stdout.splitlines()
        }
        self.assertEqual(report["permitopen"], "127.0.0.1:8095")
        self.assertEqual(report["allowtcpforwarding"], "local")
        self.assertEqual(report["authenticationmethods"], "publickey")
        self.assertEqual(report["authorizedkeysfile"], str(scratch.key_file))
        self.assertEqual(report["forcecommand"], "/usr/sbin/nologin")
        for name in (
            "gatewayports",
            "x11forwarding",
            "permittty",
            "permittunnel",
            "allowagentforwarding",
        ):
            with self.subTest(name):
                self.assertEqual(report[name], "no")
        other = subprocess.run(  # noqa: S603 - argv list, a program found by name, scratch paths
            [sshd, "-T", "-f", str(config), "-C", "user=someoneelse,host=localhost,addr=127.0.0.1"],
            capture_output=True,
            text=True,
            check=True,
            timeout=RUN_SECONDS,
        )
        self.assertNotIn("permitopen 127.0.0.1:8095", other.stdout)

    def start_sshd(self, scratch: Scratch) -> int:
        """Start an sshd that reads the account's key file, and return its port.

        Raises:
            AssertionError: when it does not start.
        """
        port = free_port()
        config = scratch.home / "sshd_live"
        config.write_text(
            "\n".join(
                (
                    f"Port {port}",
                    f"ListenAddress {LOOPBACK}",
                    f"HostKey {self.host_key(scratch)}",
                    f"PidFile {scratch.home / 'sshd.pid'}",
                    f"AuthorizedKeysFile {scratch.key_file}",
                    "UsePAM no",
                    "StrictModes no",
                    "PasswordAuthentication no",
                    "AllowTcpForwarding local",
                    "LogLevel ERROR",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        sshd = subprocess.Popen(  # noqa: S603 - argv list, a program found by name
            [tool("sshd", ("/usr/sbin/sshd",)), "-D", "-e", "-f", str(config)],
            stderr=subprocess.PIPE,
        )
        self.addCleanup(reap, sshd)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                socket.create_connection((LOOPBACK, port), timeout=1).close()
            except OSError:
                time.sleep(0.2)
            else:
                return port
        message = "the test sshd did not start"
        raise AssertionError(message)

    def forward(
        self, scratch: Scratch, port: int, private: Path, target: int
    ) -> tuple[int | None, int]:
        """Open a forward to a loopback port through the key.

        Returns the client's exit code if it ended on its own, else None, and the local port.
        """
        local = free_port()
        client = subprocess.Popen(  # noqa: S603 - argv list, a program found by name
            [
                tool("ssh", ("/usr/bin/ssh",)),
                "-F",
                "/dev/null",
                "-i",
                str(private),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                f"UserKnownHostsFile={scratch.home / 'known'}",
                "-o",
                "ExitOnForwardFailure=yes",
                "-p",
                str(port),
                "-L",
                f"{LOOPBACK}:{local}:{LOOPBACK}:{target}",
                "-N",
                f"{getuser()}@{LOOPBACK}",
            ],
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
        )
        self.addCleanup(reap, client)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and client.poll() is None:
            try:
                socket.create_connection((LOOPBACK, local), timeout=1).close()
            except OSError:
                time.sleep(0.2)
            else:
                break
        return client.poll(), local

    def client_key(self, scratch: Scratch) -> Path:
        """Make the key ops1 would hold and return its private half."""
        private = scratch.home / "client"
        subprocess.run(  # noqa: S603 - argv list, a program found by name, scratch paths
            [
                tool("ssh-keygen", ("/usr/bin/ssh-keygen",)),
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(private),
            ],
            check=True,
            capture_output=True,
        )
        return private

    # Control: the key opens the drain port, and sshd refuses it any other port. Red when the
    # permitopen option is dropped from the key line.
    def test_the_key_opens_the_drain_port_and_no_other(self) -> None:
        scratch = Scratch(self)
        private = self.client_key(scratch)
        public = (scratch.home / "client.pub").read_text(encoding="utf-8").split()[:2]
        scratch.place(from_address=LOOPBACK, key=" ".join(public))
        spool = socket.socket()
        spool.bind((LOOPBACK, 0))
        spool.listen()
        self.addCleanup(spool.close)
        drain_port = int(spool.getsockname()[1])
        self.assertFalse(scratch.run(port=drain_port).failed)
        port = self.start_sshd(scratch)
        ended, local = self.forward(scratch, port, private, drain_port)
        self.assertIsNone(ended)
        with socket.create_connection((LOOPBACK, local), timeout=5) as through:
            through.sendall(b"x")
        accepted, _ = spool.accept()
        accepted.close()
        ended, other = self.forward(scratch, port, private, free_port())
        self.assertIsNone(ended)
        with socket.create_connection((LOOPBACK, other), timeout=5) as through:
            through.settimeout(5)
            through.sendall(b"x")
            try:
                closed = through.recv(1) == b""
            except ConnectionResetError:
                closed = True
            self.assertTrue(closed, "sshd must refuse to open a channel to any other port")

    # Control: the key is refused from an address the owner did not name. Red when from= is dropped.
    def test_the_key_is_not_accepted_from_another_address(self) -> None:
        scratch = Scratch(self)
        private = self.client_key(scratch)
        public = (scratch.home / "client.pub").read_text(encoding="utf-8").split()[:2]
        scratch.place(from_address=FROM, key=" ".join(public))
        self.assertFalse(scratch.run().failed)
        port = self.start_sshd(scratch)
        ended, _ = self.forward(scratch, port, private, 8095)
        self.assertEqual(ended, 255)

    # Control: the key runs no command, so a request to run one never executes it. Red when the
    # forced command is dropped from the key line and nologin is not the account's shell.
    def test_the_key_runs_no_command(self) -> None:
        scratch = Scratch(self)
        private = self.client_key(scratch)
        public = (scratch.home / "client.pub").read_text(encoding="utf-8").split()[:2]
        scratch.place(from_address=LOOPBACK, key=" ".join(public))
        self.assertFalse(scratch.run().failed)
        port = self.start_sshd(scratch)
        marker = scratch.home / "ran"
        done = subprocess.run(  # noqa: S603 - argv list, a program found by name, scratch paths
            [
                tool("ssh", ("/usr/bin/ssh",)),
                "-F",
                "/dev/null",
                "-i",
                str(private),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                f"UserKnownHostsFile={scratch.home / 'known'}",
                "-p",
                str(port),
                f"{getuser()}@{LOOPBACK}",
                f"touch {marker}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=RUN_SECONDS,
            stdin=subprocess.DEVNULL,
        )
        self.assertFalse(marker.exists(), done.stderr)


if __name__ == "__main__":
    unittest.main()
