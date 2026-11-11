"""Tests that run the path the role writes, with a real ssh client and a real sshd, on this machine.

The role writes one client configuration for each path. Here that file, written by the role's own
tasks, is run with `ssh -F ... -N`, the command the unit runs, against an sshd on a loopback port
whose key carries the options the far host's account gives it, with a stand-in spool behind it that
holds a request open. A proxy between the two can be frozen, which is what a blackholed link looks
like to the client. The test stands in for the unit's restart by starting the client again.

Two things are replaced, and nothing else: the alias address, which here is the loopback address
because this machine cannot bind a private alias, and the shim port, which here is a free one. The
configuration's other lines, the keepalive options among them, are the shipped ones.

Each control a test names was run red on a sabotaged copy and green on the file as shipped (the
pull request records both).
"""

import http.client
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from getpass import getuser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from test_spool_paths_files import KEY, Scratch

LOOPBACK = "127.0.0.1"
SLUG = "demo1"
HELD_SECONDS = 31
UP_SECONDS = 20
FREEZE_DETECT_SECONDS = 60
CHUNK = 65536


def free_port() -> int:
    """Return a loopback port nothing is listening on."""
    with socket.socket() as probe:
        probe.bind((LOOPBACK, 0))
        return int(probe.getsockname()[1])


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


class SpoolHandler(BaseHTTPRequestHandler):
    """The stand-in spool: it holds a request for the seconds the query asks, then answers."""

    def do_GET(self) -> None:  # noqa: N802 - the name http.server calls
        """Answer a drain request after the hold it asks for."""
        _, _, query = self.path.partition("?hold=")
        time.sleep(int(query) if query.isdigit() else 0)
        body = b"drained"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - the signature http.server calls
        """Say nothing."""


class FreezableProxy:
    """A TCP proxy that can stop moving bytes while keeping both ends open."""

    def __init__(self, target_port: int) -> None:
        self.target_port = target_port
        self.running = threading.Event()
        self.running.set()
        self.listener = socket.socket()
        self.listener.bind((LOOPBACK, 0))
        self.listener.listen()
        self.port = int(self.listener.getsockname()[1])
        self.sockets: list[socket.socket] = [self.listener]
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self) -> None:
        """Take connections until the listener is closed."""
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            upstream = socket.create_connection((LOOPBACK, self.target_port))
            self.sockets += [client, upstream]
            for source, sink in ((client, upstream), (upstream, client)):
                threading.Thread(target=self.pump, args=(source, sink), daemon=True).start()

    def pump(self, source: socket.socket, sink: socket.socket) -> None:
        """Copy bytes one way, holding them while the proxy is frozen."""
        try:
            while True:
                self.running.wait()
                data = source.recv(CHUNK)
                if not data:
                    return
                self.running.wait()
                sink.sendall(data)
        except OSError:
            return

    def freeze(self) -> None:
        """Stop moving bytes, as a link that drops every packet does."""
        self.running.clear()

    def close(self) -> None:
        """Close every socket and let the pumps end."""
        self.running.set()
        for item in self.sockets:
            try:
                item.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            item.close()


class Rig:
    """The far host, the link, the client's files and the client, started the way the unit does."""

    def __init__(self, test: unittest.TestCase) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="spool-paths-forward-"))
        test.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.client: subprocess.Popen[bytes] | None = None
        test.addCleanup(self.stop_client)
        self.spool_port = free_port()
        self.shim_port = free_port()
        self.spool = ThreadingHTTPServer((LOOPBACK, self.spool_port), SpoolHandler)
        threading.Thread(target=self.spool.serve_forever, daemon=True).start()
        test.addCleanup(self.spool.server_close)
        test.addCleanup(self.spool.shutdown)
        self.far_host()
        self.proxy = FreezableProxy(self.ssh_port)
        test.addCleanup(self.proxy.close)
        self.write_client_files(test)

    def far_host(self) -> None:
        """Start an sshd whose one key may open the spool's loopback port and nothing else."""
        keygen = tool("ssh-keygen", ("/usr/bin/ssh-keygen",))
        sshd = tool("sshd", ("/usr/sbin/sshd",))
        far = self.home / "far"
        far.mkdir()
        for name in ("host", "client"):
            subprocess.run(  # noqa: S603 - argv list, a program found above, scratch paths
                [keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(far / name)],
                check=True,
                capture_output=True,
            )
        self.host_key = " ".join((far / "host.pub").read_text(encoding="utf-8").split()[:2])
        self.client_key = far / "client"
        options = f'restrict,port-forwarding,permitopen="{LOOPBACK}:{self.spool_port}"'
        public = (far / "client.pub").read_text(encoding="utf-8").split()[:2]
        authorized = far / "authorized_keys"
        authorized.write_text(f"{options} {' '.join(public)}\n", encoding="utf-8")
        authorized.chmod(0o600)
        self.ssh_port = free_port()
        config = far / "sshd_config"
        config.write_text(
            "\n".join(
                (
                    f"Port {self.ssh_port}",
                    f"ListenAddress {LOOPBACK}",
                    f"HostKey {far / 'host'}",
                    f"PidFile {far / 'sshd.pid'}",
                    f"AuthorizedKeysFile {authorized}",
                    "UsePAM no",
                    "StrictModes no",
                    "PasswordAuthentication no",
                    "AllowTcpForwarding local",
                    "PermitTTY no",
                    "LogLevel ERROR",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        self.sshd = subprocess.Popen(  # noqa: S603 - argv list, a program found above
            [sshd, "-D", "-e", "-f", str(config)], stderr=subprocess.PIPE
        )
        self.wait_listening(self.ssh_port)

    def write_client_files(self, test: unittest.TestCase) -> None:
        """Have the role write the path's files, then place the owner's key beside them."""
        test.addCleanup(self.stop_sshd)
        scratch = Scratch(test)
        scratch.descriptor(SLUG, "10.250.0.11")
        row = {
            "slug": SLUG,
            "ssh_host": LOOPBACK,
            "ssh_port": self.proxy.port,
            "spool_port": self.spool_port,
            "host_key": self.host_key,
        }
        done = scratch.run([row])
        test.assertFalse(done.failed, done.output)
        self.dir = scratch.dir
        shutil.copyfile(self.client_key, self.dir / f"{SLUG}.key")
        (self.dir / f"{SLUG}.key").chmod(0o600)
        text = (self.dir / f"{SLUG}.conf").read_text(encoding="utf-8")
        shipped = f"LocalForward 10.250.0.11:8080 {LOOPBACK}:{self.spool_port}"
        test.assertIn(shipped, text)
        # Only this line changes: the alias becomes the loopback address, the shim port a free one.
        replaced = f"LocalForward {LOOPBACK}:{self.shim_port} {LOOPBACK}:{self.spool_port}"
        (self.dir / f"{SLUG}.conf").write_text(text.replace(shipped, replaced), encoding="utf-8")
        test.assertIn(self.host_key, (self.dir / f"{SLUG}.known_hosts").read_text(encoding="utf-8"))
        test.assertNotEqual(KEY, self.host_key)

    def stop_sshd(self) -> None:
        """Stop the far host's sshd and close its pipe."""
        self.sshd.terminate()
        self.sshd.wait()
        if self.sshd.stderr is not None:
            self.sshd.stderr.close()

    @staticmethod
    def wait_listening(port: int, seconds: float = UP_SECONDS) -> None:
        """Wait until the port accepts a connection.

        Raises:
            AssertionError: when it does not within the time.
        """
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                socket.create_connection((LOOPBACK, port), timeout=1).close()
            except OSError:
                time.sleep(0.2)
            else:
                return
        message = f"nothing listened on port {port} within {seconds} seconds"
        raise AssertionError(message)

    def start_client(self) -> None:
        """Start the client the way the unit does: the shipped file, -N, the slug."""
        self.client = subprocess.Popen(  # noqa: S603 - argv list, a program found by name
            [
                tool("ssh", ("/usr/bin/ssh",)),
                "-F",
                str(self.dir / f"{SLUG}.conf"),
                "-o",
                f"User={getuser()}",
                "-N",
                SLUG,
            ],
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
        self.wait_listening(self.shim_port)

    def stop_client(self) -> None:
        """Kill the client if it is running, and close its pipe."""
        if self.client is not None:
            if self.client.poll() is None:
                self.client.kill()
            self.client.wait()
            if self.client.stderr is not None:
                self.client.stderr.close()

    def drain(self, hold: int = 0, timeout: float = HELD_SECONDS + 20) -> tuple[int, bytes]:
        """Make one drain request through the path and return the status and body."""
        connection = http.client.HTTPConnection(LOOPBACK, self.shim_port, timeout=timeout)
        try:
            connection.request("GET", f"/drain?hold={hold}")
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def refused(self) -> bool:
        """Return whether a new connection to the alias is refused at once."""
        started = time.monotonic()
        try:
            socket.create_connection((LOOPBACK, self.shim_port), timeout=5).close()
        except ConnectionRefusedError:
            return time.monotonic() - started < 1
        except OSError:
            return False
        return False


class TheRealPath(unittest.TestCase):
    """The shipped file does what the design says, against a real client and a real sshd."""

    @staticmethod
    def reap(process: "subprocess.Popen[bytes]") -> None:
        """Kill a process the test started, wait for it and close its pipe."""
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stderr is not None:
            process.stderr.close()

    def test_a_drain_request_through_the_path_is_answered(self) -> None:
        rig = Rig(self)
        rig.start_client()
        self.assertEqual(rig.drain(), (200, b"drained"))

    # The drain holds a request for the full thirty seconds. The keepalive options must not cut a
    # busy channel. Red when the keepalive is made to count a held request as silence.
    def test_a_request_held_for_the_full_thirty_seconds_is_answered(self) -> None:
        rig = Rig(self)
        rig.start_client()
        self.assertEqual(rig.drain(hold=HELD_SECONDS), (200, b"drained"))
        self.assertIsNone(rig.client.poll() if rig.client else 1)

    # Control: killing the path leaves nothing listening, so the collector is refused at once, which
    # is a failed cycle and never a hang. Restoring it recovers with no restart of the spool or of
    # whatever dials it. Red when the alias is held by something that outlives the client.
    def test_killing_the_path_is_refused_at_once_and_restoring_it_recovers(self) -> None:
        rig = Rig(self)
        rig.start_client()
        self.assertEqual(rig.drain()[0], 200)
        rig.stop_client()
        self.assertTrue(rig.refused(), "a downed path must refuse at once, not hang")
        rig.start_client()
        self.assertEqual(rig.drain(), (200, b"drained"))

    def test_a_request_in_flight_when_the_path_drops_fails_and_does_not_stall(self) -> None:
        rig = Rig(self)
        rig.start_client()
        killer = threading.Timer(2, rig.stop_client)
        killer.start()
        self.addCleanup(killer.cancel)
        started = time.monotonic()
        with self.assertRaises((ConnectionError, http.client.HTTPException, OSError)):
            rig.drain(hold=20, timeout=15)
        self.assertLess(time.monotonic() - started, 10)

    # Control: a link that goes silent without closing is detected by the keepalive options and the
    # client exits, so the unit can restart it. Red when ServerAliveInterval is removed or zero.
    def test_a_blackholed_link_makes_the_client_exit_within_the_keepalive_window(self) -> None:
        rig = Rig(self)
        rig.start_client()
        self.assertEqual(rig.drain()[0], 200)
        rig.proxy.freeze()
        client = rig.client
        self.assertIsNotNone(client)
        try:
            code = client.wait(timeout=FREEZE_DETECT_SECONDS) if client else -1
        except subprocess.TimeoutExpired:
            self.fail("the client did not give up on a link that went silent")
        self.assertEqual(code, 255)
        self.assertTrue(rig.refused())

    def test_a_client_that_cannot_bind_its_alias_exits(self) -> None:
        rig = Rig(self)
        holder = socket.socket()
        holder.bind((LOOPBACK, rig.shim_port))
        holder.listen()
        self.addCleanup(holder.close)
        client = subprocess.Popen(  # noqa: S603 - argv list, a program found by name
            [
                tool("ssh", ("/usr/bin/ssh",)),
                "-F",
                str(rig.dir / f"{SLUG}.conf"),
                "-o",
                f"User={getuser()}",
                "-N",
                SLUG,
            ],
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
        self.addCleanup(self.reap, client)
        self.assertEqual(client.wait(timeout=UP_SECONDS), 255)


if __name__ == "__main__":
    unittest.main()
