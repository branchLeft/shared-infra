#!/usr/bin/env python3
"""A Compose healthcheck that probes a name resolving to more than one address
family can race those families against each other: the client tries one, and
only falls back to the other after that attempt is timed out rather than
refused outright. That race can cost seconds even when the server itself
answers in milliseconds, and a `timeout:` sized for the server's own latency
has no margin for it.

This asserts every HTTP healthcheck probe committed in shim-compose.yml
targets a literal address rather than a name -- `ipaddress.ip_address()`
raises on anything that isn't one, which a hostname like `localhost` is,
whether or not it happens to resolve to a single family today. Matched by
regex rather than a YAML parser, the same way the sibling suites in this
directory and in hetzner/provision/ do, to stay stdlib-only.

What this does not and cannot prove: that the underlying service actually
listens on the family this probes, or that the multi-second stall the probed
name previously produced is gone. Both are host-observable facts this suite
has no access to; the delivery mechanism for this file is a human rsyncing it
to the host, and the healthcheck's own live status after that is what proves
it.

`HealthcheckResponseDrainTests` and `HealthcheckProbeTimingTests` below cover
a second, unrelated stall in the same probe (branchLeft/workspace#442): the
callback reads `r.statusCode` but, before the fix, never drained or destroyed
`r`. An unconsumed `http.IncomingMessage` leaves its socket paused, so Node's
event loop cannot empty and the process survives until the *server's* own
`keepAliveTimeout` (5000ms by default) closes the connection -- comfortably
past this healthcheck's 3s budget even though the server answers instantly.
The static test below (`HealthcheckResponseDrainTests`) is what would have
caught the original defect; the timing test is a live differential proof for
anyone verifying the fix rather than trusting the pattern match.
"""

from __future__ import annotations

import ipaddress
import pathlib
import re
import shutil
import subprocess
import time
import unittest
from urllib.parse import urlsplit

PROVISION_DIR = pathlib.Path(__file__).resolve().parent
SHIM_COMPOSE = PROVISION_DIR / "shim-compose.yml"

# A bare http(s):// URL as it appears inside a healthcheck's `CMD`/`node -e`
# string: no whitespace or quote characters, since the surrounding source
# always quotes the literal with `'`.
HTTP_URL = re.compile(r"https?://[^\s'\"]+")

# The mailgun-shim healthcheck's `node -e` body, as YAML's `>-` folds it: each
# line of the block scalar joined by a single space. `(?m)^ {10}\S` matches
# only the folded lines themselves (10-space indent), not the `interval:`
# sibling key that follows at 6.
NODE_DASH_E_BODY = re.compile(r"- >-\n((?:^ {10}\S.*\n)+)", re.MULTILINE)

# `(r) => { ... r.statusCode ... r.resume()/.destroy() ... }` -- the response
# callback reads the status and also drains or tears down the same object,
# within one arrow-function body (`[^}]*` stops at the first `}`, i.e. this
# callback's own close brace, not a later one).
DRAINS_RESPONSE = re.compile(r"\((\w+)\)\s*=>\s*\{[^}]*\b\1\.statusCode\b[^}]*\b\1\.(?:resume|destroy)\(\)")


def probed_urls(compose_text: str) -> list[str]:
    """Every http(s):// URL literal committed in the compose file, in file
    order. Deliberately whole-file rather than scoped to a `healthcheck:`
    block: a probe added anywhere outside one would still make an HTTP call
    subject to the same resolution race, and this suite is meant to catch
    that too.
    """
    return HTTP_URL.findall(compose_text)


def shim_healthcheck_script(compose_text: str) -> str:
    """The mailgun-shim healthcheck's `node -e` script, folded to a single
    line the way YAML's `>-` block scalar folds it, so it can be handed to
    `node -e` standalone -- the same text Docker itself executes.
    """
    match = NODE_DASH_E_BODY.search(compose_text)
    if match is None:
        raise AssertionError("no `- >-` node script found in shim-compose.yml; the extractor regex has drifted")
    return " ".join(line.strip() for line in match.group(1).splitlines())


class HealthcheckProbeAddressTests(unittest.TestCase):
    def test_the_compose_file_actually_declares_an_http_probe(self):
        """A regex that matched nothing would pass every assertion below vacuously."""
        urls = probed_urls(SHIM_COMPOSE.read_text(encoding="utf-8"))
        self.assertGreater(len(urls), 0, "no http(s):// probe found; the pattern has stopped matching")

    def test_no_probe_targets_a_name_that_could_resolve_dual_stack(self):
        """The host component of every probed URL must be an IP literal, not
        a name -- `ipaddress.ip_address` accepts only the former, so this
        fails on `localhost` (or any other hostname) without needing to name
        `localhost` itself as the forbidden string.
        """
        for url in probed_urls(SHIM_COMPOSE.read_text(encoding="utf-8")):
            host = urlsplit(url).hostname
            with self.subTest(url=url):
                self.assertIsNotNone(host, f"{url} has no parseable host component")
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    self.fail(
                        f"{url} probes {host!r}, which is a name rather than an IP "
                        "literal -- a name resolving to more than one address family "
                        "can race those families against the healthcheck's own timeout"
                    )

    def test_the_shim_probe_is_addressed_by_ipv4_specifically(self):
        """Pins the fix's actual choice: the shim's other host-facing address
        in this file (`127.0.0.1:8825:8080`) is IPv4, so its own healthcheck
        should probe the same family rather than an IPv6 literal that
        happens to also be unambiguous.
        """
        urls = probed_urls(SHIM_COMPOSE.read_text(encoding="utf-8"))
        shim_urls = [url for url in urls if ":8080/" in url]
        self.assertEqual(len(shim_urls), 1, f"expected exactly one probe of port 8080, found {shim_urls}")
        host = urlsplit(shim_urls[0]).hostname
        self.assertIsInstance(ipaddress.ip_address(host), ipaddress.IPv4Address)


class HealthcheckResponseDrainTests(unittest.TestCase):
    def test_the_probe_callback_drains_or_destroys_the_response(self):
        """branchLeft/workspace#442's actual defect: the callback read
        `r.statusCode` and set `process.exitCode` from it, but never called
        `r.resume()` or `r.destroy()`. A readable stream that is never read
        stays paused, so the process cannot exit until the *server* closes
        the idle connection -- not something this healthcheck's own 3s
        `timeout:` has any say over. This would have failed against the
        pre-fix script (no `.resume()`/`.destroy()` in the callback body).
        """
        script = shim_healthcheck_script(SHIM_COMPOSE.read_text(encoding="utf-8"))
        self.assertRegex(
            script,
            DRAINS_RESPONSE,
            "the response callback reads statusCode but never calls "
            ".resume()/.destroy() on the same object -- the socket stays "
            "paused and Node waits out the server's keepAliveTimeout "
            "instead of exiting once the status is known",
        )


@unittest.skipUnless(shutil.which("node"), "node not on PATH")
class HealthcheckProbeTimingTests(unittest.TestCase):
    """Runs the exact committed `node -e` script against a real local HTTP
    server, the same way Docker's healthcheck runs it against the shim. The
    server's `keepAliveTimeout` is set to 1.5s rather than the production
    default of 5s -- long enough to sit well clear of ordinary `node -e`
    process-startup noise (the issue's own measurement: 151ms bare startup,
    196ms end-to-end once drained), but short enough that a regression here
    fails in ~1.5s rather than the full 5s, on every CI run rather than as a
    manual one-off measurement like the issue's own reproduction.

    Skipped, not failed, where `node` is unavailable: this environment is not
    guaranteed to have it, and `HealthcheckResponseDrainTests` above is the
    assertion that must never be skippable.
    """

    KEEP_ALIVE_TIMEOUT_MS = 1500

    SERVER_SCRIPT = (
        "const http = require('node:http');"
        "const server = http.createServer((req, res) => {"
        "res.writeHead(200, {'Content-Type': 'application/json'});"
        "res.end(JSON.stringify({status: 'ok'}));"
        "});"
        f"server.keepAliveTimeout = {KEEP_ALIVE_TIMEOUT_MS};"
        "server.listen(8080, '127.0.0.1', () => { process.stdout.write('ready\\n'); });"
    )

    def setUp(self):
        self.server = subprocess.Popen(
            [shutil.which("node"), "-e", self.SERVER_SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        ready = self.server.stdout.readline()
        if "ready" not in ready:
            self.server.kill()
            self.fail(f"local test server did not report ready; got {ready!r}")
        self.addCleanup(self._stop_server)

    def _stop_server(self):
        self.server.kill()
        self.server.wait(timeout=5)
        self.server.stdout.close()

    def test_probe_completes_well_under_its_own_healthcheck_timeout(self):
        script = shim_healthcheck_script(SHIM_COMPOSE.read_text(encoding="utf-8"))
        start = time.monotonic()
        try:
            result = subprocess.run(
                [shutil.which("node"), "-e", script],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            self.fail(
                "probe did not exit within 5s against a 200 response -- an "
                "undrained response would stall for this test server's "
                f"{self.KEEP_ALIVE_TIMEOUT_MS}ms keepAliveTimeout at "
                "minimum, so 5s is already a wide margin, not a tight one"
            )
        elapsed = time.monotonic() - start
        self.assertEqual(
            result.returncode,
            0,
            f"probe did not exit 0 against a 200 response (stderr: {result.stderr!r})",
        )
        # 1s sits well clear of both sides of the differential this test
        # relies on: comfortably above ordinary process-startup noise
        # (~150-200ms drained), comfortably below the 1.5s an undrained
        # response would stall for against this test server. A regression
        # that removes `.resume()`/`.destroy()` fails this in ~1.5s.
        self.assertLess(
            elapsed,
            1.0,
            f"probe took {elapsed:.3f}s against a 3s healthcheck timeout -- "
            "an unconsumed response socket stalling until the server's own "
            "keepAliveTimeout would reproduce branchLeft/workspace#442",
        )


if __name__ == "__main__":
    unittest.main()
