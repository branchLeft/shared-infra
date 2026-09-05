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
"""

from __future__ import annotations

import ipaddress
import pathlib
import re
import unittest
from urllib.parse import urlsplit

PROVISION_DIR = pathlib.Path(__file__).resolve().parent
SHIM_COMPOSE = PROVISION_DIR / "shim-compose.yml"

# A bare http(s):// URL as it appears inside a healthcheck's `CMD`/`node -e`
# string: no whitespace or quote characters, since the surrounding source
# always quotes the literal with `'`.
HTTP_URL = re.compile(r"https?://[^\s'\"]+")


def probed_urls(compose_text: str) -> list[str]:
    """Every http(s):// URL literal committed in the compose file, in file
    order. Deliberately whole-file rather than scoped to a `healthcheck:`
    block: a probe added anywhere outside one would still make an HTTP call
    subject to the same resolution race, and this suite is meant to catch
    that too.
    """
    return HTTP_URL.findall(compose_text)


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


if __name__ == "__main__":
    unittest.main()
