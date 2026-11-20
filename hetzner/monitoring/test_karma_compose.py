#!/usr/bin/env python3
"""The Karma incident view in the monitoring stack is private, read-only and pinned.

Karma has no login of its own, so what keeps it from the network is how the Compose file
publishes it. These tests read `stack/compose.yml` as text, because the job that runs them
has no YAML parser, and check the four things that would otherwise fail quietly: the image
is pinned by digest, the only published port is edge1's loopback, it reads the stack's own
Alertmanager, and it cannot create or expire a silence. That no edge route can reach
it is pinned by the edge render test, which refuses 8084 as an edge1 backend.
"""

from __future__ import annotations

import pathlib
import re
import unittest

MONITORING = pathlib.Path(__file__).resolve().parent
COMPOSE = MONITORING / "stack" / "compose.yml"

SERVICE_HEADER = re.compile(r"^  ([a-z][a-z0-9-]*):\s*$")
TOP_LEVEL_HEADER = re.compile(r"^\S")
IMAGE_LINE = re.compile(
    r"^    image: ghcr\.io/prymitive/karma:v\d+\.\d+@sha256:[0-9a-f]{64}\s*$", re.MULTILINE
)
PORT_LINE = re.compile(r"^      - '([^']+)'\s*$")
LOOPBACK_PORT = re.compile(r"127\.0\.0\.1:\d+:\d+")


def service_block(text: str, name: str) -> list[str]:
    """The lines of one service under `services:`, header included, comments kept."""
    lines = text.splitlines()
    found: list[str] = []
    inside = False
    for line in lines:
        header = SERVICE_HEADER.match(line)
        if header and header.group(1) == name:
            inside = True
            found = [line]
            continue
        if inside and (header or TOP_LEVEL_HEADER.match(line)):
            break
        if inside:
            found.append(line)
    return found


def published_ports(block: list[str]) -> list[str]:
    """The entries under the service's own `ports:` key."""
    ports: list[str] = []
    in_ports = False
    for line in block:
        if re.match(r"^    ports:\s*$", line):
            in_ports = True
            continue
        if in_ports:
            entry = PORT_LINE.match(line)
            if entry:
                ports.append(entry.group(1))
            elif line.strip() and not line.lstrip().startswith("#"):
                in_ports = False
    return ports


def environment(block: list[str]) -> dict[str, str]:
    """The `KEY: value` pairs under the service's `environment:` key, quotes removed."""
    pairs: dict[str, str] = {}
    in_env = False
    for line in block:
        if re.match(r"^    environment:\s*$", line):
            in_env = True
            continue
        if in_env:
            pair = re.match(r"^      ([A-Z_]+): (.+?)\s*$", line)
            if pair:
                pairs[pair.group(1)] = pair.group(2).strip("'\"")
            elif line.strip() and not line.lstrip().startswith("#"):
                in_env = False
    return pairs


class KarmaComposeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = COMPOSE.read_text(encoding="utf-8")
        self.block = service_block(self.text, "karma")
        self.assertTrue(self.block, "compose.yml has no `karma` service to check")
        self.body = "\n".join(self.block)

    def test_the_image_is_pinned_by_tag_and_digest(self) -> None:
        self.assertRegex(self.body, IMAGE_LINE)

    def test_the_only_published_port_is_edge1_loopback(self) -> None:
        ports = published_ports(self.block)
        self.assertEqual(len(ports), 1, f"karma publishes {ports}; it must publish exactly one")
        self.assertRegex(
            ports[0],
            LOOPBACK_PORT,
            "karma has no login, so it may be published on 127.0.0.1 only, never on a "
            "private-network address or on every interface",
        )

    def test_the_loopback_port_is_not_taken_by_another_service(self) -> None:
        mine = published_ports(self.block)[0].rsplit(":", 1)[0]
        for other in re.findall(r"^  ([a-z][a-z0-9-]*):\s*$", self.text, re.MULTILINE):
            if other == "karma":
                continue
            with self.subTest(service=other):
                others = published_ports(service_block(self.text, other))
                self.assertNotIn(mine, [p.rsplit(":", 1)[0] for p in others])

    def test_it_reads_the_stacks_own_alertmanager(self) -> None:
        env = environment(self.block)
        self.assertEqual(env.get("ALERTMANAGER_URI"), "http://alertmanager:9093")

    def test_it_cannot_create_or_expire_a_silence(self) -> None:
        env = environment(self.block)
        self.assertEqual(env.get("ALERTMANAGER_READONLY"), "true")
        self.assertNotIn("ALERTMANAGER_PROXY", env)

    def test_it_runs_unprivileged_with_a_read_only_filesystem(self) -> None:
        for line in ("user: '65534:65534'", "read_only: true", "cap_drop: [ALL]"):
            with self.subTest(line=line):
                self.assertIn(f"\n    {line}\n", self.body)
        self.assertIn("no-new-privileges:true", self.body)

    def test_it_declares_a_healthcheck_and_waits_for_a_healthy_alertmanager(self) -> None:
        self.assertIn("\n    healthcheck:\n", self.body)
        self.assertIn("condition: service_healthy", self.body)


class ServiceBlockParserTests(unittest.TestCase):
    """The reader has to find something, or every test above passes on nothing."""

    SAMPLE = (
        "name: x\n"
        "services:\n"
        "  a:\n"
        "    image: i\n"
        "    ports:\n"
        "      - '127.0.0.1:1:2'\n"
        "      # a comment\n"
        "      - '10.0.0.1:3:4'\n"
        "    environment:\n"
        "      K: 'v'\n"
        "      # comment\n"
        "      L: w\n"
        "  b:\n"
        "    ports:\n"
        "      - '5:6'\n"
        "volumes:\n"
        "  v:\n"
    )

    def test_a_service_block_stops_at_the_next_service_and_at_top_level(self) -> None:
        self.assertEqual(len(service_block(self.SAMPLE, "a")), 10)
        self.assertEqual(len(service_block(self.SAMPLE, "b")), 3)
        self.assertEqual(service_block(self.SAMPLE, "missing"), [])

    def test_ports_and_environment_are_read_across_comments(self) -> None:
        block = service_block(self.SAMPLE, "a")
        self.assertEqual(published_ports(block), ["127.0.0.1:1:2", "10.0.0.1:3:4"])
        self.assertEqual(environment(block), {"K": "v", "L": "w"})

    def test_a_wide_binding_is_not_a_loopback_one(self) -> None:
        self.assertIsNone(LOOPBACK_PORT.fullmatch("8084:8080"))
        self.assertIsNone(LOOPBACK_PORT.fullmatch("10.20.1.10:8084:8080"))
        self.assertIsNotNone(LOOPBACK_PORT.fullmatch("127.0.0.1:8084:8080"))


if __name__ == "__main__":
    unittest.main()
