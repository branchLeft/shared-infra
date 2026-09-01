#!/usr/bin/env python3
"""Every relative bind-mount source a stack names must exist in the repository.

A stack is deployed by rsyncing its `stack/` directory to the host, so a
`./thing:/in/container` mount resolves against what was copied. When the source
is missing, Docker does not fail: it creates an empty *directory* at that path
and mounts it. A container expecting a file then reads a directory and dies, and
because the unit is `Type=oneshot` the restart policy turns that into a crash
loop behind a stack that reported a clean start.

`docker compose config` does not catch it -- the file is syntactically valid
with or without the source present -- and neither do the config-validation jobs,
which load rendered Caddy and Prometheus configuration and nothing else. This is
the only check that reads the mount sources, so a typo'd or deleted one is
caught here or on the host.

Sources are matched by regex rather than by parsing YAML: these files are
hand-written in one consistent style, and the suites beside this one hand-roll
their Compose parsing for the same reason -- to stay stdlib-only, so the CI job
needs no install step.
"""

import pathlib
import re
import unittest

HETZNER = pathlib.Path(__file__).resolve().parent.parent

# A relative bind mount in a `volumes:` list: `- ./source:/target[:mode]`.
# Only `./` sources are checked. A named volume has no path to verify, and an
# absolute source is a host path this repository does not ship.
RELATIVE_BIND_MOUNT = re.compile(r"\A\s*-\s+(?P<source>\./[^:\s]+):")

# The crowdsec acquisition mount specifically, captured with its target this
# time: `- ./crowdsec/acquis.d:/target:ro`. Its target has to match
# `crowdsec_service.acquisition_dir` in the sibling `config.yaml.local`, and
# nothing else ties those two files together (branchLeft/shared-infra#85).
CROWDSEC_ACQUIS_MOUNT = re.compile(r"\A\s*-\s+\./crowdsec/acquis\.d:(?P<target>[^:\s]+):ro\s*\Z")

# `crowdsec_service:` is the only block this repository's config.yaml.local
# nests a key under, so a plain `acquisition_dir:` line is unambiguous without
# tracking indentation depth.
ACQUISITION_DIR = re.compile(r"\A\s*acquisition_dir:\s*(?P<path>\S+)\s*\Z")

# Sources written on the host at deploy time instead of being committed, keyed
# by stack. The exemption is the dangerous half of this check -- an entry here
# is a mount nothing verifies -- so each one is pinned by exact path and needs
# a reason, and the test below fails a stale entry.
#
# `alertmanager.yml` is rendered from `alertmanager.yml.tmpl` and four secrets
# by `render_alertmanager_config.py`, written 0600 on the host. Committing it
# would put those secrets in a public repository, which is why the template is
# what lives here.
# `prometheus/mx1-metrics-password` is the same shape: the `stalwart` scrape
# job's `basic_auth` password, written 0600 on the host by the same script from
# `STALWART_PROMETHEUS_SECRET`. Committing it would put a live credential in a
# public repository.
#
# This exemption is what makes the empty-directory failure this file describes
# reachable for that one path, so `write_prometheus_password()` clears such a
# directory before writing -- without that, one hand-run `docker compose up`
# would wedge every later `ExecStartPre` and take the whole stack down.
# Prometheus itself tolerates the file being absent: it starts, that one scrape
# fails, and `up{job="stalwart"} == 0` pages within five minutes.
DEPLOY_TIME_SOURCES = {
    "monitoring": {
        "./alertmanager/alertmanager.yml",
        "./prometheus/mx1-metrics-password",
    },
}


def stack_compose_files() -> dict[str, pathlib.Path]:
    """Every committed stack, keyed by the directory holding its `stack/`."""
    return {
        path.parent.parent.name: path for path in sorted(HETZNER.glob("*/stack/compose.yml"))
    }


def relative_bind_sources(compose: pathlib.Path) -> list[str]:
    """The `./...` mount sources named in a Compose file, in file order."""
    return [
        match.group("source")
        for line in compose.read_text(encoding="utf-8").splitlines()
        if (match := RELATIVE_BIND_MOUNT.match(line))
    ]


class RelativeBindMountTests(unittest.TestCase):
    def test_the_repository_actually_declares_relative_bind_mounts(self):
        """A regex that matched nothing would pass the assertion below vacuously."""
        total = sum(
            len(relative_bind_sources(compose)) for compose in stack_compose_files().values()
        )
        self.assertGreater(total, 0, "no `./` bind mounts found; the pattern has stopped matching")

    def test_every_relative_bind_mount_source_is_committed(self):
        for stack, compose in stack_compose_files().items():
            exempt = DEPLOY_TIME_SOURCES.get(stack, set())
            for source in relative_bind_sources(compose):
                if source in exempt:
                    continue
                with self.subTest(stack=stack, source=source):
                    path = (compose.parent / source).resolve()
                    self.assertTrue(
                        path.exists(),
                        f"{compose} mounts {source}, which is not in the repository. "
                        "Docker creates an empty directory for a missing source rather "
                        "than failing, so this reaches the host as a crash loop.",
                    )

    def test_no_exemption_outlives_the_mount_it_covers(self):
        """A stale exemption silently un-checks whatever path later takes its name."""
        composes = stack_compose_files()
        for stack, sources in DEPLOY_TIME_SOURCES.items():
            with self.subTest(stack=stack):
                self.assertIn(stack, composes, f"{stack} is exempted but has no stack/compose.yml")
                declared = set(relative_bind_sources(composes[stack]))
                self.assertEqual(
                    sources - declared,
                    set(),
                    f"{stack} exempts sources it no longer mounts: {sorted(sources - declared)}",
                )


class CrowdsecAcquisitionMountTests(unittest.TestCase):
    """The entrypoint's populate rsync walks every path under /etc/crowdsec on
    a cold start; a read-only directory anywhere in that tree fails it with
    EROFS. The mount lives outside /etc/crowdsec because of that, and
    `config.yaml.local` repoints CrowdSec at wherever it actually is -- these
    two assertions are what would catch either file drifting from the other.
    """

    def test_the_compose_mount_target_matches_the_configured_acquisition_dir(self):
        compose = HETZNER / "edge" / "stack" / "compose.yml"
        config_local = HETZNER / "edge" / "stack" / "crowdsec" / "config.yaml.local"
        target = next(
            (
                m.group("target")
                for line in compose.read_text(encoding="utf-8").splitlines()
                if (m := CROWDSEC_ACQUIS_MOUNT.match(line))
            ),
            None,
        )
        configured = next(
            (
                m.group("path")
                for line in config_local.read_text(encoding="utf-8").splitlines()
                if (m := ACQUISITION_DIR.match(line))
            ),
            None,
        )
        self.assertIsNotNone(target, f"no acquis.d bind mount found in {compose}")
        self.assertIsNotNone(configured, f"no acquisition_dir set in {config_local}")
        self.assertEqual(
            target,
            configured,
            f"{compose} mounts the acquisition files at {target}, but "
            f"{config_local} points crowdsec_service.acquisition_dir at "
            f"{configured} -- CrowdSec would silently stop reading them.",
        )

    def test_the_mount_target_is_not_back_under_etc_crowdsec(self):
        compose = HETZNER / "edge" / "stack" / "compose.yml"
        target = next(
            (
                m.group("target")
                for line in compose.read_text(encoding="utf-8").splitlines()
                if (m := CROWDSEC_ACQUIS_MOUNT.match(line))
            ),
            None,
        )
        self.assertIsNotNone(target, f"no acquis.d bind mount found in {compose}")
        self.assertFalse(
            target == "/etc/crowdsec" or target.startswith("/etc/crowdsec/"),
            f"{compose} mounts the acquisition files at {target}, which is under "
            "/etc/crowdsec -- the populate rsync walks everything there on a cold "
            "start, and a read-only directory there fails it with EROFS "
            "(branchLeft/shared-infra#85).",
        )


class PatternTests(unittest.TestCase):
    """The matcher's failure direction, against shapes the committed stacks lack."""

    def test_it_reads_a_plain_relative_mount(self):
        self.assertEqual(
            RELATIVE_BIND_MOUNT.match("      - ./Caddyfile:/etc/caddy/Caddyfile:ro").group(
                "source"
            ),
            "./Caddyfile",
        )

    def test_it_reads_a_mount_with_no_mode(self):
        self.assertEqual(
            RELATIVE_BIND_MOUNT.match("      - ./conf:/conf").group("source"), "./conf"
        )

    def test_a_named_volume_is_not_a_relative_mount(self):
        self.assertIsNone(RELATIVE_BIND_MOUNT.match("      - caddy-data:/data"))

    def test_an_absolute_source_is_not_a_relative_mount(self):
        self.assertIsNone(RELATIVE_BIND_MOUNT.match("      - /etc/branchleft:/etc/branchleft:ro"))


if __name__ == "__main__":
    unittest.main()
