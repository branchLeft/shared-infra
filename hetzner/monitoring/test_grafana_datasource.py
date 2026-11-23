#!/usr/bin/env python3
"""The provisioned Grafana datasource can be applied over a Grafana that has started before.

A Grafana whose data volume already holds the provisioned datasource `Prometheus` (created with
an uid Grafana made up) stops at start when the provisioning file names the same datasource with
another uid: "Datasource provisioning error: data source not found", exit 1, never healthy. The
stack's compose unit then fails and so does the delivery that restarted it. A fresh volume, which
is all a CI run has, never shows it.

Two checks. The first reads the provisioning file as text, because the job that runs these tests
has no YAML parser, and holds every datasource that pins an uid to a `deleteDatasources` entry of
the same name. It always runs. The second starts the pinned Grafana image twice on one data
directory, first with the file as it was before the uid was pinned and then with the file in the
repository, and needs Docker and the image, so it runs only when BRANCHLEFT_GRAFANA_PERSISTED=1.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import unittest

MONITORING = pathlib.Path(__file__).resolve().parent
STACK = MONITORING / "stack"
PROVISIONING = STACK / "grafana" / "provisioning"
DATASOURCE_FILE = PROVISIONING / "datasources" / "prometheus.yaml"
COMPOSE = STACK / "compose.yml"

LIVE_FLAG = "BRANCHLEFT_GRAFANA_PERSISTED"
UP_LINE = "HTTP Server Listen"
FAILED_LINE = "Failed to provision data sources"
START_SECONDS = 90

# The file as it was before the uid was pinned: what an earlier start of the stack provisioned.
BEFORE_THE_UID = (
    "apiVersion: 1\n"
    "\n"
    "datasources:\n"
    "  - name: Prometheus\n"
    "    type: prometheus\n"
    "    access: proxy\n"
    "    url: http://prometheus:9090\n"
    "    isDefault: true\n"
    "    editable: false\n"
)

GRAFANA_IMAGE = re.compile(r"^    image: (docker\.io/grafana/grafana:[^\s@]+@sha256:[0-9a-f]{64})\s*$", re.MULTILINE)
TOP_KEY = re.compile(r"^([A-Za-z][A-Za-z]*):")
ENTRY = re.compile(r"^  - (\w+): (.+?)\s*$")
FIELD = re.compile(r"^    (\w+): (.+?)\s*$")


def section(text: str, key: str) -> list[dict[str, str]]:
    """The entries under one top-level list key, each as its `field: value` pairs.

    Comments and blank lines are skipped. A key that is not in the file gives an empty list.
    """
    entries: list[dict[str, str]] = []
    inside = False
    for line in text.splitlines():
        top = TOP_KEY.match(line)
        if top:
            inside = top.group(1) == key
            continue
        if not inside or not line.strip() or line.lstrip().startswith("#"):
            continue
        entry = ENTRY.match(line)
        if entry:
            entries.append({entry.group(1): entry.group(2)})
            continue
        field = FIELD.match(line)
        if field and entries:
            entries[-1][field.group(1)] = field.group(2)
    return entries


def pinned_without_a_delete(text: str) -> list[str]:
    """The names of datasources that pin an uid and have no `deleteDatasources` entry."""
    deleted = {entry.get("name") for entry in section(text, "deleteDatasources")}
    return [
        entry["name"]
        for entry in section(text, "datasources")
        if "uid" in entry and entry.get("name") not in deleted
    ]


class DatasourceFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DATASOURCE_FILE.read_text(encoding="utf-8")

    def test_the_file_pins_an_uid_for_the_dashboards(self) -> None:
        names = [entry["name"] for entry in section(self.text, "datasources") if "uid" in entry]
        self.assertEqual(names, ["Prometheus"], "dashboards.test.ts holds every panel to this uid")

    def test_every_datasource_that_pins_an_uid_is_deleted_by_name_first(self) -> None:
        self.assertEqual(
            pinned_without_a_delete(self.text),
            [],
            "a datasource that pins an uid needs a `deleteDatasources` entry of the same name, "
            "or a Grafana that has started before stops at start (see the module docstring)",
        )

    def test_the_delete_names_the_first_organisation(self) -> None:
        for entry in section(self.text, "deleteDatasources"):
            with self.subTest(name=entry.get("name")):
                self.assertEqual(entry.get("orgId"), "1")


class SectionReaderTests(unittest.TestCase):
    """The reader has to find something, or the tests above pass on nothing."""

    SAMPLE = (
        "apiVersion: 1\n"
        "deleteDatasources:\n"
        "  - name: A\n"
        "    orgId: 1\n"
        "datasources:\n"
        "  # a comment\n"
        "  - name: A\n"
        "    uid: a\n"
        "\n"
        "  - name: B\n"
        "    type: prometheus\n"
        "  - name: C\n"
        "    uid: c\n"
    )

    def test_entries_are_read_with_their_fields(self) -> None:
        self.assertEqual(section(self.SAMPLE, "deleteDatasources"), [{"name": "A", "orgId": "1"}])
        self.assertEqual(
            section(self.SAMPLE, "datasources"),
            [{"name": "A", "uid": "a"}, {"name": "B", "type": "prometheus"}, {"name": "C", "uid": "c"}],
        )
        self.assertEqual(section(self.SAMPLE, "missing"), [])

    def test_a_pinned_uid_without_a_delete_is_found(self) -> None:
        self.assertEqual(pinned_without_a_delete(self.SAMPLE), ["C"])

    def test_the_file_as_it_was_before_the_uid_pins_nothing(self) -> None:
        self.assertEqual(pinned_without_a_delete(BEFORE_THE_UID), [])

    def test_a_file_that_pins_an_uid_with_no_delete_is_refused(self) -> None:
        pinned = BEFORE_THE_UID.replace("    type:", "    uid: prometheus\n    type:")
        self.assertEqual(pinned_without_a_delete(pinned), ["Prometheus"])


def docker_run(name: str, data: pathlib.Path, provisioning: pathlib.Path, image: str) -> tuple[bool, str]:
    """Start Grafana on ``data`` with ``provisioning``; return (it came up, its log)."""
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    started = subprocess.run(
        [
            "docker", "run", "-d", "--name", name, "-e", "GF_SECURITY_ADMIN_PASSWORD=x",
            "-v", f"{data}:/var/lib/grafana", "-v", f"{provisioning}:/etc/grafana/provisioning:ro", image,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if started.returncode != 0:
        return False, started.stderr
    log = ""
    deadline = time.monotonic() + START_SECONDS
    while time.monotonic() < deadline:
        time.sleep(1)
        log = subprocess.run(["docker", "logs", name], capture_output=True, text=True, check=False)
        log_text = log.stdout + log.stderr
        state = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", name],
            capture_output=True, text=True, check=False,
        ).stdout.strip()
        if UP_LINE in log_text or FAILED_LINE in log_text or state != "running":
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
            return UP_LINE in log_text and FAILED_LINE not in log_text, log_text
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    return False, "Grafana did not report in time"


@unittest.skipUnless(
    os.environ.get(LIVE_FLAG) == "1" and shutil.which("docker") is not None,
    f"set {LIVE_FLAG}=1 with Docker on PATH to start the pinned Grafana image",
)
class PersistedGrafanaTests(unittest.TestCase):
    """The repository's provisioning starts a Grafana whose volume holds the earlier datasource."""

    def test_the_provisioning_starts_over_a_volume_of_an_earlier_start(self) -> None:
        image = GRAFANA_IMAGE.search(COMPOSE.read_text(encoding="utf-8"))
        self.assertIsNotNone(image, "compose.yml has no pinned grafana image")
        assert image is not None
        with tempfile.TemporaryDirectory() as scratch:
            root = pathlib.Path(scratch)
            data = root / "data"
            data.mkdir(mode=0o777)
            data.chmod(0o777)
            before = root / "before" / "datasources"
            before.mkdir(parents=True)
            (before / "prometheus.yaml").write_text(BEFORE_THE_UID, encoding="utf-8")
            for path in (root / "before", before, before / "prometheus.yaml"):
                path.chmod(0o755 if path.is_dir() else 0o644)
            first_up, first_log = docker_run("grafana-persisted-before", data, root / "before", image.group(1))
            self.assertTrue(first_up, f"the earlier start did not come up: {first_log[-2000:]}")
            for repeat in ("one", "two"):
                up, log = docker_run(f"grafana-persisted-{repeat}", data, PROVISIONING, image.group(1))
                tail = "\n".join(line for line in log.splitlines() if "provision" in line.lower())[-2000:]
                self.assertTrue(up, f"start {repeat} over the earlier volume did not come up: {tail}")


if __name__ == "__main__":
    unittest.main()
