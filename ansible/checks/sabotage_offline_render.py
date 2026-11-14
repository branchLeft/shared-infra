"""Red-then-green proof that offline_render.py catches what it claims (run by ansible-offline.yml).

A temporary copy of the tree gets planted defects (S1 to S6, and S9), and one run must exit 1
and name each by host, role and output; the clean copy must exit 0. S7 plants a sentinel in a
rendered line and requires it in no captured output, then removes each of the two layers that
keep it out and shows the leak the test looks for is real. S8 puts secret-looking values in the
environment and requires a template that reads them to render empty. A tool the test needs
(docker, visudo, ssh-keygen) that is missing fails the test: a proof that cannot run is not one.
Named sabotage_* so the lint job's test_*.py discovery does not run its minutes of Ansible.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

CHECKS = Path(__file__).resolve().parent
ROOT = CHECKS.parents[1]
SENTINEL = "SENTINEL_7f3a91c4"
ENV_SENTINELS = {"GITHUB_TOKEN": "ENVSENTINEL_a1", "ANSIBLE_VAULT_PASSWORD": "ENVSENTINEL_b2"}
NEEDED = ("docker", "visudo", "ssh-keygen", "test")
COPIED = ("roles", "playbooks", "trust", "owner_vars", "checks", "tools")
SKIPPED = shutil.ignore_patterns("molecule", "tests", "__pycache__", "*.pyc", ".venv")
ROLES = "ansible/roles"
DRIVER = "ansible/checks/offline_render.py"
DATA = "ansible/checks/offline"
SUDOERS = f"{ROLES}/broker_deploy/templates/branchleft-slot.sudoers.j2"


class Tree:
    """A copy of the repository's Ansible inputs that a test may break."""

    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="offline-sabotage-"))
        for name in COPIED:
            shutil.copytree(ROOT / "ansible" / name, self.dir / "ansible" / name, ignore=SKIPPED)
        pulumi = ROOT / "hetzner" / "estate" / "Pulumi.production.yaml"
        (self.dir / "hetzner" / "estate").mkdir(parents=True)
        shutil.copy(pulumi, self.dir / "hetzner" / "estate" / pulumi.name)

    def edit(self, relative: str, old: str, new: str) -> None:
        """Replace ``old`` with ``new`` in a file of the copy.

        Raises:
            AssertionError: ``old`` is not in the file, so nothing was sabotaged.
        """
        path = self.dir / relative
        text = path.read_text(encoding="utf-8")
        if old not in text:
            message = f"{relative} has no {old!r} to sabotage"
            raise AssertionError(message)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def write(self, relative: str, text: str, append: bool = False) -> None:
        """Write (or append to) a file of the copy."""
        path = self.dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a" if append else "w", encoding="utf-8") as handle:
            handle.write(text)

    def run(self, hosts: Sequence[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        """Run the copy's own offline_render.py on the copy and capture what it prints."""
        argv = [sys.executable, str(self.dir / DRIVER), "--root", str(self.dir)]
        for host in hosts:
            argv += ["--host", host]
        return subprocess.run(  # noqa: S603
            argv,
            env={**os.environ, **env},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=900,
        )

    def remove(self) -> None:
        """Delete the copy."""
        shutil.rmtree(self.dir, ignore_errors=True)


def plant_s1_to_s6_and_s9(tree: Tree) -> None:
    """Plant the defects the run must name."""
    tree.edit(SUDOERS, "ALL=(root) NOPASSWD", "ALL=(root NOPASSWD")
    compose = f"{ROLES}/db1_stack/templates/compose.yml.j2"
    tree.edit(compose, "name: db\n", "name: db\nbogus_top_level_key: true\n")
    keys = f"{ROLES}/tunnel_account/templates/authorized_keys.j2"
    tree.edit(keys, "{{ tunnel_account_in.db1_public_key }}", "ssh-ed25519 NOT-A-KEY-AT-ALL")
    env_file = f"{ROLES}/website_app1/templates/website.env.j2"
    tree.edit(env_file, "CONTACT_SMTP_HOST", "{% if x %}CONTACT_SMTP_HOST")
    tree.edit(f"{ROLES}/db1_stack/vars/main.yml", "db1_stack_exporter_user: exporter\n", "")
    tree.edit(f"{DATA}/facts/edge1.yml", "distribution_release: trixie\n", "")
    defaults = f"{ROLES}/node_exporter/defaults/main.yml"
    tree.edit(
        defaults, "node_exporter_disk_stop_percent: 70", "node_exporter_disk_stop_percent: no"
    )


def plant_sentinel(tree: Tree) -> None:
    """Make the broken sudoers template carry a sentinel on a line of its own."""
    tree.edit(SUDOERS, "ALL=(root) NOPASSWD", "# {{ planted_sentinel }}\nALL=(root NOPASSWD")
    entry = f"  planted_sentinel:\n    type: str\n    value: {SENTINEL}\n"
    tree.write(f"{DATA}/dummies.yml", entry, append=True)


def plant_env_probe(tree: Tree) -> None:
    """Add a template that reads two secret-looking variables of the environment, and a check."""
    reads = (
        "{{ lookup('ansible.builtin.env', 'GITHUB_TOKEN') }}"
        "{{ lookup('ansible.builtin.env', 'ANSIBLE_VAULT_PASSWORD') }}"
    )
    tree.write(f"{ROLES}/example_config/templates/env_probe.j2", reads)
    task = "\n- name: Probe the environment\n  ansible.builtin.template:\n"
    task += "    src: env_probe.j2\n    dest: /tmp/env_probe\n"
    tree.write(f"{ROLES}/example_config/tasks/main.yml", task, append=True)
    check = "  env_probe.j2:\n    binary: test\n    argv: [test, '!', '-s', '{file}']\n"
    tree.write(f"{DATA}/validators.yml", check, append=True)


def break_driver(old: str, new: str) -> Callable[[Tree], None]:
    """Return a step that breaks the copy's own driver by one text edit."""

    def step(tree: Tree) -> None:
        tree.edit(DRIVER, old, new)

    return step


NO_LOG_OFF = break_driver("NO_LOG = True", "NO_LOG = False")
DISCARD_OFF = break_driver("ANSIBLE_STDIO = subprocess.DEVNULL", "ANSIBLE_STDIO = None")
UNSCRUBBED = break_driver("env=scrubbed_env(workdir),", "env=None,")


@dataclass(frozen=True)
class Scenario:
    """A copy, what is done to it, which hosts the driver renders, and the environment."""

    steps: tuple[Callable[[Tree], None], ...] = ()
    hosts: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)


SCENARIOS: dict[str, Scenario] = {
    "clean": Scenario(),
    "planted": Scenario((plant_s1_to_s6_and_s9,), ("unwired", "db1", "app1", "edge1")),
    "sentinel": Scenario((plant_sentinel,), ("unwired",)),
    "sentinel-no-log": Scenario((plant_sentinel, NO_LOG_OFF), ("unwired",)),
    "sentinel-stdio": Scenario((plant_sentinel, DISCARD_OFF), ("unwired",)),
    "sentinel-both": Scenario((plant_sentinel, NO_LOG_OFF, DISCARD_OFF), ("unwired",)),
    "probe": Scenario((plant_env_probe,), ("unwired",), ENV_SENTINELS),
    "probe-unscrubbed": Scenario((plant_env_probe, UNSCRUBBED), ("unwired",), ENV_SENTINELS),
}


def one_run(name: str) -> subprocess.CompletedProcess[str]:
    """Make a copy, do what the scenario says, run the driver on it, delete the copy."""
    scenario = SCENARIOS[name]
    tree = Tree()
    try:
        for step in scenario.steps:
            step(tree)
        return tree.run(scenario.hosts, scenario.env)
    finally:
        tree.remove()


@functools.cache
def runs() -> dict[str, subprocess.CompletedProcess[str]]:
    """Run every scenario once, four at a time."""
    with ThreadPoolExecutor(max_workers=4) as pool:
        done = pool.map(one_run, SCENARIOS)
        return dict(zip(SCENARIOS, done, strict=True))


def red_line(name: str, host: str, role: str, template: str) -> str:
    """Return the red line of a scenario that names the host, role and output.

    Raises:
        AssertionError: The run has no such line.
    """
    output = runs()[name].stdout
    for line in output.splitlines():
        if line.startswith("red") and f" {host} {role} {template}" in line:
            return line
    message = f"no red line for {host} {role} {template}:\n{output}"
    raise AssertionError(message)


def everything_printed(name: str) -> str:
    """Return all that a scenario's driver wrote to stdout and stderr."""
    return runs()[name].stdout + runs()[name].stderr


class ToolsPresent(unittest.TestCase):
    """The programs the proof needs are there; a missing one fails, it does not skip."""

    def test_programs(self) -> None:
        missing = [name for name in NEEDED if shutil.which(name) is None]
        self.assertEqual([], missing, "the sabotage proof cannot run without these programs")


class PlantedDefects(unittest.TestCase):
    """Red: each planted defect is named by the run, which exits 1."""

    def test_s0_exit_is_one(self) -> None:
        self.assertEqual(1, runs()["planted"].returncode, runs()["planted"].stdout)

    def test_s1_sudoers_refused_by_visudo(self) -> None:
        line = red_line("planted", "unwired", "broker_deploy", "branchleft-slot.sudoers.j2")
        self.assertIn("validate", line)

    def test_s2_compose_refused_by_docker(self) -> None:
        self.assertIn("docker", red_line("planted", "db1", "db1_stack", "compose.yml.j2"))

    def test_s3_key_refused_by_ssh_keygen(self) -> None:
        line = red_line("planted", "unwired", "tunnel_account", "authorized_keys.j2")
        self.assertIn("ssh-keygen", line)

    def test_s4_syntax_error(self) -> None:
        self.assertIn("syntax", red_line("planted", "app1", "website_app1", "website.env.j2"))

    def test_s5_variable_defined_nowhere(self) -> None:
        line = red_line("planted", "db1", "db1_stack", "exporter.my.cnf.j2")
        self.assertIn("db1_stack_exporter_user", line)

    def test_s6_fact_missing_from_the_fixture(self) -> None:
        line = red_line("planted", "edge1", "host_baseline", "docker.list.j2")
        self.assertIn("distribution_release", line)

    def test_s9_input_breaks_the_argument_spec(self) -> None:
        line = red_line("planted", "db1", "node_exporter", "argument_specs")
        self.assertIn("argument spec", line)


class CleanTree(unittest.TestCase):
    """Green: the same tree, unplanted, exits 0 with no red."""

    def test_clean_copy_is_green(self) -> None:
        run = runs()["clean"]
        self.assertEqual(0, run.returncode, run.stdout + run.stderr)
        self.assertNotIn("\nred", "\n" + run.stdout)


class NoPrint(unittest.TestCase):
    """S7: a sentinel in a rendered line reaches no output, and the leak looked for is real."""

    def test_s7_driver_prints_no_sentinel(self) -> None:
        self.assertEqual(1, runs()["sentinel"].returncode, runs()["sentinel"].stdout)
        self.assertNotIn(SENTINEL, everything_printed("sentinel"))

    def test_s7_either_layer_alone_still_holds(self) -> None:
        self.assertNotIn(SENTINEL, everything_printed("sentinel-no-log"))
        self.assertNotIn(SENTINEL, everything_printed("sentinel-stdio"))

    def test_s7_both_layers_removed_leaks(self) -> None:
        leaked = SENTINEL in everything_printed("sentinel-both")
        self.assertTrue(leaked, "the leak this test guards against must be visible")


class EnvScrub(unittest.TestCase):
    """S8: secret-looking environment variables never reach a template."""

    def test_s8_probe_renders_empty(self) -> None:
        run = runs()["probe"]
        self.assertEqual(0, run.returncode, run.stdout + run.stderr)
        self.assertIn(" example_config env_probe.j2", run.stdout)

    def test_s8_unscrubbed_environment_is_caught(self) -> None:
        self.assertEqual(1, runs()["probe-unscrubbed"].returncode)
        self.assertIn(
            "test", red_line("probe-unscrubbed", "unwired", "example_config", "env_probe.j2")
        )


if __name__ == "__main__":
    unittest.main()
