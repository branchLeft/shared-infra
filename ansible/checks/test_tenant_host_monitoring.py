"""Check that the tenant hosts are monitored as the monitoring runbook states.

No metrics port is public.

Full reasoning: `test_tenant_host_monitoring.md`.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"
PLAYBOOKS = ANSIBLE / "playbooks"
TENANT_PLAYBOOKS = ("dbt1", "appt1", "edget")
EXPORTER = "node_exporter"
JOURNAL_KEY = "host_baseline_journal_retention_days"
# The ceiling the website's privacy notice states for server logs, and the figure these hosts keep.
PRIVACY_CEILING_DAYS = 90
TENANT_RETENTION_DAYS = 30
UNIT = ROOT / "hetzner" / "provision" / "node-exporter.service"
ADDRESS_PLAN = ROOT / "hetzner-host" / "addressPlan.ts"


def _play(host: str) -> dict[str, object]:
    """Return the one play of the host's playbook.

    Raises:
        TypeError: the playbook is not a list of one mapping.
    """
    loaded: object = yaml.safe_load((PLAYBOOKS / f"{host}.yml").read_text(encoding="utf-8"))
    if not isinstance(loaded, list) or len(loaded) != 1 or not isinstance(loaded[0], dict):
        message = f"{host}.yml is not one play"
        raise TypeError(message)
    return {str(key): value for key, value in loaded[0].items()}


def _role_names(host: str) -> list[str]:
    """Return the role directory names the host's play applies, in order."""
    roles = _play(host).get("roles")
    names: list[str] = []
    if isinstance(roles, list):
        for entry in roles:
            path = entry["role"] if isinstance(entry, dict) else entry
            names.append(Path(str(path)).name)
    return names


def _play_vars(host: str) -> dict[str, object]:
    """Return the play's own vars (not the vars files)."""
    play_vars = _play(host).get("vars")
    if not isinstance(play_vars, dict):
        return {}
    return {str(key): value for key, value in play_vars.items()}


class TenantHostsRunTheExporter(unittest.TestCase):
    """Each tenant host applies node_exporter once, in the place its play says."""

    def test_each_tenant_playbook_applies_the_exporter_exactly_once(self) -> None:
        for host in TENANT_PLAYBOOKS:
            with self.subTest(host):
                self.assertEqual(_role_names(host).count(EXPORTER), 1)

    def test_on_the_database_host_the_exporter_comes_before_the_database_role(self) -> None:
        names = _role_names("dbt1")
        self.assertLess(names.index(EXPORTER), names.index("db_t1"))

    def test_on_the_other_two_the_exporter_is_last(self) -> None:
        for host in ("appt1", "edget"):
            with self.subTest(host):
                self.assertEqual(_role_names(host)[-1], EXPORTER)

    def test_each_host_lists_the_exporter_in_its_role_row(self) -> None:
        for host in TENANT_PLAYBOOKS:
            with self.subTest(host):
                row: object = yaml.safe_load(
                    (ANSIBLE / "checks" / "host_roles" / f"{host}.yml").read_text(encoding="utf-8")
                )
                assert isinstance(row, list)  # noqa: S101 - narrows the type
                self.assertIn(EXPORTER, row)

    def test_no_tenant_playbook_moves_the_exporters_subnet_prefix(self) -> None:
        # The tenants network reuses the estate's range, so the default finds the host's address.
        for host in TENANT_PLAYBOOKS:
            with self.subTest(host):
                self.assertNotIn("node_exporter_subnet_prefix", _play_vars(host))

    def test_the_default_prefix_covers_every_tenant_address(self) -> None:
        defaults: object = yaml.safe_load(
            (ANSIBLE / "roles" / EXPORTER / "defaults" / "main.yml").read_text(encoding="utf-8")
        )
        assert isinstance(defaults, dict)  # noqa: S101 - narrows the type
        prefix = str(defaults["node_exporter_subnet_prefix"])
        source = ADDRESS_PLAN.read_text(encoding="utf-8")
        block = source[source.index("export const TENANTS_HOST_IPS") :]
        block = block[: block.index("} as const")]
        addresses = re.findall(r"'(\d+\.\d+\.\d+\.\d+)'", block)
        self.assertEqual(len(addresses), 3)
        for address in addresses:
            self.assertTrue(address.startswith(prefix), address)


class TheExporterIsNeverPublic(unittest.TestCase):
    """The exporter binds the host's own private address, so no firewall keeps it private."""

    def test_the_unit_listens_on_the_role_address_never_every_address(self) -> None:
        # Comments in the unit say "never 0.0.0.0", so only its command lines are read.
        commands = [
            line
            for line in UNIT.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        ]
        listens = re.findall(r"--web\.listen-address=(\S+)", "\n".join(commands))
        self.assertEqual(listens, ["${NODE_EXPORTER_LISTEN_ADDRESS}:9100"])
        # The literal is the wildcard the test must never find; it is not a bind address.
        self.assertNotIn("0.0.0.0", "\n".join(commands))  # noqa: S104
        self.assertNotIn("[::]", "\n".join(commands))

    def test_the_role_refuses_to_install_without_an_address_in_the_estate_subnet(self) -> None:
        tasks = (ANSIBLE / "roles" / EXPORTER / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("node_exporter_private_address | length > 0", tasks)
        self.assertIn("so node_exporter would bind a public interface", tasks)


class JournalRetentionIsStatedPerHost(unittest.TestCase):
    """Each tenant host sets one figure, inside the privacy notice's ceiling; no other host does."""

    def test_each_tenant_playbook_sets_thirty_days(self) -> None:
        for host in TENANT_PLAYBOOKS:
            with self.subTest(host):
                self.assertEqual(_play_vars(host).get(JOURNAL_KEY), TENANT_RETENTION_DAYS)

    def test_the_figure_is_inside_the_privacy_notices_ceiling(self) -> None:
        self.assertLessEqual(TENANT_RETENTION_DAYS, PRIVACY_CEILING_DAYS)

    def test_no_other_playbook_sets_it_so_the_live_hosts_are_unchanged(self) -> None:
        for playbook in sorted(PLAYBOOKS.glob("*.yml")):
            if playbook.stem in TENANT_PLAYBOOKS:
                continue
            with self.subTest(playbook.stem):
                self.assertNotIn(JOURNAL_KEY, playbook.read_text(encoding="utf-8"))

    def test_the_role_default_writes_nothing(self) -> None:
        defaults: object = yaml.safe_load(
            (ANSIBLE / "roles" / "host_baseline" / "defaults" / "main.yml").read_text(
                encoding="utf-8"
            )
        )
        assert isinstance(defaults, dict)  # noqa: S101 - narrows the type
        self.assertEqual(defaults[JOURNAL_KEY], 0)

    def test_the_role_refuses_a_figure_over_the_ceiling(self) -> None:
        retention = ANSIBLE / "roles" / "host_baseline" / "tasks" / "_journal_retention.yml"
        tasks = retention.read_text(encoding="utf-8")
        self.assertIn(f"{JOURNAL_KEY} | int <= {PRIVACY_CEILING_DAYS}", tasks)


if __name__ == "__main__":
    unittest.main()
