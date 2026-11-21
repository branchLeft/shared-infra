"""The support-access textfile directory is the same in the three places that name it.

The break-glass textfile writer replaces `support_access.prom` in one directory, made by
`breakglass_grant_host`. The node_exporter unit names that directory with a second
`--collector.textfile.directory` flag, and the `node_exporter` role makes it too. A role imports
no role (ANS-12), so the three copies are held together here: a directory renamed in one place
alone leaves the exporter reading a directory the writer never writes, and the portal reads
every tenant's support access as unknown while every check stays green.

The writer's own copy (`OUTPUT_DIR` in branchLeft/ghost-platform) is not in this repository. The
role's Molecule scenario runs the pinned writer and reads the file where this directory says.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
GRANT_VARS = ROOT / "ansible" / "roles" / "breakglass_grant_host" / "vars" / "main.yml"
EXPORTER_VARS = ROOT / "ansible" / "roles" / "node_exporter" / "vars" / "main.yml"
UNIT = ROOT / "hetzner" / "provision" / "node-exporter.service"
FLAG = re.compile(r"--collector\.textfile\.directory=(\S+)")


def variable(path: Path, name: str) -> str | None:
    """Return a string variable of a role's vars file, or None when it is absent."""
    document, _problem = load_yaml(path)
    if not isinstance(document, dict):
        return None
    value = document.get(name)
    return value if isinstance(value, str) else None


def flags(text: str) -> list[str]:
    """Return the directory of each textfile flag on the ExecStart line."""
    found: list[str] = []
    for line in text.splitlines():
        if line.startswith("ExecStart="):
            found.extend(FLAG.findall(line))
    return found


class SupportAccessTextfileDirAgrees(unittest.TestCase):
    """The writer's role, the exporter's role and the exporter's unit name one directory."""

    def test_the_two_roles_agree(self) -> None:
        grant = variable(GRANT_VARS, "breakglass_grant_host_textfile_dir")
        exporter = variable(EXPORTER_VARS, "node_exporter_support_access_textfile_dir")
        self.assertIsNotNone(grant)
        self.assertEqual(grant, exporter)

    def test_the_unit_reads_it(self) -> None:
        grant = variable(GRANT_VARS, "breakglass_grant_host_textfile_dir")
        self.assertIn(grant, flags(UNIT.read_text(encoding="utf-8")))

    def test_the_unit_still_reads_the_backup_workers_directory(self) -> None:
        backup = variable(EXPORTER_VARS, "node_exporter_textfile_dir")
        self.assertIn(backup, flags(UNIT.read_text(encoding="utf-8")))

    def test_the_two_directories_differ(self) -> None:
        backup = variable(EXPORTER_VARS, "node_exporter_textfile_dir")
        grant = variable(GRANT_VARS, "breakglass_grant_host_textfile_dir")
        self.assertNotEqual(backup, grant)

    def test_the_flag_reader_refuses_a_unit_without_the_flag(self) -> None:
        self.assertEqual(
            [], flags("ExecStart=/usr/local/bin/node_exporter --web.listen-address=x:9100\n")
        )

    def test_the_flag_reader_reads_each_repeat(self) -> None:
        text = "ExecStart=/x --collector.textfile.directory=/a --collector.textfile.directory=/b\n"
        self.assertEqual(["/a", "/b"], flags(text))


if __name__ == "__main__":
    unittest.main()
