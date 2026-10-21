"""The pull's trust anchor is declared once, and every pulled host loads it.

The signer allowlist and the remote are the trust anchor of the pull: whoever can
land a commit that a listed key signed gets root on every pulled host. So each
must be declared in exactly one file of the inventory, and each host playbook
must load that file. The host's trigger runs its playbook with `-i localhost,`,
which loads no group variables, so the load is made by vars_files in the playbook
itself. A check of the inventory alone would pass while that load is wrong.

The group variable files are flat, so their top-level keys are read by pattern
and no YAML library is needed (the lock carries none with type stubs).

Run by the Ansible job: python -m unittest discover -b -s ansible/checks -p "test_*.py".
"""

import re
import unittest
from pathlib import Path

ANSIBLE: Path = Path(__file__).resolve().parents[1]
INVENTORY: Path = ANSIBLE / "inventories" / "production"
GROUP_VARS: Path = INVENTORY / "group_vars"
PLAYBOOKS: Path = ANSIBLE / "playbooks"
SHARED: str = "all/pull_trigger.yml"
ANCHOR_KEYS: tuple[str, ...] = ("pull_trigger_signers", "pull_trigger_remote_url")
# Each playbook that runs the pull, and the group file that holds its values.
PULLED_HOSTS: dict[str, str] = {
    "edge1.yml": "edge/pull_trigger.yml",
    "mx1.yml": "mx/pull_trigger.yml",
}
KEY_PATTERN: re.Pattern[str] = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):", re.MULTILINE)


def inventory_files() -> list[Path]:
    # Every YAML file of the inventory, host_vars included: a second copy in any of
    # them is a second trust anchor, whatever directory it sits in.
    return sorted(INVENTORY.rglob("*.yml"))


def top_level_keys(path: Path) -> set[str]:
    return set(KEY_PATTERN.findall(path.read_text(encoding="utf-8")))


def home_of(path: Path) -> str:
    base = GROUP_VARS if path.is_relative_to(GROUP_VARS) else INVENTORY
    return str(path.relative_to(base))


class TrustAnchorDeclaredOnce(unittest.TestCase):
    def test_each_anchor_key_is_declared_in_exactly_one_file(self) -> None:
        for key in ANCHOR_KEYS:
            with self.subTest(key=key):
                homes = [home_of(p) for p in inventory_files() if key in top_level_keys(p)]
                self.assertEqual(
                    homes,
                    [SHARED],
                    f"{key} must be declared only in {SHARED}; found in {homes}",
                )

    def test_the_shared_file_names_both_keys(self) -> None:
        keys = top_level_keys(GROUP_VARS / SHARED)
        self.assertTrue(set(ANCHOR_KEYS) <= keys, f"{SHARED} lacks {set(ANCHOR_KEYS) - keys}")


class EveryPulledHostLoadsTheAnchor(unittest.TestCase):
    def test_each_host_playbook_loads_the_shared_file_and_its_group_file(self) -> None:
        for playbook, group_file in PULLED_HOSTS.items():
            with self.subTest(playbook=playbook):
                text = (PLAYBOOKS / playbook).read_text(encoding="utf-8")
                self.assertIn(
                    f"group_vars/{SHARED}",
                    text,
                    f"{playbook} must load {SHARED} in vars_files: "
                    "the trigger runs with localhost,",
                )
                self.assertIn(f"group_vars/{group_file}", text)

    def test_each_group_names_its_own_playbook_on_the_allowlist(self) -> None:
        for playbook, group_file in PULLED_HOSTS.items():
            with self.subTest(group_file=group_file):
                text = (GROUP_VARS / group_file).read_text(encoding="utf-8")
                self.assertIn(f"pull_trigger_playbook: ansible/playbooks/{playbook}", text)
                self.assertIn(f"  - ansible/playbooks/{playbook}", text)


if __name__ == "__main__":
    unittest.main()
