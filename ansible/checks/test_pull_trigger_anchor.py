"""The pull's trust anchor is declared once, and every pulled host loads it.

The signer allowlist and the remote are the anchor: whoever lands a commit a listed
key signed gets root on each pulled host. The trigger runs playbooks with
`-i localhost,`, which loads no group variables, so each host's play must load the
shared file in vars_files. An inventory check alone would pass while that is wrong.
Run by the Ansible job.
"""

import re
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]

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
                host = playbook.removesuffix(".yml")
                plays: list[dict[str, object]] = yaml.safe_load(
                    (PLAYBOOKS / playbook).read_text(encoding="utf-8")
                )
                # The play that targets the host: `all` reaches it, and so does its name.
                targeted = [p for p in plays if p.get("hosts") in ("all", "localhost", host)]
                self.assertEqual(len(targeted), 1, f"{playbook} needs one play that targets {host}")
                vars_files = targeted[0].get("vars_files")
                loaded = [str(f) for f in vars_files] if isinstance(vars_files, list) else []
                for name in (SHARED, group_file):
                    self.assertTrue(
                        any(f.endswith(f"group_vars/{name}") for f in loaded),
                        f"{playbook} must load {name} in vars_files of its play for {host}: "
                        "the trigger runs with localhost,",
                    )

    def test_each_group_names_its_own_playbook_on_the_allowlist(self) -> None:
        for playbook, group_file in PULLED_HOSTS.items():
            with self.subTest(group_file=group_file):
                text = (GROUP_VARS / group_file).read_text(encoding="utf-8")
                self.assertIn(f"pull_trigger_playbook: ansible/playbooks/{playbook}", text)
                self.assertIn(f"  - ansible/playbooks/{playbook}", text)


if __name__ == "__main__":
    unittest.main()
