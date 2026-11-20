"""Unit tests for how the monitoring_stack verify plays are shared out between the scenarios.

The plays of the verify step are shared out between three scenarios, each its own shard, so
that no shard takes longer than about twelve minutes. A play that no scenario imports would
pass silently (its shard simply does not run it), so these tests read the files and fail on
a verify file that no scenario imports, one that two scenarios import, a scenario the guard
in tasks/assert_parts.yml does not name, a play that is missing or has moved, a scenario that
does not end with the log scan, and a scenario that leaves out a step the default scenario
must run.

Sabotage, the red and then green for the change that made them: delete the import of
verify_pager.yml from molecule/pager/verify.yml, or a name from the guard's scenario list, or
the log-scan import from a verify file, and these tests fail; put it back and they pass.
"""

import re
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROLE = Path(__file__).resolve().parents[2]
MOLECULE = ROLE / "molecule"
DEFAULT = MOLECULE / "default"
# The steps only the default scenario runs, one run of each for the whole role (ANS-15).
DEFAULT_ONLY_STEPS = ("check-fresh", "idempotence", "check-configured", "molecule-check")
LOG_SCAN = "verify_log_scan.yml"
# Which verify file each scenario runs, and the plays each file holds, in order. A play added,
# renamed or moved is a change to this list, so a play cannot drop out of every file unseen.
FILES = {
    "default": "verify.yml",
    "pager": "verify_pager.yml",
    "restarts": "verify_restarts.yml",
}
PLAYS = {
    "verify.yml": [
        "Assert every scenario that holds cases runs verify",
        "Verify the instance",
        "Verify a play variable does not move the project directory",
        "Verify the monitoring secrets file and the renderer path",
        "Exercise the restart decision for a stamp, a rotated key and a failed run",
    ],
    "verify_pager.yml": [
        "Exercise the restart decision for a key another role owns and for the renderer",
        "Verify the stale NTFY_ lines are cleared and the pager gauge follows the pager file",
    ],
    "verify_restarts.yml": [
        "Exercise the restart decision for a new drop-in, a unit that is stopped, a failing restart"
        " and a plan",
    ],
    LOG_SCAN: ["Scan the log for the values"],
}
SNAPS_READ = re.compile(r"monitoring_stack_verify_snaps\.(\w+)")
SNAPS_TAKEN = re.compile(r"monitoring_stack_verify_snap_name: (\w+)")
SHARED_VARS = "{{ playbook_dir }}/../default/vars/restart_decision.yml"


def scenario_dirs() -> list[str]:
    """Return the scenario directories: every directory under molecule/ with a molecule.yml."""
    return sorted(
        path.name
        for path in MOLECULE.iterdir()
        if path.is_dir() and (path / "molecule.yml").exists()
    )


def skipped_steps(scenario: str) -> list[str]:
    """Return the steps the scenario's skip-steps.txt leaves out, none when it has no file."""
    path = MOLECULE / scenario / "skip-steps.txt"
    if not path.is_file():
        return []
    lines = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def plays(path: Path) -> list[dict[str, object]]:
    """Return the top-level plays and imports of a playbook file."""
    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [dict(entry) for entry in parsed]


def imports(path: Path) -> list[str]:
    """Return the playbooks a file imports, in order."""
    return [
        str(entry["ansible.builtin.import_playbook"])
        for entry in plays(path)
        if "ansible.builtin.import_playbook" in entry
    ]


def play_names(path: Path) -> list[str]:
    """Return the names of the plays a file holds itself, in order."""
    return [
        str(entry["name"])
        for entry in plays(path)
        if "ansible.builtin.import_playbook" not in entry
    ]


class VerifyParts(unittest.TestCase):
    def test_the_scenarios_are_the_three_the_guard_names(self) -> None:
        self.assertEqual(scenario_dirs(), sorted(FILES))
        guard = yaml.safe_load((DEFAULT / "tasks" / "assert_parts.yml").read_text(encoding="utf-8"))
        named = guard[0]["vars"]["monitoring_stack_verify_scenarios"]
        self.assertEqual(sorted(named), sorted(FILES))

    def test_every_verify_file_holds_the_plays_listed_for_it(self) -> None:
        for name, expected in PLAYS.items():
            with self.subTest(file=name):
                self.assertEqual(play_names(DEFAULT / name), expected)

    def test_no_verify_file_is_left_out_or_run_twice(self) -> None:
        on_disk = sorted(path.name for path in DEFAULT.glob("verify*.yml"))
        self.assertEqual(on_disk, sorted(PLAYS))
        run_by: dict[str, list[str]] = {name: [] for name in FILES.values()}
        for scenario in FILES:
            verify = MOLECULE / scenario / "verify.yml"
            for target in imports(verify):
                if scenario != "default":
                    self.assertEqual(target, f"../default/{FILES[scenario]}")
                    run_by[FILES[scenario]].append(scenario)
        run_by["verify.yml"] = ["default"]
        for name, scenarios in run_by.items():
            with self.subTest(file=name):
                self.assertEqual(len(scenarios), 1)

    def test_every_scenario_ends_with_the_log_scan_over_its_own_log(self) -> None:
        for scenario, name in FILES.items():
            with self.subTest(scenario=scenario):
                self.assertEqual(imports(DEFAULT / name), [LOG_SCAN])
                self.assertEqual(
                    plays(DEFAULT / name)[-1],
                    {
                        "name": "Scan the log as every scenario does",
                        "ansible.builtin.import_playbook": LOG_SCAN,
                    },
                )

    def test_the_restart_decision_plays_read_the_one_set_of_vars(self) -> None:
        self.assertTrue((DEFAULT / "vars" / "restart_decision.yml").is_file())
        for name in ("verify.yml", "verify_pager.yml", "verify_restarts.yml"):
            with self.subTest(file=name):
                text = (DEFAULT / name).read_text(encoding="utf-8")
                self.assertIn(SHARED_VARS, text)

    def test_every_scenario_runs_verify_and_only_default_plans_and_checks_twice(self) -> None:
        for scenario in FILES:
            with self.subTest(scenario=scenario):
                self.assertTrue((MOLECULE / scenario / "verify.yml").is_file())
                skipped = skipped_steps(scenario)
                self.assertNotIn("verify", skipped)
                if scenario == "default":
                    self.assertEqual(skipped, [], "the default scenario runs every step")
                else:
                    self.assertEqual(sorted(skipped), sorted(DEFAULT_ONLY_STEPS))

    def test_every_snapshot_a_verify_file_reads_is_taken_in_the_same_file(self) -> None:
        # A snapshot is taken in the run that holds the play, and each scenario is a run of its
        # own container, so a name read in one file and taken in another is undefined at run time.
        for name in PLAYS:
            with self.subTest(file=name):
                text = (DEFAULT / name).read_text(encoding="utf-8")
                missing = sorted(set(SNAPS_READ.findall(text)) - set(SNAPS_TAKEN.findall(text)))
                self.assertEqual(missing, [], f"{name} reads snapshots it never takes")

    def test_no_file_names_a_shared_variable_without_its_role_prefix(self) -> None:
        # The shared names carry the role prefix (ansible-lint's var-naming rule). A play, a task
        # file or a message that still says verify_<name> reads an undefined variable at run time.
        shared = yaml.safe_load((DEFAULT / "vars" / "restart_decision.yml").read_text("utf-8"))
        prefix = "monitoring_stack_verify_"
        stale = [rf"\bverify_{re.escape(name[len(prefix) :])}\b" for name in shared]
        for path in sorted(DEFAULT.rglob("*.yml")):
            text = path.read_text(encoding="utf-8")
            with self.subTest(file=str(path.relative_to(MOLECULE))):
                self.assertEqual([p for p in stale if re.search(p, text)], [])

    def test_the_other_scenarios_share_the_default_scenarios_play_files(self) -> None:
        for scenario in set(FILES) - {"default"}:
            with self.subTest(scenario=scenario):
                link = MOLECULE / scenario / "molecule.yml"
                self.assertTrue(link.is_symlink())
                self.assertEqual(link.resolve(), DEFAULT / "molecule.yml")
                for name in ("converge.yml", "prepare.yml"):
                    text = (MOLECULE / scenario / name).read_text(encoding="utf-8")
                    self.assertIn(f"import_playbook: ../default/{name}", text)


if __name__ == "__main__":
    unittest.main()
