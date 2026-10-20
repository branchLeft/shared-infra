"""Unit tests for the egress_nat role: the contracts of its files, which need no container.

The Molecule scenario proves what the role does to a host. These tests prove the
parts of the role that must not change by accident, from the files alone, so that a
change to one of them fails in seconds and names the control it broke.
"""

import unittest
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parents[2]
REPO = ROLE.parents[2]
PROVISION = REPO / "hetzner" / "provision"

# The four files the role delivers, by their name in files/ and in hetzner/provision.
SOURCES = (
    "branchleft_host_egress.sh",
    "branchleft_nat.sh",
    "branchleft-host-egress.service",
    "branchleft-nat.service",
)

SHELL_MODULES = ("ansible.builtin.shell", "ansible.builtin.raw", "ansible.builtin.script")


def load(relative: str) -> object:
    """Parse one YAML file of the role."""
    parsed: object = yaml.safe_load((ROLE / relative).read_text(encoding="utf-8"))
    return parsed


def as_dict(value: object) -> dict[str, object]:
    """Narrow a parsed value to a mapping, failing the test if it is not one."""
    if not isinstance(value, dict):
        raise AssertionError(f"expected a mapping, got {type(value).__name__}")
    return {str(key): item for key, item in value.items()}


def as_list(value: object) -> list[object]:
    """Narrow a parsed value to a list, failing the test if it is not one."""
    if not isinstance(value, list):
        raise AssertionError(f"expected a list, got {type(value).__name__}")
    return list(value)


def module_of(task: dict[str, object]) -> str:
    """The module a task calls: its one key that is not a task keyword."""
    keywords = {
        "name",
        "when",
        "register",
        "notify",
        "failed_when",
        "changed_when",
        "vars",
        "loop",
        "check_mode",
        "block",
        "rescue",
        "always",
    }
    modules = [key for key in task if key not in keywords]
    if len(modules) != 1:
        raise AssertionError(f"cannot tell the module of {task.get('name')}: {modules}")
    return modules[0]


def reconciler_tasks() -> tuple[list[dict[str, object]], list[dict[str, object]], list[object]]:
    """The tasks before the guard, the guard's block and the guard's rescue."""
    tasks = [as_dict(task) for task in as_list(load("tasks/_reconciler.yml"))]
    guard = [task for task in tasks if "block" in task]
    if len(guard) != 1:
        raise AssertionError("expected exactly one guard block in _reconciler.yml")
    block = [as_dict(task) for task in as_list(guard[0]["block"])]
    return tasks, block, as_list(guard[0].get("rescue", []))


def named(tasks: list[dict[str, object]], start: str) -> dict[str, object]:
    """The one task whose name starts with the text."""
    found = [task for task in tasks if str(task.get("name", "")).startswith(start)]
    if len(found) != 1:
        raise AssertionError(f"expected one task named '{start}...', found {len(found)}")
    return found[0]


def position(tasks: list[dict[str, object]], start: str) -> int:
    """The index of the one task whose name starts with the text."""
    return tasks.index(named(tasks, start))


class OneHomeTests(unittest.TestCase):
    """Every delivered file is a link to the file in hetzner/provision, never a copy."""

    def test_each_source_is_a_link_to_its_original(self) -> None:
        for name in SOURCES:
            path = ROLE / "files" / name
            with self.subTest(name=name):
                self.assertTrue(path.is_symlink(), f"files/{name} must be a link, not a copy")
                self.assertEqual(path.resolve(), (PROVISION / name).resolve())

    def test_files_holds_nothing_else(self) -> None:
        present = sorted(path.name for path in (ROLE / "files").iterdir())
        self.assertEqual(present, sorted(SOURCES))

    def test_vars_name_only_files_the_role_holds(self) -> None:
        constants = as_dict(load("vars/main.yml"))
        for key in ("egress_nat_host_egress", "egress_nat_nat_gateway"):
            item = as_dict(constants[key])
            for field in ("reconciler_src", "unit_src"):
                self.assertIn(item[field], SOURCES)


class UnitContractTests(unittest.TestCase):
    """A unit starts the program the role installs, at the path it installs it to."""

    def test_each_unit_runs_the_reconciler_the_role_installs(self) -> None:
        constants = as_dict(load("vars/main.yml"))
        for key in ("egress_nat_host_egress", "egress_nat_nat_gateway"):
            item = as_dict(constants[key])
            unit = (ROLE / "files" / str(item["unit_src"])).read_text(encoding="utf-8")
            with self.subTest(unit=item["unit_name"]):
                self.assertIn(f"ExecStart={item['reconciler_dest']}\n", unit)

    def test_each_unit_is_installed_under_the_name_the_shell_script_used(self) -> None:
        constants = as_dict(load("vars/main.yml"))
        self.assertEqual(
            as_dict(constants["egress_nat_host_egress"])["unit_name"],
            "branchleft-host-egress.service",
        )
        self.assertEqual(
            as_dict(constants["egress_nat_nat_gateway"])["unit_name"],
            "branchleft-nat.service",
        )

    def test_each_reconciler_is_installed_under_usr_local_sbin(self) -> None:
        constants = as_dict(load("vars/main.yml"))
        self.assertEqual(
            as_dict(constants["egress_nat_host_egress"])["reconciler_dest"],
            "/usr/local/sbin/branchleft-host-egress",
        )
        self.assertEqual(
            as_dict(constants["egress_nat_nat_gateway"])["reconciler_dest"],
            "/usr/local/sbin/branchleft-nat",
        )


class InstallTests(unittest.TestCase):
    """Owner, group, mode and order of the install, as the shell scripts did it."""

    def test_reconciler_is_root_owned_and_not_writable_by_others(self) -> None:
        _, block, _ = reconciler_tasks()
        copy = as_dict(named(block, "Install the reconciler")["ansible.builtin.copy"])
        self.assertEqual(copy["owner"], "root")
        self.assertEqual(copy["group"], "root")
        self.assertEqual(copy["mode"], "0755")

    def test_unit_is_root_owned_and_mode_0644(self) -> None:
        _, block, _ = reconciler_tasks()
        copy = as_dict(named(block, "Install the unit")["ansible.builtin.copy"])
        self.assertEqual(copy["owner"], "root")
        self.assertEqual(copy["group"], "root")
        self.assertEqual(copy["mode"], "0644")

    def test_both_files_are_kept_when_replaced_so_the_guard_can_restore_them(self) -> None:
        _, block, _ = reconciler_tasks()
        for start in ("Install the reconciler", "Install the unit"):
            copy = as_dict(named(block, start)["ansible.builtin.copy"])
            with self.subTest(task=start):
                self.assertIs(copy["backup"], True)

    def test_order_is_the_order_of_the_shell_scripts(self) -> None:
        _, block, _ = reconciler_tasks()
        order = [
            position(block, "Install the reconciler"),
            position(block, "Install the unit"),
            position(block, "Load the unit"),
            position(block, "Enable the unit"),
            position(block, "Restart the unit"),
            position(block, "Start the unit"),
            position(block, "Assert the unit"),
        ]
        self.assertEqual(order, sorted(order))

    def test_unit_install_reloads_systemd_before_the_unit_is_enabled(self) -> None:
        _, block, _ = reconciler_tasks()
        self.assertEqual(named(block, "Install the unit")["notify"], "Reload systemd manager")
        flush = named(block, "Load the unit")
        self.assertEqual(flush["ansible.builtin.meta"], "flush_handlers")

    def test_restart_runs_only_when_a_file_changed(self) -> None:
        _, block, _ = reconciler_tasks()
        restart = named(block, "Restart the unit")
        condition = str(restart["when"])
        self.assertIn("egress_nat_reconciler_copy.changed", condition)
        self.assertIn("egress_nat_unit_copy.changed", condition)
        spec = as_dict(restart["ansible.builtin.systemd_service"])
        self.assertEqual(spec["state"], "restarted")

    def test_enable_does_not_start(self) -> None:
        _, block, _ = reconciler_tasks()
        spec = as_dict(named(block, "Enable the unit")["ansible.builtin.systemd_service"])
        self.assertIs(spec["enabled"], True)
        self.assertNotIn("state", spec)


class GuardTests(unittest.TestCase):
    """A restart that fails puts the previous files back, runs them, and fails the role."""

    def test_the_previous_state_is_read_before_the_guard(self) -> None:
        tasks, _, _ = reconciler_tasks()
        before = [str(task.get("register")) for task in tasks if "register" in task]
        self.assertIn("egress_nat_reconciler_before", before)
        self.assertIn("egress_nat_unit_before", before)
        guard_at = next(i for i, task in enumerate(tasks) if "block" in task)
        self.assertLess(tasks.index(named(tasks, "Read whether the reconciler")), guard_at)
        self.assertLess(tasks.index(named(tasks, "Read whether the unit")), guard_at)

    def test_the_guard_has_a_rescue(self) -> None:
        _, _, rescue = reconciler_tasks()
        self.assertGreater(len(rescue), 0)

    def test_the_rescue_restores_both_files_from_their_kept_copies(self) -> None:
        _, _, rescue = reconciler_tasks()
        tasks = [as_dict(task) for task in rescue]
        for start, dest_key in (
            ("Put the previous reconciler back", "reconciler"),
            ("Put the previous unit back", "unit"),
        ):
            copy = as_dict(named(tasks, start)["ansible.builtin.copy"])
            with self.subTest(task=start):
                self.assertIs(copy["remote_src"], True)
                self.assertIn(f"egress_nat_{dest_key}_copy.backup_file", str(copy["src"]))

    def test_the_rescue_removes_what_a_first_install_wrote(self) -> None:
        _, _, rescue = reconciler_tasks()
        tasks = [as_dict(task) for task in rescue]
        for start in (
            "Remove a unit this run installed",
            "Remove a reconciler this run installed",
        ):
            task = named(tasks, start)
            with self.subTest(task=start):
                self.assertEqual(as_dict(task["ansible.builtin.file"])["state"], "absent")
                self.assertIn("not egress_nat_", str(task["when"]))

    def test_the_rescue_runs_the_previous_reconciler_again(self) -> None:
        _, _, rescue = reconciler_tasks()
        tasks = [as_dict(task) for task in rescue]
        rerun = named(tasks, "Run the previous reconciler again")
        spec = as_dict(rerun["ansible.builtin.systemd_service"])
        self.assertEqual(spec["state"], "restarted")
        self.assertIn("egress_nat_reconciler_before.stat.exists", str(rerun["when"]))

    def test_the_rescue_ends_by_failing_the_role(self) -> None:
        _, _, rescue = reconciler_tasks()
        last = as_dict(rescue[-1])
        self.assertIn("ansible.builtin.fail", last)

    def test_the_rescue_reloads_systemd_before_it_runs_the_unit(self) -> None:
        _, _, rescue = reconciler_tasks()
        tasks = [as_dict(task) for task in rescue]
        self.assertLess(
            position(tasks, "Make systemd read"),
            position(tasks, "Run the previous reconciler again"),
        )

    def test_the_kept_copies_are_removed_on_success_and_on_revert(self) -> None:
        _, block, rescue = reconciler_tasks()
        tasks = [as_dict(task) for task in rescue]
        for scope in (block, tasks):
            for start in ("Remove the kept copy of the previous reconciler",):
                task = named(scope, start)
                self.assertEqual(as_dict(task["ansible.builtin.file"])["state"], "absent")


class EntryPointTests(unittest.TestCase):
    """The gateway half is installed only where the switch says so, after the host half."""

    def test_host_egress_comes_first_and_is_unconditional(self) -> None:
        tasks = [as_dict(task) for task in as_list(load("tasks/main.yml"))]
        self.assertEqual(len(tasks), 2)
        self.assertNotIn("when", tasks[0])
        first = as_dict(tasks[0]["vars"])
        self.assertEqual(first["egress_nat_item"], "{{ egress_nat_host_egress }}")

    def test_nat_gateway_is_gated_on_the_switch(self) -> None:
        tasks = [as_dict(task) for task in as_list(load("tasks/main.yml"))]
        second = as_dict(tasks[1]["vars"])
        self.assertEqual(second["egress_nat_item"], "{{ egress_nat_nat_gateway }}")
        self.assertIn("egress_nat_gateway_enabled", str(tasks[1]["when"]))

    def test_the_switch_is_off_by_default(self) -> None:
        defaults = as_dict(load("defaults/main.yml"))
        self.assertIs(defaults["egress_nat_gateway_enabled"], False)
        spec = as_dict(as_dict(as_dict(load("meta/argument_specs.yml"))["argument_specs"])["main"])
        options = as_dict(spec["options"])
        self.assertIs(as_dict(options["egress_nat_gateway_enabled"])["default"], False)


class InterfaceTests(unittest.TestCase):
    """The interface the spec declares is the interface the role reads (ANS-7)."""

    def test_spec_and_defaults_agree(self) -> None:
        defaults = as_dict(load("defaults/main.yml"))
        spec = as_dict(as_dict(as_dict(load("meta/argument_specs.yml"))["argument_specs"])["main"])
        options = as_dict(spec["options"])
        self.assertEqual(sorted(options), sorted(defaults))
        for name, option in options.items():
            self.assertEqual(as_dict(option)["default"], defaults[name])

    def test_every_variable_carries_the_role_name(self) -> None:
        for relative in ("defaults/main.yml", "vars/main.yml"):
            for name in as_dict(load(relative)):
                with self.subTest(file=relative, name=name):
                    self.assertTrue(name.startswith("egress_nat_"))


class NoShellTests(unittest.TestCase):
    """ANS-3: no shell, raw or script task in the role's tasks or handlers."""

    def walk(self, tasks: list[object]) -> list[dict[str, object]]:
        """Every task, with the tasks inside blocks."""
        found: list[dict[str, object]] = []
        for raw in tasks:
            task = as_dict(raw)
            found.append(task)
            for key in ("block", "rescue", "always"):
                if key in task:
                    found.extend(self.walk(as_list(task[key])))
        return found

    def test_no_task_calls_a_shell_module(self) -> None:
        for relative in ("tasks/main.yml", "tasks/_reconciler.yml", "handlers/main.yml"):
            for task in self.walk(as_list(load(relative))):
                if "block" in task:
                    continue
                with self.subTest(file=relative, task=task.get("name")):
                    self.assertNotIn(module_of(task), SHELL_MODULES)


if __name__ == "__main__":
    unittest.main()
