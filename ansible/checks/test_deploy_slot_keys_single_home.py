"""Check that the slot provisioning program has one home and that the role's pins match it.

The program is `hetzner/provision/provision_deploy_slot.py`. The deploy_slot_keys role installs it
from there and holds no copy and no link of it. Its module pins, for itself, every path, mode and
word the program writes into the deploy account's authorized_keys, and refuses a program whose
constants differ. This file holds those pins to the program and to the wrapper that deploy_tooling
installs, so a change to one of the three without the others fails here, in CI, and not on a host.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

import deploy_tooling_vars as tooling_vars
from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "deploy_slot_keys"
MODULE = ROLE / "library" / "deploy_slot_keys_reconcile.py"
PROGRAM_NAME = "provision_deploy_slot.py"
PROGRAM = ROOT / "hetzner" / "provision" / PROGRAM_NAME
# Program constants the module does not pin because they are not part of what the program writes:
# a bit mask for the directories above the program, and a size limit on a key.
UNPINNED_PROGRAM_CONSTANTS = frozenset({"FORBIDDEN_WRITE_BITS", "MAX_KEY_BLOB"})


def module_pins(source: str) -> tuple[dict[str, str | int], dict[str, str]]:
    """Return the module's pinned values and which program constant each one is checked against.

    The first mapping is every top-level ``PINNED_*`` literal by name. The second is the module's
    ``PINNED_PROGRAM_CONSTANTS``: the program constant's name to the name of the pin it must equal.
    """
    values: dict[str, str | int] = {}
    pairs: dict[str, str] = {}
    for node in ast.parse(source).body:
        target, value = _assignment(node)
        if target is None or value is None:
            continue
        if target.startswith("PINNED_") and target != "PINNED_PROGRAM_CONSTANTS":
            literal = ast.literal_eval(value)
            if isinstance(literal, (str, int)):
                values[target] = literal
        elif target == "PINNED_PROGRAM_CONSTANTS" and isinstance(value, ast.Dict):
            for key, pin in zip(value.keys, value.values, strict=True):
                if isinstance(key, ast.Constant) and isinstance(pin, ast.Name):
                    pairs[str(key.value)] = pin.id
    return values, pairs


def _assignment(node: ast.stmt) -> tuple[str | None, ast.expr | None]:
    """Return the name and value of a top-level assignment, either plain or annotated."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        name = node.targets[0]
        if isinstance(name, ast.Name):
            return name.id, node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
        return node.target.id, node.value
    return None, None


def load_program(path: Path = PROGRAM) -> ModuleType:
    """Import the slot program from its file, without putting its directory on the path.

    Raises:
        ImportError: the file cannot be loaded as a module.
    """
    spec = importlib.util.spec_from_file_location("slot_program_under_check", path)
    if spec is None or spec.loader is None:
        message = f"cannot load {path}"
        raise ImportError(message)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def program_constants(program: ModuleType) -> dict[str, str | int]:
    """Return the program's top-level upper-case constants that are text or a whole number."""
    found: dict[str, str | int] = {}
    for name, value in vars(program).items():
        if name.isupper() and isinstance(value, (str, int)) and not isinstance(value, bool):
            found[name] = value
    return found


def copies_of_program(role: Path, program: Path) -> list[str]:
    """Return every path under the role that is a copy of, or a link to, the program.

    A file with the program's name, a file with the program's bytes under any name, and any
    symbolic link at all (a link under the role is a second path to some other file) are copies.
    """
    wanted = hashlib.sha256(program.read_bytes()).hexdigest()
    found: list[str] = []
    for path in sorted(role.rglob("*")):
        relative = path.relative_to(role).as_posix()
        if path.is_symlink():
            found.append(relative)
        elif path.is_file() and (
            path.name == program.name or hashlib.sha256(path.read_bytes()).hexdigest() == wanted
        ):
            found.append(relative)
    return found


class SlotProgramSingleHome(unittest.TestCase):
    """The role's pins agree with the program, and the role holds no second copy of it."""

    pins: dict[str, str | int]
    pairs: dict[str, str]
    constants: dict[str, str | int]

    @classmethod
    def setUpClass(cls) -> None:
        """Read the module's pins and the program's constants once."""
        cls.pins, cls.pairs = module_pins(MODULE.read_text("utf-8"))
        cls.constants = program_constants(load_program())

    def test_the_module_pins_something_for_every_constant_it_names(self) -> None:
        self.assertTrue(self.pairs, "the module names no program constant to check")
        for constant, pin in self.pairs.items():
            with self.subTest(constant=constant):
                self.assertIn(pin, self.pins)

    def test_every_pin_equals_the_programs_own_constant(self) -> None:
        for constant, pin in self.pairs.items():
            with self.subTest(constant=constant):
                self.assertIn(constant, self.constants)
                self.assertEqual(self.pins[pin], self.constants[constant])

    def test_every_constant_the_program_writes_with_is_pinned(self) -> None:
        # A new path, mode or word in the program is a new thing it can write into
        # authorized_keys. It has to be pinned in the module, or named here as not written.
        unpinned = set(self.constants) - set(self.pairs) - UNPINNED_PROGRAM_CONSTANTS
        self.assertEqual(set(), unpinned)

    def test_the_unpinned_names_are_still_constants_of_the_program(self) -> None:
        # An entry that no longer names a constant would silently excuse a future one.
        self.assertEqual(set(), UNPINNED_PROGRAM_CONSTANTS - set(self.constants))

    def test_the_pinned_wrapper_is_the_one_deploy_tooling_installs(self) -> None:
        installed = tooling_vars.load_vars()["deploy_tooling_wrapper_path"]
        self.assertEqual(installed, self.pins["PINNED_WRAPPER"])

    def test_the_pinned_stack_directory_is_one_deploy_tooling_creates(self) -> None:
        directories = [
            target.path
            for target in tooling_vars.targets(tooling_vars.load_vars())
            if target.kind == "directory"
        ]
        self.assertIn(self.pins["PINNED_STACK_DIR"], directories)

    def test_the_role_installs_the_program_from_its_one_home(self) -> None:
        role_vars = tooling_vars.load_vars(ROLE)
        self.assertEqual(PROGRAM_NAME, role_vars["deploy_slot_keys_program_source"])
        home = tooling_vars.resolve(
            str(role_vars["deploy_slot_keys_programs_dir"]),
            {**role_vars, "role_path": str(ROLE)},
        )
        self.assertEqual(PROGRAM.parent.resolve(), Path(home).resolve())
        self.assertTrue(PROGRAM.is_file())

    def test_the_program_is_not_a_target_of_deploy_tooling(self) -> None:
        # deploy_tooling installs the programs it names and no other role may write them.
        names = tooling_vars.program_names(tooling_vars.load_vars())
        self.assertNotIn(PROGRAM_NAME, names)

    def test_the_role_installs_to_a_path_deploy_tooling_does_not_own(self) -> None:
        role_vars = tooling_vars.load_vars(ROLE)
        owned = {target.path for target in tooling_vars.targets(tooling_vars.load_vars())}
        self.assertNotIn(role_vars["deploy_slot_keys_program_path"], owned)

    def test_the_role_holds_no_copy_and_no_link_of_the_program(self) -> None:
        self.assertEqual([], copies_of_program(ROLE, PROGRAM))

    def test_app1_lists_the_role_after_deploy_tooling(self) -> None:
        # The wrapper the forced commands run is installed by deploy_tooling, so it is listed first.
        document, problem = load_yaml(ROOT / "ansible" / "checks" / "host_roles.yml")
        self.assertIsNone(problem)
        self.assertIsInstance(document, dict)
        roles = document["app1"] if isinstance(document, dict) else []
        self.assertIn("deploy_slot_keys", roles)
        self.assertLess(roles.index("deploy_tooling"), roles.index("deploy_slot_keys"))


class CopyDetection(unittest.TestCase):
    """The copy check finds what it is meant to find, so an empty result means something."""

    def setUp(self) -> None:
        """Make a role tree and a program to compare with, outside the repository."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        base = Path(self.directory.name)
        self.role = base / "role"
        (self.role / "files").mkdir(parents=True)
        self.program = base / PROGRAM_NAME
        self.program.write_text("EXAMPLE_PROGRAM_BODY = 1\n", "utf-8")

    def test_a_tree_without_a_copy_is_clean(self) -> None:
        (self.role / "files" / "other.txt").write_text("unrelated\n", "utf-8")
        self.assertEqual([], copies_of_program(self.role, self.program))

    def test_a_file_with_the_programs_name_is_found(self) -> None:
        (self.role / "files" / PROGRAM_NAME).write_text("changed\n", "utf-8")
        self.assertEqual([f"files/{PROGRAM_NAME}"], copies_of_program(self.role, self.program))

    def test_the_programs_bytes_under_another_name_are_found(self) -> None:
        (self.role / "files" / "renamed.py").write_bytes(self.program.read_bytes())
        self.assertEqual(["files/renamed.py"], copies_of_program(self.role, self.program))

    def test_a_link_is_found_whatever_it_points_at(self) -> None:
        (self.role / "files" / "link").symlink_to(self.program)
        self.assertEqual(["files/link"], copies_of_program(self.role, self.program))


class PinReader(unittest.TestCase):
    """The reader of the module's pins sees a pin, a pairing and a missing name."""

    def test_it_reads_a_pin_and_the_constant_it_is_checked_against(self) -> None:
        source = (
            "PINNED_HOME = '/example/home'\n"
            "PINNED_MODE = 0o750\n"
            "PINNED_PROGRAM_CONSTANTS: Mapping[str, str | int] = {'HOME': PINNED_HOME,"
            " 'MODE': PINNED_MODE}\n"
            "UNRELATED = 'x'\n"
        )
        values, pairs = module_pins(source)
        self.assertEqual({"PINNED_HOME": "/example/home", "PINNED_MODE": 0o750}, values)
        self.assertEqual({"HOME": "PINNED_HOME", "MODE": "PINNED_MODE"}, pairs)

    def test_a_pair_that_names_no_pin_is_left_for_the_check_to_refuse(self) -> None:
        values, pairs = module_pins("PINNED_PROGRAM_CONSTANTS = {'HOME': PINNED_MISSING}\n")
        self.assertEqual({}, values)
        self.assertEqual({"HOME": "PINNED_MISSING"}, pairs)


if __name__ == "__main__":
    unittest.main()
