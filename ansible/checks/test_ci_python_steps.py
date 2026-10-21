"""Tests that the Python under ansible/ is checked by the Ansible workflow.

A program a new host runs as root, and the tool that builds its first-boot record, are
code like any other: mypy, ruff and their unit tests must run on them in CI. These tests
read .github/workflows/ansible.yml and fail when a directory of such Python is not named
there, so adding one without wiring it is red rather than silently unchecked.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"
WORKFLOW = (ROOT / ".github" / "workflows" / "ansible.yml").read_text(encoding="utf-8")

# The Python directories directly under ansible/ that hold their own tests.
UNITTEST_STEP = re.compile(r"-m unittest discover -b -s ansible/(?P<name>[a-z_]+) -p")
SELECTOR = re.compile(r"grep -qs '(?P<pattern>[^']+)' \"\$role/pyproject.toml\"")


ROOTS = ANSIBLE / "roles"
GOOD_PYPROJECT = '[tool.mypy]\nmypy_path = "$MYPY_CONFIG_FILE_DIR/files"\n'


def selector_pattern() -> re.Pattern[str]:
    """Return the pattern the workflow's role program step greps each pyproject.toml for.

    Raises:
        AssertionError: The workflow has no such step.
    """
    selector = SELECTOR.search(WORKFLOW)
    if selector is None:
        message = "the role program step has no pyproject.toml selector"
        raise AssertionError(message)
    return re.compile(selector.group("pattern"), re.MULTILINE)


def roles_shipping_a_program(roles: Path) -> set[str]:
    """Return the roles with a Python file directly in files/: the code a host runs as root.

    Fixtures under molecule/ are not a role's program and are not counted.
    """
    return {role.name for role in roles.iterdir() if any((role / "files").glob("*.py"))}


def unselected_roles(roles: Path, pattern: re.Pattern[str]) -> set[str]:
    """Return the roles that ship a program and that the workflow's step does not check.

    The step visits a role only when it has tests/unit/, and skips it when it has a library/
    or when its pyproject.toml has no line that matches the selector, so each of those is
    a way for a program to get no mypy, ruff or unit tests in silence.
    """
    skipped: set[str] = set()
    for name in roles_shipping_a_program(roles):
        role = roles / name
        pyproject = role / "pyproject.toml"
        selected = (
            (role / "tests" / "unit").is_dir()
            and not (role / "library").is_dir()
            and pyproject.is_file()
            and pattern.search(pyproject.read_text(encoding="utf-8")) is not None
        )
        if not selected:
            skipped.add(name)
    return skipped


def make_role(
    roles: Path,
    name: str,
    *,
    pyproject: str | None,
    tests: bool,
    library: bool = False,
    program: bool = True,
) -> None:
    """Build a role directory with the parts the selector looks at."""
    role = roles / name
    (role / "files").mkdir(parents=True)
    if program:
        (role / "files" / "program.py").write_text("", encoding="utf-8")
    if pyproject is not None:
        (role / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    if tests:
        (role / "tests" / "unit").mkdir(parents=True)
    if library:
        (role / "library").mkdir()


# One matcher for every install or download of the lock, in each form the repository writes:
# pip, pip3, python -m pip and uv pip, with -r, --requirement or a bare path to requirements.txt.
LOCK_INSTALL = re.compile(
    r"(?:\bpip3?\"?|\buv pip)\s+(?:install|download|sync)\b.*requirements\.txt"
)
WHEELS_ONLY = "--only-binary=:all:"
README = ANSIBLE / "README.md"


def lock_installs(text: str) -> list[str]:
    """Return every line that installs or downloads the lock, with or without the hash flag.

    A backslash continuation is joined to the line it continues first, so a command split over
    two lines is matched whole, as the shell reads it.
    """
    joined = text.replace("\\\n", " ")
    return [line.strip() for line in joined.splitlines() if LOCK_INSTALL.search(line)]


def sdist_reachable_lines(text: str) -> list[str]:
    """Return the lock installs that do not refuse a source build.

    --require-hashes alone does not cover everything pip runs: an entry with no wheel for
    the interpreter is built from its source archive, and the build backend it asks for is
    fetched from the index with no hash. --only-binary=:all: removes the build.
    """
    return [line for line in lock_installs(text) if WHEELS_ONLY not in line]


def readmes_outside_the_recipe() -> list[Path]:
    """Return every README* file under ansible/ except the one that holds the install recipe.

    The skeleton's README.md.j2 is included: every new role's README is made from it.
    """
    return [path for path in ANSIBLE.rglob("README*") if path.is_file() and path != README]


def python_directories() -> set[str]:
    """Return the directories directly under ansible/ with a test_*.py file in them."""
    return {path.parent.name for path in ANSIBLE.glob("*/test_*.py")}


def step_lines(command: str) -> list[str]:
    """Return the workflow's lines that run one tool over the directories named after it."""
    return [line for line in WORKFLOW.splitlines() if command in line]


class WorkflowPythonStepsTest(unittest.TestCase):
    def test_the_scan_finds_the_directories_it_is_meant_to_find(self) -> None:
        # A control: an empty scan would make every other test here pass.
        self.assertLessEqual({"harness", "checks", "tools"}, python_directories())

    def test_each_python_directory_has_a_unittest_step(self) -> None:
        run = {match.group("name") for match in UNITTEST_STEP.finditer(WORKFLOW)}
        self.assertEqual(set(), python_directories() - run)

    def test_each_python_directory_is_type_checked_linted_and_format_checked(self) -> None:
        for command in (
            'ansible-venv/bin/mypy" ',
            'ansible-venv/bin/ruff" check ',
            'ansible-venv/bin/ruff" format --check ',
        ):
            lines = step_lines(command)
            self.assertEqual(1, len(lines), f"{command!r}: {lines}")
            named = set(lines[0].split(command, 1)[1].rstrip("'").split())
            with self.subTest(command=command):
                self.assertEqual(set(), python_directories() - named)

    def test_the_role_scan_finds_the_roles_it_is_meant_to_find(self) -> None:
        # A control: an empty scan would make the next test pass.
        self.assertLessEqual({"ansible_runtime", "pull_trigger"}, roles_shipping_a_program(ROOTS))

    def test_the_role_program_step_selects_every_role_that_ships_a_program(self) -> None:
        self.assertEqual(set(), unselected_roles(ROOTS, selector_pattern()))

    def test_a_role_that_ships_a_program_and_is_not_selected_is_found(self) -> None:
        # The controls of the test above: each way a role can be skipped, and one that is not.
        pattern = selector_pattern()
        with tempfile.TemporaryDirectory() as directory:
            roles = Path(directory)
            make_role(roles, "selected", pyproject=GOOD_PYPROJECT, tests=True)
            make_role(roles, "no_pyproject_line", pyproject="[project]\n", tests=True)
            make_role(roles, "no_pyproject", pyproject=None, tests=True)
            make_role(roles, "no_tests", pyproject=GOOD_PYPROJECT, tests=False)
            make_role(roles, "has_library", pyproject=GOOD_PYPROJECT, tests=True, library=True)
            make_role(roles, "no_program", pyproject=None, tests=False, program=False)
            self.assertEqual(
                {"no_pyproject_line", "no_pyproject", "no_tests", "has_library"},
                unselected_roles(roles, pattern),
            )

    def test_the_role_program_step_does_not_select_a_role_with_no_program(self) -> None:
        selector = SELECTOR.search(WORKFLOW)
        if selector is None:
            self.fail("the role program step has no pyproject.toml selector")
        pattern = re.compile(selector.group("pattern"), re.MULTILINE)
        text = (ANSIBLE / "roles" / "egress_nat" / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIsNone(pattern.search(text))

    def test_the_install_scan_finds_the_commands_it_is_meant_to_find(self) -> None:
        # A control: a scan that matched nothing would make the next two tests pass.
        self.assertEqual(2, len(lock_installs(WORKFLOW)))
        self.assertLessEqual(3, len(lock_installs(README.read_text("utf-8"))))

    def test_every_workflow_install_of_the_lock_is_wheels_only(self) -> None:
        self.assertEqual([], sdist_reachable_lines(WORKFLOW))

    def test_every_readme_install_of_the_lock_is_wheels_only(self) -> None:
        self.assertEqual([], sdist_reachable_lines(README.read_text(encoding="utf-8")))

    def test_every_other_readme_points_at_the_one_install_recipe(self) -> None:
        # Every README under ansible/ is scanned, with or without the hash flag, so a copy of
        # the install cannot sit outside the recipe and skip the wheels-only check above.
        # The control: the scan reaches a role README, not only ansible/README.md.
        scanned = readmes_outside_the_recipe()
        names = {path.relative_to(ANSIBLE).as_posix() for path in scanned}
        self.assertIn("roles/ansible_runtime/README.md", names)
        self.assertTrue(any(name.startswith("patterns/") for name in names), names)
        self.assertIn("role_skeleton/README.md.j2", names)
        for path in scanned:
            with self.subTest(readme=str(path.relative_to(ROOT))):
                self.assertEqual([], lock_installs(path.read_text(encoding="utf-8")))

    def test_a_readme_install_of_the_lock_outside_the_recipe_is_found(self) -> None:
        # The control of the test above: a bare install is found, and a comment that names the
        # recipe is not, so the pointer each copy now carries passes.
        bare = ".venv/bin/pip install -r ansible/requirements.txt"
        pointer = "# Install the lock with the one recipe: ansible/README.md"
        self.assertEqual([bare], lock_installs("\n".join([bare, pointer])))

    def test_an_install_that_can_build_from_source_is_found(self) -> None:
        # The controls of the tests above: each form the repository writes, with and without the
        # flag, a command split over two lines, and prose that names the flag without running pip.
        bare = ".venv/bin/pip install --require-virtualenv --require-hashes -r requirements.txt"
        download = ".venv/bin/pip download --require-hashes -r requirements.txt -d WHEELHOUSE"
        quoted = (
            'run: \'"$RUNNER_TEMP/ansible-venv/bin/pip" install --require-hashes '
            "-r requirements.txt'"
        )
        pip3 = "pip3 install --require-hashes -r requirements.txt"
        uv_sync = "uv pip sync --require-hashes requirements.txt"
        python_m = "python3 -m pip install --require-hashes -r requirements.txt"
        long_flag = "pip install --require-hashes --requirement requirements.txt"
        split = "pip install --require-hashes \\\n    -r requirements.txt"
        guarded = f"{bare} {WHEELS_ONLY}"
        prose = "# --require-hashes makes pip refuse any package without a recorded hash"
        text = "\n".join(
            [
                "  " + bare,
                download,
                quoted,
                pip3,
                uv_sync,
                python_m,
                long_flag,
                split,
                guarded,
                prose,
            ]
        )
        self.assertEqual(9, len(lock_installs(text)))
        self.assertNotIn(prose, lock_installs(text))
        self.assertEqual(8, len(sdist_reachable_lines(text)))


if __name__ == "__main__":
    unittest.main()
