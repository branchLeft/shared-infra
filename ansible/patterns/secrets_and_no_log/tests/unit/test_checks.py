"""Unit tests for the checks that run before any secret is written.

problems.j2 is rendered with the variables the role passes it, and the source
file assertion in tasks/main.yml is evaluated against a stat result. The two
Ansible filters and the one test the checks use are supplied as ansible-core
defines them. Run with: python3 -m unittest discover -b -s tests/unit -p "test_*.py"
from the pattern directory.
"""

import json
import re
import unittest
from pathlib import Path
from typing import cast

import jinja2
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
TEMPLATE = (ROLE / "templates" / "problems.j2").read_text(encoding="utf-8")


def load_yaml(path: Path) -> object:
    # ruamel.yaml is typed; PyYAML ships no stubs, so mypy cannot check what it returns.
    loaded: object = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    return loaded


VARS = cast("dict[str, object]", load_yaml(ROLE / "vars" / "main.yml"))
TASKS = cast("list[dict[str, object]]", load_yaml(ROLE / "tasks" / "main.yml"))

# Values made for the test run: none is a real secret.
THROWAWAY_VALUE = "THROWAWAY_VALUE_0001"  # noqa: S105


def make_env() -> jinja2.Environment:
    # The checks render text, not HTML, so autoescape would change the values compared.
    env = jinja2.Environment(autoescape=False)  # noqa: S701
    env.filters["to_json"] = lambda value: json.dumps(value, sort_keys=True)
    env.filters["from_json"] = json.loads
    env.tests["match"] = lambda value, pattern: re.match(pattern, value) is not None
    return env


ENV = make_env()


def render_problems(secrets: list[dict[str, str]], env_name: str) -> dict[str, list[int]]:
    context = dict(VARS)
    context["secrets_and_no_log_secrets"] = secrets
    context["secrets_and_no_log_env_name"] = env_name
    return cast("dict[str, list[int]]", json.loads(ENV.from_string(TEMPLATE).render(context)))


def assertions_of(task: dict[str, object]) -> list[str]:
    block = cast("dict[str, object]", task["ansible.builtin.assert"])
    return cast("list[str]", block["that"])


def source_assertion() -> list[str]:
    for task in TASKS:
        if str(task.get("name", "")).startswith("Refuse a source file that is missing"):
            return assertions_of(task)
    raise AssertionError("no task refuses a source file that is missing or not plain")  # noqa: TRY003


def source_passes(stat: dict[str, object]) -> bool:
    item = {"item": "/root/EXAMPLE_SOURCE", "stat": stat}
    return all(bool(ENV.compile_expression(expr)(item=item)) for expr in source_assertion())


PLAIN_ROOT_FILE: dict[str, object] = {
    "exists": True,
    "isreg": True,
    "uid": 0,
    "mode": "0600",
    "size": 12,
}


class EnvironmentFileNameTest(unittest.TestCase):
    def test_a_name_equal_to_a_secret_name_is_listed_by_entry_number(self) -> None:
        secrets = [{"name": "EXAMPLE_ENV", "value": THROWAWAY_VALUE}]
        self.assertEqual(render_problems(secrets, "EXAMPLE_ENV")["env_name"], [1])

    def test_the_second_entry_is_the_one_listed(self) -> None:
        secrets = [
            {"name": "EXAMPLE_A", "value": THROWAWAY_VALUE},
            {"name": "EXAMPLE_B", "value": THROWAWAY_VALUE},
        ]
        self.assertEqual(render_problems(secrets, "EXAMPLE_B")["env_name"], [2])

    def test_a_name_no_secret_uses_is_not_listed(self) -> None:
        secrets = [{"name": "EXAMPLE_A", "value": THROWAWAY_VALUE}]
        self.assertEqual(render_problems(secrets, "service.env")["env_name"], [])

    def test_no_environment_file_lists_nothing(self) -> None:
        secrets = [{"name": "EXAMPLE_A", "value": THROWAWAY_VALUE}]
        self.assertEqual(render_problems(secrets, "")["env_name"], [])

    def test_the_check_reports_no_name_or_value(self) -> None:
        secrets = [{"name": "EXAMPLE_ENV", "value": THROWAWAY_VALUE}]
        self.assertNotIn(THROWAWAY_VALUE, json.dumps(render_problems(secrets, "EXAMPLE_ENV")))


def refusal_passes(exprs: list[str], problems: dict[str, list[int]]) -> bool:
    return all(bool(ENV.compile_expression(e)(secrets_and_no_log_problems=problems)) for e in exprs)


def task_assertion(name_prefix: str) -> list[str]:
    for task in TASKS:
        if str(task.get("name", "")).startswith(name_prefix):
            return assertions_of(task)
    raise AssertionError(f"no task named {name_prefix!r}")  # noqa: TRY003


class EnvironmentFileNameWiringTest(unittest.TestCase):
    def test_the_refusal_fails_when_a_secret_has_the_environment_file_name(self) -> None:
        exprs = task_assertion("Refuse an environment file that has the name of a secret")
        problems = {"env_name": [1]}
        self.assertFalse(refusal_passes(exprs, problems))

    def test_the_refusal_passes_when_no_secret_has_the_environment_file_name(self) -> None:
        exprs = task_assertion("Refuse an environment file that has the name of a secret")
        problems: dict[str, list[int]] = {"env_name": []}
        self.assertTrue(refusal_passes(exprs, problems))


class SourceFileTest(unittest.TestCase):
    def test_a_plain_root_only_file_with_content_passes(self) -> None:
        self.assertTrue(source_passes(PLAIN_ROOT_FILE))

    def test_an_empty_root_only_file_is_refused(self) -> None:
        self.assertFalse(source_passes({**PLAIN_ROOT_FILE, "size": 0}))

    def test_a_group_readable_file_is_refused(self) -> None:
        self.assertFalse(source_passes({**PLAIN_ROOT_FILE, "mode": "0640"}))

    def test_a_file_not_owned_by_root_is_refused(self) -> None:
        self.assertFalse(source_passes({**PLAIN_ROOT_FILE, "uid": 1000}))

    def test_a_missing_file_is_refused(self) -> None:
        self.assertFalse(source_passes({"exists": False}))


if __name__ == "__main__":
    unittest.main()
