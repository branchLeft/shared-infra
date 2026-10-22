"""Fails while restart_stamp runs with a default other than the one its spec declares.

ANS-12 leaves the equality to review because Ansible does not apply the default of an
argument_specs entry. For this role the second copy is the inline ``| default(...)`` of each
optional option of a class in tasks/decide.yml, and this check holds the two together. See
restart_stamp/README.md, "Composition (ANS-12)".
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import role_defaults
from role_defaults import declared_defaults, literal, running_default_problems

ROOT = Path(__file__).resolve().parents[2]
RESTART_STAMP = ROOT / "ansible" / "roles" / "restart_stamp"

HEAD = "---\nargument_specs:\n  decide:\n    short_description: Decide\n    options:\n"
CLASSES = (
    "      cap_classes:\n        type: list\n        elements: dict\n        required: true\n"
    "        options:\n          name:\n            type: str\n            required: true\n"
)
FLAG = "          flag:\n            type: bool\n            default: {value}\n"
TASK = "---\n- name: Work out\n  ansible.builtin.set_fact:\n    out: '{{ c.flag | default(%s) }}'\n"


def problems_of(specs: str, tasks: str | None) -> list[str]:
    """The problems of a throwaway role with these argument_specs and this decide.yml."""
    with tempfile.TemporaryDirectory() as tmp:
        role = Path(tmp) / "cap"
        (role / "meta").mkdir(parents=True)
        (role / "tasks").mkdir()
        (role / "meta" / "argument_specs.yml").write_text(specs, encoding="utf-8")
        if tasks is not None:
            (role / "tasks" / "decide.yml").write_text(tasks, encoding="utf-8")
        return running_default_problems(role)


def differ(declared: object, running: str) -> list[str]:
    return [
        "cap cap_classes[].flag (decide): meta/argument_specs.yml declares default "
        f"{declared!r} but tasks/decide.yml runs with default({running})"
    ]


class RealTreeTest(unittest.TestCase):
    def test_restart_stamp_runs_with_the_defaults_its_spec_declares(self) -> None:
        self.assertEqual([], running_default_problems(RESTART_STAMP))

    def test_the_check_sees_the_three_flags_of_a_class(self) -> None:
        # The control of the test above: a clean result means something only if the options
        # that have a default are the ones the role runs with an inline default for.
        self.assertEqual(
            [
                ("decide", "restart_stamp_classes[].drift", False),
                ("decide", "restart_stamp_classes[].adoptable", False),
                ("decide", "restart_stamp_classes[].gate", True),
            ],
            declared_defaults(RESTART_STAMP),
        )
        text = (RESTART_STAMP / "tasks" / "decide.yml").read_text(encoding="utf-8")
        for name in ("drift", "adoptable", "gate"):
            with self.subTest(name=name):
                self.assertIn(f"c.{name} | default(", text)


class EqualityTest(unittest.TestCase):
    def test_a_running_default_equal_to_the_declared_one_is_not_reported(self) -> None:
        # One case for each type of literal; each differs from the next by one thing.
        cases = (
            ("false", "false"),
            ("true", "true"),
            ("True", "true"),
            ("none", "null"),
            ("0", "0"),
            ("30", "30"),
            ("'x'", "x"),
            ('"x"', "x"),
        )
        for running, declared in cases:
            with self.subTest(running=running):
                specs = HEAD + CLASSES + FLAG.format(value=declared)
                self.assertEqual([], problems_of(specs, TASK % running))

    def test_a_running_default_that_differs_from_the_declared_one_is_reported(self) -> None:
        # The task copy changed. Each case differs in the value, not only the type, so a
        # check that compared one kind of value could not pass them all.
        cases = (
            ("false", "true", True),
            ("true", "false", False),
            ("0", "30", 30),
            ("'x'", "y", "y"),
            ("none", "false", False),
        )
        for running, declared, value in cases:
            with self.subTest(running=running, declared=declared):
                specs = HEAD + CLASSES + FLAG.format(value=declared)
                self.assertEqual(differ(value, running), problems_of(specs, TASK % running))

    def test_the_spec_copy_changed_is_reported_the_same_way(self) -> None:
        # The far copy (review-round rule 4): the task is as it was, the spec moved.
        specs = HEAD + CLASSES + FLAG.format(value="true")
        self.assertEqual(differ(True, "false"), problems_of(specs, TASK % "false"))

    def test_a_value_of_another_type_is_not_the_same_value(self) -> None:
        # 0 is falsy and 1 is truthy, and neither is the boolean the spec declares.
        for running, declared, value in (("0", "false", False), ("1", "true", True)):
            with self.subTest(running=running):
                specs = HEAD + CLASSES + FLAG.format(value=declared)
                self.assertEqual(differ(value, running), problems_of(specs, TASK % running))

    def test_one_copy_in_two_is_enough_to_report(self) -> None:
        tasks = TASK % "false" + "    again: '{{ c.flag | default(true) }}'\n"
        specs = HEAD + CLASSES + FLAG.format(value="false")
        self.assertEqual(differ(False, "true"), problems_of(specs, tasks))

    def test_a_literal_the_reading_cannot_place_is_reported(self) -> None:
        for running in ("other_var", "x ~ y", "false, true", "'a' ~ 'b'"):
            tasks = "---\n- name: Work out\n  ansible.builtin.set_fact:\n    out: " + (
                "'{{ c.flag | default(" + running + ") }}'\n"
            )
            with self.subTest(running=running):
                specs = HEAD + CLASSES + FLAG.format(value="false")
                self.assertEqual(differ(False, running), problems_of(specs, tasks))

    def test_an_option_with_no_running_copy_is_reported(self) -> None:
        # A declared default that no task shows is a value the check could not hold to
        # anything: the option is named, so the next reader sees what to add.
        specs = HEAD + CLASSES + FLAG.format(value="false")
        for label, tasks in (
            ("no tasks file", None),
            ("another option's default", TASK.replace("c.flag", "c.other") % "false"),
            (
                "no default",
                "---\n- name: Work out\n  ansible.builtin.set_fact:\n    out: '{{ c.flag }}'\n",
            ),
        ):
            with self.subTest(label=label):
                self.assertEqual(
                    [
                        "cap cap_classes[].flag (decide): no `.flag | default(...)` in "
                        "tasks/decide.yml, so the value it runs with is not shown"
                    ],
                    problems_of(specs, tasks),
                )

    def test_a_default_outside_a_list_element_is_reported_not_passed(self) -> None:
        # The check reads only where the default of a list element runs. A top-level option
        # with a default is a case it does not read, so it says so rather than pass it.
        specs = HEAD + "      cap_top:\n        type: str\n        default: x\n"
        self.assertEqual(
            [
                "cap cap_top (decide): declares a default but is not an option of a list "
                "element, and this check reads only the tasks of the entry point, where those run"
            ],
            problems_of(specs, "---\n- name: Nothing\n  ansible.builtin.debug:\n    msg: x\n"),
        )

    def test_a_dictionary_option_in_a_list_element_is_read(self) -> None:
        # The dictionary is required, so the only default is that of its option `level`.
        specs = (
            HEAD
            + CLASSES
            + "          extra:\n            type: dict\n            required: true\n"
            + "            options:\n              level:\n                type: int\n"
            + "                default: 2\n"
        )
        head = "---\n- name: Work out\n  ansible.builtin.set_fact:\n"
        self.assertEqual(
            [], problems_of(specs, head + "    out: '{{ c.extra.level | default(2) }}'\n")
        )
        self.assertEqual(
            [
                "cap cap_classes[].extra.level (decide): meta/argument_specs.yml declares "
                "default 2 but tasks/decide.yml runs with default(3)"
            ],
            problems_of(specs, head + "    out: '{{ c.extra.level | default(3) }}'\n"),
        )


class LiteralTest(unittest.TestCase):
    def test_the_literals_of_a_jinja_default_are_read(self) -> None:
        self.assertIs(False, literal("false"))
        self.assertIs(True, literal(" True "))
        self.assertIsNone(literal("None"))
        self.assertEqual(-3, literal("-3"))
        self.assertEqual("a b", literal("'a b'"))
        self.assertEqual("", literal('""'))

    def test_anything_else_is_unreadable(self) -> None:
        for text in ("x", "1.5", "[]", "'a' ~ 'b'", "'unterminated"):
            with self.subTest(text=text):
                self.assertIs(role_defaults.UNREADABLE, literal(text))


if __name__ == "__main__":
    unittest.main()
