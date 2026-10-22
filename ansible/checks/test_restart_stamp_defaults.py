"""Fails while restart_stamp runs with a default other than the one its spec declares.

The two copies are held together here for this role. See restart_stamp/README.md,
"Composition (ANS-12)".
"""

from __future__ import annotations

import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

import role_defaults
from jinja2 import nodes
from role_defaults import declared_defaults, literal, running_default_problems

ROOT = Path(__file__).resolve().parents[2]
RESTART_STAMP = ROOT / "ansible" / "roles" / "restart_stamp"

HEAD = "---\nargument_specs:\n  decide:\n    short_description: Decide\n    options:\n"
CLASSES = (
    "      cap_classes:\n        type: list\n        elements: dict\n        required: true\n"
    "        options:\n          name:\n            type: str\n            required: true\n"
)
FLAG = "          flag:\n            type: bool\n            default: {value}\n"
SET_FACT = "---\n- name: Work out\n  ansible.builtin.set_fact:\n"
INCLUDE = "---\n- name: Include\n  ansible.builtin.include_tasks:\n    file: {file}\n"
SPEC_FALSE = HEAD + CLASSES + FLAG.format(value="false")
OTHER_ENTRY = "  other:\n    short_description: Other\n    options:\n"


def task(body: str) -> str:
    """A task file whose one fact is this template body, inside a loop over the classes."""
    return SET_FACT + "    out: >-\n      {% for c in cap_classes %}" + body + "{% endfor %}\n"


def flag_default(running: str, element: str = "c.flag") -> str:
    return task("{{ " + element + " | default(" + running + ") }}")


def problems_of(specs: str, tasks: str | None, more: Mapping[str, str] | None = None) -> list[str]:
    """The problems of a throwaway role with these argument_specs, decide.yml and other files."""
    with tempfile.TemporaryDirectory() as tmp:
        role = Path(tmp) / "cap"
        (role / "meta").mkdir(parents=True)
        (role / "meta" / "argument_specs.yml").write_text(specs, encoding="utf-8")
        files = {**({"tasks/decide.yml": tasks} if tasks is not None else {}), **(more or {})}
        for name, text in files.items():
            (role / name).parent.mkdir(parents=True, exist_ok=True)
            (role / name).write_text(text, encoding="utf-8")
        return running_default_problems(role)


def differ(declared: object, running: str, name: str = "tasks/decide.yml") -> list[str]:
    return [
        "cap cap_classes[].flag (decide): meta/argument_specs.yml declares default "
        f"{declared!r} but {name} runs with {running}"
    ]


def no_copy() -> list[str]:
    return [
        "cap cap_classes[].flag (decide): no `<element>.flag | default(...)` in "
        "tasks/decide.yml or a file it includes, so the value it runs with is not shown"
    ]


def not_an_element(name: str = "tasks/decide.yml") -> str:
    return (
        f"cap cap_classes[].flag (decide): {name} gives `.flag` a default on something "
        "other than an element of cap_classes"
    )


def not_reached(name: str) -> list[str]:
    return [
        f"cap cap_classes[].flag (decide): {name} gives `.flag` a default, and "
        "tasks/decide.yml does not reach that file"
    ]


def expression(text: str) -> nodes.Node:
    """The Jinja node of an expression, as the check reads it.

    Raises:
        TypeError: when the text does not parse as one output.
    """
    output = role_defaults.JINJA.parse("{{ " + text + " }}").body[0]
    if not isinstance(output, nodes.Output):
        raise TypeError(text)
    return output.nodes[0]


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
            ("-3", "-3"),
            ("'x'", "x"),
            ('"x"', "x"),
        )
        for running, declared in cases:
            with self.subTest(running=running):
                specs = HEAD + CLASSES + FLAG.format(value=declared)
                self.assertEqual([], problems_of(specs, flag_default(running)))

    def test_a_running_default_that_differs_from_the_declared_one_is_reported(self) -> None:
        # The task copy changed. Each case differs in the value, not only the type, so a
        # check that compared one kind of value could not pass them all.
        cases = (
            ("false", "true", True, "default(false)"),
            ("true", "false", False, "default(true)"),
            ("0", "30", 30, "default(0)"),
            ("'x'", "y", "y", "default('x')"),
            ("none", "false", False, "default(none)"),
        )
        for running, declared, value, shown in cases:
            with self.subTest(running=running, declared=declared):
                specs = HEAD + CLASSES + FLAG.format(value=declared)
                self.assertEqual(differ(value, shown), problems_of(specs, flag_default(running)))

    def test_the_spec_copy_changed_is_reported_the_same_way(self) -> None:
        # The far copy (review-round rule 4): the task is as it was, the spec moved.
        specs = HEAD + CLASSES + FLAG.format(value="true")
        self.assertEqual(differ(True, "default(false)"), problems_of(specs, flag_default("false")))

    def test_a_value_of_another_type_is_not_the_same_value(self) -> None:
        # 0 is falsy and 1 is truthy, and neither is the boolean the spec declares.
        for running, declared, value in (("0", "false", False), ("1", "true", True)):
            with self.subTest(running=running):
                specs = HEAD + CLASSES + FLAG.format(value=declared)
                self.assertEqual(
                    differ(value, f"default({running})"), problems_of(specs, flag_default(running))
                )

    def test_one_copy_in_two_is_enough_to_report(self) -> None:
        tasks = task("{{ c.flag | default(false) }}{{ c.flag | default(true) }}")
        self.assertEqual(differ(False, "default(true)"), problems_of(SPEC_FALSE, tasks))

    def test_a_literal_the_reading_cannot_place_is_reported(self) -> None:
        unreadable = "a default this check cannot read"
        for running in ("other_var", "x ~ y", "false, true", "'a' ~ 'b'", "1.5", "[]", ""):
            with self.subTest(running=running):
                self.assertEqual(
                    differ(False, unreadable), problems_of(SPEC_FALSE, flag_default(running))
                )

    def test_a_default_given_with_a_keyword_is_not_read_as_a_literal(self) -> None:
        tasks = task("{{ c.flag | default(false, boolean=true) }}")
        self.assertEqual(
            differ(False, "a default this check cannot read"), problems_of(SPEC_FALSE, tasks)
        )

    def test_the_short_name_of_the_filter_is_read_too(self) -> None:
        self.assertEqual(
            differ(False, "default(true)"), problems_of(SPEC_FALSE, task("{{ c.flag | d(true) }}"))
        )

    def test_an_option_with_no_running_copy_is_reported(self) -> None:
        # A declared default that no task shows is a value the check could not hold to
        # anything: the option is named, so the next reader sees what to add.
        for label, tasks in (
            ("no tasks file", None),
            ("another option's default", flag_default("false", "c.other")),
            ("no default", task("{{ c.flag }}")),
        ):
            with self.subTest(label=label):
                self.assertEqual(no_copy(), problems_of(SPEC_FALSE, tasks))

    def test_a_default_outside_a_list_element_is_reported_not_passed(self) -> None:
        # The check reads only where the default of a list element runs. A top-level option
        # with a default is a case it does not read, so it says so rather than pass it.
        specs = HEAD + "      cap_top:\n        type: str\n        default: x\n"
        self.assertEqual(
            [
                "cap cap_top (decide): declares a default but is not an option of a list "
                "element, and this check reads only the tasks of the entry point, where those run"
            ],
            problems_of(specs, SET_FACT + "    out: x\n"),
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
        self.assertEqual([], problems_of(specs, flag_default("2", "c.extra.level")))
        self.assertEqual(
            [
                "cap cap_classes[].extra.level (decide): meta/argument_specs.yml declares "
                "default 2 but tasks/decide.yml runs with default(3)"
            ],
            problems_of(specs, flag_default("3", "c.extra.level")),
        )


class DecoyTest(unittest.TestCase):
    """A copy that is written down but does not run is not the copy that runs."""

    def test_a_jinja_comment_is_not_a_copy(self) -> None:
        # The running default is flipped; the comment keeps the old, declared spelling, as
        # words and as a braced expression.
        for comment in (
            "{#- the old form was c.flag | default(false) -#}",
            "{#- {{ c.flag | default(false) }} -#}",
        ):
            with self.subTest(comment=comment):
                flipped = task("{{ c.flag | default(true) }}" + comment)
                self.assertEqual(differ(False, "default(true)"), problems_of(SPEC_FALSE, flipped))
                # The controls: the same comment beside a right copy changes nothing, and a
                # comment alone is not a copy.
                right = task("{{ c.flag | default(false) }}" + comment.replace("false", "true"))
                self.assertEqual([], problems_of(SPEC_FALSE, right))
                self.assertEqual(no_copy(), problems_of(SPEC_FALSE, task(comment)))

    def test_a_yaml_comment_is_not_a_copy(self) -> None:
        note = "# {{ c.flag | default(false) }}\n"
        self.assertEqual(
            differ(False, "default(true)"), problems_of(SPEC_FALSE, flag_default("true") + note)
        )
        self.assertEqual(no_copy(), problems_of(SPEC_FALSE, task("") + note))

    def test_a_string_that_reads_like_a_copy_is_not_a_copy(self) -> None:
        decoy = "{{ 'c.flag | default(false)' }}"
        self.assertEqual(
            differ(False, "default(true)"),
            problems_of(SPEC_FALSE, task("{{ c.flag | default(true) }}" + decoy)),
        )
        self.assertEqual(no_copy(), problems_of(SPEC_FALSE, task(decoy)))

    def test_a_copy_on_something_other_than_an_element_is_reported(self) -> None:
        # Beside a right copy: another object, and another loop, give the option a default.
        for label, body in (
            ("another object", "{{ other.flag | default(true) }}"),
            ("another loop", "{% for o in others %}{{ o.flag | default(true) }}{% endfor %}"),
        ):
            with self.subTest(label=label):
                tasks = task("{{ c.flag | default(false) }}" + body)
                self.assertEqual([not_an_element()], problems_of(SPEC_FALSE, tasks))

    def test_the_subscript_spelling_is_read_as_the_attribute(self) -> None:
        self.assertEqual([], problems_of(SPEC_FALSE, flag_default("false", "c['flag']")))
        self.assertEqual(
            differ(False, "default(true)"),
            problems_of(SPEC_FALSE, flag_default("true", 'c["flag"]')),
        )

    def test_a_bare_expression_is_read(self) -> None:
        # `when` and `that` take an expression with no braces round it.
        for key in ("when", "failed_when"):
            with self.subTest(key=key):
                tasks = (
                    flag_default("false")
                    + "- name: Check\n  ansible.builtin.debug:\n    msg: x\n"
                    + f"  {key}: item.flag | default(true)\n"
                )
                self.assertEqual([not_an_element()], problems_of(SPEC_FALSE, tasks))

    def test_a_template_that_cannot_be_parsed_is_reported(self) -> None:
        found = problems_of(
            SPEC_FALSE, task("{{ c.flag | default(false) }}{{ c.flag | default( }}")
        )
        self.assertTrue(
            found[0].startswith("cap tasks/decide.yml: a template cannot be parsed: "), found
        )


class ReachTest(unittest.TestCase):
    """The file an entry point includes is read; a file it does not reach is not skipped."""

    def test_a_copy_in_an_included_file_is_read(self) -> None:
        for file in ("_check.yml", "sub/_check.yml"):
            with self.subTest(file=file):
                more = {f"tasks/{file}": flag_default("true")}
                self.assertEqual(
                    differ(False, "default(true)", f"tasks/{file}"),
                    problems_of(SPEC_FALSE, INCLUDE.format(file=file), more),
                )

    def test_the_only_copy_may_be_in_an_included_file(self) -> None:
        more = {"tasks/_check.yml": flag_default("false")}
        self.assertEqual([], problems_of(SPEC_FALSE, INCLUDE.format(file="_check.yml"), more))

    def test_a_copy_in_a_file_no_entry_point_reaches_is_reported(self) -> None:
        for name in ("tasks/other.yml", "handlers/h.yml", "vars/main.yml", "defaults/main.yml"):
            with self.subTest(name=name):
                self.assertEqual(
                    not_reached(name),
                    problems_of(SPEC_FALSE, flag_default("false"), {name: flag_default("true")}),
                )

    def test_a_file_another_entry_point_holds_to_its_own_default_is_not_reported(self) -> None:
        # The control of the one above: when the other entry point declares the same option, its
        # file is read under that declaration, so it is not a stray copy of this one's.
        specs = SPEC_FALSE + OTHER_ENTRY + CLASSES + FLAG.format(value="false")
        right = {"tasks/other.yml": flag_default("false")}
        self.assertEqual([], problems_of(specs, flag_default("false"), right))
        # And it is held to it: a flipped copy there is reported against the entry that owns it.
        flipped = {"tasks/other.yml": flag_default("true")}
        self.assertEqual(
            [
                "cap cap_classes[].flag (other): meta/argument_specs.yml declares default "
                "False but tasks/other.yml runs with default(true)"
            ],
            problems_of(specs, flag_default("false"), flipped),
        )

    def test_a_file_that_includes_itself_ends(self) -> None:
        tasks = INCLUDE.format(file="decide.yml") + flag_default("false").removeprefix("---\n")
        self.assertEqual([], problems_of(SPEC_FALSE, tasks))


class LiteralTest(unittest.TestCase):
    def test_the_literals_of_a_jinja_default_are_read(self) -> None:
        self.assertIs(False, literal(expression("false")))
        self.assertIs(True, literal(expression(" True ")))
        self.assertIsNone(literal(expression("None")))
        self.assertEqual(-3, literal(expression("-3")))
        self.assertEqual("a b", literal(expression("'a b'")))
        self.assertEqual("", literal(expression('""')))

    def test_anything_else_is_unreadable(self) -> None:
        for text in ("x", "1.5", "[]", "'a' ~ 'b'", "-true", "-1.5"):
            with self.subTest(text=text):
                self.assertIs(role_defaults.UNREADABLE, literal(expression(text)))


if __name__ == "__main__":
    unittest.main()
