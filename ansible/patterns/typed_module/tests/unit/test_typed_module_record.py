"""Unit tests for typed_module_record: its logic, its argument_spec and check mode.

The pattern README gives the command, with the library directory on PYTHONPATH.
"""

import dataclasses
import stat
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Literal, cast
from unittest import mock

import typed_module_record as record
from ruamel.yaml import YAML

# Values made for the test run: none is a real secret.
THROWAWAY_TOKEN = "THROWAWAY_TOKEN_VALUE_0001"  # noqa: S105
OTHER_THROWAWAY_TOKEN = "OTHER_THROWAWAY_VALUE_0002"  # noqa: S105

SAMPLE: Mapping[str, object] = {
    "path": "/etc/EXAMPLE_SERVICE.record",
    "name": "EXAMPLE_NAME",
    "count": 3,
    "state": "absent",
    "mode": "0640",
    "token": THROWAWAY_TOKEN,
}


def load_yaml(text: str) -> Mapping[str, Mapping[str, object]]:
    """Parse one of the module's documentation blocks."""
    return cast("Mapping[str, Mapping[str, object]]", YAML(typ="safe").load(text))


def make_params(directory: Path, **changes: object) -> record.Params:
    """Return parameters for a file in ``directory``, with ``changes`` applied."""
    values = {**SAMPLE, "path": str(directory / "record"), "state": "present", **changes}
    return record.params_from_mapping(values)


class ArgumentSpecTests(unittest.TestCase):
    """The argument_spec is generated from the types and agrees with the documentation."""

    def test_documentation_options_match_the_generated_argument_spec(self) -> None:
        documented = load_yaml(record.DOCUMENTATION)["options"]
        self.assertEqual(set(documented), set(record.ARGUMENT_SPEC))
        for name, option in record.ARGUMENT_SPEC.items():
            with self.subTest(option=name):
                doc = cast("Mapping[str, object]", documented[name])
                self.assertEqual(doc["type"], option["type"], f"{name}: type")
                self.assertEqual(doc.get("required", False), option.get("required", False))
                self.assertEqual(doc.get("default"), option.get("default"), f"{name}: default")
                self.assertEqual(doc.get("choices"), option.get("choices"), f"{name}: choices")

    def test_the_spec_follows_the_types_of_the_dataclass(self) -> None:
        self.assertEqual(
            record.ARGUMENT_SPEC,
            {
                "path": {"type": "path", "required": True},
                "name": {"type": "str", "required": True},
                "count": {"type": "int", "default": 1},
                "state": {"type": "str", "choices": ["present", "absent"], "default": "present"},
                "mode": {"type": "str", "default": "0600"},
                "token": {"type": "str", "no_log": True},
            },
        )

    def test_every_secret_named_option_is_no_log(self) -> None:
        for name, option in record.ARGUMENT_SPEC.items():
            if any(word in name for word in ("token", "password", "secret", "key")):
                with self.subTest(option=name):
                    self.assertIs(option.get("no_log"), True, f"{name} is a secret without no_log")

    def test_the_documentation_blocks_are_valid_yaml(self) -> None:
        self.assertIn("typed_module_record", load_yaml(record.DOCUMENTATION)["module"] or "")
        self.assertIsInstance(YAML(typ="safe").load(record.EXAMPLES), list)
        self.assertIn("changed", load_yaml(record.RETURN))

    def test_a_type_with_no_ansible_form_is_refused(self) -> None:
        @dataclasses.dataclass
        class Unsupported:
            values: dict[str, int]

        with self.assertRaises(TypeError):
            record.build_argument_spec(Unsupported)

    def test_choices_must_be_strings(self) -> None:
        @dataclasses.dataclass
        class Numbered:
            level: Literal[1, 2]

        with self.assertRaises(TypeError):
            record.build_argument_spec(Numbered)

    def test_an_optional_field_must_default_to_none(self) -> None:
        @dataclasses.dataclass
        class Required:
            note: str | None

        with self.assertRaises(TypeError):
            record.build_argument_spec(Required)

    def test_a_default_factory_is_refused(self) -> None:
        @dataclasses.dataclass
        class Factory:
            names: list[str] = dataclasses.field(default_factory=list)

        with self.assertRaises(TypeError):
            record.build_argument_spec(Factory)

    def test_a_list_field_states_its_elements(self) -> None:
        @dataclasses.dataclass
        class Listed:
            names: list[str]

        self.assertEqual(
            record.build_argument_spec(Listed),
            {"names": {"type": "list", "elements": "str", "required": True}},
        )

    def test_every_option_reaches_the_typed_parameters(self) -> None:
        self.assertEqual(set(SAMPLE), set(record.ARGUMENT_SPEC), "the sample is missing an option")
        params = record.params_from_mapping(SAMPLE)
        built = {**dataclasses.asdict(params), "path": str(params.path)}
        self.assertEqual(built, dict(SAMPLE))

    def test_omitted_token_becomes_none(self) -> None:
        values = {key: value for key, value in SAMPLE.items() if key != "token"}
        self.assertIsNone(record.params_from_mapping(values).token)

    def test_a_wrongly_typed_value_is_refused(self) -> None:
        for key, bad in (("count", "3"), ("count", True), ("name", 1), ("token", 5)):
            with self.subTest(key=key, bad=bad), self.assertRaises(TypeError):
                record.params_from_mapping({**SAMPLE, key: bad})

    def test_an_unknown_state_is_refused(self) -> None:
        with self.assertRaisesRegex(record.ValidationError, "state must be present or absent"):
            record.params_from_mapping({**SAMPLE, "state": "bogus"})

    def test_the_secret_is_not_in_the_repr(self) -> None:
        self.assertNotIn(THROWAWAY_TOKEN, repr(record.params_from_mapping(SAMPLE)))


class ValidationTests(unittest.TestCase):
    """A value with the right type and an unacceptable content is refused by name."""

    def refused(self, message: str, **changes: object) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(record.ValidationError, message),
        ):
            record.validate(make_params(Path(directory), **changes))

    def test_count_outside_the_range(self) -> None:
        self.refused("count must be between 1 and 100, got 0", count=0)
        self.refused("count must be between 1 and 100, got 101", count=101)

    def test_name_with_a_newline_or_a_leading_digit(self) -> None:
        self.refused("name must start with a letter", name="NAME\ninjected=1")
        self.refused("name must start with a letter", name="1NAME")
        self.refused("name must start with a letter", name="")

    def test_mode_that_is_not_four_octal_digits(self) -> None:
        for mode in ("600", "0999", "06000", "u=rw", "0600\n"):
            with self.subTest(mode=mode):
                self.refused("mode must be four octal digits", mode=mode)

    def test_empty_token(self) -> None:
        self.refused("token must not be empty", token="")

    def test_a_refusal_never_names_the_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            params = make_params(Path(directory), count=0, token=THROWAWAY_TOKEN)
            with self.assertRaises(record.ValidationError) as caught:
                record.validate(params)
        self.assertNotIn(THROWAWAY_TOKEN, str(caught.exception))

    def test_acceptable_values_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            record.validate(make_params(Path(directory), count=100, mode="0000"))
            record.validate(make_params(Path(directory), count=1, name="a"))


class RenderAndPlanTests(unittest.TestCase):
    """The pure logic: what is written, and what an apply would do."""

    def setUp(self) -> None:
        self.params = make_params(Path("/unused"))

    def test_render_is_deterministic_and_keyed_by_the_token(self) -> None:
        self.assertEqual(record.render(self.params), record.render(self.params))
        other = dataclasses.replace(self.params, token=OTHER_THROWAWAY_TOKEN)
        self.assertNotEqual(record.render(self.params), record.render(other))

    def test_render_never_contains_the_token(self) -> None:
        self.assertNotIn(THROWAWAY_TOKEN, record.render(self.params))
        self.assertIn("signature=", record.render(self.params))

    def test_render_without_a_token_has_no_signature(self) -> None:
        text = record.render(dataclasses.replace(self.params, token=None))
        self.assertEqual(text, "name=EXAMPLE_NAME\ncount=3\n")

    def test_a_missing_file_is_written(self) -> None:
        decided = record.plan(self.params, record.Observed(None, None))
        self.assertEqual(decided.action, "write")
        self.assertTrue(decided.changed)
        self.assertEqual(decided.before, "")
        self.assertEqual(decided.after, record.render(self.params))

    def test_a_matching_file_is_left_alone(self) -> None:
        observed = record.Observed(record.render(self.params), 0o640)
        decided = record.plan(self.params, observed)
        self.assertEqual(decided.action, "none")
        self.assertFalse(decided.changed)

    def test_other_content_is_rewritten(self) -> None:
        self.assertEqual(record.plan(self.params, record.Observed("x\n", 0o640)).action, "write")

    def test_other_mode_is_corrected_without_a_rewrite(self) -> None:
        observed = record.Observed(record.render(self.params), 0o644)
        self.assertEqual(record.plan(self.params, observed).action, "chmod")

    def test_absent_removes_an_existing_file_only(self) -> None:
        absent = dataclasses.replace(self.params, state="absent")
        self.assertEqual(record.plan(absent, record.Observed("x\n", 0o600)).action, "remove")
        self.assertEqual(record.plan(absent, record.Observed(None, None)).action, "none")


class RunTests(unittest.TestCase):
    """The module against a real directory: check mode, apply, and the second apply."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.directory = Path(self._directory.name)
        self.params = make_params(self.directory)

    def names(self) -> list[str]:
        """Return every entry in the directory, temporary files included."""
        return sorted(entry.name for entry in self.directory.iterdir())

    def test_check_mode_reports_a_change_and_writes_nothing(self) -> None:
        decided = record.run(self.params, check_mode=True)
        self.assertTrue(decided.changed)
        self.assertEqual(self.names(), [])

    def test_apply_changes_once_and_the_second_apply_changes_nothing(self) -> None:
        first = record.run(self.params, check_mode=False)
        second = record.run(self.params, check_mode=False)
        self.assertTrue(first.changed)
        self.assertFalse(second.changed)
        self.assertEqual(self.names(), ["record"])

    def test_the_file_has_the_content_and_the_mode(self) -> None:
        record.run(self.params, check_mode=False)
        target = self.directory / "record"
        self.assertEqual(target.read_text(encoding="utf-8"), record.render(self.params))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assertNotIn(THROWAWAY_TOKEN, target.read_text(encoding="utf-8"))

    def test_check_mode_after_an_apply_reports_no_change(self) -> None:
        record.run(self.params, check_mode=False)
        self.assertFalse(record.run(self.params, check_mode=True).changed)

    def test_check_mode_leaves_drifted_content_and_mode_alone(self) -> None:
        record.run(self.params, check_mode=False)
        target = self.directory / "record"
        target.write_text("drifted\n", encoding="utf-8")
        target.chmod(0o666)
        self.assertEqual(record.run(self.params, check_mode=True).action, "write")
        self.assertEqual(target.read_text(encoding="utf-8"), "drifted\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o666)

    def test_apply_repairs_drifted_content_then_changes_nothing(self) -> None:
        record.run(self.params, check_mode=False)
        target = self.directory / "record"
        target.write_text("drifted\n", encoding="utf-8")
        self.assertTrue(record.run(self.params, check_mode=False).changed)
        self.assertFalse(record.run(self.params, check_mode=False).changed)
        self.assertEqual(target.read_text(encoding="utf-8"), record.render(self.params))

    def test_apply_repairs_a_drifted_mode_then_changes_nothing(self) -> None:
        record.run(self.params, check_mode=False)
        target = self.directory / "record"
        target.chmod(0o666)
        self.assertEqual(record.run(self.params, check_mode=False).action, "chmod")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assertFalse(record.run(self.params, check_mode=False).changed)

    def test_check_mode_of_a_removal_keeps_the_file(self) -> None:
        record.run(self.params, check_mode=False)
        absent = dataclasses.replace(self.params, state="absent")
        self.assertTrue(record.run(absent, check_mode=True).changed)
        self.assertEqual(self.names(), ["record"])

    def test_removal_changes_once(self) -> None:
        record.run(self.params, check_mode=False)
        absent = dataclasses.replace(self.params, state="absent")
        self.assertTrue(record.run(absent, check_mode=False).changed)
        self.assertFalse(record.run(absent, check_mode=False).changed)
        self.assertEqual(self.names(), [])

    def test_a_missing_directory_is_refused_in_both_modes(self) -> None:
        params = dataclasses.replace(self.params, path=self.directory / "missing" / "record")
        for check_mode in (True, False):
            with (
                self.subTest(check_mode=check_mode),
                self.assertRaisesRegex(record.ValidationError, "directory .* does not exist"),
            ):
                record.run(params, check_mode=check_mode)

    def test_a_directory_in_the_way_is_refused(self) -> None:
        (self.directory / "record").mkdir()
        with self.assertRaisesRegex(record.ValidationError, "is not a regular file"):
            record.run(self.params, check_mode=False)

    def test_a_symlink_in_the_way_is_refused_and_its_target_untouched(self) -> None:
        target = self.directory / "elsewhere"
        target.write_text("keep\n", encoding="utf-8")
        (self.directory / "record").symlink_to(target)
        with self.assertRaisesRegex(record.ValidationError, "is not a regular file"):
            record.run(self.params, check_mode=False)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")

    def test_a_failed_write_leaves_no_temporary_file(self) -> None:
        with (
            mock.patch("os.replace", side_effect=OSError("DISK_FULL")),
            self.assertRaises(OSError),
        ):
            record.run(self.params, check_mode=False)
        self.assertEqual(self.names(), [])


class FakeModule:
    """Stands in for AnsibleModule: records how it was built and how it ended."""

    instances: list["FakeModule"] = []  # noqa: RUF012 - reset by each test

    def __init__(self, argument_spec: object, supports_check_mode: bool) -> None:
        self.argument_spec = argument_spec
        self.supports_check_mode = supports_check_mode
        self.params: dict[str, object] = {}
        self.check_mode = False
        self.result: dict[str, object] = {}
        FakeModule.instances.append(self)

    def exit_json(self, **result: object) -> None:
        self.result = {"exit": "ok", **result}

    def fail_json(self, **result: object) -> None:
        self.result = {"exit": "failed", **result}


class MainTests(unittest.TestCase):
    """The glue between AnsibleModule and the logic."""

    def setUp(self) -> None:
        FakeModule.instances = []
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.directory = Path(self._directory.name)

    def run_main(self, *, check_mode: bool, **changes: object) -> FakeModule:
        values = {**SAMPLE, "path": str(self.directory / "record"), "state": "present", **changes}

        def build(argument_spec: object, supports_check_mode: bool) -> FakeModule:
            module = FakeModule(argument_spec, supports_check_mode)
            module.params = dict(values)
            module.check_mode = check_mode
            return module

        with mock.patch.object(record, "AnsibleModule", side_effect=build):
            record.main()
        return FakeModule.instances[-1]

    def test_the_module_declares_check_mode_and_the_generated_spec(self) -> None:
        module = self.run_main(check_mode=True)
        self.assertIs(module.supports_check_mode, True)
        self.assertEqual(module.argument_spec, record.ARGUMENT_SPEC)

    def test_check_mode_run_changes_nothing_on_the_host(self) -> None:
        module = self.run_main(check_mode=True)
        self.assertEqual(module.result["exit"], "ok")
        self.assertIs(module.result["changed"], True)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_apply_run_changes_the_host_once(self) -> None:
        self.assertIs(self.run_main(check_mode=False).result["changed"], True)
        self.assertIs(self.run_main(check_mode=False).result["changed"], False)

    def test_a_bad_value_is_failed_with_a_named_message(self) -> None:
        module = self.run_main(check_mode=False, count=0)
        self.assertEqual(module.result["exit"], "failed")
        self.assertEqual(module.result["msg"], "count must be between 1 and 100, got 0")

    def test_the_result_never_carries_the_token(self) -> None:
        module = self.run_main(check_mode=False)
        self.assertNotIn(THROWAWAY_TOKEN, repr(module.result))


if __name__ == "__main__":
    unittest.main()
