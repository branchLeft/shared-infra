"""Checks that the deploy_tooling role's class internal gets the gateway's files, not the policy.

Class internal is a third host class beside app and gateway. It installs what the hand-run
deploy-tooling script installs on a host with no DOCKER-USER policy program: the wrapper, the
template unit, the directories and the sudoers read. It never gets the policy program, its unit
or the firewall read-back. The directories and the sudoers read are not gated by class at all,
so every class reads the drop-in and none writes it. Each check returns the problems it found;
the tests run it on the real role (no problems) and on the role with one edit (the problem).
"""

from __future__ import annotations

import unittest

import deploy_tooling_vars as role_vars
import yaml  # type: ignore[import-untyped]

MAIN = role_vars.ROLE / "tasks" / "main.yml"
ARG_SPECS = role_vars.ROLE / "meta" / "argument_specs.yml"
CLASS_KEY = "deploy_tooling_host_class"
POLICY_GATE = "deploy_tooling_host_class == 'app'"
APP_SET_FACT_GATE = "deploy_tooling_host_class == 'app' else"
APP_LIST = "deploy_tooling_app_file_targets"
ISOLATION_INCLUDE = "_isolation.yml"
POLICY_INSTALL = "Install the policy program and its unit"
DIRECTORY_TASK = "Create the directories both hand-run scripts create"
COMMON_INSTALL = "Install the deploy wrapper and the compose template unit"
SUDOERS_KEY = "deploy_tooling_sudoers"
SUDOERS_CONTENT = "deploy_tooling_sudoers_content"
VARIANT_MESSAGE = "must name its policy variant"
POLICY_LABELS = frozenset({"policy program", "policy unit"})


def _tasks(text: str) -> list[dict[str, object]]:
    """Return the tasks of a task file, each a mapping.

    Raises:
        TypeError: the file is not a list.
    """
    doc: object = yaml.safe_load(text)
    if not isinstance(doc, list):
        message = "tasks/main.yml is not a list"
        raise TypeError(message)
    return [
        {str(key): value for key, value in task.items()} for task in doc if isinstance(task, dict)
    ]


def _host_class_choices(specs_text: str) -> list[object]:
    """Return the choices the argument spec gives the host class.

    Raises:
        TypeError: the spec is not the shape the role declares.
    """
    doc: object = yaml.safe_load(specs_text)
    if not isinstance(doc, dict):
        message = "argument_specs.yml is not a mapping"
        raise TypeError(message)
    specs = doc.get("argument_specs")
    main = specs.get("main") if isinstance(specs, dict) else None
    options = main.get("options") if isinstance(main, dict) else None
    option = options.get(CLASS_KEY) if isinstance(options, dict) else None
    choices = option.get("choices") if isinstance(option, dict) else None
    if not isinstance(choices, list):
        message = f"{CLASS_KEY} has no choices list in argument_specs.yml"
        raise TypeError(message)
    return choices


def choices_problems(specs_text: str) -> list[str]:
    """Return a problem unless the argument spec takes exactly the classes the checks know."""
    choices = _host_class_choices(specs_text)
    if sorted(str(c) for c in choices) != sorted(role_vars.HOST_CLASSES):
        return [
            f"{CLASS_KEY} choices are {choices}, the checks know {list(role_vars.HOST_CLASSES)}"
        ]
    return []


def file_set_problems(variables: dict[str, object]) -> list[str]:
    """Return a problem unless internal gets exactly the gateway's files and no policy file."""
    problems: list[str] = []
    gateway = role_vars.file_targets_for_class(variables, "gateway")
    internal = role_vars.file_targets_for_class(variables, "internal")
    app = role_vars.file_targets_for_class(variables, "app")
    if [t.path for t in internal] != [t.path for t in gateway]:
        problems.append("class internal does not get the same files as class gateway")
    labels = {t.label for t in internal}
    if labels != {"deploy wrapper", "compose template unit"}:
        problems.append(f"class internal gets {sorted(labels)}, expected the wrapper and the unit")
    if labels & POLICY_LABELS:
        problems.append("class internal gets the policy program or its unit")
    if len(app) <= len(internal):
        problems.append("class app does not get the policy files on top of the common ones")
    return problems


def gating_problems(main_text: str) -> list[str]:
    """Return a problem for each policy file given to a class but app, or a common one gated."""
    problems: list[str] = []
    tasks = _tasks(main_text)
    for task in tasks:
        name = str(task.get("name", ""))
        if APP_LIST in str(task) or ISOLATION_INCLUDE in str(task):
            when = task.get("when")
            # The set_fact that lists the files for this host is gated by its own expression.
            listed_for_app = APP_SET_FACT_GATE in str(task)
            if when != POLICY_GATE and not listed_for_app:
                problems.append(
                    f"'{name}' gives the policy files to a class other than app: when={when!r}"
                )
    for common in (DIRECTORY_TASK, COMMON_INSTALL):
        matches = [t for t in tasks if t.get("name") == common]
        if len(matches) != 1:
            problems.append(f"'{common}' is not found once in tasks/main.yml")
        elif "when" in matches[0]:
            problems.append(f"'{common}' is gated by {matches[0]['when']!r}, every class gets it")
    return problems


def sudoers_problems(main_text: str) -> list[str]:
    """Return a problem for each sudoers check gated by host class, or a missing content compare."""
    problems: list[str] = []
    sudoers = [t for t in _tasks(main_text) if SUDOERS_KEY in str(t)]
    if not any(SUDOERS_CONTENT in str(t) for t in sudoers):
        problems.append("no task compares the sudoers drop-in with the one grant")
    for task in sudoers:
        when = str(task.get("when", ""))
        if CLASS_KEY in when:
            problems.append(f"sudoers check '{task.get('name', '')}' is gated by {when!r}")
    return problems


def variant_problems(main_text: str) -> list[str]:
    """Return a problem unless the variant assertion lets class internal omit the variant."""
    for task in _tasks(main_text):
        assertion = task.get("ansible.builtin.assert")
        if isinstance(assertion, dict) and VARIANT_MESSAGE in str(assertion.get("fail_msg", "")):
            that = assertion.get("that")
            if not isinstance(that, list) or len(that) < 2:
                return ["the variant assertion has no second condition"]
            if "'internal'" not in str(that[1]):
                return [
                    f"the variant assertion still requires a variant for class internal: {that[1]}"
                ]
            return []
    return ["no task asserts that an app host names its variant"]


class TestRealTree(unittest.TestCase):
    """The role as it stands has none of the problems."""

    def test_the_argument_spec_takes_the_three_classes(self) -> None:
        self.assertEqual(choices_problems(ARG_SPECS.read_text(encoding="utf-8")), [])

    def test_internal_gets_the_gateway_files_and_no_policy_program(self) -> None:
        self.assertEqual(file_set_problems(role_vars.load_vars()), [])

    def test_the_policy_files_are_gated_on_class_app_alone(self) -> None:
        self.assertEqual(gating_problems(MAIN.read_text(encoding="utf-8")), [])

    def test_the_sudoers_checks_are_not_gated_by_class(self) -> None:
        self.assertEqual(sudoers_problems(MAIN.read_text(encoding="utf-8")), [])

    def test_an_internal_host_needs_no_policy_variant(self) -> None:
        self.assertEqual(variant_problems(MAIN.read_text(encoding="utf-8")), [])


class TestControls(unittest.TestCase):
    """Each way of breaking the class is found, in the text of the real files."""

    def setUp(self) -> None:
        self.main = MAIN.read_text(encoding="utf-8")
        self.specs = ARG_SPECS.read_text(encoding="utf-8")

    def _edited(self, text: str, old: str, new: str) -> str:
        """Return the text with the first occurrence replaced, failing if the edit did not apply."""
        self.assertIn(old, text)
        edited = text.replace(old, new, 1)
        self.assertNotEqual(edited, text)
        return edited

    def test_a_policy_program_given_to_internal_is_found(self) -> None:
        # Sabotage (a): the policy program's copy gated on class internal too.
        edited = self._edited(
            self.main,
            "  when: deploy_tooling_host_class == 'app'\n",
            "  when: deploy_tooling_host_class in ['app', 'internal']\n",
        )
        problems = gating_problems(edited)
        self.assertTrue(any(POLICY_INSTALL in p for p in problems), problems)

    def test_the_isolation_include_given_to_internal_is_found(self) -> None:
        edited = self._edited(
            self.main,
            "include_tasks: _isolation.yml\n  when: deploy_tooling_host_class == 'app'\n",
            "include_tasks: _isolation.yml\n"
            "  when: deploy_tooling_host_class in ['app', 'internal']\n",
        )
        problems = gating_problems(edited)
        self.assertTrue(any("Apply the isolation policy" in p for p in problems), problems)

    def test_a_sudoers_read_dropped_from_internal_is_found(self) -> None:
        # Sabotage (b): the drop-in comparison skipped for class internal.
        edited = self._edited(
            self.main,
            "    quiet: true\n\n# ----- The app-host isolation",
            "    quiet: true\n"
            "  when: deploy_tooling_host_class != 'internal'\n\n"
            "# ----- The app-host isolation",
        )
        problems = sudoers_problems(edited)
        self.assertTrue(any("is gated by" in p for p in problems), problems)

    def test_the_wrapper_install_gated_by_class_is_found(self) -> None:
        edited = self._edited(
            self.main,
            "  notify: Reload systemd manager\n\n- name: Install the policy program and its unit",
            "  notify: Reload systemd manager\n  when: deploy_tooling_host_class != 'internal'\n\n"
            "- name: Install the policy program and its unit",
        )
        self.assertTrue(gating_problems(edited))

    def test_internal_missing_from_the_argument_spec_is_found(self) -> None:
        edited = self._edited(self.specs, "          - internal\n", "")
        self.assertTrue(choices_problems(edited))

    def test_a_variant_still_required_for_internal_is_found(self) -> None:
        edited = self._edited(
            self.main,
            "deploy_tooling_host_class in ['gateway', 'internal'] or",
            "deploy_tooling_host_class in ['gateway'] or",
        )
        self.assertTrue(variant_problems(edited))

    def test_internal_given_the_policy_files_is_found(self) -> None:
        variables = role_vars.load_vars()
        common = variables["deploy_tooling_common_file_targets"]
        app = variables["deploy_tooling_app_file_targets"]
        if not isinstance(common, list) or not isinstance(app, list):
            self.fail("the role's file target lists are not lists in vars/main.yml")
        broken = dict(variables)
        broken["deploy_tooling_common_file_targets"] = [*common, *app]
        self.assertTrue(file_set_problems(broken))

    def test_an_unknown_class_is_refused(self) -> None:
        with self.assertRaises(role_vars.RoleVarsError):
            role_vars.file_targets_for_class(role_vars.load_vars(), "edge")


if __name__ == "__main__":
    unittest.main()
