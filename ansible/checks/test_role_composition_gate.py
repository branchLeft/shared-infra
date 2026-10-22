"""Fails while a role composes another role in a way the ANS-12 amendment does not allow.

The structure of every composition (green now) and the citation of the merged amendment (red
until committed) are kept apart. See restart_stamp/README.md, "Composition (ANS-12)".
"""

from __future__ import annotations

import copy
import inspect
import json
import os
import sys
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import role_composition
import role_tasks
from amendment_citation import (
    HttpStandardsApi,
    Response,
    StandardsReadError,
    amendment_problems,
    citation_problems,
)
from role_composition import (
    CONDITIONS,
    REVIEW_ONLY,
    citation_gate,
    composition_problems,
    including_roles,
    readme_conditions,
    run_gate,
)

ROOT = Path(__file__).resolve().parents[2]
ROLE_DIRS = (ROOT / "ansible" / "roles", ROOT / "ansible" / "patterns")
CITATION = ROOT / "ansible" / "checks" / "ans12_composition_citation.txt"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
README = ROOT / "ansible" / "roles" / "restart_stamp" / "README.md"

# What the API returned for standards pull request 154 (merged) and 155 (open), kept as
# returned: an open pull request has merged false and a merge commit that is GitHub's test
# merge, not a commit of the repository.
MERGED = json.loads((FIXTURES / "standards_pull_154.json").read_text(encoding="utf-8"))
OPEN = json.loads((FIXTURES / "standards_pull_155.json").read_text(encoding="utf-8"))
MERGED_SHA = str(MERGED["merge_commit_sha"])
OPEN_SHA = str(OPEN["merge_commit_sha"])
OTHER_SHA = "b" * 40
NOT_THERE = "the fixture has none"


def line(number: int, sha: str) -> str:
    return f"https://github.com/branchLeft/standards/pull/{number} merged {sha}\n"


# The ANS-12 section of docs/stacks/ansible.md at the merge commit of pull request 154, cut
# down to its first paragraph and its second named limit (the two lines that matter are the
# repository's own), and the section as an amendment might leave it. The rule is written for
# these tests; it is not the amendment.
HEAD = """\
## ANS-12 — one role per logical service

A role configures one service, or one cross-cutting capability with one reason
to change, and nothing else. Composition is in a playbook, which lists roles in
order; `meta/main.yml` carries no `dependencies`.

"""
LIMIT_PARAGRAPH = """\
**Named limit:** nothing here forbids a role's tasks from including or
importing another role, which composes roles in the way a dependency does. That
is decided with the first role pattern and recorded here by amendment.

"""
RULE = """\
**Composition:** a role may include another role only when it is a capability role,
one that configures no service.

"""
NEXT_CLAUSE = "## ANS-13 — where roles and playbooks live\n"
BEFORE = HEAD + LIMIT_PARAGRAPH + NEXT_CLAUSE
AMENDED = HEAD + RULE + NEXT_CLAUSE
RULE_BUT_LIMIT_KEPT = HEAD + LIMIT_PARAGRAPH + RULE + NEXT_CLAUSE
LIMIT_GONE_NO_RULE = HEAD + NEXT_CLAUSE
NO_SECTION = NEXT_CLAUSE


class FakeApi:
    """The standards repository as a fixture: it refuses any pull request or file it lacks."""

    def __init__(self, pulls: Mapping[int, Mapping[str, object]], files: Mapping[str, str]) -> None:
        self.pulls = pulls
        self.files = files

    def pull(self, number: int) -> Mapping[str, object]:
        if number not in self.pulls:
            raise StandardsReadError(str(number), NOT_THERE)
        return self.pulls[number]

    def file_at(self, sha: str, path: str) -> str:
        if sha not in self.files:
            raise StandardsReadError(f"{path}@{sha}", NOT_THERE)
        return self.files[sha]


def api_with(document: str, pull: Mapping[str, object] = MERGED) -> FakeApi:
    return FakeApi({int(str(pull["number"])): pull}, {str(pull["merge_commit_sha"]): document})


class StubResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body

    def read(self) -> bytes:
        return self.body


class StubConnection:
    """One connection that answers from a script; an exception in the script is raised."""

    def __init__(self, script: list[Response | OSError], seen: list[dict[str, str]]) -> None:
        self.script = script
        self.seen = seen

    def request(self, method: str, url: str, *, headers: dict[str, str]) -> None:
        self.seen.append({"method": method, "url": url, **headers})

    def getresponse(self) -> Response:
        step = self.script.pop(0)
        if isinstance(step, OSError):
            raise step
        return step

    def close(self) -> None:
        return None


def api_over(
    script: list[Response | OSError], bearer: str | None = "value"
) -> tuple[HttpStandardsApi, list[dict[str, str]]]:
    seen: list[dict[str, str]] = []
    return HttpStandardsApi(bearer, lambda _host: StubConnection(script, seen)), seen


# A pair of throwaway roles that meet every condition, and the changes that break one each.
CALLER_VARS = "caller_cap_role: '{{ role_path | realpath | dirname }}/capability'\n"
CALL = (
    "---\n- name: Call\n  ansible.builtin.include_role:\n"
    "    name: '{{ caller_cap_role }}'\n    tasks_from: read\n"
    "  vars:\n    cap_items: [x]\n"
)
SPECS = (
    "---\nargument_specs:\n  read:\n    short_description: Read\n    options:\n"
    "      cap_items:\n        type: list\n        required: true\n"
    "      cap_extra:\n        type: str\n        default: x\n"
)
THIRD = "---\n- name: Pass on\n  ansible.builtin.include_role:\n    name: third\n"
SPEC_HEAD = "---\nargument_specs:\n  read:\n    short_description: Read\n    options:\n"
ITEMS = "      cap_items:\n        type: list\n        required: true\n"
# The required list of the pair, now with elements that have options of their own.
ELEMENT_ITEMS = (
    "      cap_items:\n        type: list\n        elements: dict\n        required: true\n"
    "        options:\n          name:\n            type: str\n            required: true\n"
)


def no_default(*paths: str) -> list[str]:
    """The one problem the pair reports when these options have no default."""
    return [
        "roles/caller (tasks/main.yml): the entry point read of capability declares optional "
        f"input(s) {list(paths)} with no `default` in its meta/argument_specs.yml"
    ]


def blocked(key: str, section: str = "block") -> str:
    """The call of CALL inside a block that sets ``key`` for everything in it."""
    return (
        f"---\n- name: Round\n  vars:\n    {key}: 1\n  {section}:\n"
        "    - name: Call\n      ansible.builtin.include_role:\n"
        "        name: '{{ caller_cap_role }}'\n        tasks_from: read\n"
        "      vars:\n        cap_items: [x]\n"
    )


def go(target: str, key: str) -> str:
    """An include of a file of the role that sets ``key`` for every task in that file."""
    return f"---\n- name: Go\n  ansible.builtin.include_tasks: {target}\n  vars:\n    {key}: 1\n"


@dataclass(frozen=True)
class Pair:
    """The files of the throwaway pair; a test changes the one it breaks."""

    call: str = CALL
    caller_vars: str = CALLER_VARS
    specs: str | None = SPECS
    readme: str = "Called by `caller`.\n"
    callee_tasks: str = "---\n- name: Say\n  ansible.builtin.debug:\n    msg: x\n"
    caller_meta: str | None = None
    caller_files: tuple[tuple[str, str], ...] = ()
    callee_files: tuple[tuple[str, str], ...] = ()


def make_pair(base: Path, pair: Pair) -> tuple[Path, ...]:
    """Write roles/caller and roles/capability under ``base`` and return the roles directory."""
    caller, callee = base / "roles" / "caller", base / "roles" / "capability"
    for role in (caller, callee):
        (role / "tasks").mkdir(parents=True)
        (role / "meta").mkdir()
    for relative, text in pair.caller_files:
        (caller / relative).parent.mkdir(parents=True, exist_ok=True)
        (caller / relative).write_text(text, encoding="utf-8")
    for relative, text in pair.callee_files:
        (callee / relative).parent.mkdir(parents=True, exist_ok=True)
        (callee / relative).write_text(text, encoding="utf-8")
    (caller / "tasks" / "main.yml").write_text(pair.call, encoding="utf-8")
    (caller / "vars").mkdir(exist_ok=True)
    (caller / "vars" / "main.yml").write_text("---\n" + pair.caller_vars, encoding="utf-8")
    (callee / "tasks" / "read.yml").write_text(pair.callee_tasks, encoding="utf-8")
    (callee / "README.md").write_text(pair.readme, encoding="utf-8")
    if pair.specs is not None:
        (callee / "meta" / "argument_specs.yml").write_text(pair.specs, encoding="utf-8")
    if pair.caller_meta is not None:
        (caller / "meta" / "main.yml").write_text(pair.caller_meta, encoding="utf-8")
    return (base / "roles",)


def problems_of(pair: Pair) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        return composition_problems(make_pair(Path(tmp), pair))


class RealTreeTest(unittest.TestCase):
    def test_the_real_tree_composes_only_capability_roles(self) -> None:
        # Green now: this is the structure alone, so a false positive of the rules on the real
        # tree shows here and not in the test that waits for the citation.
        self.assertEqual([], composition_problems(ROLE_DIRS))

    def test_the_scan_finds_the_include_of_the_real_edge_stack(self) -> None:
        # A control for the two tests around it: a clean result means something only if the
        # scan sees the include that is there.
        self.assertEqual(["roles/edge_stack"], sorted(including_roles(ROLE_DIRS)))

    def test_without_the_citation_file_the_only_problem_is_the_missing_citation(self) -> None:
        # The cause of the red below, pinned: the tree has an include and the file is missing,
        # and nothing else is wrong with it.
        with tempfile.TemporaryDirectory() as tmp:
            problems = citation_gate(ROLE_DIRS, Path(tmp) / "citation.txt", FakeApi({}, {}))
        self.assertEqual(1, len(problems), problems)
        self.assertTrue(problems[0].startswith("roles/edge_stack (tasks/_decide.yml"), problems)
        self.assertIn("citation.txt is missing", problems[0])

    def test_the_real_tree_has_the_amendment_cited_for_every_role_that_includes_a_role(
        self,
    ) -> None:
        # Red until the citation is committed, on purpose: it is the merge hold of the pull
        # request that adds the first role to include another. In CI it reads the standards
        # repository; elsewhere it is skipped, and says so, when that cannot be read.
        api = HttpStandardsApi(os.environ.get("GITHUB_TOKEN"))
        problems, skipped = run_gate(
            ROLE_DIRS, CITATION, api, os.environ.get("GITHUB_ACTIONS") == "true"
        )
        if skipped:
            print(f"SKIPPED: {skipped}", file=sys.__stderr__)
            self.skipTest(skipped)
        self.assertEqual([], problems)

    def test_the_readme_states_the_conditions_the_gate_enforces(self) -> None:
        # The gate's list and the README's are one list: break either and this fails.
        text = README.read_text(encoding="utf-8")
        held = readme_conditions(text, "gate-conditions")
        review = readme_conditions(text, "review-conditions")
        self.assertEqual(list(CONDITIONS), held)
        self.assertEqual(list(REVIEW_ONLY), review)


class CompositionTest(unittest.TestCase):
    def test_a_capability_role_called_as_the_conditions_say_is_not_reported(self) -> None:
        self.assertEqual([], problems_of(Pair()))

    def test_an_import_role_is_reported(self) -> None:
        text = CALL.replace("include_role", "import_role")
        self.assertEqual(
            ["roles/caller (tasks/main.yml): import_role is never used to compose roles"],
            problems_of(Pair(call=text)),
        )

    def test_a_bare_name_is_reported(self) -> None:
        text = CALL.replace("'{{ caller_cap_role }}'", "capability")
        self.assertEqual(
            [
                "roles/caller (tasks/main.yml): capability is named bare, "
                "not by a path built from role_path"
            ],
            problems_of(Pair(call=text)),
        )

    def test_a_name_that_cannot_be_resolved_is_reported(self) -> None:
        text = CALL.replace("{{ caller_cap_role }}", "{{ somebody_elses_variable }}")
        problems = problems_of(Pair(call=text))
        self.assertEqual(1, len(problems), problems)
        self.assertIn("cannot be resolved", problems[0])

    def test_a_name_that_is_a_path_other_than_the_one_required_is_reported(self) -> None:
        # A string that names a path is not resolved: only the path built from role_path is.
        for name in ("../capability", "'{{ role_path }}/../capability'", "/etc/capability"):
            text = CALL.replace("'{{ caller_cap_role }}'", name)
            with self.subTest(name=name):
                problems = problems_of(Pair(call=text))
                self.assertEqual(1, len(problems), problems)
                self.assertIn("cannot be resolved", problems[0])

    def test_a_name_that_resolves_through_the_roles_own_defaults_is_resolved(self) -> None:
        # The resolution reads defaults/ as well as vars/: the same call, with the variable
        # moved, is as clean as before.
        with tempfile.TemporaryDirectory() as tmp:
            roles = make_pair(Path(tmp), Pair(caller_vars="unused: 1\n"))
            (roles[0] / "caller" / "defaults").mkdir()
            (roles[0] / "caller" / "defaults" / "main.yml").write_text(
                "---\n" + CALLER_VARS, encoding="utf-8"
            )
            self.assertEqual([], composition_problems(roles))

    def test_a_callee_with_no_typed_inputs_is_reported(self) -> None:
        problems = problems_of(Pair(specs=None))
        self.assertEqual(1, len(problems), problems)
        self.assertIn("has no argument_specs for its entry point read", problems[0])

    def test_a_call_that_omits_a_required_input_is_reported(self) -> None:
        text = CALL.replace("cap_items: [x]", "cap_extra: y")
        self.assertEqual(
            [
                "roles/caller (tasks/main.yml): "
                "the call does not give required input(s) ['cap_items']"
            ],
            problems_of(Pair(call=text)),
        )

    def test_each_required_input_is_reported_by_name_when_it_is_left_out(self) -> None:
        # Two required inputs of different names, left out one at a time and both: the report
        # names exactly those left out, so a constant list or a first-name-only report fails.
        specs = SPECS + "      cap_second:\n        type: str\n        required: true\n"
        given = {
            "cap_items": "cap_items: [x]",
            "cap_second": "cap_second: y",
        }
        cases: tuple[tuple[tuple[str, ...], list[str]], ...] = (
            (("cap_items",), ["cap_second"]),
            (("cap_second",), ["cap_items"]),
            ((), ["cap_items", "cap_second"]),
            (("cap_items", "cap_second"), []),
        )
        for gave, left_out in cases:
            lines = "".join(f"\n    {given[name]}" for name in gave) or "\n    cap_extra: y"
            text = CALL.replace("  vars:\n    cap_items: [x]\n", f"  vars:{lines}\n")
            expected = (
                [
                    "roles/caller (tasks/main.yml): "
                    f"the call does not give required input(s) {left_out}"
                ]
                if left_out
                else []
            )
            with self.subTest(gave=gave):
                self.assertEqual(expected, problems_of(Pair(call=text, specs=specs)))

    def test_a_call_that_gives_an_input_the_entry_point_does_not_declare_is_reported(self) -> None:
        text = CALL.replace("cap_items: [x]", "cap_items: [x]\n    not_declared_anywhere: 1")
        self.assertEqual(
            [
                "roles/caller (tasks/main.yml): the call gives input(s) ['not_declared_anywhere'] "
                "that the entry point read of capability does not declare"
            ],
            problems_of(Pair(call=text)),
        )

    def test_a_call_that_gives_an_optional_input_the_entry_point_declares_is_not_reported(
        self,
    ) -> None:
        # The control of the case above: the optional input cap_extra is declared.
        text = CALL.replace("cap_items: [x]", "cap_items: [x]\n    cap_extra: y")
        self.assertEqual([], problems_of(Pair(call=text)))

    def test_a_call_to_an_entry_point_that_declares_no_inputs_is_reported(self) -> None:
        # The entry point exists in argument_specs.yml but has no options at all: every input
        # the call gives is one the callee does not declare.
        specs = "---\nargument_specs:\n  read:\n    short_description: Read\n"
        self.assertEqual(
            [
                "roles/caller (tasks/main.yml): the call gives input(s) ['cap_items'] "
                "that the entry point read of capability does not declare"
            ],
            problems_of(Pair(specs=specs)),
        )

    def test_a_callee_that_includes_a_role_itself_is_reported(self) -> None:
        problems = problems_of(Pair(callee_tasks=THIRD))
        self.assertIn(
            "roles/caller (tasks/main.yml): capability includes a role itself",
            problems,
        )

    def test_a_callee_whose_readme_does_not_name_the_caller_is_reported(self) -> None:
        self.assertEqual(
            ["roles/caller (tasks/main.yml): the README of capability does not name caller"],
            problems_of(Pair(readme="Called by `other`.\n")),
        )

    def test_a_readme_that_names_a_longer_role_is_not_a_naming_of_the_caller(self) -> None:
        self.assertEqual(
            ["roles/caller (tasks/main.yml): the README of capability does not name caller"],
            problems_of(Pair(readme="Called by `caller_two`.\n")),
        )

    def test_a_role_with_dependencies_is_reported(self) -> None:
        meta = "---\ndependencies:\n  - role: capability\n"
        self.assertEqual(
            ["roles/caller: meta/main.yml carries dependencies"],
            problems_of(Pair(caller_meta=meta)),
        )

    def test_a_role_with_an_empty_dependencies_list_is_not_reported(self) -> None:
        self.assertEqual([], problems_of(Pair(caller_meta="---\ndependencies: []\n")))

    def test_an_include_of_a_file_outside_the_role_is_reported(self) -> None:
        for path in (
            "'{{ role_path }}/../capability/tasks/read.yml'",
            "../capability/tasks/read.yml",
            "/etc/x.yml",
            "'{{ computed }}.yml'",
            "'{{ role_path }}/{{ computed }}.yml'",
        ):
            text = CALL + f"- name: Borrow\n  ansible.builtin.include_tasks: {path}\n"
            with self.subTest(path=path):
                problems = problems_of(Pair(call=text))
                self.assertEqual(1, len(problems), problems)
                self.assertIn("include_tasks names a file that is not a literal path", problems[0])

    def test_an_import_of_a_file_outside_the_role_is_reported(self) -> None:
        text = (
            CALL + "- name: Borrow\n  ansible.builtin.import_tasks: ../capability/tasks/read.yml\n"
        )
        problems = problems_of(Pair(call=text))
        self.assertEqual(1, len(problems), problems)
        self.assertIn("import_tasks names a file that is not a literal path", problems[0])

    def test_an_include_of_the_roles_own_files_is_not_reported(self) -> None:
        # Each file is there: an include of a file the role does not have is not an own file.
        for path, where in (
            ("_check.yml", "tasks/_check.yml"),
            ("'{{ role_path }}/tasks/sub/_check.yml'", "tasks/sub/_check.yml"),
            ("'{{ role_path }}/handlers/_check.yml'", "handlers/_check.yml"),
            ("sub/_check.yml", "tasks/sub/_check.yml"),
        ):
            text = CALL + f"- name: Own\n  ansible.builtin.include_tasks: {path}\n"
            with self.subTest(path=path):
                self.assertEqual(
                    [], problems_of(Pair(call=text, caller_files=((where, "---\n[]\n"),)))
                )

    def test_an_include_of_a_file_the_scan_does_not_read_is_reported(self) -> None:
        # The scan reads tasks/ and handlers/ only. A file anywhere else in the role, though
        # the path stays inside it, would hold tasks that no check sees: a second copy of the
        # stamp steps, or an import of another role. Each file here holds that import.
        hidden = "---\n- name: Hide\n  ansible.builtin.import_role:\n    name: third\n"
        for path, where in (
            ("'{{ role_path }}/vars/more.yml'", "vars/more.yml"),
            ("'{{ role_path }}/files/more.yml'", "files/more.yml"),
            ("files/more.yml", "files/more.yml"),
            ("'{{ role_path }}/tasks/more.txt'", "tasks/more.txt"),
        ):
            text = CALL + f"- name: Borrow\n  ansible.builtin.include_tasks: {path}\n"
            with self.subTest(path=path):
                problems = problems_of(Pair(call=text, caller_files=((where, hidden),)))
                self.assertEqual(1, len(problems), problems)
                self.assertIn("include_tasks names a file that is not a literal path", problems[0])

    def test_a_bare_name_that_is_also_a_file_elsewhere_in_the_role_is_reported(self) -> None:
        # Ansible may find the name at the root of the role instead of under tasks/, and the
        # scan would not have read that file.
        hidden = "---\n- name: Hide\n  ansible.builtin.import_role:\n    name: third\n"
        text = CALL + "- name: Borrow\n  ansible.builtin.include_tasks: more.yml\n"
        files = (("tasks/more.yml", "---\n[]\n"), ("more.yml", hidden))
        problems = problems_of(Pair(call=text, caller_files=files))
        self.assertEqual(1, len(problems), problems)
        self.assertIn("include_tasks names a file that is not a literal path", problems[0])

    def test_an_own_file_the_scan_reads_is_read_for_what_it_holds(self) -> None:
        # The control of the two tests above: the same import, in a file under tasks/, is
        # found by the scan, so a clean result for the other paths is the refusal and not a
        # scan that sees nothing.
        hidden = "---\n- name: Hide\n  ansible.builtin.import_role:\n    name: third\n"
        text = CALL + "- name: Borrow\n  ansible.builtin.include_tasks: more.yml\n"
        problems = problems_of(Pair(call=text, caller_files=(("tasks/more.yml", hidden),)))
        self.assertEqual(
            ["roles/caller (tasks/more.yml): import_role is never used to compose roles"], problems
        )

    def test_an_include_of_a_file_the_role_does_not_have_is_reported(self) -> None:
        # Ansible looks for a relative file in the role and then in the playbook's directory
        # and the working directory, which the scan does not read. Here the file is in the
        # playbook directory; the same import in a file under tasks/ is found (the control
        # above), so a clean result would be the file being missed.
        hidden = "---\n- name: Hide\n  ansible.builtin.import_role:\n    name: third\n"
        for path in ("helper.yml", "'{{ role_path }}/tasks/helper.yml'"):
            text = CALL + f"- name: Borrow\n  ansible.builtin.include_tasks: {path}\n"
            with self.subTest(path=path), tempfile.TemporaryDirectory() as tmp:
                roles = make_pair(Path(tmp), Pair(call=text))
                (Path(tmp) / "playbooks").mkdir()
                (Path(tmp) / "playbooks" / "helper.yml").write_text(hidden, encoding="utf-8")
                problems = composition_problems(roles)
                self.assertEqual(1, len(problems), problems)
                self.assertIn("include_tasks names a file that is not a literal path", problems[0])

    def test_an_include_through_a_linked_directory_that_leaves_the_scan_is_reported(self) -> None:
        # tasks/link points at vars/, and the scan does not go into a linked directory: it
        # reads tasks/main.yml and never vars/more.yml, which holds the import.
        hidden = "---\n- name: Hide\n  ansible.builtin.import_role:\n    name: third\n"
        for path in ("link/more.yml", "'{{ role_path }}/tasks/link/more.yml'"):
            text = CALL + f"- name: Borrow\n  ansible.builtin.include_tasks: {path}\n"
            with self.subTest(path=path), tempfile.TemporaryDirectory() as tmp:
                pair = Pair(call=text, caller_files=(("vars/more.yml", hidden),))
                roles = make_pair(Path(tmp), pair)
                (roles[0] / "caller" / "tasks" / "link").symlink_to(
                    "../vars", target_is_directory=True
                )
                problems = composition_problems(roles)
                self.assertEqual(1, len(problems), problems)
                self.assertIn("include_tasks names a file that is not a literal path", problems[0])

    def test_an_include_through_a_linked_directory_inside_the_scan_is_read(self) -> None:
        # The control of the case above: tasks/link points at tasks/sub, which the scan reads,
        # so the same import is found there and a link is not refused for being a link.
        hidden = "---\n- name: Hide\n  ansible.builtin.import_role:\n    name: third\n"
        text = CALL + "- name: Borrow\n  ansible.builtin.include_tasks: link/more.yml\n"
        with tempfile.TemporaryDirectory() as tmp:
            pair = Pair(call=text, caller_files=(("tasks/sub/more.yml", hidden),))
            roles = make_pair(Path(tmp), pair)
            (roles[0] / "caller" / "tasks" / "link").symlink_to("sub", target_is_directory=True)
            self.assertEqual(
                ["roles/caller (tasks/sub/more.yml): import_role is never used to compose roles"],
                composition_problems(roles),
            )

    def test_a_var_given_by_a_block_round_the_call_is_checked(self) -> None:
        # The call gives what the blocks round it give, as well as its own vars. The same key on
        # the task is reported by the test above, so this is that report through a block.
        for section in ("block", "rescue", "always"):
            text = blocked("not_declared_anywhere", section)
            with self.subTest(section=section):
                self.assertEqual(
                    [
                        "roles/caller (tasks/main.yml): the call gives input(s) "
                        "['not_declared_anywhere'] that the entry point read of capability "
                        "does not declare"
                    ],
                    problems_of(Pair(call=text)),
                )

    def test_a_var_given_by_two_blocks_round_the_call_is_checked(self) -> None:
        text = (
            "---\n- name: Outer\n  vars:\n    not_declared_anywhere: 1\n  block:\n"
            "    - name: Inner\n      vars:\n        cap_extra: y\n      block:\n"
            "        - name: Call\n          ansible.builtin.include_role:\n"
            "            name: '{{ caller_cap_role }}'\n            tasks_from: read\n"
            "          vars:\n            cap_items: [x]\n"
        )
        problems = problems_of(Pair(call=text))
        self.assertEqual(1, len(problems), problems)
        self.assertIn("['not_declared_anywhere']", problems[0])

    def test_a_declared_var_given_by_a_block_is_not_reported_and_counts_as_given(self) -> None:
        # The controls of the two cases above: a declared optional input is passed on, and a
        # required input given by the block alone is given.
        self.assertEqual([], problems_of(Pair(call=blocked("cap_extra"))))
        by_block = blocked("cap_items").replace("      vars:\n        cap_items: [x]\n", "")
        self.assertEqual([], problems_of(Pair(call=by_block)))

    def test_a_var_given_by_an_include_above_the_call_is_checked(self) -> None:
        # The call is in tasks/_call.yml and the vars are on the include of that file, at one
        # level, at two, and in a file that includes itself (which must end).
        on = "- name: On\n  ansible.builtin.include_tasks: _call.yml\n"
        again = "---\n- name: Again\n  ansible.builtin.include_tasks: _again.yml\n" + on
        starts = {
            "one": ("_call.yml", ()),
            "two": ("_mid.yml", (("tasks/_mid.yml", "---\n" + on),)),
            "self": ("_again.yml", (("tasks/_again.yml", again),)),
        }
        for label, (target, others) in starts.items():
            files = (("tasks/_call.yml", CALL), *others)
            with self.subTest(label=label):
                self.assertEqual(
                    [
                        "roles/caller (tasks/_call.yml): the call gives input(s) "
                        "['not_declared_anywhere'] that the entry point read of capability "
                        "does not declare"
                    ],
                    problems_of(Pair(call=go(target, "not_declared_anywhere"), caller_files=files)),
                )
                self.assertEqual(
                    [], problems_of(Pair(call=go(target, "cap_extra"), caller_files=files))
                )

    def test_the_legacy_spellings_of_an_include_are_seen(self) -> None:
        # The module word of action and local_action, and the key=value form of the include.
        outside = CALL + "- name: Borrow\n  action: include_tasks ../capability/tasks/read.yml\n"
        bare = (
            "---\n- name: Call\n  local_action: include_role name=capability tasks_from=read\n"
            "  vars:\n    cap_items: [x]\n"
        )
        own = CALL + "- name: Own\n  action: include_tasks _check.yml\n"
        self.assertEqual(1, len(problems_of(Pair(call=outside))))
        self.assertEqual(
            [
                "roles/caller (tasks/main.yml): capability is named bare, "
                "not by a path built from role_path"
            ],
            problems_of(Pair(call=bare)),
        )
        self.assertEqual(
            [], problems_of(Pair(call=own, caller_files=(("tasks/_check.yml", "---\n[]\n"),)))
        )

    def test_the_legacy_mapping_form_of_an_include_is_seen(self) -> None:
        text = (
            "---\n- name: Call\n  action:\n    module: ansible.builtin.import_role\n"
            "    name: capability\n"
        )
        self.assertEqual(
            ["roles/caller (tasks/main.yml): import_role is never used to compose roles"],
            problems_of(Pair(call=text)),
        )

    def test_a_role_that_calls_no_role_is_not_reported_and_needs_no_citation(self) -> None:
        text = "---\n- name: Say\n  ansible.builtin.debug:\n    msg: x\n"
        with tempfile.TemporaryDirectory() as tmp:
            roles = make_pair(Path(tmp), Pair(call=text))
            self.assertEqual([], composition_problems(roles))
            self.assertEqual({}, including_roles(roles))


class OptionalDefaultTest(unittest.TestCase):
    """ANS-12: every option that is not ``required: true`` has a ``default`` in the spec.

    An input includes an option of a list element or of a dictionary, at any depth. A
    ``default`` key counts whatever its value.
    """

    def test_an_option_with_no_default_is_reported_wherever_it_is(self) -> None:
        # One option without a default in each case, at a different depth and with a different
        # name, so a report that finds only one place or one name cannot pass them all.
        cases = {
            "top level": (
                SPEC_HEAD + ITEMS + "      cap_extra:\n        type: str\n",
                ["cap_extra"],
            ),
            "another name": (
                SPEC_HEAD + ITEMS + "      cap_other:\n        type: bool\n",
                ["cap_other"],
            ),
            "required false": (
                SPEC_HEAD
                + ITEMS
                + "      cap_extra:\n        type: str\n        required: false\n",
                ["cap_extra"],
            ),
            "list element": (
                SPEC_HEAD + ELEMENT_ITEMS + "          mode:\n            type: str\n",
                ["cap_items[].mode"],
            ),
            "list element, another name": (
                SPEC_HEAD
                + ELEMENT_ITEMS
                + "          mode:\n            type: str\n            default: x\n"
                + "          flag:\n            type: bool\n",
                ["cap_items[].flag"],
            ),
            "dictionary": (
                SPEC_HEAD
                + ITEMS
                + "      cap_group:\n        type: dict\n        default: {}\n        options:\n"
                + "          mode:\n            type: str\n",
                ["cap_group.mode"],
            ),
            "dictionary in a list element": (
                SPEC_HEAD
                + ELEMENT_ITEMS
                + "          extra:\n            type: dict\n            default: {}\n"
                + "            options:\n              level:\n                type: int\n",
                ["cap_items[].extra.level"],
            ),
            "an option that is not a mapping": (
                SPEC_HEAD + ITEMS + "      cap_extra:\n",
                ["cap_extra"],
            ),
        }
        for label, (specs, paths) in cases.items():
            with self.subTest(label=label):
                self.assertEqual(no_default(*paths), problems_of(Pair(specs=specs)))

    def test_every_option_without_a_default_is_named_in_the_order_of_the_spec(self) -> None:
        specs = (
            SPEC_HEAD
            + ELEMENT_ITEMS
            + "          mode:\n            type: str\n"
            + "      cap_extra:\n        type: str\n"
        )
        self.assertEqual(
            no_default("cap_items[].mode", "cap_extra"), problems_of(Pair(specs=specs))
        )

    def test_a_default_only_in_the_roles_defaults_does_not_count(self) -> None:
        # The case ANS-12 names: the role runs with cap_extra = x, and the spec does not say so.
        specs = SPEC_HEAD + ITEMS + "      cap_extra:\n        type: str\n"
        files = (("defaults/main.yml", "---\ncap_extra: x\n"),)
        self.assertEqual(
            no_default("cap_extra"), problems_of(Pair(specs=specs, callee_files=files))
        )

    def test_a_default_in_the_callers_vars_or_in_the_call_does_not_count(self) -> None:
        # The caller giving the option is a different thing: it is passed on, and the spec
        # still declares no default for a caller who leaves it out.
        specs = SPEC_HEAD + ITEMS + "      cap_extra:\n        type: str\n"
        text = CALL.replace("cap_items: [x]", "cap_items: [x]\n    cap_extra: y")
        self.assertEqual(
            no_default("cap_extra"),
            problems_of(Pair(call=text, specs=specs, caller_vars=CALLER_VARS + "cap_extra: z\n")),
        )

    def test_a_default_key_counts_whatever_its_value(self) -> None:
        # false, 0, an empty string, an empty mapping and null are all declared defaults. A test
        # of the value for truth reports the first four, and a test of the key's value being
        # not None reports the last.
        for value in ("false", "0", "''", "{}", "null", "~"):
            specs = (
                SPEC_HEAD
                + ITEMS
                + f"      cap_extra:\n        type: str\n        default: {value}\n"
            )
            with self.subTest(value=value):
                self.assertEqual([], problems_of(Pair(specs=specs)))

    def test_a_default_that_is_an_empty_key_is_a_declared_null(self) -> None:
        specs = SPEC_HEAD + ITEMS + "      cap_extra:\n        type: str\n        default:\n"
        self.assertEqual([], problems_of(Pair(specs=specs)))

    def test_a_default_key_counts_in_a_list_element_and_a_dictionary(self) -> None:
        elements = (
            SPEC_HEAD
            + ELEMENT_ITEMS
            + "          mode:\n            type: str\n            default: null\n"
            + "          flag:\n            type: bool\n            default: false\n"
            + "          extra:\n            type: dict\n            default: {}\n"
            + "            options:\n              level:\n                type: int\n"
            + "                default: 0\n"
        )
        self.assertEqual([], problems_of(Pair(specs=elements)))

    def test_a_required_option_needs_no_default_at_any_depth(self) -> None:
        specs = (
            SPEC_HEAD
            + ELEMENT_ITEMS
            + "          extra:\n            type: dict\n            required: true\n"
            + "            options:\n              level:\n                type: int\n"
            + "                required: true\n"
        )
        self.assertEqual([], problems_of(Pair(specs=specs)))

    def test_only_the_entry_point_the_call_names_is_read(self) -> None:
        # The limit the README names: another entry point of the same role, never called, is
        # not checked.
        other = "  other:\n    short_description: Other\n    options:\n"
        self.assertEqual(
            [], problems_of(Pair(specs=SPECS + other + "      cap_x:\n        type: str\n"))
        )

    def test_the_optional_options_of_the_real_restart_stamp_are_seen_and_all_have_a_default(
        self,
    ) -> None:
        # The control of the real-tree test above: a clean result means something only if the
        # walk finds the options that are there. They are the three flags of a class of
        # `decide`, all inside a list element, and `drift` and `adoptable` default to false.
        file = ROOT / "ansible" / "roles" / "restart_stamp" / "meta" / "argument_specs.yml"
        entries = list(role_tasks.mapping_at(file, "argument_specs"))
        options_of = {
            entry: role_tasks.mapping_at(file, "argument_specs", str(entry), "options")
            for entry in entries
        }
        optional = {
            entry: [
                path
                for path, spec in role_tasks.option_specs(options)
                if isinstance(spec, Mapping) and spec.get("required") is not True
            ]
            for entry, options in options_of.items()
        }
        self.assertEqual(
            {
                "read": [],
                "decide": [
                    "restart_stamp_classes[].drift",
                    "restart_stamp_classes[].adoptable",
                    "restart_stamp_classes[].gate",
                ],
                "mark_pending": [],
                "adopt": [],
                "record": [],
            },
            optional,
        )
        for entry, options in options_of.items():
            with self.subTest(entry=entry):
                self.assertEqual([], role_tasks.options_without_default(options))


class OptionPredicateTest(unittest.TestCase):
    """The words of ANS-12 as one function in role_tasks: the walk and the default."""

    def test_the_walk_names_a_list_element_and_a_dictionary_differently(self) -> None:
        options = {
            "a": {"type": "list", "options": {"b": {"type": "dict", "options": {"c": {}}}}},
            "d": {"type": "dict", "options": {"e": {"type": "list", "options": {"f": {}}}}},
        }
        self.assertEqual(
            ["a", "a[].b", "a[].b.c", "d", "d.e", "d.e[].f"],
            [path for path, _ in role_tasks.option_specs(options)],
        )

    def test_the_walk_of_something_that_is_not_options_yields_nothing(self) -> None:
        not_options: tuple[object, ...] = (None, [], "x", 3)
        for options in not_options:
            with self.subTest(options=options):
                self.assertEqual([], list(role_tasks.option_specs(options)))
                self.assertEqual([], role_tasks.options_without_default(options))

    def test_a_default_key_is_a_default_whatever_it_holds(self) -> None:
        values: tuple[object, ...] = (False, 0, "", None, [], {}, True, 1)
        for value in values:
            options = {"a": {"type": "str", "default": value}}
            with self.subTest(value=value):
                self.assertEqual([], role_tasks.options_without_default(options))

    def test_an_option_with_neither_required_nor_default_is_reported(self) -> None:
        options: dict[str, object] = {
            "a": {"type": "str"},
            "b": {"type": "str", "required": False},
            "c": {"type": "str", "required": "true"},
            "d": {"type": "str", "required": True},
            "e": {"type": "str", "default": None},
            "f": None,
            "g": {"type": "dict", "default": {}, "options": {"h": {"type": "str"}}},
        }
        self.assertEqual(["a", "b", "c", "f", "g.h"], role_tasks.options_without_default(options))

    def test_a_required_parent_does_not_excuse_its_optional_children(self) -> None:
        options = {"a": {"type": "list", "required": True, "options": {"b": {"type": "str"}}}}
        self.assertEqual(["a[].b"], role_tasks.options_without_default(options))


class OneReaderTest(unittest.TestCase):
    def test_a_role_yaml_file_is_read_as_a_mapping_in_one_place(self) -> None:
        # The step is written once, in role_tasks, and the other checks call it: a second
        # copy drifts, and a duplicate blocks a merge (ws#2439).
        self.assertIs(role_tasks.mapping_at, vars(role_composition)["mapping_at"])
        self.assertIn("mapping_at(", inspect.getsource(role_tasks.role_vars))
        checks = Path(__file__).resolve().parent
        for module in ("role_composition.py", "amendment_citation.py"):
            source = (checks / module).read_text(encoding="utf-8")
            with self.subTest(module=module):
                self.assertNotIn("YAML_LOADER", source)
                self.assertNotIn("YAML(", source)


class CitationTest(unittest.TestCase):
    def test_the_merged_amendment_is_accepted(self) -> None:
        # The positive control of every case below: all of them differ from this by one thing.
        self.assertEqual([], citation_problems(line(154, MERGED_SHA), api_with(AMENDED)))

    def test_a_merged_pull_request_that_is_not_the_amendment_is_refused(self) -> None:
        # The real pull request 154 and the ANS-12 text as it was before: a merge exists, and
        # the clause still holds the named limit and no rule.
        problems = citation_problems(line(154, MERGED_SHA), api_with(BEFORE))
        self.assertEqual(
            [
                "ANS-12 at the cited commit still carries the named limit it was to close",
                "ANS-12 at the cited commit does not state the capability-role rule",
            ],
            problems,
        )

    def test_a_clause_that_keeps_the_named_limit_beside_the_rule_is_refused(self) -> None:
        self.assertEqual(
            ["ANS-12 at the cited commit still carries the named limit it was to close"],
            citation_problems(line(154, MERGED_SHA), api_with(RULE_BUT_LIMIT_KEPT)),
        )

    def test_a_clause_that_drops_the_limit_and_states_no_rule_is_refused(self) -> None:
        self.assertEqual(
            ["ANS-12 at the cited commit does not state the capability-role rule"],
            citation_problems(line(154, MERGED_SHA), api_with(LIMIT_GONE_NO_RULE)),
        )

    def test_a_document_with_no_ans12_section_is_refused(self) -> None:
        self.assertEqual(
            ["docs/stacks/ansible.md at the cited commit has no ANS-12 section"],
            citation_problems(line(154, MERGED_SHA), api_with(NO_SECTION)),
        )

    def test_the_limit_is_found_across_a_line_break(self) -> None:
        # The clause wraps its lines; the sentence is searched with its whitespace collapsed.
        self.assertIn("still carries", " ".join(amendment_problems(BEFORE)))

    def test_an_open_pull_request_is_refused_though_its_merge_commit_is_cited(self) -> None:
        # What the API returns for an open pull request: merged false and a test-merge commit
        # that is not null. Cited with that commit, only the merged assertion can refuse it.
        self.assertEqual(
            ["standards pull request 155 is not merged"],
            citation_problems(line(155, OPEN_SHA), api_with(AMENDED, OPEN)),
        )

    def test_a_merged_pull_request_cited_with_another_commit_is_refused(self) -> None:
        api = FakeApi({154: MERGED}, {OTHER_SHA: AMENDED})
        self.assertEqual(
            [f"{OTHER_SHA} is not the merge commit of standards pull request 154"],
            citation_problems(line(154, OTHER_SHA), api),
        )

    def test_a_pull_request_merged_into_another_branch_is_refused(self) -> None:
        # The real response of 154 with the base changed, the only field that differs.
        elsewhere = copy.deepcopy(MERGED)
        elsewhere["base"] = {"ref": "release"}
        self.assertEqual(
            ["standards pull request 154 was not merged into main"],
            citation_problems(line(154, MERGED_SHA), api_with(AMENDED, elsewhere)),
        )

    def test_a_pull_request_with_no_base_is_refused(self) -> None:
        bare = {key: value for key, value in MERGED.items() if key != "base"}
        self.assertEqual(
            ["standards pull request 154 was not merged into main"],
            citation_problems(line(154, MERGED_SHA), api_with(AMENDED, bare)),
        )

    def test_a_citation_that_is_not_a_merged_standards_pull_request_is_refused(self) -> None:
        wrong = (
            "https://github.com/branchLeft/standards/pull/154\n",
            f"https://github.com/branchLeft/shared-infra/pull/154 merged {MERGED_SHA}\n",
            "https://github.com/branchLeft/standards/pull/154 merged abc123\n",
            "TBD\n",
            "",
        )
        for text in wrong:
            with self.subTest(text=text):
                self.assertEqual(
                    ["the citation is malformed"], citation_problems(text, api_with(AMENDED))
                )

    def test_a_pull_request_the_repository_does_not_have_is_a_failed_lookup(self) -> None:
        # The fixture of the old test, standards 155 and a made-up commit: refused by the
        # lookup, not matched by its shape.
        with self.assertRaises(StandardsReadError):
            citation_problems(line(155, "a" * 40), FakeApi({}, {}))


class LookupPolicyTest(unittest.TestCase):
    def gate(self, in_ci: bool) -> tuple[list[str], str | None]:
        with tempfile.TemporaryDirectory() as tmp:
            roles = make_pair(Path(tmp), Pair())
            citation = Path(tmp) / "citation.txt"
            citation.write_text(line(154, MERGED_SHA), encoding="utf-8")
            return run_gate(roles, citation, FakeApi({}, {}), in_ci)

    def test_a_lookup_that_fails_in_ci_is_a_problem(self) -> None:
        problems, skipped = self.gate(in_ci=True)
        self.assertIsNone(skipped)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("could not be read in CI", problems[0])

    def test_a_lookup_that_fails_outside_ci_is_skipped_with_its_reason(self) -> None:
        problems, skipped = self.gate(in_ci=False)
        self.assertEqual([], problems)
        self.assertIn("so the citation is not checked", skipped or "")

    def test_a_lookup_that_succeeds_is_checked_in_both(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            roles = make_pair(Path(tmp), Pair())
            citation = Path(tmp) / "citation.txt"
            citation.write_text(line(155, OPEN_SHA), encoding="utf-8")
            api = api_with(AMENDED, OPEN)
            for in_ci in (True, False):
                with self.subTest(in_ci=in_ci):
                    problems, skipped = run_gate(roles, citation, api, in_ci)
                    self.assertIsNone(skipped)
                    self.assertEqual(1, len(problems), problems)
                    self.assertIn("standards pull request 155 is not merged", problems[0])


class HttpClientTest(unittest.TestCase):
    def test_a_transport_error_is_tried_again_once(self) -> None:
        body = json.dumps(MERGED).encode()
        api, seen = api_over([OSError("reset"), StubResponse(200, body)])
        self.assertEqual(154, api.pull(154)["number"])
        self.assertEqual(2, len(seen))

    def test_two_transport_errors_are_a_failed_lookup(self) -> None:
        api, seen = api_over([OSError("reset"), OSError("reset")])
        with self.assertRaises(StandardsReadError):
            api.pull(154)
        self.assertEqual(2, len(seen))

    def test_a_server_error_is_tried_again_once(self) -> None:
        body = json.dumps(MERGED).encode()
        api, seen = api_over([StubResponse(502, b""), StubResponse(200, body)])
        self.assertEqual(154, api.pull(154)["number"])
        self.assertEqual(2, len(seen))

    def test_a_refusal_is_not_tried_again(self) -> None:
        api, seen = api_over([StubResponse(403, b"{}"), StubResponse(200, b"{}")])
        with self.assertRaises(StandardsReadError) as caught:
            api.pull(154)
        self.assertEqual(1, len(seen))
        self.assertIn("HTTP 403", str(caught.exception))

    def test_the_token_is_sent_in_a_header_and_never_named_in_an_error(self) -> None:
        api, seen = api_over([StubResponse(404, b"{}")], "value-of-the-credential")
        with self.assertRaises(StandardsReadError) as caught:
            api.pull(154)
        self.assertEqual("Bearer value-of-the-credential", seen[0]["Authorization"])
        self.assertNotIn("value-of-the-credential", str(caught.exception))
        self.assertNotIn("value-of-the-credential", seen[0]["url"])

    def test_no_token_sends_no_authorization_header(self) -> None:
        api, seen = api_over([StubResponse(404, b"{}")], None)
        with self.assertRaises(StandardsReadError):
            api.pull(154)
        self.assertNotIn("Authorization", seen[0])

    def test_a_body_that_is_not_a_json_object_is_a_failed_lookup(self) -> None:
        for body in (b"not json", b"[]"):
            api, _ = api_over([StubResponse(200, body)])
            with self.subTest(body=body), self.assertRaises(StandardsReadError):
                api.pull(154)

    def test_the_file_is_read_at_the_cited_commit_as_raw_text(self) -> None:
        api, seen = api_over([StubResponse(200, "ANS-12 — text".encode())])
        self.assertEqual("ANS-12 — text", api.file_at(MERGED_SHA, "docs/stacks/ansible.md"))
        self.assertEqual(
            f"/repos/branchLeft/standards/contents/docs/stacks/ansible.md?ref={MERGED_SHA}",
            seen[0]["url"],
        )
        self.assertEqual("application/vnd.github.raw+json", seen[0]["Accept"])


if __name__ == "__main__":
    unittest.main()
