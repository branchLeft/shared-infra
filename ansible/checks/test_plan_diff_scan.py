"""A file a role copies whole must not trip the plan's secret scan, or it has no approvable plan.

This module holds the scan's `credential-assignment` pattern as a constant and fails when a task
the playbooks reach copies a file with a matching line and does not set `diff: false`, or sets it
over a file that does not match. See README.md, "test_plan_diff_scan.py".
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]

# The credential-assignment pattern of the plan's scan (see the module docstring).
CREDENTIAL_ASSIGNMENT = re.compile(
    r"(passw(or)?d|passphrase|secret|token|api[_-]?key|private[_-]?key|credential)"
    r'[A-Za-z0-9_.-]*"?\s*[:=]\s*"?[^\s"]{4,}',
    re.IGNORECASE | re.ASCII,
)
# The same pattern as the workflow writes it, kept to prove the translation against grep itself.
WORKFLOW_ERE = (
    "(passw(or)?d|passphrase|secret|token|api[_-]?key|private[_-]?key|credential)"
    '[A-Za-z0-9_.-]*"?[[:space:]]*[:=][[:space:]]*"?[^[:space:]"]{4,}'
)
COPIERS = frozenset(("copy", "template"))
INCLUDERS = frozenset(("include_tasks", "import_tasks"))
SEARCH = {
    "copy": ("files", "templates", ".", "tasks"),
    "template": ("templates", "files", ".", "tasks"),
}
EXPRESSION = re.compile(r"\{\{\s*([A-Za-z_]\w*)((?:\.\w+|\[['\"]\w+['\"]\])*)\s*\}\}")
PIPELINE = re.compile(r"\{\{\s*([A-Za-z_]\w*)((?:\s*\|\s*\w+(?:\([^()]*\))?)+)\s*\}\}")
STAGE = re.compile(r"\|\s*(\w+)(?:\(([^()]*)\))?")
DEPTH = 6

Env = dict[str, object]
Finding = tuple[str, str, str]


def matching_lines(text: str) -> list[int]:
    """Return the 1-based number of each line of ``text`` the scan matches.

    grep splits its input on the newline alone, so this does too: str.splitlines also splits on
    form feeds and other separators, which would move a match to another line.
    """
    return [n for n, line in enumerate(text.split("\n"), 1) if CREDENTIAL_ASSIGNMENT.search(line)]


def _evaluate(expression: re.Match[str], env: Env, depth: int) -> object:
    """Return what a `{{ name.key }}` expression stands for in ``env``, or None if unknown."""
    value = env.get(expression[1])
    for attribute in re.findall(r"\w+", expression[2]):
        value = value.get(attribute) if isinstance(value, dict) else None
    if isinstance(value, str) and depth:
        return render(value, env, depth - 1)
    return value


def render(text: str, env: Env, depth: int = DEPTH) -> str:
    """Replace each `{{ name }}` whose value is plain text in ``env``; leave the rest."""

    def one(expression: re.Match[str]) -> str:
        value = _evaluate(expression, env, depth)
        return value if isinstance(value, str) else expression[0]

    return EXPRESSION.sub(one, text)


def _filtered(text: str, env: Env) -> object:
    """Return the list a `{{ name | filter(...) | ... }}` loop stands for, else ``text``.

    Only the filters a split loop needs are understood: intersect(name), difference(name),
    selectattr('attr', 'in', name), rejectattr('attr', 'in', name) and list. Any other filter, or a
    name that is not a list, leaves the text as it was, so the loop is unresolved and is a finding.
    """
    whole = PIPELINE.fullmatch(text.strip())
    if whole is None:
        return text
    current = value_of("{{ " + whole[1] + " }}", env)
    for stage in STAGE.finditer(whole[2]):
        name = stage[1]
        arguments = [part.strip().strip("'\"") for part in (stage[2] or "").split(",")]
        if not isinstance(current, list):
            return text
        if name == "list":
            continue
        if name in ("intersect", "difference") and len(arguments) == 1:
            other = value_of("{{ " + arguments[0] + " }}", env)
            if not isinstance(other, list):
                return text
            keep = name == "intersect"
            current = [item for item in current if (item in other) == keep]
        elif name in ("selectattr", "rejectattr") and len(arguments) == 3 and arguments[1] == "in":
            other = value_of("{{ " + arguments[2] + " }}", env)
            if not isinstance(other, list):
                return text
            keep = name == "selectattr"
            current = [
                item
                for item in current
                if isinstance(item, dict) and (item.get(arguments[0]) in other) == keep
            ]
        else:
            return text
    return current


def value_of(text: object, env: Env) -> object:
    """Return the list or mapping a lone `{{ name }}` stands for, else the rendered text."""
    if isinstance(text, str):
        whole = EXPRESSION.fullmatch(text.strip())
        if whole:
            value = _evaluate(whole, env, DEPTH)
            return text if value is None else value
        if PIPELINE.fullmatch(text.strip()):
            return _filtered(text, env)
        return render(text, env)
    return text


def edge_stack_deliver(env: Env) -> list[str] | None:
    """Return the files the edge_stack role delivers by copy, or None when they cannot be named.

    The role makes the list while it runs (tasks/_classify.yml): the static CrowdSec files of its
    vars, then every regular file directly in the acquisition directory of the stack directory,
    found on the controller by a `find` with delegate_to: localhost. The stack directory is in the
    checkout, so the same list is made here.
    """
    static = env.get("edge_stack_crowdsec_files")
    source = env.get("edge_stack_source_dir")
    acquis = env.get("edge_stack_acquis_dir")
    if not (isinstance(static, list) and isinstance(source, str) and isinstance(acquis, str)):
        return None
    directory = Path(render(source, env)) / acquis
    if not directory.is_dir():
        return None
    found = sorted(entry.name for entry in directory.iterdir() if entry.is_file())
    return [str(item) for item in static] + [f"{acquis}/{name}" for name in found]


# Per role, a list it makes while it runs and the function that makes the same list from the
# checkout. A role not named here has only the lists its defaults/ and vars/ set.
DERIVED_LISTS = {"edge_stack": ("edge_stack_deliver", edge_stack_deliver)}


def role_variables(role: Path) -> Env:
    """Return every variable the role's defaults/ and vars/ set, whatever its type."""
    found: Env = {}
    for directory in ("defaults", "vars"):
        for path in sorted((role / directory).rglob("*.y*ml")):
            document, _problem = load_yaml(path)
            if isinstance(document, dict):
                found.update({str(k): v for k, v in document.items()})
    return found


def _task_lists(node: object) -> Iterator[tuple[dict[str, object], bool]]:
    """Yield each task under ``node`` and whether a block around it already sets diff: false."""
    if isinstance(node, list):
        for item in node:
            yield from _task_lists(item)
    elif isinstance(node, dict):
        blocks = [node[key] for key in ("block", "rescue", "always") if key in node]
        if blocks:
            for inner in blocks:
                for task, off in _task_lists(inner):
                    yield task, off or node.get("diff") is False
        else:
            yield node, False


def _module_args(task: dict[str, object], modules: frozenset[str]) -> tuple[str, object] | None:
    """Return the (short module name, arguments) of the task if it uses one of ``modules``."""
    for key, value in task.items():
        module = str(key).rsplit(".", 1)[-1]
        if module in modules:
            return module, value
    return None


def tasks_of(role: Path) -> Iterator[tuple[Path, dict[str, object], bool]]:
    """Yield (file, task, diff_is_off) for each task under the role's tasks/ directory."""
    for path in sorted((role / "tasks").rglob("*.y*ml")):
        document, _problem = load_yaml(path)
        for task, inherited in _task_lists(document):
            yield path, task, inherited or task.get("diff") is False


def named_roles(playbooks: Path) -> list[str]:
    """Return the name of each role the playbooks in ``playbooks`` list under `roles:`."""
    names: set[str] = set()
    for path in sorted(playbooks.glob("*.yml")):
        document, _problem = load_yaml(path)
        for play in document if isinstance(document, list) else []:
            entries = play.get("roles", []) if isinstance(play, dict) else []
            for entry in entries if isinstance(entries, list) else []:
                value = entry.get("role", entry.get("name")) if isinstance(entry, dict) else entry
                if isinstance(value, str):
                    names.add(Path(value).name)
    return sorted(names)


def _loop_environments(task: dict[str, object], env: Env) -> list[Env]:
    """Return ``env`` once per item of the task's loop (once, unchanged, when it has none)."""
    spec = task.get("loop", task.get("with_items"))
    if spec is None:
        return [env]
    control = task.get("loop_control")
    name = control.get("loop_var", "item") if isinstance(control, dict) else "item"
    items = value_of(spec, env)
    if not isinstance(items, list):
        return [{**env, str(name): None}]
    return [{**env, str(name): value_of(item, env)} for item in items]


def _including_environments(role: Path, path: Path, env: Env) -> list[Env]:
    """Return the environments a task file runs in: one per include that names it, or ``env``."""
    found: list[Env] = []
    for _other, task, _off in tasks_of(role):
        included = _module_args(task, INCLUDERS)
        if included is None:
            continue
        arguments = included[1]
        target = arguments.get("file") if isinstance(arguments, dict) else arguments
        if not isinstance(target, str) or Path(target).name != path.name:
            continue
        passed = task.get("vars")
        local: Env = {**env}
        if isinstance(passed, dict):
            local.update({str(k): value_of(v, env) for k, v in passed.items()})
        found.extend(_loop_environments(task, local))
    return found or [env]


def _source_files(role: Path, module: str, text: str) -> list[Path]:
    """Return the files a rendered `src` names: one file, or every file under a directory."""
    given = Path(text)
    candidates = (
        [given] if given.is_absolute() else [role / folder / text for folder in SEARCH[module]]
    )
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_dir():
            return sorted(path for path in resolved.rglob("*") if path.is_file())
        if resolved.is_file():
            return [resolved]
    return []


def findings_for(root: Path) -> tuple[list[Finding], list[str]]:
    """Return (findings, scanned): the unsafe tasks, and each source file that was read.

    A task that sets diff: false is still resolved and read, so a pass shows the walk reached
    the file. It hides every file it copies, so each of those files must have a matching line: a
    file without one is a finding, and the loop is split into a hidden task and a visible one. A
    task that sets no_log renders a secret and is not held to that (see below).
    """
    roles_dir = root / "ansible" / "roles"
    every = {role.name: role_variables(role) for role in sorted(roles_dir.glob("*"))}
    fallback = {k: v for variables in every.values() for k, v in variables.items()}
    findings: set[Finding] = set()
    scanned: list[str] = []
    for name in named_roles(root / "ansible" / "playbooks"):
        role = roles_dir / name
        base: Env = {**fallback, **every[name], "role_path": str(role)}
        if name in DERIVED_LISTS:
            variable, derive = DERIVED_LISTS[name]
            made = derive(base)
            if made is not None:
                base[variable] = made
        for path, task, diff_is_off in tasks_of(role):
            used = _module_args(task, COPIERS)
            args = used[1] if used else None
            if used is None or not isinstance(args, dict):
                continue
            src = args.get("src")
            if "content" in args or args.get("remote_src") or not isinstance(src, str):
                continue
            where = (str(path.relative_to(root)), str(task.get("name", "(unnamed)")))
            # A task with no_log renders a secret into the file (ANS-16): its diff is hidden for
            # what the file becomes, not for a line of its source, so a source without a
            # matching line is expected there.
            carries_secret = task.get("no_log") not in (None, False, "false")
            for outer in _including_environments(role, path, base):
                for env in _loop_environments(task, outer):
                    text = render(src, env)
                    sources = [] if "{{" in text else _source_files(role, used[0], text)
                    if not sources and not diff_is_off:
                        findings.add((*where, "reads a source the check cannot find or resolve"))
                    for source in sources:
                        shown = source.relative_to(root) if source.is_relative_to(root) else source
                        scanned.append(f"{name}:{shown}")
                        lines = matching_lines(source.read_text(encoding="utf-8", errors="replace"))
                        if lines and not diff_is_off:
                            message = (
                                f"copies {shown}, whose line {lines[0]} matches the plan's "
                                "secret scan, and sets no diff: false"
                            )
                            findings.add((*where, message))
                        elif diff_is_off and not lines and not carries_secret:
                            message = (
                                f"sets diff: false but copies {shown}, which has no matching "
                                "line, so its diff is hidden for nothing: split the loop"
                            )
                            findings.add((*where, message))
    return sorted(findings), scanned


class RegexCase(unittest.TestCase):
    """The scan's pattern, as translated, matches what the workflow's grep matches."""

    SAMPLES = (
        'password: "abcd1234"',
        "api_key=abcdef",
        "    secret:   hunter2",
        "CONTACT_SMTP_PASSWORD: ${CONTACT_SMTP_PASSWORD:?set it}",
        "the authenticating credential: ExposeAuthInfo writes it",
        "TOKEN = 'xyz12'",
        'credentials_file":"/etc/x"',
        "password: abc",
        "a secret is never printed",
        "token",
        "tokens are listed here: abcdef",
        "private-key:\tvalue1",
        "sshd can expose the authenticating credential. ExposeAuthInfo writes the key",
        "      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD:?set it in the env file}",
        "NO_RATE_TOKENS = frozenset(('', 'none'))",
        "this is the exporter's login, because the exporter expands a value",
    )

    # One line of each kind, with whether the scan must match it: prose that reads as a secret,
    # a variable reference that cannot be reworded, a prose line reworded so it no longer reads
    # as a secret, and a line with no secret word at all.
    KINDS = (
        ("prose that matches", "the authenticating credential: ExposeAuthInfo writes it", True),
        ("variable reference", "MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD:?set it}", True),
        ("prose reworded", "the authenticating credential. ExposeAuthInfo writes it", False),
        ("no secret word", "image: docker.io/library/postgres:17-alpine", False),
    )

    def test_each_kind_of_line_is_classed(self) -> None:
        """Prose and variable references match, reworded prose and plain lines do not."""
        for kind, line, expected in self.KINDS:
            with self.subTest(kind=kind):
                self.assertEqual(bool(CREDENTIAL_ASSIGNMENT.search(line)), expected)

    def test_lines_are_split_on_newline_only(self) -> None:
        """A form feed is not a line break to grep, so it does not move a match to a later line."""
        text = "a\nb\x0cpassword: abcd1234\nc\n"
        self.assertEqual(matching_lines(text), [2])
        self.assertEqual(len(text.splitlines()), 4)

    def test_known_lines_match_or_do_not(self) -> None:
        """Lines of each kind the scan is known to hit or to pass are classed so."""
        self.assertTrue(CREDENTIAL_ASSIGNMENT.search('password: "abcd1234"'))
        self.assertTrue(CREDENTIAL_ASSIGNMENT.search("CONTACT_SMTP_PASSWORD: ${CONTACT_SMTP:?x}"))
        self.assertTrue(CREDENTIAL_ASSIGNMENT.search("the authenticating credential: Expose"))
        self.assertFalse(CREDENTIAL_ASSIGNMENT.search("password: abc"))
        self.assertFalse(CREDENTIAL_ASSIGNMENT.search("a secret is never printed"))

    @unittest.skipUnless(shutil.which("grep"), "grep is needed to compare the translation")
    def test_translation_agrees_with_grep(self) -> None:
        """Each sample line is matched by the Python pattern exactly when grep matches it."""
        for line in self.SAMPLES:
            result = subprocess.run(  # noqa: S603
                [shutil.which("grep") or "grep", "-Eiq", "-e", WORKFLOW_ERE],
                input=line + "\n",
                text=True,
                env={"LC_ALL": "C"},
                check=False,
            )
            self.assertEqual(
                result.returncode == 0,
                bool(CREDENTIAL_ASSIGNMENT.search(line)),
                f"grep and the translation disagree on sample {self.SAMPLES.index(line)}",
            )


class TreeCase(unittest.TestCase):
    """A tree of one playbook and a role, so each way a copy can be unsafe is found."""

    DOCLINE = "# the authenticating credential: ExposeAuthInfo writes the key\n"

    def setUp(self) -> None:
        """Create the tree: a playbook naming role r, which has files/ and a tasks/ directory."""
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.role = self.root / "ansible" / "roles" / "r"
        (self.role / "tasks").mkdir(parents=True)
        (self.role / "files").mkdir()
        (self.root / "ansible" / "playbooks").mkdir()
        (self.root / "hetzner" / "provision").mkdir(parents=True)
        self.put(
            self.root / "ansible" / "playbooks" / "h.yml",
            "- hosts: all\n  roles:\n    - role: ../roles/r\n",
        )

    def put(self, path: Path, text: str) -> None:
        """Write ``text`` to ``path``."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def tasks(self, text: str) -> list[str]:
        """Write the role's tasks and return the findings as sentences."""
        self.put(self.role / "tasks" / "main.yml", text)
        return [f"{file}: task {name!r} {what}" for file, name, what in findings_for(self.root)[0]]

    def test_a_secret_like_file_without_diff_false_is_found_by_line(self) -> None:
        """The finding names the file and the line, and never the text of the line."""
        self.put(self.role / "files" / "p.py", "x = 1\n" + self.DOCLINE)
        found = self.tasks(
            "- name: Install p\n  ansible.builtin.copy:\n    src: p.py\n    dest: /usr/p.py\n"
        )
        self.assertEqual(len(found), 1)
        self.assertIn("files/p.py", found[0])
        self.assertIn("line 2", found[0])
        self.assertNotIn("ExposeAuthInfo", found[0])

    def test_diff_false_on_the_task_or_its_block_passes(self) -> None:
        """diff: false on the task, or on a block around it, is the control."""
        self.put(self.role / "files" / "p.py", self.DOCLINE)
        task = "ansible.builtin.copy:\n    src: p.py\n    dest: /usr/p.py\n"
        plain = "- name: a\n  " + task
        block = (
            "- block:\n    - name: a\n      ansible.builtin.copy:\n"
            "          src: p.py\n          dest: /x\n"
        )
        self.assertEqual(self.tasks(plain + "  diff: false\n"), [])
        self.assertEqual(self.tasks(block + "  diff: false\n"), [])
        self.assertEqual(len(self.tasks(block + "  diff: true\n")), 1)

    def test_no_log_alone_does_not_count(self) -> None:
        """no_log hides the result, not the diff, so it is not the control for the scan."""
        self.put(self.role / "files" / "p.py", self.DOCLINE)
        found = self.tasks(
            "- name: a\n  ansible.builtin.copy:\n    src: p.py\n    dest: /x\n  no_log: true\n"
        )
        self.assertEqual(len(found), 1)

    def test_a_clean_file_needs_no_diff_false(self) -> None:
        """A file with no matching line passes with the keyword absent."""
        self.put(self.role / "files" / "p.py", "x = 1\n")
        self.assertEqual(
            self.tasks("- name: a\n  ansible.builtin.copy:\n    src: p.py\n    dest: /x\n"), []
        )

    def test_inline_content_and_remote_sources_are_skipped(self) -> None:
        """Inline content has no file to read, and a remote source is on the host."""
        found = self.tasks(
            "- name: a\n  ansible.builtin.copy:\n    content: 'password: abcdefgh'\n    dest: /x\n"
            "- name: b\n  ansible.builtin.copy:\n    src: /etc/p\n    remote_src: true\n"
            "    dest: /y\n"
        )
        self.assertEqual(found, [])

    def test_a_template_is_read_from_templates(self) -> None:
        """A template task finds its source under templates/."""
        self.put(self.role / "templates" / "t.j2", "token = abcdefgh\n")
        found = self.tasks("- name: a\n  ansible.builtin.template:\n    src: t.j2\n    dest: /x\n")
        self.assertEqual(len(found), 1)
        self.assertIn("templates/t.j2", found[0])

    def test_a_source_reached_through_role_path_is_resolved(self) -> None:
        """The slot role's route, role_path/../../../hetzner/provision, is followed."""
        self.put(self.root / "hetzner" / "provision" / "p.py", self.DOCLINE)
        self.put(
            self.role / "vars" / "main.yml",
            "r_dir: '{{ role_path }}/../../../hetzner/provision'\n",
        )
        found = self.tasks(
            "- name: a\n  ansible.builtin.copy:\n    src: '{{ r_dir }}/p.py'\n    dest: /x\n"
        )
        self.assertEqual(len(found), 1)
        self.assertIn("hetzner/provision/p.py", found[0])

    def test_a_directory_source_is_read_whole(self) -> None:
        """A source that is a directory is judged by every file in it."""
        self.put(self.role / "files" / "d" / "a.txt", "fine\n")
        self.put(self.role / "files" / "d" / "b.txt", self.DOCLINE)
        found = self.tasks("- name: a\n  ansible.builtin.copy:\n    src: d/\n    dest: /x\n")
        self.assertEqual(len(found), 1)
        self.assertIn("d/b.txt", found[0])

    def test_a_source_that_cannot_be_found_is_a_finding(self) -> None:
        """A source the check cannot read is not known to be safe."""
        found = self.tasks("- name: a\n  ansible.builtin.copy:\n    src: gone.py\n    dest: /x\n")
        self.assertEqual(len(found), 1)
        self.assertIn("cannot find", found[0])

    def test_diff_false_on_a_file_with_no_matching_line_is_a_finding(self) -> None:
        """A task that hides its diff must hide only files that read as secret."""
        self.put(self.role / "files" / "clean.txt", "x = 1\n")
        found = self.tasks(
            "- name: a\n  ansible.builtin.copy:\n    src: clean.txt\n    dest: /x\n  diff: false\n"
        )
        self.assertEqual(len(found), 1)
        self.assertIn("files/clean.txt", found[0])
        self.assertIn("split the loop", found[0])

    def test_a_loop_mixing_matching_and_clean_files_is_a_finding_until_split(self) -> None:
        """One hidden loop over both kinds fails; a hidden loop and a visible one pass."""
        self.put(self.role / "files" / "bad.txt", self.DOCLINE)
        self.put(self.role / "files" / "good.txt", "x = 1\n")
        self.put(
            self.role / "vars" / "main.yml",
            "r_files: [bad.txt, good.txt]\nr_hidden: [bad.txt]\n"
            "r_items:\n  - {path: bad.txt}\n  - {path: good.txt}\n",
        )
        copy = "  ansible.builtin.copy:\n    src: '{{ item }}'\n    dest: /x\n"
        mixed = "- name: a\n" + copy + "  loop: '{{ r_files }}'\n  diff: false\n"
        found = self.tasks(mixed)
        self.assertEqual(len(found), 1)
        self.assertIn("files/good.txt", found[0])
        hidden = (
            "- name: a\n" + copy + "  loop: '{{ r_files | intersect(r_hidden) }}'\n  diff: false\n"
        )
        shown = "- name: b\n" + copy + "  loop: '{{ r_files | difference(r_hidden) }}'\n"
        self.assertEqual(self.tasks(hidden + shown), [])
        # A match left in the visible half, or a clean file left in the hidden half, is found.
        self.assertEqual(len(self.tasks(shown.replace("difference", "intersect"))), 1)
        self.assertEqual(len(self.tasks(hidden.replace("intersect", "difference"))), 1)

    def test_a_list_of_mappings_is_split_by_attribute(self) -> None:
        """selectattr and rejectattr split a loop over {path: ...} items by a list of paths."""
        self.put(self.role / "files" / "bad.txt", self.DOCLINE)
        self.put(self.role / "files" / "good.txt", "x = 1\n")
        self.put(
            self.role / "vars" / "main.yml",
            "r_hidden: [bad.txt]\nr_items:\n  - {path: bad.txt}\n  - {path: good.txt}\n",
        )
        copy = "  ansible.builtin.copy:\n    src: '{{ item.path }}'\n    dest: /x\n"
        hidden = (
            "- name: a\n" + copy + "  loop: \"{{ r_items | selectattr('path', 'in', r_hidden) "
            '| list }}"\n  diff: false\n'
        )
        shown = (
            "- name: b\n" + copy + "  loop: \"{{ r_items | rejectattr('path', 'in', r_hidden) "
            '| list }}"\n'
        )
        self.assertEqual(self.tasks(hidden + shown), [])
        self.assertEqual(len(self.tasks(shown.replace("rejectattr", "selectattr"))), 1)

    def test_a_task_with_no_log_may_hide_a_file_that_has_no_matching_line(self) -> None:
        """no_log marks a file that becomes secret when rendered, which its source does not show."""
        self.put(self.role / "templates" / "t.j2", "KEY={{ value }}\n")
        found = self.tasks(
            "- name: a\n  ansible.builtin.template:\n    src: t.j2\n    dest: /x\n"
            "  no_log: true\n  diff: false\n"
        )
        self.assertEqual(found, [])

    def test_a_list_the_role_makes_is_resolved_and_a_match_in_it_is_found(self) -> None:
        """edge_stack_deliver is the static CrowdSec files plus the files of the acquisition dir."""
        edge = self.root / "ansible" / "roles" / "edge_stack"
        self.put(
            self.root / "ansible" / "playbooks" / "e.yml",
            "- hosts: all\n  roles:\n    - role: ../roles/edge_stack\n",
        )
        self.put(
            edge / "vars" / "main.yml",
            "edge_stack_source_dir: '{{ role_path }}/files/stack'\n"
            "edge_stack_crowdsec_files: [crowdsec/config.yaml.local]\n"
            "edge_stack_acquis_dir: crowdsec/acquis.d\n",
        )
        stack = edge / "files" / "stack" / "crowdsec"
        self.put(stack / "config.yaml.local", "x: 1\n")
        self.put(stack / "acquis.d" / "a.yaml", self.DOCLINE)
        self.put(
            edge / "tasks" / "main.yml",
            "- name: Deliver the CrowdSec files\n  ansible.builtin.copy:\n"
            "    src: '{{ edge_stack_source_dir }}/{{ item }}'\n    dest: /x/{{ item }}\n"
            "  loop: '{{ edge_stack_deliver }}'\n",
        )
        messages = [m for _f, _n, m in findings_for(self.root)[0]]
        self.assertEqual(len(messages), 1)
        self.assertIn("acquis.d/a.yaml", messages[0])
        self.put(stack / "acquis.d" / "a.yaml", "x: 1\n")
        findings, scanned = findings_for(self.root)
        self.assertEqual(findings, [])
        self.assertTrue(any(s.endswith("acquis.d/a.yaml") for s in scanned))
        self.assertTrue(any(s.endswith("config.yaml.local") for s in scanned))

    def test_a_role_no_playbook_names_is_not_read(self) -> None:
        """Only the roles the playbooks list are in the plan's reach."""
        other = self.root / "ansible" / "roles" / "other"
        self.put(other / "files" / "p.py", self.DOCLINE)
        self.put(
            other / "tasks" / "main.yml",
            "- name: a\n  ansible.builtin.copy:\n    src: p.py\n    dest: /x\n",
        )
        self.assertEqual(self.tasks("[]\n"), [])


class RealTreeCase(unittest.TestCase):
    """The roles this repository's playbooks name."""

    def test_every_copied_file_that_reads_as_secret_has_diff_false(self) -> None:
        """No task copies a file with a line the plan's scan matches without diff: false.

        There is no list of exceptions: a file that reads as secret is reworded, or, when it is a
        variable reference that cannot change, its task sets diff: false.
        """
        findings, scanned = findings_for(ROOT)
        found = [f"{f}: task {n!r} {m}" for f, n, m in findings]
        self.assertEqual(found, [], "\n".join(found))
        # The walk must have read the files the fix is about, or a pass proves nothing.
        self.assertTrue(any(s.endswith("provision_deploy_slot.py") for s in scanned))
        self.assertTrue(any(s.endswith("website_app1/files/compose.yml") for s in scanned))
        # The loops that are made while a role runs, or split into a hidden task and a visible
        # one, must be resolved to their files, or the files they copy were never read.
        for tail in (
            "edge_stack:hetzner/edge/stack/crowdsec/config.yaml.local",
            "control_plane:hetzner/control-plane/stack/postgres/pg_hba.conf",
            "control_plane:hetzner/control-plane/stack/compose.yml",
            "monitoring_stack:hetzner/monitoring/stack/prometheus/alerts.yml",
            "monitoring_stack:hetzner/monitoring/stack/compose.yml",
            "demo1_build:ansible/roles/demo1_build/files/ghost-platform/demo-host/provision/"
            "branchleft_slot.py",
            "demo1_build:ansible/roles/demo1_build/files/ghost-platform/demo-host/provision/"
            "render_slot_sudoers.py",
        ):
            self.assertIn(tail, scanned)
        self.assertTrue(any(s.startswith("edge_stack:") and "acquis.d/" in s for s in scanned))


if __name__ == "__main__":
    unittest.main()
