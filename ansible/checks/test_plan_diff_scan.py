"""A file a role copies whole must not trip the plan's secret scan, or it has no approvable plan.

The gated apply asks each host what a run would change, in check mode, with a diff. Before the
plan is shown to the approver, a scan reads that diff and withholds all of it when any line looks
like a secret. A role that copies a whole file (a program, a compose file) puts the file into the
diff as it changes, so one line that merely reads like a secret, such as a docstring sentence or
an environment variable reference, withholds the plan of the host: nothing can be approved.

The control is a task keyword, `diff: false`, set on the copy or template task whose file is not
secret but reads as secret-like text. The scan is a backstop, never loosened to fit a file
(ANS-16). This module holds the scan's pattern as a constant and fails when a task the playbooks
reach copies a file with a matching line and does not set `diff: false`.

The pattern is the `credential-assignment` entry of the backstop in the workflow step "Judge the
answers, scan the diff and write the result" of the ssh-check-hosts action, in
branchLeft/github-workflows, at the tag ansible-gated-apply.yml pins (v1.0.19 when this was
written). The workflow runs it as `grep -Eiq` on the diff in the C locale. It is translated here:
`re.I` for `-i`, `re.A` so that `\\s` is the ASCII set the C locale gives the POSIX space class,
and `\\s` for `[[:space:]]`. The other entries of the backstop name key material and tokens that
no role file holds, so they are not copied.

The check reads the source of a task, not the text Ansible renders from it. A template whose
rendered text differs from its source is judged by its source.
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
DEPTH = 6

Env = dict[str, object]
Finding = tuple[str, str, str]

# Tasks that copy a file the scan reads as secret, or whose source the check cannot name (a list
# made on the host), and set no diff: false. Each has the defect this check exists for, found
# when the check was written, and none has failed a plan yet, because a diff reaches the scan
# only when the file is first delivered or changes near such a line. They are listed so that
# the check is green and still fails for every new one. Setting diff: false on a task, or
# fixing the file, removes its entry: a listed task that no longer has a finding fails the
# test, so the list can only shrink. The reach of each is the plan of its host.
KNOWN_UNSAFE = (
    ("ansible/roles/control_plane/tasks/main.yml", "Deliver the stack's files"),
    (
        "ansible/roles/db1_stack/tasks/_compose.yml",
        "Render the compose file the deploy program reads",
    ),
    ("ansible/roles/demo1_build/tasks/_release.yml", "Copy each vendored program into the release"),
    ("ansible/roles/demo1_egress_spool/tasks/_compose.yml", "Place the rendered Compose file"),
    ("ansible/roles/edge_stack/tasks/_deliver.yml", "Deliver the CrowdSec files"),
    (
        "ansible/roles/exporters_and_collectors/tasks/_snds_collector.yml",
        "Install the collector program",
    ),
    ("ansible/roles/monitoring_stack/tasks/main.yml", "Deliver the stack's files"),
    ("ansible/roles/nextcloud_stack/tasks/main.yml", "Deliver the stack's files"),
    ("ansible/roles/nextcloud_stack/tasks/main.yml", "Install the drop-in of the instance"),
    ("ansible/roles/ntfy_pager/tasks/main.yml", "Deliver the renderer"),
)


def matching_lines(text: str) -> list[int]:
    """Return the 1-based number of each line of ``text`` the scan matches."""
    return [n for n, line in enumerate(text.splitlines(), 1) if CREDENTIAL_ASSIGNMENT.search(line)]


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


def value_of(text: object, env: Env) -> object:
    """Return the list or mapping a lone `{{ name }}` stands for, else the rendered text."""
    if isinstance(text, str):
        whole = EXPRESSION.fullmatch(text.strip())
        if whole:
            value = _evaluate(whole, env, DEPTH)
            return text if value is None else value
        return render(text, env)
    return text


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
    the file; only a task without it can produce a finding.
    """
    roles_dir = root / "ansible" / "roles"
    every = {role.name: role_variables(role) for role in sorted(roles_dir.glob("*"))}
    fallback = {k: v for variables in every.values() for k, v in variables.items()}
    findings: set[Finding] = set()
    scanned: list[str] = []
    for name in named_roles(root / "ansible" / "playbooks"):
        role = roles_dir / name
        base: Env = {**fallback, **every[name], "role_path": str(role)}
        for path, task, diff_is_off in tasks_of(role):
            used = _module_args(task, COPIERS)
            args = used[1] if used else None
            if used is None or not isinstance(args, dict):
                continue
            src = args.get("src")
            if "content" in args or args.get("remote_src") or not isinstance(src, str):
                continue
            where = (str(path.relative_to(root)), str(task.get("name", "(unnamed)")))
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
    )

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
        """No task copies a file with a line the plan's scan matches without diff: false."""
        findings, scanned = findings_for(ROOT)
        new = [f"{f}: task {n!r} {m}" for f, n, m in findings if (f, n) not in KNOWN_UNSAFE]
        self.assertEqual(new, [], "\n".join(new))
        # The walk must have read the files the fix is about, or a pass proves nothing.
        self.assertTrue(any(s.endswith("provision_deploy_slot.py") for s in scanned))
        self.assertTrue(any(s.endswith("website_app1/files/compose.yml") for s in scanned))

    def test_the_list_of_known_unsafe_tasks_holds_only_tasks_still_unsafe(self) -> None:
        """A task fixed with diff: false must leave the list, so the list only shrinks."""
        current = {(f, n) for f, n, _m in findings_for(ROOT)[0]}
        stale = [pair for pair in KNOWN_UNSAFE if pair not in current]
        self.assertEqual(stale, [], f"{stale} no longer has a finding: remove it from the list")


if __name__ == "__main__":
    unittest.main()
