"""Tests for the Ansible path filter.

The filter in .github/workflows/ansible.yml decides whether the Ansible lint job runs, and
ci_select.py decides which shards run. A role test that reads a file outside ansible/ must
run when that file changes, so every such path has to be inside what the filter watches. The
scan that finds those paths is ci_select.reads_by_path, the one the shard choice uses, so the
filter and the choice cannot disagree about what a role reads. These tests fail when a path
a role reads is outside the filter.

The lint job also runs checks that read the whole tree, not a named path: one lists every
tracked file, two walk the checkout. A change to any file can break such a check, so when one
exists the filter must cover every tracked file, which its ``.`` entry does. The scan that finds
those checks reads the checks' own sources, so a new one is found with no list to edit.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import ci_select

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ansible.yml"
FILTER = re.compile(r"watched=\(\n(.*?)\n\s*\)", re.DOTALL)
# The directories watched whole, whatever they hold now or later.
WHOLE = ("ansible/", "hetzner/", "mail/")
# The hand-step ratchet register: every runbook it counts must be a path the filter watches.
REGISTER = Path(__file__).resolve().parent / "hand_runbook_steps.yml"
# The filter entry that stands for the whole repository.
WHOLE_TREE = "."
# The directories whose tests and programs the lint job runs, and the calls in them that
# enumerate the checkout: git's file list and a directory walk. A source that makes either call
# reads files it does not name. This file is left out: it lists files only to judge the filter.
LINT_DIRS = ("ansible/checks", "ansible/harness", "ansible/tools")
WHOLE_TREE_CALLS = ("ls-files", "os.walk(")
SELF = Path(__file__).resolve()


def parse_watched(workflow_text: str) -> list[str]:
    """Return the entries of the watched=( ... ) array, or [] when the array is absent."""
    match = FILTER.search(workflow_text)
    if match is None:
        return []
    return [line.strip() for line in match.group(1).splitlines() if line.strip()]


def uncovered(reads: set[str], watched: list[str]) -> list[str]:
    """Return the reads the filter does not name.

    A read is named when the filter lists it exactly, lists a directory that holds it, or
    lists files under it (a directory a verify step only reads the parts of). The ``.`` entry
    names every path.
    """
    if WHOLE_TREE in watched:
        return []
    names = {entry.rstrip("/") for entry in watched}
    dirs = {entry.rstrip("/") for entry in watched if entry.endswith("/")}
    missing = []
    for read in sorted(reads):
        if read in names:
            continue
        if any(read.startswith(d + "/") for d in dirs):
            continue
        if any(name.startswith(read + "/") for name in names):
            continue
        missing.append(read)
    return missing


def lint_sources(root: Path) -> dict[str, str]:
    """Map each Python file the lint job runs, other than this one, to its text without comments."""
    found: dict[str, str] = {}
    for directory in LINT_DIRS:
        for path in sorted((root / directory).rglob("*.py")):
            if path.resolve() != SELF and path.is_file() and not path.is_symlink():
                text = path.read_text(encoding="utf-8", errors="ignore")
                found[path.relative_to(root).as_posix()] = ci_select.without_comments(text)
    return found


def whole_tree_readers(sources: dict[str, str]) -> list[str]:
    """Return the sources that enumerate the checkout, so they read files they do not name."""
    return sorted(
        name for name, text in sources.items() if any(call in text for call in WHOLE_TREE_CALLS)
    )


def tracked_files(root: Path) -> set[str]:
    """Return every file git tracks under ``root``."""
    listing = subprocess.run(  # noqa: S603
        ["git", "-C", str(root), "ls-files", "-z"],  # noqa: S607
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    return {name for name in listing.split("\0") if name}


def lint_reads(root: Path) -> set[str]:
    """Return the paths the lint job's checks read: the whole tree, or the paths they name.

    A check that enumerates the checkout reads every tracked file. Otherwise the paths outside
    ansible/ that the checks' own text names are the reads.
    """
    sources = lint_sources(root)
    if whole_tree_readers(sources):
        return tracked_files(root)
    named: set[str] = set()
    for text in sources.values():
        named |= ci_select.outside_reads(text)
    return named


class WatchedPathsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.watched = parse_watched(WORKFLOW.read_text(encoding="utf-8"))
        # The entries that name a path. The ``.`` entry is judged by LintReadsTest, so the
        # tests below still hold when it is present.
        self.named = [entry for entry in self.watched if entry != WHOLE_TREE]
        self.reads = ci_select.reads_by_path(ROOT)

    def test_every_outside_path_a_role_reads_is_watched(self) -> None:
        self.assertTrue(self.watched, "the workflow has no watched=( ... ) array")
        missing = uncovered(set(self.reads), self.named)
        detail = [f"{path} (read by {', '.join(sorted(self.reads[path]))})" for path in missing]
        self.assertEqual([], detail, "these paths are read by role tests but not in the filter")

    def test_ansible_hetzner_and_mail_are_watched_whole(self) -> None:
        # A file named one by one is a file the next edit forgets to name.
        for directory in WHOLE:
            with self.subTest(directory=directory):
                self.assertIn(directory, self.watched)

    def test_every_runbook_the_ratchet_counts_is_watched(self) -> None:
        # The ratchet (test_no_new_hand_runbook_steps.py) reads every mail/RUNBOOK-*.md. A runbook
        # change the filter does not name never runs it, so a new hand step could land green.
        runbooks = set(re.findall(r"^(\S+\.md):\s*$", REGISTER.read_text(encoding="utf-8"), re.M))
        self.assertIn("mail/RUNBOOK-mx1-provision.md", runbooks)
        self.assertEqual([], uncovered(runbooks, self.named))

    def test_the_lint_files_and_the_two_files_the_tools_read_are_watched(self) -> None:
        for path in (
            ".ansible-lint",
            ".yamllint",
            ".github/workflows/ansible.yml",
            ".github/workflows/ansible-delivery.yml",
            "hetzner-host/cloudInit.ts",
            "hetzner-host/pullBootstrapFixed.json",
        ):
            with self.subTest(path=path):
                self.assertIn(path, self.watched)
                self.assertTrue((ROOT / path).is_file(), path)

    def test_everything_that_runs_every_shard_is_watched(self) -> None:
        # A change the shard choice treats as deciding every role must start the workflow's
        # work at all, or it would pass in silence.
        self.assertEqual([], uncovered(set(ci_select.EVERY_SHARD), self.named))

    def test_scanner_finds_known_reads(self) -> None:
        # A control: the scan must see the reads it is meant to find, or a clean result
        # proves nothing.
        self.assertIn("hetzner/monitoring/stack", self.reads)
        self.assertIn("hetzner/provision/branchleft-nat.service", self.reads)
        self.assertIn("hetzner/provision/branchleft-db-tunnel.service", self.reads)
        # Read through a symlink in files/, not through a path in molecule/ or tests/.
        self.assertIn("hetzner/control-plane/stack", self.reads)

    def test_a_read_with_no_entry_is_reported(self) -> None:
        watched = ["ansible/", "hetzner-host/cloudInit.ts"]
        self.assertEqual(
            ["hetzner/provision/branchleft-nat.service"],
            uncovered({"hetzner/provision/branchleft-nat.service"}, watched),
        )

    def test_a_directory_entry_covers_the_files_under_it(self) -> None:
        self.assertEqual(
            [], uncovered({"hetzner/monitoring/stack/snds/x.py"}, ["hetzner/monitoring/stack/"])
        )
        self.assertEqual(
            ["hetzner/monitoring/stack"],
            uncovered(
                {"hetzner/monitoring/stack"},
                ["hetzner/monitoring/systemd/monitoring.override.conf"],
            ),
        )


class LintReadsTest(unittest.TestCase):
    """A file the lint job's checks read must start the lint job when it changes."""

    def setUp(self) -> None:
        self.watched = parse_watched(WORKFLOW.read_text(encoding="utf-8"))

    def test_every_file_the_lint_checks_read_is_watched(self) -> None:
        reads = lint_reads(ROOT)
        self.assertIn("ansible/checks/hand_installers.yml", reads)
        self.assertEqual([], uncovered(reads, self.watched))

    def test_the_scan_finds_the_checks_that_read_the_whole_tree(self) -> None:
        # A control: a scan that found none would let the test above judge the named reads
        # only, and a clean result would prove nothing about the tree walkers.
        found = whole_tree_readers(lint_sources(ROOT))
        for name in (
            "ansible/checks/test_no_new_script_dependents.py",
            "ansible/checks/test_no_new_hand_installers.py",
            "ansible/checks/test_no_new_hand_runbook_steps.py",
        ):
            with self.subTest(check=name):
                self.assertIn(name, found)

    def test_a_scripts_only_change_is_covered(self) -> None:
        # The change that put the repository red: a file under scripts/ that names a script the
        # dependents check counts. Neither it nor any other directory outside the named ones may
        # be left out of the filter.
        reads = lint_reads(ROOT)
        for path in ("scripts/ci_skip.py", ".github/workflows/ci.yml", "README.md"):
            with self.subTest(path=path):
                self.assertIn(path, reads)
                self.assertEqual([], uncovered({path}, self.watched))

    def fixture(self, files: dict[str, str]) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)  # noqa: S603, S607
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", relative], check=True)  # noqa: S603, S607
        return root

    def test_a_tree_walking_check_makes_every_tracked_file_a_read(self) -> None:
        root = self.fixture(
            {
                "ansible/checks/test_walk.py": "files = git('ls-files')\n",
                "scripts/other.py": "x = 1\n",
            }
        )
        reads = lint_reads(root)
        self.assertIn("scripts/other.py", reads)
        self.assertEqual(["scripts/other.py"], uncovered({"scripts/other.py"}, list(WHOLE)))
        self.assertEqual([], uncovered(reads, [*WHOLE, WHOLE_TREE]))

    def test_a_directory_walk_is_a_whole_tree_read(self) -> None:
        root = self.fixture({"ansible/checks/test_walk.py": "for d, s, f in os.walk(root): pass\n"})
        self.assertEqual(["ansible/checks/test_walk.py"], whole_tree_readers(lint_sources(root)))

    def test_a_call_named_only_in_a_comment_is_not_a_walk(self) -> None:
        root = self.fixture({"ansible/checks/test_x.py": "# lists files with ls-files\nx = 1\n"})
        self.assertEqual([], whole_tree_readers(lint_sources(root)))

    def test_with_no_tree_walker_the_named_reads_must_be_watched(self) -> None:
        root = self.fixture(
            {"ansible/checks/test_named.py": 'PATH = "hetzner-host/cloudInit.ts"\n'}
        )
        reads = lint_reads(root)
        self.assertEqual({"hetzner-host/cloudInit.ts"}, reads)
        self.assertEqual(["hetzner-host/cloudInit.ts"], uncovered(reads, list(WHOLE)))
        self.assertEqual([], uncovered(reads, [*WHOLE, "hetzner-host/cloudInit.ts"]))


class CommentsAreNotReadsTest(unittest.TestCase):
    # A path named in a comment tells the reader something; it does not make the role read
    # it, so the filter must not be widened to cover it.
    def test_whole_line_yaml_comment_is_not_a_read(self) -> None:
        text = "# Mirrors hetzner/provision/test_compose_unit_contract.py.\n"
        self.assertEqual(set(), ci_select.outside_reads(text))

    def test_trailing_yaml_comment_is_not_a_read(self) -> None:
        text = "verify_repo: ROOT  # mirrors hetzner/provision/branchleft-nat.service\n"
        self.assertEqual(set(), ci_select.outside_reads(text))

    def test_shell_comments_are_not_reads(self) -> None:
        whole = "    # cp hetzner/provision/x.service /etc\n"
        trailing = "cp a b  # hetzner/provision/x.service\n"
        self.assertEqual(set(), ci_select.outside_reads(whole))
        self.assertEqual(set(), ci_select.outside_reads(trailing))

    def test_joined_path_in_a_comment_is_not_a_read(self) -> None:
        text = '# ROOT / "hetzner" / "provision" / "x.service"\n'
        self.assertEqual(set(), ci_select.outside_reads(text))

    def test_a_real_read_on_a_line_with_a_comment_still_counts(self) -> None:
        text = "src: '{{ verify_repo }}/hetzner/provision/x.service'  # the unit file\n"
        self.assertEqual({"hetzner/provision/x.service"}, ci_select.outside_reads(text))

    def test_a_real_read_after_a_hash_inside_quotes_still_counts(self) -> None:
        text = 'marker: " # "; src: "hetzner/provision/x.service"\n'
        self.assertEqual({"hetzner/provision/x.service"}, ci_select.outside_reads(text))

    def test_a_real_read_after_an_escaped_quote_still_counts(self) -> None:
        text = 'note: "a \\" b # c"; src: "hetzner/provision/x.service"\n'
        self.assertEqual({"hetzner/provision/x.service"}, ci_select.outside_reads(text))

    def test_a_comment_only_fixture_reads_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vars_dir = root / "ansible" / "roles" / "backup_restore"
            vars_dir = vars_dir / "molecule" / "default" / "vars"
            vars_dir.mkdir(parents=True)
            (vars_dir / "test.yml").write_text(
                "# Mirrors hetzner/provision/test_compose_unit_contract.py.\n"
                "verify_repo: ROOT  # and hetzner/provision/branchleft-nat.service\n",
                encoding="utf-8",
            )
            self.assertEqual({}, ci_select.reads_by_path(root))

    def test_a_real_read_fixture_is_still_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vars_dir = root / "ansible" / "roles" / "backup_restore"
            vars_dir = vars_dir / "molecule" / "default" / "vars"
            vars_dir.mkdir(parents=True)
            (vars_dir / "test.yml").write_text(
                "# Mirrors hetzner/provision/test_compose_unit_contract.py.\n"
                "verify_repo: '{{ root }}/hetzner/provision/x.service'  # the unit\n",
                encoding="utf-8",
            )
            self.assertIn("hetzner/provision/x.service", ci_select.reads_by_path(root))
            reads = ci_select.reads_by_path(root)
            self.assertNotIn("hetzner/provision/test_compose_unit_contract.py", reads)


if __name__ == "__main__":
    unittest.main()
