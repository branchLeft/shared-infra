"""The runbook's interim hand blocks for the monitoring roles are named and checked.

Each hand block that writes the secrets file, copies the stack or installs a drop-in
carries `<!-- interim-hand-block: NAME -->` above its fence, and NAME is listed in
INTERIM below. An unmarked fence, an unlisted or unfenced marker, or a listed name
without a marker fails. The STALWART block is also run as bash against a temporary file.
The SNDS rotation is not a hand block: it goes through the seeding tool into the host's
inputs file, so the runbook's section 14 must hold no fence that writes the secrets file.
The roles are the target; see ansible/roles/monitoring_stack/README.md.
"""

from __future__ import annotations

import os
import pathlib
import re
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Iterator

RUNBOOK = pathlib.Path(__file__).resolve().parent.parent / "RUNBOOK-monitoring.md"
ENV_FILE = "/etc/branchleft/monitoring.env"

INTERIM = {
    "s3-value-block",
    "s3-stalwart-block",
    "s4-rsync",
    "s5-script-call",
    "s13-rollback",
}

MARKER = re.compile(r"^<!-- interim-hand-block: (\S+) -->$")
FENCE_OPEN = re.compile(r"^```bash\s*$")
FENCE_CLOSE = re.compile(r"^```\s*$")

# What makes a bash fence a hand path that a role also covers.
HAND_WRITES = (
    re.compile(r"cat\s*>\s*/etc/branchleft/monitoring\.env"),
    re.compile(r"^\s*f=/etc/branchleft/monitoring\.env", re.MULTILINE),
    re.compile(r"\brsync\b.*\bhetzner/monitoring/stack/", re.DOTALL),
    re.compile(r"install-systemd-drop-ins\.sh"),
)


def bash_fences(text: str) -> list[tuple[int, str, str | None]]:
    """Return (line, body, marker name or None) for each bash fence.

    The marker is the name on the nearest non-blank line above the fence, when that line is a
    marker.
    """
    lines = text.splitlines()
    found: list[tuple[int, str, str | None]] = []
    i = 0
    while i < len(lines):
        if FENCE_OPEN.match(lines[i]):
            j = i - 1
            while j >= 0 and not lines[j].strip():
                j -= 1
            marker = MARKER.match(lines[j]) if j >= 0 else None
            end = i + 1
            while end < len(lines) and not FENCE_CLOSE.match(lines[end]):
                end += 1
            found.append(
                (
                    i + 1,
                    "\n".join(lines[i + 1 : end]),
                    marker.group(1) if marker else None,
                )
            )
            i = end
        i += 1
    return found


def marker_names(text: str) -> list[str]:
    """Return the name on every marker line, in order."""
    return [m.group(1) for line in text.splitlines() if (m := MARKER.match(line))]


def is_hand_write(body: str) -> bool:
    """Say whether a fence writes the secrets file, copies the stack or installs the drop-ins."""
    return any(pattern.search(body) for pattern in HAND_WRITES)


def problems(text: str, listed: set[str]) -> list[str]:
    """Return every way the markers and the hand-write fences disagree with the list."""
    found: list[str] = []
    fenced = {name for _, _, name in bash_fences(text) if name is not None}
    for line, body, name in bash_fences(text):
        if is_hand_write(body) and name is None:
            found.append(f"line {line}: a hand write with no interim-hand-block marker")
        if name is not None and name not in listed:
            found.append(f"line {line}: marker {name} is not in the list")
    for name in marker_names(text):
        if name not in fenced:
            found.append(f"marker {name} has no bash fence under it")
    for name in sorted(listed):
        if name not in marker_names(text):
            found.append(f"{name} is listed and has no marker")
    return found


def block_named(text: str, name: str) -> str:
    """Return the body of the fence under the marker with this name."""
    for _, body, found in bash_fences(text):
        if found == name:
            return body
    raise AssertionError(f"no block is marked {name}")


def remote_script(body: str) -> str:
    """Cut out the part of a replace block that runs on the host.

    It is the text between the single quote that ends the ssh line and the single quote that
    ends the last line of the script.
    """
    start = body.index("ssh ")
    start = body.index("'\n", start) + 2
    end = body.index("'\nunset ", start)
    return body[start:end]


class Outcome:
    def __init__(self, code: int, out: str, err: str, env_path: pathlib.Path) -> None:
        self.code = code
        self.out = out
        self.err = err
        self.env_path = env_path


def run_remote(
    body: str,
    workdir: pathlib.Path,
    value: str,
    initial: str | None,
    failing_mv: bool = False,
    dir_mode: int | None = None,
) -> Outcome:
    """Run the host part of a replace block against a temporary file."""
    script = remote_script(body)
    assert ENV_FILE in script
    env_path = workdir / "monitoring.env"
    script = script.replace(ENV_FILE, str(env_path))
    if initial is not None:
        env_path.write_text(initial, encoding="utf-8")
        env_path.chmod(0o644)
    environment = dict(os.environ)
    if failing_mv:
        fake = workdir / "fakebin"
        fake.mkdir()
        mv = fake / "mv"
        mv.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        mv.chmod(0o755)
        environment["PATH"] = f"{fake}:{environment['PATH']}"
    if dir_mode is not None:
        workdir.chmod(dir_mode)
    try:
        done = subprocess.run(
            ["bash", "-c", script],
            input=value,
            capture_output=True,
            text=True,
            env=environment,
            timeout=60,
            check=False,
        )
    finally:
        workdir.chmod(0o755)
    return Outcome(done.returncode, done.stdout, done.stderr, env_path)


class MarkersTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = RUNBOOK.read_text(encoding="utf-8")

    def test_every_hand_write_is_marked_and_every_marker_is_listed(self) -> None:
        self.assertEqual([], problems(self.text, INTERIM))

    def test_the_blocks_were_actually_found(self) -> None:
        self.assertEqual(INTERIM, set(marker_names(self.text)))
        for name in INTERIM:
            self.assertTrue(block_named(self.text, name).strip(), name)

    def test_an_unmarked_hand_write_is_reported(self) -> None:
        text = "```bash\nrsync -av hetzner/monitoring/stack/ root@h:/opt/branchleft/monitoring/\n```\n"
        self.assertEqual(
            ["line 1: a hand write with no interim-hand-block marker"],
            problems(text, set()),
        )

    def test_an_unmarked_secrets_file_write_is_reported(self) -> None:
        text = "```bash\nssh h 'cat > /etc/branchleft/monitoring.env'\n```\n"
        self.assertEqual(1, len(problems(text, set())))

    def test_a_marker_that_is_not_listed_is_reported(self) -> None:
        text = "<!-- interim-hand-block: other -->\n\n```bash\nls\n```\n"
        self.assertEqual(
            ["line 3: marker other is not in the list"], problems(text, set())
        )

    def test_a_marker_with_no_fence_is_reported(self) -> None:
        text = "<!-- interim-hand-block: other -->\n\nSome prose.\n"
        self.assertIn(
            "marker other has no bash fence under it", problems(text, {"other"})
        )

    def test_a_listed_name_with_no_marker_is_reported(self) -> None:
        self.assertEqual(
            ["gone is listed and has no marker"], problems("Prose.\n", {"gone"})
        )

    def test_a_marked_hand_write_is_not_reported(self) -> None:
        text = (
            "<!-- interim-hand-block: s4 -->\n\n"
            "```bash\nrsync -av hetzner/monitoring/stack/ root@h:/x/\n```\n"
        )
        self.assertEqual([], problems(text, {"s4"}))

    def test_a_read_of_the_secrets_file_is_not_a_hand_write(self) -> None:
        text = "```bash\nssh h 'ls -l /etc/branchleft/monitoring.env'\n```\n"
        self.assertEqual([], problems(text, set()))


REPLACE_BLOCKS = (
    ("s3-stalwart-block", "STALWART_PROMETHEUS_SECRET"),
)

OTHER_LINES = "SMTP_PASSWORD=keep-one\nNTFY_TOPIC=keep-two\n"


class ReplaceBlockTests(unittest.TestCase):
    """Run the host part of each block that replaces one key."""

    def setUp(self) -> None:
        self.text = RUNBOOK.read_text(encoding="utf-8")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workdir = pathlib.Path(self.tmp.name)
        self.addCleanup(self.workdir.chmod, 0o755)

    def each(self) -> Iterator[tuple[str, str]]:
        for name, key in REPLACE_BLOCKS:
            with self.subTest(block=name):
                # A fresh directory for every block.
                for child in self.workdir.iterdir():
                    if child.is_dir():
                        for inner in child.iterdir():
                            inner.unlink()
                        child.rmdir()
                    else:
                        child.unlink()
                yield block_named(self.text, name), key

    def leftovers(self) -> list[str]:
        return sorted(
            p.name for p in self.workdir.iterdir() if p.name != "monitoring.env"
        )

    def test_a_replace_keeps_the_other_lines_and_leaves_one_line_of_the_key(
        self,
    ) -> None:
        for body, key in self.each():
            result = run_remote(
                body, self.workdir, "new-value", f"{key}=old\n{OTHER_LINES}"
            )
            content = result.env_path.read_text(encoding="utf-8")
            self.assertEqual(0, result.code, result.err)
            self.assertEqual(OTHER_LINES + f"{key}=new-value\n", content)
            self.assertIn(f"OK: {key} replaced, 9 bytes, exactly one line", result.out)
            self.assertEqual([], self.leftovers())

    def test_the_new_file_is_closed_to_root(self) -> None:
        for body, key in self.each():
            result = run_remote(body, self.workdir, "v", f"{key}=old\n{OTHER_LINES}")
            self.assertEqual(0o600, stat.S_IMODE(result.env_path.stat().st_mode))

    def test_a_value_with_sed_and_url_characters_round_trips(self) -> None:
        value = "https://example.invalid/d?key=A%2FB%2BC%3D&format=csv&x=\\1"
        for body, key in self.each():
            result = run_remote(
                body, self.workdir, value, f"{key}=old&x\n{OTHER_LINES}"
            )
            self.assertEqual(0, result.code, result.err)
            self.assertEqual(
                OTHER_LINES + f"{key}={value}\n",
                result.env_path.read_text(encoding="utf-8"),
            )

    def test_a_file_that_holds_only_the_key_is_replaced(self) -> None:
        # grep -v finds no line to keep and exits 1: that is not an error.
        for body, key in self.each():
            result = run_remote(body, self.workdir, "new", f"{key}=old\n")
            self.assertEqual(0, result.code, result.err)
            self.assertEqual(
                f"{key}=new\n", result.env_path.read_text(encoding="utf-8")
            )

    def test_a_file_without_the_key_gets_it_appended(self) -> None:
        for body, key in self.each():
            result = run_remote(body, self.workdir, "new", OTHER_LINES)
            self.assertEqual(0, result.code, result.err)
            self.assertEqual(
                OTHER_LINES + f"{key}=new\n",
                result.env_path.read_text(encoding="utf-8"),
            )

    def test_an_empty_value_is_refused_and_the_old_file_stays(self) -> None:
        for body, key in self.each():
            before = f"{key}=old\n{OTHER_LINES}"
            result = run_remote(body, self.workdir, "", before)
            self.assertEqual(1, result.code)
            self.assertEqual(before, result.env_path.read_text(encoding="utf-8"))
            self.assertNotIn("OK", result.out)
            self.assertEqual([], self.leftovers())

    def test_an_absent_file_is_refused_and_nothing_is_created(self) -> None:
        for body, key in self.each():
            result = run_remote(body, self.workdir, "new", None)
            self.assertEqual(1, result.code)
            self.assertFalse(result.env_path.exists())
            self.assertNotIn("OK", result.out)
            self.assertEqual([], self.leftovers())

    def test_a_failed_move_prints_no_success_keeps_the_old_file_and_removes_the_temp(
        self,
    ) -> None:
        for body, key in self.each():
            before = f"{key}=old\n{OTHER_LINES}"
            result = run_remote(body, self.workdir, "new", before, failing_mv=True)
            self.assertEqual(1, result.code)
            self.assertNotIn("OK", result.out)
            self.assertIn("monitoring.env was NOT updated", result.err)
            self.assertEqual(before, result.env_path.read_text(encoding="utf-8"))
            self.assertEqual(["fakebin"], self.leftovers())

    @unittest.skipIf(os.geteuid() == 0, "root writes into a closed directory")
    def test_an_unwritable_directory_prints_no_success_and_keeps_the_old_file(
        self,
    ) -> None:
        for body, key in self.each():
            before = f"{key}=old\n{OTHER_LINES}"
            result = run_remote(body, self.workdir, "new", before, dir_mode=0o500)
            self.assertEqual(1, result.code)
            self.assertNotIn("OK", result.out)
            self.assertEqual(before, result.env_path.read_text(encoding="utf-8"))

    def test_the_value_is_not_in_the_ssh_command_line(self) -> None:
        for body, _ in self.each():
            line = next(line for line in body.splitlines() if "ssh " in line)
            self.assertNotIn("$STALWART_SECRET", line.split("|", 1)[1])

    def test_the_check_comes_before_the_move_and_the_success_line_after_it(
        self,
    ) -> None:
        # A control on the text itself: a sabotage that moves the file first, or prints OK
        # before the move, is caught here as well as by the runs above.
        for body, _ in self.each():
            script = remote_script(body)
            self.assertLess(script.index("grep -c"), script.index('mv "$t"'))
            self.assertLess(script.index("wc -c | tr"), script.index('mv "$t"'))
            self.assertLess(script.index('mv "$t"'), script.index('echo "OK:'))


SECTION_14 = re.compile(r"^## 14\. .*?(?=^## 15\. )", re.MULTILINE | re.DOTALL)
ROTATION = re.compile(
    r"ssh -t .*seed_host_inputs\.py --host edge1 --set monitoring_stack_snds_data_url\s*$"
)


def section_14_fences(text: str) -> list[str]:
    """The bash fences of section 14, each with its line continuations joined."""
    section = SECTION_14.search(text)
    if section is None:
        raise AssertionError("no section 14")
    return [
        re.sub(r"\s*\\\n\s*", " ", body) for _, body, _ in bash_fences(section.group(0))
    ]


class SndsRotationTests(unittest.TestCase):
    """The SNDS URL has one writer: the role, from the host's inputs file. Section 14 rotates it."""

    def setUp(self) -> None:
        self.text = RUNBOOK.read_text(encoding="utf-8")

    def test_no_fence_under_section_14_writes_the_url_into_the_secrets_file(self) -> None:
        for body in section_14_fences(self.text):
            self.assertFalse(
                "SNDS_DATA_URL" in body and "monitoring.env" in body, body.splitlines()[0]
            )
            self.assertFalse(is_hand_write(body), body.splitlines()[0])

    def test_the_rotation_fence_calls_the_seeding_tool_for_the_one_key(self) -> None:
        rotation = [b for b in section_14_fences(self.text) if ROTATION.search(b)]
        self.assertEqual(1, len(rotation))
        # A terminal for the hidden prompt, and no value anywhere on the command line.
        self.assertNotIn("read -rs", rotation[0])
        self.assertNotIn("$SNDS", rotation[0])
        self.assertIn("python3 -I /var/lib/pull-trigger/current/ansible/tools/seed_host_inputs.py", rotation[0])

    def test_the_two_writers_wording_is_gone(self) -> None:
        self.assertNotRegex(self.text, r"(?i)two\s+writers")
        self.assertRegex(self.text, r"One writer of `SNDS_DATA_URL`")

    def test_no_prose_sends_the_owner_to_write_the_line_by_hand(self) -> None:
        flat = re.sub(r"\s+", " ", self.text)
        self.assertNotIn("step 14 still writes this key by hand", flat)
        self.assertNotIn("then write the new URL into `/etc/branchleft/monitoring.env`", flat)
        self.assertNotIn("re-do §14's write step", flat)

    def test_the_rotation_says_when_the_new_link_arrives(self) -> None:
        flat = re.sub(r"\s+", " ", self.text)
        self.assertIn("reaches the collector at the next gated apply, not at once", flat)
        self.assertNotIn("leaves the old file whole", flat)
        # The unqualified sentence said every non-success left the file unchanged, which a
        # failed read-back does not: the new file is already in place. The qualified wording
        # must name that exception.
        self.assertNotIn("Anything else means the file was not changed", flat)
        self.assertIn("A failed read-back is the one exception to the line above", flat)


if __name__ == "__main__":
    unittest.main()
