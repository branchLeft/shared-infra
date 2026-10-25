"""Tests for check_role_paths: the real tree passes, and a path two roles write fails."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from check_role_paths import ROOT, check, writers_of

COPY = "- ansible.builtin.copy:\n    dest: {path}\n    content: x\n"


class RealTree(unittest.TestCase):
    def test_no_two_roles_write_the_same_path(self) -> None:
        self.assertEqual(check(ROOT), [])

    def test_the_check_compares_paths_and_does_not_pass_over_nothing(self) -> None:
        paths, _templated = writers_of(ROOT)
        self.assertGreater(len(paths), 20)
        self.assertIn("/etc/ssh/sshd_config.d/01-branchleft-hardening.conf", paths)


class Paths(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def _write(self, relative: str, text: str) -> None:
        path = self.root / "ansible" / "roles" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_one_role_writing_a_path_passes(self) -> None:
        self._write("a/tasks/main.yml", COPY.format(path="/etc/x"))
        self._write("b/tasks/main.yml", COPY.format(path="/etc/y"))
        self.assertEqual(check(self.root), [])

    def test_two_roles_writing_one_literal_path_fail_naming_both(self) -> None:
        self._write("a/tasks/main.yml", COPY.format(path="/etc/x"))
        self._write("b/tasks/main.yml", COPY.format(path="/etc/x"))
        self.assertEqual(["/etc/x is written by a, b"], check(self.root))

    def test_a_path_built_from_variables_is_resolved_before_it_is_compared(self) -> None:
        self._write("a/defaults/main.yml", "a_dir: /etc/x.d\na_file: '{{ a_dir }}/f'\n")
        self._write("a/tasks/main.yml", COPY.format(path="'{{ a_file }}'"))
        self._write("b/tasks/main.yml", COPY.format(path="/etc/x.d/f"))
        self.assertEqual(["/etc/x.d/f is written by a, b"], check(self.root))

    def test_a_variable_of_another_role_is_resolved_too(self) -> None:
        self._write("a/vars/main.yml", "a_file: /etc/shared\n")
        self._write("a/tasks/main.yml", COPY.format(path="'{{ a_file }}'"))
        self._write("b/tasks/main.yml", COPY.format(path="'{{ a_file }}'"))
        self.assertEqual(["/etc/shared is written by a, b"], check(self.root))

    def test_a_link_counts_and_a_directory_does_not(self) -> None:
        link = "- ansible.builtin.file:\n    path: /etc/l\n    state: link\n    src: /x\n"
        directory = "- ansible.builtin.file:\n    path: /etc/d\n    state: directory\n"
        self._write("a/tasks/main.yml", link + directory)
        self._write("b/tasks/main.yml", link + directory)
        self.assertEqual(["/etc/l is written by a, b"], check(self.root))

    def test_a_path_left_templated_is_not_compared(self) -> None:
        self._write("a/tasks/main.yml", COPY.format(path="'/etc/{{ item }}'"))
        self._write("b/tasks/main.yml", COPY.format(path="'/etc/{{ item }}'"))
        self.assertEqual(check(self.root), [])
        self.assertEqual(2, writers_of(self.root)[1])


if __name__ == "__main__":
    unittest.main()
