"""Unit tests for branchleft_edge_entry.

The program is the only writer of the descriptor directory the certificate
check reads, so its refusals (slug, size, shape) and its atomic write are
covered here rather than left to a live host to discover.
"""

import contextlib
import io
import os
import stat
import tempfile
import unittest

import branchleft_edge_entry as bee

GOOD = b'{"hostnames": ["blog.example.test"]}'


def run(argv, body=b"", directory=None):
    """Run main() with stdin bytes and a directory; return (exit code, stderr text)."""
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        code = bee.main(argv, stdin=io.BytesIO(body), directory=directory)
    return code, err.getvalue()


class EntryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def listing(self):
        return sorted(os.listdir(self.dir))

    def test_publish_writes_the_descriptor_world_readable(self):
        code, _ = run(["x", "publish", "blog"], GOOD, self.dir)
        self.assertEqual(code, 0)
        path = os.path.join(self.dir, "blog.json")
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), GOOD)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
        self.assertEqual(self.listing(), ["blog.json"])

    def test_publish_replaces_an_existing_file_and_leaves_no_temporary(self):
        run(["x", "publish", "blog"], GOOD, self.dir)
        newer = b'{"hostnames": ["shop.example.test"]}'
        code, _ = run(["x", "publish", "blog"], newer, self.dir)
        self.assertEqual(code, 0)
        with open(os.path.join(self.dir, "blog.json"), "rb") as handle:
            self.assertEqual(handle.read(), newer)
        self.assertEqual(self.listing(), ["blog.json"])

    def test_withdraw_removes_the_file(self):
        run(["x", "publish", "blog"], GOOD, self.dir)
        code, _ = run(["x", "withdraw", "blog"], b"", self.dir)
        self.assertEqual(code, 0)
        self.assertEqual(self.listing(), [])

    def test_withdraw_of_an_absent_file_succeeds(self):
        code, _ = run(["x", "withdraw", "blog"], b"", self.dir)
        self.assertEqual(code, 0)

    def test_bad_slugs_are_refused_and_nothing_is_written(self):
        bad = ["", "Blog", "a.b", "a/b", "../x", "a" * 64, "a\n", "a b", "-" * 0 + "é"]
        for slug in bad:
            with self.subTest(slug=slug):
                code, err = run(["x", "publish", slug], GOOD, self.dir)
                self.assertEqual(code, 1)
                self.assertIn("refused", err)
                self.assertEqual(self.listing(), [])

    def test_a_bad_slug_on_withdraw_is_refused(self):
        run(["x", "publish", "blog"], GOOD, self.dir)
        code, _ = run(["x", "withdraw", "../blog"], b"", self.dir)
        self.assertEqual(code, 1)
        self.assertEqual(self.listing(), ["blog.json"])

    def test_the_longest_slug_is_accepted(self):
        slug = "a" * 63
        code, _ = run(["x", "publish", slug], GOOD, self.dir)
        self.assertEqual(code, 0)
        self.assertEqual(self.listing(), [slug + ".json"])

    def test_body_at_the_limit_is_accepted_and_one_byte_over_is_refused(self):
        pad = bee.STDIN_LIMIT - len(b'{"p": ""}')
        at_limit = b'{"p": "' + b"a" * pad + b'"}'
        self.assertEqual(len(at_limit), bee.STDIN_LIMIT)
        code, _ = run(["x", "publish", "blog"], at_limit, self.dir)
        self.assertEqual(code, 0)

        over = at_limit[:-2] + b'a"}'
        self.assertEqual(len(over), bee.STDIN_LIMIT + 1)
        code, err = run(["x", "publish", "blog"], over, self.dir)
        self.assertEqual(code, 1)
        self.assertIn("exceeds", err)
        with open(os.path.join(self.dir, "blog.json"), "rb") as handle:
            self.assertEqual(handle.read(), at_limit)

    def test_invalid_json_or_wrong_shape_is_refused_and_nothing_is_written(self):
        cases = [b"", b"not json", b"[]", b"42", b'"text"', b"\xff\xfe", b'{"a": '[:-1]]
        for body in cases:
            with self.subTest(body=body):
                code, err = run(["x", "publish", "blog"], body, self.dir)
                self.assertEqual(code, 1)
                self.assertIn("refused", err)
                self.assertEqual(self.listing(), [])

    def test_a_missing_directory_fails_without_a_traceback(self):
        missing = os.path.join(self.dir, "absent")
        code, err = run(["x", "publish", "blog"], GOOD, missing)
        self.assertEqual(code, 1)
        self.assertIn("failed", err)

    def test_unknown_verb_or_wrong_arity_is_a_usage_error(self):
        for argv in (["x", "rename", "blog"], ["x", "publish"], ["x"], ["x", "publish", "a", "b"]):
            with self.subTest(argv=argv):
                code, _ = run(argv, GOOD, self.dir)
                self.assertEqual(code, 2)
                self.assertEqual(self.listing(), [])


if __name__ == "__main__":
    unittest.main()
