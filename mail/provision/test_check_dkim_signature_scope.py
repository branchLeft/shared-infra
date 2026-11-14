"""Unit tests for check_dkim_signature_scope.py. No key material: the
signatures below are placeholders that only carry the tags the check reads.
Run with: python3 -m unittest discover -s mail/provision -p 'test_*.py' -v
"""

import unittest

import check_dkim_signature_scope as check

PUBLICPRESS = "publicpress.co.uk"

BASE_HEADERS = (
    "From: noreply@publicpress.co.uk\r\n"
    "To: rob@example.net\r\n"
    "Subject: test\r\n"
    "\r\n"
    "body\r\n"
)


def _sig(domain: str, selector: str, algorithm: str = "rsa-sha256") -> str:
    return (
        f"DKIM-Signature: v=1; a={algorithm}; c=relaxed/relaxed; d={domain}; "
        f"s={selector}; h=from:to:subject; bh=AAAA; b=BBBB\r\n"
    )


def _message(*signature_lines: str) -> bytes:
    return ("".join(signature_lines) + BASE_HEADERS).encode()


class ScopedSigningPassesTests(unittest.TestCase):
    def test_one_publicpress_signature_passes(self):
        raw = _message(_sig(PUBLICPRESS, "bl"))
        ok, line = check.verdict(raw, PUBLICPRESS)
        self.assertTrue(ok)
        self.assertIn("d=publicpress.co.uk", line)


class BothKeysFailsTests(unittest.TestCase):
    """The config the owner ruled out: publicpress mail also carrying the
    branchleft.co.uk signatures. This must fail."""

    def test_publicpress_plus_two_branchleft_signatures_fails(self):
        raw = _message(
            _sig(PUBLICPRESS, "bl"),
            _sig("branchleft.co.uk", "ed", "ed25519-sha256"),
            _sig("branchleft.co.uk", "rsa"),
        )
        ok, line = check.verdict(raw, PUBLICPRESS)
        self.assertFalse(ok)
        self.assertIn("3 DKIM-Signature headers", line)

    def test_one_branchleft_signature_alone_fails(self):
        raw = _message(_sig("branchleft.co.uk", "rsa"))
        ok, line = check.verdict(raw, PUBLICPRESS)
        self.assertFalse(ok)
        self.assertIn("expected d=publicpress.co.uk", line)

    def test_two_publicpress_signatures_fail(self):
        raw = _message(_sig(PUBLICPRESS, "bl"), _sig(PUBLICPRESS, "bl2"))
        ok, _ = check.verdict(raw, PUBLICPRESS)
        self.assertFalse(ok)

    def test_no_signature_fails(self):
        ok, line = check.verdict(_message(), PUBLICPRESS)
        self.assertFalse(ok)
        self.assertIn("0 DKIM-Signature headers", line)


class DuplicateTagTests(unittest.TestCase):
    """Two d= tags in one signature: the last would win silently, so the check
    could read the branchleft.co.uk d= while the other one signs. Must fail."""

    def test_duplicate_d_in_one_signature_fails(self):
        raw = _message(
            "DKIM-Signature: v=1; a=rsa-sha256; d=branchleft.co.uk; d=publicpress.co.uk; "
            "s=bl; h=from; bh=AAAA; b=BBBB\r\n"
        )
        ok, line = check.verdict(raw, PUBLICPRESS)
        self.assertFalse(ok)
        self.assertIn("duplicate tag d=", line)

    def test_a_repeated_tag_that_is_not_d_also_fails(self):
        raw = _message(_sig(PUBLICPRESS, "bl").replace("s=bl;", "s=bl; s=other;"))
        ok, line = check.verdict(raw, PUBLICPRESS)
        self.assertFalse(ok)
        self.assertIn("duplicate tag s=", line)


class MalformedHeaderTests(unittest.TestCase):
    """A header line with no colon, or a space before the colon, ends header
    parsing early in a standard parser, so a later signature would be
    uncounted. The check must fail on the malformed line instead."""

    def test_a_line_with_no_colon_before_a_branchleft_signature_fails(self):
        raw = (
            b"From: noreply@publicpress.co.uk\r\n"
            b"this line has no colon\r\n"
            + _sig("branchleft.co.uk", "rsa").encode()
            + _sig(PUBLICPRESS, "bl").encode()
            + b"To: rob@example.net\r\n\r\nbody\r\n"
        )
        ok, line = check.verdict(raw, PUBLICPRESS)
        self.assertFalse(ok)
        self.assertIn("not a header line", line)

    def test_a_space_before_the_colon_fails(self):
        raw = (
            b"Subject : test\r\n"
            + _sig(PUBLICPRESS, "bl").encode()
            + b"From: noreply@publicpress.co.uk\r\n\r\nbody\r\n"
        )
        ok, line = check.verdict(raw, PUBLICPRESS)
        self.assertFalse(ok)
        self.assertIn("not a header line", line)

    def test_a_folded_continuation_is_not_malformed(self):
        raw = (
            b"Subject: a long\r\n subject\r\n"
            + _sig(PUBLICPRESS, "bl").encode()
            + BASE_HEADERS.encode()
        )
        ok, _ = check.verdict(raw, PUBLICPRESS)
        self.assertTrue(ok)


class ParseTests(unittest.TestCase):
    def test_tags_are_read_whatever_the_spacing(self):
        tags = check.parse_tags(" v=1;d=publicpress.co.uk ;  s=bl ")
        self.assertEqual(tags["d"], "publicpress.co.uk")
        self.assertEqual(tags["s"], "bl")

    def test_folded_header_is_read(self):
        raw = (
            b"DKIM-Signature: v=1; a=rsa-sha256; d=publicpress.co.uk;\r\n"
            b" s=bl; h=from:to; bh=AAAA; b=BBBB\r\n"
        ) + BASE_HEADERS.encode()
        ok, _ = check.verdict(raw, PUBLICPRESS)
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
