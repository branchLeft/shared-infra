#!/usr/bin/env python3
"""Unit tests for the pure parts of check_shim_image_starts.py. The container
run itself is CI-only (the shim-image-starts job); these keep its image
selection and its right-reason classification from drifting.
"""

from __future__ import annotations

import pathlib
import unittest

import check_shim_image_starts as check

DIGEST = "sha256:" + "a" * 64
IMAGE = f"ghcr.io/branchleft/mailgun-shim@{DIGEST}"


class PinnedImageTests(unittest.TestCase):
    def test_reads_the_real_compose_file_image(self):
        text = pathlib.Path(check.COMPOSE).read_text(encoding="utf-8")
        self.assertRegex(check.pinned_image(text), r"^ghcr\.io/branchleft/mailgun-shim@sha256:[0-9a-f]{64}$")

    def test_reads_the_pinned_line(self):
        self.assertEqual(IMAGE, check.pinned_image(f"services:\n  s:\n    image: {IMAGE}\n"))

    def test_refuses_a_tag_pin(self):
        with self.assertRaises(SystemExit):
            check.pinned_image("services:\n  s:\n    image: ghcr.io/branchleft/mailgun-shim:latest\n")

    def test_refuses_two_shim_lines(self):
        with self.assertRaises(SystemExit):
            check.pinned_image(f"    image: {IMAGE}\n    image: {IMAGE}\n")


class ClassifyFailureTests(unittest.TestCase):
    def test_a_missing_smtp_host_is_named(self):
        log = "Error: Missing required environment variable SMTP_HOST\n    at requireEnv"
        self.assertEqual("smtp-host-missing", check.classify_failure(log))

    def test_a_database_open_error_is_not_a_missing_smtp_host(self):
        for marker in check.MOUNT_OR_PERMISSION:
            with self.subTest(marker=marker):
                log = f"{marker}: unable to open database file"
                self.assertEqual("mount-or-permission", check.classify_failure(log))

    def test_a_permission_error_outranks_the_missing_variable_text(self):
        log = f"{check.SMTP_HOST_MISSING}\nEACCES: permission denied"
        self.assertEqual("mount-or-permission", check.classify_failure(log))

    def test_anything_else_is_other(self):
        self.assertEqual("other", check.classify_failure("Segmentation fault"))


if __name__ == "__main__":
    unittest.main()
