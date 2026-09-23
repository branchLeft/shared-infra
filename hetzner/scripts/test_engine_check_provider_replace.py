#!/usr/bin/env python3
"""Tests for the pure parts of engine-check-provider-replace.

The scenarios themselves need a Pulumi state import, which only the platform
owner runs. What is checked here is what would make that run lie: a seeded
checkpoint whose resources point at a provider that is not in it, or an
operation filter that misses a replacement.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "engine_check_provider_replace", HERE / "engine-check-provider-replace.py"
)
check = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = check
spec.loader.exec_module(check)


class Checkpoint(unittest.TestCase):
    def test_every_resource_references_the_seeded_provider(self):
        for seeded in ("explicit", "default"):
            resources = check.checkpoint("s", seeded)["deployment"]["resources"]
            provider = next(r for r in resources if r["type"] == "pulumi:providers:hcloud")
            ref = f"{provider['urn']}::{provider['id']}"
            customs = [r for r in resources if r["custom"] and r is not provider]
            self.assertEqual(len(customs), 2)
            for resource in customs:
                self.assertEqual(resource["provider"], ref)

    def test_explicit_state_carries_the_old_token_and_the_program_name(self):
        resources = check.checkpoint("s", "explicit")["deployment"]["resources"]
        provider = resources[1]
        self.assertTrue(provider["urn"].endswith("::hcloud-tenants"))
        self.assertEqual(provider["inputs"]["token"], check.FAKE_A)
        self.assertNotEqual(check.FAKE_A, check.FAKE_B)
        self.assertIn("'hcloud-tenants'", check.PROGRAM)

    def test_default_state_uses_the_default_provider_urn(self):
        resources = check.checkpoint("s", "default")["deployment"]["resources"]
        self.assertTrue(resources[1]["urn"].endswith("::default_1_41_0"))
        self.assertNotIn("token", resources[1]["inputs"])


class Replacements(unittest.TestCase):
    def test_counts_every_replacing_operation(self):
        steps = [
            ("same", "a"),
            ("update", "b"),
            ("replace", "c"),
            ("create-replacement", "d"),
            ("delete-replaced", "e"),
            ("delete", "f"),
            ("create", "g"),
        ]
        self.assertEqual(
            check.replacements(steps),
            [("replace", "c"), ("create-replacement", "d"), ("delete-replaced", "e"), ("delete", "f")],
        )

    def test_nothing_replacing_is_empty(self):
        self.assertEqual(check.replacements([("same", "a"), ("update", "b")]), [])


if __name__ == "__main__":
    unittest.main()
