"""The delivery and the drift check share one concurrency group (ansible-delivery-hosts).

Both take the per-host flock, so a run must queue behind an earlier one and never cancel it.
Removing the key, renaming the group or cancelling in progress fails here. The GitHub behaviour
the group accepts (one pending run, replaced by a newer one) is in the PR body, not in a test.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from check_pins import load_yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOWS = (
    ".github/workflows/ansible-delivery.yml",
    ".github/workflows/ansible-drift-check.yml",
)
CONCURRENCY = {"group": "ansible-delivery-hosts", "cancel-in-progress": False}


def concurrency_of(relative: str) -> object:
    document, problem = load_yaml(REPO_ROOT / relative)
    if problem is not None:
        raise AssertionError(problem)
    if not isinstance(document, dict):
        raise AssertionError(f"{relative} is not a mapping")
    return document.get("concurrency")


class DeliveryConcurrencyTests(unittest.TestCase):
    def test_delivery_and_drift_check_share_one_queued_group(self) -> None:
        for relative in WORKFLOWS:
            with self.subTest(workflow=relative):
                self.assertEqual(CONCURRENCY, concurrency_of(relative))

    def test_a_missing_key_is_named(self) -> None:
        # Sabotage check: the same rule applied to a document without the key must fail.
        document: dict[str, object] = {"name": "x", "on": {"push": None}}
        self.assertNotEqual(CONCURRENCY, document.get("concurrency"))


if __name__ == "__main__":
    unittest.main()
