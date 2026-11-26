"""The delivery workflow queues behind an earlier run in one group, and the drift check stays out.

Removing the key, renaming the group or cancelling in progress fails here. The nightly drift
check must not carry a workflow-level concurrency key: a newer pending run replaces an older
pending one, so a drift run queued behind an approval-waiting delivery would evict that delivery.
The drift check's plan jobs are serialised by the reusable workflow's ansible-plan group
(branchLeft/workspace#3053), not here.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from check_pins import load_yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DELIVERY = ".github/workflows/ansible-delivery.yml"
DRIFT = ".github/workflows/ansible-drift-check.yml"
CONCURRENCY = {"group": "ansible-delivery-hosts", "cancel-in-progress": False}


def workflow_mapping(relative: str) -> dict[str, object]:
    document, problem = load_yaml(REPO_ROOT / relative)
    if problem is not None:
        raise AssertionError(problem)
    if not isinstance(document, dict):
        raise AssertionError(f"{relative} is not a mapping")
    return document


class DeliveryConcurrencyTests(unittest.TestCase):
    def test_delivery_is_queued_in_its_own_group(self) -> None:
        self.assertEqual(CONCURRENCY, workflow_mapping(DELIVERY).get("concurrency"))

    def test_the_drift_check_is_not_in_the_delivery_group(self) -> None:
        self.assertNotIn("concurrency", workflow_mapping(DRIFT))

    def test_a_missing_key_fails_the_rule(self) -> None:
        # Sabotage check: the rule, applied to a document without the key, must fail.
        document: dict[str, object] = {"name": "x", "on": {"push": None}}
        self.assertNotEqual(CONCURRENCY, document.get("concurrency"))


if __name__ == "__main__":
    unittest.main()
