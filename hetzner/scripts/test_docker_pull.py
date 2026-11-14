#!/usr/bin/env python3
"""Unit tests for the registry pull retry the Docker proofs share.

The retry is the only thing between a flaky registry and a proof that stops
loudly, so its three tries, its pauses and its abort are driven here through a
fake pull and a fake pause. No docker, no network.
"""

from __future__ import annotations

import unittest
from unittest import mock

from lib import docker_pull
from lib.docker_pull import ATTEMPTS, PAUSE_SECONDS, ensure_image, pull_with_retry
from lib.proof_harness import ProofAbort

IMAGE = "example/probe:1"


class FakePull:
    """Answers a scripted sequence of pull outcomes and records every call."""

    def __init__(self, outcomes: list[bool]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[str] = []

    def __call__(self, image: str) -> bool:
        self.calls.append(image)
        return self.outcomes.pop(0)


class PullWithRetry(unittest.TestCase):
    def setUp(self) -> None:
        self.pauses: list[float] = []

    def pause(self, seconds: float) -> None:
        self.pauses.append(seconds)

    def test_three_tries_and_five_second_pauses_are_the_policy(self) -> None:
        self.assertEqual(ATTEMPTS, 3)
        self.assertEqual(PAUSE_SECONDS, 5.0)

    def test_a_first_try_success_pulls_once_and_does_not_pause(self) -> None:
        pull = FakePull([True])
        pull_with_retry(IMAGE, pull=pull, pause=self.pause)
        self.assertEqual(pull.calls, [IMAGE])
        self.assertEqual(self.pauses, [])

    def test_a_success_on_the_third_try_pulls_three_times_and_pauses_twice(
        self,
    ) -> None:
        pull = FakePull([False, False, True])
        pull_with_retry(IMAGE, pull=pull, pause=self.pause)
        self.assertEqual(len(pull.calls), 3)
        self.assertEqual(self.pauses, [5.0, 5.0])

    def test_no_success_aborts_after_three_tries_with_the_named_message(self) -> None:
        pull = FakePull([False, False, False])
        with self.assertRaises(ProofAbort) as raised:
            pull_with_retry(IMAGE, pull=pull, pause=self.pause)
        self.assertEqual(
            str(raised.exception), f"could not pull {IMAGE} after 3 attempts"
        )
        self.assertEqual(len(pull.calls), 3)
        self.assertEqual(self.pauses, [5.0, 5.0])


class EnsureImage(unittest.TestCase):
    def test_a_local_image_is_not_pulled(self) -> None:
        completed = mock.Mock(returncode=0)
        with (
            mock.patch.object(
                docker_pull.subprocess, "run", return_value=completed
            ) as run,
            mock.patch.object(docker_pull, "pull_with_retry") as pull,
        ):
            ensure_image(IMAGE)
        pull.assert_not_called()
        self.assertEqual(run.call_args.args[0], ["docker", "image", "inspect", IMAGE])

    def test_a_missing_image_is_pulled_with_the_retry(self) -> None:
        completed = mock.Mock(returncode=1)
        with (
            mock.patch.object(docker_pull.subprocess, "run", return_value=completed),
            mock.patch.object(docker_pull, "pull_with_retry") as pull,
        ):
            ensure_image(IMAGE)
        pull.assert_called_once_with(IMAGE)


if __name__ == "__main__":
    unittest.main()
