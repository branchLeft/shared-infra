"""Registry pulls for the proofs: one retry, then a loud failure.

A shared runner can time out on a registry pull, so a pull is tried three times,
five seconds apart, and then the proof stops. No try is skipped. The proofs import
this module; none of them copies the retry.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from subprocess import DEVNULL

from lib.proof_harness import ProofAbort

ATTEMPTS = 3
PAUSE_SECONDS = 5.0


def _pull_once(image: str) -> bool:
    return (
        subprocess.run(
            ["docker", "pull", "-q", image], stdout=DEVNULL, check=False
        ).returncode
        == 0
    )


def pull_with_retry(
    image: str,
    *,
    pull: Callable[[str], bool] = _pull_once,
    pause: Callable[[float], None] = time.sleep,
) -> None:
    """Pull image, retrying up to ATTEMPTS times. After the last failed try, abort the proof."""
    attempt = 1
    while not pull(image):
        if attempt >= ATTEMPTS:
            raise ProofAbort(f"could not pull {image} after {attempt} attempts")
        attempt += 1
        pause(PAUSE_SECONDS)


def ensure_image(image: str) -> None:
    """Pull image only when docker image inspect cannot find it locally."""
    present = (
        subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=DEVNULL,
            stderr=DEVNULL,
            check=False,
        ).returncode
        == 0
    )
    if not present:
        pull_with_retry(image)
