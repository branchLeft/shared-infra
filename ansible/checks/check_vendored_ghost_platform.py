"""Check demo1's vendored files are the bytes ghost-platform has at the pinned commit.

demo1_build and demo1_egress_spool carry copies of ghost-platform files under
files/ghost-platform, at the paths they have upstream, and pin each copy's sha256 in this
repository. The role holds a file to its pin on the host, and test_demo1_no_github_fetch holds the
file list to the pins, but a file and its pin changed together pass both. This check closes that:
it reads each role's `<role>_source_sha`, fetches that commit of branchLeft/ghost-platform, and
fails, naming the file, when any vendored file differs from the same path at that commit by even
one byte, or when the commit has no such file.

The bytes are read with `git cat-file blob`, so no checkout filter (line endings, attributes)
can make a changed file look the same. A role with no vendored file fails too: a check that
compares nothing passes everything.

The fetch is the runner's, over HTTPS, of one public commit and no credential; demo1's own
allowlist is untouched. `--upstream ROLE=DIR` reads the commit from a local clone instead.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ROLES_DIR = Path("ansible/roles")
VENDORED = Path("files/ghost-platform")
# The roles that carry upstream files. The pin of each is `<role>_source_sha` in its defaults.
ROLES = ("demo1_build", "demo1_egress_spool")
UPSTREAM_URL = "https://github.com/branchLeft/ghost-platform.git"
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
GIT_TIMEOUT_SECONDS = 120


class VendoredCheckError(Exception):
    """The check cannot read what it compares, so it cannot say the files agree."""


def refuse(message: str) -> NoReturn:
    """Stop the check with a message.

    Raises:
        VendoredCheckError: always, carrying the message.
    """
    raise VendoredCheckError(message)


def run_git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    """Run git in ``repo`` and return the completed process, whatever its status.

    Raises:
        VendoredCheckError: git cannot be run or does not finish.
    """
    try:
        return subprocess.run(  # noqa: S603 - fixed program, arguments are not shell-parsed
            ["git", "-C", str(repo), *args],  # noqa: S607 - git on PATH is the runner's
            capture_output=True,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
            env={
                "GIT_TERMINAL_PROMPT": "0",
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(repo),
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        refuse(f"git {args[0]} did not run: {type(error).__name__}")


def read_pin(role_dir: Path, role: str) -> str:
    """Return the commit ``<role>_source_sha`` names in the role's defaults.

    Raises:
        VendoredCheckError: the defaults are missing or do not hold exactly one 40-hex pin.
    """
    path = role_dir / "defaults" / "main.yml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        refuse(f"{path} cannot be read: {type(error).__name__}")
    found: list[str] = re.findall(
        rf"^{role}_source_sha:\s*['\"]?([^'\"\s#]+)['\"]?\s*(?:#.*)?$", text, re.M
    )
    if len(found) != 1 or not SHA_PATTERN.fullmatch(found[0]):
        refuse(f"{path} does not set {role}_source_sha to one 40-hex commit")
    return found[0]


def vendored_files(role_dir: Path) -> list[str]:
    """Return every file under the role's files/ghost-platform, as paths from the upstream root."""
    base = role_dir / VENDORED
    return sorted(item.relative_to(base).as_posix() for item in base.rglob("*") if item.is_file())


def upstream_blob(repo: Path, sha: str, path: str) -> bytes | None:
    """Return the bytes of ``path`` at ``sha`` in ``repo``, or None when there is no such file."""
    result = run_git(repo, "cat-file", "blob", f"{sha}:{path}")
    return result.stdout if result.returncode == 0 else None


def compare_role(role_dir: Path, role: str, repo: Path) -> list[str]:
    """Return one finding for each vendored file of ``role`` that is not upstream's at its pin."""
    sha = read_pin(role_dir, role)
    files = vendored_files(role_dir)
    if not files:
        return [f"{role}: no file under {VENDORED}, so nothing was compared"]
    if run_git(repo, "cat-file", "-e", f"{sha}^{{commit}}").returncode != 0:
        return [f"{role}: commit {sha} is not in the upstream repository"]
    findings: list[str] = []
    for path in files:
        upstream = upstream_blob(repo, sha, path)
        local = (role_dir / VENDORED / path).read_bytes()
        if upstream is None:
            findings.append(f"{role}: {path} is not in ghost-platform at {sha}")
        elif upstream != local:
            findings.append(f"{role}: {path} differs from ghost-platform at {sha}")
    return findings


def fetch_commit(sha: str, url: str, into: Path) -> Path:
    """Fetch the one commit ``sha`` from ``url`` into a new repository in ``into`` and return it.

    Raises:
        VendoredCheckError: the commit cannot be fetched.
    """
    into.mkdir(parents=True, exist_ok=True)
    for args in (("init", "--quiet"), ("fetch", "--quiet", "--depth", "1", url, sha)):
        result = run_git(into, *args)
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip().splitlines()[-1:]
            refuse(f"git {args[0]} of {sha} from {url} failed: {detail}")
    return into


def run_checks(root: Path, upstream: dict[str, Path], url: str) -> list[str]:
    """Return every finding for both roles, fetching a commit unless ``upstream`` has a clone."""
    findings: list[str] = []
    with tempfile.TemporaryDirectory(prefix="vendored-ghost-platform-") as scratch:
        for role in ROLES:
            role_dir = root / ROLES_DIR / role
            try:
                repo = upstream.get(role) or fetch_commit(
                    read_pin(role_dir, role), url, Path(scratch) / role
                )
                findings.extend(compare_role(role_dir, role, repo))
            except VendoredCheckError as error:
                findings.append(f"{role}: {error}")
    return findings


def parse_upstream(values: Sequence[str]) -> dict[str, Path]:
    """Parse ``ROLE=DIR`` arguments.

    Raises:
        VendoredCheckError: an argument is not ROLE=DIR for one of the two roles.
    """
    parsed: dict[str, Path] = {}
    for value in values:
        role, _, directory = value.partition("=")
        if role not in ROLES or not directory:
            refuse(f"--upstream wants ROLE=DIR with ROLE one of {ROLES}")
        parsed[role] = Path(directory)
    return parsed


def main(argv: Sequence[str]) -> int:
    """Print every finding and return 1 if there is one."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", maxsplit=1)[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root to check")
    parser.add_argument("--url", default=UPSTREAM_URL, help="where to fetch ghost-platform from")
    parser.add_argument(
        "--upstream", action="append", default=[], metavar="ROLE=DIR", help="a local clone to read"
    )
    args = parser.parse_args(argv)
    try:
        findings = run_checks(args.root, parse_upstream(args.upstream), args.url)
    except VendoredCheckError as error:
        findings = [str(error)]
    for finding in findings:
        print(f"FAIL {finding}")
    print(f"check_vendored_ghost_platform: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
