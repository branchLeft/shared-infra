"""Pin tests for publish-hetzner-host.yml: it attests the tarball it publishes, and holds no more than that needs.

The workflow is parsed with the strict loader from test_workflow_concurrency, never
grepped, except the one `uses:` line, whose version comment a parser drops.
problems() is the whole set of pins, so a damaged copy of the file can be fed to
it. The rules are written up in test_publish_hetzner_host.md.
"""

from __future__ import annotations

import pathlib
import re
import unittest
from collections.abc import Callable

import test_workflow_concurrency as concurrency_rules

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "publish-hetzner-host.yml"

ATTEST_ACTION = "branchLeft/github-workflows/.github/actions/attest-npm-tarball"
ATTEST_SHA = "a2175a416b57f950fed891837f88f2d1a31e00f4"
ATTEST_USES = re.compile(
    rf"^\s*uses:\s*{re.escape(ATTEST_ACTION)}@(?P<ref>\S+)\s*(?P<comment>#.*)?$",
    re.MULTILINE,
)
PINNED_COMMENT = re.compile(r"^#\s*v1\.2\.0\s*$")
JOB = "publish"
JOB_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "write",
    "attestations": "write",
}
TARBALL_NAME = "hetzner-host.tgz"
PUBLISH_COMMAND = f"pnpm publish ./{TARBALL_NAME} --no-git-checks"
PACK_COMMAND = f"pnpm pack --out ./{TARBALL_NAME}"
ATTEST_WITH = {
    "tarball": f"hetzner-host/{TARBALL_NAME}",
    "repo": "branchLeft/shared-infra",
    "signer-workflow": "branchLeft/shared-infra/.github/workflows/publish-hetzner-host.yml",
    "ref": "${{ steps.attest-ref.outputs.ref }}",
}
NPM_PUBLISH = re.compile(r"\b(?:pnpm|npm)\s+publish\b")


def parse(text: str) -> dict[str, object]:
    data = concurrency_rules.load(text)
    if not isinstance(data, dict):
        raise TypeError("workflow is not a mapping")
    return data


def steps_of(data: dict[str, object]) -> list[dict[str, object]]:
    return data["jobs"][JOB]["steps"]  # type: ignore[index]


def index_of(
    steps: list[dict[str, object]], predicate: Callable[[dict[str, object]], bool]
) -> int | None:
    for position, step in enumerate(steps):
        if predicate(step):
            return position
    return None


def is_attest(step: dict[str, object]) -> bool:
    return str(step.get("uses", "")).startswith(ATTEST_ACTION + "@")


def runs(step: dict[str, object], command: str) -> bool:
    return str(step.get("run", "")).strip() == command


def problems(text: str, *, other_workflows: dict[str, str] | None = None) -> list[str]:
    found: list[str] = []
    try:
        data = parse(text)
        jobs = data["jobs"]
        steps = steps_of(data)
    except (KeyError, TypeError, ValueError) as error:
        return [f"workflow shape: {error!r}"]

    if list(jobs) != [JOB]:  # type: ignore[arg-type]
        found.append(f"jobs must be exactly [{JOB!r}]")
    if data.get("permissions") != {"contents": "read"}:
        found.append(
            f"top-level permissions must be exactly contents: read, found {data.get('permissions')!r}"
        )
    if jobs[JOB].get("permissions") != JOB_PERMISSIONS:  # type: ignore[index]
        found.append(
            f"job permissions must be exactly {JOB_PERMISSIONS}, found {jobs[JOB].get('permissions')!r}"
        )  # type: ignore[index]

    attest = [step for step in steps if is_attest(step)]
    if len(attest) != 1:
        found.append(f"exactly one attest step required, found {len(attest)}")
        return found
    step = attest[0]
    lines = ATTEST_USES.findall(text)
    if (
        len(lines) != 1
        or lines[0][0] != ATTEST_SHA
        or not PINNED_COMMENT.match(lines[0][1] or "")
    ):
        found.append(
            f"the attest step must be pinned to {ATTEST_SHA} with a `# v1.2.0` comment, found {lines}"
        )
    if step.get("with") != ATTEST_WITH:
        found.append(
            f"attest inputs must be exactly {ATTEST_WITH}, found {step.get('with')!r}"
        )
    for key in ("if", "continue-on-error"):
        if key in step:
            found.append(f"the attest step must not carry {key}")

    pack = index_of(steps, lambda s: runs(s, PACK_COMMAND))
    publish = index_of(steps, lambda s: runs(s, PUBLISH_COMMAND))
    ref = index_of(steps, lambda s: s.get("id") == "attest-ref")
    attest_at = index_of(steps, is_attest)
    if pack is None:
        found.append(f"a pack step running `{PACK_COMMAND}` is required")
    if publish is None:
        found.append(f"a publish step running `{PUBLISH_COMMAND}` is required")
    if ref is None:
        found.append("the attest-ref step is required")
    if None not in (pack, ref, attest_at, publish) and not (
        pack < ref < attest_at < publish
    ):  # type: ignore[operator]
        found.append("order must be pack, attest-ref, attest, publish")
    if publish is not None and steps[publish].get("env") != {
        "NODE_AUTH_TOKEN": "${{ secrets.GITHUB_TOKEN }}"
    }:
        found.append(
            "the publish credential must be the run's GITHUB_TOKEN as NODE_AUTH_TOKEN, unchanged"
        )
    if sum(1 for s in steps if NPM_PUBLISH.search(str(s.get("run", "")))) != 1:
        found.append("exactly one step may publish")

    for name, other in (other_workflows or {}).items():
        if NPM_PUBLISH.search(other) and ATTEST_ACTION not in other:
            found.append(f"{name} publishes an npm package and has no attest step")
    return found


def other_workflow_texts() -> dict[str, str]:
    return {
        path.name: path.read_text()
        for path in concurrency_rules.workflow_files()
        if path != WORKFLOW
    }


class PublishHetznerHostPinTests(unittest.TestCase):
    def test_the_real_workflow_holds_every_pin_and_no_other_workflow_publishes_unattested(
        self,
    ) -> None:
        self.assertEqual(
            problems(WORKFLOW.read_text(), other_workflows=other_workflow_texts()), []
        )


class PublishHetznerHostSabotageTests(unittest.TestCase):
    """Each pin goes red when its control is broken in a copy of the file."""

    def setUp(self) -> None:
        self.text = WORKFLOW.read_text()

    def mutate(self, old: str, new: str) -> str:
        self.assertEqual(self.text.count(old), 1, old)
        return self.text.replace(old, new)

    def assert_red(self, text: str, fragment: str) -> None:
        self.assertTrue(
            any(fragment in item for item in problems(text)), problems(text)
        )

    def test_removing_the_attest_step_is_red(self) -> None:
        start = self.text.index("      # A composite action's steps start")
        end = self.text.index("      # `--no-git-checks` stays")
        self.assert_red(self.text[:start] + self.text[end:], "exactly one attest step")

    def test_a_tag_instead_of_a_sha_is_red(self) -> None:
        self.assert_red(
            self.mutate(f"@{ATTEST_SHA} # v1.2.0", "@v1.2.0"), "must be pinned"
        )

    def test_a_sha_with_no_version_comment_is_red(self) -> None:
        self.assert_red(
            self.mutate(f"@{ATTEST_SHA} # v1.2.0", f"@{ATTEST_SHA}"), "must be pinned"
        )

    def test_dropping_id_token_is_red(self) -> None:
        self.assert_red(self.mutate("      id-token: write\n", ""), "job permissions")

    def test_widening_a_permission_is_red(self) -> None:
        self.assert_red(
            self.mutate(
                "      attestations: write\n",
                "      attestations: write\n      actions: write\n",
            ),
            "job permissions",
        )

    def test_a_signing_permission_at_the_top_level_is_red(self) -> None:
        self.assert_red(
            self.mutate(
                "permissions:\n  contents: read\n\njobs:",
                "permissions:\n  contents: read\n  id-token: write\n\njobs:",
            ),
            "top-level permissions",
        )

    def test_publishing_the_package_directory_instead_of_the_tarball_is_red(
        self,
    ) -> None:
        self.assert_red(
            self.mutate(f"run: {PUBLISH_COMMAND}", "run: pnpm publish --no-git-checks"),
            "publish step running",
        )

    def test_publishing_before_attesting_is_red(self) -> None:
        text = self.text
        publish_at = text.index("      # `--no-git-checks` stays")
        publish = text[publish_at:]
        attest_at = text.index("      # A composite action's steps start")
        moved = text[:attest_at] + publish + text[attest_at:publish_at]
        self.assert_red(moved, "order must be")

    def test_an_identity_read_from_the_triggering_ref_is_red(self) -> None:
        self.assert_red(
            self.mutate("${{ steps.attest-ref.outputs.ref }}", "${{ github.ref }}"),
            "attest inputs",
        )

    def test_continue_on_error_on_the_attest_step_is_red(self) -> None:
        self.assert_red(
            self.mutate(
                "        with:\n          tarball:",
                "        continue-on-error: true\n        with:\n          tarball:",
            ),
            "must not carry continue-on-error",
        )

    def test_a_new_unattested_publish_workflow_is_red(self) -> None:
        extra = {
            "publish-other.yml": "jobs:\n  p:\n    steps:\n      - run: pnpm publish\n"
        }
        self.assertTrue(
            any(
                "no attest step" in item
                for item in problems(self.text, other_workflows=extra)
            )
        )


if __name__ == "__main__":
    unittest.main()
