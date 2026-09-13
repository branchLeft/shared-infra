#!/usr/bin/env python3
"""Render the quarterly passphrase-drill's dated evidence comment.

`.github/workflows/passphrase-drill.yml` runs `verify-archive-passphrase.py`
once per live Hetzner-native stack in this repo, against a fresh
`pulumi stack export` of that stack's own state. Each run produces an
outcome (`PASS`/`FAIL`/`ARCHIVE`/`INCONCLUSIVE`) and a static, secret-free
detail string. This script's only job is to fold those per-stack results
into one dated Markdown comment body and decide the run's overall exit code
-- it never sees a passphrase, a salt, or anything decrypted, because
nothing upstream of it ever produces those as text.

Input is a JSON array on stdin, one object per stack:

    [{"stack": "mail", "exit_code": 0, "outcome": "PASS", "detail": "..."}]

`stack`, `outcome` and `detail` come straight from `verify-archive-passphrase.py
--json`'s own `archive`/`outcome`/`detail` fields (the workflow substitutes
its own stack label for the archive filename, since a live export's
filename carries no repository context). `exit_code` is that script's own
exit status for the run, needed here because `--json` reports the outcome
label but not the process exit code alongside it.

Exit code is the worst of the given outcomes, in the same order
`verify-archive-passphrase.py` uses (`FAIL` > `ARCHIVE` > `INCONCLUSIVE` >
`PASS`), imported from it directly rather than restated here -- a change to
that ordering must not silently diverge between the two scripts.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_verifier_module():
    """Load `verify-archive-passphrase.py` despite the hyphen in its name.

    A hyphenated filename is not a legal module name, so a plain `import`
    cannot reach it; `importlib` loads it from its path instead. This keeps
    the severity ordering (`FAIL` > `ARCHIVE` > `INCONCLUSIVE` > `PASS`) and
    the exit-code constants defined in exactly one place, so a future change
    there cannot silently diverge between the two scripts.
    """
    path = Path(__file__).resolve().parent / "verify-archive-passphrase.py"
    spec = importlib.util.spec_from_file_location("verify_archive_passphrase", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_verifier = _load_verifier_module()
EXIT_PASS = _verifier.EXIT_PASS
SEVERITY = _verifier.SEVERITY
plural = _verifier.plural


def worst_outcome(results: list[dict]) -> int:
    outcomes = [r["exit_code"] for r in results]
    for code in SEVERITY:
        if code in outcomes:
            return code
    return EXIT_PASS


def render(date: str, repo_label: str, results: list[dict]) -> str:
    if not results:
        raise ValueError("no results to render")

    lines = [f"## Passphrase drill — {date}", ""]
    width = max(len(r["stack"]) for r in results)
    outcome_width = max(len(r["outcome"]) for r in results)
    for r in results:
        lines.append(
            f"- `{r['stack']:<{width}}`  **{r['outcome']:<{outcome_width}}**  {r['detail']}"
        )

    lines.append("")
    bad = [r for r in results if r["outcome"] != "PASS"]
    if not bad:
        lines.append(f"All {plural(len(results), 'stack')} in {repo_label} opened with their escrowed passphrase.")
    else:
        lines.append(
            f"{plural(len(bad), 'stack')} in {repo_label} did not PASS this run — "
            "see the detail above; never a plaintext value, only the verifier's own classification."
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--date", required=True, help="the run's date, e.g. 2026-09-13")
    parser.add_argument("--repo-label", required=True, help="e.g. branchLeft/shared-infra")
    args = parser.parse_args(argv)

    try:
        results = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"error: stdin is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if not isinstance(results, list) or not results:
        print("error: expected a non-empty JSON array of per-stack results", file=sys.stderr)
        return 2

    for r in results:
        missing = {"stack", "exit_code", "outcome", "detail"} - set(r)
        if missing:
            print(f"error: result missing field(s): {sorted(missing)}", file=sys.stderr)
            return 2

    print(render(args.date, args.repo_label, results))
    return worst_outcome(results)


if __name__ == "__main__":
    sys.exit(main())
