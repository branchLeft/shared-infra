"""Check results, secret scrubbing and the job-summary text for the probe.

Nothing here talks to a network. The table is the only place a check's outcome
is turned into words, so a check that did not pass cannot be shown as a pass.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass

# Every code the table must hold exactly once, in this order.
EXPECTED_CODES: tuple[str, ...] = ("P1", "P2", "P3", "P4", "P5", "P6")

MASK = "***"


class Status(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"  # the check ran and the platform did something other than expected
    ERROR = "ERROR"  # the check could not be carried out, so it proves nothing


@dataclass(frozen=True)
class CheckResult:
    code: str
    title: str
    status: Status
    detail: str


def scrub(text: str, secrets: Iterable[str]) -> str:
    """Replaces every non-trivial secret value in `text`, longest first."""
    cleaned = text
    for value in sorted({s for s in secrets if len(s) >= 4}, key=len, reverse=True):
        cleaned = cleaned.replace(value, MASK)
    return cleaned


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def complete(results: Iterable[CheckResult]) -> list[CheckResult]:
    """One row per expected code, in order. A code with no result is an ERROR row."""
    by_code: dict[str, CheckResult] = {}
    for result in results:
        by_code.setdefault(result.code, result)
    rows: list[CheckResult] = []
    for code in EXPECTED_CODES:
        rows.append(
            by_code.get(
                code,
                CheckResult(
                    code, "(no result)", Status.ERROR, "the check did not report"
                ),
            )
        )
    return rows


def all_passed(results: Iterable[CheckResult]) -> bool:
    return all(row.status is Status.PASS for row in complete(results))


def render_table(results: Iterable[CheckResult]) -> str:
    rows = complete(results)
    lines = [
        "| Check | What it proves | Result | Observed |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| {_cell(row.code)} | {_cell(row.title)} | **{row.status.value}** | {_cell(row.detail)} |"
        )
    passed = sum(1 for row in rows if row.status is Status.PASS)
    verdict = "ALL CHECKS PASSED" if passed == len(rows) else "NOT ALL CHECKS PASSED"
    lines.append("")
    lines.append(f"{verdict}: {passed} of {len(rows)} passed.")
    return "\n".join(lines)


@dataclass(frozen=True)
class Leftover:
    kind: str
    name: str


def render_cleanup(
    destroyed: Iterable[str], leftovers: Iterable[Leftover], note: str = ""
) -> str:
    """The cleanup section. It says plainly whether everything was destroyed."""
    gone = list(destroyed)
    left = list(leftovers)
    lines: list[str] = []
    if left:
        lines.append(
            f"**NOT EVERYTHING WAS DESTROYED: {len(left)} resource(s) remain.**"
        )
        lines.append("")
        lines.append("| Leftover | Name |")
        lines.append("| --- | --- |")
        for item in left:
            lines.append(f"| {_cell(item.kind)} | {_cell(item.name)} |")
        lines.append("")
        lines.append(
            "Delete these by hand in the OVHcloud project before the next run."
        )
    else:
        lines.append(
            f"**Everything was destroyed: {len(gone)} resource(s) removed, none remain.**"
        )
        if gone:
            lines.append("")
            lines.append(", ".join(f"`{_cell(name)}`" for name in gone))
    if note:
        lines.append("")
        lines.append(_cell(note))
    return "\n".join(lines)
