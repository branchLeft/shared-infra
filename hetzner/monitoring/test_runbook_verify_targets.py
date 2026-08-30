#!/usr/bin/env python3
"""Prometheus.yml is renderer-verified (render.test.ts's file-snapshot
assertion), so reading the committed file is as reliable as calling the
TypeScript renderer, without a second toolchain in a Python test. Checks
that every job_name it declares is named in RUNBOOK-monitoring.md §8 --
not a full re-derivation of which targets are up/down.
"""

import pathlib
import re
import unittest

MONITORING = pathlib.Path(__file__).resolve().parent
HETZNER = MONITORING.parent
RUNBOOK = HETZNER / "RUNBOOK-monitoring.md"
PROMETHEUS_CONFIG = MONITORING / "stack" / "prometheus" / "prometheus.yml"

JOB_NAME = re.compile(r"^\s*-\s*job_name:\s*(\S+)\s*$", re.MULTILINE)
SECTION_8 = re.compile(
    r"^## 8\. Verify the stack is up\n(.*?)(?=^## \d+\.)", re.MULTILINE | re.DOTALL
)
# Strip fenced code blocks before locating headings: an `## N.`-shaped line
# inside a fence (a shell comment, say) would otherwise satisfy the section
# boundary lookahead and truncate the captured prose early.
FENCED_CODE_BLOCK = re.compile(r"^```[^\n]*\n.*?^```[ \t]*$\n?", re.MULTILINE | re.DOTALL)


def rendered_job_names() -> list[str]:
    text = PROMETHEUS_CONFIG.read_text(encoding="utf-8")
    # YAML permits `job_name: website` and `job_name: 'website'` interchangeably;
    # strip a quoted value's quotes so both forms compare equal to the
    # unquoted backtick token the runbook prose uses.
    return [name.strip("'\"") for name in JOB_NAME.findall(text)]


def section_8_text() -> str:
    text = FENCED_CODE_BLOCK.sub("", RUNBOOK.read_text(encoding="utf-8"))
    match = SECTION_8.search(text)
    if match is None:
        raise AssertionError("could not find a '## 8. Verify the stack is up' section "
                              "followed by another numbered '## N.' heading")
    return match.group(1)


class RunbookVerifyTargetsTests(unittest.TestCase):
    def test_the_job_names_and_the_section_were_actually_found(self):
        """A regex that stopped matching would otherwise pass every
        assertion below by finding nothing to check."""
        jobs = rendered_job_names()
        self.assertEqual(
            sorted(jobs),
            sorted(
                [
                    "prometheus",
                    "alertmanager",
                    "caddy",
                    "crowdsec",
                    "website",
                    "node",
                    "mysqld",
                    "cadvisor",
                    "blackbox_http",
                    "blackbox_mail",
                ]
            ),
            "prometheus.yml's job_name list changed shape -- update the "
            "expectation above and RUNBOOK-monitoring.md §8 together",
        )
        self.assertGreater(len(section_8_text().strip()), 0)

    def test_every_rendered_job_name_is_named_in_section_8(self):
        jobs = rendered_job_names()
        # Self-contained on purpose, duplicating the sibling test's non-empty
        # check: run this method alone (a single `-k`, an IDE click) and a
        # regex that stopped matching still fails loudly instead of iterating
        # zero subTests and reporting a pass.
        self.assertTrue(jobs, "rendered_job_names() found nothing to check")
        section = section_8_text()
        for job in jobs:
            with self.subTest(job=job):
                self.assertIn(
                    f"`{job}`",
                    section,
                    f"prometheus.yml declares job_name '{job}' but "
                    "RUNBOOK-monitoring.md §8 never mentions it -- an operator "
                    "reading the checklist would see an unexplained extra "
                    "target on the host.",
                )


if __name__ == "__main__":
    unittest.main()
