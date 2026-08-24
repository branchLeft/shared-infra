#!/usr/bin/env python3
"""`RUNBOOK-monitoring.md` §8 ("Verify the stack is up") is hand-maintained
prose that names every Prometheus scrape job an operator should expect to
see. It drifted once already: `#38` added the `website` job and nobody
updated the runbook (`#50`).

`render.test.ts`'s `toMatchFileSnapshot` already keeps
`stack/prometheus/prometheus.yml` byte-identical to what
`renderPrometheusConfig()` emits, so the committed file is as reliable a
source for "what job names actually exist" as calling the renderer directly
-- and reading it here avoids spawning Node from a Python test, the same
by-path-not-by-subprocess preference `test_render_alertmanager_config.py`
in this directory documents.

This does not attempt a full derivation of §8's prose (which host is
`up`/`down`, why) -- that would reproduce `MONITORED_NODE_HOSTS`'s
`expected_up` membership in a second language and go stale on its own. It
asserts the narrower, still load-bearing thing: every `job_name` the rendered
config declares is named somewhere in §8. A job present on the host and
absent from the checklist is exactly what shipped un-caught last time.
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


def rendered_job_names() -> list[str]:
    text = PROMETHEUS_CONFIG.read_text(encoding="utf-8")
    return JOB_NAME.findall(text)


def section_8_text() -> str:
    text = RUNBOOK.read_text(encoding="utf-8")
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
                ]
            ),
            "prometheus.yml's job_name list changed shape -- update the "
            "expectation above and RUNBOOK-monitoring.md §8 together",
        )
        self.assertGreater(len(section_8_text().strip()), 0)

    def test_every_rendered_job_name_is_named_in_section_8(self):
        section = section_8_text()
        for job in rendered_job_names():
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
