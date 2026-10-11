#!/usr/bin/env python3
"""Guard the S3 key split in ci.yml.

mail-* jobs read MAIL_S3_* secrets; hetzner-* jobs read HETZNER_S3_*. No job
may read both, so code running in one stack cannot reach the other's key.
ci.yml is read as text (stdlib only): jobs are the two-space keys under `jobs:`.
"""

import pathlib
import re
import unittest

CI = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"
JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
MAIL_REF = re.compile(r"\bMAIL_S3_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)\b")
HETZNER_REF = re.compile(r"\bHETZNER_S3_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)\b")
VERIFY_RE = re.compile(
    r"^      - name: Verify the deploy secrets are present\n(.*?)(?=^      - name: |\Z)",
    re.S | re.M,
)


def jobs(text):
    """Map job id to the text of its block."""
    found, current, lines, in_jobs = {}, None, [], False
    for line in text.splitlines():
        if re.match(r"^[A-Za-z]", line):
            in_jobs = line.startswith("jobs:")
            continue
        if not in_jobs:
            continue
        match = JOB_RE.match(line)
        if match:
            if current:
                found[current] = "\n".join(lines)
            current, lines = match.group(1), []
        elif current:
            lines.append(line)
    if current:
        found[current] = "\n".join(lines)
    return found


class CiS3KeySplit(unittest.TestCase):
    def setUp(self):
        self.jobs = jobs(CI.read_text(encoding="utf-8"))
        # Scope: jobs that read either S3 key family. Typecheck jobs read neither.
        def reads_s3(block):
            return bool(MAIL_REF.search(block) or HETZNER_REF.search(block))
        self.mail = {j: b for j, b in self.jobs.items() if j.startswith("mail-") and reads_s3(b)}
        self.hetzner = {j: b for j, b in self.jobs.items() if j.startswith("hetzner-") and reads_s3(b)}

    def test_expected_jobs_present(self):
        self.assertTrue({"mail-plan", "mail-apply"} <= set(self.mail), sorted(self.mail))
        self.assertTrue(
            {"hetzner-network-plan", "hetzner-network-apply", "hetzner-estate-plan", "hetzner-estate-apply"} <= set(self.hetzner),
            sorted(self.hetzner),
        )

    def test_t1_mail_jobs_use_mail_key_only(self):
        for job, block in self.mail.items():
            with self.subTest(job=job):
                self.assertRegex(block, MAIL_REF)
                self.assertNotRegex(block, HETZNER_REF)

    def test_t2_hetzner_jobs_use_hetzner_key_only(self):
        for job, block in self.hetzner.items():
            with self.subTest(job=job):
                self.assertRegex(block, HETZNER_REF)
                self.assertNotRegex(block, MAIL_REF)

    def test_t3_no_job_references_both(self):
        for job, block in self.jobs.items():
            with self.subTest(job=job):
                self.assertFalse(MAIL_REF.search(block) and HETZNER_REF.search(block))

    def test_t4_mail_verify_step_names_mail_keys(self):
        for job, block in self.mail.items():
            with self.subTest(job=job):
                match = VERIFY_RE.search(block + "\n")
                self.assertIsNotNone(match, "no verify-secrets step")
                step = match.group(1)
                self.assertIn("MAIL_S3_ACCESS_KEY_ID", step)
                self.assertIn("MAIL_S3_SECRET_ACCESS_KEY", step)
                self.assertNotIn("HETZNER_S3_", step)


if __name__ == "__main__":
    unittest.main()
