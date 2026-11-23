#!/usr/bin/env python3
"""Mint the tenant portal's Professional enquiry submission credential (send-as sales@).

The same provisioner as 60 and 62, run with the portal's own send-as account, credential label
and description. The logic and its idempotence live in provision_website_submission_credential.py;
this file only sets the three values that differ. The mail_reconcilers role runs it as the
"portal" row of its mint table, so it is placed beside the provisioner in /root/mail-provision.
"""

from __future__ import annotations

import os
import runpy
from pathlib import Path

PORTAL_PARAMETERS: dict[str, str] = {
    "SEND_AS_LOCAL": "sales",
    "CREDENTIAL_LABEL": "portal-support-smtp",
    "APP_PASSWORD_DESCRIPTION": "portal-support-transactional-submission",
}


def main() -> None:
    os.environ.update(PORTAL_PARAMETERS)
    provisioner = Path(__file__).resolve().parent / "provision_website_submission_credential.py"
    runpy.run_path(str(provisioner), run_name="__main__")


if __name__ == "__main__":
    main()
