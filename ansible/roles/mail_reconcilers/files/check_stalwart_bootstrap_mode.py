#!/usr/bin/python3 -I
"""Says whether Stalwart is still in bootstrap mode, and changes nothing.

The configure step must never finish Stalwart's bootstrap: that is the owner's one-time
step (the role README, "Named limits"). configure_stalwart.py finishes it whenever the
administrator credential file it reads holds the temporary account, so the role asks
first. This program makes one read, GET /api/account, with the administrator credential
file the program would use, and applies the test configure_stalwart.py applies: the
account holds the sysBootstrapUpdate permission.

Exit status: 0 when Stalwart is not in bootstrap mode, 3 when it is, 2 when it cannot be
told (no file, a file of the wrong shape, no answer, an answer of the wrong shape). Only
status 0 lets the step go on, so every doubt refuses. It prints one fixed line and never
prints the credential, the address's answer or an error's text.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import sys
import urllib.request
from collections.abc import Mapping

PREFIX = "check_stalwart_bootstrap_mode"
BOOTSTRAP_PERMISSION = "sysBootstrapUpdate"
REQUEST_TIMEOUT_SECONDS = 15
NOT_BOOTSTRAP = 0
UNKNOWN = 2
BOOTSTRAP = 3
# Fixed texts, so that nothing read from the answer can reach an error.
NOT_AN_OBJECT = "the account answer is not an object"
BAD_PERMISSIONS = "the account permissions are not a list of text"
BAD_CREDENTIAL = "the credential file is not user:secret"


class CannotTellError(ValueError):
    """The mode cannot be told from what was read. The message is one of the fixed texts."""


def is_bootstrap_mode(account: object) -> bool:
    """Return whether the answer of GET /api/account is the bootstrap account's.

    Raises:
        CannotTellError: the answer is not an object, or its permissions are not a list of
            text, so the mode cannot be told. An answer with no permissions is not in
            bootstrap mode, as configure_stalwart.py reads it.
    """
    if not isinstance(account, dict):
        raise CannotTellError(NOT_AN_OBJECT)
    permissions = account.get("permissions", [])
    if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
        raise CannotTellError(BAD_PERMISSIONS)
    return BOOTSTRAP_PERMISSION in permissions


def read_credentials(path: str) -> tuple[str, str]:
    """Return the user name and the secret in the one-line file at path, split at the first colon.

    Raises:
        OSError: the file cannot be read.
        CannotTellError: the file holds no colon. The message names no content.
    """
    with open(path, encoding="utf-8") as handle:
        text = handle.read().strip()
    user, separator, secret = text.partition(":")
    if not separator or not user or not secret:
        raise CannotTellError(BAD_CREDENTIAL)
    return user, secret


def fetch_account(base_url: str, user: str, secret: str) -> object:
    """Return the parsed answer of GET /api/account for the credential.

    Raises:
        OSError: no answer, or an answer that is not a success (urllib's errors are OSErrors).
        http.client.HTTPException: the answer is not HTTP.
        ValueError: the answer is not JSON.
    """
    token = base64.b64encode(f"{user}:{secret}".encode()).decode()
    request = urllib.request.Request(  # noqa: S310 - the loopback address the role names
        f"{base_url}/api/account", method="GET", headers={"Authorization": f"Basic {token}"}
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
        parsed: object = json.loads(response.read())
    return parsed


def run(environment: Mapping[str, str]) -> int:
    """Return the exit status for the paths and address the environment names."""
    path = environment.get("STALWART_CREDENTIALS_PATH", "")
    base_url = environment.get("STALWART_BASE_URL", "")
    if not path or not base_url.startswith("http://127.0.0.1:"):
        print(f"{PREFIX}: REFUSED, nothing written: no credential path, or not a loopback address")
        return UNKNOWN
    try:
        user, secret = read_credentials(path)
        bootstrap = is_bootstrap_mode(fetch_account(base_url, user, secret))
    except (OSError, ValueError, http.client.HTTPException) as error:
        print(f"{PREFIX}: REFUSED, nothing written: could not tell ({type(error).__name__})")
        return UNKNOWN
    if bootstrap:
        print(f"{PREFIX}: REFUSED, nothing written: Stalwart is in bootstrap mode")
        return BOOTSTRAP
    print(f"{PREFIX}: Stalwart is not in bootstrap mode")
    return NOT_BOOTSTRAP


if __name__ == "__main__":
    sys.exit(run(os.environ))
