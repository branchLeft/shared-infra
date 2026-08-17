#!/usr/bin/env python3
"""Rotates the Stalwart admin password via x:AccountPassword/set and
verifies the swap (old credential dead, new one live) without ever
printing either value -- run this any time the admin credential in
STALWART_CREDENTIALS_PATH needs rotating (compromise, routine hygiene,
handover). Not part of run-all.sh: rotation is a deliberate one-off
action, not a state to reconcile towards on every re-run.

Usage: python3 rotate_admin_credential.py
Prints only a final ROTATED / FAILED status line -- never a secret value,
on success or failure.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("STALWART_BASE_URL", "http://127.0.0.1:8080")
CREDENTIALS_PATH = os.environ.get(
    "STALWART_CREDENTIALS_PATH", "/root/.stalwart-admin-credentials"
)


def _request(method: str, path: str, auth: tuple[str, str], body: bytes | None = None):
    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, method=method)
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _jmap_call(auth: tuple[str, str], method: str, args: dict) -> dict:
    body = json.dumps(
        {"using": ["urn:ietf:params:jmap:core"], "methodCalls": [[method, args, "0"]]}
    ).encode()
    response = _request("POST", "/jmap", auth, body)
    name, result, _ = response["methodResponses"][0]
    if name == "error":
        raise RuntimeError(f"{method} failed: {result}")
    return result


def _can_authenticate(auth: tuple[str, str]) -> bool:
    try:
        _request("GET", "/api/account", auth)
        return True
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return False
        raise


def main() -> int:
    with open(CREDENTIALS_PATH, encoding="utf-8") as f:
        username, old_secret = f.read().strip().split(":", 1)
    old_auth = (username, old_secret)

    if not _can_authenticate(old_auth):
        print("FAILED: current credential in file does not authenticate -- nothing rotated")
        return 1

    new_secret = secrets.token_urlsafe(24)
    new_auth = (username, new_secret)

    # `currentSecret` is required even though the caller is already
    # authenticated via basic auth as this same account -- Stalwart treats
    # a password change as needing proof of the current password
    # regardless, not just a valid session (confirmed: omitting it returns
    # a "forbidden" x:AccountPassword/set response, not a silent no-op).
    result = _jmap_call(
        old_auth,
        "x:AccountPassword/set",
        {"update": {"singleton": {"secret": new_secret, "currentSecret": old_secret}}},
    )
    if "singleton" not in result.get("updated", {}):
        print(f"FAILED: x:AccountPassword/set did not report the update as applied: {result.get('notUpdated')}")
        return 1

    # Verify the swap actually took effect before touching the credentials
    # file -- a false "success" response with no real change would
    # otherwise leave the file pointing at a dead password.
    new_works = _can_authenticate(new_auth)
    old_dead = not _can_authenticate(old_auth)

    if not (new_works and old_dead):
        print(
            "FAILED: rotation call succeeded but verification did not "
            f"(new credential works: {new_works}, old credential dead: {old_dead}) "
            "-- credentials file left unchanged, investigate before retrying"
        )
        return 1

    with open(CREDENTIALS_PATH, "w", encoding="utf-8") as f:
        f.write(f"{username}:{new_secret}\n")
    os.chmod(CREDENTIALS_PATH, 0o600)

    print(f"ROTATED: new credential verified live, old credential verified dead, {CREDENTIALS_PATH} updated (mode 600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
