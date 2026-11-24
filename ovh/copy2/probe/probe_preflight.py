"""Reads the probe project's roles with the probe's own OVHcloud credential.

`up` runs this before Pulumi touches anything. The OVH provider wraps a failed
role read without its HTTP status, so a refused read would only say "calling
Get". This module makes the same two calls the provider makes, token first and
then `GET /cloud/project/<id>/role`, and reports the status in plain words.
Nothing is created: it is a read. Offline tests pass a fake `Send`.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping

TOKEN_URL = "https://www.ovh.com/auth/oauth2/token"
API_BASES: Mapping[str, str] = {"ovh-eu": "https://eu.api.ovh.com/v1"}
PROJECT_ID = re.compile(r"[0-9a-f]{32}")
TIMEOUT_SECONDS = 20

# (method, url, headers, body) -> (HTTP status, body text). Raises OSError when
# no answer came at all. The body is read only to find the token.
Send = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, str]]

_HINTS = {
    403: "The OAuth client may not read roles on this project.",
    404: "This project id is not reachable with this client.",
}


class PreflightError(Exception):
    """A plain-words reason the probe must not start. It never holds a secret."""


def urllib_send(
    method: str, url: str, headers: Mapping[str, str], body: bytes | None
) -> tuple[int, str]:
    request = urllib.request.Request(
        url, data=body, headers=dict(headers), method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as answer:
            return answer.status, answer.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""


def _token(body: str) -> str:
    try:
        parsed = json.loads(body)
    except ValueError as exc:
        raise PreflightError("OVHcloud's token answer was not JSON") from exc
    token = parsed.get("access_token") if isinstance(parsed, dict) else None
    if not isinstance(token, str) or not token:
        raise PreflightError("OVHcloud's token answer held no access token")
    return token


def check_role_read(
    send: Send, environ: Mapping[str, str]
) -> None:
    """Raises PreflightError unless the credential can read the project's roles."""
    endpoint = environ.get("OVH_ENDPOINT", "")
    base = API_BASES.get(endpoint)
    if base is None:
        raise PreflightError(f"the OVH endpoint {endpoint!r} is not one the probe knows")
    project = environ.get("OVH_CLOUD_PROJECT_SERVICE", "")
    if not PROJECT_ID.fullmatch(project):
        raise PreflightError("the probe project id is not a 32-character hex id")
    client_id = environ.get("OVH_CLIENT_ID", "")
    client_secret = environ.get("OVH_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        raise PreflightError("the OVHcloud client id or secret is not set in this step")

    form = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
    ).encode("ascii")
    try:
        status, body = send(
            "POST",
            TOKEN_URL,
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            form,
        )
    except OSError as exc:
        raise PreflightError(
            f"could not reach OVHcloud for a token: {type(exc).__name__}"
        ) from exc
    if status != 200:
        raise PreflightError(
            f"this credential cannot get an access token: {status}"
        )
    token = _token(body)

    path = f"/cloud/project/{project}/role"
    try:
        status, _ = send(
            "GET",
            f"{base}{path}",
            {"Authorization": f"Bearer {token}", "Accept": "application/json"},
            None,
        )
    except OSError as exc:
        raise PreflightError(
            f"could not reach OVHcloud to read project roles: {type(exc).__name__}"
        ) from exc
    if status == 200:
        return
    hint = _HINTS.get(status, "OVHcloud refused the read.")
    raise PreflightError(
        f"this credential cannot read project roles: {status} (GET {path}). {hint}"
    )
