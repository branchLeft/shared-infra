#!/usr/bin/env python3
"""Send one known-bad request to the public edge and report blocked or allowed.

Read-only: a single GET, no redirects followed, no body. It proves nothing about
config on a host; it reports what the public edge answers today. One request
only, because a second distinct rule hit within 60 seconds can ban the address.

Exit codes: 0 blocked (403), 1 allowed (2xx), 2 anything else or no answer.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

USER_AGENT = "branchleft-edge-block-probe"
TIMEOUT_SECONDS = 20
BLOCKED_STATUS = 403
EXIT_BLOCKED = 0
EXIT_ALLOWED = 1
EXIT_OTHER = 2


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return the edge's own answer; a redirect is reported, not followed."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


def classify(status: int | None) -> str:
    """Name what the edge answered. None means no HTTP answer at all."""
    if status is None:
        return "other"
    if status == BLOCKED_STATUS:
        return "blocked"
    if 200 <= status < 300:
        return "allowed"
    return "other"


def exit_code_for(verdict: str) -> int:
    return {"blocked": EXIT_BLOCKED, "allowed": EXIT_ALLOWED}.get(verdict, EXIT_OTHER)


def build_url(host: str, path: str) -> str:
    """The URL for one request. The host must be a bare name, never a URL."""
    if "/" in host or ":" in host or not host:
        raise ValueError(f"host must be a bare hostname, got {host!r}")
    if not path.startswith("/"):
        raise ValueError(f"path must start with '/', got {path!r}")
    return f"https://{host}{path}"


def probe(url: str) -> int | None:
    """Return the HTTP status of one GET, or None when there was no answer."""
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            return int(response.status)
    except urllib.error.HTTPError as error:
        status = int(error.code)
        error.close()
        return status
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", required=True, help="public edge hostname, e.g. example.branchleft.co.uk")
    parser.add_argument("--path", default="/.env", help="known-bad sensitive-file path (default: /.env)")
    args = parser.parse_args(argv)

    url = build_url(args.host, args.path)
    status = probe(url)
    verdict = classify(status)
    print(json.dumps({"url": url, "status": status, "verdict": verdict}))
    return exit_code_for(verdict)


if __name__ == "__main__":
    sys.exit(main())
