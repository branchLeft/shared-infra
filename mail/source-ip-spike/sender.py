#!/usr/bin/env python3
"""Send one message to the sink from a chosen source address and print the outcome as JSON.

It is the 20-line client of the spike. With `--source` it binds the socket to that local
address before connecting; without it the kernel chooses. The outcome line carries the
errno of a failed bind or connect, because "the address is not on this interface" is
a result the spike reports, not a crash.

With `--auth-user` and `--auth-password` it logs in first (STARTTLS is used when offered,
without verifying the certificate: the target is a throwaway server in the lab). This is
how the spike submits through Stalwart.
"""

from __future__ import annotations

import argparse
import json
import smtplib
import ssl
import sys
from typing import Any

MESSAGE = "Subject: source-ip-spike\r\n\r\nspike\r\n"


def insecure_context() -> ssl.SSLContext:
    """A TLS context that accepts any certificate: the peer is a throwaway lab server."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def send(args: argparse.Namespace) -> dict[str, Any]:
    """Return {"ok": bool, "error": str, "errno": int | None, "stage": str}."""
    source = (args.source, 0) if args.source else None
    stage = "connect"
    try:
        client: smtplib.SMTP
        if args.implicit_tls:
            client = smtplib.SMTP_SSL(
                args.host,
                args.port,
                timeout=args.timeout,
                local_hostname=args.ehlo,
                source_address=source,
                context=insecure_context(),
            )
        else:
            client = smtplib.SMTP(
                timeout=args.timeout, local_hostname=args.ehlo, source_address=source
            )
            client.connect(args.host, args.port)
        stage = "ehlo"
        client.ehlo()
        if args.auth_user:
            if client.has_extn("starttls"):
                stage = "starttls"
                client.starttls(context=insecure_context())
                client.ehlo()
            stage = "auth"
            client.login(args.auth_user, args.auth_password)
        stage = "send"
        client.sendmail(args.mail_from, [args.rcpt_to], MESSAGE)
        client.quit()
    except (OSError, smtplib.SMTPException) as error:
        number = error.errno if isinstance(error, OSError) else None
        return {
            "ok": False,
            "stage": stage,
            "error": f"{type(error).__name__}: {error}",
            "errno": number,
        }
    return {"ok": True, "stage": "done", "error": "", "errno": None}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Send one message to the sink.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument(
        "--source", default="", help="local address to bind; empty lets the kernel choose"
    )
    parser.add_argument("--ehlo", default="sender.spike.test")
    parser.add_argument("--mail-from", required=True)
    parser.add_argument("--rcpt-to", default="rcpt@sink.spike.test")
    parser.add_argument(
        "--implicit-tls", action="store_true", help="wrap the connection in TLS at once (port 465)"
    )
    parser.add_argument("--auth-user", default="")
    parser.add_argument("--auth-password", default="")
    parser.add_argument("--timeout", type=float, default=15.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    outcome = send(build_parser().parse_args(argv))
    print(json.dumps(outcome, sort_keys=True))
    return 0 if outcome["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
