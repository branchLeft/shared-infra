#!/usr/bin/env python3
"""Proves the sign-in service credential's sender scope on the live server:
one SMTP session over STARTTLS, one sender it must accept, two it must refuse.
No message body is ever sent (the session stops after RCPT and resets), so the
check costs no sending reputation and delivers nothing.
Mechanism: provision_zitadel_submission_credential.md.
"""
from __future__ import annotations

import os
import smtplib
import ssl
import sys

import provision_zitadel_submission_credential as zitadel

SMTP_HOST = os.environ.get("STALWART_HOSTNAME", "mx1.branchleft.co.uk")
SMTP_PORT = 587

# A local mailbox: the accepted RCPT never leaves this host.
RECIPIENT = f"rob@{zitadel.MAIN_DOMAIN}"

# Another address on the account's own domain, and one on the main domain.
REFUSE_SENDERS = (
    f"scope-check-refuse@{zitadel.ACCOUNT_DOMAIN}",
    f"scope-check-refuse@{zitadel.MAIN_DOMAIN}",
)


def verdict(accept_mail: int, accept_rcpt: int, refusals: tuple[int, ...]) -> tuple[bool, str]:
    """PASS only when the account's own address was accepted at MAIL and RCPT
    and every other sender got a permanent 5xx. A 4xx is a deferral, not a
    refusal, and does not pass. If the control fails the refusals prove nothing."""
    if accept_mail != 250 or accept_rcpt != 250:
        return False, "FAIL: the credential's own address was not accepted (the control failed; the refusals prove nothing)"
    open_ones = [code for code in refusals if not 500 <= code <= 599]
    if open_ones:
        return False, f"FAIL: another sender was NOT refused (got {open_ones}) -- the scope is open"
    return True, "PASS: own address accepted, every other sender refused"


def _reply(code: int, text: bytes) -> str:
    return f"{code} {text.decode(errors='replace')}"


def run(secret: str) -> int:
    address = zitadel.account_address()
    if address in REFUSE_SENDERS:
        raise ValueError("a refused sender is the account's own address; the check would prove nothing")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl.create_default_context())
        smtp.ehlo()
        smtp.login(address, secret)
        mail_code, mail_text = smtp.mail(address)
        print(f"ACCEPT  MAIL FROM:<{address}> -> {_reply(mail_code, mail_text)}")
        rcpt_code = 0
        if mail_code == 250:
            rcpt_code, rcpt_text = smtp.rcpt(RECIPIENT)
            print(f"ACCEPT  RCPT TO:<{RECIPIENT}> -> {_reply(rcpt_code, rcpt_text)}")
        smtp.rset()
        codes = []
        for sender in REFUSE_SENDERS:
            code, text = smtp.mail(sender)
            print(f"REFUSE  MAIL FROM:<{sender}> -> {_reply(code, text)}")
            codes.append(code)
            smtp.rset()
    passed, summary = verdict(mail_code, rcpt_code, tuple(codes))
    print(summary)
    return 0 if passed else 1


def main() -> int:
    secret = zitadel._load_recorded_secret()
    if secret is None:
        print(
            f"check_zitadel_sender_scope: nothing recorded under {zitadel.CREDENTIAL_LABEL!r} "
            f"in {zitadel.SERVICE_CREDENTIALS_PATH}; run the provisioning step first",
            file=sys.stderr,
        )
        return 1
    try:
        return run(secret)
    except ValueError as exc:
        print(f"check_zitadel_sender_scope: {exc}", file=sys.stderr)
        return 1
    except smtplib.SMTPAuthenticationError as exc:
        print(f"check_zitadel_sender_scope: authentication refused ({exc.smtp_code}); stop, do not retry", file=sys.stderr)
        return 1
    except (smtplib.SMTPException, OSError) as exc:
        print(f"check_zitadel_sender_scope: SMTP session failed: {exc!r}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
