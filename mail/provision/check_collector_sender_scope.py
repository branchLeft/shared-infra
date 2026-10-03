#!/usr/bin/env python3
"""Proves the collector's sender scope on the live server: one SMTP session,
one sender it must accept, one it must refuse.
Why one session, and what each outcome means: provision_collector_submission_credential.md.
"""
from __future__ import annotations

import os
import smtplib
import ssl
import sys
import uuid
from email.message import EmailMessage

import provision_collector_submission_credential as collector

SMTP_HOST = os.environ.get("STALWART_HOSTNAME", "mx1.branchleft.co.uk")
SMTP_PORT = 587

# A local mailbox with no forwarding script, so the accepted message never
# leaves this host and costs no sending reputation.
RECIPIENT = f"rob@{collector.MAIN_DOMAIN}"

ACCEPT_SENDER = f"scope-check-accept@{collector.COLLECTOR_SENDING_DOMAINS[0]}"
REFUSE_SENDER = f"scope-check-refuse@{collector.MAIN_DOMAIN}"


def verdict(accept_mail: int, accept_rcpt: int, accept_data: int, refuse_mail: int) -> tuple[bool, str]:
    """PASS only when every accept step got 250 and the refused MAIL FROM got
    a permanent 5xx. A 4xx is a deferral, not a refusal, and does not pass."""
    accepted = accept_mail == 250 and accept_rcpt == 250 and accept_data == 250
    refused = 500 <= refuse_mail <= 599
    if accepted and refused:
        return True, "PASS: in-scope sender accepted, main-domain sender refused"
    if not accepted:
        return False, "FAIL: the in-scope sender was not accepted (the control failed; the refusal proves nothing)"
    return False, f"FAIL: the main-domain sender was NOT refused (got {refuse_mail}) -- the scope is open"


def _message(sender: str, nonce: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = RECIPIENT
    message["Subject"] = f"Collector sender-scope check {nonce}"
    message.set_content(f"Accepted by the collector's sender scope. Check id {nonce}.\n")
    return message


def _reply(code: int, text: bytes) -> str:
    return f"{code} {text.decode(errors='replace')}"


def check_senders(authenticated: str, accept: str, refuse: str) -> None:
    """Raises ValueError unless the accept sender can only pass through the
    domain rule: the account's own address passes even with no rule loaded."""
    if accept == authenticated:
        raise ValueError(f"accept sender {accept!r} is the authenticated address; it proves nothing")
    if accept.split("@", 1)[1] not in collector.COLLECTOR_SENDING_DOMAINS:
        raise ValueError(f"accept sender {accept!r} is outside the collector's sending domains")
    if refuse.split("@", 1)[1] != collector.MAIN_DOMAIN:
        raise ValueError(f"refuse sender {refuse!r} is not in the main domain")


def run(secret: str) -> int:
    nonce = uuid.uuid4().hex[:12]
    address = collector.collector_address()
    check_senders(address, ACCEPT_SENDER, REFUSE_SENDER)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl.create_default_context())
        smtp.ehlo()
        smtp.login(address, secret)

        mail_code, mail_text = smtp.mail(ACCEPT_SENDER)
        print(f"ACCEPT  MAIL FROM:<{ACCEPT_SENDER}> -> {_reply(mail_code, mail_text)}")
        rcpt_code = data_code = 0
        if mail_code == 250:
            rcpt_code, rcpt_text = smtp.rcpt(RECIPIENT)
            print(f"ACCEPT  RCPT TO:<{RECIPIENT}> -> {_reply(rcpt_code, rcpt_text)}")
            if rcpt_code == 250:
                try:
                    data_code, data_text = smtp.data(_message(ACCEPT_SENDER, nonce).as_bytes())
                except smtplib.SMTPDataError as exc:
                    data_code, data_text = exc.smtp_code, exc.smtp_error
                print(f"ACCEPT  DATA -> {_reply(data_code, data_text)}")
        smtp.rset()

        refuse_code, refuse_text = smtp.mail(REFUSE_SENDER)
        print(f"REFUSE  MAIL FROM:<{REFUSE_SENDER}> -> {_reply(refuse_code, refuse_text)}")
        smtp.rset()

    passed, summary = verdict(mail_code, rcpt_code, data_code, refuse_code)
    print(f"{summary} (check id {nonce})")
    return 0 if passed else 1


def main() -> int:
    secret = collector._load_recorded_secret()
    if secret is None:
        print(
            f"check_collector_sender_scope: nothing recorded under {collector.CREDENTIAL_LABEL!r} "
            f"in {collector.SERVICE_CREDENTIALS_PATH}; run the provisioning step first",
            file=sys.stderr,
        )
        return 1
    try:
        return run(secret)
    except ValueError as exc:
        print(f"check_collector_sender_scope: {exc}", file=sys.stderr)
        return 1
    except smtplib.SMTPAuthenticationError as exc:
        print(f"check_collector_sender_scope: authentication refused ({exc.smtp_code}); stop, do not retry", file=sys.stderr)
        return 1
    except (smtplib.SMTPException, OSError) as exc:
        print(f"check_collector_sender_scope: SMTP session failed: {exc!r}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
