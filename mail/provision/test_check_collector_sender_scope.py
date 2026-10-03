#!/usr/bin/env python3
"""Unit tests for check_collector_sender_scope.py.
Run with: python3 -m unittest discover -s mail/provision -p 'test_*.py' -v
"""
import contextlib
import io
import os
import smtplib
import tempfile
import unittest
from unittest import mock

import check_collector_sender_scope as check

SECRET = "s3cr3t-value-that-must-never-be-printed"


class VerdictTests(unittest.TestCase):
    def test_accept_then_permanent_refusal_passes(self):
        self.assertTrue(check.verdict(250, 250, 250, 550)[0])

    def test_a_deferral_is_not_a_refusal(self):
        self.assertFalse(check.verdict(250, 250, 250, 451)[0])

    def test_an_accepted_main_domain_sender_fails(self):
        passed, summary = check.verdict(250, 250, 250, 250)

        self.assertFalse(passed)
        self.assertIn("scope is open", summary)

    def test_a_failed_control_fails_even_with_a_refusal(self):
        passed, summary = check.verdict(550, 0, 0, 550)

        self.assertFalse(passed)
        self.assertIn("control failed", summary)

    def test_a_refused_data_step_fails_the_control(self):
        self.assertFalse(check.verdict(250, 250, 554, 550)[0])


class SendersTests(unittest.TestCase):
    def test_accept_sender_is_in_the_collector_set(self):
        domain = check.ACCEPT_SENDER.split("@", 1)[1]

        self.assertIn(domain, check.collector.COLLECTOR_SENDING_DOMAINS)

    def test_refuse_sender_is_the_main_domain(self):
        self.assertEqual(check.REFUSE_SENDER.split("@", 1)[1], check.collector.MAIN_DOMAIN)

    def test_recipient_is_local_to_the_main_domain(self):
        self.assertEqual(check.RECIPIENT.split("@", 1)[1], check.collector.MAIN_DOMAIN)


class FakeSMTP:
    """Scripted SMTP session: MAIL FROM replies keyed by sender."""

    instances = []

    def __init__(self, mail_replies, data_reply=(250, b"2.0.0 Message queued with id 1a2b3c.")):
        self.mail_replies = mail_replies
        self.data_reply = data_reply
        self.calls = []

    def __call__(self, host, port, timeout):
        self.calls.append(("connect", host, port))
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        self.calls.append(("ehlo",))

    def starttls(self, context):
        self.calls.append(("starttls",))

    def login(self, user, password):
        self.calls.append(("login", user))

    def mail(self, sender):
        self.calls.append(("mail", sender))
        return self.mail_replies[sender]

    def rcpt(self, recipient):
        self.calls.append(("rcpt", recipient))
        return 250, b"2.1.5 OK"

    def data(self, body):
        self.calls.append(("data",))
        code, text = self.data_reply
        if code != 250:
            raise smtplib.SMTPDataError(code, text)
        return code, text

    def rset(self):
        self.calls.append(("rset",))


class RunTests(unittest.TestCase):
    def run_with(self, fake):
        out = io.StringIO()
        with mock.patch.object(check.smtplib, "SMTP", fake), contextlib.redirect_stdout(out):
            code = check.run(SECRET)
        return code, out.getvalue()

    def scoped(self):
        return FakeSMTP({
            check.ACCEPT_SENDER: (250, b"2.1.0 OK"),
            check.REFUSE_SENDER: (550, b"5.7.1 Sender address not allowed."),
        })

    def test_scope_in_place_passes_and_prints_both_replies(self):
        code, output = self.run_with(self.scoped())

        self.assertEqual(code, 0)
        self.assertIn(f"REFUSE  MAIL FROM:<{check.REFUSE_SENDER}> -> 550 5.7.1 Sender address not allowed.", output)
        self.assertIn("ACCEPT  DATA -> 250 2.0.0 Message queued with id", output)

    def test_the_secret_is_never_printed(self):
        _, output = self.run_with(self.scoped())

        self.assertNotIn(SECRET, output)

    def test_one_connection_one_login_accept_before_refuse(self):
        fake = self.scoped()
        self.run_with(fake)

        names = [call[0] for call in fake.calls]
        self.assertEqual(names.count("connect"), 1)
        self.assertEqual(names.count("login"), 1)
        mails = [call[1] for call in fake.calls if call[0] == "mail"]
        self.assertEqual(mails, [check.ACCEPT_SENDER, check.REFUSE_SENDER])

    def test_logs_in_as_the_collector_over_starttls_on_587(self):
        fake = self.scoped()
        self.run_with(fake)

        self.assertIn(("connect", check.SMTP_HOST, 587), fake.calls)
        self.assertLess(fake.calls.index(("starttls",)), fake.calls.index(("login", check.collector.collector_address())))

    def test_open_scope_fails(self):
        fake = FakeSMTP({check.ACCEPT_SENDER: (250, b"2.1.0 OK"), check.REFUSE_SENDER: (250, b"2.1.0 OK")})

        code, output = self.run_with(fake)

        self.assertEqual(code, 1)
        self.assertIn("scope is open", output)

    def test_a_refused_data_step_fails_without_raising(self):
        fake = self.scoped()
        fake.data_reply = (554, b"5.7.1 rejected")

        code, output = self.run_with(fake)

        self.assertEqual(code, 1)
        self.assertIn("ACCEPT  DATA -> 554", output)


class SenderChoiceTests(unittest.TestCase):
    def test_committed_senders_are_valid(self):
        check.check_senders(check.collector.collector_address(), check.ACCEPT_SENDER, check.REFUSE_SENDER)

    def test_the_accept_sender_is_not_the_authenticated_address(self):
        self.assertNotEqual(check.ACCEPT_SENDER, check.collector.collector_address())

    def test_the_authenticated_address_as_accept_sender_is_refused(self):
        address = check.collector.collector_address()

        with self.assertRaises(ValueError):
            check.check_senders(address, address, check.REFUSE_SENDER)

    def test_an_out_of_scope_accept_sender_is_refused(self):
        with self.assertRaises(ValueError):
            check.check_senders(check.collector.collector_address(), "x@elsewhere.org", check.REFUSE_SENDER)

    def test_a_non_main_domain_refuse_sender_is_refused(self):
        with self.assertRaises(ValueError):
            check.check_senders(check.collector.collector_address(), check.ACCEPT_SENDER, "x@elsewhere.org")


class PolicySMTP(FakeSMTP):
    """Answers MAIL FROM the way Stalwart's two checks would for the logged-in
    account, with the collector's rule loaded or absent (shipped defaults)."""

    def __init__(self, rule_loaded):
        super().__init__({})
        self.rule_loaded = rule_loaded
        self.user = None

    def login(self, user, password):
        super().login(user, password)
        self.user = user

    def mail(self, sender):
        self.calls.append(("mail", sender))
        domain = sender.split("@", 1)[1]
        if self.rule_loaded and self.user == check.collector.collector_address():
            if domain in check.collector.COLLECTOR_SENDING_DOMAINS:
                return 250, b"2.1.0 OK"
            return 550, b"5.7.1 Sender address not allowed."
        if sender == self.user:
            return 250, b"2.1.0 OK"
        return 501, b"5.5.4 You are not allowed to send from this address."


class RuleAbsentTests(unittest.TestCase):
    """The check must tell 'rule loaded' from 'rule absent'."""

    def run_against(self, fake):
        with mock.patch.object(check.smtplib, "SMTP", fake), contextlib.redirect_stdout(io.StringIO()) as out:
            return check.run(SECRET), out.getvalue()

    def test_rule_loaded_passes(self):
        self.assertEqual(self.run_against(PolicySMTP(rule_loaded=True))[0], 0)

    def test_rule_absent_fails(self):
        code, output = self.run_against(PolicySMTP(rule_loaded=False))

        self.assertEqual(code, 1)
        self.assertIn("control failed", output)


class EhloOnlyTests(unittest.TestCase):
    def run_main(self, smtp):
        out = io.StringIO()
        with mock.patch.object(check.smtplib, "SMTP", smtp), contextlib.redirect_stdout(out):
            code = check.main(["--ehlo-only"])
        return code, out.getvalue()

    def test_accepting_again_passes_without_logging_in(self):
        session = mock.MagicMock()
        session.__enter__.return_value.ehlo.return_value = (250, b"mx1")

        code, output = self.run_main(mock.MagicMock(return_value=session))

        self.assertEqual(code, 0)
        self.assertIn("EHLO mx1.branchleft.co.uk:587 -> 250", output)
        session.__enter__.return_value.login.assert_not_called()

    def test_refused_connection_fails(self):
        code, output = self.run_main(mock.MagicMock(side_effect=ConnectionRefusedError()))

        self.assertEqual(code, 1)
        self.assertIn("no answer", output)

    def test_no_secret_is_read(self):
        session = mock.MagicMock()
        session.__enter__.return_value.ehlo.return_value = (250, b"mx1")
        with mock.patch.object(check.collector, "_load_recorded_secret") as load:
            self.run_main(mock.MagicMock(return_value=session))
        load.assert_not_called()


class MainTests(unittest.TestCase):
    def test_no_recorded_secret_never_connects(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(check.collector, "SERVICE_CREDENTIALS_PATH", os.path.join(tmp, "none")), \
                mock.patch.object(check.smtplib, "SMTP") as smtp, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(check.main([]), 1)
        smtp.assert_not_called()

    def test_an_auth_refusal_says_do_not_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"collector-smtp:{SECRET}\n")
            err = io.StringIO()
            with mock.patch.object(check.collector, "SERVICE_CREDENTIALS_PATH", path), \
                    mock.patch.object(check, "run", side_effect=smtplib.SMTPAuthenticationError(535, b"no")), \
                    contextlib.redirect_stderr(err):
                self.assertEqual(check.main([]), 1)
        self.assertIn("do not retry", err.getvalue())
        self.assertNotIn(SECRET, err.getvalue())


if __name__ == "__main__":
    unittest.main()
