#!/usr/bin/env python3
"""Tests for secret_alert_pager and the workflow that runs it.

Every pager case uses a fake transport and a fixed clock, so nothing reaches the network.
The one exception is the transport test, which talks to a server on the loopback address.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime
import http.server
import io
import json
import os
import pathlib
import re
import socket
import stat
import tempfile
import threading
import unittest
from collections.abc import Callable, Mapping
from typing import ClassVar
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import secret_alert_pager as pager
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "secret-alert-pager.yml"

NOW = datetime.datetime(2026, 1, 15, 12, 0, tzinfo=datetime.timezone.utc)
REPO = "example-org/scratch-repo"
OTHER_REPO = "example-org/other-repo"
READ_TOKEN = "SYNTHETIC-READ-TOKEN-0001"
PUBLISH_TOKEN = "SYNTHETIC-PUBLISH-TOKEN-0001"
SECRET_VALUE = "SYNTHETIC-SECRET-VALUE-0001"
NTFY_BASE = "https://ntfy.example.test"
OWNER = "example-org"
GITHUB_HOST = "api.github.com"


def minutes_ago(minutes: int) -> str:
    moment = NOW - datetime.timedelta(minutes=minutes)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def item(
    number: int = 7,
    *,
    repo: str = REPO,
    age_minutes: int = 5,
    private: object = False,
    secret: str | None = None,
    state: str = "open",
) -> dict[str, object]:
    """One alert as the organisation listing returns it."""
    entry: dict[str, object] = {
        "number": number,
        "state": state,
        "created_at": minutes_ago(age_minutes),
        "html_url": f"https://github.com/{repo}/security/secret-scanning/{number}",
        "secret_type": "example_token",
        "secret_type_display_name": "Example Token",
        "repository": {"full_name": repo, "private": private},
    }
    if secret is not None:
        entry["secret"] = secret
    return entry


def json_response(
    status: int, payload: object, headers: Mapping[str, str] | None = None
) -> pager.HttpResponse:
    return pager.HttpResponse(
        status=status, headers=dict(headers or {}), body=json.dumps(payload).encode()
    )


class FakeTransport:
    """Answers GitHub listing requests from a handler and records every ntfy publish."""

    def __init__(
        self,
        listing: Callable[[pager.HttpRequest], pager.HttpResponse],
        publish_statuses: list[int] | None = None,
    ) -> None:
        self.listing = listing
        self.publish_statuses = list(publish_statuses or [])
        self.requests: list[pager.HttpRequest] = []
        self.pages: list[pager.HttpRequest] = []

    def send(self, request: pager.HttpRequest) -> pager.HttpResponse:
        self.requests.append(request)
        host = urlsplit(request.url).hostname
        if host == GITHUB_HOST:
            return self.listing(request)
        if request.url == NTFY_BASE + "/":
            status = self.publish_statuses.pop(0) if self.publish_statuses else 200
            if status == 200:
                self.pages.append(request)
            return json_response(status, {})
        raise AssertionError(f"unexpected request to {request.url}")

    def page_texts(self) -> list[str]:
        return [str(json.loads(page.body or b"{}")["message"]) for page in self.pages]


def listing_of(*items: dict[str, object]) -> Callable[[pager.HttpRequest], pager.HttpResponse]:
    def handler(request: pager.HttpRequest) -> pager.HttpResponse:
        return json_response(200, list(items))

    return handler


def environment(**overrides: str) -> dict[str, str]:
    env = {
        "PAGER_READ_TOKEN": READ_TOKEN,
        "NTFY_PAGER_PUBLISH_TOKEN": PUBLISH_TOKEN,
        "GITHUB_REPOSITORY_OWNER": OWNER,
        "NTFY_BASE_URL": NTFY_BASE,
    }
    env.update(overrides)
    return env


class PagerCase(unittest.TestCase):
    """A temporary directory for the state file and a helper that runs main against it."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.state_file = self.directory / "state" / "paged.json"

    def run_main(
        self,
        transport: FakeTransport,
        *,
        env: Mapping[str, str] | None = None,
        now: datetime.datetime = NOW,
    ) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = pager.main(
                ["--state-file", str(self.state_file)],
                env=environment() if env is None else env,
                transport=transport,
                clock=lambda: now,
            )
        return code, stdout.getvalue(), stderr.getvalue()

    def paged_keys(self) -> list[str]:
        document = json.loads(self.state_file.read_text(encoding="utf-8"))
        return list(document["paged"])


class ReaderTests(PagerCase):
    def test_hide_secret_requested(self) -> None:
        transport = FakeTransport(listing_of())
        self.run_main(transport)
        request = transport.requests[0]
        parts = urlsplit(request.url)
        query = parse_qs(parts.query)
        self.assertEqual(parts.scheme, "https")
        self.assertEqual(parts.hostname, GITHUB_HOST)
        self.assertEqual(parts.path, f"/orgs/{OWNER}/secret-scanning/alerts")
        self.assertEqual(query["hide_secret"], ["true"])
        self.assertEqual(query["state"], ["open"])
        self.assertEqual(query["per_page"], ["100"])
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.headers["Authorization"], f"Bearer {READ_TOKEN}")
        self.assertEqual(request.headers["Accept"], "application/vnd.github+json")
        self.assertEqual(request.headers["X-GitHub-Api-Version"], "2022-11-28")

    def test_refused_read_fails_loud(self) -> None:
        refused = json_response(403, {"message": "Resource not accessible by integration"})
        transport = FakeTransport(lambda request: refused)
        code, _, stderr = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertIn("ERROR: AlertReadError", stderr)
        self.assertIn("403", stderr)
        self.assertIn("Resource not accessible by integration", stderr)
        self.assertEqual(transport.pages, [])
        self.assertFalse(self.state_file.exists())

    def test_refused_read_keeps_an_existing_state_file_untouched(self) -> None:
        self.state_file.parent.mkdir(parents=True)
        self.state_file.write_text('{"version": 1, "paged": ["a/b:1"]}', encoding="utf-8")
        before = self.state_file.read_bytes()
        transport = FakeTransport(lambda request: json_response(403, {"message": "refused"}))
        code, _, _ = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertEqual(self.state_file.read_bytes(), before)

    def test_error_text_carries_neither_token(self) -> None:
        transport = FakeTransport(lambda request: json_response(403, {"message": "refused"}))
        _, stdout, stderr = self.run_main(transport)
        for text in (stdout, stderr):
            self.assertNotIn(READ_TOKEN, text)
            self.assertNotIn(PUBLISH_TOKEN, text)

    def test_server_error_without_message_still_names_the_status(self) -> None:
        transport = FakeTransport(lambda request: pager.HttpResponse(503, {}, b"<html>"))
        code, _, stderr = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertIn("503", stderr)
        self.assertNotIn("<html>", stderr)

    def test_transport_failure_on_read_fails_loud(self) -> None:
        def broken(request: pager.HttpRequest) -> pager.HttpResponse:
            raise pager.HttpTransportError("connection refused")

        code, _, stderr = self.run_main(FakeTransport(broken))
        self.assertEqual(code, 1)
        self.assertIn("ERROR: AlertReadError", stderr)

    def test_invalid_json_body_fails_without_echoing_the_body(self) -> None:
        body = f"not json {SECRET_VALUE}".encode()
        transport = FakeTransport(lambda request: pager.HttpResponse(200, {}, body))
        code, _, stderr = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertIn("AlertPayloadError", stderr)
        self.assertNotIn(SECRET_VALUE, stderr)

    def test_non_list_body_is_a_payload_error(self) -> None:
        transport = FakeTransport(lambda request: json_response(200, {"alerts": []}))
        code, _, stderr = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertIn("AlertPayloadError", stderr)

    def test_malformed_item_is_named_and_never_echoed(self) -> None:
        broken = item(secret=SECRET_VALUE)
        broken["number"] = "seven"
        transport = FakeTransport(listing_of(broken))
        code, _, stderr = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertIn("AlertPayloadError", stderr)
        self.assertIn("number", stderr)
        self.assertNotIn(SECRET_VALUE, stderr)

    def test_each_required_field_is_checked(self) -> None:
        mutations: dict[str, Callable[[dict[str, object]], object]] = {
            "boolean number": lambda entry: entry.update(number=True),
            "missing secret_type": lambda entry: entry.pop("secret_type"),
            "missing html_url": lambda entry: entry.pop("html_url"),
            "plain-http html_url": lambda entry: entry.update(html_url="http://example.test/x"),
            "missing created_at": lambda entry: entry.pop("created_at"),
            "naive created_at": lambda entry: entry.update(created_at="2026-01-15T11:55:00"),
            "garbled created_at": lambda entry: entry.update(created_at="yesterday"),
            "missing repository": lambda entry: entry.pop("repository"),
            "repository without full_name": lambda entry: entry.update(repository={"private": False}),
            "non-string display name": lambda entry: entry.update(secret_type_display_name=5),
        }
        for label, mutate in mutations.items():
            with self.subTest(label):
                entry = item()
                mutate(entry)
                with self.assertRaises(pager.AlertPayloadError):
                    pager.parse_listing_page(json.dumps([entry]).encode())

    def test_display_name_falls_back_to_secret_type(self) -> None:
        entry = item()
        del entry["secret_type_display_name"]
        listed, _ = pager.parse_listing_page(json.dumps([entry]).encode())
        self.assertEqual(listed[0].alert.secret_type_display_name, "example_token")

    def test_private_and_unknown_visibility_repositories_are_skipped_and_counted(self) -> None:
        transport = FakeTransport(
            listing_of(
                item(1, repo="example-org/private-repo", private=True),
                item(2, repo="example-org/odd-repo", private="false"),
                item(3, repo="example-org/odd-repo-two", private=None),
                item(4),
            )
        )
        code, stdout, _ = self.run_main(transport)
        self.assertEqual(code, 0)
        self.assertEqual(len(transport.pages), 1)
        self.assertIn("alert: 4", transport.page_texts()[0])
        self.assertIn("skipped_non_public=3", stdout)
        self.assertEqual(self.paged_keys(), [f"{REPO}:4"])

    def test_resolved_alert_in_the_listing_is_not_paged(self) -> None:
        transport = FakeTransport(listing_of(item(1, state="resolved")))
        self.run_main(transport)
        self.assertEqual(transport.pages, [])

    def test_pagination_follows_the_next_link(self) -> None:
        first_url_seen: list[str] = []
        second = f"https://{GITHUB_HOST}/orgs/{OWNER}/secret-scanning/alerts?hide_secret=true&state=open&after=abc"

        def handler(request: pager.HttpRequest) -> pager.HttpResponse:
            if request.url == second:
                return json_response(200, [item(2, age_minutes=6)])
            first_url_seen.append(request.url)
            return json_response(200, [item(1)], {"link": f'<{second}>; rel="next", <{second}>; rel="last"'})

        transport = FakeTransport(handler)
        code, _, _ = self.run_main(transport)
        self.assertEqual(code, 0)
        self.assertEqual(len(first_url_seen), 1)
        self.assertEqual(self.paged_keys(), [f"{REPO}:1", f"{REPO}:2"])
        self.assertEqual(transport.requests[1].headers["Authorization"], f"Bearer {READ_TOKEN}")

    SECOND = f"https://{GITHUB_HOST}/orgs/{OWNER}/secret-scanning/alerts?hide_secret=true&after=abc"

    def read_with_link(self, header: str | None) -> FakeTransport:
        """Read the listing when the first page carries this Link header (none when None)."""

        def handler(request: pager.HttpRequest) -> pager.HttpResponse:
            if request.url == self.SECOND or "after=" in request.url:
                return json_response(200, [])
            return json_response(200, [], {} if header is None else {"link": header})

        transport = FakeTransport(handler)
        pager.read_open_public_alerts(transport, pager.load_config(environment(), self.state_file))
        return transport

    def test_every_spelling_of_the_next_relation_is_followed(self) -> None:
        second = self.SECOND
        headers = {
            "quoted": f'<{second}>; rel="next"',
            "bare": f"<{second}>; rel=next",
            "upper-case name and value": f'<{second}>; REL="NEXT"',
            "several relation types": f'<{second}>; rel="prev next"',
            "next is not first": f'<{second}x>; rel="prev", <{second}>; rel="next", <{second}y>; rel="last"',
            "other parameters first": f'<{second}>; title="a, b"; rel="next"',
            "no space after the semicolon": f'<{second}>;rel="next"',
            "spaces around the equals sign": f'<{second}> ; rel = "next"',
            "empty parameter": f'<{second}>; ; rel="next"',
        }
        for label, header in headers.items():
            with self.subTest(label):
                transport = self.read_with_link(header)
                self.assertEqual(len(transport.requests), 2)
                self.assertEqual(transport.requests[1].url, second)

    def test_a_comma_inside_the_angle_brackets_does_not_split_the_link(self) -> None:
        comma_url = self.SECOND + "&labels=a,b"
        transport = self.read_with_link(f'<{comma_url}>; rel="next"')
        self.assertEqual(transport.requests[1].url, comma_url)

    def test_no_next_relation_means_no_second_request(self) -> None:
        second = self.SECOND
        headers: dict[str, str | None] = {
            "header absent": None,
            "only prev and last": f'<{second}>; rel="prev", <{second}>; rel="last"',
            "next only as a word in the url": f'<{second}&next=1>; rel="last"',
            "next only in another parameter": f'<{second}>; title="next"; rel="last"',
            "relation that merely contains next": f'<{second}>; rel="nextish"',
            "empty header": "",
        }
        for label, header in headers.items():
            with self.subTest(label):
                self.assertEqual(len(self.read_with_link(header).requests), 1)

    def test_a_link_that_looks_like_next_but_cannot_be_parsed_fails_closed(self) -> None:
        second = self.SECOND
        headers = {
            "unterminated angle bracket": f'<{second}; rel="next"',
            "missing url": 'rel="next"',
            "missing semicolon": f"<{second}> rel=next",
            "unterminated quote": f'<{second}>; rel="next',
        }
        for label, header in headers.items():
            with self.subTest(label):
                with self.assertRaises(pager.AlertReadError):
                    self.read_with_link(header)

    def test_garbage_that_is_not_a_next_link_is_ignored(self) -> None:
        self.assertEqual(len(self.read_with_link("garbage").requests), 1)

    def test_next_link_to_a_foreign_host_is_refused_before_any_request(self) -> None:
        for foreign in (
            "https://evil.example.test/orgs/x/secret-scanning/alerts?hide_secret=true",
            f"http://{GITHUB_HOST}/orgs/x/secret-scanning/alerts?hide_secret=true",
            f"https://{GITHUB_HOST}.evil.example.test/a?hide_secret=true",
        ):
            with self.subTest(foreign):
                link = {"link": f'<{foreign}>; rel="next"'}

                def handler(request: pager.HttpRequest, link: dict[str, str] = link) -> pager.HttpResponse:
                    return json_response(200, [item()], link)

                transport = FakeTransport(handler)
                code, _, stderr = self.run_main(transport)
                self.assertEqual(code, 1)
                self.assertIn("AlertReadError", stderr)
                self.assertEqual(len(transport.requests), 1)
                self.assertEqual(transport.pages, [])

    def test_next_link_that_drops_hide_secret_is_refused(self) -> None:
        bare = f"https://{GITHUB_HOST}/orgs/{OWNER}/secret-scanning/alerts?state=open"
        transport = FakeTransport(
            lambda request: json_response(200, [item()], {"link": f'<{bare}>; rel="next"'})
        )
        code, _, stderr = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertIn("hide_secret", stderr)
        self.assertEqual(len(transport.requests), 1)

    def test_page_cap_raises_rather_than_truncating(self) -> None:
        loop = f"https://{GITHUB_HOST}/orgs/{OWNER}/secret-scanning/alerts?hide_secret=true&page=2"
        transport = FakeTransport(
            lambda request: json_response(200, [], {"link": f'<{loop}>; rel="next"'})
        )
        code, _, stderr = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertIn("AlertReadError", stderr)
        self.assertEqual(len(transport.requests), pager.MAXIMUM_LISTING_PAGES)


class MessageTests(PagerCase):
    def make_alert(self) -> pager.SecretAlert:
        listed, _ = pager.parse_listing_page(json.dumps([item(42)]).encode())
        return listed[0].alert

    def test_message_names_repository_number_kind_and_link(self) -> None:
        page = pager.build_page(self.make_alert())
        lines = page.message.split("\n")
        self.assertEqual(lines[0], "ALERT_BODY_PLACEHOLDER")
        self.assertIn(f"repository: {REPO}", lines)
        self.assertIn("alert: 42", lines)
        self.assertIn("kind: Example Token", lines)
        self.assertIn(f"link: https://github.com/{REPO}/security/secret-scanning/42", lines)
        self.assertEqual(page.title, "ALERT_TITLE_PLACEHOLDER")
        self.assertEqual(page.click, f"https://github.com/{REPO}/security/secret-scanning/42")
        self.assertEqual(page.priority, 5)
        self.assertEqual(page.topic, "branchleft-pages")

    def test_message_never_contains_secret_value(self) -> None:
        transport = FakeTransport(listing_of(item(7, secret=SECRET_VALUE)))
        code, stdout, stderr = self.run_main(transport)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(len(transport.pages), 1)
        sent = transport.pages[0].body or b""
        payload = json.loads(sent)
        self.assertEqual(set(payload), {"topic", "title", "message", "priority", "tags", "click"})
        self.assertNotIn(SECRET_VALUE, sent.decode())
        self.assertNotIn(SECRET_VALUE, payload["message"])
        self.assertNotIn(SECRET_VALUE, self.state_file.read_text(encoding="utf-8"))
        self.assertNotIn(SECRET_VALUE, stdout + stderr)

    def test_alert_and_listing_reprs_cannot_show_the_secret(self) -> None:
        listed, _ = pager.parse_listing_page(json.dumps([item(secret=SECRET_VALUE)]).encode())
        self.assertNotIn(SECRET_VALUE, repr(listed))
        self.assertNotIn("secret_value", {field.name for field in dataclasses.fields(listed[0].alert)})

    def test_leak_guard_refuses_a_page_that_carries_the_secret(self) -> None:
        page = pager.build_page(self.make_alert())
        leaking = dataclasses.replace(page, message=page.message + "\n" + SECRET_VALUE)
        with self.assertRaises(pager.MessageLeakError) as caught:
            pager.ensure_page_free_of_secret(leaking, SECRET_VALUE)
        self.assertNotIn(SECRET_VALUE, str(caught.exception))
        pager.ensure_page_free_of_secret(page, SECRET_VALUE)
        pager.ensure_page_free_of_secret(leaking, "")

    def test_leak_guard_stops_the_run_when_the_builder_leaks(self) -> None:
        real_build = pager.build_page

        def leaking_build(alert: pager.SecretAlert) -> pager.NtfyPage:
            page = real_build(alert)
            return dataclasses.replace(page, title=SECRET_VALUE)

        transport = FakeTransport(listing_of(item(7, secret=SECRET_VALUE)))
        with mock.patch.object(pager, "build_page", leaking_build):
            code, _, stderr = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertIn("MessageLeakError", stderr)
        self.assertNotIn(SECRET_VALUE, stderr)
        self.assertEqual(transport.pages, [])
        self.assertEqual(self.paged_keys(), [])


class PublishTests(PagerCase):
    def test_publish_uses_bearer_and_priority_five(self) -> None:
        transport = FakeTransport(listing_of(item(7)))
        code, _, _ = self.run_main(transport)
        self.assertEqual(code, 0)
        request = transport.pages[0]
        self.assertEqual(request.url, NTFY_BASE + "/")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.headers["Authorization"], "Bearer " + PUBLISH_TOKEN)
        self.assertEqual(request.headers["Content-Type"], "application/json")
        payload = json.loads(request.body or b"")
        self.assertEqual(payload["priority"], 5)
        self.assertEqual(payload["topic"], "branchleft-pages")
        self.assertEqual(payload["tags"], ["rotating_light"])
        self.assertEqual(payload["click"], f"https://github.com/{REPO}/security/secret-scanning/7")

    def test_failed_publish_fails_loud_without_the_token_and_is_not_recorded(self) -> None:
        transport = FakeTransport(listing_of(item(7)), publish_statuses=[401])
        code, stdout, stderr = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertIn("ERROR: PageDeliveryError", stderr)
        self.assertIn("401", stderr)
        for text in (stdout, stderr):
            self.assertNotIn(PUBLISH_TOKEN, text)
            self.assertNotIn(READ_TOKEN, text)
        self.assertEqual(self.paged_keys(), [])

    def test_transport_failure_on_publish_fails_loud(self) -> None:
        class FailingPublish(FakeTransport):
            def send(self, request: pager.HttpRequest) -> pager.HttpResponse:
                if request.url == NTFY_BASE + "/":
                    raise pager.HttpTransportError("connection reset")
                return super().send(request)

        code, _, stderr = self.run_main(FailingPublish(listing_of(item(7))))
        self.assertEqual(code, 1)
        self.assertIn("ERROR: PageDeliveryError", stderr)
        self.assertEqual(self.paged_keys(), [])


class DedupeTests(PagerCase):
    def test_new_alert_in_window_pages(self) -> None:
        transport = FakeTransport(listing_of(item(7, age_minutes=5)))
        code, stdout, _ = self.run_main(transport)
        self.assertEqual(code, 0)
        self.assertEqual(len(transport.pages), 1)
        self.assertIn(f"repository: {REPO}", transport.page_texts()[0])
        self.assertEqual(self.paged_keys(), [f"{REPO}:7"])
        self.assertIn("paged=1", stdout)

    def test_cold_start_records_old_alerts_as_backlog_without_paging(self) -> None:
        transport = FakeTransport(listing_of(item(7, age_minutes=20), item(8, age_minutes=900)))
        code, stdout, _ = self.run_main(transport)
        self.assertEqual(code, 0)
        self.assertEqual(transport.pages, [])
        self.assertEqual(self.paged_keys(), [f"{REPO}:7", f"{REPO}:8"])
        self.assertIn("backlog_recorded=2", stdout)

    def test_cold_start_window_edge_is_inclusive_at_fifteen_minutes(self) -> None:
        transport = FakeTransport(listing_of(item(1, age_minutes=15), item(2, age_minutes=16)))
        self.run_main(transport)
        self.assertEqual(len(transport.pages), 1)
        self.assertIn("alert: 1", transport.page_texts()[0])

    def test_cold_start_with_nothing_open_still_creates_the_state_file(self) -> None:
        code, _, _ = self.run_main(FakeTransport(listing_of()))
        self.assertEqual(code, 0)
        self.assertEqual(self.paged_keys(), [])

    def test_backlog_is_not_paged_by_the_next_warm_run(self) -> None:
        listing = listing_of(item(7, age_minutes=20))
        self.run_main(FakeTransport(listing))
        later = FakeTransport(listing)
        self.run_main(later, now=NOW + datetime.timedelta(minutes=5))
        self.assertEqual(later.pages, [])

    def test_each_alert_pages_once_across_overlapping_windows(self) -> None:
        first_listing = listing_of(item(7, age_minutes=5), item(8, age_minutes=3))
        first = FakeTransport(first_listing)
        self.run_main(first)
        second = FakeTransport(first_listing)
        self.run_main(second, now=NOW + datetime.timedelta(minutes=5))
        third_listing = listing_of(
            item(7, age_minutes=10), item(8, age_minutes=8), item(9, age_minutes=1)
        )
        third = FakeTransport(third_listing)
        self.run_main(third, now=NOW + datetime.timedelta(minutes=10))
        self.assertEqual(len(first.pages), 2)
        self.assertEqual(second.pages, [])
        self.assertEqual(len(third.pages), 1)
        self.assertIn("alert: 9", third.page_texts()[0])
        self.assertEqual(self.paged_keys(), [f"{REPO}:7", f"{REPO}:8", f"{REPO}:9"])

    def test_warm_start_pages_an_old_alert_that_is_not_in_the_set(self) -> None:
        self.run_main(FakeTransport(listing_of()))
        transport = FakeTransport(listing_of(item(5, age_minutes=600)))
        self.run_main(transport, now=NOW + datetime.timedelta(minutes=5))
        self.assertEqual(len(transport.pages), 1)

    def test_same_number_in_two_repositories_pages_both(self) -> None:
        transport = FakeTransport(listing_of(item(3, repo=REPO), item(3, repo=OTHER_REPO)))
        self.run_main(transport)
        self.assertEqual(len(transport.pages), 2)
        self.assertEqual(self.paged_keys(), [f"{OTHER_REPO}:3", f"{REPO}:3"])

    def test_an_alert_listed_twice_in_one_run_pages_once(self) -> None:
        transport = FakeTransport(listing_of(item(7), item(7)))
        self.run_main(transport)
        self.assertEqual(len(transport.pages), 1)

    def test_several_alerts_page_oldest_first(self) -> None:
        transport = FakeTransport(
            listing_of(item(3, age_minutes=2), item(1, age_minutes=9), item(2, age_minutes=5))
        )
        self.run_main(transport)
        numbers = [text.split("alert: ")[1].split("\n")[0] for text in transport.page_texts()]
        self.assertEqual(numbers, ["1", "2", "3"])

    def test_a_failed_second_publish_retries_only_that_alert_next_run(self) -> None:
        listing = listing_of(item(1, age_minutes=9), item(2, age_minutes=5))
        failing = FakeTransport(listing, publish_statuses=[200, 500])
        code, _, _ = self.run_main(failing)
        self.assertEqual(code, 1)
        self.assertEqual(self.paged_keys(), [f"{REPO}:1"])
        retry = FakeTransport(listing)
        code, _, _ = self.run_main(retry, now=NOW + datetime.timedelta(minutes=5))
        self.assertEqual(code, 0)
        self.assertEqual(len(retry.pages), 1)
        self.assertIn("alert: 2", retry.page_texts()[0])
        self.assertEqual(self.paged_keys(), [f"{REPO}:1", f"{REPO}:2"])

    def test_state_is_persisted_before_the_next_page_is_sent(self) -> None:
        recorded: list[list[str]] = []

        class Observing(FakeTransport):
            def send(inner, request: pager.HttpRequest) -> pager.HttpResponse:
                if request.url == NTFY_BASE + "/" and self.state_file.exists():
                    recorded.append(self.paged_keys())
                return super().send(request)

        self.run_main(Observing(listing_of(item(1, age_minutes=9), item(2, age_minutes=5))))
        self.assertEqual(recorded, [[], [f"{REPO}:1"]])


class StateTests(PagerCase):
    def test_corrupt_state_file_fails_loud_and_is_not_treated_as_cold(self) -> None:
        bad_documents = {
            "not json": "{{{",
            "unknown version": '{"version": 2, "paged": []}',
            "paged not a list": '{"version": 1, "paged": "x"}',
            "paged holds a number": '{"version": 1, "paged": [1]}',
            "not an object": "[]",
            "missing paged": '{"version": 1}',
        }
        for label, text in bad_documents.items():
            with self.subTest(label):
                self.state_file.parent.mkdir(parents=True, exist_ok=True)
                self.state_file.write_text(text, encoding="utf-8")
                transport = FakeTransport(listing_of(item(7)))
                code, _, stderr = self.run_main(transport)
                self.assertEqual(code, 1)
                self.assertIn("ERROR: StateFileError", stderr)
                self.assertEqual(transport.pages, [])
                self.assertEqual(self.state_file.read_text(encoding="utf-8"), text)

    def test_unreadable_state_path_is_a_state_error(self) -> None:
        self.state_file.mkdir(parents=True)
        with self.assertRaises(pager.StateFileError):
            pager.PagedStateStore(self.state_file).load()

    def make_target(self, text: str = '{"version": 1, "paged": ["a/b:1"]}') -> pathlib.Path:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        target = self.directory / "target.json"
        target.write_text(text, encoding="utf-8")
        return target

    def test_load_refuses_a_symlink_and_does_not_read_its_target(self) -> None:
        target = self.make_target()
        self.state_file.symlink_to(target)
        with self.assertRaises(pager.StateFileError) as caught:
            pager.PagedStateStore(self.state_file).load()
        self.assertNotIn("a/b:1", str(caught.exception))

    def test_load_refuses_a_dangling_symlink_rather_than_calling_it_cold(self) -> None:
        self.state_file.parent.mkdir(parents=True)
        self.state_file.symlink_to(self.directory / "nowhere.json")
        with self.assertRaises(pager.StateFileError):
            pager.PagedStateStore(self.state_file).load()

    def test_load_refuses_a_fifo_without_blocking(self) -> None:
        self.state_file.parent.mkdir(parents=True)
        os.mkfifo(self.state_file)
        outcome: list[BaseException | None] = []

        def attempt() -> None:
            try:
                pager.PagedStateStore(self.state_file).load()
                outcome.append(None)
            except BaseException as failure:
                outcome.append(failure)

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(5)
        self.assertFalse(worker.is_alive(), "load blocked on a FIFO")
        self.assertIsInstance(outcome[0], pager.StateFileError)

    def test_load_names_a_non_regular_file_when_it_is_a_directory(self) -> None:
        self.state_file.mkdir(parents=True)
        with self.assertRaises(pager.StateFileError) as caught:
            pager.PagedStateStore(self.state_file).load()
        self.assertIn("regular file", str(caught.exception))

    def test_main_refuses_a_symlinked_state_file_without_paging(self) -> None:
        self.state_file.parent.mkdir(parents=True)
        self.state_file.symlink_to(self.make_target())
        transport = FakeTransport(listing_of(item(7)))
        code, _, stderr = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertIn("ERROR: StateFileError", stderr)
        self.assertEqual(transport.pages, [])

    def test_state_file_that_is_not_utf8_is_a_state_error(self) -> None:
        self.state_file.parent.mkdir(parents=True)
        self.state_file.write_bytes(b"\xff\xfe")
        with self.assertRaises(pager.StateFileError):
            pager.PagedStateStore(self.state_file).load()
        transport = FakeTransport(listing_of(item(7)))
        code, _, stderr = self.run_main(transport)
        self.assertEqual(code, 1)
        self.assertIn("ERROR: StateFileError", stderr)
        self.assertNotIn("UnicodeDecodeError", stderr)
        self.assertEqual(transport.pages, [])

    def test_save_over_a_symlink_is_refused_and_the_target_is_untouched(self) -> None:
        target = self.make_target()
        self.state_file.symlink_to(target)
        before = target.read_bytes()
        with self.assertRaises(pager.StateFileError):
            pager.PagedStateStore(self.state_file).save(frozenset({"c/d:2"}))
        self.assertEqual(target.read_bytes(), before)
        self.assertTrue(self.state_file.is_symlink())
        self.assertEqual(sorted(path.name for path in self.state_file.parent.iterdir()), ["paged.json"])

    def test_save_over_a_directory_is_refused(self) -> None:
        self.state_file.mkdir(parents=True)
        with self.assertRaises(pager.StateFileError):
            pager.PagedStateStore(self.state_file).save(frozenset())

    def test_saved_file_is_private_to_the_owner(self) -> None:
        pager.PagedStateStore(self.state_file).save(frozenset({"a/b:1"}))
        self.assertEqual(stat.S_IMODE(self.state_file.stat().st_mode), 0o600)

    def test_unwritable_state_path_is_a_state_error(self) -> None:
        blocker = self.directory / "blocker"
        blocker.write_text("a file where a directory is needed", encoding="utf-8")
        with self.assertRaises(pager.StateFileError):
            pager.PagedStateStore(blocker / "paged.json").save(frozenset({"a/b:1"}))

    def test_save_round_trips_a_sorted_set_and_leaves_no_temporary_file(self) -> None:
        store = pager.PagedStateStore(self.state_file)
        self.assertIsNone(store.load())
        store.save(frozenset({"b/c:2", "a/b:1"}))
        self.assertEqual(store.load(), frozenset({"a/b:1", "b/c:2"}))
        self.assertEqual(
            json.loads(self.state_file.read_text(encoding="utf-8")),
            {"version": 1, "paged": ["a/b:1", "b/c:2"]},
        )
        self.assertEqual([path.name for path in self.state_file.parent.iterdir()], ["paged.json"])


class OutputTests(PagerCase):
    def run_with_output(self, transport: FakeTransport) -> str:
        output = self.directory / "github_output"
        output.write_text("", encoding="utf-8")
        code, _, stderr = self.run_main(
            transport, env=environment(GITHUB_OUTPUT=str(output))
        )
        self.assertIn(code, (0, 1), stderr)
        return output.read_text(encoding="utf-8")

    def test_state_changed_is_written_only_when_state_changed(self) -> None:
        listing = listing_of(item(7, age_minutes=2))
        self.assertEqual(self.run_with_output(FakeTransport(listing)), "state_changed=true\n")
        self.assertEqual(self.run_with_output(FakeTransport(listing)), "")

    def test_state_changed_is_written_when_a_later_publish_fails(self) -> None:
        listing = listing_of(item(1, age_minutes=9), item(2, age_minutes=5))
        text = self.run_with_output(FakeTransport(listing, publish_statuses=[200, 500]))
        self.assertEqual(text, "state_changed=true\n")

    def test_state_changed_is_not_written_when_the_read_fails(self) -> None:
        transport = FakeTransport(lambda request: json_response(403, {"message": "refused"}))
        self.assertEqual(self.run_with_output(transport), "")


class AnnounceOrderTests(PagerCase):
    """state_changed=true must reach GITHUB_OUTPUT before any page can be sent."""

    def setUp(self) -> None:
        super().setUp()
        self.output = self.directory / "github_output"
        self.output.write_text("", encoding="utf-8")

    def announced_at_each_page(self, listing: Callable[[pager.HttpRequest], pager.HttpResponse]) -> list[str]:
        seen: list[str] = []
        output = self.output

        class Observing(FakeTransport):
            def send(inner, request: pager.HttpRequest) -> pager.HttpResponse:
                if request.url == NTFY_BASE + "/":
                    seen.append(output.read_text(encoding="utf-8"))
                return super().send(request)

        self.run_main(Observing(listing), env=environment(GITHUB_OUTPUT=str(self.output)))
        return seen

    def test_announced_before_the_first_page_on_a_warm_run(self) -> None:
        self.state_file.parent.mkdir(parents=True)
        self.state_file.write_text('{"version": 1, "paged": []}', encoding="utf-8")
        seen = self.announced_at_each_page(listing_of(item(1, age_minutes=9), item(2, age_minutes=5)))
        self.assertEqual(seen, ["state_changed=true\n", "state_changed=true\n"])

    def test_announced_before_the_first_page_on_a_cold_start(self) -> None:
        seen = self.announced_at_each_page(listing_of(item(1, age_minutes=5)))
        self.assertEqual(seen, ["state_changed=true\n"])

    def test_announced_before_the_cold_start_backlog_is_saved(self) -> None:
        output = pager.GithubOutputFile(str(self.directory / "missing" / "output"))
        transport = FakeTransport(listing_of(item(1, age_minutes=600)))
        config = pager.load_config(environment(), self.state_file)
        with self.assertRaises(pager.StateFileError):
            pager.run_pager(config, transport, lambda: NOW, pager.PagedStateStore(self.state_file), output)
        self.assertFalse(self.state_file.exists())

    def test_a_failed_announce_stops_the_run_before_any_page(self) -> None:
        self.state_file.parent.mkdir(parents=True)
        self.state_file.write_text('{"version": 1, "paged": []}', encoding="utf-8")
        transport = FakeTransport(listing_of(item(7)))
        env = environment(GITHUB_OUTPUT=str(self.directory / "missing" / "output"))
        code, _, stderr = self.run_main(transport, env=env)
        self.assertEqual(code, 1)
        self.assertIn("ERROR: StateFileError", stderr)
        self.assertEqual(transport.pages, [])
        self.assertEqual([r for r in transport.requests if r.method == "POST"], [])
        self.assertEqual(self.paged_keys(), [])

    def test_announced_when_saving_after_a_successful_page_fails(self) -> None:
        self.state_file.parent.mkdir(parents=True)
        self.state_file.write_text('{"version": 1, "paged": []}', encoding="utf-8")
        transport = FakeTransport(listing_of(item(7)))
        failing = pager.StateFileError("the state file cannot be written: injected")
        with mock.patch.object(pager.PagedStateStore, "save", side_effect=failing):
            code, _, stderr = self.run_main(transport, env=environment(GITHUB_OUTPUT=str(self.output)))
        self.assertEqual(code, 1)
        self.assertIn("ERROR: StateFileError", stderr)
        self.assertEqual(len(transport.pages), 1)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "state_changed=true\n")

    def test_not_announced_when_every_listed_alert_is_already_paged(self) -> None:
        self.state_file.parent.mkdir(parents=True)
        self.state_file.write_text(f'{{"version": 1, "paged": ["{REPO}:7"]}}', encoding="utf-8")
        self.announced_at_each_page(listing_of(item(7)))
        self.assertEqual(self.output.read_text(encoding="utf-8"), "")


class OutputFileTests(PagerCase):
    def test_unwritable_output_file_is_a_state_error(self) -> None:
        output = pager.GithubOutputFile(str(self.directory / "missing" / "output"))
        with self.assertRaises(pager.StateFileError):
            output.announce_state_changed()

    def test_no_output_path_is_a_no_op(self) -> None:
        pager.GithubOutputFile(None).announce_state_changed()


class ConfigTests(PagerCase):
    def test_missing_or_empty_variable_names_the_variable_never_its_value(self) -> None:
        for name in (
            "PAGER_READ_TOKEN",
            "NTFY_PAGER_PUBLISH_TOKEN",
            "GITHUB_REPOSITORY_OWNER",
            "NTFY_BASE_URL",
        ):
            for value in (None, "", "   "):
                with self.subTest(name=name, value=value):
                    env = environment()
                    if value is None:
                        del env[name]
                    else:
                        env[name] = value
                    transport = FakeTransport(listing_of(item(7)))
                    code, _, stderr = self.run_main(transport, env=env)
                    self.assertEqual(code, 1)
                    self.assertIn("ERROR: PagerConfigError", stderr)
                    self.assertIn(name, stderr)
                    self.assertEqual(transport.requests, [])
                    self.assertFalse(self.state_file.exists())

    def test_non_https_ntfy_base_url_is_rejected(self) -> None:
        for bad in ("http://ntfy.example.test", "ntfy.example.test", "ftp://x.example.test", "https://"):
            with self.subTest(bad):
                with self.assertRaises(pager.PagerConfigError):
                    pager.load_config(environment(NTFY_BASE_URL=bad), self.state_file)

    def test_owner_that_would_change_the_request_path_is_rejected(self) -> None:
        for bad in ("org/../x", "org?x=1", "org name", "org/x"):
            with self.subTest(bad):
                with self.assertRaises(pager.PagerConfigError):
                    pager.load_config(environment(GITHUB_REPOSITORY_OWNER=bad), self.state_file)

    def test_config_repr_hides_both_tokens(self) -> None:
        config = pager.load_config(environment(), self.state_file)
        self.assertNotIn(READ_TOKEN, repr(config))
        self.assertNotIn(PUBLISH_TOKEN, repr(config))

    def test_request_repr_hides_headers(self) -> None:
        request = pager.HttpRequest("https://x.example.test", "GET", {"Authorization": "Bearer " + READ_TOKEN}, None)
        self.assertNotIn(READ_TOKEN, repr(request))

    def test_state_file_flag_is_required(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            pager.main([], env=environment(), transport=FakeTransport(listing_of()))
        self.assertEqual(caught.exception.code, 2)


class UrllibTransportTests(unittest.TestCase):
    """The real transport against a loopback server: no redirect is followed, a non-2xx is a value."""

    def serve(self, handler_class: type[http.server.BaseHTTPRequestHandler]) -> str:
        server = http.server.HTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def test_redirect_is_returned_not_followed_and_forbidden_is_a_value(self) -> None:
        hits: list[tuple[str, str | None]] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                hits.append((self.path, self.headers.get("Authorization")))
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/landing")
                    self.end_headers()
                else:
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"message": "refused"}')

            def log_message(self, format: str, *args: object) -> None:
                return

        base = self.serve(Handler)
        transport = pager.UrllibTransport()
        headers = {"Authorization": "Bearer " + READ_TOKEN}
        redirected = transport.send(pager.HttpRequest(base + "/redirect", "GET", headers, None))
        self.assertEqual(redirected.status, 302)
        self.assertEqual(redirected.headers["location"], "/landing")
        self.assertEqual([path for path, _ in hits], ["/redirect"])
        refused = transport.send(pager.HttpRequest(base + "/other", "GET", headers, None))
        self.assertEqual(refused.status, 403)
        self.assertEqual(json.loads(refused.body), {"message": "refused"})

    def test_post_sends_the_body_and_headers(self) -> None:
        received: list[tuple[str | None, bytes]] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers["Content-Length"])
                received.append((self.headers.get("Authorization"), self.rfile.read(length)))
                self.send_response(200)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        base = self.serve(Handler)
        request = pager.HttpRequest(base + "/", "POST", {"Authorization": "Bearer X"}, b'{"a": 1}')
        self.assertEqual(pager.UrllibTransport().send(request).status, 200)
        self.assertEqual(received, [("Bearer X", b'{"a": 1}')])

    def test_connection_failure_is_a_transport_error(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with self.assertRaises(pager.HttpTransportError):
            pager.UrllibTransport().send(pager.HttpRequest(f"http://127.0.0.1:{port}/", "GET", {}, None))


def mapping(value: object) -> dict[str, object]:
    """Narrow a parsed YAML node to a string-keyed mapping, failing the test if it is not one."""
    if not isinstance(value, dict):
        raise TypeError(f"expected a mapping, got {type(value).__name__}")
    return {("on" if key is True else str(key)): node for key, node in value.items()}


def sequence(value: object) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(f"expected a list, got {type(value).__name__}")
    return list(value)


class WorkflowTests(unittest.TestCase):
    EXPECTED_TRIGGERS: ClassVar[set[str]] = {"schedule", "workflow_dispatch"}
    WRITE_COMMAND = re.compile(
        r"git\s+push|gh\s+pr\b|gh\s+issue\b|gh\s+api\b.*(-X|--method)\s*(POST|PUT|PATCH|DELETE)",
        re.IGNORECASE,
    )
    KEY = "secret-alert-pager-state-${{ github.run_id }}-${{ github.run_attempt }}"
    CONDITION = "${{ always() && steps.pager.outputs.state_changed == 'true' }}"

    def load(self) -> dict[str, object]:
        """The workflow with the YAML 1.1 boolean key for on: put back to the string on."""
        return mapping(yaml.safe_load(WORKFLOW.read_text(encoding="utf-8")))

    def jobs(self) -> dict[str, dict[str, object]]:
        return {name: mapping(job) for name, job in mapping(self.load()["jobs"]).items()}

    def steps(self) -> list[dict[str, object]]:
        jobs = self.jobs()
        self.assertEqual(len(jobs), 1)
        (job,) = jobs.values()
        return [mapping(step) for step in sequence(job["steps"])]

    def step_using(self, prefix: str) -> list[dict[str, object]]:
        return [step for step in self.steps() if str(step.get("uses", "")).startswith(prefix)]

    def pager_step(self) -> dict[str, object]:
        (step,) = [step for step in self.steps() if step.get("id") == "pager"]
        return step

    def test_workflow_has_no_write_permission(self) -> None:
        document = self.load()
        self.assertEqual(document["permissions"], {"contents": "read"})
        for name, job in self.jobs().items():
            for scope, level in mapping(job.get("permissions", {})).items():
                self.assertEqual(level, "read", f"job {name} grants {scope}: {level}")
        self.assertEqual(set(mapping(document["on"])), self.EXPECTED_TRIGGERS)

    def test_schedule_is_every_five_minutes(self) -> None:
        schedule = mapping(self.load()["on"])["schedule"]
        self.assertEqual(schedule, [{"cron": "*/5 * * * *"}])

    def test_no_step_writes_to_a_repository(self) -> None:
        for step in self.steps():
            self.assertIsNone(self.WRITE_COMMAND.search(str(step.get("run", ""))), step)

    def test_no_run_body_interpolates_an_expression(self) -> None:
        for step in self.steps():
            self.assertNotIn("${{", str(step.get("run", "")), step)

    def test_every_action_is_pinned_to_a_sha_with_a_version_comment(self) -> None:
        uses_lines = [
            line.strip()
            for line in WORKFLOW.read_text(encoding="utf-8").splitlines()
            if re.match(r"\s*(-\s+)?uses:", line)
        ]
        self.assertEqual(len(uses_lines), len(self.steps()) - 1)
        for line in uses_lines:
            self.assertRegex(line, r"uses: [\w./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$")

    def test_workflow_is_serialised_with_a_timeout(self) -> None:
        self.assertNotIn("concurrency", self.load())
        for job in self.jobs().values():
            self.assertEqual(
                job["concurrency"], {"group": "secret-alert-pager", "cancel-in-progress": False}
            )
            self.assertEqual(job["timeout-minutes"], 10)

    def test_checkout_does_not_persist_credentials(self) -> None:
        (checkout,) = self.step_using("actions/checkout@")
        self.assertEqual(checkout["with"], {"persist-credentials": False})

    def test_owner_set_secrets_are_used_only_where_expected(self) -> None:
        for step in self.steps():
            text = json.dumps(step)
            for name in ("PAGER_APP_ID", "PAGER_APP_PRIVATE_KEY"):
                if name in text:
                    self.assertTrue(str(step.get("uses", "")).startswith("actions/create-github-app-token@"))
                    self.assertIn(name, json.dumps(step["with"]))
                    self.assertNotIn("run", step)
            if "NTFY_PAGER_PUBLISH_TOKEN" in text:
                self.assertEqual(step.get("id"), "pager")
                self.assertIn("NTFY_PAGER_PUBLISH_TOKEN", json.dumps(step["env"]))
                self.assertNotIn("NTFY_PAGER_PUBLISH_TOKEN", str(step["run"]))
        (token_step,) = self.step_using("actions/create-github-app-token@")
        inputs = mapping(token_step["with"])
        self.assertEqual(inputs["app-id"], "${{ secrets.PAGER_APP_ID }}")
        self.assertEqual(inputs["private-key"], "${{ secrets.PAGER_APP_PRIVATE_KEY }}")
        self.assertEqual(inputs["permission-secret-scanning-alerts"], "read")
        self.assertEqual(set(inputs) & {"permission-contents", "permission-issues"}, set())

    def test_pager_step_gets_its_environment_from_the_expected_sources(self) -> None:
        step = self.pager_step()
        environment_block = mapping(step["env"])
        self.assertEqual(
            environment_block["PAGER_READ_TOKEN"], "${{ steps.app-token.outputs.token }}"
        )
        self.assertEqual(
            environment_block["NTFY_PAGER_PUBLISH_TOKEN"], "${{ secrets.NTFY_PAGER_PUBLISH_TOKEN }}"
        )
        self.assertTrue(str(environment_block["NTFY_BASE_URL"]).startswith("https://"))
        self.assertIn("python3 .github/scripts/secret_alert_pager.py", str(step["run"]))

    def test_state_cache_is_saved_under_a_new_key_and_verified(self) -> None:
        pager_step = self.pager_step()
        state_path = str(pager_step["run"]).split("--state-file ")[1].split()[0]
        restore, verify = self.step_using("actions/cache/restore@")
        (save,) = self.step_using("actions/cache/save@")
        restore_inputs = mapping(restore["with"])
        verify_inputs = mapping(verify["with"])
        self.assertEqual(restore_inputs["path"], state_path)
        self.assertEqual(restore_inputs["key"], self.KEY)
        self.assertEqual(str(restore_inputs["restore-keys"]).strip(), "secret-alert-pager-state-")
        self.assertEqual(save["with"], {"path": state_path, "key": self.KEY})
        self.assertEqual(save["if"], self.CONDITION)
        self.assertEqual(verify["if"], self.CONDITION)
        self.assertEqual(verify_inputs["key"], self.KEY)
        self.assertEqual(str(verify_inputs["lookup-only"]).lower(), "true")
        self.assertEqual(str(verify_inputs["fail-on-cache-miss"]).lower(), "true")
        steps = self.steps()
        self.assertLess(steps.index(pager_step), steps.index(save))
        self.assertLess(steps.index(save), steps.index(verify))


if __name__ == "__main__":
    unittest.main()
