"""The OVHcloud role read before `up`, against a fake HTTP sender. No network."""

from __future__ import annotations

import json
import unittest
from collections.abc import Mapping

from probe_preflight import PreflightError, check_role_read

ENV: Mapping[str, str] = {
    "OVH_ENDPOINT": "ovh-eu",
    "OVH_CLOUD_PROJECT_SERVICE": "5dd5eda4165c48fa80428816500bc992",
    "OVH_CLIENT_ID": "client-id-value",
    "OVH_CLIENT_SECRET": "client-secret-value",
}
ROLE_URL = "https://eu.api.ovh.com/v1/cloud/project/5dd5eda4165c48fa80428816500bc992/role"


class FakeSend:
    def __init__(self, token: int = 200, role: int = 200, token_body: str | None = None) -> None:
        self.token = token
        self.role = role
        self.token_body = token_body
        self.calls: list[tuple[str, str, Mapping[str, str], bytes | None]] = []

    def __call__(self, method, url, headers, body):  # type: ignore[no-untyped-def]
        self.calls.append((method, url, headers, body))
        if method == "POST":
            if self.token_body is not None:
                return self.token, self.token_body
            return self.token, json.dumps({"access_token": "token-value-0001"})
        return self.role, "[]"


class RoleReadTests(unittest.TestCase):
    def test_a_token_then_a_role_read_with_it_passes(self) -> None:
        send = FakeSend()
        check_role_read(send, ENV)
        self.assertEqual(["POST", "GET"], [c[0] for c in send.calls])
        self.assertEqual(ROLE_URL, send.calls[1][1])
        self.assertEqual("Bearer token-value-0001", send.calls[1][2]["Authorization"])
        self.assertIn(b"grant_type=client_credentials", send.calls[0][3] or b"")

    def test_a_403_on_the_role_read_is_named_with_its_status(self) -> None:
        with self.assertRaises(PreflightError) as caught:
            check_role_read(FakeSend(role=403), ENV)
        self.assertIn("this credential cannot read project roles: 403", str(caught.exception))

    def test_a_404_says_the_project_is_not_reachable(self) -> None:
        with self.assertRaises(PreflightError) as caught:
            check_role_read(FakeSend(role=404), ENV)
        self.assertIn("cannot read project roles: 404", str(caught.exception))
        self.assertIn("not reachable", str(caught.exception))

    def test_a_refused_token_stops_before_the_role_read(self) -> None:
        send = FakeSend(token=401)
        with self.assertRaises(PreflightError) as caught:
            check_role_read(send, ENV)
        self.assertIn("cannot get an access token: 401", str(caught.exception))
        self.assertEqual(["POST"], [c[0] for c in send.calls])

    def test_a_token_answer_without_a_token_is_refused(self) -> None:
        with self.assertRaises(PreflightError):
            check_role_read(FakeSend(token_body="{}"), ENV)

    def test_a_network_fault_is_named_by_type_and_carries_no_secret(self) -> None:
        def down(method, url, headers, body):  # type: ignore[no-untyped-def]
            raise ConnectionError("client-secret-value")

        with self.assertRaises(PreflightError) as caught:
            check_role_read(down, ENV)
        text = str(caught.exception)
        self.assertIn("ConnectionError", text)
        self.assertNotIn("client-secret-value", text)

    def test_a_malformed_project_id_is_refused_before_any_request(self) -> None:
        send = FakeSend()
        env = {**ENV, "OVH_CLOUD_PROJECT_SERVICE": "../../x"}
        with self.assertRaises(PreflightError):
            check_role_read(send, env)
        self.assertEqual([], send.calls)

    def test_an_unknown_endpoint_is_refused_before_any_request(self) -> None:
        send = FakeSend()
        with self.assertRaises(PreflightError):
            check_role_read(send, {**ENV, "OVH_ENDPOINT": "ovh-other"})
        self.assertEqual([], send.calls)

    def test_a_missing_client_secret_is_refused_before_any_request(self) -> None:
        send = FakeSend()
        with self.assertRaises(PreflightError):
            check_role_read(send, {**ENV, "OVH_CLIENT_SECRET": ""})
        self.assertEqual([], send.calls)


if __name__ == "__main__":
    unittest.main()
