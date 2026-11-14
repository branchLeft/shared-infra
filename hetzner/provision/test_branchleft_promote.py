#!/usr/bin/env python3
"""Unit tests for branchleft_promote.

The signature tests run the real ssh-keygen, because a stub that agrees with the
code proves nothing about the signature format the controller will produce. The
wrapper is never run here: its calls are recorded, and test_branchleft_promote_
wrapper_contract.py drives the real wrapper.
"""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import branchleft_promote as bp

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER_FILE = os.path.join(HERE, "branchleft_deploy.py")
UID = os.getuid()

NOW = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)
URL = "https://ledger.example.invalid/ledger.json"
TENANT = "ghcr.io/branchleft/ghost-tenant"
IMG_A = f"{TENANT}@sha256:{'a' * 64}"
IMG_B = f"{TENANT}@sha256:{'b' * 64}"
IMG_C = f"{TENANT}@sha256:{'c' * 64}"
SLOTS = [{"slot": 30001, "stack": "blog"}, {"slot": 30002, "stack": "canarystack"}]


def stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def ledger_body(seq=1, entries=None, issued=None, expires=None, **extra) -> bytes:
    document = {
        "v": 1,
        "seq": seq,
        "issued": stamp(issued or NOW - timedelta(hours=1)),
        "expires": stamp(expires or NOW + timedelta(hours=12)),
        "entries": entries if entries is not None else [],
    }
    document.update(extra)
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def entry(uid=30001, image=IMG_A, version="6.55.0") -> dict:
    return {"uid": uid, "image": image, "version": version}


class Keys:
    """A real ed25519 signing key and the allowed_signers file that trusts it."""

    def __init__(self, directory: str, name: str = "key", trusted: bool = True):
        self.private = os.path.join(directory, name)
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", self.private],
            check=True,
            capture_output=True,
        )
        with open(self.private + ".pub", encoding="utf-8") as handle:
            public = handle.read().split()
        self.allowed = os.path.join(directory, name + ".allowed_signers")
        principal = bp.SIGNER_IDENTITY if trusted else "someone-else"
        with open(self.allowed, "w", encoding="utf-8") as handle:
            handle.write(f'{principal} namespaces="{bp.NAMESPACE}" {public[0]} {public[1]}\n')
        os.chmod(self.allowed, 0o644)

    def sign(self, body: bytes, namespace: str = bp.NAMESPACE) -> bytes:
        path = self.private + ".payload"
        with open(path, "wb") as handle:
            handle.write(body)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-q", "-f", self.private, "-n", namespace, path],
            check=True,
            capture_output=True,
        )
        with open(path + ".sig", "rb") as handle:
            signature = handle.read()
        os.unlink(path + ".sig")
        return signature


def real_wrapper():
    return bp.load_wrapper(WRAPPER_FILE, trusted_uid=os.stat(WRAPPER_FILE).st_uid)


class Case(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = self.directory.name
        self.keys = Keys(self.root)
        self.state_dir = os.path.join(self.root, "state")
        os.mkdir(self.state_dir, 0o700)
        self.slots_path = self.write("slots.json", json.dumps(SLOTS))
        self.metrics = os.path.join(self.root, "promote.prom")
        self.wrapper_calls = []
        self.wrapper_results = []
        self.log_lines = []
        self.served = {}
        self.now = NOW

    def write(self, name: str, text: str, mode: int = 0o644) -> str:
        path = os.path.join(self.root, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(path, mode)
        return path

    def config(self, **changes) -> bp.Config:
        values = {
            "ledger_url": URL,
            "allowed_signers": self.keys.allowed,
            "slot_map": self.slots_path,
            "state_dir": self.state_dir,
            "wrapper": WRAPPER_FILE,
            "metrics_file": self.metrics,
            "trusted_uid": UID,
        }
        values.update(changes)
        return bp.Config(**values)

    def serve(self, body: bytes):
        self.served = {URL: body, URL + ".sig": self.keys.sign(body)}

    def fetch(self, url: str) -> bytes:
        if url not in self.served:
            raise bp.FetchError("not served")
        value = self.served[url]
        if isinstance(value, Exception):
            raise value
        return value

    def runner(self, argv, **kwargs):
        if argv[0] == "ssh-keygen":
            return subprocess.run(argv, **kwargs)
        self.wrapper_calls.append(list(argv))
        code = self.wrapper_results.pop(0) if self.wrapper_results else 0
        return subprocess.CompletedProcess(argv, code)

    def tick(self, **changes) -> int:
        return bp.run_once(
            self.config(**changes),
            fetch=self.fetch,
            run=self.runner,
            now=lambda: self.now,
            log=self.log_lines.append,
        )

    def state(self) -> bp.State:
        return bp.load_state(self.state_dir)


class ParseLedgerTests(unittest.TestCase):
    def refused(self, body: bytes):
        with self.assertRaises(bp.LedgerRefused):
            bp.parse_ledger(body)

    def test_reads_a_well_formed_ledger(self):
        ledger = bp.parse_ledger(ledger_body(seq=7, entries=[entry(), entry(30002, IMG_B)]))
        self.assertEqual(ledger.seq, 7)
        self.assertEqual([e.uid for e in ledger.entries], [30001, 30002])
        self.assertEqual(ledger.expires - ledger.issued, timedelta(hours=13))

    def test_refuses_what_is_not_json_or_not_utf8(self):
        for body in (b"", b"not json", b"\xff\xfe", b"[]", b"null", b"[" * 100000):
            self.refused(body)

    def test_refuses_a_repeated_key(self):
        body = b'{"v":1,"v":1,"seq":1,"issued":"2026-11-11T11:00:00Z","expires":"2026-11-11T12:00:00Z","entries":[]}'
        self.refused(body)

    def test_refuses_a_missing_or_extra_key(self):
        document = json.loads(ledger_body())
        del document["seq"]
        self.refused(json.dumps(document).encode())
        self.refused(ledger_body(tenant_name="x"))
        self.refused(ledger_body(entries=[{**entry(), "stack": "blog"}]))
        self.refused(ledger_body(entries=[{"uid": 30001, "image": IMG_A}]))

    def test_refuses_the_wrong_schema_version(self):
        self.refused(ledger_body(v=2))
        self.refused(ledger_body(v=True))

    def test_refuses_a_seq_that_is_not_a_positive_integer(self):
        for seq in (0, -1, True, 1.5, "1", None):
            self.refused(ledger_body(seq=seq))

    def test_refuses_badly_formed_times(self):
        for stamped in ("2026-11-11 11:00:00", "2026-11-11T11:00:00+00:00", "2026-13-11T11:00:00Z", 5):
            document = json.loads(ledger_body())
            document["issued"] = stamped
            self.refused(json.dumps(document).encode())

    def test_refuses_a_window_that_ends_before_it_starts(self):
        self.refused(ledger_body(expires=NOW - timedelta(hours=2)))

    def test_refuses_a_validity_window_longer_than_thirty_six_hours(self):
        issued = NOW - timedelta(hours=1)
        self.refused(ledger_body(issued=issued, expires=issued + timedelta(hours=36, seconds=1)))
        bp.parse_ledger(ledger_body(issued=issued, expires=issued + timedelta(hours=36)))

    def test_refuses_a_uid_outside_the_slot_range_or_not_an_integer(self):
        for uid in (29999, 31000, 0, True, "30001", 30001.0):
            self.refused(ledger_body(entries=[entry(uid=uid)]))

    def test_refuses_a_uid_that_appears_twice(self):
        self.refused(ledger_body(entries=[entry(), entry(image=IMG_B)]))

    def test_refuses_a_version_that_is_not_major_minor_patch(self):
        for version in ("6.55", "v6.55.0", "6.55.0-rc1", "6.55.0\n", "", 6):
            self.refused(ledger_body(entries=[entry(version=version)]))


class SignatureTests(Case):
    def verify(self, body: bytes, signature: bytes, allowed: str | None = None):
        bp.verify_signature(body, signature, allowed or self.keys.allowed)

    def test_accepts_the_trusted_signers_signature(self):
        body = ledger_body()
        self.verify(body, self.keys.sign(body))

    def test_refuses_a_tampered_body(self):
        body = ledger_body(seq=1)
        signature = self.keys.sign(body)
        with self.assertRaises(bp.LedgerRefused):
            self.verify(ledger_body(seq=2), signature)

    def test_refuses_a_truncated_or_empty_signature(self):
        body = ledger_body()
        signature = self.keys.sign(body)
        for broken in (signature[: len(signature) // 2], b"", b"garbage"):
            with self.assertRaises(bp.LedgerRefused):
                self.verify(body, broken)

    def test_refuses_a_signature_made_for_another_namespace(self):
        body = ledger_body()
        with self.assertRaises(bp.LedgerRefused):
            self.verify(body, self.keys.sign(body, namespace="some-other-namespace"))

    def test_refuses_a_key_that_is_not_in_allowed_signers(self):
        body = ledger_body()
        stranger = Keys(self.root, "stranger")
        with self.assertRaises(bp.LedgerRefused):
            self.verify(body, stranger.sign(body))

    def test_refuses_a_key_listed_under_another_principal(self):
        body = ledger_body()
        other = Keys(self.root, "other", trusted=False)
        with self.assertRaises(bp.LedgerRefused):
            self.verify(body, other.sign(body), allowed=other.allowed)

    def test_refuses_an_empty_or_missing_allowed_signers_file(self):
        body = ledger_body()
        signature = self.keys.sign(body)
        empty = self.write("empty_signers", "")
        for path in (empty, os.path.join(self.root, "nowhere")):
            with self.assertRaises(bp.LedgerRefused):
                self.verify(body, signature, allowed=path)

    def test_refuses_when_ssh_keygen_cannot_run(self):
        def missing(argv, **kwargs):
            raise FileNotFoundError("ssh-keygen")

        def slow(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 1)

        for failing in (missing, slow):
            with self.assertRaises(bp.LedgerRefused):
                bp.verify_signature(b"x", b"y", self.keys.allowed, run=failing)


class JudgeTests(unittest.TestCase):
    def setUp(self):
        self.wrapper = real_wrapper()
        self.slot_map = {30001: "blog", 30002: "canarystack"}

    def judge(self, ledger_entries, state=None, *, seq=5, now=NOW, **times):
        ledger = bp.parse_ledger(ledger_body(seq=seq, entries=ledger_entries, **times))
        return bp.judge(ledger, state or bp.State(last_seq=4), self.slot_map, now, self.wrapper)

    def running(self, image=IMG_A, version="6.55.0", previous=None, previous_version=None, **more):
        slot = bp.SlotState(
            applied_image=image,
            applied_version=version,
            previous_image=previous,
            previous_version=previous_version,
            **more,
        )
        return bp.State(last_seq=4, slots={30001: slot})

    def test_a_new_digest_for_a_known_slot_is_an_action(self):
        result = self.judge([entry(image=IMG_B, version="6.55.1")], self.running())
        self.assertEqual(result.actions, (bp.Action(30001, "blog", IMG_B, "6.55.1"),))
        self.assertEqual(result.refusals, ())

    def test_an_older_seq_is_refused_whole_as_a_replay(self):
        result = self.judge([entry(image=IMG_B)], self.running(), seq=3)
        self.assertIn("replay", result.ledger_refusal)
        self.assertEqual(result.actions, ())

    def test_the_same_ledger_seen_again_is_up_to_date_not_an_error(self):
        ledger = bp.parse_ledger(ledger_body(seq=5, entries=[entry()]))
        state = bp.State(last_seq=5, last_digest=ledger.digest)
        result = bp.judge(ledger, state, self.slot_map, NOW, self.wrapper)
        self.assertTrue(result.up_to_date)
        self.assertIsNone(result.ledger_refusal)

    def test_a_reused_seq_with_different_content_is_refused(self):
        state = bp.State(last_seq=5, last_digest="0" * 64)
        result = self.judge([entry()], state, seq=5)
        self.assertEqual(result.ledger_refusal, "seq reused with different content")

    def test_an_expired_ledger_is_refused_even_if_its_seq_is_new(self):
        result = self.judge([entry()], now=NOW + timedelta(hours=13))
        self.assertEqual(result.ledger_refusal, "the ledger has expired")
        self.assertEqual(result.actions, ())

    def test_a_ledger_issued_in_the_future_is_refused(self):
        early = NOW - timedelta(minutes=6)
        result = self.judge([entry()], now=early, issued=NOW)
        self.assertEqual(result.ledger_refusal, "the ledger is issued in the future")

    def test_a_lower_version_is_refused_as_a_downgrade(self):
        result = self.judge([entry(image=IMG_B, version="6.54.0")], self.running(previous=IMG_C))
        self.assertEqual(result.actions, ())
        self.assertEqual(result.refusals[0].uid, 30001)
        self.assertIn("downgrade", result.refusals[0].reason)

    def test_a_lower_version_is_accepted_only_as_the_revert_to_the_previous_digest(self):
        state = self.running(image=IMG_B, version="6.55.1", previous=IMG_A, previous_version="6.55.0")
        result = self.judge([entry(image=IMG_A, version="6.55.0")], state)
        self.assertEqual(result.actions, (bp.Action(30001, "blog", IMG_A, "6.55.0"),))
        other = self.judge([entry(image=IMG_C, version="6.55.0")], state)
        self.assertEqual(other.actions, ())
        self.assertIn("downgrade", other.refusals[0].reason)

    def test_a_rebuild_at_the_same_version_is_not_a_downgrade(self):
        result = self.judge([entry(image=IMG_B, version="6.55.0")], self.running())
        self.assertEqual(len(result.actions), 1)

    def test_the_digest_already_running_is_unchanged_not_an_action(self):
        result = self.judge([entry(image=IMG_A)], self.running())
        self.assertEqual((result.actions, result.refusals, result.unchanged), ((), (), (30001,)))

    def test_a_digest_that_failed_or_was_interrupted_is_not_tried_again(self):
        for state in (self.running(blocked=(IMG_B,)), self.running(pending_image=IMG_B)):
            result = self.judge([entry(image=IMG_B, version="6.55.1")], state)
            self.assertEqual(result.actions, ())
            self.assertIn("failed or was interrupted", result.refusals[0].reason)

    def test_an_image_off_the_register_is_refused(self):
        other = "ghcr.io/branchleft/not-registered@sha256:" + "a" * 64
        result = self.judge([entry(image=other)])
        self.assertEqual(result.actions, ())
        self.assertIn("register", result.refusals[0].reason)

    def test_a_tag_form_or_port_form_image_is_refused(self):
        for image in (
            f"{TENANT}:latest@sha256:{'a' * 64}",
            f"ghcr.io:443/branchleft/ghost-tenant@sha256:{'a' * 64}",
            f"{TENANT}:latest",
            f"{TENANT}@sha256:{'a' * 63}",
            f"{TENANT}@sha256:{'a' * 64}\n",
        ):
            result = self.judge([entry(image=image)])
            self.assertEqual(result.actions, (), image)
            self.assertEqual(len(result.refusals), 1, image)

    def test_a_uid_with_no_slot_map_row_is_refused(self):
        result = self.judge([entry(uid=30500)])
        self.assertEqual(result.actions, ())
        self.assertIn("no slot map row", result.refusals[0].reason)

    def test_one_refused_entry_does_not_stop_the_others(self):
        result = self.judge([entry(30001, IMG_B), entry(30002, "ghcr.io/x/y@sha256:" + "a" * 64)])
        self.assertEqual([a.uid for a in result.actions], [30001])
        self.assertEqual([r.uid for r in result.refusals], [30002])


class RunOnceTests(Case):
    def serve_ledger(self, seq=1, entries=None, **times):
        self.serve(ledger_body(seq=seq, entries=entries if entries is not None else [entry()], **times))

    def test_a_good_ledger_moves_the_slot_through_the_wrapper_and_records_it(self):
        self.serve_ledger(entries=[entry(30001, IMG_A, "6.55.0")])
        self.assertEqual(self.tick(), 0)
        self.assertEqual(self.wrapper_calls, [[WRAPPER_FILE, "blog", IMG_A]])
        slot = self.state().slots[30001]
        self.assertEqual((slot.applied_image, slot.applied_version, slot.pending_image), (IMG_A, "6.55.0", None))
        self.assertEqual(self.state().last_seq, 1)

    def test_the_same_ledger_on_the_next_tick_changes_nothing(self):
        self.serve_ledger()
        self.tick()
        self.assertEqual(self.tick(), 0)
        self.assertEqual(len(self.wrapper_calls), 1)

    def test_a_failing_wrapper_is_called_once_across_two_ticks_and_the_run_fails(self):
        self.wrapper_results = [1]
        self.serve_ledger()
        self.assertEqual(self.tick(), 1)
        self.assertEqual(self.tick(), 0)
        self.assertEqual(len(self.wrapper_calls), 1)
        self.assertIn(IMG_A, self.state().slots[30001].blocked)
        self.assertEqual(self.state().slots[30001].applied_image, None)

    def test_a_failed_digest_waits_for_a_different_digest_in_a_newer_ledger(self):
        self.wrapper_results = [1]
        self.serve_ledger(seq=1, entries=[entry(image=IMG_A)])
        self.tick()
        self.serve_ledger(seq=2, entries=[entry(image=IMG_A)])
        self.assertEqual(self.tick(), 1)
        self.assertEqual(len(self.wrapper_calls), 1)
        self.serve_ledger(seq=3, entries=[entry(image=IMG_B, version="6.55.1")])
        self.assertEqual(self.tick(), 0)
        self.assertEqual(self.wrapper_calls[-1], [WRAPPER_FILE, "blog", IMG_B])

    def test_a_crash_between_the_write_ahead_and_the_result_blocks_that_digest(self):
        class Crash(BaseException):
            pass

        def dies(argv, **kwargs):
            if argv[0] == "ssh-keygen":
                return subprocess.run(argv, **kwargs)
            raise Crash()

        self.serve_ledger()
        with self.assertRaises(Crash):
            bp.run_once(self.config(), fetch=self.fetch, run=dies, now=lambda: self.now, log=print)
        self.assertEqual(self.state().slots[30001].pending_image, IMG_A)
        self.assertEqual(self.state().last_seq, 0)
        self.serve_ledger(seq=2, entries=[entry(image=IMG_A)])
        self.assertEqual(self.tick(), 1)
        self.assertEqual(self.wrapper_calls, [])

    def test_one_refused_slot_leaves_the_others_applied_and_the_run_fails(self):
        off_register = "ghcr.io/branchleft/not-registered@sha256:" + "a" * 64
        self.serve_ledger(entries=[entry(30001, IMG_A), entry(30002, off_register)])
        self.assertEqual(self.tick(), 1)
        self.assertEqual(self.wrapper_calls, [[WRAPPER_FILE, "blog", IMG_A]])
        self.assertEqual(self.state().slots[30001].applied_image, IMG_A)

    def leaks(self) -> list[str]:
        canaries = ("blog", "canarystack", "ghost-tenant", "not-registered", "sha256", "branchleft/")
        return [word for word in canaries if any(word in line for line in self.log_lines)]

    def test_the_log_names_uids_only(self):
        off_register = "ghcr.io/branchleft/not-registered@sha256:" + "a" * 64
        self.serve_ledger(entries=[entry(30001, IMG_A), entry(30002, off_register)])
        self.tick()
        text = " ".join(self.log_lines)
        self.assertIn("30001", text)
        self.assertIn("30002", text)
        self.assertEqual(self.leaks(), [])

    def test_the_leak_scan_can_fail(self):
        self.log_lines.append("slot 30001 moved blog to " + IMG_A)
        self.assertIn("blog", self.leaks())
        self.assertIn("ghost-tenant", self.leaks())

    def test_an_unreachable_ledger_changes_nothing_and_reports_staleness(self):
        self.serve_ledger()
        self.tick()
        before = self.state()
        self.now = NOW + timedelta(hours=2)
        self.served = {URL: bp.FetchError("down")}
        self.assertEqual(self.tick(), 1)
        self.assertEqual(len(self.wrapper_calls), 1)
        self.assertEqual(self.state(), before)
        with open(self.metrics, encoding="utf-8") as handle:
            metrics = handle.read()
        self.assertIn(f"last_success_timestamp_seconds {int(NOW.timestamp())}", metrics)
        self.assertIn(f"last_run_timestamp_seconds {int(self.now.timestamp())}", metrics)

    def test_an_expired_ledger_causes_no_wrapper_call(self):
        self.serve_ledger()
        self.now = NOW + timedelta(hours=14)
        self.assertEqual(self.tick(), 1)
        self.assertEqual(self.wrapper_calls, [])
        self.assertEqual(self.state(), bp.State())

    def test_a_replayed_older_ledger_causes_no_wrapper_call(self):
        self.serve_ledger(seq=5, entries=[entry(image=IMG_B, version="6.55.1")])
        self.tick()
        self.serve_ledger(seq=4, entries=[entry(image=IMG_C, version="6.56.0")])
        self.assertEqual(self.tick(), 1)
        self.assertEqual(len(self.wrapper_calls), 1)

    def test_a_forged_ledger_causes_no_wrapper_call_and_no_state_change(self):
        body = ledger_body(entries=[entry()])
        stranger = Keys(self.root, "stranger")
        for served in (
            {URL: body, URL + ".sig": stranger.sign(body)},
            {URL: body + b" ", URL + ".sig": self.keys.sign(body)},
            {URL: body, URL + ".sig": b""},
        ):
            self.served = served
            self.assertEqual(self.tick(), 1)
        self.assertEqual(self.wrapper_calls, [])
        self.assertEqual(self.state(), bp.State())

    def test_a_missing_signature_file_causes_no_wrapper_call(self):
        self.serve_ledger()
        del self.served[URL + ".sig"]
        self.assertEqual(self.tick(), 1)
        self.assertEqual(self.wrapper_calls, [])

    def test_a_corrupt_state_file_refuses_everything(self):
        self.serve_ledger()
        self.tick()
        with open(os.path.join(self.state_dir, "state.json"), "w", encoding="utf-8") as handle:
            handle.write("{")
        self.serve_ledger(seq=2, entries=[entry(image=IMG_B, version="6.55.1")])
        self.assertEqual(self.tick(), 1)
        self.assertEqual(len(self.wrapper_calls), 1)

    def test_a_trust_anchor_the_deploy_account_could_edit_is_refused(self):
        self.serve_ledger()
        os.chmod(self.keys.allowed, 0o664)
        self.assertEqual(self.tick(), 1)
        os.chmod(self.keys.allowed, 0o644)
        os.chmod(self.slots_path, 0o666)
        self.assertEqual(self.tick(), 1)
        os.chmod(self.slots_path, 0o644)
        os.chmod(self.state_dir, 0o770)
        self.assertEqual(self.tick(), 1)
        self.assertEqual(self.wrapper_calls, [])

    def test_a_linked_trust_anchor_is_refused(self):
        self.serve_ledger()
        link = os.path.join(self.root, "linked_signers")
        os.symlink(self.keys.allowed, link)
        self.assertEqual(self.tick(allowed_signers=link), 1)
        self.assertEqual(self.wrapper_calls, [])

    def test_a_trust_anchor_owned_by_someone_else_is_refused(self):
        self.serve_ledger()
        self.assertEqual(self.tick(trusted_uid=UID + 1), 1)
        self.assertEqual(self.wrapper_calls, [])

    def test_a_slot_map_with_a_repeated_stack_is_refused(self):
        self.serve_ledger()
        repeated = [{"slot": 30001, "stack": "blog"}, {"slot": 30002, "stack": "blog"}]
        self.assertEqual(self.tick(slot_map=self.write("dup.json", json.dumps(repeated))), 1)
        self.assertEqual(self.wrapper_calls, [])

    def test_a_slot_map_naming_an_unsafe_stack_is_refused(self):
        self.serve_ledger()
        bad = self.write("bad.json", json.dumps([{"slot": 30001, "stack": "../etc"}]))
        self.assertEqual(self.tick(slot_map=bad), 1)
        self.assertEqual(self.wrapper_calls, [])

    def test_a_wrapper_that_is_not_the_wrapper_is_refused(self):
        self.serve_ledger()
        fake = self.write("fake_wrapper.py", "ATTESTED_IMAGES = {}\n")
        self.assertEqual(self.tick(wrapper=fake), 1)
        self.assertEqual(self.wrapper_calls, [])

    def test_the_register_is_the_wrappers_own_not_a_copy(self):
        wrapper = real_wrapper()
        self.assertIs(type(wrapper.ATTESTED_IMAGES), dict)
        self.assertIn(TENANT, wrapper.ATTESTED_IMAGES)
        self.assertNotIn("ATTESTED_IMAGES", vars(bp))

    def test_the_drift_metric_names_a_slot_whose_desired_image_is_not_running(self):
        off_register = "ghcr.io/branchleft/not-registered@sha256:" + "a" * 64
        self.serve_ledger(entries=[entry(30001, IMG_A), entry(30002, off_register)])
        self.tick()
        with open(self.metrics, encoding="utf-8") as handle:
            metrics = handle.read()
        self.assertIn('branchleft_promote_slot_drift{uid="30001"} 0', metrics)
        self.assertIn('branchleft_promote_slot_drift{uid="30002"} 1', metrics)
        self.assertNotIn("blog", metrics)

    def test_a_revert_entry_returns_to_the_previous_digest_and_blocks_the_one_it_left(self):
        self.serve_ledger(seq=1, entries=[entry(image=IMG_A, version="6.55.0")])
        self.tick()
        self.serve_ledger(seq=2, entries=[entry(image=IMG_B, version="6.55.1")])
        self.tick()
        self.serve_ledger(seq=3, entries=[entry(image=IMG_A, version="6.55.0")])
        self.assertEqual(self.tick(), 0)
        self.assertEqual(self.wrapper_calls[-1], [WRAPPER_FILE, "blog", IMG_A])
        self.serve_ledger(seq=4, entries=[entry(image=IMG_B, version="6.55.1")])
        self.assertEqual(self.tick(), 1)
        self.assertEqual(len(self.wrapper_calls), 3)

    def test_a_downgrade_to_any_other_digest_is_refused_end_to_end(self):
        self.serve_ledger(seq=1, entries=[entry(image=IMG_B, version="6.55.1")])
        self.tick()
        self.serve_ledger(seq=2, entries=[entry(image=IMG_C, version="6.50.0")])
        self.assertEqual(self.tick(), 1)
        self.assertEqual(len(self.wrapper_calls), 1)


class MainTests(unittest.TestCase):
    def test_a_missing_ledger_url_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bp.main(["branchleft-promote"]), 2)

    def test_an_unknown_option_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bp.main(["branchleft-promote", "--ledger-url", URL, "--force"]), 2)

    def test_a_plain_http_url_is_refused_before_anything_is_fetched(self):
        with self.assertRaises(bp.FetchError):
            bp.fetch_url("http://ledger.example.invalid/ledger.json")


if __name__ == "__main__":
    unittest.main()
