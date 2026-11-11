"""Unit tests for the bundle source of pull_trigger: a host that takes its commit on standard input.

The cases use real git, real bundles and real signatures on throwaway repositories, and call the
program through ``main`` exactly as the forced command does. The pull route has its own tests in
``test_pull_trigger``; the cases here that touch it only show that it is unchanged.
"""

import contextlib
import dataclasses
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from unittest import mock

import pull_trigger as trigger
from test_pull_trigger import (
    GIT,
    GPG,
    GPGCONF,
    SSH_KEYGEN,
    GpgKey,
    Remote,
    Run,
    SshKey,
    fake_ansible,
    forget_gpg,
    git_command,
    make_gpg_key,
    make_ssh_key,
    playbook_text,
    run,
    snapshot,
    valid_config_data,
)

PLAY = "ansible/playbooks/host.yml"
# The line the workflow that pushes to a host reads, held here exactly as that workflow holds it
# (github-workflows, the judge of a pushed host). Every line this program prints on the bundle
# source must match it, and its `changed` field is a digit on every outcome.
PUSH_LINE = re.compile(
    r"^push-receiver verdict=([a-z-]+) exit=([0-9]+) reason=([a-z-]+) mode=(check|apply) "
    r"commit=([0-9a-f]{40}) playbook=[A-Za-z0-9_./-]+ changed=([0-9]+)$"
)
WATCHDOG_SECONDS = 20


def binary_run(argv: Sequence[str | Path], cwd: Path, stdin: bytes) -> str:
    """Run a fixture command that takes binary standard input and return its stripped output."""
    done = subprocess.run(  # noqa: S603 - test fixtures, argument lists, no shell
        [str(item) for item in argv],
        cwd=cwd,
        env={**os.environ, "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z"},
        input=stdin,
        capture_output=True,
        check=True,
    )
    return done.stdout.decode().strip()


class BundleHistory:
    """The signed history every case reads, and the bundles of its commits."""

    def __init__(self, root: Path) -> None:
        """Make the keys, the history and the work area for bundles under ``root``."""
        self.root = root
        keys = root / "keys"
        keys.mkdir()
        self.web_flow: GpgKey = make_gpg_key(root, "web-flow-stand-in")
        self.other_pgp: GpgKey = make_gpg_key(root, "other")
        self.other_ssh: SshKey = make_ssh_key(keys, "other-ssh")
        self.remote = Remote.create(root)
        w = self.web_flow
        commits: dict[str, str] = {}

        def commit(name: str, parent: str | None, signer: SshKey | GpgKey | None = w) -> None:
            files = {PLAY: playbook_text(name)}
            commits[name] = self.remote.commit(files, name, parent, signer)

        commit("c0", None)
        commit("c1", commits["c0"])
        commit("c2", commits["c1"])
        commit("unsigned", commits["c1"], None)
        commit("by_ssh", commits["c1"], self.other_ssh)
        commit("by_other_pgp", commits["c1"], self.other_pgp)
        signed = self.remote.commit({PLAY: playbook_text("t")}, "to be tampered", commits["c1"], w)
        commits["tampered"] = self.remote.forge(signed, "to be tampered", "tampered after signing")
        commit("side", commits["c0"])
        commit("orphan", None)
        commit("fork", commits["c2"])
        commit("main_next", commits["c2"])
        commits["no_playbook"] = self.remote.commit({PLAY: None}, "no playbook", commits["c2"], w)
        commits["symlink"] = self.remote.commit(
            {PLAY: "->../../../etc/hostname"}, "link", commits["c2"], w
        )
        commits["malformed"] = self.malformed(commits["c2"])
        self.commits = commits

    def malformed(self, parent: str) -> str:
        """Return a signed commit whose tree holds an object git's own object check refuses.

        The tree is made with ``hash-object --literally``: its hash is right, and a bundle that
        carries it passes ``git bundle verify``. One entry has a zero-padded mode.
        """
        work = self.remote.work
        empty = run([*git_command(), "hash-object", "-t", "tree", "-w", "--stdin"], cwd=work)
        raw = (
            b"40000 ansible\0"
            + bytes.fromhex(
                run([*git_command(), "rev-parse", f"{parent}:ansible"], cwd=work),
            )
            + b"040000 junk\0"
            + bytes.fromhex(empty)
        )
        bad_tree = binary_run(
            [*git_command(), "hash-object", "-t", "tree", "--literally", "-w", "--stdin"],
            work,
            raw,
        )
        argv = git_command(self.web_flow) + ["commit-tree", "-S", "-p", parent, "-m", "m", bad_tree]
        return run(argv, cwd=work, extra={"GNUPGHOME": str(self.web_flow.home)})

    def bundle(self, name: str, directory: Path) -> Path:
        """Return a bundle of the named commit, made the way the pushing workflow makes it."""
        sha = self.commits[name]
        work = self.remote.work
        run([*git_command(), "update-ref", "--no-deref", "HEAD", sha], cwd=work)
        path = directory / f"{name}.bundle"
        run([*git_command(), "bundle", "create", path, "HEAD"], cwd=work)
        return path

    def forget(self) -> None:
        """Stop the agents the keys started."""
        for key in (self.web_flow, self.other_pgp):
            forget_gpg(key)


class Broken(io.StringIO):
    """A text stream whose reader has gone: every write is a broken pipe."""

    def write(self, text: str) -> int:
        """Refuse the write the way a closed pipe does.

        Raises:
            BrokenPipeError: Always.
        """
        raise BrokenPipeError(text)


class BrokenBytes(io.BytesIO):
    """A binary stream whose reader has gone."""

    def write(self, data: object) -> int:
        """Refuse the write the way a closed pipe does.

        Raises:
            BrokenPipeError: Always.
        """
        raise BrokenPipeError(str(data))


@dataclasses.dataclass
class Host:
    """One test's host directories, configuration and stand-in ansible-playbook."""

    root: Path
    config_path: Path
    state: Path
    logs: Path
    calls: Path

    @property
    def floor(self) -> Path:
        """The file that records the last commit applied."""
        return self.state / "last-applied"

    def seed(self, commit: str) -> None:
        """Write the floor, as the bootstrap does."""
        self.state.mkdir(mode=0o700, exist_ok=True)
        self.floor.write_text(f"{commit}\n", encoding="utf-8")
        self.floor.chmod(0o600)

    def applied(self) -> list[str]:
        """Return the calls the stand-in ansible-playbook recorded."""
        text = self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""
        return [line for line in text.splitlines() if line.startswith("-i")]


class BundleTests(unittest.TestCase):
    """The whole program on the bundle source."""

    history: BundleHistory
    bundles: Path
    made: dict[str, Path]
    root: Path

    @classmethod
    def setUpClass(cls) -> None:
        """Make the signed history once."""
        cls.root = Path(tempfile.mkdtemp(prefix="pt-bundle-fixture-")).resolve()
        cls.history = BundleHistory(cls.root)
        cls.bundles = cls.root / "bundles"
        cls.bundles.mkdir()
        cls.made = {}

    @classmethod
    def tearDownClass(cls) -> None:
        """Remove the fixture and stop the agents."""
        cls.history.forget()
        shutil.rmtree(cls.root, ignore_errors=True)

    def bundle(self, name: str) -> Path:
        """Return the bundle of a named commit, made once."""
        if name not in self.made:
            self.made[name] = self.history.bundle(name, self.bundles)
        return self.made[name]

    def commit(self, name: str) -> str:
        """Return a named commit's id."""
        return self.history.commits[name]

    def make_host(self, changed: int = 1, **config: object) -> Host:
        """Make a host that takes bundles: a short path (gpg's socket lives beneath it)."""
        root = Path(tempfile.mkdtemp(prefix="pb", dir="/tmp")).resolve()  # noqa: S108
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        root.chmod(0o700)
        helper = root / "bin"
        helper.mkdir()
        ansible = fake_ansible(helper, changed=changed)
        etc = root / "etc"
        etc.mkdir(mode=0o755)
        data = valid_config_data(
            signers=[{"format": "openpgp", "key": self.history.web_flow.armoured}],
            ansible_playbook=str(ansible),
            state_dir=str(root / "state"),
            log_dir=str(root / "logs"),
            timeout_seconds=60,
            source="bundle",
        )
        data.update(config)
        path = etc / "config.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        path.chmod(0o644)
        return Host(root, path, root / "state", root / "logs", helper / "calls.txt")

    def push(  # noqa: PLR0913 - one keyword per thing a case varies
        self,
        host: Host,
        commit: str | None = None,
        *,
        mode: str = "apply",
        word: str | None = None,
        playbook: str = PLAY,
        bundle: Path | bytes | None = None,
        text: str | None = None,
        receiving: trigger.Receiving | None = None,
        positional: Sequence[str] = (),
    ) -> Run:
        """Call the program as the forced command would and collect what it printed.

        The request text is ``<word> <commit> <playbook>``; the bundle is the file or bytes
        given, standard input being empty when none is.
        """
        out, relayed, errors = io.StringIO(), io.BytesIO(), io.StringIO()
        sent = text if text is not None else f"{word or mode} {commit} {playbook}"
        argv = ["--mode", mode, "--config", str(host.config_path), *positional]
        tools = trigger.Tools(
            git=GIT,
            gpg=Path(GPG or "/usr/bin/gpg"),
            gpgconf=Path(GPGCONF or "/usr/bin/gpgconf"),
            ssh_keygen=SSH_KEYGEN,
        )
        source = host.root / "stdin"
        if isinstance(bundle, Path):
            shutil.copyfile(bundle, source)
        else:
            source.write_bytes(bundle or b"")
        descriptor = os.open(source, os.O_RDONLY)
        try:
            limits = receiving or trigger.Receiving()
            limits = dataclasses.replace(limits, descriptor=descriptor)
            with contextlib.redirect_stderr(errors):
                code = trigger.main(
                    argv,
                    {"SSH_ORIGINAL_COMMAND": sent},
                    threading.Event(),
                    tools,
                    out,
                    relayed,
                    limits,
                )
        finally:
            os.close(descriptor)
        return Run(code, out.getvalue().strip(), errors.getvalue(), relayed.getvalue().decode())

    def assert_refused(self, result: Run, reason: str, code: int = 20) -> None:
        """Assert a refusal with its reason, and a line the pushing workflow can read."""
        self.assertEqual(code, result.code, result.summary + result.errors)
        self.assertTrue(result.has(f"reason={reason}"), result.summary)
        self.assert_line_matches(result)

    def assert_line_matches(self, result: Run) -> None:
        """Assert that the line has the judge's shape, with a digit for changed."""
        self.assertRegex(result.summary, PUSH_LINE)

    def assert_nothing_left(self, host: Host) -> None:
        """Assert that no spool file, quarantine or checkout is left behind."""
        for name in ("spool", "quarantine"):
            leftovers = list((host.state / name).iterdir()) if (host.state / name).exists() else []
            self.assertEqual([], leftovers, name)

    @contextlib.contextmanager
    def untouched(self, host: Host) -> Iterator[None]:
        """Assert that the floor, the current checkout and the work area are as they were."""

        def described() -> dict[str, str]:
            state = snapshot(host.state) if host.state.exists() else {}
            kept = ("last-applied", "current", "work/")
            return {k: v for k, v in state.items() if k.startswith(kept)}

        before = described()
        yield
        self.assertEqual(before, described())

    # ------------------------------------------------------------ the safety-class gate

    def test_request_mode_word_must_equal_key_mode(self) -> None:
        for key_mode, word in (("check", "apply"), ("apply", "check")):
            with self.subTest(key=key_mode, word=word):
                host = self.make_host()
                host.seed(self.commit("c0"))
                with self.untouched(host):
                    result = self.push(
                        host, self.commit("c1"), mode=key_mode, word=word, bundle=self.bundle("c1")
                    )
                self.assert_refused(result, "mode-mismatch")
                # The line shows the mode the key fixes, never the word the caller sent.
                self.assertTrue(result.has(f"mode={key_mode}"), result.summary)
                self.assertEqual([], host.applied())
                self.assertEqual(f"{self.commit('c0')}\n", host.floor.read_text(encoding="utf-8"))
                self.assertFalse((host.state / "current").exists())

    def test_the_mode_word_is_compared_before_the_bundle_is_read(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        result = self.push(
            host, self.commit("c1"), mode="check", word="apply", bundle=b"not a bundle at all"
        )
        self.assert_refused(result, "mode-mismatch")

    # ----------------------------------------------------------- the request

    def test_the_request_is_three_words_and_nothing_else(self) -> None:
        commit, host = self.commit("c1"), self.make_host()
        host.seed(self.commit("c0"))
        hostile = {
            "a bare commit": commit,
            "two words": f"apply {commit}",
            "four words": f"apply {commit} {PLAY} extra",
            "trailing newline": f"apply {commit} {PLAY}\n",
            "double space": f"apply  {commit} {PLAY}",
            "tab": f"apply\t{commit}\t{PLAY}",
            "uppercase commit": f"apply {commit.upper()} {PLAY}",
            "short commit": f"apply {commit[:39]} {PLAY}",
            "mode word step": f"step {commit} {PLAY}",
            "mode word upper": f"APPLY {commit} {PLAY}",
            "playbook climbs": f"apply {commit} ansible/playbooks/../../etc/passwd",
            "playbook absolute": f"apply {commit} /etc/passwd",
            "playbook is an option": f"apply {commit} --tags",
            "playbook outside playbooks": f"apply {commit} ansible/roles/x/main.yml",
            "playbook with a dollar": f"apply {commit} ansible/playbooks/$x.yml",
            "empty": "",
        }
        for name, text in hostile.items():
            with self.subTest(name), self.untouched(host):
                result = self.push(host, text=text, bundle=self.bundle("c1"))
                self.assertEqual(20, result.code, result.summary)
                self.assertTrue(result.has("reason=bad-request"), result.summary)
        self.assertEqual([], host.applied())

    def test_a_request_too_malformed_to_name_a_commit_prints_a_dash_and_no_digit_is_missing(
        self,
    ) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        result = self.push(host, text="nonsense")
        self.assertEqual(
            "push-receiver verdict=refused exit=20 reason=bad-request mode=apply "
            f"commit=- playbook={PLAY} changed=0",
            result.summary,
        )
        self.assertIsNone(PUSH_LINE.fullmatch(result.summary))

    def test_the_step_mode_is_refused_on_this_source(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        result = self.push(host, self.commit("c1"), mode="step", bundle=self.bundle("c1"))
        self.assertEqual(20, result.code)
        self.assertTrue(result.has("reason=bad-request"), result.summary)

    def test_a_commit_given_as_a_positional_word_is_refused_on_this_source(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        result = self.push(
            host, self.commit("c1"), bundle=self.bundle("c1"), positional=[self.commit("c1")]
        )
        self.assertEqual(20, result.code)
        self.assertTrue(result.has("reason=bad-request"), result.summary)

    def test_no_ssh_text_is_refused(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        out, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = trigger.main(
                ["--mode", "apply", "--config", str(host.config_path)],
                {},
                threading.Event(),
                trigger.Tools(),
                out,
                io.BytesIO(),
            )
        self.assertEqual(20, code)
        self.assertIn("reason=bad-request", out.getvalue())

    def test_the_playbook_in_the_request_must_be_the_configured_one(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        with self.untouched(host):
            result = self.push(
                host,
                self.commit("c1"),
                playbook="ansible/playbooks/other.yml",
                bundle=self.bundle("c1"),
            )
        self.assert_refused(result, "playbook-not-allowed")
        # The line names the configured playbook, not the one the caller sent.
        self.assertTrue(result.has(f"playbook={PLAY}"), result.summary)
        self.assertEqual([], host.applied())

    def test_a_configured_playbook_that_is_not_on_the_allowlist_is_refused(self) -> None:
        host = self.make_host(playbooks=["ansible/playbooks/elsewhere.yml"])
        host.seed(self.commit("c0"))
        result = self.push(host, self.commit("c1"), bundle=self.bundle("c1"))
        self.assert_refused(result, "playbook-not-allowed")
        self.assertEqual([], host.applied())

    # ------------------------------------------------------------ applying

    def test_a_signed_commit_that_descends_from_the_floor_is_applied_and_recorded(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        result = self.push(host, self.commit("c1"), bundle=self.bundle("c1"))
        self.assertEqual(10, result.code, result.summary + result.errors)
        self.assert_line_matches(result)
        self.assertTrue(result.has("verdict=applied"), result.summary)
        self.assertTrue(result.has("changed=1"), result.summary)
        self.assertEqual(f"{self.commit('c1')}\n", host.floor.read_text(encoding="utf-8"))
        self.assertEqual(1, len(host.applied()))
        self.assertIn("PLAY RECAP", result.relayed)
        checkout = (host.state / "current").resolve()
        self.assertIn("# c1", (checkout / PLAY).read_text(encoding="utf-8"))
        self.assertFalse((checkout / ".git").exists())
        self.assert_nothing_left(host)

    def test_the_playbook_runs_from_the_exact_checkout_with_the_pull_routes_arguments(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        self.push(host, self.commit("c1"), bundle=self.bundle("c1"))
        checkout = (host.state / "current").resolve()
        self.assertEqual([f"-i localhost, --connection local {checkout}/{PLAY}"], host.applied())

    def test_the_commit_equal_to_the_floor_is_accepted_so_the_second_pass_reports_unchanged(
        self,
    ) -> None:
        host = self.make_host(changed=0)
        host.seed(self.commit("c0"))
        first = self.push(host, self.commit("c1"), bundle=self.bundle("c1"))
        second = self.push(host, self.commit("c1"), bundle=self.bundle("c1"))
        for result in (first, second):
            self.assertEqual(0, result.code, result.summary + result.errors)
            self.assert_line_matches(result)
            self.assertTrue(result.has("verdict=unchanged"), result.summary)
        self.assertTrue(second.has("changed=0"), second.summary)

    def test_a_check_changes_nothing_and_leaves_the_floor_alone(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        with self.untouched(host):
            result = self.push(host, self.commit("c1"), mode="check", bundle=self.bundle("c1"))
        self.assertEqual(11, result.code, result.summary + result.errors)
        self.assert_line_matches(result)
        self.assertTrue(result.has("verdict=would-change"), result.summary)
        self.assertTrue(result.has("mode=check"), result.summary)
        self.assertIn("--check", host.applied()[0])

    def test_a_later_commit_after_an_applied_one_is_accepted_and_the_floor_moves_up(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        self.assertEqual(10, self.push(host, self.commit("c1"), bundle=self.bundle("c1")).code)
        self.assertEqual(10, self.push(host, self.commit("c2"), bundle=self.bundle("c2")).code)
        self.assertEqual(f"{self.commit('c2')}\n", host.floor.read_text(encoding="utf-8"))

    def test_a_failing_playbook_prints_a_digit_for_changed(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        ansible = Path(json.loads(host.config_path.read_text(encoding="utf-8"))["ansible_playbook"])
        fake_ansible(ansible.parent, code=2)
        result = self.push(host, self.commit("c1"), bundle=self.bundle("c1"))
        self.assertEqual(30, result.code, result.summary + result.errors)
        self.assert_line_matches(result)
        self.assertTrue(result.has("changed=0"), result.summary)

    # -------------------------------------------------------------- the floor

    def test_a_host_with_no_floor_applies_nothing_and_checks_out_nothing(self) -> None:
        host = self.make_host()
        for mode in ("apply", "check"):
            with self.subTest(mode):
                result = self.push(host, self.commit("c1"), mode=mode, bundle=self.bundle("c1"))
                self.assert_refused(result, "no-floor")
        self.assertEqual([], host.applied())
        self.assertFalse(host.floor.exists())
        self.assertFalse((host.state / "current").exists())
        self.assertEqual([], list((host.state / "work").iterdir()))
        self.assert_nothing_left(host)

    def test_a_commit_older_than_the_floor_is_refused_as_a_rollback(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c2"))
        with self.untouched(host):
            result = self.push(host, self.commit("c1"), bundle=self.bundle("c1"))
        self.assert_refused(result, "rollback")
        self.assertEqual([], host.applied())

    def test_a_commit_on_another_branch_of_the_history_is_refused_as_a_rollback(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c1"))
        with self.untouched(host):
            result = self.push(host, self.commit("side"), bundle=self.bundle("side"))
        self.assert_refused(result, "rollback")

    def test_a_bundle_of_an_unrelated_history_is_refused_as_a_rollback(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c1"))
        with self.untouched(host):
            result = self.push(host, self.commit("orphan"), bundle=self.bundle("orphan"))
        self.assert_refused(result, "rollback")

    def test_a_damaged_floor_is_a_state_error_and_not_a_pass(self) -> None:
        host = self.make_host()
        host.state.mkdir(mode=0o700)
        host.floor.write_text("not a commit\n", encoding="utf-8")
        result = self.push(host, self.commit("c1"), bundle=self.bundle("c1"))
        self.assertEqual(40, result.code)
        self.assert_line_matches(result)
        self.assertEqual([], host.applied())

    # --------------------------------------------------------------- the signature

    def test_an_unsigned_commit_is_refused(self) -> None:
        self.refuse_signature("unsigned", "unsigned")

    def test_a_commit_signed_by_an_ssh_key_that_is_not_listed_is_refused(self) -> None:
        self.refuse_signature("by_ssh", "signer-not-allowed")

    def test_a_commit_signed_by_an_openpgp_key_that_is_not_listed_is_refused(self) -> None:
        self.refuse_signature("by_other_pgp", "signer-not-allowed")

    def test_a_commit_changed_after_it_was_signed_is_refused(self) -> None:
        self.refuse_signature("tampered", "bad-signature")

    def refuse_signature(self, name: str, reason: str) -> None:
        """Assert that the named commit is refused for the reason and nothing changes."""
        host = self.make_host()
        host.seed(self.commit("c0"))
        for mode in ("apply", "check"):
            with self.subTest(mode), self.untouched(host):
                result = self.push(host, self.commit(name), mode=mode, bundle=self.bundle(name))
                self.assert_refused(result, reason)
        self.assertEqual([], host.applied())

    def test_the_signature_is_checked_before_the_floor(self) -> None:
        host = self.make_host()
        result = self.push(host, self.commit("unsigned"), bundle=self.bundle("unsigned"))
        self.assert_refused(result, "unsigned")

    # ----------------------------------------------------------------- the playbook

    def test_a_commit_with_no_playbook_is_refused(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        with self.untouched(host):
            result = self.push(host, self.commit("no_playbook"), bundle=self.bundle("no_playbook"))
        self.assert_refused(result, "playbook-not-allowed")

    def test_a_commit_whose_playbook_is_a_link_is_refused(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        with self.untouched(host):
            result = self.push(host, self.commit("symlink"), bundle=self.bundle("symlink"))
        self.assert_refused(result, "playbook-not-allowed")

    # ---------------------------------------------------------------- the bundle

    def refuse_bundle(self, bundle: Path | bytes | None, sentence: trigger.Why) -> Run:
        """Assert a bad-bundle refusal with its own sentence, nothing run and nothing left."""
        host = self.make_host()
        host.seed(self.commit("c0"))
        with self.untouched(host):
            result = self.push(host, self.commit("c1"), bundle=bundle)
        self.assert_refused(result, "bad-bundle")
        self.assertIn(sentence.value, result.errors)
        self.assertEqual([], host.applied())
        self.assert_nothing_left(host)
        return result

    def test_standard_input_that_is_not_a_bundle_is_refused(self) -> None:
        self.refuse_bundle(b"hello, this is not a bundle\n" * 100, trigger.Why.BUNDLE_NOT_A_BUNDLE)

    def test_an_empty_standard_input_is_refused(self) -> None:
        self.refuse_bundle(None, trigger.Why.BUNDLE_NOT_A_BUNDLE)

    def test_a_truncated_bundle_is_refused(self) -> None:
        whole = self.bundle("c1").read_bytes()
        self.refuse_bundle(whole[: len(whole) * 2 // 3], trigger.Why.BUNDLE_UNPACK)

    def test_a_bundle_whose_head_is_not_the_requested_commit_is_refused(self) -> None:
        self.refuse_bundle(self.bundle("c2"), trigger.Why.BUNDLE_HEAD)

    def test_a_bundle_that_does_not_stand_alone_is_refused(self) -> None:
        work = self.history.remote.work
        run(
            [*git_command(), "update-ref", "--no-deref", "HEAD", self.commit("c2")],
            cwd=work,
        )
        partial = self.bundles / "partial.bundle"
        run(
            [*git_command(), "bundle", "create", partial, "HEAD", f"^{self.commit('c1')}"], cwd=work
        )
        self.refuse_bundle(partial, trigger.Why.BUNDLE_UNVERIFIABLE)

    def test_a_bundle_over_the_byte_limit_is_refused(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        limits = trigger.Receiving(max_bytes=512)
        self.assertGreater(self.bundle("c1").stat().st_size, 512)
        with self.untouched(host):
            result = self.push(host, self.commit("c1"), bundle=self.bundle("c1"), receiving=limits)
        self.assert_refused(result, "bad-bundle")
        self.assertIn(trigger.Why.BUNDLE_OVERSIZE.value, result.errors)
        self.assert_nothing_left(host)

    def test_an_object_that_fails_git_s_object_check_is_refused_even_though_the_bundle_verifies(
        self,
    ) -> None:
        verify = subprocess.run(  # noqa: S603 - a fixture check, argument list, no shell
            [str(GIT), "bundle", "verify", str(self.bundle("malformed"))],
            cwd=self.history.remote.work,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, verify.returncode, verify.stderr)
        host = self.make_host()
        host.seed(self.commit("c0"))
        with self.untouched(host):
            result = self.push(host, self.commit("malformed"), bundle=self.bundle("malformed"))
        self.assert_refused(result, "bad-bundle")
        self.assertEqual([], host.applied())

    def test_the_quarantine_and_the_spool_are_removed_whatever_the_outcome(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        for name in ("c1", "unsigned", "side", "tampered"):
            self.push(host, self.commit(name), bundle=self.bundle(name))
            self.assert_nothing_left(host)

    # ------------------------------------------------- the stream deadline and the lock

    def test_a_stalled_stream_is_given_up_on_at_the_deadline_and_the_line_is_journalled(
        self,
    ) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        self.addCleanup(os.close, write_end)
        os.write(write_end, self.bundle("c1").read_bytes()[:100])
        outcome: dict[str, Run] = {}

        def call() -> None:
            outcome["run"] = self.push_from(host, read_end, trigger.Receiving(deadline_seconds=0.5))

        worker = threading.Thread(target=call, daemon=True)
        worker.start()
        worker.join(WATCHDOG_SECONDS)
        self.assertFalse(worker.is_alive(), "the read did not stop at its deadline")
        result = outcome["run"]
        self.assert_refused(result, "bad-bundle")
        self.assertIn(trigger.Why.BUNDLE_STALLED.value, result.errors)
        journal = (host.logs / "pull-trigger.log").read_text(encoding="utf-8")
        self.assertIn("reason=bad-bundle", journal)
        self.assert_nothing_left(host)

    def push_from(self, host: Host, descriptor: int, limits: trigger.Receiving) -> Run:
        """Call the program with a stream that is already open, as a connection is."""
        out, errors = io.StringIO(), io.StringIO()
        tools = trigger.Tools(
            git=GIT,
            gpg=Path(GPG or "/usr/bin/gpg"),
            gpgconf=Path(GPGCONF or "/usr/bin/gpgconf"),
            ssh_keygen=SSH_KEYGEN,
        )
        with contextlib.redirect_stderr(errors):
            code = trigger.main(
                ["--mode", "apply", "--config", str(host.config_path)],
                {"SSH_ORIGINAL_COMMAND": f"apply {self.commit('c1')} {PLAY}"},
                threading.Event(),
                tools,
                out,
                io.BytesIO(),
                dataclasses.replace(limits, descriptor=descriptor),
            )
        return Run(code, out.getvalue().strip(), errors.getvalue(), "")

    def test_a_request_during_a_stalled_upload_is_not_refused_busy(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        outcome: dict[str, Run] = {}

        def stalled() -> None:
            outcome["run"] = self.push_from(host, read_end, trigger.Receiving(deadline_seconds=30))

        worker = threading.Thread(target=stalled, daemon=True)
        worker.start()
        # The upload is under way once its spool file exists: from then on the first request has
        # finished making the state directories, which two requests starting together would race
        # to write (a fault of the shared start-up, not of the receiver).
        spool = host.state / "spool"
        started = time.monotonic()
        while not (spool.is_dir() and any(spool.iterdir())):
            self.assertLess(time.monotonic() - started, WATCHDOG_SECONDS, "the upload never began")
            time.sleep(0.01)
        result = self.push(host, self.commit("c1"), bundle=self.bundle("c1"))
        self.assertEqual(10, result.code, result.summary + result.errors)
        # The upload that was waiting ends with the stream, and is refused for what it sent.
        os.close(write_end)
        worker.join(WATCHDOG_SECONDS)
        self.assertFalse(worker.is_alive())
        self.assertTrue(outcome["run"].has("reason=bad-bundle"), outcome["run"].summary)

    def test_a_second_request_while_a_run_holds_the_lock_is_refused_busy_with_a_digit(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        with trigger.single_flight(host.state / "lock"):
            result = self.push(host, self.commit("c1"), bundle=self.bundle("c1"))
        self.assert_refused(result, "busy", code=21)
        self.assertEqual([], host.applied())

    def test_the_sweep_removes_old_uploads_and_leaves_a_young_one_for_a_concurrent_request(
        self,
    ) -> None:
        workspace = trigger.Workspace(Path(tempfile.mkdtemp(prefix="pt-sweep-")))
        self.addCleanup(shutil.rmtree, workspace.root, ignore_errors=True)
        workspace.root.chmod(0o700)
        workspace.prepare()
        workspace.prepare_bundle()
        old, young = workspace.spool / "old.bundle", workspace.spool / "young.bundle"
        old.write_bytes(b"x")
        young.write_bytes(b"x")
        os.utime(old, (1, 1))
        (workspace.quarantine / "q-left").mkdir()
        (workspace.scratch / "scratch-left").mkdir()
        workspace.sweep()
        workspace.sweep_bundle(360)
        self.assertFalse(old.exists())
        self.assertTrue(young.exists())
        self.assertFalse((workspace.quarantine / "q-left").exists())
        self.assertFalse((workspace.scratch / "scratch-left").exists())

    # ---------------------------------------------------- what the bundle path may run

    def test_the_bundle_path_runs_only_local_git_gpg_ssh_keygen_and_ansible_playbook(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        argvs: list[list[str]] = []
        real_run, real_popen = trigger.run_command, subprocess.Popen

        def spy_run(
            argv: Sequence[str], environment: Mapping[str, str], timeout: float = 600
        ) -> "subprocess.CompletedProcess[str]":
            argvs.append([str(item) for item in argv])
            return real_run(argv, environment, timeout)

        def spy_popen(
            argv: Sequence[str], *args: object, **kwargs: object
        ) -> "subprocess.Popen[bytes]":
            argvs.append([str(item) for item in argv])
            return real_popen(argv, *args, **kwargs)  # type: ignore[call-overload,no-any-return]

        with (
            mock.patch.object(trigger, "run_command", spy_run),
            mock.patch.object(subprocess, "Popen", spy_popen),
            mock.patch.object(trigger, "Cache", side_effect=AssertionError("a cache was built")),
        ):
            result = self.push(host, self.commit("c1"), bundle=self.bundle("c1"))
        self.assertEqual(10, result.code, result.summary + result.errors)
        programs = {Path(argv[0]).name for argv in argvs}
        self.assertTrue(
            programs <= {"git", "gpg", "gpgconf", "ssh-keygen", "ansible-playbook"}, programs
        )
        self.assertIn("ansible-playbook", programs)
        for argv in argvs:
            for word in argv:
                self.assertNotIn("://", word, argv)

    def test_the_quarantine_may_use_the_file_transport_and_no_network_one(self) -> None:
        git = trigger.Git(trigger.Tools(), Path("/nonexistent"), Path("/nonexistent"), "file")
        self.assertEqual("file", git.environment["GIT_ALLOW_PROTOCOL"])
        pull = trigger.Git(trigger.Tools(), Path("/nonexistent"), Path("/nonexistent"))
        self.assertEqual("https:file", pull.environment["GIT_ALLOW_PROTOCOL"])

    # ---------------------------------------------------------- the caller going away

    def test_a_closed_standard_output_and_error_still_give_a_journalled_line_and_the_status(
        self,
    ) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        source = host.root / "stdin"
        shutil.copyfile(self.bundle("c1"), source)
        descriptor = os.open(source, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        tools = trigger.Tools(
            git=GIT,
            gpg=Path(GPG or "/usr/bin/gpg"),
            gpgconf=Path(GPGCONF or "/usr/bin/gpgconf"),
            ssh_keygen=SSH_KEYGEN,
        )
        with contextlib.redirect_stderr(Broken()):
            code = trigger.main(
                ["--mode", "apply", "--config", str(host.config_path)],
                {"SSH_ORIGINAL_COMMAND": f"apply {self.commit('c1')} {PLAY}"},
                threading.Event(),
                tools,
                Broken(),
                BrokenBytes(),
                trigger.Receiving(descriptor=descriptor),
            )
        self.assertEqual(10, code)
        journal = (host.logs / "pull-trigger.log").read_text(encoding="utf-8")
        self.assertIn(
            f"verdict=applied exit=10 reason=ok mode=apply commit={self.commit('c1')}", journal
        )
        self.assertEqual(f"{self.commit('c1')}\n", host.floor.read_text(encoding="utf-8"))

    def test_a_refusal_with_a_closed_standard_output_still_returns_its_status(self) -> None:
        host = self.make_host()
        host.seed(self.commit("c0"))
        with contextlib.redirect_stderr(Broken()):
            code = trigger.main(
                ["--mode", "apply", "--config", str(host.config_path)],
                {"SSH_ORIGINAL_COMMAND": "garbage"},
                threading.Event(),
                trigger.Tools(),
                Broken(),
                BrokenBytes(),
            )
        self.assertEqual(20, code)
        self.assertIn("reason=bad-request", (host.logs / "pull-trigger.log").read_text("utf-8"))

    # ----------------------------------------- the named limit, shown by running it

    def test_a_merge_signed_commit_that_is_not_on_main_is_accepted_and_main_is_then_refused(
        self,
    ) -> None:
        host = self.make_host()
        host.seed(self.commit("c2"))
        # "fork" stands for a web-editor commit on a fork: validly signed, newer than the floor,
        # and on no branch of main. The receiver cannot tell, and applies it.
        first = self.push(host, self.commit("fork"), bundle=self.bundle("fork"))
        self.assertEqual(10, first.code, first.summary + first.errors)
        # The floor now sits off main, so the real next commit of main is refused, never applied.
        second = self.push(host, self.commit("main_next"), bundle=self.bundle("main_next"))
        self.assert_refused(second, "rollback")
        self.assertEqual(1, len(host.applied()))

    # ------------------------------------------------------ the line, for every verdict

    def test_every_line_with_a_commit_matches_the_workflow_s_judge(self) -> None:
        cases: list[tuple[str, str, Path | bytes | None, str, str]] = [
            ("c1", "apply", self.bundle("c1"), "apply", "c1"),
            ("c1", "check", self.bundle("c1"), "check", "c1"),
            ("c1", "apply", self.bundle("c1"), "check", "c1"),
            ("unsigned", "apply", self.bundle("unsigned"), "apply", "unsigned"),
            ("by_ssh", "apply", self.bundle("by_ssh"), "apply", "by_ssh"),
            ("tampered", "apply", self.bundle("tampered"), "apply", "tampered"),
            ("side", "apply", self.bundle("side"), "apply", "side"),
            ("c1", "apply", b"junk", "apply", "c1"),
            ("c1", "apply", self.bundle("c2"), "apply", "c1"),
            ("no_playbook", "apply", self.bundle("no_playbook"), "apply", "no_playbook"),
        ]
        for name, word, bundle, mode, _ in cases:
            with self.subTest(name=name, word=word, mode=mode):
                host = self.make_host()
                host.seed(self.commit("c0"))
                result = self.push(host, self.commit(name), mode=mode, word=word, bundle=bundle)
                self.assert_line_matches(result)
        absent = self.make_host()
        self.assert_line_matches(self.push(absent, self.commit("c1"), bundle=self.bundle("c1")))


class ConfigSourceTests(unittest.TestCase):
    """The ``source`` key, and a remote host's configuration, which it must leave as it was."""

    def test_an_absent_source_is_the_remote_source(self) -> None:
        text = json.dumps(valid_config_data())
        self.assertEqual("remote", trigger.parse_config(text).source)

    def test_the_two_sources_are_accepted_and_nothing_else(self) -> None:
        for source, ok in (("remote", True), ("bundle", True), ("push", False), ("", False)):
            with self.subTest(source):
                text = json.dumps(valid_config_data(source=source))
                if ok:
                    self.assertEqual(source, trigger.parse_config(text).source)
                else:
                    with self.assertRaises(trigger.ConfigError):
                        trigger.parse_config(text)

    def test_a_source_that_is_not_text_is_refused(self) -> None:
        for source in (None, 1, [], ["bundle"], {"bundle": True}):
            with self.subTest(source=source), self.assertRaises(trigger.ConfigError):
                trigger.parse_config(json.dumps(valid_config_data(source=source)))

    def test_a_remote_configuration_has_no_source_key_and_parses_under_the_old_and_new_key_sets(
        self,
    ) -> None:
        """A program rolled back to before this key must still read a remote host's file."""
        old_keys = trigger.CONFIG_KEYS | {"steps"}
        data = valid_config_data(steps=[])
        self.assertLessEqual(set(data), old_keys)
        self.assertNotIn("source", data)
        text = json.dumps(data)
        self.assertEqual("remote", trigger.parse_config(text).source)
        # The check the earlier program made, written out: no key outside its sets.
        self.assertTrue(trigger.CONFIG_KEYS <= set(data) <= old_keys)

    def test_the_new_key_is_the_only_one_added_to_the_optional_set(self) -> None:
        self.assertEqual({"steps", "source"}, set(trigger.OPTIONAL_CONFIG_KEYS))


class PullRouteUnchangedTests(unittest.TestCase):
    """The pull route's line is frozen: same prefix, same fields, a dash for changed."""

    commit = "0123456789abcdef" * 2 + "01234567"

    def test_the_pull_routes_lines_are_exactly_what_they_were(self) -> None:
        expected = {
            (trigger.Exit.APPLIED, "ok", 3, "apply"): "pull-trigger verdict=applied exit=10 "
            f"reason=ok mode=apply commit={self.commit} playbook={PLAY} changed=3",
            (trigger.Exit.WOULD_CHANGE, "ok", 2, "check"): "pull-trigger verdict=would-change "
            f"exit=11 reason=ok mode=check commit={self.commit} playbook={PLAY} changed=2",
            (trigger.Exit.UNCHANGED, "ok", 0, "apply"): "pull-trigger verdict=unchanged exit=0 "
            f"reason=ok mode=apply commit={self.commit} playbook={PLAY} changed=0",
            (trigger.Exit.REFUSED, "rollback", None, "apply"): "pull-trigger verdict=refused "
            f"exit=20 reason=rollback mode=apply commit={self.commit} playbook={PLAY} changed=-",
            (trigger.Exit.BUSY, "busy", None, "check"): "pull-trigger verdict=busy exit=21 "
            f"reason=busy mode=check commit={self.commit} playbook={PLAY} changed=-",
        }
        for (code, reason, changed, mode), line in expected.items():
            with self.subTest(reason=reason, mode=mode):
                verdict = trigger.Verdict(code, reason, changed)
                self.assertEqual(line, trigger.summary(verdict, mode, self.commit, PLAY))

    def test_a_remote_host_prints_the_pull_prefix_and_a_dash_for_changed_on_a_refusal(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pr", dir="/tmp")).resolve()  # noqa: S108
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        root.chmod(0o700)
        etc = root / "etc"
        etc.mkdir(mode=0o755)
        data = valid_config_data(state_dir=str(root / "state"), log_dir=str(root / "logs"))
        config = etc / "config.json"
        config.write_text(json.dumps(data), encoding="utf-8")
        config.chmod(0o644)
        out, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = trigger.main(
                ["--mode", "apply", "--config", str(config)],
                {"SSH_ORIGINAL_COMMAND": "main"},
                threading.Event(),
                trigger.Tools(),
                out,
                io.BytesIO(),
            )
        self.assertEqual(20, code)
        self.assertEqual(
            f"pull-trigger verdict=refused exit=20 reason=bad-request mode=apply commit=- "
            f"playbook={PLAY} changed=-",
            out.getvalue().strip(),
        )

    def test_the_pull_route_does_not_make_the_bundle_directories(self) -> None:
        workspace = trigger.Workspace(Path(tempfile.mkdtemp(prefix="pt-ws-")))
        self.addCleanup(shutil.rmtree, workspace.root, ignore_errors=True)
        workspace.root.chmod(0o700)
        workspace.prepare()
        self.assertFalse(workspace.spool.exists())
        self.assertFalse(workspace.quarantine.exists())


class StreamTests(unittest.TestCase):
    """The bounded read of standard input, without the rest of the program."""

    def setUp(self) -> None:
        """Make a spool directory."""
        self.root = Path(tempfile.mkdtemp(prefix="pt-spool-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_a_stream_within_the_limits_is_copied_whole(self) -> None:
        read_end, write_end = os.pipe()
        os.write(write_end, b"abc" * 1000)
        os.close(write_end)
        self.addCleanup(os.close, read_end)
        path = trigger.spool_stream(self.root, trigger.Receiving(read_end, 100_000, 5))
        self.assertEqual(b"abc" * 1000, path.read_bytes())
        self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_a_stalled_stream_ends_at_the_deadline_not_never(self) -> None:
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        self.addCleanup(os.close, write_end)
        os.write(write_end, b"some")
        caught: list[BaseException] = []

        def read() -> None:
            try:
                trigger.spool_stream(self.root, trigger.Receiving(read_end, 100_000, 0.3))
            except trigger.BadBundleError as error:
                caught.append(error)

        worker = threading.Thread(target=read, daemon=True)
        worker.start()
        worker.join(WATCHDOG_SECONDS)
        self.assertFalse(worker.is_alive(), "a stalled stream held the read past its deadline")
        self.assertEqual(1, len(caught))
        self.assertIn(trigger.Why.BUNDLE_STALLED.value, str(caught[0]))
        self.assertEqual([], list(self.root.iterdir()))

    def test_a_trickle_that_never_ends_is_cut_at_the_deadline_too(self) -> None:
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        stop = threading.Event()

        def trickle() -> None:
            while not stop.is_set():
                try:
                    os.write(write_end, b"x")
                except OSError:
                    return
                stop.wait(0.05)

        feeder = threading.Thread(target=trickle, daemon=True)
        feeder.start()
        self.addCleanup(os.close, write_end)
        self.addCleanup(stop.set)
        with self.assertRaises(trigger.BadBundleError) as caught:
            trigger.spool_stream(self.root, trigger.Receiving(read_end, 10_000_000, 0.5))
        self.assertIn(trigger.Why.BUNDLE_STALLED.value, str(caught.exception))

    def test_a_stream_over_the_byte_limit_is_refused_and_the_file_removed(self) -> None:
        read_end, write_end = os.pipe()
        os.write(write_end, b"x" * 5000)
        os.close(write_end)
        self.addCleanup(os.close, read_end)
        with self.assertRaises(trigger.BadBundleError) as caught:
            trigger.spool_stream(self.root, trigger.Receiving(read_end, 1000, 5))
        self.assertIn(trigger.Why.BUNDLE_OVERSIZE.value, str(caught.exception))
        self.assertEqual([], list(self.root.iterdir()))

    def test_a_descriptor_that_cannot_be_read_is_refused(self) -> None:
        with self.assertRaises(trigger.BadBundleError) as caught:
            trigger.spool_stream(self.root, trigger.Receiving(987654, 1000, 5))
        self.assertIn(trigger.Why.BUNDLE_UNREADABLE.value, str(caught.exception))

    def test_the_limits_are_the_documented_ones(self) -> None:
        self.assertEqual(200 * 1024 * 1024, trigger.MAX_BUNDLE_BYTES)
        self.assertEqual(300, trigger.BUNDLE_DEADLINE_SECONDS)


class BundleRequestParsingTests(unittest.TestCase):
    """The request grammar of a host that takes bundles, without the rest of the program."""

    commit = "0123456789abcdef" * 2 + "01234567"

    def resolve(self, text: str | None, mode: str = "apply") -> trigger.BundleRequest:
        """Resolve a request under a key-fixed mode."""
        arguments = trigger.parse_arguments(["--mode", mode])
        environ = {} if text is None else {"SSH_ORIGINAL_COMMAND": text}
        return trigger.resolve_bundle_request(arguments, environ)

    def test_three_words_are_accepted(self) -> None:
        request = self.resolve(f"check {self.commit} {PLAY}", "check")
        self.assertEqual(
            trigger.BundleRequest(trigger.Mode.CHECK, self.commit, PLAY),
            request,
        )

    def test_a_word_that_disagrees_with_the_key_is_parsed_and_left_to_the_mode_check(self) -> None:
        request = self.resolve(f"apply {self.commit} {PLAY}", "check")
        self.assertIs(trigger.Mode.APPLY, request.mode)

    def test_no_text_and_the_step_mode_are_refused(self) -> None:
        with self.assertRaises(trigger.BadRequestError):
            self.resolve(None)
        with self.assertRaises(trigger.BadRequestError):
            self.resolve(f"apply {self.commit} {PLAY}", "step")


if __name__ == "__main__":
    unittest.main()
