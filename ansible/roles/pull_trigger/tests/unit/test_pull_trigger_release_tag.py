"""Unit tests for the release-tag route of pull_trigger (docs/pull-signer-trust.md, T8).

A host told to require a release tag applies a commit only if an annotated tag of the fixed name
shape, whose own text names exactly that commit, is signed by a release key. Both sources and the
modes call one admission method. The cases use real git, real tags and real signatures (SSH and
OpenPGP) on throwaway repositories, and call the program through ``main`` as the forced command
does. A host not told to require a tag is unchanged: ``test_pull_trigger`` and
``test_pull_trigger_bundle`` are its tests.
"""

import contextlib
import dataclasses
import io
import json
import os
import shutil
import tempfile
import threading
import unittest
from collections.abc import Sequence
from pathlib import Path

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
RELEASE = "release/20261114.1"
Signer = SshKey | GpgKey


@dataclasses.dataclass
class Host:
    """One test's host directories, configuration and stand-in ansible-playbook."""

    root: Path
    config_path: Path
    state: Path
    calls: Path
    bare: Path

    def applied(self) -> list[str]:
        """Return the calls the stand-in ansible-playbook recorded."""
        text = self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""
        return [line for line in text.splitlines() if line.startswith("-i")]


class ReleaseTagFixture:
    """The keys, the history and the means to make tags, bundles and remotes from them."""

    def __init__(self, root: Path) -> None:
        """Make the keys and a linear signed history under ``root``."""
        self.root = root
        keys = root / "keys"
        keys.mkdir()
        self.release_ssh = make_ssh_key(keys, "release-ssh")
        self.release_ssh_two = make_ssh_key(keys, "release-ssh-two")
        self.release_pgp = make_gpg_key(root, "release-pgp")
        self.commit_signer = make_gpg_key(root, "web-flow-stand-in")
        self.other_ssh = make_ssh_key(keys, "other-ssh")
        self.remote = Remote.create(root)
        c = self.commit_signer
        commits: dict[str, str] = {}
        commits["c0"] = self.remote.commit({PLAY: playbook_text("c0")}, "c0", None, c)
        commits["c1"] = self.remote.commit({PLAY: playbook_text("c1")}, "c1", commits["c0"], c)
        commits["unsigned"] = self.remote.commit(
            {PLAY: playbook_text("u")}, "unsigned", commits["c1"], None
        )
        commits["by_release_key"] = self.remote.commit(
            {PLAY: playbook_text("r")},
            "signed by a release key",
            commits["unsigned"],
            self.release_ssh,
        )
        commits["tip"] = self.remote.commit(
            {PLAY: playbook_text("tip")}, "tip", commits["by_release_key"], c
        )
        self.commits = commits
        self.counter = 0
        self.junk_cache: list[tuple[str, str]] = []

    def forget(self) -> None:
        """Stop the agents the keys started."""
        for key in (self.release_pgp, self.commit_signer):
            forget_gpg(key)

    # ------------------------------------------------------------------------- tags

    def tag(
        self,
        target: str,
        signer: Signer | None,
        name: str = RELEASE,
        *,
        message: str | None = None,
        annotated: bool = True,
    ) -> str:
        """Make a tag object in the work repository and return its id; its ref is removed again.

        ``name`` is the name in the tag's own text. ``message`` is varied so that two tags of one
        name and target are two objects.
        """
        self.counter += 1
        text = message if message is not None else f"release {self.counter}"
        argv = git_command(signer if annotated else None)
        if signer is None:
            argv += ["-c", "tag.gpgsign=false", "-c", "tag.forceSignAnnotated=false"]
        extra = {"GNUPGHOME": str(signer.home)} if isinstance(signer, GpgKey) else {}
        if not annotated:
            run([*argv, "tag", "-f", name, target], cwd=self.remote.work)
        elif signer is None:
            run([*argv, "tag", "-f", "-a", "-m", text, name, target], cwd=self.remote.work)
        else:
            run(
                [*argv, "tag", "-f", "-s", "-m", text, name, target],
                cwd=self.remote.work,
                extra=extra,
            )
        tag_id = run([GIT, "rev-parse", f"refs/tags/{name}"], cwd=self.remote.work)
        run([GIT, "tag", "-d", name], cwd=self.remote.work)
        return tag_id

    def tamper(self, tag_id: str) -> str:
        """Return the tag with its message changed after it was signed."""
        text = run([GIT, "cat-file", "tag", tag_id], cwd=self.remote.work)
        return self.store(text.replace("\n\nrelease ", "\n\ntampered ", 1) + "\n")

    def store(self, text: str) -> str:
        """Write a tag object from its text and return its id."""
        return run(
            [GIT, "hash-object", "-t", "tag", "-w", "--stdin"], cwd=self.remote.work, stdin=text
        )

    def sign_as_ssh_namespace(self, target: str, key: SshKey, namespace: str) -> str:
        """Return a tag naming ``target``, signed by ``key`` under another SSH namespace.

        Its signature is a valid one by the listed key over the tag's exact bytes, bound to
        ``namespace`` and not to ``git``, as a signature made for another purpose would be.
        """
        body = (
            f"object {target}\ntype commit\ntag {RELEASE}\n"
            "tagger T <t@example.invalid> 0 +0000\n\nrelease\n"
        )
        payload = self.root / f"payload-{namespace}"
        payload.write_text(body, encoding="utf-8")
        run([SSH_KEYGEN, "-Y", "sign", "-n", namespace, "-f", key.private, payload])
        signature = Path(f"{payload}.sig").read_text(encoding="utf-8")
        return self.store(body + signature)

    def tag_of_tag(self, inner: str, signer: Signer) -> str:
        """Return a signed tag, of the release name, whose object is another tag."""
        return self.tag(inner, signer)

    # --------------------------------------------------------------- how a host gets them

    def export_bare(self, bare: Path, tip: str, tags: Sequence[tuple[str, str]]) -> None:
        """Put the history up to ``tip`` as ``main`` and the tags (ref suffix, id) in ``bare``."""
        refs = [f"{tip}:refs/heads/main"]
        refs += [f"{tag_id}:refs/tags/release/{suffix}" for suffix, tag_id in tags]
        run([GIT, "push", "-q", "--force", bare, *refs], cwd=self.remote.work)

    def bundle(self, directory: Path, commit: str, tags: Sequence[tuple[str, str]]) -> Path:
        """Make a bundle of HEAD ``commit``, its tip of main and the tags, as the sender would."""
        bare = directory / "sender.git"
        shutil.rmtree(bare, ignore_errors=True)
        run([GIT, "init", "-q", "--bare", "-b", "main", bare])
        self.export_bare(bare, commit, tags)
        run([GIT, f"--git-dir={bare}", "update-ref", trigger.BUNDLE_MAIN_REF, commit])
        path = directory / "sent.bundle"
        path.unlink(missing_ok=True)
        refs = [f"refs/tags/release/{suffix}" for suffix, _ in tags]
        names = ["HEAD", trigger.BUNDLE_MAIN_REF, *refs]
        run([GIT, f"--git-dir={bare}", "bundle", "create", path, *names])
        return path


def required_config(
    host_root: Path, fixture: ReleaseTagFixture, **changes: object
) -> dict[str, object]:
    """Return a configuration that requires a release tag, signed by either release key."""
    bare = host_root / "remote.git"
    helper = host_root / "bin"
    data = valid_config_data(
        remote_url=f"file://{bare}",
        signers=[{"format": "openpgp", "key": fixture.commit_signer.armoured}],
        ansible_playbook=str(helper / "ansible-playbook"),
        state_dir=str(host_root / "state"),
        log_dir=str(host_root / "logs"),
        timeout_seconds=60,
        release_signers=[
            {"format": "ssh", "key": fixture.release_ssh.public_line},
            {"format": "openpgp", "key": fixture.release_pgp.armoured},
        ],
        require_release_tag=True,
    )
    data.update(changes)
    return data


class ReleaseTagTests(unittest.TestCase):
    """The whole program with a release tag required, on both sources."""

    fixture: ReleaseTagFixture
    root: Path

    @classmethod
    def setUpClass(cls) -> None:
        """Make the keys and the history once."""
        cls.root = Path(tempfile.mkdtemp(prefix="pt-release-fixture-")).resolve()
        cls.fixture = ReleaseTagFixture(cls.root)

    @classmethod
    def tearDownClass(cls) -> None:
        """Remove the fixture and stop the agents."""
        cls.fixture.forget()
        shutil.rmtree(cls.root, ignore_errors=True)

    # ------------------------------------------------------------------------ plumbing

    def commit(self, name: str) -> str:
        """Return a named commit's id."""
        return self.fixture.commits[name]

    def junk(self, count: int) -> list[tuple[str, str]]:
        """Return ``count`` unsigned annotated release tags of c1, made once and shared."""
        cache = self.fixture.junk_cache
        while len(cache) < count:
            number = len(cache)
            tag = self.fixture.tag(self.commit("c1"), None, message=f"junk {number}")
            cache.append((f"j{number}", tag))
        return cache[:count]

    def make_host(self, *, source: str = "remote", **changes: object) -> Host:
        """Make a host that requires a release tag: a short path (gpg's socket lives beneath it)."""
        root = Path(tempfile.mkdtemp(prefix="pr", dir="/tmp")).resolve()  # noqa: S108
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        root.chmod(0o700)
        helper = root / "bin"
        helper.mkdir()
        fake_ansible(helper)
        run([GIT, "init", "-q", "--bare", "-b", "main", root / "remote.git"])
        etc = root / "etc"
        etc.mkdir(mode=0o755)
        data = required_config(root, self.fixture, **changes)
        if source == "bundle":
            data["source"] = "bundle"
        path = etc / "config.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        path.chmod(0o644)
        host = Host(root, path, root / "state", helper / "calls.txt", root / "remote.git")
        if source == "bundle":
            host.state.mkdir(mode=0o700)
            (host.state / "last-applied").write_text(f"{self.commit('c0')}\n", encoding="utf-8")
            (host.state / "last-applied").chmod(0o600)
        return host

    def tools(self) -> trigger.Tools:
        """Return the programs the run may start, as this machine has them."""
        return trigger.Tools(
            git=GIT,
            gpg=Path(GPG or "/usr/bin/gpg"),
            gpgconf=Path(GPGCONF or "/usr/bin/gpgconf"),
            ssh_keygen=SSH_KEYGEN,
        )

    def pull(
        self,
        host: Host,
        commit: str,
        tags: Sequence[tuple[str, str]],
        mode: str = "apply",
        *,
        tip: str | None = None,
    ) -> Run:
        """Put main and the tags on the host's remote, then request the commit as a pull would."""
        self.fixture.export_bare(host.bare, tip or self.commit("tip"), tags)
        out, relayed, errors = io.StringIO(), io.BytesIO(), io.StringIO()
        argv = ["--mode", mode, "--config", str(host.config_path)]
        with contextlib.redirect_stderr(errors):
            code = trigger.main(
                argv,
                {"SSH_ORIGINAL_COMMAND": commit},
                threading.Event(),
                self.tools(),
                out,
                relayed,
            )
        return Run(code, out.getvalue().strip(), errors.getvalue(), relayed.getvalue().decode())

    def push(
        self,
        host: Host,
        commit: str,
        tags: Sequence[tuple[str, str]],
        mode: str = "apply",
    ) -> Run:
        """Send a bundle that carries the tags, as the pushing workflow would."""
        bundle = self.fixture.bundle(host.root, commit, tags)
        out, relayed, errors = io.StringIO(), io.BytesIO(), io.StringIO()
        argv = ["--mode", mode, "--config", str(host.config_path)]
        descriptor = os.open(bundle, os.O_RDONLY)
        try:
            limits = trigger.Receiving(descriptor=descriptor)
            with contextlib.redirect_stderr(errors):
                code = trigger.main(
                    argv,
                    {"SSH_ORIGINAL_COMMAND": f"{mode} {commit} {PLAY}"},
                    threading.Event(),
                    self.tools(),
                    out,
                    relayed,
                    limits,
                )
        finally:
            os.close(descriptor)
        return Run(code, out.getvalue().strip(), errors.getvalue(), relayed.getvalue().decode())

    def routes(self) -> list[str]:
        """The two sources every case is run on."""
        return ["remote", "bundle"]

    def send(
        self,
        source: str,
        commit: str,
        tags: Sequence[tuple[str, str]],
        mode: str = "apply",
    ) -> tuple[Host, Run]:
        """Make a host on the source, send the commit with the tags and return both."""
        host = self.make_host(source=source)
        if source == "bundle":
            return host, self.push(host, commit, tags, mode)
        return host, self.pull(host, commit, tags, mode)

    def assert_refused(self, host: Host, result: Run, reason: str) -> None:
        """Assert a refusal for this reason that ran no playbook."""
        self.assertEqual(20, result.code, result.summary + result.errors)
        self.assertTrue(result.has(f"reason={reason}"), result.summary)
        self.assertEqual([], host.applied())

    def assert_applied(self, host: Host, result: Run) -> None:
        """Assert that the playbook ran and the run applied."""
        self.assertEqual(10, result.code, result.summary + result.errors)
        self.assertEqual(1, len(host.applied()))

    # ------------------------------------------------------------------ the good cases

    def test_a_commit_with_a_tag_signed_by_an_ssh_release_key_is_applied(self) -> None:
        tag = self.fixture.tag(self.commit("c1"), self.fixture.release_ssh)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [("a", tag)])
                self.assert_applied(host, result)

    def test_a_commit_with_a_tag_signed_by_an_openpgp_release_key_is_applied(self) -> None:
        tag = self.fixture.tag(self.commit("c1"), self.fixture.release_pgp)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [("a", tag)])
                self.assert_applied(host, result)

    def test_a_check_is_refused_without_a_tag_and_runs_with_one(self) -> None:
        tag = self.fixture.tag(self.commit("c1"), self.fixture.release_ssh)
        for source in self.routes():
            with self.subTest(source=source, tagged=False):
                host, result = self.send(source, self.commit("c1"), [], "check")
                self.assert_refused(host, result, "release-tag-missing")
            with self.subTest(source=source, tagged=True):
                host, result = self.send(source, self.commit("c1"), [("a", tag)], "check")
                self.assertEqual(11, result.code, result.summary + result.errors)

    def test_the_commits_own_signature_is_not_read_when_a_tag_is_required(self) -> None:
        tag = self.fixture.tag(self.commit("unsigned"), self.fixture.release_ssh)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("unsigned"), [("a", tag)])
                self.assert_applied(host, result)

    def test_the_tags_ref_name_does_not_matter_only_the_signed_name(self) -> None:
        tag = self.fixture.tag(self.commit("c1"), self.fixture.release_ssh)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [("anything-at-all", tag)])
                self.assert_applied(host, result)

    def test_a_real_tag_among_unsigned_tags_is_found(self) -> None:
        junk = self.junk(10)
        real = self.fixture.tag(self.commit("c1"), self.fixture.release_ssh)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [*junk, ("real", real)])
                self.assert_applied(host, result)

    # --------------------------------------------------------------- the refusals (C6)

    def test_a_commit_with_no_tag_is_refused_even_when_a_commit_signer_signed_it(self) -> None:
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [])
                self.assert_refused(host, result, "release-tag-missing")

    def test_a_lightweight_tag_is_refused(self) -> None:
        tag = self.fixture.tag(self.commit("c1"), None, annotated=False)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [("a", tag)])
                self.assert_refused(host, result, "release-tag-missing")

    def test_an_annotated_tag_with_no_signature_is_refused(self) -> None:
        tag = self.fixture.tag(self.commit("c1"), None)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [("a", tag)])
                self.assert_refused(host, result, "release-tag-missing")

    def test_a_tag_signed_by_a_key_that_is_not_a_release_key_is_refused(self) -> None:
        for name, signer in (
            ("ssh", self.fixture.other_ssh),
            ("openpgp", self.fixture.commit_signer),
        ):
            tag = self.fixture.tag(self.commit("c1"), signer)
            for source in self.routes():
                with self.subTest(name=name, source=source):
                    host, result = self.send(source, self.commit("c1"), [("a", tag)])
                    self.assert_refused(host, result, "release-tag-missing")

    def test_a_commit_signer_key_cannot_sign_a_release_even_if_it_is_also_a_release_key_elsewhere(
        self,
    ) -> None:
        # The keyring for a tag is built from the release keys alone: the commit signer's key is
        # on this host's ``signers`` list and is refused for a tag.
        tag = self.fixture.tag(self.commit("c1"), self.fixture.commit_signer)
        host = self.make_host(
            release_signers=[{"format": "ssh", "key": self.fixture.release_ssh.public_line}]
        )
        result = self.pull(host, self.commit("c1"), [("a", tag)])
        self.assert_refused(host, result, "release-tag-missing")

    def test_a_commit_signed_by_a_release_key_with_no_tag_is_refused(self) -> None:
        # The signature must be read from the tag, not from the commit it names.
        unsigned_tag = self.fixture.tag(self.commit("by_release_key"), None)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(
                    source, self.commit("by_release_key"), [("a", unsigned_tag)]
                )
                self.assert_refused(host, result, "release-tag-missing")

    def test_a_tag_that_names_another_commit_is_refused(self) -> None:
        tag = self.fixture.tag(self.commit("c0"), self.fixture.release_ssh)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [("a", tag)])
                self.assert_refused(host, result, "release-tag-missing")

    def test_a_signed_tag_of_a_tag_is_refused(self) -> None:
        inner = self.fixture.tag(self.commit("c1"), self.fixture.release_ssh)
        outer = self.fixture.tag_of_tag(inner, self.fixture.release_ssh)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [("a", outer)])
                self.assert_refused(host, result, "release-tag-missing")

    def test_a_tag_names_a_commit_directly_only_if_its_own_lines_say_so(self) -> None:
        # Newer gits peel a tag of a tag through to its commit in ``for-each-ref``, so the
        # listing alone would pass it; the tag's own ``object`` line is what is read.
        inner = self.fixture.tag(self.commit("c1"), self.fixture.release_ssh)
        outer = self.fixture.tag_of_tag(inner, self.fixture.release_ssh)
        home = Path(tempfile.mkdtemp(prefix="ph", dir="/tmp"))  # noqa: S108
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        git = trigger.Git(self.tools(), self.fixture.remote.work / ".git", home)
        repository = trigger.Repository(git)
        self.assertTrue(repository._tag_names_directly(inner, self.commit("c1")))  # noqa: SLF001
        self.assertFalse(repository._tag_names_directly(outer, self.commit("c1")))  # noqa: SLF001
        self.assertFalse(repository._tag_names_directly(inner, self.commit("c0")))  # noqa: SLF001

    def test_a_signed_tag_with_a_name_outside_the_release_shape_is_refused(self) -> None:
        for name in (
            "other/20261114.1",
            "release/latest",
            "release/20261114",
            "release/x20261114.1",
        ):
            tag = self.fixture.tag(self.commit("c1"), self.fixture.release_ssh, name)
            for source in self.routes():
                with self.subTest(name=name, source=source):
                    host, result = self.send(source, self.commit("c1"), [("release-ref", tag)])
                    self.assert_refused(host, result, "release-tag-missing")

    def test_a_signature_made_under_another_ssh_namespace_is_refused(self) -> None:
        tag = self.fixture.sign_as_ssh_namespace(
            self.commit("c1"), self.fixture.release_ssh, "file"
        )
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [("a", tag)])
                self.assert_refused(host, result, "release-tag-missing")

    def test_a_tag_whose_message_was_changed_after_signing_is_refused(self) -> None:
        for signer in (self.fixture.release_ssh, self.fixture.release_pgp):
            tag = self.fixture.tamper(self.fixture.tag(self.commit("c1"), signer))
            for source in self.routes():
                with self.subTest(signer=type(signer).__name__, source=source):
                    host, result = self.send(source, self.commit("c1"), [("a", tag)])
                    self.assert_refused(host, result, "release-tag-missing")

    def test_more_tags_than_the_limit_are_refused_as_their_own_reason_even_with_a_real_one(
        self,
    ) -> None:
        junk = self.junk(trigger.MAX_RELEASE_CANDIDATES)
        real = self.fixture.tag(self.commit("c1"), self.fixture.release_ssh)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [*junk, ("real", real)])
                self.assert_refused(host, result, "too-many-release-tags")

    def test_exactly_the_limit_of_tags_is_checked_and_a_real_one_among_them_is_found(self) -> None:
        junk = self.junk(trigger.MAX_RELEASE_CANDIDATES - 1)
        real = self.fixture.tag(self.commit("c1"), self.fixture.release_ssh)
        for source in self.routes():
            with self.subTest(source=source):
                host, result = self.send(source, self.commit("c1"), [*junk, ("real", real)])
                self.assert_applied(host, result)

    def test_a_refusal_leaves_the_host_byte_for_byte_unchanged(self) -> None:
        host = self.make_host(source="bundle")
        before = snapshot(host.state)
        result = self.push(host, self.commit("c1"), [])
        self.assert_refused(host, result, "release-tag-missing")
        kept = {
            k: v
            for k, v in snapshot(host.state).items()
            if k.startswith(("last-applied", "current", "work/"))
        }
        self.assertEqual({k: v for k, v in before.items() if k in kept}, kept)
        self.assertEqual([], list((host.state / "quarantine").iterdir()))
        self.assertEqual([], list((host.state / "spool").iterdir()))

    def test_a_tag_withdrawn_at_the_remote_is_gone_on_the_next_request(self) -> None:
        tag = self.fixture.tag(self.commit("c1"), self.fixture.release_ssh)
        host = self.make_host()
        first = self.pull(host, self.commit("c1"), [("a", tag)], "check")
        self.assertEqual(11, first.code, first.summary + first.errors)
        run([GIT, "update-ref", "-d", "refs/tags/release/a"], cwd=host.bare)
        second = self.pull(host, self.commit("c1"), [], "check")
        self.assertEqual(20, second.code, second.summary + second.errors)
        self.assertTrue(second.has("reason=release-tag-missing"), second.summary)
        self.assertEqual(1, len(host.applied()))

    def test_a_tag_is_required_of_a_commit_that_is_not_on_main_too_on_the_pull_route(self) -> None:
        # The pull route keeps its ancestry test first; the tag does not replace it.
        tag = self.fixture.tag(self.commit("tip"), self.fixture.release_ssh)
        host = self.make_host()
        result = self.pull(host, self.commit("tip"), [("a", tag)], tip=self.commit("c1"))
        self.assertEqual(20, result.code)
        self.assertTrue(result.has("reason=not-on-main"), result.summary)

    def test_a_host_that_is_not_told_to_require_a_tag_ignores_tags_and_reads_the_commit(
        self,
    ) -> None:
        tag = self.fixture.tag(self.commit("c1"), self.fixture.release_ssh)
        host = self.make_host(require_release_tag=False)
        result = self.pull(host, self.commit("c1"), [("a", tag)])
        self.assert_applied(host, result)
        unsigned = self.make_host(require_release_tag=False)
        refused = self.pull(unsigned, self.commit("unsigned"), [("a", tag)])
        self.assertEqual(20, refused.code)
        self.assertTrue(refused.has("reason=unsigned"), refused.summary)


class ReleaseConfigTests(unittest.TestCase):
    """The two optional keys, and the configuration of a host that does not use them."""

    def parse(self, **changes: object) -> trigger.Config:
        """Parse a valid configuration with ``changes``."""
        return trigger.parse_config(json.dumps(valid_config_data(**changes)))

    def test_a_configuration_without_the_keys_requires_no_tag_and_has_no_release_key(self) -> None:
        config = self.parse()
        self.assertFalse(config.require_release_tag)
        self.assertEqual((), config.release_signers)

    def test_the_keys_are_read(self) -> None:
        key = {"format": "ssh", "key": "ssh-ed25519 " + "A" * 68}
        config = self.parse(release_signers=[key], require_release_tag=True)
        self.assertTrue(config.require_release_tag)
        self.assertEqual("ssh", config.release_signers[0].key_format)

    def test_release_keys_may_be_listed_while_the_tag_is_not_yet_required(self) -> None:
        key = {"format": "ssh", "key": "ssh-ed25519 " + "A" * 68}
        config = self.parse(release_signers=[key], require_release_tag=False)
        self.assertFalse(config.require_release_tag)

    def test_a_requirement_no_key_could_meet_is_refused(self) -> None:
        for changes in (
            {"require_release_tag": True},
            {"require_release_tag": True, "release_signers": []},
        ):
            with self.subTest(changes), self.assertRaises(trigger.ConfigError):
                self.parse(**changes)

    def test_a_flag_that_is_not_a_boolean_is_refused(self) -> None:
        key = {"format": "ssh", "key": "ssh-ed25519 " + "A" * 68}
        for flag in ("true", 1, "yes", None, [True]):
            with self.subTest(flag), self.assertRaises(trigger.ConfigError):
                self.parse(release_signers=[key], require_release_tag=flag)

    def test_release_keys_that_are_not_a_list_of_keys_are_refused(self) -> None:
        for value in ("ssh-ed25519 AAAA", {"format": "ssh"}, [{"format": "ssh"}], [3]):
            with self.subTest(value), self.assertRaises(trigger.ConfigError):
                self.parse(release_signers=value)

    def test_an_unknown_key_is_still_refused(self) -> None:
        with self.assertRaises(trigger.ConfigError):
            self.parse(require_release_tags=True)


class SplitSignedTagTests(unittest.TestCase):
    """The split of a tag object into what was signed and its signature."""

    body = b"object " + b"a" * 40 + b"\ntype commit\ntag release/20261114.1\n\nmessage\n"

    def test_a_signature_block_that_runs_to_the_end_is_split_off(self) -> None:
        for kind, key_format in ((b"SSH", "ssh"), (b"PGP", "openpgp")):
            block = (
                b"-----BEGIN "
                + kind
                + b" SIGNATURE-----\nAAAA\n-----END "
                + kind
                + b" SIGNATURE-----\n"
            )
            with self.subTest(kind):
                split = trigger.split_signed_tag(self.body + block)
                self.assertEqual((self.body, block, key_format), split)

    def test_no_block_or_an_unclosed_one_or_trailing_text_is_not_a_signed_tag(self) -> None:
        opened = b"-----BEGIN SSH SIGNATURE-----\nAAAA\n"
        closed = opened + b"-----END SSH SIGNATURE-----\n"
        for raw in (self.body, self.body + opened, self.body + closed + b"after\n"):
            with self.subTest(raw[-20:]):
                self.assertIsNone(trigger.split_signed_tag(raw))

    def test_a_block_of_another_kind_is_not_a_signature(self) -> None:
        raw = self.body + b"-----BEGIN SIGNED MESSAGE-----\nAAAA\n-----END SIGNED MESSAGE-----\n"
        self.assertIsNone(trigger.split_signed_tag(raw))


if __name__ == "__main__":
    unittest.main()
