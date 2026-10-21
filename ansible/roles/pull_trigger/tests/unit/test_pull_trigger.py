"""Unit tests for pull_trigger: the validator, the refusals, the state it keeps and the exit codes.

The end-to-end cases use real git and real signatures on throwaway repositories.
"""

import contextlib
import dataclasses
import hashlib
import io
import json
import os
import random
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import threading
import unittest
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import pull_trigger as trigger

GIT = Path(shutil.which("git") or "/usr/bin/git")
SSH_KEYGEN = Path(shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen")
GPG = shutil.which("gpg")
GPGCONF = shutil.which("gpgconf")
PROGRAM = Path(trigger.__file__)

# Fixed dates make the fixture commits reproducible. Nothing here redirects git's home or
# configuration: the test process's own git reads the real environment.
FIXTURE_DATES = {
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}

# Every input the caller could send that must never reach git.
HOSTILE_COMMITS = {
    "short hex": "a" * 39,
    "long hex": "a" * 41,
    "uppercase": "A" * 40,
    "mixed case": "aA" * 20,
    "ref name": "main",
    "head": "HEAD",
    "abbreviation": "abcdef0",
    "option": "--upload-pack=EXAMPLE",
    "option-looking hex": "-" + "a" * 39,
    "empty": "",
    "space": " ",
    "trailing newline": "a" * 40 + "\n",
    "leading newline": "\n" + "a" * 40,
    "embedded newline": "a" * 20 + "\n" + "a" * 20,
    "trailing space": "a" * 40 + " ",
    "two words": "a" * 40 + " " + "b" * 40,
    "apply prefix": "apply " + "a" * 40,
    "semicolon": "a" * 40 + ";id",
    "dollar": "$(id)" + "a" * 35,
    "backtick": "`id`" + "a" * 36,
    "nul": "a" * 39 + "\x00",
    "non-hex letter": "g" * 40,
    "unicode digit": "\u0661" * 40,
    "fullwidth": "\uff41" * 40,
}


def run(
    argv: Sequence[str | Path],
    cwd: Path | None = None,
    extra: Mapping[str, str] | None = None,
    stdin: str | None = None,
) -> str:
    """Run a fixture command in the real environment and return its output.

    Raises:
        AssertionError: The command exits with a non-zero status.
    """
    environment = {**os.environ, **FIXTURE_DATES, **(extra or {})}
    done = subprocess.run(  # noqa: S603 - test fixtures, argument lists, no shell
        [str(item) for item in argv],
        cwd=cwd,
        env=environment,
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        message = f"{argv[:3]} failed: {done.stderr}"
        raise AssertionError(message)
    return done.stdout.strip()


@dataclasses.dataclass(frozen=True)
class SshKey:
    """A throwaway SSH signing key."""

    private: Path

    @property
    def public_line(self) -> str:
        """The public key line, without its comment."""
        return " ".join(self.private.with_suffix(".pub").read_text(encoding="utf-8").split()[:2])


@dataclasses.dataclass(frozen=True)
class GpgKey:
    """A throwaway OpenPGP signing key and the keyring that holds it."""

    home: Path
    fingerprint: str
    armoured: str


def git_command(signer: SshKey | GpgKey | None = None) -> list[str | Path]:
    """Return the start of every fixture ``git`` command: the program and its ``-c`` settings.

    The one place the fixtures' git settings are made. They are passed with ``-c`` and the
    real environment is kept, so the owner's own git configuration is never redirected.
    A signer turns signing on with its throwaway key; no setting here turns signing off.
    """
    argv: list[str | Path] = [GIT, "-c", "user.name=TEST_AUTHOR"]
    argv += ["-c", "user.email=author@example.invalid"]
    if isinstance(signer, SshKey):
        argv += ["-c", "commit.gpgsign=true", "-c", "gpg.format=ssh"]
        argv += ["-c", f"user.signingkey={signer.private}"]
    elif isinstance(signer, GpgKey):
        argv += ["-c", "commit.gpgsign=true", "-c", "gpg.format=openpgp"]
        argv += ["-c", f"user.signingkey={signer.fingerprint}"]
        argv += ["-c", f"gpg.program={require_gpg()}"]
    return argv


def require_gpg() -> str:
    """Return the path of gpg, or fail the test that needs it.

    A missing gpg is a failure and not a skip: a skipped OpenPGP test would let the
    OpenPGP path go unproven while the run still reported success.

    Raises:
        AssertionError: gpg is not installed on this machine.
    """
    if GPG is None or GPGCONF is None:
        message = "gpg and gpgconf must be installed: the OpenPGP tests do not skip"
        raise AssertionError(message)
    return GPG


def make_ssh_key(directory: Path, name: str) -> SshKey:
    """Make an unencrypted ed25519 key pair."""
    private = directory / name
    run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", private])
    return SshKey(private)


def make_gpg_key(directory: Path, name: str) -> GpgKey:
    """Make an OpenPGP signing key in its own keyring."""
    home = Path(tempfile.mkdtemp(prefix="g"))
    home.chmod(0o700)
    base: list[str | Path] = [require_gpg(), "--batch", "--homedir", home]
    run(
        [*base, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key", name]
        + ["ed25519", "sign", "never"]
    )
    listing = run([*base, "--list-keys", "--with-colons"])
    fingerprint = next(line.split(":")[9] for line in listing.split("\n") if line.startswith("fpr"))
    armoured = run([*base, "--armor", "--export", fingerprint]) + "\n"
    return GpgKey(home, fingerprint, armoured)


def forget_gpg(key: GpgKey) -> None:
    """Stop the agent a key's keyring started and remove the keyring."""
    if GPGCONF is not None:
        run([GPGCONF, "--homedir", key.home, "--kill", "all"])
    shutil.rmtree(key.home, ignore_errors=True)


class Remote:
    """A bare repository standing in for the read-only remote, and the means to fill it."""

    def __init__(self, bare: Path, work: Path) -> None:
        """Remember the bare repository and the work repository that fills it."""
        self.bare = bare
        self.work = work

    @classmethod
    def create(cls, root: Path) -> "Remote":
        """Make a bare repository and a work repository beside it."""
        remote = cls(root / "remote.git", root / "work")
        run([*git_command(), "init", "-q", "--bare", "-b", "main", remote.bare])
        run([*git_command(), "init", "-q", "-b", "main", remote.work])
        return remote

    def commit(
        self,
        files: Mapping[str, str | None],
        message: str,
        parent: str | None,
        signer: SshKey | GpgKey | None,
    ) -> str:
        """Make a commit whose tree is the work tree after ``files`` are applied.

        A value of None removes the file; a value starting ``->`` makes a symlink.
        """
        for name, content in files.items():
            path = self.work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.unlink(missing_ok=True)
            if content is None:
                continue
            if content.startswith("->"):
                path.symlink_to(content[2:])
            else:
                path.write_text(content, encoding="utf-8")
        run([*git_command(), "add", "-A"], cwd=self.work)
        tree = run([*git_command(), "write-tree"], cwd=self.work)
        extra = {"GNUPGHOME": str(signer.home)} if isinstance(signer, GpgKey) else {}
        argv = git_command(signer)
        argv += ["commit-tree", *(["-S"] if signer else []), *(["-p", parent] if parent else [])]
        argv += ["-m", message, tree]
        sha = run(argv, cwd=self.work, extra=extra)
        self.publish(sha)
        return sha

    def publish(self, sha: str) -> None:
        """Force a commit onto the remote's ``staging`` branch."""
        run(
            [*git_command(), "push", "-q", "--force", self.bare, f"{sha}:refs/heads/staging"],
            cwd=self.work,
        )

    def forge(self, sha: str, old: str, new: str) -> str:
        """Rewrite a commit's message but keep its signature, which then no longer verifies."""
        text = run([*git_command(), "cat-file", "commit", sha], cwd=self.work)
        return self.store(text.replace(f"\n\n{old}", f"\n\n{new}") + "\n")

    def resign_in_namespace(self, sha: str, signer: SshKey, namespace: str) -> str:
        """Return the same commit with an SSH signature made under another namespace.

        Git always signs and verifies under the namespace ``git``. The signature
        made here is a valid signature by the listed key over the same bytes git
        would sign, except for the namespace it is bound to.
        """
        text = run([*git_command(), "cat-file", "commit", sha], cwd=self.work) + "\n"
        payload = self.work.parent / f"payload-{namespace}"
        payload.write_text(text, encoding="utf-8")
        run([SSH_KEYGEN, "-Y", "sign", "-n", namespace, "-f", signer.private, payload])
        signature = Path(f"{payload}.sig").read_text(encoding="utf-8").rstrip("\n")
        header, _, body = text.partition("\n\n")
        armoured = "\n ".join(signature.split("\n"))
        return self.store(f"{header}\ngpgsig {armoured}\n\n{body}")

    def store(self, text: str) -> str:
        """Write a commit object from its text, publish it as ``staging`` and return its id."""
        stored = run(
            [*git_command(), "hash-object", "-t", "commit", "-w", "--stdin"],
            cwd=self.work,
            stdin=text,
        )
        self.publish(stored)
        return stored

    def commit_playbooks_link(
        self, target: str, files: Mapping[str, str | None], parent: str, signer: SshKey
    ) -> str:
        """Commit with ``ansible/playbooks`` a link to ``target``, then put the directory back."""
        directory = self.work / "ansible" / "playbooks"
        shutil.rmtree(directory)
        directory.symlink_to(target)
        sha = self.commit(files, "playbooks is a link", parent, signer)
        directory.unlink()
        directory.mkdir()
        return sha

    def set_ref(self, ref: str, sha: str) -> None:
        """Point a branch of the remote at a commit."""
        run([*git_command(), "update-ref", f"refs/heads/{ref}", sha], cwd=self.bare)


def playbook_text(marker: str) -> str:
    """Return the text of a placeholder playbook that carries a marker."""
    return f"- hosts: all\n  tasks: []\n# {marker}\n"


def fake_ansible(directory: Path, changed: int = 1, code: int = 0, sleep: float = 0.0) -> Path:
    """Write a stand-in for ansible-playbook that records how it was called."""
    script = directory / "ansible-playbook"
    calls = directory / "calls.txt"
    script.write_text(
        f"#!{sys.executable}\n"
        "import os, sys, time\n"
        f"with open({str(calls)!r}, 'a', encoding='utf-8') as handle:\n"
        "    handle.write(' '.join(sys.argv[1:]) + '\\n')\n"
        "    handle.write('cwd=' + os.getcwd() + '\\n')\n"
        f"time.sleep({sleep})\n"
        "print('PLAY RECAP *****')\n"
        f"print('localhost : ok=3 changed={changed} unreachable=0 failed=0 skipped=0')\n"
        f"sys.exit({code})\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def snapshot(root: Path) -> dict[str, str]:
    """Describe every file, directory and link under ``root``, so two states can be compared."""
    state: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            state[relative] = f"link {os.readlink(path)}"
        elif stat.S_ISDIR(info.st_mode):
            state[relative] = f"dir {stat.S_IMODE(info.st_mode):o}"
        else:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            state[relative] = f"file {stat.S_IMODE(info.st_mode):o} {digest}"
    return state


def resolve_commit(arguments: trigger.Arguments, environ: Mapping[str, str]) -> str:
    """Return the commit of the request the caller made, which has no step."""
    request = trigger.resolve_request(arguments, environ)
    assert request.step is None  # noqa: S101 - a test helper for the plain requests
    return request.commit


class ArgumentTests(unittest.TestCase):
    """The command line root sets and the one input the caller sends."""

    def test_the_commit_of_forty_lowercase_hex_digits_is_accepted_from_the_ssh_text(self) -> None:
        commit = "0123456789abcdef" * 2 + "01234567"
        arguments = trigger.parse_arguments(["--mode", "apply"])
        self.assertEqual(commit, resolve_commit(arguments, {"SSH_ORIGINAL_COMMAND": commit}))

    def test_the_commit_is_accepted_as_the_one_positional_word_when_run_by_hand(self) -> None:
        arguments = trigger.parse_arguments(["--mode", "check", "a" * 40])
        self.assertEqual("a" * 40, resolve_commit(arguments, {}))

    def test_every_hostile_commit_is_refused_from_the_ssh_text(self) -> None:
        arguments = trigger.parse_arguments(["--mode", "apply"])
        for name, value in HOSTILE_COMMITS.items():
            with self.subTest(name):
                with self.assertRaises(trigger.BadRequestError):
                    resolve_commit(arguments, {"SSH_ORIGINAL_COMMAND": value})

    def test_every_hostile_commit_is_refused_as_a_positional_word(self) -> None:
        for name, value in HOSTILE_COMMITS.items():
            with self.subTest(name):
                if value.startswith("-"):
                    with self.assertRaises(trigger.BadRequestError):
                        trigger.parse_arguments(["--mode", "apply", value])
                else:
                    arguments = trigger.parse_arguments(["--mode", "apply", value])
                    with self.assertRaises(trigger.BadRequestError):
                        resolve_commit(arguments, {})

    def test_a_commit_given_both_ways_is_refused(self) -> None:
        arguments = trigger.parse_arguments(["--mode", "apply", "a" * 40])
        with self.assertRaises(trigger.BadRequestError):
            resolve_commit(arguments, {"SSH_ORIGINAL_COMMAND": "a" * 40})

    def test_two_positional_words_and_none_are_refused(self) -> None:
        for words in (["a" * 40, "b" * 40], []):
            with self.subTest(words=words):
                arguments = trigger.parse_arguments(["--mode", "apply", *words])
                with self.assertRaises(trigger.BadRequestError):
                    resolve_commit(arguments, {})

    def test_an_empty_ssh_text_is_refused_not_treated_as_absent(self) -> None:
        arguments = trigger.parse_arguments(["--mode", "apply", "a" * 40])
        with self.assertRaises(trigger.BadRequestError):
            resolve_commit(arguments, {"SSH_ORIGINAL_COMMAND": ""})

    def test_a_random_string_is_accepted_only_if_it_is_exactly_forty_lowercase_hex_digits(
        self,
    ) -> None:
        generator = random.Random(20261019)  # noqa: S311 - a fixed seed, not a secret
        alphabet = string.hexdigits + string.ascii_letters + " \n\t\r-;$`'\"\\\x00\u0661"
        arguments = trigger.parse_arguments(["--mode", "apply"])
        for _ in range(3000):
            length = generator.choice([0, 1, 39, 40, 40, 40, 41, 80])
            candidate = "".join(generator.choice(alphabet) for _ in range(length))
            expected = length == 40 and all(
                character in "0123456789abcdef" for character in candidate
            )
            try:
                accepted = resolve_commit(arguments, {"SSH_ORIGINAL_COMMAND": candidate})
            except trigger.BadRequestError:
                self.assertFalse(expected, repr(candidate))
            else:
                self.assertTrue(expected, repr(candidate))
                self.assertEqual(candidate, accepted)

    def test_forty_lowercase_hex_digits_are_always_accepted(self) -> None:
        generator = random.Random(7)  # noqa: S311 - a fixed seed, not a secret
        arguments = trigger.parse_arguments(["--mode", "apply"])
        for _ in range(500):
            candidate = "".join(generator.choice("0123456789abcdef") for _ in range(40))
            self.assertEqual(
                candidate,
                resolve_commit(arguments, {"SSH_ORIGINAL_COMMAND": candidate}),
            )

    def test_the_mode_is_required_and_must_be_apply_or_check(self) -> None:
        bad = [
            [],
            ["--mode"],
            ["--mode", ""],
            ["--mode", "APPLY"],
            ["--mode", "apply;"],
            ["--mode", "plan"],
        ]
        for argv in bad:
            with self.subTest(argv=argv), self.assertRaises(trigger.BadRequestError):
                trigger.parse_arguments(argv)

    def test_an_option_given_twice_or_unknown_is_refused(self) -> None:
        bad = [
            ["--mode", "apply", "--mode", "check"],
            ["--mode", "apply", "--config", "/a", "--config", "/b"],
            ["--mode", "apply", "--help"],
            ["--mode", "apply", "-c"],
            ["--mode", "apply", "--"],
            ["--mode", "apply", "--config", "relative"],
            ["--mode", "apply", "--config"],
        ]
        for argv in bad:
            with self.subTest(argv=argv), self.assertRaises(trigger.BadRequestError):
                trigger.parse_arguments(argv)

    def test_the_default_configuration_is_the_root_owned_etc_file(self) -> None:
        arguments = trigger.parse_arguments(["--mode", "check"])
        self.assertEqual(Path("/etc/pull-trigger/config.json"), arguments.config_path)
        self.assertIs(trigger.Mode.CHECK, arguments.mode)


class StepRequestTests(unittest.TestCase):
    """The grammar of a step request, and the mode that alone may carry it."""

    commit = "0123456789abcdef" * 2 + "01234567"

    def step_arguments(self, *positional: str) -> trigger.Arguments:
        """Return the arguments the step key's forced command gives."""
        return trigger.parse_arguments(["--mode", "step", *positional])

    def test_a_commit_a_step_id_and_a_word_are_accepted_from_the_ssh_text(self) -> None:
        request = trigger.resolve_request(
            self.step_arguments(), {"SSH_ORIGINAL_COMMAND": f"{self.commit} migrate MIGRATE-1"}
        )
        self.assertEqual(trigger.Request(self.commit, "migrate", "MIGRATE-1"), request)

    def test_the_same_three_words_are_accepted_by_hand_as_three_positional_words(self) -> None:
        request = trigger.resolve_request(
            self.step_arguments(self.commit, "identity", "WORD-0001"), {}
        )
        self.assertEqual(trigger.Request(self.commit, "identity", "WORD-0001"), request)

    def test_a_step_request_with_any_mode_but_step_is_refused_for_its_mode(self) -> None:
        text = f"{self.commit} migrate MIGRATE-1"
        for mode in ("apply", "check"):
            with self.subTest(mode):
                arguments = trigger.parse_arguments(["--mode", mode])
                with self.assertRaises(trigger.StepModeOnlyError) as caught:
                    trigger.resolve_request(arguments, {"SSH_ORIGINAL_COMMAND": text})
                self.assertEqual("step-mode-only", caught.exception.reason)
                self.assertNotIn("MIGRATE-1", caught.exception.detail)

    def test_a_bare_commit_with_the_step_mode_is_refused_not_run_as_a_plain_apply(self) -> None:
        with self.assertRaises(trigger.BadRequestError):
            trigger.resolve_request(self.step_arguments(), {"SSH_ORIGINAL_COMMAND": self.commit})
        with self.assertRaises(trigger.BadRequestError):
            trigger.resolve_request(self.step_arguments(self.commit), {})

    def test_two_or_four_words_in_step_mode_are_refused_by_hand_and_by_ssh(self) -> None:
        for words in ([self.commit, "migrate"], [self.commit, "migrate", "WORD-0001", "extra"]):
            with self.subTest(words):
                with self.assertRaises(trigger.BadRequestError):
                    trigger.resolve_request(self.step_arguments(*words), {})
                with self.assertRaises(trigger.BadRequestError):
                    trigger.resolve_request(
                        self.step_arguments(), {"SSH_ORIGINAL_COMMAND": " ".join(words)}
                    )

    def test_every_hostile_step_request_is_refused_as_malformed_in_every_mode(self) -> None:
        good = "WORD-0001"
        hostile = {
            "trailing token": f"{self.commit} migrate {good} extra",
            "trailing newline": f"{self.commit} migrate {good}\n",
            "trailing space": f"{self.commit} migrate {good} ",
            "leading space": f" {self.commit} migrate {good}",
            "newline in the word": f"{self.commit} migrate WORD\n0001",
            "newline instead of a space": f"{self.commit}\nmigrate {good}",
            "tab between words": f"{self.commit}\tmigrate\t{good}",
            "double space": f"{self.commit}  migrate {good}",
            "uppercase step id": f"{self.commit} MIGRATE {good}",
            "step id starting with a digit": f"{self.commit} 1migrate {good}",
            "step id with a hyphen": f"{self.commit} mi-grate {good}",
            "step id too long": f"{self.commit} {'a' * 33} {good}",
            "lowercase word": f"{self.commit} migrate word-0001",
            "word too short": f"{self.commit} migrate ABC",
            "word too long": f"{self.commit} migrate {'A' * 33}",
            "word with an underscore": f"{self.commit} migrate WORD_0001",
            "word with a semicolon": f"{self.commit} migrate WORD;0001",
            "word with a dollar": f"{self.commit} migrate $WORD0001",
            "word is an option": f"{self.commit} migrate --tags",
            "step id is an option": f"{self.commit} --tags {good}",
            "unicode word": f"{self.commit} migrate WORD-{chr(0x661) * 4}",
            "uppercase commit": f"{self.commit.upper()} migrate {good}",
            "short commit": f"{self.commit[:39]} migrate {good}",
            "nul in the word": f"{self.commit} migrate WORD-0001\x00",
            "empty step id": f"{self.commit}  {good}",
        }
        for mode in ("apply", "check", "step"):
            for name, text in hostile.items():
                with self.subTest(mode=mode, case=name):
                    arguments = trigger.parse_arguments(["--mode", mode])
                    with self.assertRaises(trigger.BadRequestError):
                        trigger.resolve_request(arguments, {"SSH_ORIGINAL_COMMAND": text})

    def test_a_random_step_request_is_accepted_only_if_every_word_matches_its_pattern(self) -> None:
        generator = random.Random(20261021)  # noqa: S311 - a fixed seed, not a secret
        alphabet = string.ascii_letters + string.digits + " \n\t-_;$`'\"\x00" + chr(0x661)
        arguments = self.step_arguments()
        step_tail = string.ascii_lowercase + string.digits + "_"
        word_chars = string.ascii_uppercase + string.digits + "-"
        accepted = 0
        for _ in range(3000):
            step_length = generator.choice([0, 1, 8, 32, 33])
            word_length = generator.choice([0, 3, 4, 12, 32, 33])
            step_pool = generator.choice([alphabet, step_tail])
            word_pool = generator.choice([alphabet, word_chars])
            step = "".join(generator.choice(step_pool) for _ in range(step_length))
            word = "".join(generator.choice(word_pool) for _ in range(word_length))
            expected = (
                1 <= len(step) <= 32
                and step[0] in string.ascii_lowercase
                and all(ch in step_tail for ch in step)
                and 4 <= len(word) <= 32
                and all(ch in word_chars for ch in word)
            )
            text = f"{self.commit} {step} {word}"
            try:
                request = trigger.resolve_request(arguments, {"SSH_ORIGINAL_COMMAND": text})
            except trigger.BadRequestError:
                self.assertFalse(expected, repr(text))
            else:
                self.assertTrue(expected, repr(text))
                self.assertEqual(trigger.Request(self.commit, step, word), request)
                accepted += 1
        self.assertGreater(accepted, 50, "the generator no longer reaches the accepted case")

    def test_the_mode_step_is_a_mode_and_nothing_else_named_so_is(self) -> None:
        self.assertIs(trigger.Mode.STEP, self.step_arguments().mode)
        for value in ("STEP", "steps", "step;", " step"):
            with self.subTest(value), self.assertRaises(trigger.BadRequestError):
                trigger.parse_arguments(["--mode", value])


class PlaybookPathTests(unittest.TestCase):
    """What the allowlist may hold."""

    def test_plain_paths_under_ansible_playbooks_are_accepted(self) -> None:
        for path in (
            "ansible/playbooks/host.yml",
            "ansible/playbooks/host_1.yaml",
            "ansible/playbooks/group/host-2.yml",
        ):
            with self.subTest(path):
                self.assertEqual(path, trigger.canonical_playbook(path))

    def test_every_hostile_path_is_rejected(self) -> None:
        hostile = {
            "parent": "ansible/playbooks/../../etc/host.yml",
            "parent inside": "ansible/playbooks/a/../host.yml",
            "absolute": "/ansible/playbooks/host.yml",
            "absolute elsewhere": "/etc/host.yml",
            "outside": "ansible/roles/host.yml",
            "sibling": "ansible/playbooks2/host.yml",
            "root only": "ansible/playbooks",
            "dot": "ansible/playbooks/./host.yml",
            "doubled slash": "ansible/playbooks//host.yml",
            "trailing slash": "ansible/playbooks/host.yml/",
            "no extension": "ansible/playbooks/host",
            "wrong extension": "ansible/playbooks/host.sh",
            "newline": "ansible/playbooks/host.yml\n",
            "newline inside": "ansible/playbooks/ho\nst.yml",
            "space": "ansible/playbooks/ho st.yml",
            "hidden": "ansible/playbooks/.host.yml",
            "backslash": "ansible\\playbooks\\host.yml",
            "empty": "",
            "unicode": "ansible/playbooks/h\u00f6st.yml",
            "nul": "ansible/playbooks/host.yml\x00",
        }
        for name, path in hostile.items():
            with self.subTest(name):
                self.assertIsNone(trigger.canonical_playbook(path))


def valid_config_data(**changes: object) -> dict[str, object]:
    """Return a valid configuration, with ``changes`` applied."""
    key = "ssh-ed25519 " + "A" * 68
    data: dict[str, object] = {
        "remote_url": "https://example.invalid/EXAMPLE_ORG/EXAMPLE_REPO",
        "signers": [{"format": "ssh", "key": key}],
        "playbooks": ["ansible/playbooks/host.yml"],
        "playbook": "ansible/playbooks/host.yml",
        "ansible_playbook": "/usr/local/bin/ansible-playbook",
        "state_dir": "/var/lib/pull-trigger",
        "log_dir": "/var/log/pull-trigger",
        "timeout_seconds": 3600,
        "keep_runs": 50,
    }
    data.update(changes)
    return data


class ConfigTests(unittest.TestCase):
    """The configuration is root's: it is validated strictly and refused when unsafe."""

    def test_a_valid_configuration_is_read(self) -> None:
        config = trigger.parse_config(json.dumps(valid_config_data()))
        self.assertEqual("ansible/playbooks/host.yml", config.playbook)
        self.assertEqual(Path("/var/lib/pull-trigger"), config.state_dir)
        self.assertEqual("ssh", config.signers[0].key_format)

    def test_every_invalid_configuration_is_refused(self) -> None:
        pgp_open = (
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        cases: dict[str, dict[str, object]] = {
            "ssh url": {"remote_url": "ssh://example.invalid/EXAMPLE"},
            "http url": {"remote_url": "http://example.invalid/EXAMPLE"},
            "ext transport": {"remote_url": "ext::sh -c EXAMPLE"},
            "option url": {"remote_url": "--upload-pack=EXAMPLE"},
            "file url with parent": {"remote_url": "file:///srv/../etc/EXAMPLE"},
            "relative file url": {"remote_url": "file://relative/EXAMPLE"},
            "url with space": {"remote_url": "https://example.invalid/a b"},
            "no signers": {"signers": []},
            "signer not a mapping": {"signers": ["ssh-ed25519 AAAA"]},
            "signer with option": {
                "signers": [{"format": "ssh", "key": 'command="id" ssh-ed25519 ' + "A" * 68}]
            },
            "signer with newline": {
                "signers": [{"format": "ssh", "key": "ssh-ed25519 " + "A" * 68 + "\nssh-rsa AAAA"}]
            },
            "signer unknown type": {"signers": [{"format": "ssh", "key": "ssh-foo " + "A" * 68}]},
            "signer format": {"signers": [{"format": "x509", "key": "EXAMPLE"}]},
            "signer extra field": {
                "signers": [{"format": "ssh", "key": "ssh-ed25519 " + "A" * 68, "x": 1}]
            },
            "signer pgp garbage": {"signers": [{"format": "openpgp", "key": "EXAMPLE"}]},
            "signer openssh private key": {
                "signers": [
                    {
                        "format": "ssh",
                        "key": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n"
                        "-----END OPENSSH PRIVATE KEY-----\n",
                    }
                ]
            },
            "signer pgp private key": {
                "signers": [
                    {
                        "format": "openpgp",
                        "key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nAAAA\n"
                        "-----END PGP PRIVATE KEY BLOCK-----\n",
                    }
                ]
            },
            "signer pgp trailing text": {
                "signers": [{"format": "openpgp", "key": pgp_open + "extra"}]
            },
            "no playbooks": {"playbooks": []},
            "allowlist traversal": {"playbooks": ["ansible/playbooks/../../etc/x.yml"]},
            "allowlist absolute": {"playbooks": ["/etc/x.yml"]},
            "allowlist not text": {"playbooks": [1]},
            "playbook not text": {"playbook": 3},
            "relative state dir": {"state_dir": "state"},
            "state dir with parent": {"state_dir": "/var/lib/../etc"},
            "state dir too long for the agent socket": {"state_dir": "/var/lib/" + "x" * 60},
            "relative program": {"ansible_playbook": "ansible-playbook"},
            "timeout zero": {"timeout_seconds": 0},
            "timeout huge": {"timeout_seconds": 10**9},
            "timeout text": {"timeout_seconds": "3600"},
            "timeout bool": {"timeout_seconds": True},
            "keep zero": {"keep_runs": 0},
        }
        for name, changes in cases.items():
            with self.subTest(name), self.assertRaises(trigger.ConfigError):
                trigger.parse_config(json.dumps(valid_config_data(**changes)))

    def test_a_missing_or_an_unknown_key_is_refused(self) -> None:
        missing = valid_config_data()
        del missing["keep_runs"]
        extra = valid_config_data(unexpected="EXAMPLE")
        for name, data in {"missing": missing, "unknown": extra}.items():
            with self.subTest(name), self.assertRaises(trigger.ConfigError):
                trigger.parse_config(json.dumps(data))

    def test_text_that_is_not_a_json_object_is_refused(self) -> None:
        for text in ("", "not json", "[]", "null", '"text"', "{", "[" * 200_000):
            with self.subTest(text), self.assertRaises(trigger.ConfigError):
                trigger.parse_config(text)


def step_entry(**changes: object) -> dict[str, object]:
    """Return a valid entry of the step allow-list, with ``changes`` applied."""
    entry: dict[str, object] = {
        "id": "migrate",
        "tag": "control_plane_db_migrate",
        "word": "MIGRATE-0001",
    }
    entry.update(changes)
    return entry


class StepConfigTests(unittest.TestCase):
    """The step allow-list is root's, checked entry by entry, and closed."""

    def test_the_steps_this_program_can_run_are_these_three_and_a_change_is_deliberate(
        self,
    ) -> None:
        self.assertEqual(frozenset({"migrate", "identity", "provision"}), trigger.STEP_IDS)

    def test_a_configuration_without_steps_allows_none(self) -> None:
        self.assertEqual((), trigger.parse_config(json.dumps(valid_config_data())).steps)

    def test_a_valid_step_allow_list_is_read(self) -> None:
        steps = [
            step_entry(),
            step_entry(id="identity", tag="control_plane_db_identity", word="IDENTITY-0002"),
            step_entry(id="provision", tag="control_plane_db_provision", word="PROVISION-3"),
        ]
        config = trigger.parse_config(json.dumps(valid_config_data(steps=steps)))
        self.assertEqual(
            (
                trigger.Step("migrate", "control_plane_db_migrate", "MIGRATE-0001"),
                trigger.Step("identity", "control_plane_db_identity", "IDENTITY-0002"),
                trigger.Step("provision", "control_plane_db_provision", "PROVISION-3"),
            ),
            config.steps,
        )

    def test_an_empty_step_allow_list_is_valid_and_allows_none(self) -> None:
        self.assertEqual((), trigger.parse_config(json.dumps(valid_config_data(steps=[]))).steps)

    def test_a_name_that_is_not_one_of_the_programs_steps_is_refused_whatever_it_is_called(
        self,
    ) -> None:
        names = [
            "break_glass",
            "breakglass",
            "break_glass_expire",
            "support_access",
            "recover_owner_console",
            "shell",
            "restore",
            "anything",
            "Migrate",
            "migrate ",
            "migrate\n",
            "migrate2",
            "",
        ]
        for name in names:
            with self.subTest(name):
                entry = step_entry(id=name, tag="control_plane_db_other")
                with self.assertRaises(trigger.ConfigError) as caught:
                    trigger.parse_config(json.dumps(valid_config_data(steps=[entry])))
                self.assertIn("not one of the steps", caught.exception.detail)

    def test_every_invalid_step_entry_is_refused(self) -> None:
        cases: dict[str, object] = {
            "not a list": "migrate",
            "a mapping instead of a list": step_entry(),
            "an entry that is text": ["migrate"],
            "an entry with an extra field": [step_entry(extra="x")],
            "an entry with a field missing": [{"id": "migrate", "tag": "control_plane_db_migrate"}],
            "an id that is not text": [step_entry(id=1)],
            "a tag that is not text": [step_entry(tag=None)],
            "a word that is not text": [step_entry(word=5)],
            "the tag all": [step_entry(tag="all")],
            "the tag always": [step_entry(tag="always")],
            "the tag never": [step_entry(tag="never")],
            "the tag tagged": [step_entry(tag="tagged")],
            "the tag untagged": [step_entry(tag="untagged")],
            "a comma list of tags": [step_entry(tag="control_plane_db_a,control_plane_db_b")],
            "a comma list with a special": [step_entry(tag="control_plane_db_migrate,all")],
            "a tag in another role's namespace": [step_entry(tag="control_plane_migrate")],
            "an empty tag": [step_entry(tag="")],
            "a tag with a trailing newline": [step_entry(tag="control_plane_db_migrate\n")],
            "a tag with a space": [step_entry(tag="control_plane_db_mig rate")],
            "a tag that is an option": [step_entry(tag="--tags")],
            "a tag with an uppercase letter": [step_entry(tag="control_plane_db_Migrate")],
            "a tag that is only the prefix": [step_entry(tag="control_plane_db_")],
            "a tag too long": [step_entry(tag="control_plane_db_a" + "b" * 32)],
            "an empty word": [step_entry(word="")],
            "a word of three": [step_entry(word="ABC")],
            "a word of thirty-three": [step_entry(word="A" * 33)],
            "a lowercase word": [step_entry(word="migrate-0001")],
            "a word with a newline": [step_entry(word="MIGRATE\n0001")],
            "a word with an underscore": [step_entry(word="MIGRATE_0001")],
            "a duplicate id": [step_entry(), step_entry(word="OTHER-0001")],
        }
        for name, steps in cases.items():
            with self.subTest(name), self.assertRaises(trigger.ConfigError):
                trigger.parse_config(json.dumps(valid_config_data(steps=steps)))

    def test_an_id_paired_with_any_tag_but_its_own_is_refused(self) -> None:
        """The tag decides what runs, so the id the owner approves must be bound to it."""
        wrong_pairs = {
            "migrate with the identity tag": ("migrate", "control_plane_db_identity"),
            "migrate with the provision tag": ("migrate", "control_plane_db_provision"),
            "identity with the migrate tag": ("identity", "control_plane_db_migrate"),
            "identity with the provision tag": ("identity", "control_plane_db_provision"),
            "provision with the migrate tag": ("provision", "control_plane_db_migrate"),
            "provision with the identity tag": ("provision", "control_plane_db_identity"),
            "migrate with the break-glass tag": ("migrate", "control_plane_db_breakglass"),
            "provision with the break-glass tag": ("provision", "control_plane_db_break_glass"),
            "migrate with a mistyped tag": ("migrate", "control_plane_db_migrat"),
            "migrate with a longer tag": ("migrate", "control_plane_db_migrate2"),
            "migrate with no prefix": ("migrate", "migrate"),
        }
        for name, (step_id, tag) in wrong_pairs.items():
            with self.subTest(name):
                entry = step_entry(id=step_id, tag=tag)
                with self.assertRaises(trigger.ConfigError) as caught:
                    trigger.parse_config(json.dumps(valid_config_data(steps=[entry])))
                self.assertIn("followed by the step id", caught.exception.detail)

    def test_every_listed_id_is_accepted_with_exactly_its_own_tag(self) -> None:
        for step_id in sorted(trigger.STEP_IDS):
            with self.subTest(step_id):
                entry = step_entry(id=step_id, tag=f"control_plane_db_{step_id}")
                config = trigger.parse_config(json.dumps(valid_config_data(steps=[entry])))
                self.assertEqual(f"control_plane_db_{step_id}", config.steps[0].tag)

    def test_an_unknown_top_level_key_is_still_refused_with_steps_present(self) -> None:
        data = valid_config_data(steps=[step_entry()], unexpected="x")
        with self.assertRaises(trigger.ConfigError):
            trigger.parse_config(json.dumps(data))

    def test_the_selected_playbook_is_not_checked_against_the_path_rules_by_the_parser(
        self,
    ) -> None:
        config = trigger.parse_config(json.dumps(valid_config_data(playbook="../../etc/EXAMPLE")))
        self.assertNotIn(config.playbook, config.playbooks)


class PlaybookInCheckoutTests(unittest.TestCase):
    """The check on the checkout looks at the files on disk, whatever the commit says."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="pt", dir="/tmp")).resolve()  # noqa: S108
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.checkout = self.root / "checkout"
        (self.checkout / "ansible" / "playbooks").mkdir(parents=True)
        (self.checkout / "ansible" / "playbooks" / "host.yml").write_text("x", encoding="utf-8")
        (self.root / "outside").mkdir()
        (self.root / "outside" / "host.yml").write_text("x", encoding="utf-8")

    def refusal(self, playbook: str = "ansible/playbooks/host.yml") -> str:
        """Return the detail of the refusal, or fail if there is none."""
        with self.assertRaises(trigger.PlaybookNotAllowedError) as caught:
            trigger.require_playbook_in_checkout(self.checkout, playbook)
        return caught.exception.detail

    def test_a_plain_file_under_the_playbook_directory_is_accepted(self) -> None:
        trigger.require_playbook_in_checkout(self.checkout, "ansible/playbooks/host.yml")

    def test_a_playbook_directory_that_is_a_link_inside_the_checkout_is_refused(self) -> None:
        shutil.move(self.checkout / "ansible" / "playbooks", self.checkout / "real")
        (self.checkout / "ansible" / "playbooks").symlink_to("../real")
        self.assertIn(trigger.Why.PLAYBOOK_LINKED.value, self.refusal())

    def test_a_playbook_directory_that_is_a_link_to_a_host_directory_is_refused(self) -> None:
        shutil.rmtree(self.checkout / "ansible" / "playbooks")
        (self.checkout / "ansible" / "playbooks").symlink_to(self.root / "outside")
        self.assertIn(trigger.Why.PLAYBOOK_LINKED.value, self.refusal())

    def test_an_ansible_directory_that_is_a_link_is_refused(self) -> None:
        shutil.move(self.checkout / "ansible", self.checkout / "alt")
        (self.checkout / "ansible").symlink_to("alt")
        self.assertIn(trigger.Why.PLAYBOOK_LINKED.value, self.refusal())

    def test_a_playbook_file_that_is_a_link_is_refused(self) -> None:
        (self.checkout / "ansible" / "playbooks" / "host.yml").unlink()
        (self.checkout / "ansible" / "playbooks" / "host.yml").symlink_to(
            self.root / "outside" / "host.yml"
        )
        self.assertIn(trigger.Why.PLAYBOOK_LINKED.value, self.refusal())

    def test_a_name_that_climbs_out_of_the_playbook_directory_is_refused_by_the_containment_clause(
        self,
    ) -> None:
        # No part of these paths is a link and each ends at a regular file, so the walk
        # over the parts passes and the clause on the resolved path is the only barrier.
        (self.checkout / "ansible" / "other.yml").write_text("x", encoding="utf-8")
        climbs = (
            "ansible/playbooks/../other.yml",
            "ansible/playbooks/../../../outside/host.yml",
        )
        for playbook in climbs:
            with self.subTest(playbook):
                self.assertIn(trigger.Why.PLAYBOOK_ESCAPES.value, self.refusal(playbook))

    def test_a_missing_playbook_and_a_directory_are_refused(self) -> None:
        self.assertIn(trigger.Why.PLAYBOOK_ESCAPES.value, self.refusal("ansible/playbooks/no.yml"))
        (self.checkout / "ansible" / "playbooks" / "d.yml").mkdir()
        self.assertIn(trigger.Why.PLAYBOOK_ESCAPES.value, self.refusal("ansible/playbooks/d.yml"))


class ConfigFileTests(unittest.TestCase):
    """The file must be safe to trust before it is read."""

    def setUp(self) -> None:
        """Make a private directory for the file."""
        self.root = Path(tempfile.mkdtemp(prefix="pt-config-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.root.chmod(0o755)
        self.path = self.root / "config.json"

    def write(self, mode: int) -> None:
        """Write a valid configuration at the given mode."""
        self.path.write_text(json.dumps(valid_config_data()), encoding="utf-8")
        self.path.chmod(mode)

    def test_a_file_owned_by_the_user_and_not_writable_by_others_is_read(self) -> None:
        self.write(0o644)
        self.assertEqual("ansible/playbooks/host.yml", trigger.load_config(self.path).playbook)

    def test_a_file_writable_by_group_or_others_is_refused(self) -> None:
        for mode in (0o664, 0o646, 0o666, 0o622):
            self.write(mode)
            with self.subTest(oct(mode)), self.assertRaises(trigger.ConfigError):
                trigger.load_config(self.path)

    def test_a_directory_writable_by_others_is_refused(self) -> None:
        self.write(0o644)
        self.root.chmod(0o777)
        with self.assertRaises(trigger.ConfigError):
            trigger.load_config(self.path)

    def test_a_symlink_is_refused_even_to_a_good_file(self) -> None:
        self.write(0o644)
        link = self.root / "link.json"
        link.symlink_to(self.path)
        with self.assertRaises(trigger.ConfigError):
            trigger.load_config(link)

    def test_a_missing_file_and_a_directory_are_refused(self) -> None:
        with self.assertRaises(trigger.ConfigError):
            trigger.load_config(self.root / "missing.json")
        with self.assertRaises(trigger.ConfigError):
            trigger.load_config(self.root)

    def test_a_file_that_is_too_large_is_refused(self) -> None:
        self.path.write_text(" " * (trigger.MAX_CONFIG_BYTES + 10), encoding="utf-8")
        self.path.chmod(0o644)
        with self.assertRaises(trigger.ConfigError):
            trigger.load_config(self.path)


class JudgeSignatureTests(unittest.TestCase):
    """The decision from what git reports, as a table."""

    ALLOWED = frozenset({"SHA256:ALLOWED", "ABCDEF0123456789ABCDEF0123456789ABCDEF01"})

    def test_a_good_signature_by_an_allowlisted_key_is_accepted(self) -> None:
        trigger.judge_signature(True, "G", ("SHA256:ALLOWED", ""), self.ALLOWED)
        trigger.judge_signature(
            True, "U", ("OTHER_SUBKEY", "ABCDEF0123456789ABCDEF0123456789ABCDEF01"), self.ALLOWED
        )

    def test_the_table_of_refusals(self) -> None:
        table: list[tuple[str, bool, str, tuple[str, str], type[trigger.RefusedError]]] = [
            ("unsigned", False, "N", ("", ""), trigger.UnsignedError),
            (
                "unsigned with a stray status",
                False,
                "G",
                ("SHA256:ALLOWED", ""),
                trigger.UnsignedError,
            ),
            ("bad signature", True, "B", ("", ""), trigger.BadSignatureError),
            ("expired signature", True, "X", ("SHA256:ALLOWED", ""), trigger.BadSignatureError),
            ("expired key", True, "Y", ("SHA256:ALLOWED", ""), trigger.BadSignatureError),
            ("revoked key", True, "R", ("SHA256:ALLOWED", ""), trigger.BadSignatureError),
            (
                "good ssh signature by a key not listed",
                True,
                "U",
                ("SHA256:OTHER", ""),
                trigger.SignerNotAllowedError,
            ),
            ("good signature, no fingerprint", True, "G", ("", ""), trigger.SignerNotAllowedError),
            ("cannot be checked", True, "E", ("SHA256:ALLOWED", ""), trigger.SignerNotAllowedError),
            ("signed, git says none", True, "N", ("", ""), trigger.SignerNotAllowedError),
            ("unknown letter", True, "Z", ("SHA256:ALLOWED", ""), trigger.SignerNotAllowedError),
        ]
        for name, signed, status, fingerprints, expected in table:
            with self.subTest(name), self.assertRaises(expected):
                trigger.judge_signature(signed, status, fingerprints, self.ALLOWED)


class LockTests(unittest.TestCase):
    """Single flight: a second trigger is refused, and a dead holder frees the lock."""

    def setUp(self) -> None:
        """Make a directory for the lock file."""
        self.root = Path(tempfile.mkdtemp(prefix="pt-lock-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.lock = self.root / "lock"

    def test_a_second_holder_is_refused_while_the_first_holds_the_lock(self) -> None:
        with trigger.single_flight(self.lock):
            with self.assertRaises(trigger.BusyError), trigger.single_flight(self.lock):
                self.fail("the second holder must not get the lock")
        with trigger.single_flight(self.lock):
            pass

    def test_a_holder_that_is_killed_does_not_leave_the_lock_held(self) -> None:
        holder = subprocess.Popen(  # noqa: S603 - a test helper process
            [
                sys.executable,
                "-c",
                "import fcntl, sys, time\n"
                f"f = open({str(self.lock)!r}, 'w')\n"
                "fcntl.flock(f, fcntl.LOCK_EX)\n"
                "print('held', flush=True)\n"
                "time.sleep(60)\n",
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        self.assertIsNotNone(holder.stdout)
        self.assertEqual("held", (holder.stdout or io.StringIO()).readline().strip())
        with self.assertRaises(trigger.BusyError), trigger.single_flight(self.lock):
            self.fail("the lock is held by a live process")
        holder.kill()
        holder.wait()
        with trigger.single_flight(self.lock):
            pass


class ChangedCountTests(unittest.TestCase):
    """The play recap decides applied against unchanged."""

    def count(self, text: str) -> int | None:
        """Write run output and read the changed total."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.log"
            path.write_text(text, encoding="utf-8")
            return trigger.changed_count(path)

    def test_the_changed_figure_is_read_from_the_recap(self) -> None:
        text = "PLAY RECAP\nlocalhost : ok=5 changed=2 unreachable=0 failed=0 skipped=1\n"
        self.assertEqual(2, self.count(text))

    def test_several_hosts_are_summed(self) -> None:
        text = (
            "a : ok=1 changed=1 unreachable=0 failed=0\nb : ok=1 changed=3 unreachable=0 failed=0\n"
        )
        self.assertEqual(4, self.count(text))

    def test_output_without_a_recap_has_no_figure(self) -> None:
        self.assertIsNone(self.count("changed=9 is not a recap line\n"))


@dataclasses.dataclass
class Scene:
    """One test's remote, host directories and configuration."""

    root: Path
    remote: Remote
    config_path: Path
    state: Path
    logs: Path
    ansible: Path
    calls: Path
    calls_before: int = 0


class Run:
    """The outcome of one call of the program."""

    def __init__(self, code: int, summary: str, errors: str, relayed: str) -> None:
        """Keep the exit status, the summary line, stderr and the relayed playbook output."""
        self.code = code
        self.summary = summary
        self.errors = errors
        self.relayed = relayed

    def has(self, field: str) -> bool:
        """Say whether the summary line carries the field, such as ``reason=unsigned``."""
        return f" {field} " in f"{self.summary} "


class EndToEndTests(unittest.TestCase):
    """The whole program on real repositories and real signatures."""

    keys: dict[str, SshKey]
    pgp: dict[str, GpgKey]
    root: Path
    remote: Remote
    commits: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        """Make the keys and the history every test reads."""
        cls.root = Path(tempfile.mkdtemp(prefix="pt-fixture-"))
        keys_dir = cls.root / "keys"
        keys_dir.mkdir()
        cls.keys = {
            "a": make_ssh_key(keys_dir, "signer-a"),
            "b": make_ssh_key(keys_dir, "signer-b"),
        }
        cls.pgp = {
            "g": make_gpg_key(cls.root, "signer-g"),
            "h": make_gpg_key(cls.root, "signer-h"),
        }
        cls.remote = Remote.create(cls.root)
        a, b = cls.keys["a"], cls.keys["b"]
        play = "ansible/playbooks/host.yml"
        commits: dict[str, str] = {}
        commits["c1"] = cls.remote.commit({play: playbook_text("c1")}, "c1", None, a)
        commits["c2"] = cls.remote.commit({play: playbook_text("c2")}, "c2", commits["c1"], a)
        commits["other_key"] = cls.remote.commit(
            {play: playbook_text("b")}, "by b", commits["c2"], b
        )
        commits["unsigned"] = cls.remote.commit(
            {play: playbook_text("u")}, "unsigned", commits["other_key"], None
        )
        signed = cls.remote.commit(
            {play: playbook_text("t")}, "to be tampered", commits["unsigned"], a
        )
        commits["tampered"] = cls.remote.forge(signed, "to be tampered", "tampered after signing")
        commits["c6"] = cls.remote.commit({play: playbook_text("c6")}, "c6", commits["tampered"], a)
        parent = commits["c6"]
        if cls.pgp:
            commits["pgp_good"] = cls.remote.commit(
                {play: playbook_text("g")}, "by g", parent, cls.pgp["g"]
            )
            commits["pgp_other"] = cls.remote.commit(
                {play: playbook_text("h")}, "by h", commits["pgp_good"], cls.pgp["h"]
            )
            parent = commits["pgp_other"]
        commits["no_playbook"] = cls.remote.commit({play: None}, "no playbook", parent, a)
        commits["symlink"] = cls.remote.commit(
            {play: "->../../../etc/hostname"}, "link", commits["no_playbook"], a
        )
        outside = cls.root / "outside"
        outside.mkdir()
        (outside / "host.yml").write_text(playbook_text("outside"), encoding="utf-8")
        commits["dir_link_inside"] = cls.remote.commit_playbooks_link(
            "../real", {"real/host.yml": playbook_text("inside")}, commits["symlink"], a
        )
        commits["dir_link_outside"] = cls.remote.commit_playbooks_link(
            str(outside), {}, commits["dir_link_inside"], a
        )
        commits["tip"] = cls.remote.commit(
            {play: playbook_text("tip")}, "tip", commits["dir_link_outside"], a
        )
        side = cls.remote.commit({play: playbook_text("side")}, "side", commits["c2"], a)
        commits["side"] = side
        cls.remote.set_ref("main", commits["tip"])
        cls.remote.set_ref("side", side)
        cls.commits = commits

    @classmethod
    def tearDownClass(cls) -> None:
        """Remove the fixture and stop any agent it started."""
        for key in cls.pgp.values():
            forget_gpg(key)
        shutil.rmtree(cls.root, ignore_errors=True)

    def make_scene(self, **changes: object) -> Scene:
        """Make a host: its own copy of the remote, state and log directories, and configuration."""
        # A short path: gpg's agent socket lives under the state directory and a long path fails.
        root = Path(tempfile.mkdtemp(prefix="pt", dir="/tmp")).resolve()  # noqa: S108
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        root.chmod(0o700)
        bare = root / "remote.git"
        shutil.copytree(self.remote.bare, bare)
        scene_remote = Remote(bare, self.remote.work)
        signers: list[dict[str, str]] = [{"format": "ssh", "key": self.keys["a"].public_line}]
        config_dir = root / "etc"
        config_dir.mkdir(mode=0o755)
        helper = root / "bin"
        helper.mkdir()
        ansible = fake_ansible(helper)
        data = valid_config_data(
            remote_url=f"file://{bare}",
            signers=signers,
            ansible_playbook=str(ansible),
            state_dir=str(root / "state"),
            log_dir=str(root / "logs"),
            timeout_seconds=60,
        )
        data.update(changes)
        config_path = config_dir / "config.json"
        config_path.write_text(json.dumps(data), encoding="utf-8")
        config_path.chmod(0o644)
        return Scene(
            root,
            scene_remote,
            config_path,
            root / "state",
            root / "logs",
            ansible,
            helper / "calls.txt",
        )

    def request(
        self,
        scene: Scene,
        commit: str,
        mode: str = "apply",
        stop: threading.Event | None = None,
        via_ssh: bool = True,
    ) -> Run:
        """Call the program as the forced command would, and collect what it printed."""
        out, relayed, errors = io.StringIO(), io.BytesIO(), io.StringIO()
        argv = ["--mode", mode, "--config", str(scene.config_path)]
        environ: dict[str, str] = {}
        if via_ssh:
            environ["SSH_ORIGINAL_COMMAND"] = commit
        else:
            argv.append(commit)
        tools = trigger.Tools(
            git=GIT,
            gpg=Path(GPG or "/usr/bin/gpg"),
            gpgconf=Path(GPGCONF or "/usr/bin/gpgconf"),
            ssh_keygen=SSH_KEYGEN,
        )
        with contextlib.redirect_stderr(errors):
            code = trigger.main(argv, environ, stop or threading.Event(), tools, out, relayed)
        return Run(code, out.getvalue().strip(), errors.getvalue(), relayed.getvalue().decode())

    def calls(self, scene: Scene) -> list[str]:
        """Return the lines the stand-in ansible-playbook recorded."""
        return scene.calls.read_text(encoding="utf-8").splitlines() if scene.calls.exists() else []

    def prime(self, scene: Scene) -> None:
        """Apply the oldest commit, so the host has a checkout and a record to protect."""
        first = self.request(scene, self.commits["c2"])
        self.assertEqual(10, first.code, first.summary + first.errors)
        scene.calls_before = len(self.calls(scene))

    def assert_no_new_run(self, scene: Scene) -> None:
        """Assert that the playbook was not started since the scene was primed."""
        self.assertEqual(scene.calls_before, len(self.calls(scene)))

    def assert_refused(self, result: Run, reason: str, code: int = 20) -> None:
        """Assert a refusal with its named reason, and that nothing was run."""
        self.assertEqual(code, result.code, result.summary + result.errors)
        self.assertTrue(result.has(f"reason={reason}"), result.summary)

    @contextlib.contextmanager
    def no_change_to_the_host(self, scene: Scene) -> Iterator[None]:
        """Assert that the state kept for a refusal to protect is byte for byte the same."""
        before = self.host_state(scene)
        yield
        self.assertEqual(before, self.host_state(scene))

    def host_state(self, scene: Scene) -> dict[str, str]:
        """Describe the state that a refusal must leave alone: floor, current checkout and work."""
        state = snapshot(scene.state) if scene.state.exists() else {}
        return {
            name: value
            for name, value in state.items()
            if not name.startswith(("repo.git", "tmp", "home"))
        }

    def test_a_good_commit_is_applied_exactly_once_and_recorded(self) -> None:
        scene = self.make_scene()
        result = self.request(scene, self.commits["c6"])
        self.assertEqual(10, result.code, result.summary + result.errors)
        self.assertTrue(result.has("verdict=applied"))
        self.assertTrue(result.has(f"commit={self.commits['c6']}"))
        self.assertTrue(result.has("playbook=ansible/playbooks/host.yml"))
        self.assertEqual(1, len([line for line in self.calls(scene) if line.startswith("-i")]))
        self.assertIn("PLAY RECAP", result.relayed)
        log = (scene.logs / "pull-trigger.log").read_text(encoding="utf-8")
        self.assertIn(f"commit={self.commits['c6']}", log)
        self.assertEqual(
            f"{self.commits['c6']}\n", (scene.state / "last-applied").read_text(encoding="utf-8")
        )

    def test_the_playbook_runs_against_this_host_only_from_the_exact_checkout(self) -> None:
        scene = self.make_scene()
        self.request(scene, self.commits["c6"])
        arguments, workdir = self.calls(scene)[:2]
        checkout = (scene.state / "current").resolve()
        self.assertEqual(
            f"-i localhost, --connection local {checkout}/ansible/playbooks/host.yml",
            arguments,
        )
        self.assertEqual(f"cwd={checkout}/ansible", workdir)
        self.assertTrue(checkout.name.startswith(self.commits["c6"]))
        self.assertIn("# c6", (checkout / "ansible/playbooks/host.yml").read_text(encoding="utf-8"))
        self.assertFalse((checkout / ".git").exists())

    def test_the_directories_and_files_the_program_keeps_are_private_to_its_user(self) -> None:
        scene = self.make_scene()
        self.request(scene, self.commits["c6"])
        for path in (
            scene.state,
            scene.state / "repo.git",
            scene.state / "work",
            scene.logs,
            scene.logs / "runs",
        ):
            self.assertEqual(0o700, stat.S_IMODE(path.stat().st_mode), str(path))
        for path in (
            scene.logs / "pull-trigger.log",
            scene.state / "last-applied",
            scene.state / "lock",
        ):
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode), str(path))
        for path in (scene.logs / "runs").iterdir():
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode), str(path))

    def test_a_second_request_for_the_same_commit_runs_cleanly_again(self) -> None:
        scene = self.make_scene()
        self.request(scene, self.commits["c6"])
        scene.ansible.write_text(
            scene.ansible.read_text(encoding="utf-8").replace("changed=1", "changed=0"),
            encoding="utf-8",
        )
        second = self.request(scene, self.commits["c6"])
        self.assertEqual(0, second.code, second.summary + second.errors)
        self.assertTrue(second.has("verdict=unchanged"))
        self.assertEqual(2, len([line for line in self.calls(scene) if line.startswith("-i")]))
        self.assertEqual(1, len(list((scene.state / "work").iterdir())))

    def test_a_later_commit_replaces_the_current_checkout_and_removes_the_old_one(self) -> None:
        scene = self.make_scene()
        self.request(scene, self.commits["c2"])
        first = (scene.state / "current").resolve()
        self.request(scene, self.commits["c6"])
        second = (scene.state / "current").resolve()
        self.assertNotEqual(first, second)
        self.assertFalse(first.exists())
        self.assertEqual([second], list((scene.state / "work").iterdir()))

    def test_a_check_request_changes_nothing_and_asks_for_check_and_diff(self) -> None:
        scene = self.make_scene()
        self.request(scene, self.commits["c2"])
        with self.no_change_to_the_host(scene):
            result = self.request(scene, self.commits["c6"], mode="check")
        self.assertEqual(11, result.code, result.summary + result.errors)
        self.assertTrue(result.has("verdict=would-change"))
        self.assertTrue(result.has("mode=check"))
        self.assertTrue(
            self.calls(scene)[-2].startswith("-i localhost, --connection local --check --diff ")
        )

    def test_a_check_request_that_finds_nothing_to_change_exits_zero(self) -> None:
        scene = self.make_scene()
        scene.ansible.write_text(
            scene.ansible.read_text(encoding="utf-8").replace("changed=1", "changed=0"),
            encoding="utf-8",
        )
        result = self.request(scene, self.commits["c6"], mode="check")
        self.assertEqual(0, result.code)
        self.assertFalse((scene.state / "last-applied").exists())
        self.assertFalse((scene.state / "current").exists())
        self.assertEqual([], list((scene.state / "work").iterdir()))

    def test_a_commit_not_on_main_is_refused(self) -> None:
        scene = self.make_scene()
        self.prime(scene)
        with self.no_change_to_the_host(scene):
            result = self.request(scene, self.commits["side"])
        self.assert_refused(result, "not-on-main")
        self.assert_no_new_run(scene)

    def test_a_commit_that_exists_nowhere_is_refused_as_not_on_main(self) -> None:
        scene = self.make_scene()
        self.assert_refused(self.request(scene, "1" * 40), "not-on-main")

    def test_a_commit_that_main_has_moved_away_from_is_refused_though_the_cache_still_holds_it(
        self,
    ) -> None:
        scene = self.make_scene()
        late = {"ansible/playbooks/host.yml": playbook_text("late")}
        extra = scene.remote.commit(late, "late", self.commits["tip"], self.keys["a"])
        scene.remote.set_ref("main", extra)
        self.assertIn(self.request(scene, extra, mode="check").code, (0, 11))
        scene.remote.set_ref("main", self.commits["tip"])
        before = self.host_state(scene)
        result = self.request(scene, extra)
        cached = subprocess.run(  # noqa: S603 - a test probe
            [str(GIT), f"--git-dir={scene.state / 'repo.git'}", "cat-file", "-e", extra],
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            0,
            cached.returncode,
            "the commit must still be in the cache for this test to mean anything",
        )
        self.assert_refused(result, "not-on-main")
        self.assertEqual(before, self.host_state(scene))

    def test_an_unsigned_commit_is_refused(self) -> None:
        scene = self.make_scene()
        self.prime(scene)
        with self.no_change_to_the_host(scene):
            result = self.request(scene, self.commits["unsigned"])
        self.assert_refused(result, "unsigned")
        self.assert_no_new_run(scene)

    def test_a_commit_signed_by_a_key_not_on_the_allowlist_is_refused(self) -> None:
        scene = self.make_scene()
        self.prime(scene)
        with self.no_change_to_the_host(scene):
            result = self.request(scene, self.commits["other_key"])
        self.assert_refused(result, "signer-not-allowed")
        self.assert_no_new_run(scene)

    def test_a_commit_whose_signature_no_longer_verifies_is_refused(self) -> None:
        scene = self.make_scene()
        self.prime(scene)
        with self.no_change_to_the_host(scene):
            result = self.request(scene, self.commits["tampered"])
        self.assert_refused(result, "bad-signature")
        self.assert_no_new_run(scene)

    def test_an_openpgp_commit_by_an_allowlisted_key_is_applied_and_one_by_another_key_is_refused(
        self,
    ) -> None:
        both = [
            {"format": "ssh", "key": self.keys["a"].public_line},
            {"format": "openpgp", "key": self.pgp["g"].armoured},
        ]
        scene = self.make_scene(signers=both)
        self.assert_refused(self.request(scene, self.commits["pgp_other"]), "signer-not-allowed")
        result = self.request(scene, self.commits["pgp_good"])
        self.assertEqual(10, result.code, result.summary + result.errors)

    def test_an_openpgp_signature_made_by_a_key_the_host_holds_but_the_allowlist_lacks_is_refused(
        self,
    ) -> None:
        scene = self.make_scene(signers=[{"format": "ssh", "key": self.keys["a"].public_line}])
        self.assert_refused(self.request(scene, self.commits["pgp_good"]), "signer-not-allowed")

    def test_a_playbook_outside_the_allowlist_is_refused_before_anything_is_fetched(self) -> None:
        scene = self.make_scene(playbook="ansible/playbooks/other.yml")
        result = self.request(scene, self.commits["c6"])
        self.assert_refused(result, "playbook-not-allowed")
        self.assertFalse((scene.state / "repo.git" / "HEAD").exists())
        self.assert_no_new_run(scene)

    def test_a_selected_playbook_that_escapes_the_playbook_directory_is_refused(self) -> None:
        for chosen in ("../../etc/EXAMPLE", "/etc/EXAMPLE", "ansible/playbooks/../../x.yml", ""):
            with self.subTest(chosen):
                scene = self.make_scene(playbook=chosen)
                self.assert_refused(self.request(scene, self.commits["c6"]), "playbook-not-allowed")
                self.assert_no_new_run(scene)

    def test_a_playbook_that_is_absent_from_the_commit_is_refused(self) -> None:
        scene = self.make_scene()
        self.prime(scene)
        with self.no_change_to_the_host(scene):
            result = self.request(scene, self.commits["no_playbook"])
        self.assert_refused(result, "playbook-not-allowed")
        self.assert_no_new_run(scene)

    def test_a_playbook_that_is_a_symlink_in_the_commit_is_refused(self) -> None:
        scene = self.make_scene()
        self.prime(scene)
        with self.no_change_to_the_host(scene):
            result = self.request(scene, self.commits["symlink"])
        self.assert_refused(result, "playbook-not-allowed")
        self.assert_no_new_run(scene)

    def test_a_linked_playbook_or_directory_is_refused_by_each_guard_on_its_own(self) -> None:
        for name in ("dir_link_inside", "dir_link_outside", "symlink"):
            with self.subTest(name):
                scene = self.make_scene()
                self.prime(scene)
                commit = self.commits[name]
                with self.no_change_to_the_host(scene):
                    both = self.request(scene, commit)
                self.assert_refused(both, "playbook-not-allowed")
                self.assertIn(trigger.Why.PLAYBOOK_NOT_REGULAR.value, both.errors)
                # The commit test deleted: the check on the checkout alone refuses.
                with (
                    self.no_change_to_the_host(scene),
                    mock.patch.object(trigger.Cache, "regular_file_in_commit", return_value=True),
                ):
                    without_commit_test = self.request(scene, commit)
                self.assert_refused(without_commit_test, "playbook-not-allowed")
                self.assertIn(trigger.Why.PLAYBOOK_LINKED.value, without_commit_test.errors)
                # The check on the checkout deleted: the commit test alone refuses.
                with (
                    self.no_change_to_the_host(scene),
                    mock.patch.object(trigger, "require_playbook_in_checkout"),
                ):
                    without_checkout_test = self.request(scene, commit)
                self.assert_refused(without_checkout_test, "playbook-not-allowed")
                self.assertIn(trigger.Why.PLAYBOOK_NOT_REGULAR.value, without_checkout_test.errors)
                self.assert_no_new_run(scene)

    def test_the_commit_test_alone_sees_a_linked_directory_and_a_good_commit(self) -> None:
        scene = self.make_scene()
        tools = trigger.Tools(git=GIT, ssh_keygen=SSH_KEYGEN)
        cache = trigger.Cache(
            trigger.Git(tools, scene.remote.bare, scene.root), f"file://{scene.remote.bare}"
        )
        play = "ansible/playbooks/host.yml"
        for name, expected in (
            ("dir_link_inside", False),
            ("dir_link_outside", False),
            ("symlink", False),
            ("tip", True),
        ):
            with self.subTest(name):
                self.assertEqual(expected, cache.regular_file_in_commit(self.commits[name], play))

    def test_a_commit_older_than_the_one_last_applied_is_refused(self) -> None:
        scene = self.make_scene()
        self.assertEqual(10, self.request(scene, self.commits["c6"]).code)
        with self.no_change_to_the_host(scene):
            result = self.request(scene, self.commits["c2"])
        self.assert_refused(result, "rollback")

    def test_a_check_of_an_older_commit_is_refused_too(self) -> None:
        scene = self.make_scene()
        self.assertEqual(10, self.request(scene, self.commits["c6"]).code)
        self.assert_refused(self.request(scene, self.commits["c2"], mode="check"), "rollback")

    def test_a_main_that_was_rewritten_refuses_a_commit_that_does_not_descend_from_the_floor(
        self,
    ) -> None:
        scene = self.make_scene()
        self.assertEqual(10, self.request(scene, self.commits["c6"]).code)
        rewritten = scene.remote.commit(
            {"ansible/playbooks/host.yml": playbook_text("rewritten")},
            "rewritten",
            self.commits["c2"],
            self.keys["a"],
        )
        scene.remote.set_ref("main", rewritten)
        floor = self.commits["c6"]
        cached = subprocess.run(  # noqa: S603 - a test probe
            [str(GIT), f"--git-dir={scene.state / 'repo.git'}", "cat-file", "-e", floor],
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, cached.returncode, "the cache must still hold the floor commit")
        with self.no_change_to_the_host(scene):
            result = self.request(scene, rewritten)
        self.assertEqual(20, result.code, result.summary + result.errors)
        self.assertTrue(result.has("reason=rollback"))

    def test_a_rewritten_main_and_a_cache_that_lost_the_floor_commit_is_an_error_not_a_refusal(
        self,
    ) -> None:
        scene = self.make_scene()
        self.assertEqual(10, self.request(scene, self.commits["c6"]).code)
        rewritten = scene.remote.commit(
            {"ansible/playbooks/host.yml": playbook_text("rewritten")},
            "rewritten",
            self.commits["c2"],
            self.keys["a"],
        )
        scene.remote.set_ref("main", rewritten)
        shutil.rmtree(scene.state / "repo.git")
        result = self.request(scene, rewritten)
        self.assertEqual(40, result.code, result.summary + result.errors)
        self.assertTrue(result.has("reason=git-failed"))

    def test_a_signature_made_under_another_ssh_namespace_is_refused(self) -> None:
        play = {"ansible/playbooks/host.yml": playbook_text("namespace")}
        for namespace, expected in (("git", 0), ("file", 20)):
            with self.subTest(namespace):
                scene = self.make_scene()
                base = scene.remote.commit(play, "namespace", self.commits["tip"], None)
                resigned = scene.remote.resign_in_namespace(base, self.keys["a"], namespace)
                scene.remote.set_ref("main", resigned)
                result = self.request(scene, resigned, mode="check")
                # The control: under the namespace git uses, the same forged commit is accepted.
                if expected == 0:
                    self.assertIn(result.code, (0, 11), result.summary + result.errors)
                else:
                    self.assertEqual(20, result.code, result.summary + result.errors)
                    refused_as = ("reason=bad-signature", "reason=signer-not-allowed")
                    refused = any(result.has(reason) for reason in refused_as)
                    self.assertTrue(refused, result.summary)

    def test_the_program_ignores_a_module_planted_beside_it_or_on_the_python_path(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pt-isolated-")).resolve()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        beside, elsewhere, marks = root / "beside", root / "elsewhere", root / "marks"
        for directory in (beside, elsewhere, marks):
            directory.mkdir()
        program = beside / "pull_trigger.py"
        shutil.copy(PROGRAM, program)
        flags = program.read_text(encoding="utf-8").split("\n", 1)[0].split()[1:]
        # shutil, not fcntl: fcntl is built into some interpreters (Debian 13),
        # so a planted fcntl.py never loads there.
        planted = {beside / "json.py": marks / "beside", elsewhere / "shutil.py": marks / "path"}
        for module, mark in planted.items():
            module.write_text(f"open({str(mark)!r}, 'w').close()\n", encoding="utf-8")

        def start(arguments: list[str]) -> None:
            environment = {
                **os.environ,
                "PYTHONPATH": str(elsewhere),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            subprocess.run(  # noqa: S603 - the program under test, an argument list
                [sys.executable, *arguments, str(program), "--help"],
                cwd=root,
                env=environment,
                capture_output=True,
                check=False,
            )

        # The control: without the flags of the program's own first line, both modules load.
        start([])
        self.assertEqual(["beside", "path"], sorted(path.name for path in marks.iterdir()))
        for mark in marks.iterdir():
            mark.unlink()
        start(flags)
        self.assertEqual([], list(marks.iterdir()), "the first line must keep -I")

    def test_a_damaged_record_of_the_last_applied_commit_stops_the_run(self) -> None:
        scene = self.make_scene()
        self.assertEqual(10, self.request(scene, self.commits["c2"]).code)
        (scene.state / "last-applied").write_text("not a commit\n", encoding="utf-8")
        result = self.request(scene, self.commits["c6"])
        self.assertEqual(40, result.code)
        self.assertTrue(result.has("reason=state-unsafe"))

    def test_every_malformed_request_is_refused_before_the_host_is_touched(self) -> None:
        for name, value in HOSTILE_COMMITS.items():
            with self.subTest(name):
                scene = self.make_scene()
                result = self.request(scene, value)
                self.assert_refused(result, "bad-request")
                self.assertTrue(result.has("commit=-"))
                self.assert_no_new_run(scene)
                self.assertFalse((scene.state / "repo.git" / "HEAD").exists())
                if len(value.strip()) > 6:
                    self.assertNotIn(value.strip(), result.summary + result.errors)

    def test_two_arguments_and_a_missing_argument_are_refused_by_hand_as_well(self) -> None:
        scene = self.make_scene()
        out, errors = io.StringIO(), io.StringIO()
        for extra in ([self.commits["c6"], self.commits["c2"]], []):
            with self.subTest(extra), contextlib.redirect_stderr(errors):
                code = trigger.main(
                    ["--mode", "apply", "--config", str(scene.config_path), *extra],
                    {},
                    threading.Event(),
                    stdout=out,
                    caller=io.BytesIO(),
                )
                self.assertEqual(20, code)

    def test_a_trigger_that_arrives_while_another_runs_is_refused_and_does_not_run(self) -> None:
        scene = self.make_scene()
        scene.state.mkdir(mode=0o700)
        with trigger.single_flight(scene.state / "lock"):
            result = self.request(scene, self.commits["c6"])
        self.assertEqual(21, result.code, result.summary + result.errors)
        self.assertTrue(result.has("verdict=busy"))
        self.assert_no_new_run(scene)

    def test_a_failed_playbook_is_reported_as_failed_and_keeps_the_record_of_the_attempt(
        self,
    ) -> None:
        scene = self.make_scene()
        fake_ansible(scene.ansible.parent, code=2)
        result = self.request(scene, self.commits["c6"])
        self.assertEqual(30, result.code)
        self.assertTrue(result.has("reason=playbook-failed"))
        self.assertEqual(
            f"{self.commits['c6']}\n", (scene.state / "last-applied").read_text(encoding="utf-8")
        )

    def test_a_playbook_that_prints_no_recap_is_reported_as_failed(self) -> None:
        scene = self.make_scene()
        scene.ansible.write_text(f"#!{sys.executable}\nprint('no recap here')\n", encoding="utf-8")
        result = self.request(scene, self.commits["c6"])
        self.assertEqual(30, result.code)
        self.assertTrue(result.has("reason=no-recap"))

    def test_a_playbook_that_runs_too_long_is_stopped_and_reported(self) -> None:
        scene = self.make_scene(timeout_seconds=1)
        fake_ansible(scene.ansible.parent, sleep=30)
        result = self.request(scene, self.commits["c6"])
        self.assertEqual(31, result.code, result.summary + result.errors)
        self.assertTrue(result.has("verdict=timed-out"))
        with trigger.single_flight(scene.state / "lock"):
            pass

    def test_a_stop_request_ends_the_playbook_and_is_recorded_as_interrupted(self) -> None:
        scene = self.make_scene()
        fake_ansible(scene.ansible.parent, sleep=30)
        stop = threading.Event()
        timer = threading.Timer(1.5, stop.set)
        timer.start()
        self.addCleanup(timer.cancel)
        result = self.request(scene, self.commits["c6"], stop=stop)
        self.assertEqual(30, result.code, result.summary + result.errors)
        self.assertTrue(result.has("reason=interrupted"))

    def test_a_stop_that_arrives_before_the_playbook_starts_leaves_the_floor_alone(self) -> None:
        scene = self.make_scene()
        stop = threading.Event()
        stop.set()
        result = self.request(scene, self.commits["c6"], stop=stop)
        self.assertEqual(30, result.code, result.summary + result.errors)
        self.assertTrue(result.has("reason=interrupted"))
        self.assertFalse((scene.state / "last-applied").exists())
        self.assertFalse((scene.state / "current").exists())
        self.assertEqual([], self.calls(scene))

    def test_the_environment_git_runs_in_is_clean_whatever_the_caller_sets(self) -> None:
        scene = self.make_scene()
        hostile = {
            "GIT_DIR": "/nonexistent/EXAMPLE",
            "GIT_EXEC_PATH": "/nonexistent/EXAMPLE",
            "GIT_OBJECT_DIRECTORY": "/nonexistent/EXAMPLE",
            "GIT_SSH_COMMAND": "/nonexistent/EXAMPLE",
        }
        with mock_environment(hostile):
            result = self.request(scene, self.commits["c6"])
        self.assertEqual(10, result.code, result.summary + result.errors)

    def test_the_environment_built_for_git_holds_only_the_programs_own_variables(self) -> None:
        tools = trigger.Tools(
            git=GIT,
            gpg=Path(GPG or "/usr/bin/gpg"),
            gpgconf=Path(GPGCONF or "/usr/bin/gpgconf"),
            ssh_keygen=SSH_KEYGEN,
        )
        home = Path("/nonexistent/EXAMPLE-home")
        expected = {
            "PATH",
            "HOME",
            "LC_ALL",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_TERMINAL_PROMPT",
            "GIT_ALLOW_PROTOCOL",
        }
        hostile = {
            "GIT_DIR": "/nonexistent/EXAMPLE",
            "GIT_EXEC_PATH": "/nonexistent/EXAMPLE",
            "GIT_OBJECT_DIRECTORY": "/nonexistent/EXAMPLE",
            "GIT_SSH_COMMAND": "/nonexistent/EXAMPLE",
            "GIT_ASKPASS": "/nonexistent/EXAMPLE",
            "GNUPGHOME": "/nonexistent/EXAMPLE",
        }
        with mock_environment(hostile):
            environment = trigger.Git(tools, Path("/nonexistent/EXAMPLE.git"), home).environment
        # The program names every variable it passes: none comes from the caller's environment.
        self.assertEqual(expected, set(environment))
        self.assertEqual("/dev/null", environment["GIT_CONFIG_GLOBAL"])
        self.assertEqual("1", environment["GIT_CONFIG_NOSYSTEM"])
        self.assertEqual(str(home), environment["HOME"])
        self.assertEqual("0", environment["GIT_TERMINAL_PROMPT"])

    def test_a_missing_program_is_an_error_not_a_refusal(self) -> None:
        missing = Path("/nonexistent/ansible-playbook")
        scene = self.make_scene(ansible_playbook=str(missing))
        self.assertFalse(missing.exists())
        result = self.request(scene, self.commits["c6"])
        self.assertEqual(40, result.code)
        self.assertTrue(result.has("reason=tool-missing"))

    def test_an_unreachable_remote_is_an_error_and_leaves_the_host_alone(self) -> None:
        scene = self.make_scene()
        self.prime(scene)
        shutil.rmtree(scene.root / "remote.git")
        with self.no_change_to_the_host(scene):
            result = self.request(scene, self.commits["c6"])
        self.assertEqual(40, result.code, result.summary + result.errors)
        self.assertTrue(result.has("reason=git-failed"))

    def test_the_summary_and_the_log_never_carry_anything_the_caller_typed(self) -> None:
        scene = self.make_scene()
        hostile = "SECRET_TYPED_BY_CALLER\nverdict=applied exit=0"
        result = self.request(scene, hostile)
        log = (scene.logs / "pull-trigger.log").read_text(encoding="utf-8")
        self.assertNotIn("SECRET_TYPED_BY_CALLER", result.summary + result.errors + log)
        self.assertEqual(1, len(log.splitlines()))
        self.assertEqual(1, len(result.summary.splitlines()))

    def test_the_environment_of_the_program_is_not_printed(self) -> None:
        scene = self.make_scene()
        with mock_environment({"EXAMPLE_TOKEN": "SECRET_ENVIRONMENT_VALUE"}):
            result = self.request(scene, self.commits["c6"])
        log = (scene.logs / "pull-trigger.log").read_text(encoding="utf-8")
        self.assertNotIn(
            "SECRET_ENVIRONMENT_VALUE", result.summary + result.errors + result.relayed + log
        )

    def test_the_environment_passed_to_the_playbook_is_fixed(self) -> None:
        scene = self.make_scene()
        env_dump = scene.ansible.parent / "env.txt"
        scene.ansible.write_text(
            f"#!{sys.executable}\nimport os\n"
            f"open({str(env_dump)!r}, 'w').write('\\n'.join(sorted(os.environ)))\n"
            "print('PLAY RECAP')\nprint('localhost : ok=1 changed=0 unreachable=0 failed=0')\n",
            encoding="utf-8",
        )
        with mock_environment(
            {"EXAMPLE_TOKEN": "SECRET_ENVIRONMENT_VALUE", "GIT_DIR": "/nonexistent"}
        ):
            self.request(scene, self.commits["c6"])
        names = env_dump.read_text(encoding="utf-8").split("\n")
        self.assertNotIn("EXAMPLE_TOKEN", names)
        self.assertNotIn("GIT_DIR", names)
        self.assertNotIn("SSH_ORIGINAL_COMMAND", names)

    def test_old_run_output_is_pruned_to_the_configured_number(self) -> None:
        scene = self.make_scene(keep_runs=2)
        for _ in range(4):
            self.request(scene, self.commits["c6"], mode="check")
        self.assertEqual(2, len(list((scene.logs / "runs").iterdir())))

    def test_a_work_directory_left_by_a_dead_run_is_swept_on_the_next_run(self) -> None:
        scene = self.make_scene()
        self.request(scene, self.commits["c2"])
        stale = scene.state / "work" / "left-by-a-dead-run"
        stale.mkdir()
        (stale / "file").write_text("x", encoding="utf-8")
        self.request(scene, self.commits["c6"])
        self.assertFalse(stale.exists())

    def test_the_state_directory_must_be_private(self) -> None:
        scene = self.make_scene()
        scene.state.mkdir(mode=0o755)
        scene.state.chmod(0o755)
        result = self.request(scene, self.commits["c6"])
        self.assertEqual(40, result.code)
        self.assertTrue(result.has("reason=state-unsafe"))
        self.assert_no_new_run(scene)

    def test_an_unsafe_configuration_stops_the_program_before_anything_else(self) -> None:
        scene = self.make_scene()
        scene.config_path.chmod(0o666)
        result = self.request(scene, self.commits["c6"])
        self.assertEqual(40, result.code)
        self.assertTrue(result.has("reason=config-invalid"))
        self.assertFalse(scene.state.exists())

    def test_the_fetch_takes_main_only(self) -> None:
        scene = self.make_scene()
        self.request(scene, self.commits["c6"], mode="check")
        refs = run(
            [GIT, f"--git-dir={scene.state / 'repo.git'}", "for-each-ref", "--format=%(refname)"]
        )
        self.assertEqual("refs/pull-trigger/main", refs)

    # ------------------------------------------------------------------ step requests
    def step_scene(self, **changes: object) -> Scene:
        """Make a host whose allow-list holds the migrate step."""
        return self.make_scene(steps=[step_entry()], **changes)

    def step_request(
        self, scene: Scene, commit: str, step: str = "migrate", word: str = "MIGRATE-0001"
    ) -> Run:
        """Call the program as the step key's forced command would."""
        return self.request(scene, f"{commit} {step} {word}", mode="step")

    def step_calls(self, scene: Scene) -> list[str]:
        """Return the argument lines the stand-in recorded, without the working-directory lines."""
        return [line for line in self.calls(scene) if line.startswith("-i")]

    def test_a_step_request_runs_only_the_named_step_with_the_validated_id(self) -> None:
        scene = self.step_scene()
        result = self.step_request(scene, self.commits["c6"])
        self.assertEqual(10, result.code, result.summary + result.errors)
        checkout = (scene.state / "current").resolve()
        self.assertEqual(
            "-i localhost, --connection local --tags control_plane_db_migrate "
            f"-e control_plane_db_step=migrate {checkout}/ansible/playbooks/host.yml",
            self.step_calls(scene)[0],
        )
        self.assertTrue(result.has("verdict=applied"))
        self.assertTrue(result.has("mode=step"))
        self.assertTrue(result.has("step=migrate"))
        self.assertTrue(result.has(f"commit={self.commits['c6']}"))

    def test_the_summary_of_a_step_ends_with_the_step_and_the_line_of_an_apply_is_unchanged(
        self,
    ) -> None:
        scene = self.step_scene()
        step = self.step_request(scene, self.commits["c6"])
        self.assertTrue(step.summary.endswith("changed=1 step=migrate"), step.summary)
        plain = self.request(self.make_scene(), self.commits["c6"])
        self.assertTrue(plain.summary.endswith("changed=1"), plain.summary)
        self.assertNotIn("step=", plain.summary)
        check = self.request(self.make_scene(), self.commits["c6"], mode="check")
        self.assertNotIn("step=", check.summary)

    def test_a_plain_apply_and_a_check_pass_no_tag_and_no_variable(self) -> None:
        scene = self.step_scene()
        self.assertEqual(10, self.request(scene, self.commits["c6"]).code)
        self.assertEqual(11, self.request(scene, self.commits["tip"], mode="check").code)
        for line in self.step_calls(scene):
            self.assertNotIn("--tags", line)
            self.assertNotIn("-e ", line)
            self.assertNotIn("control_plane_db", line)

    def test_a_step_is_idempotent_and_the_second_request_reports_no_change(self) -> None:
        scene = self.step_scene()
        self.assertEqual(10, self.step_request(scene, self.commits["c6"]).code)
        scene.ansible.write_text(
            scene.ansible.read_text(encoding="utf-8").replace("changed=1", "changed=0"),
            encoding="utf-8",
        )
        second = self.step_request(scene, self.commits["c6"])
        self.assertEqual(0, second.code, second.summary + second.errors)
        self.assertTrue(second.has("verdict=unchanged"))
        self.assertTrue(second.has("step=migrate"))
        self.assertEqual(2, len(self.step_calls(scene)))

    def test_a_step_on_the_same_checks_as_an_apply_is_refused_for_the_same_reasons(self) -> None:
        for name, reason in (
            ("side", "not-on-main"),
            ("unsigned", "unsigned"),
            ("other_key", "signer-not-allowed"),
            ("tampered", "bad-signature"),
            ("no_playbook", "playbook-not-allowed"),
        ):
            with self.subTest(name):
                scene = self.step_scene()
                self.prime(scene)
                with self.no_change_to_the_host(scene):
                    result = self.step_request(scene, self.commits[name])
                self.assert_refused(result, reason)
                self.assert_no_new_run(scene)

    def test_a_step_that_is_not_on_the_allow_list_is_refused_and_an_empty_list_allows_none(
        self,
    ) -> None:
        cases = {
            "an empty list": self.make_scene(steps=[]),
            "no list at all": self.make_scene(),
            "another step on the list": self.step_scene(),
        }
        for name, scene in cases.items():
            with self.subTest(name):
                result = self.step_request(scene, self.commits["c6"], step="identity")
                self.assert_refused(result, "step-not-allowed")
                self.assertTrue(result.has("step=-"), result.summary)
                self.assert_no_new_run(scene)
                self.assertFalse((scene.state / "last-applied").exists())

    def test_a_wrong_confirmation_word_is_refused_and_names_the_step_from_the_list_only(
        self,
    ) -> None:
        scene = self.step_scene()
        result = self.step_request(scene, self.commits["c6"], word="MIGRATE-0002")
        self.assert_refused(result, "confirm-mismatch")
        self.assertTrue(result.has("step=migrate"))
        self.assertNotIn("MIGRATE-0002", result.summary + result.errors)
        self.assertNotIn("MIGRATE-0001", result.summary + result.errors)
        self.assert_no_new_run(scene)
        self.assertFalse((scene.state / "last-applied").exists())

    def test_the_word_of_one_step_does_not_confirm_another(self) -> None:
        steps = [
            step_entry(),
            step_entry(id="identity", tag="control_plane_db_identity", word="IDENTITY-0002"),
        ]
        scene = self.make_scene(steps=steps)
        wrong = self.step_request(scene, self.commits["c6"], step="identity", word="MIGRATE-0001")
        self.assert_refused(wrong, "confirm-mismatch")
        right = self.step_request(scene, self.commits["c6"], step="identity", word="IDENTITY-0002")
        self.assertEqual(10, right.code, right.summary + right.errors)
        self.assertIn("--tags control_plane_db_identity", self.step_calls(scene)[0])

    def test_a_step_refusal_comes_before_the_lock_the_fetch_and_the_floor(self) -> None:
        scene = self.step_scene(remote_url="file:///nonexistent/EXAMPLE.git")
        for step, word in (("identity", "MIGRATE-0001"), ("migrate", "WRONG-WORD")):
            with self.subTest(step=step, word=word):
                result = self.step_request(scene, self.commits["c6"], step, word)
                self.assertEqual(20, result.code, result.summary + result.errors)
                self.assertFalse((scene.state / "repo.git" / "HEAD").exists())
        with trigger.single_flight(scene.state / "lock"):
            busy = self.step_request(scene, self.commits["c6"], step="identity")
            self.assert_refused(busy, "step-not-allowed")
            held = self.step_request(scene, self.commits["c6"])
            self.assertEqual(21, held.code, held.summary + held.errors)

    def test_a_check_request_that_carries_a_step_is_refused_and_plans_nothing(self) -> None:
        scene = self.step_scene()
        self.prime(scene)
        with self.no_change_to_the_host(scene):
            result = self.request(scene, f"{self.commits['c6']} migrate MIGRATE-0001", mode="check")
        self.assert_refused(result, "step-mode-only")
        self.assertTrue(result.has("mode=check"))
        self.assertFalse(result.has("step=migrate"))
        self.assert_no_new_run(scene)

    def test_an_apply_request_that_carries_a_step_is_refused_and_runs_nothing(self) -> None:
        scene = self.step_scene()
        self.prime(scene)
        with self.no_change_to_the_host(scene):
            result = self.request(scene, f"{self.commits['c6']} migrate MIGRATE-0001", mode="apply")
        self.assert_refused(result, "step-mode-only")
        self.assert_no_new_run(scene)
        self.assertEqual(
            f"{self.commits['c2']}\n", (scene.state / "last-applied").read_text(encoding="utf-8")
        )

    def test_a_bare_commit_with_the_step_mode_is_refused_not_run_as_an_apply(self) -> None:
        scene = self.step_scene()
        result = self.request(scene, self.commits["c6"], mode="step")
        self.assert_refused(result, "bad-request")
        self.assert_no_new_run(scene)
        self.assertFalse((scene.state / "last-applied").exists())

    def test_a_malformed_step_request_is_refused_before_the_host_is_touched(self) -> None:
        commit = self.commits["c6"]
        for name, text in {
            "a trailing token": f"{commit} migrate MIGRATE-0001 extra",
            "a newline in the word": f"{commit} migrate MIGRATE\n0001",
            "an uppercase step id": f"{commit} MIGRATE MIGRATE-0001",
            "a lowercase word": f"{commit} migrate migrate-0001",
        }.items():
            with self.subTest(name):
                scene = self.step_scene()
                result = self.request(scene, text, mode="step")
                self.assert_refused(result, "bad-request")
                self.assert_no_new_run(scene)
                self.assertFalse((scene.state / "repo.git" / "HEAD").exists())

    def test_a_step_on_a_commit_older_than_the_floor_is_refused_as_a_rollback(self) -> None:
        scene = self.step_scene()
        self.assertEqual(10, self.request(scene, self.commits["c6"]).code)
        scene.calls_before = len(self.calls(scene))
        with self.no_change_to_the_host(scene):
            result = self.step_request(scene, self.commits["c2"])
        self.assert_refused(result, "rollback")
        self.assert_no_new_run(scene)

    def test_a_started_step_raises_the_floor_as_an_apply_does_and_a_failed_one_retries(
        self,
    ) -> None:
        scene = self.step_scene()
        fake_ansible(scene.ansible.parent, code=2)
        failed = self.step_request(scene, self.commits["c6"])
        self.assertEqual(30, failed.code, failed.summary + failed.errors)
        self.assertTrue(failed.has("reason=playbook-failed"))
        self.assertTrue(failed.has("step=migrate"))
        self.assertEqual(
            f"{self.commits['c6']}\n", (scene.state / "last-applied").read_text(encoding="utf-8")
        )
        fake_ansible(scene.ansible.parent)
        retried = self.step_request(scene, self.commits["c6"])
        self.assertEqual(10, retried.code, retried.summary + retried.errors)

    def test_after_a_step_a_plain_apply_of_an_older_commit_is_refused_as_a_rollback(self) -> None:
        scene = self.step_scene()
        self.assertEqual(10, self.step_request(scene, self.commits["tip"]).code)
        refused = self.request(scene, self.commits["c6"])
        self.assert_refused(refused, "rollback")

    def test_what_the_caller_typed_in_a_step_request_never_reaches_the_summary_or_the_log(
        self,
    ) -> None:
        scene = self.step_scene()
        typed = "typedstepname"
        word = "TYPED-WORD-9"
        refused = self.step_request(scene, self.commits["c6"], step=typed, word=word)
        wrong = self.step_request(scene, self.commits["c6"], word=word)
        malformed = self.request(scene, f"{self.commits['c6']} {typed} {word}\nextra", mode="step")
        log = (scene.logs / "pull-trigger.log").read_text(encoding="utf-8")
        for result in (refused, wrong, malformed):
            self.assertNotIn(typed, result.summary + result.errors)
            self.assertNotIn(word, result.summary + result.errors)
        self.assertNotIn(typed, log)
        self.assertNotIn(word, log)
        self.assertEqual(3, len(log.splitlines()))

    def test_the_log_line_of_a_step_names_the_step_and_the_run_output_is_kept(self) -> None:
        scene = self.step_scene()
        self.step_request(scene, self.commits["c6"])
        log = (scene.logs / "pull-trigger.log").read_text(encoding="utf-8")
        self.assertIn("mode=step", log)
        self.assertIn(" step=migrate started=", log)
        self.assertEqual(1, len(list((scene.logs / "runs").glob("*-step-*.log"))))

    def test_a_configuration_naming_a_step_the_program_cannot_run_stops_every_request(self) -> None:
        for name in ("break_glass", "anything"):
            with self.subTest(name):
                scene = self.make_scene(steps=[step_entry(id=name, tag="control_plane_db_other")])
                for text, mode in (
                    (self.commits["c6"], "apply"),
                    (self.commits["c6"], "check"),
                    (f"{self.commits['c6']} migrate MIGRATE-0001", "step"),
                ):
                    result = self.request(scene, text, mode=mode)
                    self.assertEqual(40, result.code, result.summary + result.errors)
                    self.assertTrue(result.has("reason=config-invalid"))
                self.assert_no_new_run(scene)


@contextlib.contextmanager
def mock_environment(values: Mapping[str, str]) -> Iterator[None]:
    """Set environment variables for the duration of a block."""
    saved = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


class SummaryTests(unittest.TestCase):
    """The words the caller reads."""

    def test_the_exit_codes_are_the_documented_ones(self) -> None:
        self.assertEqual(
            {
                "unchanged": 0,
                "applied": 10,
                "would-change": 11,
                "refused": 20,
                "busy": 21,
                "failed": 30,
                "timed-out": 31,
                "error": 40,
            },
            {name: int(code) for code, name in trigger.VERDICT_NAMES.items()},
        )

    def test_every_error_class_carries_a_distinct_named_reason(self) -> None:
        classes = [
            trigger.BadRequestError,
            trigger.BusyError,
            trigger.NotOnMainError,
            trigger.RollbackError,
            trigger.UnsignedError,
            trigger.BadSignatureError,
            trigger.SignerNotAllowedError,
            trigger.PlaybookNotAllowedError,
            trigger.ConfigError,
            trigger.StateError,
            trigger.ToolMissingError,
            trigger.GitError,
        ]
        reasons = [item.reason for item in classes]
        self.assertEqual(len(reasons), len(set(reasons)))
        for item in classes:
            self.assertTrue(
                all(ch in string.ascii_lowercase + "-" for ch in item.reason), item.reason
            )

    def test_a_refusal_exits_twenty_and_a_busy_host_twenty_one(self) -> None:
        self.assertEqual(trigger.Exit.REFUSED, trigger.RefusedError.exit_code)
        self.assertEqual(trigger.Exit.BUSY, trigger.BusyError.exit_code)
        self.assertEqual(trigger.Exit.ERROR, trigger.GitError.exit_code)

    def test_the_summary_line_is_one_line_of_words_the_program_made(self) -> None:
        verdict = trigger.Verdict(trigger.Exit.APPLIED, "ok", 3)
        line = trigger.summary(verdict, "apply", "a" * 40, "ansible/playbooks/host.yml")
        self.assertEqual(
            "pull-trigger verdict=applied exit=10 reason=ok mode=apply "
            f"commit={'a' * 40} playbook=ansible/playbooks/host.yml changed=3",
            line,
        )

    def test_timestamps_are_written_in_utc(self) -> None:
        self.assertEqual(
            "2026-10-19T12:00:05Z", trigger.stamp(datetime(2026, 10, 19, 12, 0, 5, tzinfo=UTC))
        )


if __name__ == "__main__":
    unittest.main()
