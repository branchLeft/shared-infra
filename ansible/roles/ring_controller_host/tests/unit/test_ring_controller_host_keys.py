"""Unit tests for ring_controller_host_keys, the module that makes the controller's two keys.

Every key here is a throwaway made by the real `ssh-keygen` in a temporary directory, so the
tests hold the module to the tool that will sign and verify with the keys. The sabotage control
for the one-time rule is test_existing_key_is_never_overwritten: remove the guard that leaves an
existing private key alone and it goes red. The control for the file mode is
test_a_new_key_is_mode_0600_owner_only_and_alone: set the mode constant wider and it goes red.
The README gives the command, with the files and library directories on PYTHONPATH.
"""

import base64
import contextlib
import grp
import hashlib
import os
import pwd
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import cast
from unittest import mock

import ring_controller_host_keys as keys
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
SSH_KEYGEN = "/usr/bin/ssh-keygen"
LEDGER = keys.LEDGER_NAME
PUSH = keys.PUSH_NAME
# A text no real key has. A fake ssh-keygen writes it into the private file and says it on
# standard error; no output of the module may ever hold it.
CANARY = "PRIVATE-BODY-CANARY-7f3a91c2e5d04b68"


def seams() -> keys.Seams:
    """Seams that trust the account the test runs as, because the test cannot be root."""
    return keys.Seams(trusted_uids=frozenset((0, os.getuid())))


def settings(directory: Path, binary: str = SSH_KEYGEN) -> keys.Settings:
    """Settings for a directory, owned by the account the test runs as."""
    return keys.Settings(str(directory), os.getuid(), os.getgid(), binary)


@contextlib.contextmanager
def parent_dir() -> Iterator[Path]:
    """Yield a parent directory that passes the module's parent check, then remove it."""
    with tempfile.TemporaryDirectory() as raw:
        parent = Path(raw) / "parent"
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)
        yield parent


def run_converge(
    directory: Path, *, check_mode: bool = False, binary: str = SSH_KEYGEN
) -> keys.Result:
    """Converge the directory with the real ssh-keygen and the test's seams."""
    return keys.converge(settings(directory, binary), check_mode=check_mode, seams=seams())


def refusal_code(directory: Path, *, binary: str = SSH_KEYGEN) -> str:
    """Return the code of the refusal a converge raises, failing the test if it raises none.

    Raises:
        AssertionError: when the converge raises no refusal.
    """
    try:
        run_converge(directory, binary=binary)
    except keys.RefusalError as refusal:
        return refusal.code
    message = "no refusal was raised"
    raise AssertionError(message)


def snapshot(directory: Path) -> dict[str, tuple[bytes, int, int, int]]:
    """Return each file's bytes, inode, mtime and mode, to show a run changed nothing."""
    found: dict[str, tuple[bytes, int, int, int]] = {}
    for entry in sorted(directory.iterdir()):
        info = entry.lstat()
        found[entry.name] = (entry.read_bytes(), info.st_ino, info.st_mtime_ns, info.st_mode)
    return found


def oracle_fingerprint(public_file: Path) -> str:
    """Return the fingerprint ssh-keygen itself prints for a public file: the independent oracle."""
    done = subprocess.run(  # noqa: S603 - fixed argv, a throwaway file
        [SSH_KEYGEN, "-l", "-f", str(public_file)], capture_output=True, text=True, check=True
    )
    return done.stdout.split()[1]


def write_fake_keygen(parent: Path, body: str) -> str:
    """Write a stand-in ssh-keygen script and return its path. The body is a shell script."""
    script = parent / "fake-ssh-keygen"
    script.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    script.chmod(0o755)
    return str(script)


class CreationTests(unittest.TestCase):
    """The first run makes both pairs, with the owner, mode and fingerprint the controller needs."""

    def test_a_new_key_is_mode_0600_owner_only_and_alone(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            result = run_converge(directory)
            self.assertTrue(result.changed)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            for name in (LEDGER, PUSH):
                with self.subTest(name=name):
                    info = (directory / name).stat()
                    self.assertTrue(stat.S_ISREG(info.st_mode))
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                    self.assertEqual(info.st_uid, os.getuid())
                    self.assertEqual(info.st_nlink, 1)
                    pub = (directory / (name + ".pub")).stat()
                    self.assertEqual(stat.S_IMODE(pub.st_mode), 0o644)
            self.assertEqual(
                sorted(p.name for p in directory.iterdir()),
                [LEDGER, LEDGER + ".pub", PUSH, PUSH + ".pub"],
            )

    def test_the_mode_constants_are_what_the_plan_says(self) -> None:
        self.assertEqual((keys.DIR_MODE, keys.KEY_MODE, keys.PUB_MODE), (0o700, 0o600, 0o644))

    def test_the_public_lines_and_fingerprints_are_the_ones_ssh_keygen_gives(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            result = run_converge(directory)
            for name in (LEDGER, PUSH):
                with self.subTest(name=name):
                    outcome = result.outcomes[name]
                    pub_file = directory / (name + ".pub")
                    self.assertEqual(
                        (pub_file.read_text(encoding="ascii")).rstrip("\n"), outcome.public
                    )
                    self.assertEqual(outcome.fingerprint, oracle_fingerprint(pub_file))
                    self.assertTrue((outcome.public or "").startswith("ssh-ed25519 "))
            self.assertNotEqual(
                result.outcomes[LEDGER].fingerprint, result.outcomes[PUSH].fingerprint
            )

    def test_the_public_half_is_the_one_derived_from_the_private_half(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            result = run_converge(directory)
            done = subprocess.run(  # noqa: S603 - fixed argv, a throwaway file
                [SSH_KEYGEN, "-y", "-f", str(directory / LEDGER)],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(
                done.stdout.split()[1], (result.outcomes[LEDGER].public or "").split()[1]
            )

    def test_the_comments_name_the_use_of_each_key(self) -> None:
        with parent_dir() as parent:
            result = run_converge(parent / "keys")
            self.assertTrue((result.outcomes[LEDGER].public or "").endswith(keys.LEDGER_COMMENT))
            self.assertTrue((result.outcomes[PUSH].public or "").endswith(keys.PUSH_COMMENT))

    def test_the_fingerprint_helper_matches_the_openssh_form(self) -> None:
        blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + bytes(36)).decode("ascii")
        digest = hashlib.sha256(base64.b64decode(blob)).digest()
        expected = "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
        self.assertEqual(keys.fingerprint(blob), expected)
        self.assertNotIn("=", keys.fingerprint(blob))


class OneTimeTests(unittest.TestCase):
    """A second run changes nothing: the key is made once and never again."""

    def test_existing_key_is_never_overwritten(self) -> None:
        # The sabotage control: delete the `entry is None` guard in _converge_key (make it
        # always create) and the bytes, inode or fingerprint below differ and this goes red.
        with parent_dir() as parent:
            directory = parent / "keys"
            first = run_converge(directory)
            before = snapshot(directory)
            second = run_converge(directory)
            self.assertFalse(second.changed)
            self.assertEqual(snapshot(directory), before)
            for name in (LEDGER, PUSH):
                self.assertEqual(
                    second.outcomes[name].fingerprint, first.outcomes[name].fingerprint
                )
                self.assertFalse(second.outcomes[name].created)

    def test_a_missing_public_file_is_rewritten_and_the_private_key_is_not_touched(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            run_converge(directory)
            private_before = (directory / LEDGER).read_bytes()
            inode_before = (directory / LEDGER).stat().st_ino
            (directory / (LEDGER + ".pub")).unlink()
            result = run_converge(directory)
            self.assertEqual(result.outcomes[LEDGER].public_changed, True)
            self.assertFalse(result.outcomes[LEDGER].created)
            self.assertEqual((directory / LEDGER).read_bytes(), private_before)
            self.assertEqual((directory / LEDGER).stat().st_ino, inode_before)
            self.assertTrue((directory / (LEDGER + ".pub")).exists())

    def test_a_public_file_with_no_private_key_is_refused_and_nothing_is_written(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            run_converge(directory)
            (directory / PUSH).unlink()
            before = snapshot(directory)
            self.assertEqual(refusal_code(directory), keys.E_KEY_LOST)
            self.assertEqual(snapshot(directory), before)

    def test_one_refused_pair_leaves_the_other_untouched_even_when_it_is_absent(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            directory.mkdir(mode=0o700)
            (directory / (PUSH + ".pub")).write_text("ssh-ed25519 AAAA x\n", encoding="ascii")
            self.assertEqual(refusal_code(directory), keys.E_KEY_LOST)
            self.assertFalse((directory / LEDGER).exists())

    def test_a_lost_race_keeps_the_other_writers_key(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            other = parent / "other"
            run_converge(other)
            planted = (other / LEDGER).read_bytes()
            calls: list[int] = []

            def plant() -> None:
                # Runs once, right before the first link: another writer publishes first.
                if not calls:
                    calls.append(1)
                    (directory / LEDGER).write_bytes(planted)
                    (directory / LEDGER).chmod(0o600)

            hooked = seams()
            hooked.before_link = plant
            result = keys.converge(settings(directory), check_mode=False, seams=hooked)
            self.assertEqual((directory / LEDGER).read_bytes(), planted)
            self.assertFalse(result.outcomes[LEDGER].created)
            self.assertFalse(any(p.name.startswith(".") for p in directory.iterdir()))

    def test_an_interrupted_run_leaves_temporary_files_that_the_next_run_removes(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            run_converge(directory)
            stale = [
                directory / ".ledger-signing.tmp-0123456789abcdef",
                directory / ".ledger-signing.tmp-0123456789abcdef.pub",
            ]
            for item in stale:
                item.write_text("x", encoding="ascii")
            result = run_converge(directory)
            self.assertEqual(result.temp_cleaned, 2)
            self.assertFalse(any(item.exists() for item in stale))


class AdoptAndRefuseTests(unittest.TestCase):
    """An existing key is accepted only as the module would have made it."""

    def made(self, parent: Path) -> Path:
        directory = parent / "keys"
        run_converge(directory)
        return directory

    def test_a_group_or_other_readable_key_is_refused_and_not_corrected(self) -> None:
        for mode in (0o640, 0o604, 0o644, 0o660):
            with self.subTest(mode=oct(mode)), parent_dir() as parent:
                directory = self.made(parent)
                (directory / LEDGER).chmod(mode)
                self.assertEqual(refusal_code(directory), keys.E_KEY_MODE)
                self.assertEqual(stat.S_IMODE((directory / LEDGER).stat().st_mode), mode)

    def test_a_narrower_mode_is_adopted_and_the_bytes_are_never_touched(self) -> None:
        with parent_dir() as parent:
            directory = self.made(parent)
            (directory / LEDGER).chmod(0o400)
            before = (directory / LEDGER).read_bytes()
            result = run_converge(directory)
            self.assertTrue(result.outcomes[LEDGER].adopted)
            self.assertEqual(stat.S_IMODE((directory / LEDGER).stat().st_mode), 0o600)
            self.assertEqual((directory / LEDGER).read_bytes(), before)

    def test_a_widened_directory_is_closed_again(self) -> None:
        with parent_dir() as parent:
            directory = self.made(parent)
            directory.chmod(0o755)
            result = run_converge(directory)
            self.assertTrue(result.directory_adopted)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    def test_a_key_that_is_not_ed25519_is_refused(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            directory.mkdir(mode=0o700)
            subprocess.run(  # noqa: S603 - fixed argv, a throwaway file
                [SSH_KEYGEN, "-q", "-t", "ecdsa", "-N", "", "-f", str(directory / LEDGER)],
                check=True,
            )
            (directory / (LEDGER + ".pub")).unlink()
            self.assertEqual(refusal_code(directory), keys.E_KEY_FORM)

    def test_a_key_with_a_passphrase_is_refused_and_does_not_hang(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            directory.mkdir(mode=0o700)
            subprocess.run(  # noqa: S603 - fixed argv, a throwaway file
                [SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "pw", "-f", str(directory / LEDGER)],
                check=True,
            )
            (directory / (LEDGER + ".pub")).unlink()
            self.assertEqual(refusal_code(directory), keys.E_KEY_FORM)

    def test_text_that_is_not_a_key_is_refused(self) -> None:
        with parent_dir() as parent:
            directory = self.made(parent)
            (directory / LEDGER).write_text("not a key\n", encoding="ascii")
            self.assertEqual(refusal_code(directory), keys.E_KEY_FORM)

    def test_a_link_a_second_hard_link_a_directory_and_a_big_file_are_refused(self) -> None:
        with parent_dir() as parent:
            directory = self.made(parent)
            os.link(directory / LEDGER, parent / "elsewhere")
            self.assertEqual(refusal_code(directory), keys.E_KEY_LINKS)
        with parent_dir() as parent:
            directory = self.made(parent)
            (directory / LEDGER).unlink()
            (directory / (LEDGER + ".pub")).unlink()
            (directory / LEDGER).symlink_to(directory / PUSH)
            self.assertEqual(refusal_code(directory), keys.E_KEY_OPEN)
        with parent_dir() as parent:
            directory = self.made(parent)
            (directory / LEDGER).unlink()
            (directory / LEDGER).mkdir()
            self.assertEqual(refusal_code(directory), keys.E_KEY_TYPE)
        with parent_dir() as parent:
            directory = self.made(parent)
            (directory / LEDGER).write_bytes(b"x" * (keys.MAX_KEY_FILE_BYTES + 1))
            (directory / LEDGER).chmod(0o600)
            self.assertEqual(refusal_code(directory), keys.E_KEY_SIZE)

    def test_a_foreign_file_in_the_directory_is_refused(self) -> None:
        with parent_dir() as parent:
            directory = self.made(parent)
            (directory / "notes").write_text("x", encoding="ascii")
            self.assertEqual(refusal_code(directory), keys.E_FOREIGN)

    def test_a_temporary_name_that_is_not_a_file_is_refused(self) -> None:
        with parent_dir() as parent:
            directory = self.made(parent)
            (directory / ".push.tmp-0123456789abcdef").mkdir()
            self.assertEqual(refusal_code(directory), keys.E_TEMP)

    def test_a_link_in_place_of_the_directory_is_refused(self) -> None:
        with parent_dir() as parent:
            real = parent / "real"
            real.mkdir(mode=0o700)
            (parent / "keys").symlink_to(real)
            self.assertEqual(refusal_code(parent / "keys"), keys.E_DIR)

    def test_a_parent_that_others_can_write_is_refused(self) -> None:
        with parent_dir() as parent:
            parent.chmod(0o775)
            self.assertEqual(refusal_code(parent / "keys"), keys.E_PARENT)

    def test_a_missing_parent_is_refused(self) -> None:
        with parent_dir() as parent:
            self.assertEqual(refusal_code(parent / "missing" / "keys"), keys.E_PARENT)

    def test_the_ssh_keygen_binary_must_be_root_owned_regular_and_closed(self) -> None:
        with parent_dir() as parent:
            self.assertEqual(
                refusal_code(parent / "keys", binary=str(parent / "absent")), keys.E_KEYGEN_BIN
            )
            wide = write_fake_keygen(parent, "exit 0\n")
            Path(wide).chmod(0o777)
            self.assertEqual(refusal_code(parent / "keys", binary=wide), keys.E_KEYGEN_BIN)
            link = parent / "link"
            link.symlink_to(SSH_KEYGEN)
            self.assertEqual(refusal_code(parent / "keys", binary=str(link)), keys.E_KEYGEN_BIN)
            # Owned by an account the module does not trust: neither root nor the test's own.
            untrusted = keys.Seams(trusted_uids=frozenset((os.getuid() + 1,)))
            good = write_fake_keygen(parent, "exit 0\n")
            with self.assertRaises(keys.RefusalError) as caught:
                keys.check_binary(settings(parent / "keys", good), untrusted)
            self.assertEqual(caught.exception.code, keys.E_KEYGEN_BIN)

    def test_arguments_are_checked(self) -> None:
        for directory in ("relative", "/", "/a/../b", ""):
            with self.subTest(directory=directory), self.assertRaises(keys.RefusalError) as caught:
                keys.settings_from_params(directory, "root", "root", SSH_KEYGEN)
            self.assertEqual(caught.exception.code, keys.E_ARGS)
        for owner in ("Root", "1bad", "a b", ""):
            with self.subTest(owner=owner), self.assertRaises(keys.RefusalError) as caught:
                keys.settings_from_params("/a/b", owner, "root", SSH_KEYGEN)
            self.assertEqual(caught.exception.code, keys.E_ARGS)
        with self.assertRaises(keys.RefusalError) as caught:
            keys.settings_from_params("/a/b", "no_such_account_here", "root", SSH_KEYGEN)
        self.assertEqual(caught.exception.code, keys.E_OWNER)
        with self.assertRaises(keys.RefusalError) as caught:
            keys.settings_from_params("/a/b", "root", "root", "ssh-keygen")
        self.assertEqual(caught.exception.code, keys.E_ARGS)


class CheckModeTests(unittest.TestCase):
    """Check mode computes the plan and writes nothing."""

    def test_a_fresh_host_would_make_the_directory_and_both_pairs_and_makes_nothing(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            result = run_converge(directory, check_mode=True)
            self.assertTrue(result.changed)
            self.assertFalse(directory.exists())
            self.assertTrue(all(o.created for o in result.outcomes.values()))
            self.assertTrue(all(o.public is None for o in result.outcomes.values()))

    def test_a_configured_host_shows_no_change_and_the_same_public_halves(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            made = run_converge(directory)
            before = snapshot(directory)
            planned = run_converge(directory, check_mode=True)
            self.assertFalse(planned.changed)
            self.assertEqual(snapshot(directory), before)
            for name in (LEDGER, PUSH):
                self.assertEqual(planned.outcomes[name].public, made.outcomes[name].public)

    def test_check_mode_on_a_missing_key_in_an_existing_directory_makes_nothing(self) -> None:
        with parent_dir() as parent:
            directory = parent / "keys"
            directory.mkdir(mode=0o700)
            result = run_converge(directory, check_mode=True)
            self.assertTrue(result.outcomes[LEDGER].created)
            self.assertEqual(list(directory.iterdir()), [])


class NoPrivateBytesTests(unittest.TestCase):
    """No private byte reaches a return value, a message or an exception."""

    def fake_that_leaks_everywhere(self, parent: Path) -> str:
        """A stand-in ssh-keygen that puts a canary in every place it could be seen from."""
        return write_fake_keygen(
            parent,
            f"""
echo {CANARY} >&2
case "$1" in
  -y) echo "{CANARY}" >&2; echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== x"; exit 0 ;;
esac
for last; do :; done
printf '%s\\n' "{CANARY}" > "$last"
printf '%s\\n' "{CANARY}" > "$last.pub"
echo {CANARY}
exit 0
""",
        )

    def test_the_fake_does_leak_when_it_is_read_which_shows_the_scan_can_find_it(self) -> None:
        # The control: the canary is really in the private file, so a scan of the module's
        # output for it is a scan that could find it.
        with parent_dir() as parent:
            fake = self.fake_that_leaks_everywhere(parent)
            directory = parent / "keys"
            run_converge(directory, binary=fake)
            leaked = [
                p.name for p in directory.iterdir() if CANARY in p.read_text(errors="replace")
            ]
            self.assertEqual(sorted(leaked), [LEDGER, PUSH])

    def test_a_refusal_and_a_result_hold_no_canary(self) -> None:
        with parent_dir() as parent:
            fake = self.fake_that_leaks_everywhere(parent)
            directory = parent / "keys"
            try:
                result = run_converge(directory, binary=fake)
            except keys.RefusalError as refusal:
                self.assertNotIn(CANARY, str(refusal))
                self.assertNotIn(CANARY, repr(refusal.args))
            else:
                self.assertNotIn(CANARY, repr(result))

    def test_a_failing_keygen_is_a_fixed_code_with_no_canary(self) -> None:
        with parent_dir() as parent:
            fake = write_fake_keygen(parent, f"echo {CANARY} >&2\necho {CANARY}\nexit 1\n")
            with self.assertRaises(keys.RefusalError) as caught:
                run_converge(parent / "keys", binary=fake)
            self.assertEqual(caught.exception.code, keys.E_KEYGEN)
            self.assertNotIn(CANARY, str(caught.exception))
            self.assertNotIn(CANARY, repr(caught.exception.__cause__))

    def test_the_module_entry_point_returns_no_canary_on_success_or_failure(self) -> None:
        class Stub:
            """Stands in for AnsibleModule and keeps what the module returns."""

            check_mode = False

            def __init__(self, params: dict[str, str]) -> None:
                self.params = params
                self.kept: dict[str, object] = {}

            def exit_json(self, **kwargs: object) -> None:
                self.kept = {"exit": True, **kwargs}

            def fail_json(self, **kwargs: object) -> None:
                self.kept = {"fail": True, **kwargs}

        with parent_dir() as parent:
            fake = self.fake_that_leaks_everywhere(parent)
            for directory in (parent / "keys", parent / "missing" / "keys"):
                stub = Stub(
                    {
                        "directory": str(directory),
                        "owner": pwd.getpwuid(os.getuid()).pw_name,
                        "group": grp.getgrgid(os.getgid()).gr_name,
                        "ssh_keygen": fake,
                    }
                )
                with (
                    mock.patch.object(keys, "AnsibleModule", return_value=stub),
                    mock.patch.object(keys, "Seams", seams),
                ):
                    keys.main()
                self.assertNotIn(CANARY, repr(stub.kept))
                self.assertTrue(stub.kept)

    def test_ssh_keygen_runs_with_an_empty_environment_and_no_shell(self) -> None:
        with parent_dir() as parent:
            seen = parent / "env-seen"
            fake = write_fake_keygen(
                parent,
                f"""
env > {seen}
case "$1" in
  -y) echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== x"; exit 0 ;;
esac
exit 1
""",
            )
            with (
                mock.patch.dict(
                    os.environ, {"ANTHROPIC_API_KEY": "x", "SSH_ASKPASS": "y", "FOO_API_KEY": "z"}
                ),
                contextlib.suppress(keys.RefusalError),
            ):
                run_converge(parent / "keys", binary=fake)
            names = {line.split("=", 1)[0] for line in seen.read_text().splitlines() if "=" in line}
            self.assertNotIn("ANTHROPIC_API_KEY", names)
            self.assertNotIn("SSH_ASKPASS", names)
            self.assertNotIn("FOO_API_KEY", names)
            self.assertIn("LC_ALL", names)

    def test_ssh_keygen_is_called_by_argv_with_no_shell_and_no_terminal(self) -> None:
        recorded: list[dict[str, object]] = []

        def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            recorded.append({"argv": argv, **kwargs})
            return subprocess.CompletedProcess(argv, 1, b"", b"")

        with parent_dir() as parent, mock.patch.object(subprocess, "run", fake_run):
            with contextlib.suppress(keys.RefusalError):
                run_converge(parent / "keys")
        self.assertTrue(recorded)
        for call in recorded:
            self.assertIsInstance(call["argv"], list)
            self.assertNotIn("shell", call)
            self.assertIs(call["stderr"], subprocess.DEVNULL)
            self.assertIs(call["stdin"], subprocess.DEVNULL)
            self.assertEqual(call["start_new_session"], True)
            self.assertEqual(call["env"], {"LC_ALL": "C"})
            self.assertIn("timeout", call)
        generated = [c for c in recorded if "-t" in cast("list[str]", c["argv"])]
        for call in generated:
            argv = cast("list[str]", call["argv"])
            self.assertEqual(argv[argv.index("-N") + 1], "")


class RoleAgreementTests(unittest.TestCase):
    """The role's constants and the module's are one set of facts."""

    def vars(self) -> dict[str, object]:
        loaded = YAML(typ="safe").load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))
        return cast("dict[str, object]", loaded)

    def test_the_vars_hold_the_modules_names_and_modes(self) -> None:
        held = self.vars()
        self.assertEqual(held["ring_controller_host_ledger_key_name"], keys.LEDGER_NAME)
        self.assertEqual(held["ring_controller_host_push_key_name"], keys.PUSH_NAME)
        self.assertEqual(held["ring_controller_host_keys_directory_mode"], f"{keys.DIR_MODE:04o}")
        self.assertEqual(held["ring_controller_host_key_mode"], f"{keys.KEY_MODE:04o}")
        self.assertEqual(held["ring_controller_host_public_mode"], f"{keys.PUB_MODE:04o}")


if __name__ == "__main__":
    unittest.main()
