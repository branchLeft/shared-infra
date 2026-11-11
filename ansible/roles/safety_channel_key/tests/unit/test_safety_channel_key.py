"""Unit tests for safety_channel_key, the module that makes the safety service's signing key.

The key is a throwaway made by each test in a temporary directory. No value here is a real
key, and the real key is never read. The sabotage control is test_existing_key_is_never_overwritten:
break the guard that leaves an existing key alone and it goes red.
The README gives the command, with the files and library directories on PYTHONPATH.
"""

import base64
import contextlib
import dataclasses
import grp
import hashlib
import io
import logging
import os
import pwd
import stat
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import cast
from unittest import mock

import safety_channel_key as scheme
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]

# RFC 8032 section 7.1, tests 1 to 3: the seed and the public key it must give.
RFC_VECTORS = (
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    ),
)

# Throwaway seeds, made by the test. Placeholders: nothing here was ever a real key.
SEED = bytes(range(32))
OTHER_SEED = bytes(range(100, 132))
TEMP_NAME = ".channel-signing.key.tmp-0123456789abcdef"


def seed_text(seed: bytes) -> bytes:
    """Return the text a key file holds for a seed."""
    return base64.b64encode(seed)


def pieces_of(seed: bytes) -> list[str]:
    """Return every spelling of a seed a leak could take: base64 text, hex and its halves."""
    text = seed_text(seed).decode("ascii")
    return [text, text[:-1], seed.hex(), seed.hex()[:32], seed.decode("latin-1")]


def public_by_library(seed: bytes) -> bytes:
    """Return the public half the pinned cryptography package derives: the independent oracle."""
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def account_names() -> tuple[str, str]:
    """Return the names of the account and group this test runs as."""
    return pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name


class DerivationTests(unittest.TestCase):
    """The hand-written RFC 8032 derivation, against the RFC and against a library."""

    def test_rfc_8032_vectors(self) -> None:
        for seed_hex, public_hex in RFC_VECTORS:
            with self.subTest(seed=public_hex[:8]):
                self.assertEqual(scheme.derive_public(bytes.fromhex(seed_hex)).hex(), public_hex)

    def test_two_hundred_seeds_agree_with_the_pinned_library(self) -> None:
        for counter in range(200):
            seed = hashlib.sha256(b"safety-channel-key-test" + counter.to_bytes(4, "big")).digest()
            self.assertEqual(scheme.derive_public(seed), public_by_library(seed), counter)

    def test_the_edge_seeds_agree_with_the_library(self) -> None:
        for seed in (bytes(32), b"\xff" * 32, b"\x01" + bytes(31), bytes(31) + b"\x80"):
            self.assertEqual(scheme.derive_public(seed), public_by_library(seed))

    def test_decode_accepts_only_the_canonical_text_of_32_bytes(self) -> None:
        self.assertEqual(scheme.decode_seed(seed_text(SEED)), SEED)
        for bad in (
            b"",
            seed_text(SEED) + b"\n",
            b" " + seed_text(SEED),
            seed_text(SEED[:31]),
            seed_text(SEED + b"x"),
            seed_text(SEED)[:-1] + b"!",
            seed_text(SEED).decode("ascii").replace("=", "").encode("ascii"),
            self.non_canonical(SEED),
        ):
            with self.subTest(length=len(bad)):
                self.assertIsNone(scheme.decode_seed(bad))

    @staticmethod
    def non_canonical(seed: bytes) -> bytes:
        """Return 44 characters that decode to the seed's length but are not its canonical text.

        Raises:
            AssertionError: when the construction does not decode to the same bytes.
        """
        text = seed_text(seed)
        alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        # The last character before the padding carries 4 bits of data and 2 bits that must
        # be zero. Setting one of the two decodes to the same bytes, which is not canonical.
        value = alphabet.index(text[42])
        changed = text[:42] + bytes([alphabet[value + 1]]) + text[43:]
        if base64.b64decode(changed) != seed:
            raise AssertionError
        return changed


class HostCase(unittest.TestCase):
    """A temporary parent that stands for /etc/branchleft, and a settings object for it."""

    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name)
        self.parent = self.root / "branchleft"
        self.parent.mkdir()
        self.parent.chmod(0o755)
        self.directory = self.parent / "content-safety"
        self.key = self.directory / scheme.KEY_NAME
        self.pub = self.directory / scheme.PUB_NAME
        self.settings = scheme.Settings(str(self.directory), os.getuid(), os.getgid())
        self.chowned: list[tuple[int, int, int]] = []
        self.seams = scheme.Seams(
            root_uid=os.getuid(),
            chown=self.record_chown,
            random_bytes=lambda count: SEED[:count],
        )

    def record_chown(self, fd: int, uid: int, gid: int) -> None:
        """Remember which file was chowned, by inode, and do it when it is a no-op."""
        self.chowned.append((os.fstat(fd).st_ino, uid, gid))
        if (uid, gid) == (os.getuid(), os.getgid()):
            os.fchown(fd, uid, gid)

    def run_module(
        self, *, check_mode: bool = False, seams: scheme.Seams | None = None
    ) -> scheme.Result:
        """Converge with the test's settings."""
        return scheme.converge(
            self.settings, check_mode=check_mode, seams=seams if seams is not None else self.seams
        )

    def make_directory(self, mode: int = 0o700) -> None:
        """Make the key directory as it would be after a first run."""
        self.directory.mkdir()
        self.directory.chmod(mode)

    def plant(self, path: Path, data: bytes, mode: int = 0o400) -> None:
        """Put a file there, as an earlier run or a person would have."""
        if not self.directory.exists():
            self.make_directory()
        path.unlink(missing_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def plant_key(self, seed: bytes = SEED, mode: int = 0o400) -> None:
        """Put a valid key there."""
        self.plant(self.key, seed_text(seed), mode)

    def snapshot(self) -> dict[str, tuple[int, int, bytes | None]]:
        """Return every entry of the directory with its mode, inode and (for files) bytes."""
        shot: dict[str, tuple[int, int, bytes | None]] = {}
        for entry in sorted(self.directory.iterdir()):
            info = entry.lstat()
            body = entry.read_bytes() if stat.S_ISREG(info.st_mode) else None
            shot[entry.name] = (stat.S_IMODE(info.st_mode), info.st_ino, body)
        return shot

    def assert_refused(self, code: str, path: Path) -> scheme.RefusalError:
        """Require a refusal that is the code and the path and nothing else, and no change."""
        before = self.snapshot() if self.directory.exists() else None
        with self.assertRaises(scheme.RefusalError) as caught:
            self.run_module()
        self.assertEqual(str(caught.exception), f"{code}: {path}")
        if before is not None:
            self.assertEqual(self.snapshot(), before)
        return caught.exception

    def assert_no_seed_in(self, text: str, seed: bytes = SEED) -> None:
        """Require that no spelling of the seed is in the text."""
        for piece in pieces_of(seed):
            self.assertNotIn(piece, text)


class CreateTests(HostCase):
    """The key is made when it is absent, in the shape the service reads."""

    def test_generated_when_absent(self) -> None:
        result = self.run_module()
        self.assertTrue(result.created)
        self.assertTrue(result.changed)
        self.assertFalse(result.adopted)
        self.assertTrue(result.public_changed)
        self.assertEqual(self.key.read_bytes(), seed_text(SEED))
        self.assertEqual(len(self.key.read_bytes()), 44)
        self.assertEqual(len(base64.b64decode(self.key.read_bytes())), 32)
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.pub.stat().st_mode), 0o444)
        self.assertEqual(self.key.stat().st_uid, self.settings.uid)
        self.assertEqual(self.key.stat().st_gid, self.settings.gid)
        self.assertEqual(
            sorted(path.name for path in self.directory.iterdir()),
            sorted(
                [
                    scheme.KEY_NAME,
                    scheme.PUB_NAME,
                ]
            ),
        )

    def test_the_public_half_is_written_and_returned(self) -> None:
        result = self.run_module()
        expected = base64.b64encode(public_by_library(SEED)).decode("ascii")
        self.assertEqual(result.public_key, expected)
        self.assertEqual(self.pub.read_text(encoding="ascii"), expected + "\n")

    def test_the_owner_is_set_through_the_seam_on_the_key_and_the_directory(self) -> None:
        self.run_module()
        owners = {(uid, gid) for _, uid, gid in self.chowned}
        self.assertEqual(owners, {(self.settings.uid, self.settings.gid)})
        # The directory, the key's temporary file and the public file's temporary file.
        self.assertGreaterEqual(len(self.chowned), 3)

    def test_the_second_run_changes_nothing(self) -> None:
        first = self.run_module()
        before = self.snapshot()
        second = self.run_module()
        self.assertFalse(second.changed)
        self.assertFalse(second.created)
        self.assertFalse(second.adopted)
        self.assertFalse(second.public_changed)
        self.assertEqual(second.temp_cleaned, 0)
        self.assertEqual(second.public_key, first.public_key)
        self.assertEqual(self.snapshot(), before)

    def test_a_new_directory_is_made_not_adopted(self) -> None:
        result = self.run_module()
        self.assertTrue(result.directory_created)
        self.assertFalse(result.adopted)

    def test_existing_key_is_never_overwritten(self) -> None:
        """The sabotage control: an existing key is byte-identical after every run."""
        self.plant_key(OTHER_SEED)
        before = self.snapshot()[scheme.KEY_NAME]

        asked: list[int] = []

        def new_seed(count: int) -> bytes:
            """Offer a different seed, and note that a new one was wanted at all."""
            asked.append(count)
            return SEED[:count]

        seams = dataclasses.replace(self.seams, random_bytes=new_seed)
        for _ in range(3):
            result = self.run_module(seams=seams)
            self.assertFalse(result.created)
            self.assertEqual(self.snapshot()[scheme.KEY_NAME], before)
        self.assertEqual(self.key.read_bytes(), seed_text(OTHER_SEED))
        self.assertEqual(asked, [])
        # The public half is the existing key's, not a new key's.
        self.assertEqual(
            self.pub.read_text(encoding="ascii").strip(),
            base64.b64encode(public_by_library(OTHER_SEED)).decode("ascii"),
        )

    def test_an_existing_key_survives_a_lost_race_to_publish(self) -> None:
        """Another writer publishes between our look and our link: its key stands."""

        def publish_other_key() -> None:
            self.key.write_bytes(seed_text(OTHER_SEED))
            self.key.chmod(0o400)

        seams = dataclasses.replace(self.seams, before_link=publish_other_key)
        result = self.run_module(seams=seams)
        self.assertFalse(result.created)
        self.assertEqual(self.key.read_bytes(), seed_text(OTHER_SEED))
        self.assertEqual(
            result.public_key, base64.b64encode(public_by_library(OTHER_SEED)).decode("ascii")
        )
        self.assertEqual(
            sorted(path.name for path in self.directory.iterdir()),
            sorted([scheme.KEY_NAME, scheme.PUB_NAME]),
        )

    def test_an_interrupted_create_leaves_no_key_and_the_next_run_cleans_up(self) -> None:
        def crash() -> None:
            raise KeyboardInterrupt

        crashing = dataclasses.replace(self.seams, after_temp_write=crash)
        with self.assertRaises(KeyboardInterrupt):
            self.run_module(seams=crashing)
        self.assertFalse(self.key.exists())
        orphans = [path.name for path in self.directory.iterdir()]
        self.assertEqual(len(orphans), 1)
        self.assertTrue(scheme.TEMP_NAME.fullmatch(orphans[0]))
        result = self.run_module()
        self.assertEqual(result.temp_cleaned, 1)
        self.assertTrue(result.created)
        self.assertEqual(self.key.read_bytes(), seed_text(SEED))
        self.assertEqual(
            sorted(path.name for path in self.directory.iterdir()),
            sorted([scheme.KEY_NAME, scheme.PUB_NAME]),
        )

    def test_a_leftover_temp_file_is_cleaned_and_reported(self) -> None:
        self.run_module()
        self.plant(self.directory / TEMP_NAME, b"left behind")
        result = self.run_module()
        self.assertEqual(result.temp_cleaned, 1)
        self.assertTrue(result.changed)
        self.assertFalse((self.directory / TEMP_NAME).exists())
        self.assertFalse(self.run_module().changed)

    def test_a_planted_temp_symlink_is_refused(self) -> None:
        self.run_module()
        target = self.root / "elsewhere"
        target.write_bytes(b"x")
        (self.directory / TEMP_NAME).symlink_to(target)
        self.assert_refused(scheme.E_TEMP, self.directory / TEMP_NAME)
        self.assertEqual(target.read_bytes(), b"x")


class AdoptTests(HostCase):
    """A valid key with another owner or a narrower mode is adopted, its bytes untouched."""

    def test_a_different_owner_is_adopted_and_the_bytes_are_unchanged(self) -> None:
        self.plant_key(OTHER_SEED)
        inode = self.key.stat().st_ino
        before = self.key.read_bytes()
        other = dataclasses.replace(self.settings, uid=os.getuid() + 1)
        result = scheme.converge(other, check_mode=False, seams=self.seams)
        self.assertTrue(result.adopted)
        self.assertTrue(result.changed)
        self.assertFalse(result.created)
        self.assertIn((inode, os.getuid() + 1, os.getgid()), self.chowned)
        self.assertEqual(self.key.read_bytes(), before)
        self.assertEqual(self.key.stat().st_ino, inode)

    def test_a_narrower_mode_is_adopted_once(self) -> None:
        self.plant_key(OTHER_SEED, mode=0o600)
        inode = self.key.stat().st_ino
        first = self.run_module()
        self.assertTrue(first.adopted)
        self.assertTrue(first.changed)
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o400)
        self.assertEqual(self.key.read_bytes(), seed_text(OTHER_SEED))
        self.assertEqual(self.key.stat().st_ino, inode)
        second = self.run_module()
        self.assertFalse(second.changed)
        self.assertFalse(second.adopted)

    def test_a_directory_with_another_mode_is_adopted(self) -> None:
        self.plant_key()
        self.directory.chmod(0o755)
        result = self.run_module()
        self.assertTrue(result.adopted)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(self.key.read_bytes(), seed_text(SEED))

    def test_a_wider_mode_is_refused_not_adopted(self) -> None:
        for mode in (0o640, 0o604, 0o644, 0o660, 0o666):
            with self.subTest(mode=oct(mode)):
                self.plant_key(mode=mode)
                self.assert_refused(scheme.E_KEY_MODE, self.key)
                self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), mode)
                self.key.unlink()


class RefusalTests(HostCase):
    """Each way the key's place can be wrong is a refusal naming the path and nothing else."""

    def test_a_symlink_in_the_keys_place(self) -> None:
        target = self.root / "real-key"
        target.write_bytes(seed_text(SEED))
        target.chmod(0o400)
        self.make_directory()
        self.key.symlink_to(target)
        self.assert_refused(scheme.E_KEY_OPEN, self.key)
        self.assertEqual(target.read_bytes(), seed_text(SEED))

    def test_a_directory_in_the_keys_place(self) -> None:
        self.make_directory()
        self.key.mkdir()
        self.assert_refused(scheme.E_KEY_TYPE, self.key)

    def test_a_pipe_in_the_keys_place_does_not_hang(self) -> None:
        self.make_directory()
        os.mkfifo(self.key, 0o400)
        self.assert_refused(scheme.E_KEY_TYPE, self.key)

    def test_a_hard_linked_key(self) -> None:
        self.plant_key()
        os.link(self.key, self.root / "another-name")
        self.assert_refused(scheme.E_KEY_LINKS, self.key)

    def test_a_key_that_is_too_big_is_not_read(self) -> None:
        self.plant(self.key, b"A" * 65)
        self.assert_refused(scheme.E_KEY_SIZE, self.key)

    def test_a_key_of_the_wrong_length(self) -> None:
        for name, seed in (("short", SEED[:31]), ("long", SEED + b"x")):
            with self.subTest(name):
                self.plant(self.key, seed_text(seed))
                error = self.assert_refused(scheme.E_KEY_FORM, self.key)
                self.assert_no_seed_in(str(error), seed)
                self.key.unlink()

    def test_text_that_is_not_base64_or_not_canonical_or_has_whitespace(self) -> None:
        cases = {
            "bad character": seed_text(SEED)[:-1] + b"!",
            "trailing newline": seed_text(SEED) + b"\n",
            "leading space": b" " + seed_text(SEED)[:-1],
            "inner space": seed_text(SEED)[:10] + b" " + seed_text(SEED)[11:],
            "not canonical": DerivationTests.non_canonical(SEED),
            "unpadded": seed_text(SEED)[:-1],
            "empty": b"",
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.plant(self.key, data)
                error = self.assert_refused(scheme.E_KEY_FORM, self.key)
                self.assert_no_seed_in(str(error))
                self.key.unlink()

    def test_a_group_or_other_readable_key_is_refused_before_it_is_read(self) -> None:
        for mode in (0o440, 0o404, 0o640):
            with self.subTest(mode=oct(mode)):
                # The content is not even valid, so a refusal for the mode proves the order.
                self.plant(self.key, b"not a key", mode)
                self.assert_refused(scheme.E_KEY_MODE, self.key)
                self.key.unlink()

    def test_a_parent_not_owned_by_root(self) -> None:
        seams = dataclasses.replace(self.seams, root_uid=os.getuid() + 1)
        with self.assertRaises(scheme.RefusalError) as caught:
            self.run_module(seams=seams)
        self.assertEqual(str(caught.exception), f"{scheme.E_PARENT}: {self.parent}")
        self.assertFalse(self.directory.exists())

    def test_a_parent_writable_by_group_or_others(self) -> None:
        for mode in (0o775, 0o757, 0o777):
            with self.subTest(mode=oct(mode)):
                self.parent.chmod(mode)
                with self.assertRaises(scheme.RefusalError) as caught:
                    self.run_module()
                self.assertEqual(str(caught.exception), f"{scheme.E_PARENT}: {self.parent}")
                self.assertFalse(self.directory.exists())

    def test_a_missing_parent_and_a_parent_that_is_a_link(self) -> None:
        self.parent.rmdir()
        with self.assertRaises(scheme.RefusalError):
            self.run_module()
        real = self.root / "real-parent"
        real.mkdir()
        self.parent.symlink_to(real)
        with self.assertRaises(scheme.RefusalError) as caught:
            self.run_module()
        self.assertEqual(str(caught.exception), f"{scheme.E_PARENT}: {self.parent}")
        self.assertEqual(list(real.iterdir()), [])

    def test_a_directory_that_is_a_link_or_a_file(self) -> None:
        real = self.root / "real-directory"
        real.mkdir()
        self.directory.symlink_to(real)
        with self.assertRaises(scheme.RefusalError) as caught:
            self.run_module()
        self.assertEqual(str(caught.exception), f"{scheme.E_DIR}: {self.directory}")
        self.assertEqual(list(real.iterdir()), [])
        self.directory.unlink()
        self.directory.write_bytes(b"a file")
        with self.assertRaises(scheme.RefusalError) as caught:
            self.run_module()
        self.assertEqual(str(caught.exception), f"{scheme.E_DIR}: {self.directory}")

    def test_a_directory_holding_a_foreign_file_is_refused_and_not_adopted(self) -> None:
        self.plant_key()
        self.directory.chmod(0o755)
        self.plant(self.directory / "notes.txt", b"foreign", 0o644)
        before = self.snapshot()
        with self.assertRaises(scheme.RefusalError) as caught:
            self.run_module()
        self.assertEqual(
            str(caught.exception), f"{scheme.E_FOREIGN}: {self.directory / 'notes.txt'}"
        )
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o755)


class PublicFileTests(HostCase):
    """The public file is non-secret: rewritten when missing or different, and reported once."""

    def test_a_missing_public_file_is_written_once(self) -> None:
        self.plant_key()
        first = self.run_module()
        self.assertTrue(first.public_changed)
        self.assertTrue(first.changed)
        self.assertFalse(first.created)
        self.assertFalse(self.run_module().changed)

    def test_a_different_public_file_is_rewritten_once(self) -> None:
        self.run_module()
        self.pub.chmod(0o644)
        self.pub.write_text("EXAMPLE_WRONG\n", encoding="ascii")
        self.pub.chmod(0o444)
        first = self.run_module()
        self.assertTrue(first.public_changed)
        self.assertEqual(
            self.pub.read_text(encoding="ascii"),
            base64.b64encode(public_by_library(SEED)).decode("ascii") + "\n",
        )
        self.assertFalse(self.run_module().changed)

    def test_a_public_file_with_the_wrong_mode_is_rewritten(self) -> None:
        self.run_module()
        self.pub.chmod(0o600)
        self.assertTrue(self.run_module().public_changed)
        self.assertEqual(stat.S_IMODE(self.pub.stat().st_mode), 0o444)

    def test_a_link_in_the_public_files_place_is_replaced_not_followed(self) -> None:
        self.run_module()
        target = self.root / "elsewhere"
        target.write_bytes(b"unrelated")
        self.pub.unlink()
        self.pub.symlink_to(target)
        self.assertTrue(self.run_module().public_changed)
        self.assertFalse(self.pub.is_symlink())
        self.assertEqual(target.read_bytes(), b"unrelated")

    def test_a_directory_in_the_public_files_place_is_refused(self) -> None:
        self.run_module()
        self.pub.unlink()
        self.pub.mkdir()
        self.assert_refused(scheme.E_PUB, self.pub)


class CheckModeTests(HostCase):
    """Check mode computes the plan and writes nothing."""

    def test_a_fresh_host_would_create(self) -> None:
        result = self.run_module(check_mode=True)
        self.assertTrue(result.changed)
        self.assertTrue(result.created)
        self.assertIsNone(result.public_key)
        self.assertFalse(self.directory.exists())

    def test_an_existing_directory_without_a_key_would_create_and_writes_nothing(self) -> None:
        self.make_directory()
        result = self.run_module(check_mode=True)
        self.assertTrue(result.created)
        self.assertIsNone(result.public_key)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_a_configured_host_shows_no_change(self) -> None:
        self.run_module()
        before = self.snapshot()
        result = self.run_module(check_mode=True)
        self.assertFalse(result.changed)
        self.assertIsNotNone(result.public_key)
        self.assertEqual(self.snapshot(), before)

    def test_adopt_clean_up_and_public_rewrite_are_planned_and_not_done(self) -> None:
        self.plant_key(mode=0o600)
        self.plant(self.directory / TEMP_NAME, b"left behind")
        before = self.snapshot()
        result = self.run_module(check_mode=True)
        self.assertTrue(result.adopted)
        self.assertTrue(result.public_changed)
        self.assertEqual(result.temp_cleaned, 1)
        self.assertFalse(result.created)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.chowned, [])


@dataclasses.dataclass
class Outcome:
    """What main() told the stand-in for the Ansible module: how it ended, and with what."""

    how: str = ""
    kwargs: dict[str, object] = dataclasses.field(default_factory=dict)


class NoLeakTests(HostCase):
    """The seed is in the key file and nowhere else: not a return, a refusal, a print or a log."""

    def run_capturing(self, run: Callable[[], object]) -> str:
        """Run something and return everything it printed or logged, as one text."""
        out, err = io.StringIO(), io.StringIO()
        handler_stream = io.StringIO()
        handler = logging.StreamHandler(handler_stream)
        root = logging.getLogger()
        root.addHandler(handler)
        previous = root.level
        root.setLevel(logging.DEBUG)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                run()
        finally:
            root.removeHandler(handler)
            root.setLevel(previous)
        return out.getvalue() + err.getvalue() + handler_stream.getvalue()

    def test_a_create_returns_prints_and_logs_no_part_of_the_seed(self) -> None:
        results: list[scheme.Result] = []
        printed = self.run_capturing(lambda: results.append(self.run_module()))
        self.assert_no_seed_in(printed)
        self.assert_no_seed_in(repr(results[0]))
        self.assert_no_seed_in(repr(dataclasses.asdict(results[0])))
        self.assertEqual(self.key.read_bytes(), seed_text(SEED))

    def test_an_existing_key_returns_no_part_of_the_seed(self) -> None:
        self.plant_key(OTHER_SEED)
        results: list[scheme.Result] = []
        printed = self.run_capturing(lambda: results.append(self.run_module()))
        self.assert_no_seed_in(printed + repr(results[0]), OTHER_SEED)

    def test_the_public_files_and_the_directory_listing_hold_no_part_of_the_seed(self) -> None:
        self.run_module()
        self.assert_no_seed_in(self.pub.read_text(encoding="ascii"))
        self.assert_no_seed_in(" ".join(path.name for path in self.directory.iterdir()))

    def test_a_check_mode_run_returns_no_part_of_the_seed(self) -> None:
        self.plant_key(OTHER_SEED, mode=0o600)
        result = self.run_module(check_mode=True)
        self.assert_no_seed_in(repr(result), OTHER_SEED)

    def test_the_entry_point_returns_only_the_documented_keys(self) -> None:
        name, group = account_names()
        self.plant_key(OTHER_SEED)
        outcome = self.call_main(name, group)
        self.assertEqual(outcome.how, "exit")
        self.assertEqual(
            sorted(outcome.kwargs),
            ["adopted", "changed", "created", "public_changed", "public_key", "temp_cleaned"],
        )
        self.assert_no_seed_in(repr(outcome), OTHER_SEED)
        self.assertEqual(
            outcome.kwargs["public_key"],
            base64.b64encode(public_by_library(OTHER_SEED)).decode("ascii"),
        )

    def test_the_entry_point_refuses_with_the_code_and_path_only(self) -> None:
        name, group = account_names()
        self.plant(self.key, seed_text(OTHER_SEED) + b"\n")
        outcome = self.call_main(name, group)
        self.assertEqual(outcome.how, "fail")
        self.assertEqual(outcome.kwargs, {"msg": f"{scheme.E_KEY_FORM}: {self.key}"})

    def test_an_unexpected_error_is_named_by_its_type_and_not_its_message(self) -> None:
        name, group = account_names()
        self.plant_key(OTHER_SEED)
        text = seed_text(OTHER_SEED).decode("ascii")
        with mock.patch.object(scheme, "converge", side_effect=ValueError(text)):
            outcome = self.call_main(name, group)
        self.assertEqual(outcome.kwargs, {"msg": f"{scheme.E_INTERNAL}: ValueError"})

    def test_an_os_error_is_named_by_its_errno_only(self) -> None:
        name, group = account_names()
        with mock.patch.object(scheme, "converge", side_effect=PermissionError(13, "denied /x")):
            outcome = self.call_main(name, group)
        self.assertEqual(outcome.kwargs, {"msg": f"{scheme.E_IO}: EACCES"})

    def call_main(self, owner: str, group: str) -> "Outcome":
        """Run main() with a stand-in for the Ansible module and return what it was told."""
        seen = Outcome()
        test = self

        class Finished(Exception):  # noqa: N818 - stops main() where Ansible would exit
            """Raised by the stand-in's exit and fail, as the real ones end the process."""

        class FakeModule:
            """Takes the parameters the role passes, and records the one call main() makes."""

            check_mode = False

            def __init__(self, **_: object) -> None:
                self.params = {
                    "directory": str(test.directory),
                    "owner": owner,
                    "group": group,
                }

            def exit_json(self, **kwargs: object) -> None:
                seen.how, seen.kwargs = "exit", dict(kwargs)
                raise Finished

            def fail_json(self, **kwargs: object) -> None:
                seen.how, seen.kwargs = "fail", dict(kwargs)
                raise Finished

        real_converge = scheme.converge

        def converge_here(settings: scheme.Settings, *, check_mode: bool) -> scheme.Result:
            return real_converge(settings, check_mode=check_mode, seams=test.seams)

        with (
            mock.patch.object(scheme, "AnsibleModule", FakeModule),
            mock.patch.object(scheme, "converge", converge_here),
            contextlib.suppress(Finished),
        ):
            scheme.main()
        return seen


class ArgumentTests(unittest.TestCase):
    """The module checks its own arguments before it touches anything."""

    def test_accepted(self) -> None:
        name, group = account_names()
        settings = scheme.settings_from_params("/etc/branchleft/content-safety", name, group)
        self.assertEqual((settings.uid, settings.gid), (os.getuid(), os.getgid()))

    def test_refused(self) -> None:
        name, group = account_names()
        directory = "/etc/branchleft/content-safety"
        cases = {
            "relative": (("content-safety", name, group), scheme.E_ARGS),
            "dot dot": (("/etc/branchleft/../x", name, group), scheme.E_ARGS),
            "trailing slash": ((directory + "/", name, group), scheme.E_ARGS),
            "root": (("/", name, group), scheme.E_ARGS),
            "upper case owner": ((directory, "Root", group), scheme.E_ARGS),
            "owner with a space": ((directory, "a b", group), scheme.E_ARGS),
            "owner with a newline": ((directory, name + "\n", group), scheme.E_ARGS),
            "group too long": ((directory, name, "g" * 33), scheme.E_ARGS),
            "no such owner": ((directory, "no-such-account-here", group), scheme.E_OWNER),
            "no such group": ((directory, name, "no-such-group-here"), scheme.E_OWNER),
        }
        for label, (args, code) in cases.items():
            with self.subTest(label), self.assertRaises(scheme.RefusalError) as caught:
                scheme.settings_from_params(*args)
            self.assertEqual(caught.exception.code, code)


class PinTests(unittest.TestCase):
    """The role's constants equal the module's, and the role has no way to read the key."""

    @staticmethod
    def load(relative: str) -> dict[str, object]:
        """Read a YAML file of the role."""
        return cast(dict[str, object], YAML(typ="safe").load(ROLE / relative))

    def test_vars_equal_the_modules_constants(self) -> None:
        values = self.load("vars/main.yml")
        self.assertEqual(values["safety_channel_key_key_name"], scheme.KEY_NAME)
        self.assertEqual(values["safety_channel_key_pub_name"], scheme.PUB_NAME)
        self.assertEqual(
            values["safety_channel_key_directory_mode"], format(scheme.DIR_MODE, "04o")
        )
        self.assertEqual(values["safety_channel_key_key_mode"], format(scheme.KEY_MODE, "04o"))
        self.assertEqual(values["safety_channel_key_pub_mode"], format(scheme.PUB_MODE, "04o"))
        self.assertEqual(values["safety_channel_key_directory"], "/etc/branchleft/content-safety")

    def test_defaults_and_spec_agree(self) -> None:
        defaults = self.load("defaults/main.yml")
        spec = cast(
            dict[str, dict[str, dict[str, dict[str, dict[str, object]]]]],
            self.load("meta/argument_specs.yml"),
        )
        options = spec["argument_specs"]["main"]["options"]
        self.assertEqual(sorted(defaults), sorted(options))
        for name, value in defaults.items():
            self.assertEqual(options[name]["default"], value)

    def test_the_module_task_is_hidden_and_the_role_has_no_route_to_the_key(self) -> None:
        text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        tasks = cast(list[dict[str, object]], YAML(typ="safe").load(text))
        module_task = tasks[0]
        self.assertIn("safety_channel_key", module_task)
        self.assertIs(module_task["no_log"], True)
        self.assertIs(module_task["diff"], False)
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        for word in (
            "lookup",
            "query",
            "pipe",
            "slurp",
            "stat:",
            "ansible.builtin.stat",
            "shell",
            "script",
            "command",
        ):
            self.assertNotIn(word, code)
        self.assertEqual(sorted(path.name for path in (ROLE / "tasks").iterdir()), ["main.yml"])


if __name__ == "__main__":
    unittest.main()
