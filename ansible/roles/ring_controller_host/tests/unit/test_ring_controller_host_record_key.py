"""Unit tests for ring_controller_host_record_key, the module that makes the record-signing key.

The key is a throwaway made by each test in a temporary directory. No value here is a real key,
and the real key is never read. The sabotage controls, each red when its guard is removed:
test_existing_key_is_never_overwritten (the guard that leaves an existing key alone),
test_a_new_key_is_root_only_0400_in_a_0700_directory and
test_the_key_is_never_wider_than_0400_at_any_moment (the creation mode), and
test_a_key_another_account_owns_is_refused_before_it_is_read (the root-only rule).
The README gives the command, with the library directory on PYTHONPATH.
"""

import base64
import contextlib
import dataclasses
import hashlib
import io
import logging
import os
import stat
import tempfile
import unittest
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import cast
from unittest import mock

import ring_controller_host_record_key as scheme
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
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
TEMP_NAME = ".record-signing.key.tmp-0123456789abcdef"


def pem_of(seed: bytes) -> bytes:
    """Return the PKCS8 PEM the pinned library writes for a seed: the independent oracle."""
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def public_pem_by_library(seed: bytes) -> str:
    """Return the SPKI PEM the pinned library writes for a seed's public half."""
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def pieces_of(seed: bytes) -> list[str]:
    """Return every spelling of a seed a leak could take: the PEM body, its halves, base64, hex."""
    body = pem_of(seed).decode("ascii").splitlines()[1]
    return [
        body,
        body[:32],
        body[20:50],
        base64.b64encode(seed).decode("ascii"),
        seed.hex(),
        seed.hex()[:32],
        seed.decode("latin-1"),
    ]


class DerivationTests(unittest.TestCase):
    """The hand-written RFC 8032 derivation and the two PEM forms, against the RFC and a library."""

    def test_rfc_8032_vectors(self) -> None:
        for seed_hex, public_hex in RFC_VECTORS:
            with self.subTest(seed=public_hex[:8]):
                self.assertEqual(scheme.derive_public(bytes.fromhex(seed_hex)).hex(), public_hex)

    def test_two_hundred_seeds_give_the_libraries_pem_forms(self) -> None:
        for counter in range(200):
            seed = hashlib.sha256(
                b"ring-controller-record-key" + counter.to_bytes(4, "big")
            ).digest()
            with self.subTest(counter=counter):
                self.assertEqual(scheme.private_pem(seed), pem_of(seed))
                self.assertEqual(
                    scheme.public_pem(scheme.derive_public(seed)), public_pem_by_library(seed)
                )

    def test_the_edge_seeds_agree_with_the_library(self) -> None:
        for seed in (bytes(32), b"\xff" * 32, b"\x01" + bytes(31), bytes(31) + b"\x80"):
            self.assertEqual(scheme.private_pem(seed), pem_of(seed))
            self.assertEqual(
                scheme.public_pem(scheme.derive_public(seed)), public_pem_by_library(seed)
            )

    def test_the_library_reads_the_modules_private_pem_as_the_same_key(self) -> None:
        """The reader the controller uses (PKCS8) accepts the text, and finds the same pair."""
        loaded = load_pem_private_key(scheme.private_pem(SEED), password=None)
        self.assertIsInstance(loaded, Ed25519PrivateKey)
        public = cast(Ed25519PrivateKey, loaded).public_key()
        self.assertEqual(
            public.public_bytes(Encoding.Raw, PublicFormat.Raw), scheme.derive_public(SEED)
        )

    def test_decode_accepts_only_the_canonical_pem_of_one_ed25519_seed(self) -> None:
        self.assertEqual(scheme.decode_seed(scheme.private_pem(SEED)), SEED)
        good = scheme.private_pem(SEED)
        bad = {
            "empty": b"",
            "no newline at the end": good[:-1],
            "extra newline": good + b"\n",
            "crlf": good.replace(b"\n", b"\r\n"),
            "wrong header": good.replace(b"PRIVATE", b"PUBLIC", 1),
            "openssh form": b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + good[28:],
            "two lines": good[:30] + b"\n" + good[30:],
            "short seed": scheme.private_pem(SEED[:31]),
            "long seed": scheme.private_pem(SEED + b"x"),
            "another algorithm": self.other_algorithm(),
            "not base64": good[:40] + b"!" + good[41:],
        }
        for label, data in bad.items():
            with self.subTest(label):
                self.assertIsNone(scheme.decode_seed(data))

    @staticmethod
    def other_algorithm() -> bytes:
        """Return a PEM of the right length whose algorithm identifier is not Ed25519."""
        der = bytearray(scheme.PKCS8_PREFIX + SEED)
        der[11] ^= 0x01
        return scheme.PRIVATE_HEADER + base64.b64encode(bytes(der)) + scheme.PRIVATE_FOOTER


class HostCase(unittest.TestCase):
    """A temporary parent that stands for the config directory, and settings for it."""

    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name)
        self.parent = self.root / "ring-controller"
        self.parent.mkdir()
        self.parent.chmod(0o755)
        self.directory = self.parent / "record-signing"
        self.key = self.directory / scheme.KEY_NAME
        self.public = self.parent / "record-signing.pub"
        self.settings = scheme.Settings(str(self.directory), str(self.public))
        # The test cannot be root, so root is whoever the test runs as.
        self.seams = scheme.Seams(
            root_uid=os.getuid(),
            effective_uid=os.getuid,
            random_bytes=lambda count: SEED[:count],
        )

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
        self.plant(self.key, scheme.private_pem(seed), mode)

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


@contextlib.contextmanager
def umask(value: int) -> Iterator[None]:
    """Run with a umask, which can only narrow a mode, and restore it."""
    previous = os.umask(value)
    try:
        yield
    finally:
        os.umask(previous)


class CreateTests(HostCase):
    """The key is made when it is absent, in the shape the controller reads, and root-only."""

    def test_generated_when_absent(self) -> None:
        result = self.run_module()
        self.assertTrue(result.created)
        self.assertTrue(result.changed)
        self.assertFalse(result.adopted)
        self.assertEqual(self.key.read_bytes(), pem_of(SEED))
        self.assertEqual(sorted(path.name for path in self.directory.iterdir()), [scheme.KEY_NAME])
        self.assertFalse(self.public.exists(), "the module never writes the public file")

    def test_a_new_key_is_root_only_0400_in_a_0700_directory(self) -> None:
        """The mode sabotage control: set the mode constant wider and this goes red."""
        self.run_module()
        info = self.key.stat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(info.st_uid, self.seams.root_uid)
        self.assertEqual(self.directory.stat().st_uid, self.seams.root_uid)
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual((scheme.DIR_MODE, scheme.KEY_MODE), (0o700, 0o400))

    def test_a_permissive_umask_does_not_widen_anything(self) -> None:
        with umask(0):
            self.run_module()
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

    def test_the_key_is_never_wider_than_0400_at_any_moment(self) -> None:
        """The mode-safe open: the file has its final mode while it holds the first byte."""
        seen: list[int] = []

        def look() -> None:
            for entry in self.directory.iterdir():
                seen.append(stat.S_IMODE(entry.lstat().st_mode))

        seams = dataclasses.replace(self.seams, after_temp_write=look, before_link=look)
        with umask(0):
            self.run_module(seams=seams)
        self.assertGreaterEqual(len(seen), 2)
        self.assertEqual(set(seen), {0o400})
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

    def test_the_new_directory_is_never_wider_than_0700(self) -> None:
        modes: list[int] = []
        real_mkdir = os.mkdir

        def watching_mkdir(path: str, mode: int = 0o777, **kwargs: int) -> None:
            modes.append(mode)
            real_mkdir(path, mode, **kwargs)

        with umask(0), mock.patch.object(os, "mkdir", watching_mkdir):
            self.run_module()
        self.assertEqual(modes, [0o700])

    def test_the_public_half_is_returned_as_an_spki_pem(self) -> None:
        result = self.run_module()
        self.assertEqual(result.public_key, public_pem_by_library(SEED))
        self.assertTrue(cast(str, result.public_key).startswith("-----BEGIN PUBLIC KEY-----\n"))

    def test_no_public_file_is_written_next_to_the_key(self) -> None:
        """The world-readable copy is the role's, not the module's: the directory stays closed."""
        self.run_module()
        self.assertEqual([p.name for p in self.directory.iterdir()], [scheme.KEY_NAME])

    def test_the_second_run_changes_nothing(self) -> None:
        first = self.run_module()
        before = self.snapshot()
        second = self.run_module()
        self.assertFalse(second.changed)
        self.assertFalse(second.created)
        self.assertFalse(second.adopted)
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
        self.assertEqual(self.key.read_bytes(), pem_of(OTHER_SEED))
        self.assertEqual(asked, [])
        # The public half is the existing key's, not a new key's.
        self.assertEqual(result.public_key, public_pem_by_library(OTHER_SEED))

    def test_an_existing_key_survives_a_lost_race_to_publish(self) -> None:
        """Another writer publishes between our look and our link: its key stands."""

        def publish_other_key() -> None:
            self.key.write_bytes(pem_of(OTHER_SEED))
            self.key.chmod(0o400)

        seams = dataclasses.replace(self.seams, before_link=publish_other_key)
        result = self.run_module(seams=seams)
        self.assertFalse(result.created)
        self.assertEqual(self.key.read_bytes(), pem_of(OTHER_SEED))
        self.assertEqual(result.public_key, public_pem_by_library(OTHER_SEED))
        self.assertEqual([p.name for p in self.directory.iterdir()], [scheme.KEY_NAME])

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
        self.assertEqual(self.key.read_bytes(), pem_of(SEED))
        self.assertEqual([p.name for p in self.directory.iterdir()], [scheme.KEY_NAME])

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
    """A valid key with a narrower mode is adopted, its bytes untouched."""

    def test_a_narrower_mode_is_adopted_once(self) -> None:
        self.plant_key(OTHER_SEED, mode=0o600)
        inode = self.key.stat().st_ino
        first = self.run_module()
        self.assertTrue(first.adopted)
        self.assertTrue(first.changed)
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o400)
        self.assertEqual(self.key.read_bytes(), pem_of(OTHER_SEED))
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
        self.assertEqual(self.key.read_bytes(), pem_of(SEED))

    def test_a_wider_mode_is_refused_not_adopted(self) -> None:
        for mode in (0o440, 0o640, 0o604, 0o644, 0o660, 0o666):
            with self.subTest(mode=oct(mode)):
                self.plant_key(mode=mode)
                self.assert_refused(scheme.E_KEY_MODE, self.key)
                self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), mode)
                self.key.unlink()


class RefusalTests(HostCase):
    """Each way the key's place can be wrong is a refusal naming the path and nothing else."""

    def test_a_key_another_account_owns_is_refused_before_it_is_read(self) -> None:
        """The root-only control: remove the owner check and this goes red."""
        # The content is not even a key, so a refusal for the owner proves the order. The test's
        # own account stands in for the stranger by making root some other uid.
        self.plant(self.key, b"not even a key")
        stranger = dataclasses.replace(self.seams, root_uid=os.getuid() + 1)
        fd = os.open(self.key, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        with self.assertRaises(scheme.RefusalError) as caught:
            scheme.judge_key(fd, str(self.key), stranger)
        self.assertEqual(str(caught.exception), f"{scheme.E_KEY_OWNER}: {self.key}")
        # The same key, with root being this account, is judged on its content instead.
        with self.assertRaises(scheme.RefusalError) as caught:
            scheme.judge_key(fd, str(self.key), self.seams)
        self.assertEqual(str(caught.exception), f"{scheme.E_KEY_FORM}: {self.key}")

    def converge_open(self, seams: scheme.Seams, dfd: int) -> None:
        """Run the work inside an already open directory, as converge does after its checks."""
        scheme.converge_in_directory(
            self.settings, seams, dfd, check_mode=False, result=scheme.Result()
        )

    def test_a_directory_another_account_owns_is_refused(self) -> None:
        self.plant_key()
        stranger = dataclasses.replace(self.seams, root_uid=os.getuid() + 1)
        dfd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, dfd)
        with self.assertRaises(scheme.RefusalError) as caught:
            self.converge_open(stranger, dfd)
        self.assertEqual(str(caught.exception), f"{scheme.E_DIR_OWNER}: {self.directory}")

    def test_the_module_refuses_to_run_as_anyone_but_root(self) -> None:
        not_root = dataclasses.replace(self.seams, root_uid=os.getuid() + 1)
        with self.assertRaises(scheme.RefusalError) as caught:
            self.run_module(seams=not_root)
        self.assertEqual(str(caught.exception), f"{scheme.E_NOT_ROOT}: {self.directory}")
        self.assertFalse(self.directory.exists())

    def test_a_key_that_has_gone_is_not_made_again_while_its_public_half_is_there(self) -> None:
        """The lost-key control: remove the check and a new key is made, and this goes red."""
        self.run_module()
        first_public = self.run_module().public_key
        self.key.unlink()
        self.public.write_text(cast(str, first_public), encoding="ascii")
        before = self.snapshot()
        asked: list[int] = []

        def new_seed(count: int) -> bytes:
            asked.append(count)
            return OTHER_SEED[:count]

        seams = dataclasses.replace(self.seams, random_bytes=new_seed)
        with self.assertRaises(scheme.RefusalError) as caught:
            self.run_module(seams=seams)
        self.assertEqual(str(caught.exception), f"{scheme.E_KEY_LOST}: {self.public}")
        self.assertEqual(asked, [])
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.key.exists())

    def test_a_key_directory_that_has_gone_is_not_made_again_either(self) -> None:
        self.public.write_text("EXAMPLE_PUBLIC_HALF\n", encoding="ascii")
        for check_mode in (False, True):
            with (
                self.subTest(check_mode=check_mode),
                self.assertRaises(scheme.RefusalError) as caught,
            ):
                self.run_module(check_mode=check_mode)
            self.assertEqual(str(caught.exception), f"{scheme.E_KEY_LOST}: {self.public}")
            self.assertFalse(self.directory.exists())

    def test_a_public_half_with_its_key_present_is_not_a_refusal(self) -> None:
        self.run_module()
        self.public.write_text("EXAMPLE_STALE_PUBLIC_HALF\n", encoding="ascii")
        self.assertFalse(self.run_module().created)

    def test_a_symlink_in_the_keys_place(self) -> None:
        target = self.root / "real-key"
        target.write_bytes(pem_of(SEED))
        target.chmod(0o400)
        self.make_directory()
        self.key.symlink_to(target)
        self.assert_refused(scheme.E_KEY_OPEN, self.key)
        self.assertEqual(target.read_bytes(), pem_of(SEED))

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
        self.plant(self.key, b"A" * 257)
        self.assert_refused(scheme.E_KEY_SIZE, self.key)

    def test_text_that_is_not_the_canonical_pem(self) -> None:
        good = scheme.private_pem(OTHER_SEED)
        cases = {
            "short seed": scheme.private_pem(OTHER_SEED[:31]),
            "long seed": scheme.private_pem(OTHER_SEED + b"x"),
            "trailing newline": good + b"\n",
            "no final newline": good[:-1],
            "the old OpenSSH form": b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + good[28:],
            "empty": b"",
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.plant(self.key, data)
                error = self.assert_refused(scheme.E_KEY_FORM, self.key)
                self.assert_no_seed_in(str(error), OTHER_SEED)
                self.key.unlink()

    def test_a_group_or_other_readable_key_is_refused_before_it_is_read(self) -> None:
        for mode in (0o440, 0o404, 0o640):
            with self.subTest(mode=oct(mode)):
                # The content is not even valid, so a refusal for the mode proves the order.
                self.plant(self.key, b"not a key", mode)
                self.assert_refused(scheme.E_KEY_MODE, self.key)
                self.key.unlink()

    def test_a_parent_not_owned_by_root(self) -> None:
        seams = dataclasses.replace(
            self.seams, root_uid=os.getuid() + 1, effective_uid=lambda: os.getuid() + 1
        )
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
        self.plant(self.directory / "record-signing.pub", b"foreign", 0o644)
        before = self.snapshot()
        with self.assertRaises(scheme.RefusalError) as caught:
            self.run_module()
        self.assertEqual(
            str(caught.exception), f"{scheme.E_FOREIGN}: {self.directory / 'record-signing.pub'}"
        )
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o755)


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

    def test_adopt_and_clean_up_are_planned_and_not_done(self) -> None:
        self.plant_key(mode=0o600)
        self.plant(self.directory / TEMP_NAME, b"left behind")
        before = self.snapshot()
        result = self.run_module(check_mode=True)
        self.assertTrue(result.adopted)
        self.assertEqual(result.temp_cleaned, 1)
        self.assertFalse(result.created)
        self.assertEqual(self.snapshot(), before)


@dataclasses.dataclass
class Outcome:
    """What main() told the stand-in for the Ansible module: how it ended, and with what."""

    how: str = ""
    kwargs: dict[str, object] = dataclasses.field(default_factory=dict)


class NoLeakTests(HostCase):
    """The private bytes are in the key file and nowhere else: not a return, a refusal, a log."""

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
        self.assertEqual(self.key.read_bytes(), pem_of(SEED))

    def test_an_existing_key_returns_no_part_of_the_seed(self) -> None:
        self.plant_key(OTHER_SEED)
        results: list[scheme.Result] = []
        printed = self.run_capturing(lambda: results.append(self.run_module()))
        self.assert_no_seed_in(printed + repr(results[0]), OTHER_SEED)

    def test_a_check_mode_run_returns_no_part_of_the_seed(self) -> None:
        self.plant_key(OTHER_SEED, mode=0o600)
        result = self.run_module(check_mode=True)
        self.assert_no_seed_in(repr(result), OTHER_SEED)

    def test_the_entry_point_returns_only_the_documented_keys(self) -> None:
        self.plant_key(OTHER_SEED)
        outcome = self.call_main()
        self.assertEqual(outcome.how, "exit")
        self.assertEqual(
            sorted(outcome.kwargs),
            ["adopted", "changed", "created", "public_key", "temp_cleaned"],
        )
        self.assert_no_seed_in(repr(outcome), OTHER_SEED)
        self.assertEqual(outcome.kwargs["public_key"], public_pem_by_library(OTHER_SEED))

    def test_the_entry_point_refuses_with_the_code_and_path_only(self) -> None:
        self.plant(self.key, pem_of(OTHER_SEED) + b"\n")
        outcome = self.call_main()
        self.assertEqual(outcome.how, "fail")
        self.assertEqual(outcome.kwargs, {"msg": f"{scheme.E_KEY_FORM}: {self.key}"})

    def test_an_unexpected_error_is_named_by_its_type_and_not_its_message(self) -> None:
        self.plant_key(OTHER_SEED)
        text = pem_of(OTHER_SEED).decode("ascii")
        with mock.patch.object(scheme, "converge", side_effect=ValueError(text)):
            outcome = self.call_main()
        self.assertEqual(outcome.kwargs, {"msg": f"{scheme.E_INTERNAL}: ValueError"})

    def test_an_os_error_is_named_by_its_errno_only(self) -> None:
        with mock.patch.object(scheme, "converge", side_effect=PermissionError(13, "denied /x")):
            outcome = self.call_main()
        self.assertEqual(outcome.kwargs, {"msg": f"{scheme.E_IO}: EACCES"})

    def call_main(self) -> "Outcome":
        """Run main() with a stand-in for the Ansible module and return what it was told."""
        seen = Outcome()
        test = self

        class Finished(Exception):  # noqa: N818 - stops main() where Ansible would exit
            """Raised by the stand-in's exit and fail, as the real ones end the process."""

        class FakeModule:
            """Takes the parameter the role passes, and records the one call main() makes."""

            check_mode = False

            def __init__(self, **_: object) -> None:
                self.params = {
                    "directory": str(test.directory),
                    "public_file": str(test.public),
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
    """The module checks its own argument before it touches anything."""

    def test_accepted(self) -> None:
        settings = scheme.settings_from_params(
            "/etc/branchleft/ring-controller/record-signing",
            "/etc/branchleft/ring-controller/record-signing.pub",
        )
        self.assertEqual(settings.directory, "/etc/branchleft/ring-controller/record-signing")
        self.assertEqual(settings.public_file, "/etc/branchleft/ring-controller/record-signing.pub")

    def test_refused(self) -> None:
        directory = "/etc/branchleft/ring-controller/record-signing"
        public = "/etc/branchleft/ring-controller/record-signing.pub"
        for label, values in {
            "relative directory": ("record-signing", public),
            "dot dot": ("/etc/branchleft/../x", public),
            "trailing slash": (directory + "/", public),
            "root": ("/", public),
            "relative public file": (directory, "record-signing.pub"),
            "public file with dot dot": (directory, "/etc/branchleft/../x.pub"),
            "public file inside the key directory": (directory, directory + "/record-signing.pub"),
        }.items():
            with self.subTest(label), self.assertRaises(scheme.RefusalError) as caught:
                scheme.settings_from_params(*values)
            self.assertEqual(caught.exception.code, scheme.E_ARGS)


class PinTests(unittest.TestCase):
    """The role's constants equal the module's."""

    @staticmethod
    def load(relative: str) -> dict[str, object]:
        """Read a YAML file of the role."""
        return cast(dict[str, object], YAML(typ="safe").load(ROLE / relative))

    def test_vars_equal_the_modules_constants(self) -> None:
        values = self.load("vars/main.yml")
        self.assertEqual(values["ring_controller_host_record_key_name"], scheme.KEY_NAME)
        self.assertEqual(
            values["ring_controller_host_record_key_directory_mode"], format(scheme.DIR_MODE, "04o")
        )
        self.assertEqual(
            values["ring_controller_host_record_key_mode"], format(scheme.KEY_MODE, "04o")
        )
        self.assertEqual(
            values["ring_controller_host_record_key_directory"],
            "/etc/branchleft/ring-controller/record-signing",
        )


if __name__ == "__main__":
    unittest.main()
