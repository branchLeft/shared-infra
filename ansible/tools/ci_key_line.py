"""Build and verify the two forced-command key lines of a CI account's authorized_keys.

`build` makes one line from a public key file; `verify` rebuilds both lines and requires a
read-back to equal them byte for byte. It prints reason codes only, never a key or a line read
back. Standard library only. See ansible/tools/README.md."""

from __future__ import annotations

import ipaddress
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

# Run with `python -I`, which leaves the script's own folder off the path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pubkey_only  # noqa: E402

KEY_TYPE: Final = "ssh-ed25519"
# Held equal to the ci_login and pull_trigger roles by a test.
PROGRAM: Final = "/usr/local/sbin/pull-trigger"
OPTIONS: Final = "restrict"
MODES: Final[tuple[str, ...]] = ("check", "apply")
MAX_READBACK_BYTES: Final = 4096
MAX_NOT_KEYS_BYTES: Final = 65536
COMMAND_CLAUSE: Final = re.compile(r'command="([^"]*)"')
FROM_CLAUSE: Final = re.compile(r'from="([^"]*)"')


def valid_ipv4(text: str) -> bool:
    """A dotted quad in its plain form, so `010.0.0.1` and `1.2.3` are refused."""
    try:
        return str(ipaddress.IPv4Address(text)) == text
    except ValueError:
        return False


def options_for(mode: str, from_address: str) -> str:
    return f'{OPTIONS},from="{from_address}",command="sudo {PROGRAM} --mode {mode}"'


def line_for(mode: str, key: pubkey_only.KeyCheck, from_address: str) -> str:
    """One authorized_keys line; the key's comment is dropped."""
    return f"{options_for(mode, from_address)} {key.key_type} {key.body}"


def read_limited(path: Path, limit: int) -> bytes | None:
    """The file's bytes, or None when it is unreadable or longer than the limit."""
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None


def clause(pattern: re.Pattern[str], options: str) -> str | None:
    found = pattern.search(options)
    return found[1] if found else None


def why_lines_differ(got: str, want: str) -> str:
    """Name the first part of a read-back line that differs from the line it should be."""
    got_words = got.rsplit(" ", 2)
    want_words = want.rsplit(" ", 2)
    if len(got_words) != 3:
        return "not_identical"
    if not got_words[0].startswith(OPTIONS):
        return "restrict_missing"
    if clause(COMMAND_CLAUSE, got_words[0]) != clause(COMMAND_CLAUSE, want_words[0]):
        return "command_mismatch"
    sources = FROM_CLAUSE.findall(got_words[0])
    if not sources:
        return "from_missing"
    if len(sources) > 1:
        return "several_from"
    if sources != FROM_CLAUSE.findall(want_words[0]):
        return "from_mismatch"
    if got_words[0] != want_words[0]:
        return "options_differ"
    if got_words[1:] != want_words[1:]:
        return "key_mismatch"
    return "not_identical"


def build_line(mode: str, pub: Path, from_address: str) -> tuple[str, str]:
    """The line and an empty reason, or an empty line and the reason it was refused."""
    if mode not in MODES:
        return "", "bad_mode"
    if not valid_ipv4(from_address):
        return "", "bad_from"
    key = pubkey_only.check_file(pub, KEY_TYPE)
    if not key.ok:
        return "", key.reason
    return line_for(mode, key, from_address), ""


def verify_lines(
    readback: Path,
    check_pub: Path,
    apply_pub: Path,
    from_address: str,
    not_keys: Path | None,
) -> str:
    """An empty string when the read-back is exactly the two lines, else a reason code."""
    if not valid_ipv4(from_address):
        return "bad_from"
    keys: dict[str, pubkey_only.KeyCheck] = {}
    for mode, pub in (("check", check_pub), ("apply", apply_pub)):
        keys[mode] = pubkey_only.check_file(pub, KEY_TYPE)
        if not keys[mode].ok:
            return f"{mode}_pub_{keys[mode].reason}"
    if keys["check"].body == keys["apply"].body:
        return "same_key_both_modes"
    if not_keys is not None:
        held = read_limited(not_keys, MAX_NOT_KEYS_BYTES)
        if held is None:
            return "not_keys_unreadable"
        words = set(held.decode("utf-8", errors="replace").split())
        if keys["check"].body in words or keys["apply"].body in words:
            return "key_in_not_keys"
    data = read_limited(readback, MAX_READBACK_BYTES)
    if data is None:
        return "readback_unreadable"
    wanted = [line_for(mode, keys[mode], from_address) for mode in MODES]
    if data == ("\n".join(wanted) + "\n").encode("ascii"):
        return ""
    got = data.decode("utf-8", errors="replace").splitlines()
    if len(got) != len(wanted):
        return "line_count"
    if got == wanted[::-1]:
        return "order_swapped"
    for got_line, want_line in zip(got, wanted, strict=True):
        if got_line != want_line:
            return why_lines_differ(got_line, want_line)
    return "not_identical"


def main(argv: Sequence[str] | None = None) -> int:
    parser = pubkey_only.QuietParser(prog="ci_key_line.py")
    commands = parser.add_subparsers(
        dest="command", required=True, parser_class=pubkey_only.QuietParser
    )
    build = commands.add_parser("build")
    build.add_argument("--mode", required=True)
    build.add_argument("--pub", required=True, type=Path)
    build.add_argument("--from", dest="from_address", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--file", required=True, type=Path)
    verify.add_argument("--check-pub", required=True, type=Path)
    verify.add_argument("--apply-pub", required=True, type=Path)
    verify.add_argument("--from", dest="from_address", required=True)
    verify.add_argument("--not-keys", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.command == "build":
        line, reason = build_line(args.mode, args.pub, args.from_address)
        if reason:
            print(f"keyline=REFUSED reason={reason}", file=sys.stderr)
            return 1
        print(line)
        return 0
    reason = verify_lines(
        args.file, args.check_pub, args.apply_pub, args.from_address, args.not_keys
    )
    if reason:
        print(f"keylines=REFUSED reason={reason}")
        return 1
    print("keylines=ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
