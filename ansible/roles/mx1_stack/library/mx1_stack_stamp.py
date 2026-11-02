#!/usr/bin/python
"""Decide, mark and record the stamp of one class of the mx1 stack.

A class is one of the things the role keeps in step with the repository: Stalwart's
project, the mailgun-shim project and the local resolver. Each has a stamp file, which
holds either the word ``pending`` or one ``<input name> <sha256>`` line per input, sorted.

The stamp is written in two steps, so a run that fails part-way is followed by a run that
acts again: ``mark`` writes ``pending`` before anything is changed, and ``record`` writes
the lines only after the read-back has shown the running containers fresh and healthy.

The module reads only the files it is told to hash and the stamp. It returns names and
hashes, never a value, and in check mode it writes nothing.
"""

import hashlib
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: mx1_stack_stamp
short_description: Decide, mark and record the stamp of one mx1 class
description:
  - C(decide) reads the stamp and the hashes of the class's inputs and says whether the class is
    due, and whether a host with no stamp can be adopted as it stands.
  - C(mark) writes the word C(pending) to the stamp, before the class is acted on.
  - C(record) writes one C(name sha256) line per input, only after the read-back has passed.
  - Never returns a file's content. A refusal names an input or a line number, never a value.
version_added: "1.0.0"
author:
  - branchLeft
options:
  action:
    description: What to do.
    type: str
    required: true
    choices: [decide, mark, record]
  stamp_path:
    description: The stamp file.
    type: path
    required: true
  files:
    description: Input name to the path of the file whose SHA-256 is the input's line.
    type: dict
    default: {}
  values:
    description: Input name to a string whose SHA-256 is the input's line.
    type: dict
    default: {}
  expected:
    description:
      - Input name to the SHA-256 the repository says that file should have (C(decide) only).
      - An input whose file hashes to something else, or is absent, makes the class due.
    type: dict
    default: {}
  live_ok:
    description: Whether the running state is running, healthy and on the pinned image (C(decide)
      only).
    type: bool
    default: true
  stale:
    description: Whether a freshness read found an input newer than its container (C(decide) only).
    type: bool
    default: false
attributes:
  check_mode:
    support: full
    description: C(mark) and C(record) report the change they would make and write nothing.
  diff_mode:
    support: none
    description: The stamp holds hashes of secrets, so no diff is shown.
"""

EXAMPLES = r"""
- name: Decide whether the shim class is due
  mx1_stack_stamp:
    action: decide
    stamp_path: /var/lib/branchleft/mx1.shim.applied
    files:
      shim_compose: /etc/mailgun-shim/shim-compose.yml
    expected:
      shim_compose: "{{ shim_compose_text | hash('sha256') }}"
    live_ok: true
    stale: false
"""

RETURN = r"""
state:
  description: C(absent), C(pending) or C(recorded).
  returned: when action is decide
  type: str
differing:
  description: The inputs whose line differs from the stamp, sorted. Every input when the stamp is
    absent.
  returned: when action is decide
  type: list
  elements: str
due:
  description: Whether the class must be acted on.
  returned: when action is decide
  type: bool
adopt:
  description: Whether a host with no stamp is in the state the repository describes, and only the
    stamp is missing.
  returned: when action is decide
  type: bool
reasons:
  description: One plain sentence per reason the class is due. Holds no value.
  returned: when action is decide
  type: list
  elements: str
repository_differs:
  description: The inputs with a repository hash whose file differs from it or is absent.
  returned: when action is decide
  type: list
  elements: str
lines:
  description: The input names and the SHA-256 of each, which C(record) writes.
  returned: always
  type: dict
"""

PENDING = "pending"
ABSENT_HASH = "absent"
LINE_PATTERN = re.compile(r"(?P<name>[a-z][a-z0-9_]*) (?P<hash>[0-9a-f]{64}|absent)")
NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]*")
STATE_ABSENT = "absent"
STATE_PENDING = "pending"
STATE_RECORDED = "recorded"
FILE_MODE = 0o600
CHUNK = 1 << 16


class StampError(Exception):
    """The stamp, or an input, cannot be read. Carries no part of any file."""


@dataclass(frozen=True)
class Stamp:
    """What the stamp file holds."""

    state: str
    lines: Mapping[str, str]


def hash_file(path: str) -> str:
    """Return the SHA-256 of a file's bytes, or ``absent`` when there is no such file.

    Raises:
        StampError: The path is not a regular file, or cannot be read.
    """
    if not os.path.lexists(path):
        return ABSENT_HASH
    if os.path.islink(path) or not os.path.isfile(path):
        message = f"input file {path} is not a regular file"
        raise StampError(message)
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(CHUNK), b""):
                digest.update(block)
    except OSError as error:
        message = f"input file {path} cannot be read ({error.strerror})"
        raise StampError(message) from None
    return digest.hexdigest()


def hash_value(value: str) -> str:
    """Return the SHA-256 of a string's UTF-8 bytes."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def current_lines(files: Mapping[str, str], values: Mapping[str, str]) -> dict[str, str]:
    """Return the line for each input, sorted by name.

    Raises:
        StampError: An input name is malformed or named twice, or a file cannot be read.
    """
    names = [*files, *values]
    for name in names:
        if NAME_PATTERN.fullmatch(name) is None:
            message = "an input name is not lower-case letters, digits and underscores"
            raise StampError(message)
    if len(set(names)) != len(names):
        message = "an input name is given twice"
        raise StampError(message)
    lines = {name: hash_file(path) for name, path in files.items()}
    lines.update({name: hash_value(text) for name, text in values.items()})
    return dict(sorted(lines.items()))


def render(lines: Mapping[str, str]) -> str:
    """Return the stamp text for a set of lines: sorted ``name hash`` lines."""
    return "".join(f"{name} {digest}\n" for name, digest in sorted(lines.items()))


def parse(text: str) -> Stamp:
    """Return what a stamp text holds.

    Raises:
        StampError: The text is neither ``pending`` nor a set of well-formed lines.
    """
    if text == f"{PENDING}\n":
        return Stamp(STATE_PENDING, {})
    lines: dict[str, str] = {}
    if not text.endswith("\n"):
        message = "the stamp does not end in a line break"
        raise StampError(message)
    for number, raw in enumerate(text.splitlines(), start=1):
        found = LINE_PATTERN.fullmatch(raw)
        if found is None or found["name"] in lines:
            message = f"line {number} of the stamp is malformed or repeats an input"
            raise StampError(message)
        lines[found["name"]] = found["hash"]
    if not lines:
        message = "the stamp is empty"
        raise StampError(message)
    if list(lines) != sorted(lines):
        message = "the stamp's lines are not sorted"
        raise StampError(message)
    return Stamp(STATE_RECORDED, lines)


def read_stamp(path: str) -> Stamp:
    """Return the stamp at ``path``; an absent file is the ``absent`` state.

    Raises:
        StampError: The stamp is not a regular file, is not owner-only, cannot be read
            or is malformed.
    """
    if not os.path.lexists(path):
        return Stamp(STATE_ABSENT, {})
    if os.path.islink(path) or not os.path.isfile(path):
        message = "the stamp is not a regular file"
        raise StampError(message)
    if os.stat(path).st_mode & 0o077:
        message = "the stamp is readable by someone other than its owner"
        raise StampError(message)
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError):
        message = "the stamp cannot be read"
        raise StampError(message) from None
    return parse(text)


def differing(stamp: Stamp, lines: Mapping[str, str]) -> list[str]:
    """Return the inputs whose line differs from the stamp, including inputs only one side has."""
    if stamp.state != STATE_RECORDED:
        return sorted(lines)
    names = set(lines) | set(stamp.lines)
    return sorted(name for name in names if stamp.lines.get(name) != lines.get(name))


@dataclass(frozen=True)
class Decision:
    """The verdict of ``decide``."""

    state: str
    differing: list[str]
    due: bool
    adopt: bool
    reasons: list[str]
    repository_differs: list[str]


def decide(
    stamp: Stamp,
    lines: Mapping[str, str],
    *,
    expected: Mapping[str, str],
    live_ok: bool,
    stale: bool,
) -> Decision:
    """Say whether a class is due.

    A class is due when any line differs, the stamp is ``pending``, a placed file differs from
    the repository (or, with no repository hash to compare, is absent), a freshness read is
    stale or the live state is not ok. A host with no stamp is adopted when none of those
    holds but the stamp's absence.
    """
    changed = differing(stamp, lines)
    repository_differs = sorted(
        name for name, digest in expected.items() if lines.get(name) != digest
    )
    missing = sorted(
        name for name, digest in lines.items() if digest == ABSENT_HASH and name not in expected
    )
    reasons: list[str] = []
    if stamp.state == STATE_PENDING:
        reasons.append("the stamp is pending: an earlier run did not finish")
    if stamp.state == STATE_RECORDED:
        reasons.extend(f"input {name} differs from the stamp" for name in changed)
    reasons.extend(f"input {name} differs from the repository" for name in repository_differs)
    reasons.extend(f"input {name} is absent" for name in missing)
    if stale:
        reasons.append("an input is newer than the container that reads it")
    if not live_ok:
        reasons.append("the running state is not ok")
    adopt = stamp.state == STATE_ABSENT and not reasons
    if stamp.state == STATE_ABSENT and reasons:
        reasons.insert(
            0, "there is no stamp and the host is not in the state the repository describes"
        )
    due = bool(reasons)
    return Decision(stamp.state, changed, due, adopt, reasons, repository_differs)


def write_atomic(path: str, text: str) -> None:
    """Replace ``path`` with ``text``, mode 0600, through a temporary file in its directory."""
    directory = os.path.dirname(path) or "."
    descriptor, temporary = tempfile.mkstemp(prefix=".mx1-stamp.", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, FILE_MODE)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def would_change(path: str, text: str) -> bool:
    """Return whether the file at ``path`` differs from ``text`` in content or mode."""
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            return True
        if os.stat(path).st_mode & 0o777 != FILE_MODE:
            return True
        with open(path, encoding="utf-8") as handle:
            return handle.read() != text
    except (OSError, UnicodeDecodeError):
        return True


def as_text_map(raw: object) -> dict[str, str]:
    """Return a module parameter as a map of strings."""
    if not isinstance(raw, Mapping):
        return {}
    return {str(key): str(value) for key, value in raw.items()}


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(
        argument_spec={
            "action": {"type": "str", "required": True, "choices": ["decide", "mark", "record"]},
            "stamp_path": {"type": "path", "required": True},
            "files": {"type": "dict", "default": {}},
            "values": {"type": "dict", "default": {}},
            "expected": {"type": "dict", "default": {}},
            "live_ok": {"type": "bool", "default": True},
            "stale": {"type": "bool", "default": False},
        },
        supports_check_mode=True,
    )
    path = str(module.params["stamp_path"])
    try:
        lines = current_lines(
            as_text_map(module.params["files"]), as_text_map(module.params["values"])
        )
        if module.params["action"] == "decide":
            verdict = decide(
                read_stamp(path),
                lines,
                expected=as_text_map(module.params["expected"]),
                live_ok=bool(module.params["live_ok"]),
                stale=bool(module.params["stale"]),
            )
            module.exit_json(
                changed=False,
                state=verdict.state,
                differing=verdict.differing,
                due=verdict.due,
                adopt=verdict.adopt,
                reasons=verdict.reasons,
                repository_differs=verdict.repository_differs,
                lines=lines,
            )
        else:
            text = f"{PENDING}\n" if module.params["action"] == "mark" else render(lines)
            changed = would_change(path, text)
            if changed and not module.check_mode:
                write_atomic(path, text)
            module.exit_json(changed=changed, lines=lines)
    except StampError as error:
        module.fail_json(msg=f"mx1 stamp {path}: {error}")


if __name__ == "__main__":
    main()
