#!/usr/bin/python
"""Read, decide on, adopt and record the stamps of a restart-by-fingerprint role.

A role that restarts a unit only when what the unit runs from has changed keeps a stamp: a file
holding the sha256 fingerprint of the inputs that were last acted on and read back. This module
is the one implementation of the steps on those stamps, for every such role. It cannot be a role
that other roles call (ANS-12), so each role links this file into its own library/.

It acts on stamps and nothing else: it restarts no unit, reads no file that is not a stamp and
writes no file that is not a stamp. It never returns a stamp's content except from ``read``.
"""

import dataclasses
import grp
import os
import pwd
import re
import stat
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: restart_stamp
short_description: The stamp steps of a restart-by-fingerprint role
description:
  - V(state=read) reads each stamp and returns its content, or the word given in O(absent) for a
    stamp that is not there.
  - V(state=decide) works out, for each class, whether it is adopted, due, and to be marked
    pending, from the stamp, the fingerprint, the drift and the gate the caller supplies. It reads
    and writes nothing.
  - V(state=adopt) writes the stamp of each class whose C(adopt) is true. It runs in check mode
    too, where it reports the change and writes nothing.
  - V(state=record) writes the stamp of each class whose C(read_back) is true. In check mode it
    does nothing, because no action ran.
  - A stamp is one sha256 and a newline. Anything that is not a sha256 is refused, so the word
    C(pending), or any other word, can never be recorded as a fingerprint.
version_added: "1.0.0"
author:
  - AUTHOR_NAME
options:
  state:
    description: The step to run.
    type: str
    required: true
    choices: [read, decide, adopt, record]
  classes:
    description: The classes the step acts on. Each is a mapping; the keys a step reads are below.
    type: list
    elements: dict
    required: true
    suboptions:
      name:
        description: The class's name, used as the key of the result. Unique in the list.
        type: str
        required: true
      file:
        description: Absolute path of the class's stamp. Read by read, adopt and record.
        type: str
      stamp:
        description: What the stamp holds now, as read returned it. Read by decide.
        type: str
      fingerprint:
        description: The sha256 of the inputs. Read by decide, adopt and record.
        type: str
      drift:
        description: A file of the class on the host differs from the repository's. Read by decide.
        type: bool
        default: false
      adoptable:
        description: The class may be adopted when it has no stamp. Read by decide.
        type: bool
        default: false
      gate:
        description: When false the class is neither adopted nor due. Read by decide.
        type: bool
        default: true
      adopt:
        description: Write this class's stamp. Read by adopt.
        type: bool
        default: false
      read_back:
        description: The class's action ran and was read back as done. Read by record.
        type: bool
        default: false
  absent:
    description: What read returns for a stamp that is not there, and what decide takes as that.
    type: str
    default: absent
  unreadable:
    description:
      - What read does with a stamp that is there and cannot be read (a directory, a link to
        nothing, an I/O error).
      - V(fail) stops the run. V(absent) treats the stamp as not there.
    type: str
    choices: [fail, absent]
    default: fail
  owner:
    description: Owner of a written stamp.
    type: str
    default: root
  group:
    description: Group of a written stamp.
    type: str
    default: root
  mode:
    description: Permissions of a written stamp, as four octal digits in a string.
    type: str
    default: "0600"
attributes:
  check_mode:
    support: full
    description: Read and decide run as in an apply. Adopt reports its change and writes
      nothing. Record does nothing.
  diff_mode:
    support: none
    description: A stamp holds a hash of files that may hold a key, so no diff is returned.
"""

EXAMPLES = r"""
- name: Read the stamp
  restart_stamp:
    state: read
    classes:
      - { name: unit, file: /var/lib/EXAMPLE_SERVICE/unit.applied }
  register: example_service_stamps
  no_log: true

- name: Record the fingerprint once the restart was read back
  restart_stamp:
    state: record
    classes:
      - name: unit
        file: /var/lib/EXAMPLE_SERVICE/unit.applied
        fingerprint: "{{ example_service_fingerprint }}"
        read_back: true
  no_log: true
"""

RETURN = r"""
changed:
  description: Whether a stamp was, or in check mode would be, written.
  returned: always
  type: bool
stamps:
  description: What each stamp holds, by class name, or the O(absent) word.
  returned: when state is read
  type: dict
decisions:
  description: For each class name, a mapping of C(adopt), C(due) and C(mark), all booleans.
  returned: when state is decide
  type: dict
written:
  description: The names of the classes whose stamp was, or in check mode would be, written.
  returned: when state is adopt or record
  type: list
  elements: str
"""

State = Literal["read", "decide", "adopt", "record"]
STATES: tuple[State, ...] = ("read", "decide", "adopt", "record")
Unreadable = Literal["fail", "absent"]

FINGERPRINT = re.compile(r"[0-9a-f]{64}")
MODE = re.compile(r"0[0-7]{3}")


class StampError(Exception):
    """A value or a file the module refuses. Each subclass owns its message."""


class ClassNameRepeatedError(StampError):
    """Two classes carry one name."""

    def __init__(self, name: str) -> None:
        super().__init__(f"the class name {name!r} is used more than once")


class ClassKeyMissingError(StampError):
    """A key the step needs is not in a class."""

    def __init__(self, name: str, key: str, state: str) -> None:
        super().__init__(f"class {name!r} has no {key}, which state={state} needs")


class FileNotAbsoluteError(StampError):
    """A stamp path that is not absolute."""

    def __init__(self, name: str, path: str) -> None:
        super().__init__(f"the stamp of {name!r} must be an absolute path, got {path!r}")


class FingerprintNotAllowedError(StampError):
    """A value that is not a sha256 where a fingerprint is written."""

    def __init__(self, name: str) -> None:
        super().__init__(f"the fingerprint of {name!r} is not a sha256, so it is not written")


class ModeNotAllowedError(StampError):
    """A mode that is not four octal digits."""

    def __init__(self, mode: str) -> None:
        super().__init__(f"mode must be four octal digits such as 0600, got {mode!r}")


class OwnerNotKnownError(StampError):
    """An owner or group the host does not have."""

    def __init__(self, kind: str, name: str) -> None:
        super().__init__(f"the {kind} {name!r} does not exist on this host")


class StampUnreadableError(StampError):
    """A stamp is there and cannot be read."""

    def __init__(self, name: str, path: str, reason: str) -> None:
        super().__init__(f"the stamp of {name!r} at {path} is there and cannot be read: {reason}")


class DirectoryMissingError(StampError):
    """The directory a stamp would be written into does not exist."""

    def __init__(self, directory: Path) -> None:
        super().__init__(f"directory {directory} does not exist")


class NotARegularFileError(StampError):
    """Something other than a regular file is where a stamp is written."""

    def __init__(self, path: Path) -> None:
        super().__init__(f"{path} exists and is not a regular file")


class ParamTypeError(TypeError):
    """A value AnsibleModule validated is not the type this module reads it as."""

    def __init__(self, key: str, expected: str) -> None:
        super().__init__(f"{key} is not {expected}")


@dataclasses.dataclass(frozen=True)
class StampClass:
    """One class's inputs. A key a step does not read is left at its default."""

    name: str
    file: str | None = None
    stamp: str | None = None
    fingerprint: str | None = None
    drift: bool = False
    adoptable: bool = False
    gate: bool = True
    adopt: bool = False
    read_back: bool = False


@dataclasses.dataclass(frozen=True)
class Decision:
    """What one class is to the run."""

    adopt: bool
    due: bool
    mark: bool


@dataclasses.dataclass(frozen=True)
class Identity:
    """The owner, group and mode a written stamp has."""

    uid: int
    gid: int
    mode: int


@dataclasses.dataclass(frozen=True)
class Observed:
    """What the host holds at a stamp's path: None when the file does not exist."""

    content: str | None
    uid: int
    gid: int
    mode: int


ARGUMENT_SPEC: dict[str, dict[str, object]] = {
    "state": {"type": "str", "required": True, "choices": list(STATES)},
    "classes": {
        "type": "list",
        "elements": "dict",
        "required": True,
        "options": {
            "name": {"type": "str", "required": True},
            "file": {"type": "str"},
            "stamp": {"type": "str"},
            "fingerprint": {"type": "str"},
            "drift": {"type": "bool", "default": False},
            "adoptable": {"type": "bool", "default": False},
            "gate": {"type": "bool", "default": True},
            "adopt": {"type": "bool", "default": False},
            "read_back": {"type": "bool", "default": False},
        },
    },
    "absent": {"type": "str", "default": "absent"},
    "unreadable": {"type": "str", "default": "fail", "choices": ["fail", "absent"]},
    "owner": {"type": "str", "default": "root"},
    "group": {"type": "str", "default": "root"},
    "mode": {"type": "str", "default": "0600"},
}


def _text(values: Mapping[str, object], key: str) -> str:
    """Return ``values[key]`` as a string.

    Raises:
        ParamTypeError: when the value is not a string.
    """
    value = values.get(key)
    if not isinstance(value, str):
        raise ParamTypeError(key, "a string")
    return value


def _optional_text(values: Mapping[str, object], key: str) -> str | None:
    """Return ``values[key]`` as a string, or None when it is not given.

    Raises:
        ParamTypeError: when the value is given and is not a string.
    """
    value = values.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ParamTypeError(key, "a string")
    return value


def _flag(values: Mapping[str, object], key: str) -> bool:
    """Return ``values[key]`` as a boolean.

    Raises:
        ParamTypeError: when the value is not a boolean.
    """
    value = values.get(key)
    if not isinstance(value, bool):
        raise ParamTypeError(key, "a boolean")
    return value


def classes_from(values: object) -> list[StampClass]:
    """Build the classes from the list AnsibleModule validated.

    Raises:
        ParamTypeError: when an entry is not a mapping or a value has the wrong type.
        ClassNameRepeatedError: when two classes carry one name.
    """
    if not isinstance(values, Sequence) or isinstance(values, str):
        raise ParamTypeError("classes", "a list")
    classes: list[StampClass] = []
    for entry in values:
        if not isinstance(entry, Mapping):
            raise ParamTypeError("classes", "a list of mappings")
        classes.append(
            StampClass(
                name=_text(entry, "name"),
                file=_optional_text(entry, "file"),
                stamp=_optional_text(entry, "stamp"),
                fingerprint=_optional_text(entry, "fingerprint"),
                drift=_flag(entry, "drift"),
                adoptable=_flag(entry, "adoptable"),
                gate=_flag(entry, "gate"),
                adopt=_flag(entry, "adopt"),
                read_back=_flag(entry, "read_back"),
            )
        )
    seen: set[str] = set()
    for item in classes:
        if item.name in seen:
            raise ClassNameRepeatedError(item.name)
        seen.add(item.name)
    return classes


def _needs(item: StampClass, key: Literal["file", "stamp", "fingerprint"], state: str) -> str:
    """Return the value of ``key`` on a class.

    Raises:
        ClassKeyMissingError: when the class does not carry it.
    """
    value = getattr(item, key)
    if not isinstance(value, str):
        raise ClassKeyMissingError(item.name, key, state)
    return value


def _stamp_path(item: StampClass, state: str) -> str:
    """Return a class's stamp path.

    Raises:
        ClassKeyMissingError: when the class has no file.
        FileNotAbsoluteError: when the path is not absolute.
    """
    path = _needs(item, "file", state)
    if not path.startswith("/"):
        raise FileNotAbsoluteError(item.name, path)
    return path


def read_stamps(
    classes: Sequence[StampClass], absent: str, unreadable: Unreadable
) -> dict[str, str]:
    """Return what each stamp holds, by name. Reads only; nothing is written.

    Only a stamp that is not there is ``absent``, unless ``unreadable`` says a stamp that is there
    and cannot be read is too. Links are not followed to decide whether a stamp is there: a link
    is there, and reading it fails when it leads nowhere.

    Raises:
        StampUnreadableError: when a stamp is there, cannot be read and ``unreadable`` is fail.
    """
    found: dict[str, str] = {}
    for item in classes:
        path = _stamp_path(item, "read")
        try:
            Path(path).lstat()
        except FileNotFoundError:
            found[item.name] = absent
            continue
        try:
            found[item.name] = Path(path).read_text(encoding="utf-8", errors="replace").strip()
        except OSError as error:
            if unreadable == "absent":
                found[item.name] = absent
                continue
            raise StampUnreadableError(item.name, path, error.strerror or "I/O error") from error
    return found


def decide(classes: Sequence[StampClass], absent: str) -> dict[str, Decision]:
    """Return, for each class, whether it is adopted, due and to be marked pending.

    A computation on the inputs and nothing else. With the gate open a class is adopted when it is
    adoptable, has no stamp and nothing differs on the host; otherwise it is due when a file
    differs or the stamp is not this fingerprint. With the gate closed it is neither. It is marked
    when it is due or a file drifts, whatever the gate, because the file is still placed.

    Raises:
        ClassKeyMissingError: when a class has no stamp or no fingerprint.
    """
    decisions: dict[str, Decision] = {}
    for item in classes:
        stamp = _needs(item, "stamp", "decide")
        fingerprint = _needs(item, "fingerprint", "decide")
        adopt = item.adoptable and item.gate and stamp == absent and not item.drift
        due = item.gate and not adopt and (item.drift or stamp != fingerprint)
        decisions[item.name] = Decision(adopt=adopt, due=due, mark=due or item.drift)
    return decisions


def _fingerprint_to_write(item: StampClass, state: str) -> str:
    """Return the fingerprint a class writes.

    Raises:
        ClassKeyMissingError: when the class has no fingerprint.
        FingerprintNotAllowedError: when it is not a sha256.
    """
    fingerprint = _needs(item, "fingerprint", state)
    if FINGERPRINT.fullmatch(fingerprint) is None:
        raise FingerprintNotAllowedError(item.name)
    return fingerprint


def stamps_to_write(
    classes: Sequence[StampClass], state: Literal["adopt", "record"]
) -> list[StampClass]:
    """Return the classes whose stamp this step writes, each checked.

    Raises:
        ClassKeyMissingError: when a class to write has no file or fingerprint.
        FileNotAbsoluteError: when a stamp path is not absolute.
        FingerprintNotAllowedError: when a fingerprint to write is not a sha256.
    """
    chosen = [item for item in classes if (item.adopt if state == "adopt" else item.read_back)]
    for item in chosen:
        _stamp_path(item, state)
        _fingerprint_to_write(item, state)
    return chosen


def identity(owner: str, group: str, mode: str) -> Identity:
    """Resolve the owner, group and mode a written stamp has.

    Raises:
        ModeNotAllowedError: when the mode is not four octal digits.
        OwnerNotKnownError: when the owner or the group does not exist.
    """
    if MODE.fullmatch(mode) is None:
        raise ModeNotAllowedError(mode)
    try:
        uid = pwd.getpwnam(owner).pw_uid
    except KeyError as error:
        raise OwnerNotKnownError("owner", owner) from error
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError as error:
        raise OwnerNotKnownError("group", group) from error
    return Identity(uid=uid, gid=gid, mode=int(mode, 8))


def _target(path: str) -> Path:
    """Return where a write to ``path`` lands: a link is followed, as ``copy`` follows it."""
    return Path(os.path.realpath(path))


def observe(target: Path) -> Observed:
    """Read the file at ``target`` as the host holds it now.

    Raises:
        DirectoryMissingError: when the directory of the file does not exist.
        NotARegularFileError: when something other than a regular file is there.
    """
    if not target.parent.is_dir():
        raise DirectoryMissingError(target.parent)
    try:
        info = target.lstat()
    except FileNotFoundError:
        return Observed(content=None, uid=-1, gid=-1, mode=-1)
    if not stat.S_ISREG(info.st_mode):
        raise NotARegularFileError(target)
    return Observed(
        content=target.read_text(encoding="utf-8", errors="replace"),
        uid=info.st_uid,
        gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode),
    )


def differs(observed: Observed, fingerprint: str, wanted: Identity) -> bool:
    """Return whether the stamp on the host is not what a write would leave."""
    return (
        observed.content != f"{fingerprint}\n"
        or observed.uid != wanted.uid
        or observed.gid != wanted.gid
        or observed.mode != wanted.mode
    )


def _write_atomically(target: Path, content: str, wanted: Identity) -> None:
    """Write ``content`` beside ``target`` with its owner and mode already set, then rename it."""
    descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        os.fchmod(descriptor, wanted.mode)
        os.fchown(descriptor, wanted.uid, wanted.gid)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def write_stamps(
    classes: Sequence[StampClass],
    state: Literal["adopt", "record"],
    wanted: Identity,
    *,
    check_mode: bool,
) -> list[str]:
    """Write the stamp of each class this step writes, and return the names that changed.

    A stamp already as it would be written is left alone and not named. In check mode adopt names
    what it would write and writes nothing, and record does nothing. In check mode a directory that
    is not there yet is not an error: its stamp would be written, once a task has made it.

    Raises:
        StampError: when a class or a file on the host is refused (see ``stamps_to_write`` and
            ``observe``).
    """
    chosen = stamps_to_write(classes, state)
    if check_mode and state == "record":
        return []
    changed: list[str] = []
    for item in chosen:
        fingerprint = _fingerprint_to_write(item, state)
        target = _target(_stamp_path(item, state))
        if check_mode and not target.parent.is_dir():
            # A plan on a fresh host: the directory is made by a task that check mode skips.
            changed.append(item.name)
        elif differs(observe(target), fingerprint, wanted):
            if not check_mode:
                _write_atomically(target, f"{fingerprint}\n", wanted)
            changed.append(item.name)
    return changed


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC, supports_check_mode=True)
    params: dict[str, object] = dict(module.params)
    try:
        state = _text(params, "state")
        classes = classes_from(params["classes"])
        absent = _text(params, "absent")
        if state == "read":
            unreadable: Unreadable = "absent" if _text(params, "unreadable") == "absent" else "fail"
            module.exit_json(changed=False, stamps=read_stamps(classes, absent, unreadable))
        elif state == "decide":
            decisions = decide(classes, absent)
            module.exit_json(
                changed=False,
                decisions={
                    name: {"adopt": item.adopt, "due": item.due, "mark": item.mark}
                    for name, item in decisions.items()
                },
            )
        else:
            step: Literal["adopt", "record"] = "adopt" if state == "adopt" else "record"
            wanted = identity(_text(params, "owner"), _text(params, "group"), _text(params, "mode"))
            written = write_stamps(classes, step, wanted, check_mode=module.check_mode)
            module.exit_json(changed=bool(written), written=written)
    except (StampError, ParamTypeError, OSError) as error:
        module.fail_json(msg=str(error))


if __name__ == "__main__":
    main()
