#!/usr/bin/python
"""Manage one RECORD_FILE: the typed Ansible module the pattern copies.

The module is deliberately trivial. Its shape is the template: one dataclass
holds the parameters, the argument_spec is generated from that dataclass, the
decision is a pure function, and the only code that touches the host is
``apply``. ``ansible.builtin.copy`` with ``content:`` would do this module's
job, so a real role does not ship it (ANS-9); see the pattern README.
"""

import dataclasses
import hmac
import os
import re
import stat
import tempfile
import types
import typing
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from ansible.module_utils.basic import AnsibleModule

if typing.TYPE_CHECKING:
    from _typeshed import DataclassInstance

DOCUMENTATION = r"""
module: typed_module_record
short_description: Manage one RECORD_FILE of the typed_module pattern
description:
  - Writes a small record file with a name, a count and, when a token is given, a keyed signature
    of the name, or removes the file.
  - Replaces the file atomically, and reports a change only when the content or the mode differs.
  - The token is never written to the file, returned or logged.
version_added: "1.0.0"
author:
  - AUTHOR_NAME
options:
  path:
    description: Absolute path of the record file. Its directory must already exist.
    type: path
    required: true
  name:
    description: Name written into the record, one word that starts with a letter.
    type: str
    required: true
  count:
    description: Number written into the record, from 1 to 100.
    type: int
    default: 1
  state:
    description: Whether the record file is present or absent.
    type: str
    choices: [present, absent]
    default: present
  mode:
    description: Permissions of the record file, as four octal digits in a string.
    type: str
    default: "0600"
  token:
    description:
      - Secret used as the key of the signature written into the record.
      - Supplied at run time. It is never written to the file, returned or logged.
    type: str
attributes:
  check_mode:
    support: full
    description: Reports what an apply would change and changes nothing.
  diff_mode:
    support: full
    description: Returns the record's content before and after.
"""

EXAMPLES = r"""
- name: Write the record
  typed_module_record:
    path: /etc/EXAMPLE_SERVICE.record
    name: EXAMPLE_NAME
    count: 3

- name: Write the record with a signature, without logging the token
  typed_module_record:
    path: /etc/EXAMPLE_SERVICE.record
    name: EXAMPLE_NAME
    token: "{{ example_service_token }}"
  no_log: true

- name: Remove the record
  typed_module_record:
    path: /etc/EXAMPLE_SERVICE.record
    name: EXAMPLE_NAME
    state: absent
"""

RETURN = r"""
changed:
  description: Whether the apply changed, or in check mode would change, the record file.
  returned: always
  type: bool
action:
  description: What was done, or in check mode would be done.
  returned: success
  type: str
  sample: write
path:
  description: The record file's path.
  returned: success
  type: str
  sample: /etc/EXAMPLE_SERVICE.record
diff:
  description: The record's content before and after, shown by --diff.
  returned: success
  type: dict
"""

State = Literal["present", "absent"]
Action = Literal["none", "write", "chmod", "remove"]

COUNT_MIN = 1
COUNT_MAX = 100
NAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
MODE_PATTERN = re.compile(r"0[0-7]{3}")

_SCALAR_TYPES: dict[type, str] = {
    str: "str",
    int: "int",
    bool: "bool",
    float: "float",
    Path: "path",
}


class ValidationError(Exception):
    """A value that has the right type and is still not acceptable.

    Each subclass owns its message, so a message is stated once and a test can
    name the case it expects. None of them ever carries the token.
    """


class StateNotKnownError(ValidationError):
    """The state is neither present nor absent."""

    def __init__(self, state: str) -> None:
        super().__init__(f"state must be present or absent, got {state!r}")


class CountOutOfRangeError(ValidationError):
    """The count is outside the range the record allows."""

    def __init__(self, count: int) -> None:
        super().__init__(f"count must be between {COUNT_MIN} and {COUNT_MAX}, got {count}")


class NameNotAllowedError(ValidationError):
    """The name would not be one plain word in the record."""

    def __init__(self) -> None:
        super().__init__(
            "name must start with a letter and hold only letters, digits and underscores, "
            "at most 64 characters"
        )


class ModeNotAllowedError(ValidationError):
    """The mode is not four octal digits."""

    def __init__(self, mode: str) -> None:
        super().__init__(f"mode must be four octal digits such as 0600, got {mode!r}")


class TokenEmptyError(ValidationError):
    """A token was given with no content."""

    def __init__(self) -> None:
        super().__init__("token must not be empty when it is given")


class NotARegularFileError(ValidationError):
    """Something other than a regular file is at the record's path."""

    def __init__(self, path: Path) -> None:
        super().__init__(f"{path} exists and is not a regular file")


class DirectoryMissingError(ValidationError):
    """The directory the record would be written into does not exist."""

    def __init__(self, directory: Path) -> None:
        super().__init__(f"directory {directory} does not exist")


class SpecError(TypeError):
    """A parameter type or default that the argument_spec cannot state."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"{field}: {reason}")


class WrongTypeError(TypeError):
    """A value AnsibleModule validated is not the type the dataclass declares."""

    def __init__(self, key: str, expected: str) -> None:
        super().__init__(f"{key} is not {expected}")


REASON_CHOICES = "only string choices are supported"
REASON_OPTIONAL = "only 'X | None = None' unions are supported"
REASON_FACTORY = "a default_factory has no argument_spec form"
REASON_TYPE = "no argument_spec type for this annotation"


@dataclasses.dataclass(frozen=True)
class Params:
    """The module's parameters. The argument_spec is generated from this class."""

    path: Path
    name: str
    count: int = 1
    state: State = "present"
    mode: str = "0600"
    # repr=False keeps the secret out of any traceback or log line that prints the object.
    token: str | None = dataclasses.field(default=None, repr=False, metadata={"no_log": True})


@dataclasses.dataclass(frozen=True)
class Observed:
    """What the host holds now: None when the file does not exist."""

    content: str | None
    mode: int | None


@dataclasses.dataclass(frozen=True)
class Plan:
    """What an apply would do, with the content before and after for the diff."""

    action: Action
    before: str
    after: str

    @property
    def changed(self) -> bool:
        """Whether the plan changes anything."""
        return self.action != "none"


def _option_type(field: str, annotation: object) -> dict[str, object]:
    """Return the argument_spec ``type`` (and ``choices``, ``elements``) for one annotation.

    Raises:
        SpecError: when the annotation has no Ansible argument type.
    """
    origin = typing.get_origin(annotation)
    arguments = typing.get_args(annotation)
    if origin is Literal:
        if not all(isinstance(choice, str) for choice in arguments):
            raise SpecError(field, REASON_CHOICES)
        return {"type": "str", "choices": list(arguments)}
    if origin is list and len(arguments) == 1:
        return {"type": "list", "elements": _scalar(field, arguments[0])}
    return {"type": _scalar(field, annotation)}


def _scalar(field: str, annotation: object) -> str:
    """Return the argument_spec name of a scalar type.

    Raises:
        SpecError: when the type has no Ansible argument type.
    """
    if isinstance(annotation, type) and annotation in _SCALAR_TYPES:
        return _SCALAR_TYPES[annotation]
    raise SpecError(field, REASON_TYPE)


def build_argument_spec(model: "type[DataclassInstance]") -> dict[str, dict[str, object]]:
    """Generate the module's argument_spec from the dataclass that holds its parameters.

    A field without a default is required. ``X | None`` must default to None. A
    field with ``metadata={"no_log": True}`` is a secret.

    Raises:
        SpecError: when a field has a type or a default the argument_spec cannot state.
    """
    hints = typing.get_type_hints(model)
    spec: dict[str, dict[str, object]] = {}
    for field in dataclasses.fields(model):
        annotation = hints[field.name]
        optional = typing.get_origin(annotation) in (typing.Union, types.UnionType)
        if optional:
            members = [m for m in typing.get_args(annotation) if m is not type(None)]
            if len(members) != 1 or field.default is not None:
                raise SpecError(field.name, REASON_OPTIONAL)
            annotation = members[0]
        if field.default_factory is not dataclasses.MISSING:
            raise SpecError(field.name, REASON_FACTORY)
        option = _option_type(field.name, annotation)
        if field.default is dataclasses.MISSING:
            option["required"] = True
        elif field.default is not None:
            option["default"] = field.default
        if field.metadata.get("no_log"):
            option["no_log"] = True
        spec[field.name] = option
    return spec


ARGUMENT_SPEC = build_argument_spec(Params)


def _text(values: Mapping[str, object], key: str) -> str:
    """Return ``values[key]`` as a string.

    Raises:
        WrongTypeError: when the value is not a string.
    """
    value = values[key]
    if not isinstance(value, str):
        raise WrongTypeError(key, "a string")
    return value


def _whole(values: Mapping[str, object], key: str) -> int:
    """Return ``values[key]`` as an integer.

    Raises:
        WrongTypeError: when the value is not an integer.
    """
    value = values[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise WrongTypeError(key, "an integer")
    return value


def _state(text: str) -> State:
    """Return ``text`` as a state.

    Raises:
        StateNotKnownError: when the text is neither present nor absent.
    """
    if text == "present":
        return "present"
    if text == "absent":
        return "absent"
    raise StateNotKnownError(text)


def params_from_mapping(values: Mapping[str, object]) -> Params:
    """Build the typed parameters from the values AnsibleModule validated.

    Raises:
        WrongTypeError: when a value is not the type its field declares.
    """
    token = values.get("token")
    if token is not None and not isinstance(token, str):
        raise WrongTypeError("token", "a string")
    return Params(
        path=Path(_text(values, "path")),
        name=_text(values, "name"),
        count=_whole(values, "count"),
        state=_state(_text(values, "state")),
        mode=_text(values, "mode"),
        token=token,
    )


def validate(params: Params) -> None:
    """Refuse a value that has the right type and is still not acceptable.

    Raises:
        CountOutOfRangeError: when the count is outside the allowed range.
        NameNotAllowedError: when the name is not one plain word.
        ModeNotAllowedError: when the mode is not four octal digits.
        TokenEmptyError: when a token is given with no content.
    """
    if not COUNT_MIN <= params.count <= COUNT_MAX:
        raise CountOutOfRangeError(params.count)
    if NAME_PATTERN.fullmatch(params.name) is None:
        raise NameNotAllowedError
    if MODE_PATTERN.fullmatch(params.mode) is None:
        raise ModeNotAllowedError(params.mode)
    if params.token == "":
        raise TokenEmptyError


def render(params: Params) -> str:
    """Return the record's content. The token only keys the signature; it is never written."""
    lines = [f"name={params.name}", f"count={params.count}"]
    if params.token is not None:
        key = params.token.encode("utf-8")
        signature = hmac.new(key, params.name.encode("utf-8"), "sha256").hexdigest()
        lines.append(f"signature={signature}")
    return "\n".join(lines) + "\n"


def observe(path: Path) -> Observed:
    """Read the record file as the host holds it now.

    Raises:
        NotARegularFileError: when the path exists and is not a regular file.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return Observed(content=None, mode=None)
    if not stat.S_ISREG(info.st_mode):
        raise NotARegularFileError(path)
    return Observed(
        content=path.read_text(encoding="utf-8", errors="replace"),
        mode=stat.S_IMODE(info.st_mode),
    )


def plan(params: Params, observed: Observed) -> Plan:
    """Decide what an apply would do. A pure function: it reads nothing and writes nothing."""
    before = observed.content or ""
    if params.state == "absent":
        return Plan("none" if observed.content is None else "remove", before, "")
    wanted = render(params)
    if observed.content != wanted:
        return Plan("write", before, wanted)
    if observed.mode != int(params.mode, 8):
        return Plan("chmod", before, wanted)
    return Plan("none", before, wanted)


def _write_atomically(path: Path, content: str, mode: int) -> None:
    """Write ``content`` next to ``path`` with ``mode`` already set, then rename it into place."""
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def apply(params: Params, decided: Plan) -> None:
    """Carry out a plan. The only function that changes the host."""
    if decided.action == "remove":
        params.path.unlink()
    elif decided.action == "chmod":
        params.path.chmod(int(params.mode, 8))
    elif decided.action == "write":
        _write_atomically(params.path, decided.after, int(params.mode, 8))


def run(params: Params, *, check_mode: bool) -> Plan:
    """Validate, decide and, unless in check mode, apply. Return the plan.

    Raises:
        DirectoryMissingError: when the directory of a present file does not exist, in either mode.
    """
    validate(params)
    if params.state == "present" and not params.path.parent.is_dir():
        raise DirectoryMissingError(params.path.parent)
    decided = plan(params, observe(params.path))
    if decided.changed and not check_mode:
        apply(params, decided)
    return decided


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC, supports_check_mode=True)
    try:
        params = params_from_mapping(module.params)
        decided = run(params, check_mode=module.check_mode)
    except (ValidationError, OSError) as error:
        module.fail_json(msg=str(error))
    else:
        module.exit_json(
            changed=decided.changed,
            action=decided.action,
            path=str(params.path),
            diff={"before": decided.before, "after": decided.after},
        )


if __name__ == "__main__":
    main()
