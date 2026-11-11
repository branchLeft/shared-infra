#!/usr/bin/python
"""Say which of a list of keys a secrets file holds with a value, and return the names only.

The role needs to know whether the pager's secrets file is usable (every one of its four keys
on a line with something after the ``=``) without reading a value into a variable or a log. The
module reads the file once, line by line, and returns the names of the keys that are missing
and one flag. It never returns a line, a value or a byte count, and it never writes the file.
It reads in check mode too, so a plan sees what an apply sees. A file that does not exist is
not an error: it is the case the caller is asking about, so every key is missing.
"""

import re

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: monitoring_stack_envfile_keys
short_description: Names of the keys a secrets file lacks a value for
description:
  - Reads the file at I(path) and checks each name in I(keys). A key is present when some line
    starts with the key and an C(=) and has at least one character other than white space after it.
  - Returns the names of the keys that are not present, and C(configured), true when none is
    missing. A line, a value and a byte count are never returned.
  - A file that does not exist reports every key as missing. Any other failure to read the file
    is a refusal that names the path and the reason, never a line.
  - Read-only. The file is not written, so the task reports no change in either mode.
version_added: "1.0.0"
author:
  - branchLeft
options:
  path:
    description: The file to read.
    type: path
    required: true
  keys:
    description:
      - The names to look for. Each is an upper-case name of letters, digits and underscores,
        not starting with a digit.
    type: list
    elements: str
    required: true
attributes:
  check_mode:
    support: full
    description: The module reads the file in check mode and in an apply alike.
  diff_mode:
    support: none
    description: The file holds secrets, so no diff is shown.
"""

EXAMPLES = r"""
- name: Find out whether the pager's secrets file holds all four keys
  monitoring_stack_envfile_keys:
    path: /etc/branchleft/ntfy-pager.env
    keys:
      - NTFY_PAGER_TOKEN
  register: monitoring_stack_pager_state
  no_log: true
"""

RETURN = r"""
configured:
  description: True when every key in I(keys) has a line with a value.
  returned: success
  type: bool
missing:
  description: The names, in the order given, of the keys without a line that has a value.
  returned: success
  type: list
  elements: str
"""

KEY_PATTERN = re.compile(r"[A-Z_][A-Z0-9_]*\Z")


class KeysError(Exception):
    """The file cannot be read, or a key is not a plain name. Carries no part of the file."""


def present_keys(lines: list[bytes], keys: list[str]) -> set[str]:
    """Return the keys among ``keys`` that start a line and have a non-blank value after the ``=``.

    A line is a key and an ``=`` at its start and then at least one character that is not white
    space. The comparison is on bytes, as the file is read, so a value is never decoded.
    """
    found: set[str] = set()
    for key in keys:
        prefix = f"{key}=".encode()
        for line in lines:
            if line.startswith(prefix) and line[len(prefix) :].strip():
                found.add(key)
                break
    return found


def missing_keys(path: str, keys: list[str]) -> list[str]:
    """Return the names of the keys the file at ``path`` has no value for, in the order given.

    Raises:
        KeysError: A key is not a plain name, or the file exists and cannot be read.
    """
    for key in keys:
        if KEY_PATTERN.match(key) is None:
            message = "each key must be an upper-case name of letters, digits and underscores"
            raise KeysError(message)
    try:
        with open(path, "rb") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return list(keys)
    except OSError as error:
        message = f"{path} cannot be read ({error.strerror or type(error).__name__})"
        raise KeysError(message) from None
    found = present_keys(lines, keys)
    return [key for key in keys if key not in found]


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(
        argument_spec={
            "path": {"type": "path", "required": True},
            "keys": {"type": "list", "elements": "str", "required": True},
        },
        supports_check_mode=True,
    )
    keys = [str(key) for key in module.params["keys"]]
    try:
        missing = missing_keys(str(module.params["path"]), keys)
    except KeysError as error:
        module.fail_json(msg=f"monitoring_stack_envfile_keys: {error}")
    module.exit_json(changed=False, configured=not missing, missing=missing)


if __name__ == "__main__":
    main()
