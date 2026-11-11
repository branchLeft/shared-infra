#!/usr/bin/python
"""Return the SHA-256 of the monitoring secrets file with one key's lines left out.

The role fingerprints its secrets file without the one line the stack does not read
(SNDS_DATA_URL, read only by the collector, rotated every 30 days). The digest is of the
same bytes that ``sed '/^KEY=/d' FILE | sha256sum`` hashed, so a host that holds a stamp
written by the earlier shell task computes the same fingerprint and does not restart.

The module reads the file once, line by line, and returns the digest only. It never
returns a line, a value or a byte count, and it never writes the file. It reads in check
mode too, so a plan sees the same digest an apply does.
"""

import hashlib
import re

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: monitoring_stack_envfile_digest
short_description: SHA-256 of a file with the lines of one key left out
description:
  - Reads the file at I(path), leaves out every line that starts with I(skip_key) followed by
    C(=), and returns the SHA-256 of the rest, as the bytes the file holds.
  - Returns the digest only. A line, a value and a byte count are never returned, and a refusal
    names the path and the reason, never a line.
  - Read-only. The file is not written, so the task reports no change in either mode.
version_added: "1.0.0"
author:
  - branchLeft
options:
  path:
    description: The file to hash.
    type: path
    required: true
  skip_key:
    description:
      - The key whose lines are left out. An upper-case name of letters, digits and underscores,
        not starting with a digit.
      - A line is left out when it starts with the key and an C(=), exactly as C(sed) matched it.
    type: str
    required: true
attributes:
  check_mode:
    support: full
    description: The module reads the file in check mode and in an apply alike.
  diff_mode:
    support: none
    description: The digest is of a file that holds secrets, so no diff is shown.
"""

EXAMPLES = r"""
- name: Hash the monitoring secrets file without the SNDS line
  monitoring_stack_envfile_digest:
    path: /etc/branchleft/monitoring.env
    skip_key: SNDS_DATA_URL
  register: monitoring_stack_env_hash
  no_log: true
  diff: false
"""

RETURN = r"""
digest:
  description: The SHA-256 of the file's bytes with the skipped key's lines left out, as 64
    lower-case hexadecimal characters.
  returned: success
  type: str
  sample: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
"""

KEY_PATTERN = re.compile(r"[A-Z_][A-Z0-9_]*\Z")


class DigestError(Exception):
    """The file cannot be read, or the key is not a plain name. Carries no part of the file."""


def digest_without_key(path: str, key: str) -> str:
    """Return the SHA-256 of the file's lines, leaving out those that start with ``key=``.

    Iterating a binary file splits it on b"\\n" only and keeps each line's end, which is the
    line model ``sed`` uses, so the digest equals the one the shell pipeline computed.

    Raises:
        DigestError: The key is not a plain name, or the file cannot be opened or read.
    """
    if KEY_PATTERN.match(key) is None:
        message = "skip_key must be an upper-case name of letters, digits and underscores"
        raise DigestError(message)
    prefix = f"{key}=".encode()
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for line in handle:
                if not line.startswith(prefix):
                    hasher.update(line)
    except OSError as error:
        message = f"{path} cannot be read ({error.strerror or type(error).__name__})"
        raise DigestError(message) from None
    return hasher.hexdigest()


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(
        argument_spec={
            "path": {"type": "path", "required": True},
            "skip_key": {"type": "str", "required": True},
        },
        supports_check_mode=True,
    )
    path = str(module.params["path"])
    try:
        digest = digest_without_key(path, str(module.params["skip_key"]))
    except DigestError as error:
        module.fail_json(msg=f"monitoring_stack_envfile_digest: {error}")
    module.exit_json(changed=False, digest=digest)


if __name__ == "__main__":
    main()
