#!/usr/bin/python
"""Check that a spool's drain port listens on the loopback address and on nothing else.

The path from ops1 rests on the spool's drain listener being bound to the far host's loopback
address. A wildcard or public bind would put the drain port on the network, so this module reads
the host's listening sockets with `ss` and reports whether the port is listening, where, and
whether anything but the loopback address holds it. It changes nothing and runs in check mode.
"""

from dataclasses import dataclass, field
from typing import Final

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: spool_path_listener_check
short_description: Check that a TCP port listens on the loopback address only
description:
  - Runs C(ss -H -ltn) and reads the local address of every listening socket on I(port).
  - Reports I(loopback) true when the loopback address listens, and I(others) as the other local
    addresses that hold the port, which is empty when the bind is loopback only.
version_added: "1.0.0"
author:
  - branchLeft
options:
  port:
    description: The TCP port to look for.
    type: int
    required: true
  loopback:
    description: The loopback address the port must be bound to.
    type: str
    default: 127.0.0.1
attributes:
  check_mode:
    support: full
    description: The module only reads.
  diff_mode:
    support: none
    description: The module changes nothing.
"""

EXAMPLES = r"""
- name: Check the drain port is loopback only
  spool_path_listener_check:
    port: 8095
  register: spool_path_account_listener
"""

RETURN = r"""
loopback:
  description: Whether the loopback address listens on the port.
  returned: success
  type: bool
others:
  description: Local addresses other than the loopback that hold the port.
  returned: success
  type: list
  elements: str
"""

SS: Final = "ss"
LOCAL_ADDRESS_FIELD: Final = 3


@dataclass
class Found:
    """The listening addresses of one port."""

    loopback: bool = False
    others: list[str] = field(default_factory=list)


def parse(output: str, port: int, loopback: str) -> Found:
    """Return where the port listens, from the output of `ss -H -ltn`."""
    found = Found()
    suffix = f":{port}"
    for line in output.splitlines():
        fields = line.split()
        if len(fields) <= LOCAL_ADDRESS_FIELD or not fields[LOCAL_ADDRESS_FIELD].endswith(suffix):
            continue
        address = fields[LOCAL_ADDRESS_FIELD].removesuffix(suffix)
        if address == loopback:
            found.loopback = True
        else:
            found.others.append(address)
    found.others.sort()
    return found


def main() -> None:
    """Run the module."""
    module = AnsibleModule(
        argument_spec={
            "port": {"type": "int", "required": True},
            "loopback": {"type": "str", "default": "127.0.0.1"},
        },
        supports_check_mode=True,
    )
    code, output, _ = module.run_command([module.get_bin_path(SS, required=True), "-H", "-ltn"])
    if code != 0:
        module.fail_json(msg="ss could not list the listening sockets")
    found = parse(output, int(module.params["port"]), str(module.params["loopback"]))
    module.exit_json(changed=False, loopback=found.loopback, others=found.others)


if __name__ == "__main__":
    main()
