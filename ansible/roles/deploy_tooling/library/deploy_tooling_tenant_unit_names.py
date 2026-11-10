#!/usr/bin/python
"""Work out which tenant instances of the compose template unit the role enables.

The host's tenant list is the only source of a name. A tenant name is held to the rules
the tenant stack role applies (the pattern, the length, the reserved mail spool name),
because this role runs before that one and must not enable an instance for a name it
would refuse. A name the caller asks for that is not in the host's list is refused too.
A refusal says which position was wrong and why, never the name: a plan log is public
and a tenant's name is not for it.
"""

import re
from collections.abc import Sequence
from typing import Final

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: deploy_tooling_tenant_unit_names
short_description: Name the tenant instances of the compose template unit to enable
description:
  - Turns the host's tenant names into the names of the unit instances the role enables.
  - Refuses a tenant name the tenant stack role would refuse, a repeated name, and a
    requested name that is not one of the host's tenants.
  - A refusal names a position and a reason, never a tenant's name.
  - Changes nothing, so it runs in check mode and reports no change.
version_added: "1.0.0"
author:
  - branchLeft
options:
  known:
    description:
      - The names of the host's tenants, from the host's tenant list.
    type: list
    elements: str
    required: true
  requested:
    description:
      - The tenants to enable, each of which must be in known. Empty means every tenant in known.
    type: list
    elements: str
    default: []
  unit_prefix:
    description:
      - The part of the template unit's name before the at sign.
    type: str
    required: true
"""

EXAMPLES = r"""
- name: Name the instances to enable
  deploy_tooling_tenant_unit_names:
    known: "{{ example_tenant_names }}"
    requested: []
    unit_prefix: EXAMPLE-PREFIX
"""

RETURN = r"""
changed:
  description: Always false; the module changes nothing.
  returned: always
  type: bool
count:
  description: How many instances were named.
  returned: success
  type: int
ansible_facts:
  description: deploy_tooling_tenant_unit_list, the full unit names, in the order of the list.
  returned: success
  type: dict
"""

ARGUMENT_SPEC: Final[dict[str, dict[str, object]]] = {
    "known": {"type": "list", "elements": "str", "required": True},
    "requested": {"type": "list", "elements": "str", "default": []},
    "unit_prefix": {"type": "str", "required": True},
}

# Copied from the tenant stack role's check (ANS-12 forbids importing it); a unit test holds
# each to the original.
SLUG_PATTERN: Final = re.compile(r"[a-z]([a-z0-9-]*[a-z0-9])?")
SLUG_MAX_LENGTH: Final = 26
SPOOL_SLUG: Final = "mail-spool"
PREFIX_PATTERN: Final = re.compile(r"[a-z][a-z0-9-]*")
FACT_NAME: Final = "deploy_tooling_tenant_unit_list"


class TenantUnitError(Exception):
    """A reason a tenant instance cannot be named. It carries a position, never a name."""


def _check_name(slug: str, where: str) -> None:
    """Refuse a name that is not a tenant name, saying where it was and why.

    Raises:
        TenantUnitError: the name breaks the tenant name rules, or is the mail spool's.
    """
    if SLUG_PATTERN.fullmatch(slug) is None or len(slug) > SLUG_MAX_LENGTH:
        message = (
            f"{where} is not a tenant name (lower case, digits and hyphens, "
            f"at most {SLUG_MAX_LENGTH})"
        )
        raise TenantUnitError(message)
    if slug == SPOOL_SLUG:
        message = f"{where} is the mail spool's name, which no tenant may have"
        raise TenantUnitError(message)


def unit_names(known: Sequence[str], requested: Sequence[str], prefix: str) -> list[str]:
    """Return the unit names to enable, in order.

    Raises:
        TenantUnitError: the prefix is not one, a name in either list is not a tenant name or
            is repeated, or a requested name is not in the host's list.
    """
    if PREFIX_PATTERN.fullmatch(prefix) is None:
        message = "the unit prefix is not a unit name prefix"
        raise TenantUnitError(message)
    for index, slug in enumerate(known, start=1):
        _check_name(slug, f"tenant {index} of the host's list")
    if len(set(known)) != len(known):
        message = "the host's tenant list repeats a tenant"
        raise TenantUnitError(message)
    for index, slug in enumerate(requested, start=1):
        if slug not in known:
            message = f"requested unit {index} is not one of the host's tenants"
            raise TenantUnitError(message)
    if len(set(requested)) != len(requested):
        message = "the requested units repeat a tenant"
        raise TenantUnitError(message)
    wanted = list(requested) if requested else list(known)
    return [f"{prefix}@{slug}.service" for slug in wanted]


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC, supports_check_mode=True)
    try:
        listed = unit_names(
            module.params["known"], module.params["requested"], module.params["unit_prefix"]
        )
    except TenantUnitError as error:
        module.fail_json(msg=str(error))
    else:
        module.exit_json(changed=False, count=len(listed), ansible_facts={FACT_NAME: listed})


if __name__ == "__main__":
    main()
