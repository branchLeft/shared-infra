"""Filter that accepts only an ignore list of IP addresses and CIDR ranges.

The value must be one line of tokens separated by single spaces, and each token must parse as an
IPv4 or IPv6 address or network. A host name is refused: a character class cannot tell "cafe"
(hex letters, not an address) from an address, so each token is parsed.
"""

from __future__ import annotations

import ipaddress
import re

_ONE_LINE_OF_TOKENS = re.compile(r"[^\s]+(?: [^\s]+)*")


def ignoreip_is_valid(value: object) -> bool:
    """Return whether `value` is one line of space-separated addresses and CIDR ranges.

    Returns:
        True when the value is non-empty, has no newline or doubled separator, and every token
        parses with the standard library's ipaddress module; False otherwise.
    """
    if not isinstance(value, str) or _ONE_LINE_OF_TOKENS.fullmatch(value) is None:
        return False
    for token in value.split(" "):
        try:
            ipaddress.ip_network(token, strict=False)
        except ValueError:
            return False
    return True


class FilterModule:
    """Registers the ignore-list filter with Ansible."""

    def filters(self) -> dict[str, object]:
        """Return the filters this module provides."""
        return {"ignoreip_is_valid": ignoreip_is_valid}
