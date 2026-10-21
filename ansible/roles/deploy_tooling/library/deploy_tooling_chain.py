#!/usr/bin/python
"""Read back the app-host firewall policy and fail unless the chains carry it.

Lists the IPv4 DOCKER-USER and INPUT chains and the IPv6 INPUT chain (and DOCKER-USER
where Docker made one), and checks the rules the policy program adds are all there in
the program's order and that nothing above its last drop can let a packet past. The
rules' literals are read from the program as installed, so the module restates none.
The README shows what the listing looks like.
"""

import dataclasses
import ipaddress
import re
import shlex
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Literal

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: deploy_tooling_chain
short_description: Check that the firewall chains carry the app-host isolation policy
description:
  - Lists the iptables and ip6tables filter tables and checks the chains the policy program
    writes to, without changing anything.
  - Fails when an owned rule is missing, is out of order, is one this host's variant must not
    carry, or when a foreign rule above the policy's last drop could let a packet past it.
  - Reads the rules' literals from the policy program installed on the host.
  - The IPv6 DOCKER-USER chain is checked only when the chain exists.
version_added: "1.0.0"
author:
  - branchLeft
options:
  reconciler_path:
    description: Absolute path of the installed policy program the rules' literals are read from.
    type: path
    required: true
  variant:
    description:
      - Which chain this host is expected to carry.
      - standard has the database exception and no protected-port drops.
      - protected_no_db has the protected-port drops and no database exception.
    type: str
    required: true
    choices: [standard, protected_no_db]
  foreign_chain_allowlist:
    description:
      - Names of chains other tools own. A rule above the policy's last drop may jump to one.
      - Any other rule there must be a drop or a reject with a match.
    type: list
    elements: str
    default: []
attributes:
  check_mode:
    support: full
    description: Reads only, so it behaves the same in check mode.
  diff_mode:
    support: none
"""

EXAMPLES = r"""
- name: Read the chains back
  deploy_tooling_chain:
    reconciler_path: /usr/local/sbin/EXAMPLE_POLICY_PROGRAM
    variant: standard
    foreign_chain_allowlist: []
"""

RETURN = r"""
changed:
  description: Always false; the module changes nothing.
  returned: always
  type: bool
owned_rules:
  description: How many of the policy's rules were found, over all chains checked.
  returned: success
  type: int
foreign_rules:
  description: How many other rules the checked chains hold. They are counted, not listed.
  returned: success
  type: int
"""

Variant = Literal["standard", "protected_no_db"]
Family = Literal["iptables", "ip6tables"]

DOCKER_USER = "DOCKER-USER"
INPUT = "INPUT"
ACCEPT = "ACCEPT"
DROP = "DROP"
DROPPING_TARGETS = frozenset({DROP, "REJECT"})
KNOWN_MATCH_MODULES = frozenset({"conntrack", "tcp", "udp"})
CHAIN_NAME = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_.-]{0,27}")
BRIDGE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,15}")
PORT = re.compile(r"[0-9]{1,5}")
CONNTRACK_STATES = frozenset({"ESTABLISHED", "RELATED"})

ARGUMENT_SPEC: dict[str, dict[str, object]] = {
    "reconciler_path": {"type": "path", "required": True},
    "variant": {"type": "str", "required": True, "choices": ["standard", "protected_no_db"]},
    "foreign_chain_allowlist": {"type": "list", "elements": "str", "default": []},
}

LITERAL_NAMES = (
    "SUBNET",
    "DB_PORT",
    "GATEWAY_PRIVATE_IP",
    "PROTECTED_ADDRESS",
    "PROTECTED_PORTS",
    "MAIL_SPOOL_BRIDGE",
    "METADATA_ADDRESS",
    "DB_HOST",
)
ASSIGNMENT = re.compile(r'^\s*(?P<name>[A-Z_]+)="(?P<value>[^"]*)"\s*$')
DEFAULTED = re.compile(r"^\$\{[A-Z_]+:-(?P<default>[^}]*)\}$")


class PolicyError(Exception):
    """A reason the chains are not the policy, or the check could not be made.

    Each subclass owns its message. None carries a rule from outside the policy except
    the one that broke it, and none a secret.
    """


class ReconcilerUnreadableError(PolicyError):
    """The installed policy program could not be read."""

    def __init__(self, path: Path, reason: str) -> None:
        super().__init__(f"cannot read the policy program at {path}: {reason}")


class LiteralMissingError(PolicyError):
    """The policy program no longer assigns a value this module reads from it."""

    def __init__(self, name: str, found: int) -> None:
        super().__init__(
            f"the policy program has {found} usable assignment(s) of {name}, expected exactly one; "
            "the module reads it from there and cannot check the chains without it"
        )


class LiteralInvalidError(PolicyError):
    """A value read from the policy program is not the shape the module expects."""

    def __init__(self, name: str, value: str) -> None:
        super().__init__(f"the policy program's {name} is {value!r}, which is not a usable value")


class ListingError(PolicyError):
    """The firewall tool could not list its filter table."""

    def __init__(self, tool: str, status: int, detail: str) -> None:
        super().__init__(f"{tool} could not list the filter table (exit {status}): {detail}")


class ChainAbsentError(PolicyError):
    """A chain the policy needs does not exist."""

    def __init__(self, family: Family, chain: str) -> None:
        super().__init__(f"{family} has no {chain} chain")


class RuleMissingError(PolicyError):
    """An owned rule is not in its chain."""

    def __init__(self, family: Family, chain: str, label: str, rendered: str) -> None:
        super().__init__(f"{family} {chain}: the {label} is missing; expected {rendered}")


class RuleMisplacedError(PolicyError):
    """An owned rule is in its chain, below a rule it must come before."""

    def __init__(self, family: Family, chain: str, label: str, order: Sequence[str]) -> None:
        super().__init__(
            f"{family} {chain}: the {label} is in the wrong place; the policy's rules must run in "
            f"this order: {', '.join(order)}"
        )


class RuleForbiddenError(PolicyError):
    """The chain carries an owned rule this host's variant must not carry."""

    def __init__(self, family: Family, chain: str, label: str, variant: str) -> None:
        super().__init__(
            f"{family} {chain}: the {label} is present, and a {variant} host must not carry it"
        )


class RuleBypassError(PolicyError):
    """A foreign rule above the policy's last drop could let a packet past it."""

    def __init__(self, family: Family, chain: str, text: str) -> None:
        super().__init__(
            f"{family} {chain}: a rule above the policy's last drop can let a packet past: {text}"
        )


class ParameterError(PolicyError):
    """A parameter the module was given is not usable."""

    def __init__(self, name: str, value: str) -> None:
        super().__init__(f"{name} {value!r} is not usable")


@dataclasses.dataclass(frozen=True)
class Params:
    """The module's parameters."""

    reconciler_path: Path
    variant: Variant
    foreign_chain_allowlist: frozenset[str]


@dataclasses.dataclass(frozen=True)
class Literals:
    """The values the policy program carries, read from it."""

    subnet: str
    db_port: str
    gateway_ip: str
    protected_address: str
    protected_ports: tuple[str, ...]
    mail_spool_bridge: str
    metadata_address: str
    db_host: str


@dataclasses.dataclass(frozen=True)
class Rule:
    """One rule as ``iptables -S`` prints it, reduced to the fields the policy uses.

    A rule with an option this parser does not know has it in ``extra``, so it is
    never equal to an owned rule, and it counts as a rule with a match.
    """

    target: str = ""
    goto: bool = False
    in_iface: str = ""
    out_iface: str = ""
    out_negated: bool = False
    src: str = ""
    src_negated: bool = False
    dst: str = ""
    protocol: str = ""
    dport: str = ""
    ctstate: frozenset[str] = frozenset()
    ctorigdst: str = ""
    ctorigdstport: str = ""
    extra: tuple[str, ...] = ()
    text: str = dataclasses.field(default="", compare=False)

    @property
    def has_match(self) -> bool:
        """Whether the rule matches on anything, so that it is not a rule for every packet."""
        return bool(
            self.in_iface
            or self.out_iface
            or self.src
            or self.dst
            or self.protocol
            or self.dport
            or self.ctstate
            or self.ctorigdst
            or self.ctorigdstport
            or self.extra
        )


@dataclasses.dataclass(frozen=True)
class Owned:
    """One rule the policy adds, with the name a message gives it."""

    label: str
    rule: Rule


@dataclasses.dataclass(frozen=True)
class ChainPolicy:
    """What one chain must carry, top to bottom, and what it must not."""

    family: Family
    chain: str
    owned: tuple[Owned, ...]
    forbidden: tuple[Owned, ...]
    only_if_present: bool


@dataclasses.dataclass(frozen=True)
class Table:
    """The chains of one filter table and the rules in each, in order."""

    chains: frozenset[str]
    rules: Mapping[str, tuple[Rule, ...]]


@dataclasses.dataclass(frozen=True)
class Result:
    """What a passing check found."""

    owned_rules: int
    foreign_rules: int


@dataclasses.dataclass(frozen=True)
class Listing:
    """The outcome of one list command."""

    status: int
    stdout: str
    stderr: str


Runner = Callable[[Family], Listing]


def normalise_address(value: str) -> str:
    """Return an address as the policy writes it: a host route's ``/32`` is dropped."""
    return value.removesuffix("/32")


def read_literals(text: str) -> Literals:
    """Read the values the policy program carries from its text.

    Raises:
        LiteralMissingError: when a value is not assigned exactly once.
        LiteralInvalidError: when a value is not an address, a port or a bridge name.
    """
    found: dict[str, list[str]] = {name: [] for name in LITERAL_NAMES}
    for line in text.splitlines():
        match = ASSIGNMENT.match(line)
        if match is None or match["name"] not in found:
            continue
        value = match["value"]
        defaulted = DEFAULTED.match(value)
        if defaulted is not None:
            value = defaulted["default"]
        elif "$" in value:
            continue
        if value:
            found[match["name"]].append(value)
    for name, values in found.items():
        if len(values) != 1:
            raise LiteralMissingError(name, len(values))
    return _checked_literals({name: values[0] for name, values in found.items()})


def _checked_literals(values: Mapping[str, str]) -> Literals:
    """Return the literals once every value has the shape it needs.

    Raises:
        LiteralInvalidError: when a value is not an address, a port or a bridge name.
    """
    for name in (
        "SUBNET",
        "GATEWAY_PRIVATE_IP",
        "PROTECTED_ADDRESS",
        "METADATA_ADDRESS",
        "DB_HOST",
    ):
        if not _plausible(name, values[name]):
            raise LiteralInvalidError(name, values[name])
    ports = tuple(values["PROTECTED_PORTS"].split())
    for name, value in (("DB_PORT", values["DB_PORT"]), *(("PROTECTED_PORTS", p) for p in ports)):
        if PORT.fullmatch(value) is None:
            raise LiteralInvalidError(name, value)
    if not ports:
        raise LiteralInvalidError("PROTECTED_PORTS", values["PROTECTED_PORTS"])
    if BRIDGE_NAME.fullmatch(values["MAIL_SPOOL_BRIDGE"]) is None:
        raise LiteralInvalidError("MAIL_SPOOL_BRIDGE", values["MAIL_SPOOL_BRIDGE"])
    return Literals(
        subnet=values["SUBNET"],
        db_port=values["DB_PORT"],
        gateway_ip=values["GATEWAY_PRIVATE_IP"],
        protected_address=values["PROTECTED_ADDRESS"],
        protected_ports=ports,
        mail_spool_bridge=values["MAIL_SPOOL_BRIDGE"],
        metadata_address=values["METADATA_ADDRESS"],
        db_host=values["DB_HOST"],
    )


def _plausible(name: str, value: str) -> bool:
    """Return whether ``value`` parses as the kind of address ``name`` holds."""
    try:
        if name == "SUBNET":
            ipaddress.ip_network(value)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_rule(line: str) -> tuple[str, Rule]:
    """Parse one ``-A`` line of ``iptables -S`` into its chain and a rule.

    A line the parser cannot read, or an option it does not know, ends up in the
    rule's ``extra``: such a rule is foreign and counts as having a match.
    """
    try:
        words = shlex.split(line)
    except ValueError:
        return "", Rule(extra=("unparsed",), text=line)
    chain = words[1] if len(words) > 1 else ""
    fields: dict[str, object] = {}
    extra: list[str] = []
    negate = False
    index = 2
    while index < len(words):
        word = words[index]
        value = words[index + 1] if index + 1 < len(words) else ""
        if word == "!":
            negate = True
            index += 1
            continue
        consumed = 2
        if word in ("-m", "--match") and value in KNOWN_MATCH_MODULES:
            pass
        elif word in ("-s", "--source"):
            fields["src"], fields["src_negated"] = normalise_address(value), negate
            negate = False
        elif word in ("-o", "--out-interface"):
            fields["out_iface"], fields["out_negated"] = value, negate
            negate = False
        elif word in _PLAIN_OPTIONS and not negate:
            fields[_PLAIN_OPTIONS[word]] = value
        elif word == "--ctstate" and not negate:
            fields["ctstate"] = frozenset(value.split(","))
        elif word in ("-j", "--jump", "-g", "--goto"):
            fields["target"], fields["goto"] = value, word in ("-g", "--goto")
        else:
            # An option this parser does not know. Its value is read as the next word and
            # lands here too, so nothing after it can be mistaken for a known option.
            extra.append(word)
            consumed = 1
        if negate:
            extra.append("!")
        negate = False
        index += consumed
    return chain, _build_rule(fields, tuple(extra), line)


_PLAIN_OPTIONS: Mapping[str, str] = {
    "-i": "in_iface",
    "--in-interface": "in_iface",
    "-d": "dst",
    "--destination": "dst",
    "-p": "protocol",
    "--protocol": "protocol",
    "--dport": "dport",
    "--destination-port": "dport",
    "--ctorigdst": "ctorigdst",
    "--ctorigdstport": "ctorigdstport",
}


def _build_rule(fields: Mapping[str, object], extra: tuple[str, ...], text: str) -> Rule:
    """Build a rule from the parsed fields, with addresses normalised."""
    state = fields.get("ctstate")
    return Rule(
        target=str(fields.get("target", "")),
        goto=bool(fields.get("goto", False)),
        in_iface=str(fields.get("in_iface", "")),
        out_iface=str(fields.get("out_iface", "")),
        out_negated=bool(fields.get("out_negated", False)),
        src=str(fields.get("src", "")),
        src_negated=bool(fields.get("src_negated", False)),
        dst=normalise_address(str(fields.get("dst", ""))),
        protocol=str(fields.get("protocol", "")),
        dport=str(fields.get("dport", "")),
        ctstate=state if isinstance(state, frozenset) else frozenset(),
        ctorigdst=normalise_address(str(fields.get("ctorigdst", ""))),
        ctorigdstport=str(fields.get("ctorigdstport", "")),
        extra=extra,
        text=text,
    )


def parse_listing(text: str) -> Table:
    """Parse the output of ``iptables -S`` or ``ip6tables -S`` into chains and rules."""
    chains: set[str] = set()
    rules: dict[str, list[Rule]] = {}
    for line in text.splitlines():
        if line.startswith(("-N ", "-P ")):
            chains.add(line.split()[1])
        elif line.startswith("-A "):
            chain, rule = parse_rule(line)
            chains.add(chain)
            rules.setdefault(chain, []).append(rule)
    return Table(
        chains=frozenset(chains),
        rules={chain: tuple(found) for chain, found in rules.items()},
    )


def render(rule: Rule) -> str:
    """Return the rule as the option string the policy program passes to the firewall tool."""
    parts: list[str] = []
    if rule.in_iface:
        parts += ["-i", rule.in_iface]
    if rule.out_iface:
        parts += ["!" if rule.out_negated else "", "-o", rule.out_iface]
    if rule.src:
        parts += ["!" if rule.src_negated else "", "-s", rule.src]
    if rule.dst:
        parts += ["-d", rule.dst]
    if rule.protocol:
        parts += ["-p", rule.protocol]
    if rule.dport:
        parts += ["--dport", rule.dport]
    if rule.ctstate:
        parts += ["-m", "conntrack", "--ctstate", ",".join(sorted(rule.ctstate))]
    if rule.ctorigdst:
        parts += ["--ctorigdst", rule.ctorigdst, "--ctorigdstport", rule.ctorigdstport]
    parts += ["-j", rule.target]
    return " ".join(part for part in parts if part)


def _established_accept(bridge: str = "") -> Rule:
    return Rule(target=ACCEPT, in_iface=bridge, ctstate=CONNTRACK_STATES)


def _spool_forward_drop(literals: Literals) -> Owned:
    return Owned(
        "spool bridge forward drop",
        Rule(
            target=DROP,
            in_iface=literals.mail_spool_bridge,
            out_iface=literals.mail_spool_bridge,
            out_negated=True,
        ),
    )


def _spool_input(literals: Literals) -> tuple[Owned, Owned]:
    return (
        Owned("spool bridge established accept", _established_accept(literals.mail_spool_bridge)),
        Owned("spool bridge input drop", Rule(target=DROP, in_iface=literals.mail_spool_bridge)),
    )


def _db_accept(literals: Literals) -> Owned:
    return Owned(
        "database accept",
        Rule(
            target=ACCEPT,
            dst=literals.db_host,
            protocol="tcp",
            dport=literals.db_port,
        ),
    )


def _protected_drops(literals: Literals) -> tuple[Owned, ...]:
    # The program inserts each at the same position, so the last port ends up first.
    return tuple(
        Owned(
            f"protected-port drop {port}",
            Rule(
                target=DROP,
                src=literals.gateway_ip,
                src_negated=True,
                protocol="tcp",
                ctorigdst=literals.protected_address,
                ctorigdstport=port,
            ),
        )
        for port in reversed(literals.protected_ports)
    )


def policies(literals: Literals, variant: Variant) -> tuple[ChainPolicy, ...]:
    """Return what each chain must carry on a host of ``variant``, from the program's literals."""
    database = (_db_accept(literals),)
    protected = _protected_drops(literals)
    standard = variant == "standard"
    docker_user = (
        Owned("established accept", _established_accept()),
        _spool_forward_drop(literals),
        *(() if standard else protected),
        *(database if standard else ()),
        Owned("subnet drop", Rule(target=DROP, dst=literals.subnet)),
        Owned("metadata drop", Rule(target=DROP, dst=literals.metadata_address)),
    )
    spool_input = _spool_input(literals)
    return (
        ChainPolicy(
            "iptables", DOCKER_USER, docker_user, protected if standard else database, False
        ),
        ChainPolicy("iptables", INPUT, spool_input, (), False),
        ChainPolicy("ip6tables", INPUT, spool_input, (), False),
        ChainPolicy("ip6tables", DOCKER_USER, (_spool_forward_drop(literals),), (), True),
    )


def check_chain(
    policy: ChainPolicy, table: Table, variant: str, allowed_chains: frozenset[str]
) -> Result:
    """Check one chain against its policy.

    Raises:
        ChainAbsentError: when a chain that must exist does not.
        RuleMissingError: when an owned rule is not in the chain.
        RuleMisplacedError: when an owned rule is in the chain, out of order.
        RuleForbiddenError: when the chain carries a rule this variant must not.
        RuleBypassError: when a foreign rule above the last drop could let a packet past it.
    """
    if policy.chain not in table.chains:
        if policy.only_if_present:
            return Result(0, 0)
        raise ChainAbsentError(policy.family, policy.chain)
    observed = table.rules.get(policy.chain, ())
    matched: dict[int, int] = {}
    for index, rule in enumerate(observed):
        wanted = len(matched)
        if wanted < len(policy.owned) and rule == policy.owned[wanted].rule:
            matched[wanted] = index
    if len(matched) < len(policy.owned):
        missing = policy.owned[len(matched)]
        if any(rule == missing.rule for rule in observed):
            raise RuleMisplacedError(
                policy.family,
                policy.chain,
                _displaced(policy, observed, missing.label),
                [o.label for o in policy.owned],
            )
        raise RuleMissingError(policy.family, policy.chain, missing.label, render(missing.rule))
    for forbidden in policy.forbidden:
        if any(rule == forbidden.rule for rule in observed):
            raise RuleForbiddenError(policy.family, policy.chain, forbidden.label, variant)
    last_drop = max(
        (matched[i] for i, owned in enumerate(policy.owned) if owned.rule.target == DROP),
        default=-1,
    )
    owned_positions = set(matched.values())
    for index, rule in enumerate(observed[:last_drop]):
        if index not in owned_positions and not _cannot_bypass(rule, allowed_chains):
            raise RuleBypassError(policy.family, policy.chain, rule.text)
    return Result(len(policy.owned), len(observed) - len(policy.owned))


def _displaced(policy: ChainPolicy, observed: Sequence[Rule], fallback: str) -> str:
    """Return the label of the owned rule whose move alone would put the chain in order.

    The in-order scan stops at the first rule that does not follow the one before it, which
    blames the rule after a displaced one. The rule to name is the first whose removal leaves
    the rest in order; when no single rule does, or one is absent, ``fallback`` is named.
    """
    positions: list[int] = []
    for owned in policy.owned:
        found = [index for index, rule in enumerate(observed) if rule == owned.rule]
        if not found:
            return fallback
        positions.append(found[0])
    for skip, owned in enumerate(policy.owned):
        rest = [place for index, place in enumerate(positions) if index != skip]
        if all(before < after for before, after in zip(rest, rest[1:], strict=False)):
            return owned.label
    return fallback


def _cannot_bypass(rule: Rule, allowed_chains: frozenset[str]) -> bool:
    """Return whether a foreign rule above the policy's last drop cannot let a packet past it.

    A drop or a reject with a match takes packets away and cannot add any. A jump to a
    chain another tool owns is allowed only by name, from the allow-list.
    """
    if rule.target in DROPPING_TARGETS and rule.has_match:
        return True
    return rule.target in allowed_chains and not rule.goto and not rule.extra


def check_all(params: Params, runner: Runner) -> Result:
    """Read the program's literals, list both tables and check every chain.

    Raises:
        ReconcilerUnreadableError: when the policy program cannot be read.
        PolicyError: when the chains are not the policy (a subclass names how).
    """
    try:
        text = params.reconciler_path.read_text(encoding="utf-8")
    except OSError as error:
        raise ReconcilerUnreadableError(
            params.reconciler_path, error.strerror or "unreadable"
        ) from error
    literals = read_literals(text)
    tables: dict[Family, Table] = {}
    owned = 0
    foreign = 0
    for policy in policies(literals, params.variant):
        if policy.family not in tables:
            tables[policy.family] = _list_table(policy.family, runner)
        found = check_chain(
            policy, tables[policy.family], params.variant, params.foreign_chain_allowlist
        )
        owned += found.owned_rules
        foreign += found.foreign_rules
    return Result(owned, foreign)


def _list_table(family: Family, runner: Runner) -> Table:
    """List one family's filter table.

    Raises:
        ListingError: when the tool exits non-zero.
    """
    listing = runner(family)
    if listing.status != 0:
        detail = listing.stderr.strip().splitlines()[:1]
        raise ListingError(family, listing.status, detail[0] if detail else "no output")
    return parse_listing(listing.stdout)


def params_from_mapping(values: Mapping[str, object]) -> Params:
    """Build the typed parameters from the values AnsibleModule validated.

    Raises:
        ParameterError: when a value is not the type or shape it must be.
    """
    variant: Variant
    given = values["variant"]
    allowlist = values["foreign_chain_allowlist"]
    path = values["reconciler_path"]
    if given == "standard":
        variant = "standard"
    elif given == "protected_no_db":
        variant = "protected_no_db"
    else:
        raise ParameterError("variant", str(given))
    if not isinstance(path, str):
        raise ParameterError("reconciler_path", str(path))
    if not isinstance(allowlist, list):
        raise ParameterError("foreign_chain_allowlist", str(allowlist))
    names = [str(name) for name in allowlist]
    for name in names:
        if CHAIN_NAME.fullmatch(name) is None:
            raise ParameterError("foreign_chain_allowlist", name)
    return Params(Path(path), variant, frozenset(names))


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC, supports_check_mode=True)

    def runner(family: Family) -> Listing:
        binary = module.get_bin_path(family, required=True)
        status, out, err = module.run_command([binary, "-w", "-t", "filter", "-S"], check_rc=False)
        return Listing(status, out, err)

    try:
        params = params_from_mapping(module.params)
        found = check_all(params, runner)
    except PolicyError as error:
        module.fail_json(msg=str(error))
    else:
        module.exit_json(
            changed=False,
            msg="the firewall chains carry the policy",
            owned_rules=found.owned_rules,
            foreign_rules=found.foreign_rules,
        )


if __name__ == "__main__":
    main()
