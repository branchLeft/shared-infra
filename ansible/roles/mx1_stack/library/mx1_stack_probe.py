#!/usr/bin/python
"""The one read-only probe module of the mx1 stack (ANS-9).

Every check the role makes that is not a file write or a package install is an action of this
module: it reads the host, changes nothing and returns plain answers. Nothing it returns holds
a container's environment, a secret or the raw output of a command.

Actions: ``recursion`` (the local resolver answers), ``shim_cert`` (one gentle TLS connect),
``docker_health`` (containers run, are healthy and run the pinned image), ``container_fresh``
(a running container sees the current content of the files that it reads), ``unbound_checkconf``
(unbound accepts its assembled configuration) and ``port53`` (nothing but unbound holds port 53).
"""

import calendar
import hashlib
import ipaddress
import os
import re
import socket
import struct
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: mx1_stack_probe
short_description: Read-only checks of the mx1 stack
description:
  - C(recursion) asks the local resolver for a name with C(dig), and retries.
  - C(shim_cert) makes one TLS connection with C(openssl s_client) and says whether the certificate
      verifies. It never fails.
  - C(docker_health) says whether named containers run, are healthy and run the pinned image, and
      waits for the ones that are starting.
  - C(container_fresh) says, for each input a container reads, whether the running container has
      the current content. A file mounted into a container is read through C(docker exec); a file
      the container reads when it is created is judged by time.
  - C(unbound_checkconf) runs C(unbound-checkconf) on the assembled configuration.
  - C(port53) lists what holds port 53 and says whether anything but unbound does.
  - Changes nothing, in check mode or out of it. Returns no environment variable, no secret and no
      raw command output.
version_added: "1.0.0"
author:
  - branchLeft
options:
  action:
    description: What to check.
    type: str
    required: true
    choices: [recursion, shim_cert, docker_health, container_fresh, unbound_checkconf, port53]
  name:
    description: The name C(recursion) resolves.
    type: str
  tries:
    description: How many reads C(recursion) and C(docker_health) make.
    type: int
    default: 1
  interval:
    description: Seconds between reads.
    type: int
    default: 2
  host:
    description: The address C(shim_cert) connects to.
    type: str
    default: 127.0.0.1
  port:
    description: The port C(shim_cert) connects to.
    type: int
  servername:
    description: The name C(shim_cert) asks for, and expects in the answer.
    type: str
  containers:
    description: For C(docker_health), a list of C(name) and C(image) (the exact image reference of
      the compose file).
    type: list
    elements: dict
    default: []
  inputs:
    description:
      - For C(container_fresh), a list of C(name), C(service), C(container), C(path), C(kind) and
          C(container_path).
      - C(kind) is C(create_env) (read when the container is created) or C(bind_file) (mounted at
          C(container_path)).
    type: list
    elements: dict
    default: []
  proc_root:
    description: Where C(port53) reads the process table. Only a test changes it.
    type: path
    default: /proc
attributes:
  check_mode:
    support: full
    description: Every action only reads, so check mode and a real run are the same.
  diff_mode:
    support: none
    description: Nothing is changed.
"""

EXAMPLES = r"""
- name: Read whether the caddy container sees the Caddyfile on the host
  mx1_stack_probe:
    action: container_fresh
    inputs:
      - name: shim_caddyfile
        service: caddy
        container: mailgun-shim-caddy
        path: /etc/mailgun-shim/Caddyfile
        kind: bind_file
        container_path: /etc/caddy/Caddyfile
"""

RETURN = r"""
ok:
  description: Whether the check passed (C(docker_health), C(shim_cert), C(unbound_checkconf),
    C(port53)).
  returned: when the action judges something
  type: bool
stale_services:
  description: The services with an input the running container does not have, sorted.
  returned: when action is container_fresh
  type: list
  elements: str
results:
  description: One entry per input, with C(fresh), C(reason) and the two SHA-256 values of a
    mounted file.
  returned: when action is container_fresh
  type: list
  elements: dict
containers:
  description: One entry per container, with C(ok) and C(reason).
  returned: when action is docker_health
  type: list
  elements: dict
conflicts:
  description: What holds port 53 and is not unbound or the system stub resolver.
  returned: when action is port53
  type: list
  elements: dict
warning:
  description: A sentence for the operator when a warn-only check did not pass.
  returned: when action is shim_cert
  type: str
"""

# The one format string the role ever gives docker inspect. It names five fields and not
# Config.Env, so no environment variable can reach a result or a log.
INSPECT_FORMAT = (
    "{{.Created}}|{{.State.StartedAt}}|{{.State.Status}}|"
    "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.Config.Image}}"
)
SHA256_LINE = re.compile(r"(?P<digest>[0-9a-f]{64})  ")
TIMESTAMP = re.compile(
    r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<hour>\d{2}):(?P<minute>\d{2}):"
    r"(?P<second>\d{2})(?:\.(?P<fraction>\d{1,9}))?Z"
)
KIND_CREATE_ENV = "create_env"
KIND_BIND_FILE = "bind_file"
DNS_PORT = 53
STUB_RESOLVER = ipaddress.ip_address("127.0.0.53")
TCP_LISTEN = "0A"
UDP_UNCONNECTED = "07"
NS_PER_SECOND = 1_000_000_000
CHUNK = 1 << 16
OUTPUT_LIMIT = 400

ACTIONS = (
    "recursion",
    "shim_cert",
    "docker_health",
    "container_fresh",
    "unbound_checkconf",
    "port53",
)
Runner = Callable[[Sequence[str], str | None], tuple[int, str, str]]
Sleeper = Callable[[float], None]
Finder = Callable[[str], str | None]


class ProbeError(Exception):
    """A refusal. Its text is fixed words and names; it never carries a command's raw output."""


@dataclass(frozen=True)
class Inspected:
    """The five fields of a container that the probe reads."""

    created_ns: int
    started_ns: int
    status: str
    health: str
    image: str


def parse_timestamp_ns(text: str) -> int:
    """Return an RFC 3339 UTC time, as Docker prints it, in nanoseconds since the epoch.

    Raises:
        ProbeError: The text is not in that shape.
    """
    found = TIMESTAMP.fullmatch(text)
    if found is None:
        message = "a container time is not in the shape Docker prints"
        raise ProbeError(message)
    seconds = calendar.timegm(
        (
            int(found["year"]),
            int(found["month"]),
            int(found["day"]),
            int(found["hour"]),
            int(found["minute"]),
            int(found["second"]),
            0,
            0,
            0,
        )
    )
    fraction = (found["fraction"] or "").ljust(9, "0")
    return seconds * NS_PER_SECOND + int(fraction or "0")


def parse_inspect(stdout: str, container: str) -> Inspected:
    """Return the fields of one ``docker inspect --format`` line.

    Raises:
        ProbeError: The line does not hold five fields.
    """
    parts = stdout.strip().split("|")
    if len(parts) != 5:
        message = f"docker inspect of {container} did not print the five fields asked for"
        raise ProbeError(message)
    return Inspected(
        created_ns=parse_timestamp_ns(parts[0]),
        started_ns=parse_timestamp_ns(parts[1]),
        status=parts[2],
        health=parts[3],
        image=parts[4],
    )


def inspect_container(run: Runner, docker: str, container: str) -> Inspected | None:
    """Return a container's fields, or None when the container does not exist."""
    code, stdout, _stderr = run([docker, "inspect", "--format", INSPECT_FORMAT, container], None)
    if code != 0:
        return None
    return parse_inspect(stdout, container)


def file_sha256(path: str) -> str:
    """Return the SHA-256 of a file's bytes."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def container_sha256(run: Runner, docker: str, container: str, path: str) -> str | None:
    """Return the SHA-256 of a file as the running container reads it, or None."""
    code, stdout, _stderr = run([docker, "exec", container, "sha256sum", path], None)
    if code != 0:
        return None
    found = SHA256_LINE.match(stdout)
    return None if found is None else found["digest"]


def judge_input(
    entry: Mapping[str, str], inspected: Inspected | None, run: Runner, docker: str
) -> dict[str, object]:
    """Return the freshness of one input against the container that reads it."""
    result: dict[str, object] = {
        "name": entry["name"],
        "service": entry["service"],
        "container": entry["container"],
        "kind": entry["kind"],
        "fresh": False,
        "reason": "",
        "host_sha256": "",
        "container_sha256": "",
    }
    path = entry["path"]
    if inspected is None:
        result["reason"] = "no such container"
        return result
    if not os.path.isfile(path):
        result["reason"] = "the file is missing on the host"
        return result
    mtime_ns = os.stat(path).st_mtime_ns
    if entry["kind"] == KIND_CREATE_ENV:
        if mtime_ns > inspected.created_ns:
            result["reason"] = "the file is newer than the container's creation"
            return result
        result["fresh"] = True
        return result
    if inspected.status != "running":
        result["reason"] = "the container is not running, so it cannot be read"
        return result
    result["host_sha256"] = file_sha256(path)
    seen = container_sha256(run, docker, entry["container"], entry["container_path"])
    if seen is None:
        result["reason"] = "the container could not read the file"
        return result
    result["container_sha256"] = seen
    if seen != result["host_sha256"]:
        result["reason"] = "the container sees different content from the host"
    elif mtime_ns > inspected.started_ns:
        result["reason"] = "the file is newer than the container's start"
    else:
        result["fresh"] = True
    return result


def container_fresh(
    inputs: Sequence[Mapping[str, str]], run: Runner, docker: str
) -> dict[str, object]:
    """Return, for each input, whether its container has the current content.

    Raises:
        ProbeError: An input has an unknown kind, or a field is missing.
    """
    inspected: dict[str, Inspected | None] = {}
    results: list[dict[str, object]] = []
    for entry in inputs:
        for field_name in ("name", "service", "container", "path", "kind"):
            if not entry.get(field_name):
                message = f"an input has no {field_name}"
                raise ProbeError(message)
        if entry["kind"] not in (KIND_CREATE_ENV, KIND_BIND_FILE):
            message = (
                f"input {entry['name']} has kind {entry['kind']}, which is not read by a container"
            )
            raise ProbeError(message)
        if entry["kind"] == KIND_BIND_FILE and not entry.get("container_path"):
            message = f"input {entry['name']} is a mounted file with no container_path"
            raise ProbeError(message)
        container = entry["container"]
        if container not in inspected:
            inspected[container] = inspect_container(run, docker, container)
        results.append(judge_input(entry, inspected[container], run, docker))
    stale = sorted({str(item["service"]) for item in results if not item["fresh"]})
    return {"results": results, "stale_services": stale, "ok": not stale}


def container_reason(inspected: Inspected | None, image: str) -> str:
    """Return why a container is not ok, or an empty string when it is."""
    if inspected is None:
        return "no such container"
    if inspected.status != "running":
        return f"state is {inspected.status}, not running"
    if inspected.health not in ("none", "healthy"):
        return f"health is {inspected.health}"
    if inspected.image != image:
        return "runs an image other than the pinned one"
    return ""


def docker_health(
    containers: Sequence[Mapping[str, str]],
    run: Runner,
    docker: str,
    tries: int,
    interval: int,
    sleep: Sleeper,
) -> dict[str, object]:
    """Return whether every container runs, is healthy and runs its pinned image.

    A container still starting is read again, up to ``tries`` reads.
    """
    verdicts: list[dict[str, object]] = []
    for attempt in range(max(1, tries)):
        verdicts = []
        for entry in containers:
            reason = container_reason(inspect_container(run, docker, entry["name"]), entry["image"])
            verdicts.append({"name": entry["name"], "ok": reason == "", "reason": reason})
        if all(verdict["ok"] for verdict in verdicts):
            break
        if attempt + 1 < max(1, tries):
            sleep(interval)
    return {"ok": all(verdict["ok"] for verdict in verdicts), "containers": verdicts}


def recursion(
    run: Runner, dig: str, name: str, tries: int, interval: int, sleep: Sleeper
) -> dict[str, object]:
    """Ask the local resolver for ``name`` until it answers with an address.

    Raises:
        ProbeError: The resolver never answered with an address.
    """
    argv = [dig, "+short", "+time=3", "+tries=1", "@127.0.0.1", "A", name]
    for attempt in range(max(1, tries)):
        _code, stdout, _stderr = run(argv, None)
        if any(is_address(line.strip()) for line in stdout.splitlines()):
            return {"changed": False, "ok": True}
        if attempt + 1 < max(1, tries):
            sleep(interval)
    message = (
        f"unbound is running but did not resolve {name} via 127.0.0.1: recursion is not "
        "working, and DNSBL results cannot be trusted until it is fixed"
    )
    raise ProbeError(message)


def is_address(text: str) -> bool:
    """Return whether a line is an IP address."""
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def shim_cert(
    run: Runner, openssl: str | None, host: str, port: int, servername: str
) -> dict[str, object]:
    """Make one TLS connection and say whether the certificate verifies. Never fails."""
    if openssl is None:
        return {"ok": False, "warning": "openssl is missing, so the certificate was not checked"}
    _code, stdout, _stderr = run(
        [openssl, "s_client", "-connect", f"{host}:{port}", "-servername", servername], ""
    )
    if servername in stdout and "Verify return code: 0" in stdout:
        return {"ok": True, "warning": ""}
    return {
        "ok": False,
        "warning": (
            f"could not confirm a verified {servername} certificate on port {port}; a fresh ACME "
            "issuance can take a few seconds after the container reports healthy, so look by hand "
            "before treating this as a failure"
        ),
    }


def unbound_checkconf(run: Runner, checkconf: str) -> dict[str, object]:
    """Run unbound's check over the assembled configuration.

    Raises:
        ProbeError: unbound rejects the configuration.
    """
    code, stdout, stderr = run([checkconf], None)
    if code != 0:
        detail = " ".join((stderr or stdout).split())[:OUTPUT_LIMIT]
        message = f"unbound-checkconf rejected the configuration: {detail}"
        raise ProbeError(message)
    return {"changed": False, "ok": True}


def decode_address(hex_address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Return the address of a /proc/net socket line.

    Raises:
        ProbeError: The field is not an address in the kernel's shape.
    """
    try:
        raw = bytes.fromhex(hex_address)
    except ValueError:
        message = "a socket address in /proc/net is not hexadecimal"
        raise ProbeError(message) from None
    if len(raw) == 4:
        return ipaddress.IPv4Address(
            socket.inet_ntoa(struct.pack("<I", int.from_bytes(raw, "big")))
        )
    if len(raw) == 16:
        words = [raw[index : index + 4][::-1] for index in range(0, 16, 4)]
        return ipaddress.IPv6Address(b"".join(words))
    message = "a socket address in /proc/net has an unexpected length"
    raise ProbeError(message)


def dns_sockets(proc_root: str) -> list[tuple[str, str, str]]:
    """Return (protocol, address, inode) for each socket bound to port 53."""
    found: list[tuple[str, str, str]] = []
    tables = (
        ("tcp", TCP_LISTEN),
        ("tcp6", TCP_LISTEN),
        ("udp", UDP_UNCONNECTED),
        ("udp6", UDP_UNCONNECTED),
    )
    for protocol, state in tables:
        try:
            with open(os.path.join(proc_root, "net", protocol), encoding="utf-8") as handle:
                rows = handle.read().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if len(fields) < 10:
                continue
            hex_address, _, hex_port = fields[1].partition(":")
            if int(hex_port, 16) != DNS_PORT or fields[3] != state:
                continue
            found.append((protocol, str(decode_address(hex_address)), fields[9]))
    return found


def socket_owners(proc_root: str, inodes: set[str]) -> dict[str, str]:
    """Return the name of the process that holds each socket inode, where it can be read."""
    owners: dict[str, str] = {}
    try:
        entries = sorted(os.listdir(proc_root))
    except OSError:
        return owners
    for entry in entries:
        if not entry.isdigit():
            continue
        descriptors = os.path.join(proc_root, entry, "fd")
        try:
            for descriptor in os.listdir(descriptors):
                target = os.readlink(os.path.join(descriptors, descriptor))
                held = target.removeprefix("socket:[").removesuffix("]")
                if target.startswith("socket:[") and held in inodes and held not in owners:
                    with open(os.path.join(proc_root, entry, "comm"), encoding="utf-8") as comm:
                        owners[held] = comm.read().strip()
        except OSError:
            continue
    return owners


def port53(proc_root: str) -> dict[str, object]:
    """List what holds port 53, and the holders that are not unbound or the system stub."""
    sockets = dns_sockets(proc_root)
    owners = socket_owners(proc_root, {inode for _, _, inode in sockets})
    holders: list[dict[str, str]] = []
    conflicts: list[dict[str, str]] = []
    for protocol, address, inode in sockets:
        holder = owners.get(inode, "unknown")
        entry = {"protocol": protocol, "address": address, "holder": holder}
        holders.append(entry)
        if holder != "unbound" and ipaddress.ip_address(address) != STUB_RESOLVER:
            conflicts.append(entry)
    return {"ok": not conflicts, "holders": holders, "conflicts": conflicts}


def as_entries(raw: object) -> list[dict[str, str]]:
    """Return a module list parameter as dicts of strings."""
    if not isinstance(raw, list):
        return []
    return [
        {str(key): str(value) for key, value in item.items()}
        for item in raw
        if isinstance(item, Mapping)
    ]


def require_tool(find: Finder, name: str, reason: str) -> str:
    """Return the path of a program the check needs.

    Raises:
        ProbeError: The program is not on the host.
    """
    path = find(name)
    if path is None:
        message = f"{name} is missing, {reason}"
        raise ProbeError(message)
    return path


def dispatch(
    params: Mapping[str, object], run: Runner, find: Finder, sleep: Sleeper
) -> dict[str, object]:
    """Run the action the parameters name and return its answer.

    Raises:
        ProbeError: The check failed, or a program it needs is missing.
    """
    action = str(params["action"])
    tries = int(str(params["tries"]))
    interval = int(str(params["interval"]))
    if action == "recursion":
        dig = require_tool(
            find, "dig", "so the recursion check cannot run (package bind9-dnsutils)"
        )
        return recursion(run, dig, str(params["name"]), tries, interval, sleep)
    if action == "shim_cert":
        return shim_cert(
            run,
            find("openssl"),
            str(params["host"]),
            int(str(params["port"])),
            str(params["servername"]),
        )
    if action == "docker_health":
        docker = require_tool(find, "docker", "so containers cannot be read")
        return docker_health(as_entries(params["containers"]), run, docker, tries, interval, sleep)
    if action == "container_fresh":
        docker = require_tool(find, "docker", "so containers cannot be read")
        return container_fresh(as_entries(params["inputs"]), run, docker)
    if action == "unbound_checkconf":
        checkconf = require_tool(
            find, "unbound-checkconf", "so the configuration cannot be checked"
        )
        return unbound_checkconf(run, checkconf)
    return port53(str(params["proc_root"]))


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(
        argument_spec={
            "action": {"type": "str", "required": True, "choices": list(ACTIONS)},
            "name": {"type": "str"},
            "tries": {"type": "int", "default": 1},
            "interval": {"type": "int", "default": 2},
            "host": {"type": "str", "default": "127.0.0.1"},
            "port": {"type": "int"},
            "servername": {"type": "str"},
            "containers": {"type": "list", "elements": "dict", "default": []},
            "inputs": {"type": "list", "elements": "dict", "default": []},
            "proc_root": {"type": "path", "default": "/proc"},
        },
        required_if=[
            ("action", "recursion", ["name"]),
            ("action", "shim_cert", ["port", "servername"]),
        ],
        supports_check_mode=True,
    )

    def run(argv: Sequence[str], data: str | None) -> tuple[int, str, str]:
        code, stdout, stderr = module.run_command(list(argv), data=data, check_rc=False)
        return int(code), str(stdout), str(stderr)

    try:
        result = dispatch(module.params, run, module.get_bin_path, time.sleep)
    except ProbeError as error:
        module.fail_json(msg=f"mx1 {module.params['action']}: {error}")
    else:
        result.setdefault("changed", False)
        module.exit_json(**result)


if __name__ == "__main__":
    main()
