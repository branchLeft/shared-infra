#!/usr/bin/env python3
# ruff: noqa: TRY003
"""Re-key the tenants stack's state under a new passphrase, in CI. See tenants_state_rewrap.md."""

from __future__ import annotations

import argparse
import copy
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import urllib.parse
from collections.abc import Callable, Iterator, Mapping, Sequence
from types import FrameType
from typing import IO, Protocol

EXIT_OK = 0
EXIT_REFUSED = 1  # a gate said no; nothing was changed
EXIT_USAGE = 2
EXIT_ERROR = 3  # something failed before the state was touched
EXIT_RESTORED = 4  # the state was touched, a check failed, the aside copy was put back
EXIT_BROKEN = 5  # the state was touched, a check failed, and the aside copy could not be put back

# Pulumi writes a secret as an object carrying this signature, the value under
# `ciphertext` (or `plaintext` in an export that was asked to reveal secrets).
SECRET_SIG_KEY = "4dabf18193072939515e22adb298388d"  # noqa: S105
SECRET_SIG_VALUE = "1b47061264138c4ac30d75fd1eb44270"  # noqa: S105

STACKREFERENCE_TYPE = "pulumi:pulumi:StackReference"

# The pre-rewrite copy of the state object lives outside `.pulumi/`, so nothing
# Pulumi lists, removes or rewrites can reach it.
ASIDE_PREFIX = "aside"

JsonObject = dict[str, object]


class RefusalError(Exception):
    """A gate said no."""


class ToolError(Exception):
    """A step failed for a reason that is not a verdict on the state."""


class Report:
    """Everything this tool says: counts and resource types only, no id and no salt."""

    def __init__(self, summary_file: str | None = None) -> None:
        self.lines: list[str] = []
        self.summary_file = summary_file

    def line(self, text: str) -> None:
        self.lines.append(text)
        print(text, flush=True)

    def flush_summary(self, title: str) -> None:
        if not self.summary_file:
            return
        with open(self.summary_file, "a", encoding="utf-8") as fh:
            fh.write(f"## {title}\n\n```\n" + "\n".join(self.lines) + "\n```\n")


# ---------------------------------------------------------------------------
# The document: what the checkpoint holds, and the one change made to it
# ---------------------------------------------------------------------------


def walk_dicts(node: object) -> Iterator[JsonObject]:
    """Every object in a JSON document, without recursion."""
    pending: list[object] = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            yield current
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def without_secrets_providers(doc: JsonObject) -> JsonObject:
    """A shallow copy of the export, `deployment.secrets_providers` left out.

    That block carries the salt, which is not an encrypted value, and it is
    the one thing the rewrite changes, so both the scan and the equality check
    leave it out.
    """
    deployment = doc.get("deployment")
    if not isinstance(deployment, dict):
        return dict(doc)
    return {**doc, "deployment": {k: v for k, v in deployment.items() if k != "secrets_providers"}}


def deployment_of(doc: JsonObject) -> JsonObject:
    """The export's `deployment` object.

    Raises:
        RefusalError: when the document has none.
    """
    deployment = doc.get("deployment")
    if not isinstance(deployment, dict):
        raise RefusalError(
            "the export is not a `pulumi stack export` document (no `deployment` object)"
        )
    return deployment


def count_encrypted(doc: JsonObject) -> int:
    """Objects that are an encrypted value: a `ciphertext` key, or the secret signature."""
    return sum(
        "ciphertext" in obj or obj.get(SECRET_SIG_KEY) == SECRET_SIG_VALUE
        for obj in walk_dicts(without_secrets_providers(doc))
    )


def count_plaintext(doc: JsonObject) -> int:
    return sum("plaintext" in obj for obj in walk_dicts(without_secrets_providers(doc)))


@dataclasses.dataclass(frozen=True)
class Inspection:
    provider_type: str
    resource_count: int
    resource_types: dict[str, int]
    encrypted_values: int
    plaintext_values: int
    pending_operations: int


def inspect_export(doc: JsonObject) -> Inspection:
    """Read a `pulumi stack export` document into counts.

    Raises:
        RefusalError: when the document is not shaped like one.
    """
    deployment = deployment_of(doc)
    providers = deployment.get("secrets_providers")
    if not isinstance(providers, dict):
        raise RefusalError("the deployment has no `secrets_providers` block")
    resources = deployment.get("resources", [])
    if not isinstance(resources, list) or not all(isinstance(r, dict) for r in resources):
        raise RefusalError("the deployment's `resources` is not a list of objects")
    pending = deployment.get("pending_operations", [])
    if not isinstance(pending, list):
        raise RefusalError("the deployment's `pending_operations` is not a list")
    types: dict[str, int] = {}
    for resource in resources:
        kind = resource.get("type")
        name = kind if isinstance(kind, str) else "(no type)"
        types[name] = types.get(name, 0) + 1
    provider_type = providers.get("type")
    return Inspection(
        provider_type=provider_type if isinstance(provider_type, str) else "(none)",
        resource_count=len(resources),
        resource_types=dict(sorted(types.items())),
        encrypted_values=count_encrypted(doc),
        plaintext_values=count_plaintext(doc),
        pending_operations=len(pending),
    )


def gate_problems(found: Inspection, *, dropping: bool = False) -> list[str]:
    """Why this state may not be re-keyed. Empty when it may.

    With `dropping`, `found` is the inspection of the document after the reproducible
    ciphertexts were removed, so what is left is what no allowlist entry covers.
    """
    problems: list[str] = []
    if found.provider_type != "passphrase":
        problems.append(f"the secrets provider is `{found.provider_type}`, not `passphrase`")
    if found.encrypted_values and dropping:
        problems.append(
            f"{found.encrypted_values} encrypted value(s) remain after dropping the reproducible "
            "ones: a new passphrase would orphan them, so this route stops here"
        )
    elif found.encrypted_values:
        problems.append(
            f"{found.encrypted_values} encrypted value(s) are in the state: a new passphrase would "
            "orphan them, so this route stops here"
        )
    if found.plaintext_values:
        problems.append(f"{found.plaintext_values} `plaintext` value(s) are in the export")
    if found.pending_operations:
        problems.append(
            f"{found.pending_operations} pending operation(s) are in the state: "
            "an interrupted update has to be read before anything is imported"
        )
    if not found.resource_count:
        problems.append(
            "the state holds no resources, so it is not the state this route was built for"
        )
    return problems


def describe(found: Inspection, report: Report) -> None:
    report.line(f"secrets provider: {found.provider_type}")
    report.line(f"resources: {found.resource_count}")
    for kind, count in found.resource_types.items():
        report.line(f"  {count} x {kind}")
    report.line(f"encrypted values: {found.encrypted_values}")
    report.line(f"plaintext values: {found.plaintext_values}")
    report.line(f"pending operations: {found.pending_operations}")


# ---------------------------------------------------------------------------
# Encrypted values: where each one sits, and which can be re-derived
# ---------------------------------------------------------------------------

PathKey = str | int


def is_secret_object(obj: Mapping[str, object]) -> bool:
    """The test `count_encrypted` applies: a `ciphertext` key, or the secret signature."""
    return "ciphertext" in obj or obj.get(SECRET_SIG_KEY) == SECRET_SIG_VALUE


def path_order(path: tuple[PathKey, ...]) -> tuple[tuple[int, int, str], ...]:
    """A sort key that keeps list positions numeric and puts the same paths in the same order."""
    return tuple((0, k, "") if isinstance(k, int) else (1, 0, k) for k in path)


@dataclasses.dataclass(frozen=True)
class Ciphertext:
    """Where one encrypted value sits. Never the value, and never the resource id."""

    resource_type: str
    name: str  # the last segment of the resource's URN
    side: str  # `inputs`, `outputs`, or another key of the resource, or `(outside resources)`
    key_path: tuple[PathKey, ...]  # below the side
    location: tuple[PathKey, ...]  # from the document root

    @property
    def key_text(self) -> str:
        return ".".join(f"[{k}]" if isinstance(k, int) else k for k in self.key_path) or "(whole)"


def locate(doc: JsonObject, location: tuple[PathKey, ...]) -> Ciphertext:
    """Name the place `location` is in: its resource's type and URN name, and the side."""
    if (
        len(location) >= 5
        and location[0] == "deployment"
        and location[1] == "resources"
        and isinstance(location[2], int)
    ):
        resources = deployment_of(doc).get("resources")
        owner = resources[location[2]] if isinstance(resources, list) else None
        if isinstance(owner, dict):
            kind = owner.get("type")
            urn = owner.get("urn")
            return Ciphertext(
                resource_type=kind if isinstance(kind, str) else "(no type)",
                name=urn.split("::")[-1] if isinstance(urn, str) else "(no urn)",
                side=str(location[3]),
                key_path=location[4:],
                location=location,
            )
    return Ciphertext("(none)", "(none)", "(outside resources)", location, location)


def find_ciphertexts(doc: JsonObject) -> list[Ciphertext]:
    """Every encrypted value in the export, named by where it sits, in document order."""
    found: list[tuple[PathKey, ...]] = []
    pending: list[tuple[tuple[PathKey, ...], object]] = [((), without_secrets_providers(doc))]
    while pending:
        path, node = pending.pop()
        if isinstance(node, dict):
            if is_secret_object(node):
                found.append(path)
                continue
            pending.extend(((*path, str(k)), v) for k, v in node.items())
        elif isinstance(node, list):
            pending.extend(((*path, i), v) for i, v in enumerate(node))
    found.sort(key=path_order)
    return [locate(doc, path) for path in found]


@dataclasses.dataclass(frozen=True)
class Reproducible:
    """One place whose encrypted value is re-derived from the environment on every run."""

    resource_type: str  # exact
    side: str
    key_path: tuple[str, ...]  # exact: a nested or longer path is never matched
    why: str


# The allowlist. An entry is added only for a value that CI itself supplies at run time, so
# that dropping it from the state loses nothing. The tenants program passes HCLOUD_TOKEN by
# environment; the Hetzner provider records the token it was configured with, as a secret,
# in the default provider's inputs and outputs.
REPRODUCIBLE: tuple[Reproducible, ...] = (
    Reproducible(
        "pulumi:providers:hcloud",
        "inputs",
        ("token",),
        "the provider's token, set from HCLOUD_TOKEN on every run",
    ),
    Reproducible(
        "pulumi:providers:hcloud",
        "outputs",
        ("token",),
        "the provider's token, set from HCLOUD_TOKEN on every run",
    ),
)


def reproducible_entry(found: Ciphertext) -> Reproducible | None:
    for entry in REPRODUCIBLE:
        if (
            found.resource_type == entry.resource_type
            and found.side == entry.side
            and found.key_path == entry.key_path
        ):
            return entry
    return None


@dataclasses.dataclass(frozen=True)
class DropPlan:
    """The document to re-key, what was taken out of it, and what encrypted value is left."""

    doc: JsonObject
    dropped: tuple[Ciphertext, ...]
    remaining: tuple[Ciphertext, ...]


def removed_paths(old: object, new: object) -> list[tuple[PathKey, ...]]:
    """The keys `old` has and `new` lacks.

    Raises:
        RefusalError: when `new` differs from `old` in any other way.
    """
    removed: list[tuple[PathKey, ...]] = []
    pending: list[tuple[tuple[PathKey, ...], object, object]] = [((), old, new)]
    while pending:
        path, a, b = pending.pop()
        if isinstance(a, dict) and isinstance(b, dict):
            if any(k not in a for k in b):
                raise RefusalError("the document gained a key")
            for k, v in a.items():
                if k in b:
                    pending.append(((*path, str(k)), v, b[k]))
                else:
                    removed.append((*path, str(k)))
        elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
            pending.extend(((*path, i), x, y) for i, (x, y) in enumerate(zip(a, b, strict=True)))
        elif canonical(a) != canonical(b):
            raise RefusalError("the document differs in a value, not only in dropped keys")
    return sorted(removed, key=path_order)


def require_only_dropped(old: JsonObject, new: JsonObject, dropped: Sequence[Ciphertext]) -> None:
    """Prove `new` is `old` with exactly the `dropped` keys removed, and nothing else.

    `deployment.secrets_providers` is left out of both sides, as everywhere.

    Raises:
        RefusalError: when anything else differs, or a dropped key is still there.
    """
    gone = removed_paths(without_secrets_providers(old), without_secrets_providers(new))
    want = sorted((c.location for c in dropped), key=path_order)
    if gone != want:
        raise RefusalError("the document lost keys other than the ones dropped")


def plan_drop(doc: JsonObject, *, enabled: bool) -> DropPlan:
    """Take out the encrypted values the allowlist covers, when `enabled`; name what is left.

    The input document is not changed.

    Raises:
        RefusalError: when the drop did more or less than the allowlist says.
    """
    found = find_ciphertexts(doc)
    if not enabled:
        return DropPlan(doc, (), tuple(found))
    dropped = tuple(c for c in found if reproducible_entry(c) is not None)
    result = copy.deepcopy(doc)
    for c in dropped:
        parent: object = result
        for key in c.location[:-1]:
            parent = parent[key]  # type: ignore[index]
        del parent[c.location[-1]]  # type: ignore[attr-defined]
    require_only_dropped(doc, result, dropped)
    return DropPlan(result, dropped, tuple(find_ciphertexts(result)))


def describe_ciphertexts(report: Report, before: Sequence[Ciphertext], plan: DropPlan) -> None:
    """Each encrypted value by resource type, URN name, side and key path. Never a value."""
    dropping = set(plan.dropped)
    for c in before:
        entry = reproducible_entry(c)
        if entry is not None and c in dropping:
            verdict = f"DROP ({entry.why})"
        elif entry is not None:
            verdict = "re-derivable, kept (--drop-reproducible is not set)"
        else:
            verdict = "KEPT, not on the allowlist"
        report.line(
            f"  encrypted: {c.resource_type} | {c.name} | {c.side} | {c.key_text} | {verdict}"
        )


def canonical(doc: object) -> str:
    """One text per document: key order never matters, and `true` is not `1`."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def validate_provider_block(block: object) -> JsonObject:
    """The block, once it is a passphrase provider carrying a salt.

    Raises:
        RefusalError: when it is not.
    """
    if not isinstance(block, dict) or block.get("type") != "passphrase":
        raise RefusalError("the new secrets provider block is not a passphrase provider")
    state = block.get("state")
    salt = state.get("salt") if isinstance(state, dict) else None
    if not isinstance(salt, str) or not salt.startswith("v1:"):
        raise RefusalError("the new secrets provider block carries no salt")
    return block


def require_only_provider_changed(old: JsonObject, new: JsonObject) -> None:
    """Prove the rewrite changed `deployment.secrets_providers` and nothing else.

    Raises:
        RefusalError: when anything else differs, or the block did not change.
    """
    if canonical(without_secrets_providers(old)) != canonical(without_secrets_providers(new)):
        raise RefusalError("the rewrite changed more than `deployment.secrets_providers`")
    new_block = validate_provider_block(deployment_of(new).get("secrets_providers"))
    if canonical(deployment_of(old).get("secrets_providers")) == canonical(new_block):
        raise RefusalError("the secrets provider block did not change, so nothing was re-keyed")


def swap_secrets_provider(old: JsonObject, new_block: object) -> JsonObject:
    """The old checkpoint with its secrets provider block replaced by `new_block`."""
    block = validate_provider_block(new_block)
    result = copy.deepcopy(old)
    deployment_of(result)["secrets_providers"] = copy.deepcopy(block)
    require_only_provider_changed(old, result)
    return result


# ---------------------------------------------------------------------------
# What a plan may contain
# ---------------------------------------------------------------------------


def step_type(urn: str) -> str:
    """The resource type of a URN: `urn:pulumi:stack::project::parent$type::name`."""
    parts = urn.split("::")
    if len(parts) < 4:
        return "(unreadable urn)"
    return parts[2].split("$")[-1]


def plan_problems(text: str) -> tuple[dict[str, int], list[str]]:
    """`(count per op, problems)` for a `pulumi preview --json` or refresh-preview document.

    Only `same` steps are allowed, plus the `read` of a StackReference (the
    program always reads its estate reference). Any other step is named by its
    operation and resource type, never by id.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return {}, ["the plan is not valid JSON"]
    steps = doc.get("steps") if isinstance(doc, dict) else None
    if not isinstance(steps, list):
        return {}, ["the plan has no `steps` list"]
    counts: dict[str, int] = {}
    problems: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            problems.append("a step is not an object")
            continue
        op = step.get("op")
        urn = step.get("urn")
        kind = step_type(urn) if isinstance(urn, str) else "(no urn)"
        op_name = op if isinstance(op, str) else "(no op)"
        counts[op_name] = counts.get(op_name, 0) + 1
        if not (op_name == "same" or (op_name == "read" and kind == STACKREFERENCE_TYPE)):
            problems.append(f"{op_name} of a {kind}")
    if not counts.get("same"):
        problems.append("the plan holds no unchanged resource, which is not a plan of this stack")
    return counts, problems


def refresh_problems(text: str) -> tuple[dict[str, int], list[str]]:
    """`(change summary, problems)` for a refresh preview's `--json` document.

    Every step of a refresh preview carries the op `refresh`, so the steps say
    nothing about drift; the change summary does, and so does a step whose
    detailed diff is not empty.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return {}, ["the refresh preview is not valid JSON"]
    summary = doc.get("changeSummary") if isinstance(doc, dict) else None
    steps = doc.get("steps") if isinstance(doc, dict) else None
    if not isinstance(summary, dict) or not isinstance(steps, list):
        return {}, ["the refresh preview has no change summary"]
    counts = {str(op): n for op, n in summary.items() if isinstance(n, int)}
    problems = [
        f"{n} {op} against the live project"
        for op, n in sorted(counts.items())
        if op != "same" and n
    ]
    for step in steps:
        diff = step.get("detailedDiff") if isinstance(step, dict) else None
        if diff:
            urn = step.get("urn")
            kind = step_type(urn) if isinstance(urn, str) else "(no urn)"
            problems.append(f"a {kind} differs from live")
    if not counts.get("same"):
        problems.append(
            "the refresh preview holds no unchanged resource, so it is not of this stack"
        )
    return counts, problems


def counts_text(counts: Mapping[str, int]) -> str:
    return ", ".join(f"{n} {op}" for op, n in sorted(counts.items())) or "no steps"


# ---------------------------------------------------------------------------
# The state objects
# ---------------------------------------------------------------------------


class Store(Protocol):
    """Read, write and list: no delete exists, so no code path can remove an object."""

    def read(self, key: str) -> bytes: ...

    def write(self, key: str, data: bytes) -> None: ...

    def keys(self, prefix: str) -> list[str]: ...


class DirStore:
    """A directory standing in for a bucket: a `file://` backend, in tests."""

    def __init__(self, root: pathlib.Path) -> None:
        self.root = root

    def read(self, key: str) -> bytes:
        try:
            return (self.root / key).read_bytes()
        except OSError as exc:
            raise ToolError(f"cannot read an object: {exc.strerror or exc}") from exc

    def write(self, key: str, data: bytes) -> None:
        target = self.root / key
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def keys(self, prefix: str) -> list[str]:
        found = [
            str(p.relative_to(self.root))
            for p in self.root.rglob("*")
            if p.is_file() and not p.name.endswith(".attrs")
        ]
        return sorted(k for k in found if k.startswith(prefix))


FAILURE_MARKERS = (
    ("passphrase", re.compile(r"incorrect passphrase|failed to decrypt", re.IGNORECASE)),
    (
        "state bucket access",
        re.compile(
            r"AccessDenied|NoSuchBucket|InvalidAccessKeyId|SignatureDoesNotMatch|Forbidden",
            re.IGNORECASE,
        ),
    ),
    (
        "hetzner token",
        re.compile(r"unauthorized|invalid token|authentication failed", re.IGNORECASE),
    ),
)


def classify_stderr(stderr: str) -> str:
    """The class of a failure, read from a stream that is never printed."""
    for name, marker in FAILURE_MARKERS:
        if marker.search(stderr):
            return name
    return "other"


class AwsCliStore:
    """The state bucket, through the AWS CLI the runner already has."""

    def __init__(
        self,
        *,
        bucket: str,
        endpoint_url: str,
        region: str,
        path_style: bool,
        config_dir: pathlib.Path,
        aws: str = "aws",
    ) -> None:
        self.bucket = bucket
        self.endpoint_url = endpoint_url
        self.region = region
        self.aws = aws
        config = config_dir / "aws-config"
        style = "path" if path_style else "auto"
        config.write_text(f"[default]\ns3 =\n    addressing_style = {style}\n", encoding="utf-8")
        self.env = dict(os.environ)
        self.env["AWS_CONFIG_FILE"] = str(config)
        # Hetzner Object Storage does not take the newer default checksums.
        self.env["AWS_REQUEST_CHECKSUM_CALCULATION"] = "when_required"
        self.env["AWS_RESPONSE_CHECKSUM_VALIDATION"] = "when_required"
        self.env["AWS_EC2_METADATA_DISABLED"] = "true"

    def run(self, args: Sequence[str], stdin: bytes | None = None) -> bytes:
        """Run one aws CLI call and return its stdout.

        Raises:
            ToolError: when it exits non-zero; only the class of the failure is said.
        """
        command = [
            self.aws,
            "--endpoint-url",
            self.endpoint_url,
            "--region",
            self.region,
            "--no-cli-pager",
            *args,
        ]
        proc = subprocess.run(  # noqa: S603
            command,
            input=stdin,
            capture_output=True,
            env=self.env,
            check=False,
        )
        if proc.returncode != 0:
            kind = classify_stderr(proc.stderr.decode("utf-8", "replace"))
            raise ToolError(f"the aws CLI failed (exit {proc.returncode}, {kind})")
        return proc.stdout

    def uri(self, key: str) -> str:
        return f"s3://{self.bucket}/{key}"

    def read(self, key: str) -> bytes:
        return self.run(["s3", "cp", self.uri(key), "-", "--only-show-errors"])

    def write(self, key: str, data: bytes) -> None:
        self.run(["s3", "cp", "-", self.uri(key), "--only-show-errors"], stdin=data)

    def keys(self, prefix: str) -> list[str]:
        out = (
            self.run(
                [
                    "s3api",
                    "list-objects-v2",
                    "--bucket",
                    self.bucket,
                    "--prefix",
                    prefix,
                    "--output",
                    "json",
                ]
            )
            .decode("utf-8")
            .strip()
        )
        if not out or out == "null":
            return []
        listing = json.loads(out)
        contents = listing.get("Contents") if isinstance(listing, dict) else None
        if not isinstance(contents, list):
            return []
        return sorted(str(item["Key"]) for item in contents)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Pulumi
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Completed:
    returncode: int
    stderr_class: str


class Pulumi:
    """The `pulumi` binary, run in the project directory.

    stdout goes to a file the caller names, or nowhere. stderr is classified
    and dropped: with a correct passphrase, Pulumi's own errors can quote the
    decrypted value they could not parse.
    """

    def __init__(self, *, binary: str, project_dir: pathlib.Path, env: Mapping[str, str]) -> None:
        self.binary = binary
        self.project_dir = project_dir
        self.env = dict(env)

    def run(self, args: Sequence[str], stdout: int | IO[bytes]) -> Completed:
        proc = subprocess.run(  # noqa: S603
            [self.binary, *args],
            cwd=self.project_dir,
            env=self.env,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=subprocess.PIPE,
            check=False,
        )
        return Completed(proc.returncode, classify_stderr(proc.stderr.decode("utf-8", "replace")))

    def call(self, *args: str, stdout_to: pathlib.Path | None = None) -> Completed:
        if stdout_to is None:
            return self.run(args, subprocess.DEVNULL)
        with stdout_to.open("wb") as handle:
            return self.run(args, handle)

    def require(self, *args: str, stdout_to: pathlib.Path | None = None) -> None:
        """Run one command and insist it succeeds.

        Raises:
            ToolError: when it exits non-zero; only the class of the failure is said.
        """
        done = self.call(*args, stdout_to=stdout_to)
        if done.returncode != 0:
            verb = " ".join(a for a in args[:2] if not a.startswith("-"))
            raise ToolError(f"`pulumi {verb}` failed (exit {done.returncode}, {done.stderr_class})")


def child_env(
    base: Mapping[str, str], *, backend_url: str | None, with_passphrase: bool
) -> dict[str, str]:
    env = dict(base)
    env.pop("PULUMI_ACCESS_TOKEN", None)
    # This variable acts as `--yes`, which `--preview-only` refuses; every
    # command that needs a confirmation says so itself.
    env.pop("PULUMI_SKIP_CONFIRMATIONS", None)
    env["PULUMI_SKIP_UPDATE_CHECK"] = "true"
    if backend_url is not None:
        env["PULUMI_BACKEND_URL"] = backend_url
    if not with_passphrase:
        env.pop("PULUMI_CONFIG_PASSPHRASE", None)
        env.pop("PULUMI_CONFIG_PASSPHRASE_FILE", None)
    return env


def read_top_level_scalar(text: str, key: str) -> str | None:
    for line in text.splitlines():
        if line.startswith(f"{key}:"):
            return line.split(":", 1)[1].strip().strip("'\"")
    return None


def read_backend_url(text: str) -> str | None:
    in_backend = False
    for line in text.splitlines():
        if line.startswith("backend:"):
            in_backend = True
        elif in_backend:
            if line and not line[0].isspace():
                break
            if line.strip().startswith("url:"):
                return line.strip().split(":", 1)[1].strip().strip("'\"")
    return None


@dataclasses.dataclass(frozen=True)
class Backend:
    store: Store
    backend_url: str | None  # set only for a `file://` backend; otherwise Pulumi.yaml names it
    resolved_prefix: str  # what `pulumi whoami --verbose` must say its backend is


def resolve_backend(
    project_dir: pathlib.Path, env: Mapping[str, str], scratch: pathlib.Path
) -> Backend:
    """The backend this run operates on, and the store that reaches its objects.

    Raises:
        ToolError: when the backend is not one this tool is willing to operate on.
    """
    override = env.get("PULUMI_BACKEND_URL", "")
    if override:
        if not override.startswith("file://"):
            raise ToolError("PULUMI_BACKEND_URL is set to something other than a file backend")
        return Backend(DirStore(pathlib.Path(override[len("file://") :])), override, override)
    try:
        pulumi_yaml = (project_dir / "Pulumi.yaml").read_text(encoding="utf-8")
    except OSError as exc:
        raise ToolError(f"cannot read Pulumi.yaml: {exc.strerror or exc}") from exc
    url = read_backend_url(pulumi_yaml)
    if not url or not url.startswith("s3://"):
        raise ToolError("Pulumi.yaml does not pin an s3 backend")
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parsed.query)
    endpoint = query.get("endpoint", [""])[0]
    region = query.get("region", [""])[0]
    if not parsed.netloc or not endpoint or not region:
        raise ToolError("the pinned backend names no bucket, endpoint or region")
    store = AwsCliStore(
        bucket=parsed.netloc,
        endpoint_url=endpoint if "://" in endpoint else f"https://{endpoint}",
        region=region,
        path_style=query.get("s3ForcePathStyle", ["false"])[0].lower() == "true",
        config_dir=scratch,
    )
    return Backend(store, None, f"s3://{parsed.netloc}")


def assert_backend(pulumi: Pulumi, backend: Backend, scratch: pathlib.Path) -> None:
    """Prove, from Pulumi, that it resolved the backend this run means to change.

    Raises:
        ToolError: when it resolved another one.
    """
    out = scratch / "whoami.txt"
    pulumi.require("whoami", "--verbose", stdout_to=out)
    resolved = ""
    for line in out.read_text(encoding="utf-8").splitlines():
        if line.startswith("Backend URL:"):
            resolved = line.split(":", 1)[1].strip()
            break
    out.unlink()
    if not resolved.startswith(backend.resolved_prefix):
        raise ToolError("pulumi resolved a backend other than the one this run is for")


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Context:
    pulumi: Pulumi
    store: Store
    project: str
    stack: str
    project_dir: pathlib.Path
    scratch: pathlib.Path
    run_tag: str
    report: Report
    now: Callable[[], datetime.datetime]
    delete_guard: pathlib.Path | None = None
    github_output: str | None = None
    drop_reproducible: bool = False

    @property
    def state_key(self) -> str:
        return f".pulumi/stacks/{self.project}/{self.stack}.json"

    @property
    def config_file(self) -> pathlib.Path:
        return self.project_dir / f"Pulumi.{self.stack}.yaml"


def export_document(ctx: Context, name: str) -> JsonObject:
    """The stack's export with every secret left encrypted: no passphrase is needed or used.

    Raises:
        ToolError: when the export fails or is not JSON.
        RefusalError: when it is JSON but not an object.
    """
    target = ctx.scratch / name
    ctx.pulumi.require("stack", "export", "--stack", ctx.stack, stdout_to=target)
    try:
        doc = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError("the stack export could not be read as JSON") from exc
    if not isinstance(doc, dict):
        raise RefusalError("the export is not a JSON object")
    return doc


def report_gate(ctx: Context, doc: JsonObject) -> tuple[DropPlan, list[str]]:
    """Describe the export, list its encrypted values, and apply the gate.

    With `ctx.drop_reproducible` the gate reads the document after the allowlisted
    ciphertexts are taken out.

    Raises:
        RefusalError: when the export is not shaped like a checkpoint, or the drop is unsound.
    """
    describe(inspect_export(doc), ctx.report)
    before = find_ciphertexts(doc)
    plan = plan_drop(doc, enabled=ctx.drop_reproducible)
    describe_ciphertexts(ctx.report, before, plan)
    if ctx.drop_reproducible:
        ctx.report.line(
            f"after dropping {len(plan.dropped)} reproducible value(s): "
            f"{len(plan.remaining)} encrypted value(s) remain"
        )
    return plan, gate_problems(inspect_export(plan.doc), dropping=ctx.drop_reproducible)


def run_inspect(ctx: Context) -> int:
    """Read-only: the gate's counts, for the owner to read before approving the rewrap."""
    ctx.report.line(f"stack: {ctx.project}/{ctx.stack}")
    try:
        plan, problems = report_gate(ctx, export_document(ctx, "inspect-export.json"))
    except RefusalError as exc:
        ctx.report.line(f"REFUSED: {exc}")
        return EXIT_REFUSED
    for problem in problems:
        ctx.report.line(f"REFUSED: {problem}")
    if problems:
        return EXIT_REFUSED
    if plan.dropped:
        ctx.report.line(
            f"CLEAN: only the {len(plan.dropped)} listed reproducible value(s) are encrypted "
            "and a rewrap would drop them; no pending operation; a rewrap may proceed"
        )
    else:
        ctx.report.line("CLEAN: no encrypted value, no pending operation; a rewrap may proceed")
    return EXIT_OK


def aside_key_for(ctx: Context) -> str:
    stamp = ctx.now().strftime("%Y%m%dT%H%M%SZ")
    return f"{ASIDE_PREFIX}/{ctx.project}/{ctx.stack}.{stamp}.{ctx.run_tag}.json"


def put_back(store: Store, state_key: str, aside: bytes) -> bool:
    """Write the aside copy over the state object and read it back. True only if it matches."""
    try:
        store.write(state_key, aside)
        return sha256(store.read(state_key)) == sha256(aside)
    except (ToolError, OSError):
        return False


def require_clean_start(ctx: Context) -> None:
    """Refuse a start that would not re-key under a salt of this run's own making.

    Raises:
        ToolError: when no new passphrase is set.
        RefusalError: when the stack config already carries a salt.
    """
    env = ctx.pulumi.env
    if not env.get("PULUMI_CONFIG_PASSPHRASE", "").strip() and not env.get(
        "PULUMI_CONFIG_PASSPHRASE_FILE"
    ):
        raise ToolError("no new passphrase is in the environment")
    try:
        text = ctx.config_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ToolError(f"cannot read the stack config: {exc.strerror or exc}") from exc
    if re.search(r"^encryptionsalt:", text, re.MULTILINE):
        raise RefusalError(
            "the stack config already carries an `encryptionsalt`; this run mints its own"
        )


def plan_step(
    ctx: Context,
    label: str,
    args: Sequence[str],
    out_name: str,
    check: Callable[[str], tuple[dict[str, int], list[str]]],
) -> None:
    """Run a plan-shaped command and insist `check` finds no change in its output.

    Raises:
        ToolError: when the command fails or `check` names a problem.
    """
    out = ctx.scratch / out_name
    done = ctx.pulumi.call(*args, stdout_to=out)
    counts, problems = check(out.read_text(encoding="utf-8"))
    ctx.report.line(f"{label}: {counts_text(counts)}")
    if done.returncode != 0:
        problems.append(f"`pulumi {args[0]}` exited {done.returncode} ({done.stderr_class})")
    for problem in problems:
        ctx.report.line(f"  not allowed: {problem}")
    if problems:
        raise ToolError(f"{label} is not a result with no changes")


def verify_after_import(ctx: Context) -> None:
    """Nothing is applied: a plan with no change, then a refresh preview with no drift.

    Raises:
        ToolError: when either shows a change, or the delete guard refuses the plan.
    """
    plan_step(
        ctx,
        "preview after the rewrite",
        ("preview", "--stack", ctx.stack, "--json", "--expect-no-changes"),
        "preview.json",
        plan_problems,
    )
    if ctx.delete_guard is not None:
        guard = subprocess.run(  # noqa: S603
            [sys.executable, str(ctx.delete_guard), str(ctx.scratch / "preview.json")],
            capture_output=True,
            check=False,
        )
        if guard.returncode != 0:
            raise ToolError("the delete guard refused the plan after the rewrite")
        ctx.report.line("delete guard: the plan destroys nothing")
    plan_step(
        ctx,
        "refresh preview against the live project",
        ("refresh", "--stack", ctx.stack, "--preview-only", "--expect-no-changes", "--json"),
        "refresh.json",
        refresh_problems,
    )


def copy_aside(ctx: Context) -> tuple[bytes, str]:
    """Copy the state object aside and read the copy back; `(its bytes, the aside key)`.

    Raises:
        ToolError: when the copy does not read back identical, or the state moved meanwhile.
    """
    original = ctx.store.read(ctx.state_key)
    aside_key = aside_key_for(ctx)
    ctx.store.write(aside_key, original)
    if sha256(ctx.store.read(aside_key)) != sha256(original):
        raise ToolError("the aside copy does not read back identical")
    if sha256(ctx.store.read(ctx.state_key)) != sha256(original):
        raise ToolError("the state object changed while it was being copied")
    return original, aside_key


def mutate_and_verify(ctx: Context, plan: DropPlan, exported: JsonObject) -> None:
    """The steps after the point of no return. Any exception here means: put the copy back.

    `plan.doc` is `exported` with the dropped keys removed (all of `exported` when none).

    Raises:
        RefusalError: when the fresh stack is not empty or the rewrite changes more than the
            provider block and the dropped keys.
    """
    ctx.pulumi.require("stack", "rm", ctx.stack, "--force", "--yes", "--preserve-config")
    ctx.pulumi.require("stack", "init", ctx.stack, "--secrets-provider", "passphrase")
    fresh = deployment_of(export_document(ctx, "fresh-export.json"))
    if fresh.get("resources"):
        raise RefusalError("the freshly initialised stack is not empty")
    new_doc = swap_secrets_provider(plan.doc, fresh.get("secrets_providers"))
    # What is imported is the export minus exactly the dropped keys, and the new provider block.
    require_only_dropped(exported, new_doc, plan.dropped)
    new_file = ctx.scratch / "new-export.json"
    new_file.write_text(json.dumps(new_doc), encoding="utf-8")
    ctx.pulumi.require("stack", "import", "--stack", ctx.stack, "--file", str(new_file))
    if plan.dropped:
        ctx.report.line(
            f"imported: only `deployment.secrets_providers` and the {len(plan.dropped)} dropped "
            "key(s) differ from the old checkpoint"
        )
    else:
        ctx.report.line(
            "imported: only `deployment.secrets_providers` differs from the old checkpoint"
        )
    verify_after_import(ctx)


def recover(ctx: Context, original: bytes, aside_key: str, why: str) -> int:
    ctx.report.line(f"{why}; putting the aside copy back")
    if put_back(ctx.store, ctx.state_key, original):
        ctx.report.line(
            "RESTORED: the aside copy is back over the state object and reads back identical"
        )
        return EXIT_RESTORED
    ctx.report.line(
        f"NOT RESTORED: the state object may be missing. The copy is at `{aside_key}`; "
        "put it back before anything else runs"
    )
    return EXIT_BROKEN


def run_rewrap(ctx: Context) -> int:
    ctx.report.line(f"stack: {ctx.project}/{ctx.stack}")
    try:
        require_clean_start(ctx)
        old_doc = export_document(ctx, "old-export.json")
        plan, problems = report_gate(ctx, old_doc)
    except RefusalError as exc:
        ctx.report.line(f"REFUSED: {exc}")
        return EXIT_REFUSED
    for problem in problems:
        ctx.report.line(f"REFUSED: {problem}")
    if problems:
        return EXIT_REFUSED

    original, aside_key = copy_aside(ctx)
    ctx.report.line(f"aside copy: {len(original)} bytes, read back, the hashes match")
    ctx.report.line(f"aside key: {aside_key}")
    if ctx.github_output:
        with open(ctx.github_output, "a", encoding="utf-8") as fh:
            fh.write(f"aside_key={aside_key}\n")

    try:
        mutate_and_verify(ctx, plan, old_doc)
    except (KeyboardInterrupt, SystemExit):
        recover(ctx, original, aside_key, "INTERRUPTED after the removal")
        raise
    except Exception as exc:  # noqa: BLE001 - any failure after the removal must put the copy back
        why = (
            str(exc)
            if isinstance(exc, (RefusalError, ToolError))
            else f"UNEXPECTED {type(exc).__name__}"
        )
        return recover(ctx, original, aside_key, f"FAILED after the removal ({why})")
    ctx.report.line("DONE: the state is re-keyed; the previous copy stays at the aside key")
    return EXIT_OK


def run_restore(ctx: Context) -> int:
    """Put this run's aside copy back over the state object. Only a store, no Pulumi."""
    prefix = f"{ASIDE_PREFIX}/{ctx.project}/{ctx.stack}."
    matches = [k for k in ctx.store.keys(prefix) if k.endswith(f".{ctx.run_tag}.json")]
    if not matches:
        ctx.report.line("no aside copy for this run: nothing was removed, nothing to put back")
        return EXIT_OK
    if len(matches) > 1:
        ctx.report.line("ERROR: more than one aside copy matches this run; not guessing")
        return EXIT_ERROR
    if put_back(ctx.store, ctx.state_key, ctx.store.read(matches[0])):
        ctx.report.line(
            "RESTORED: the aside copy is back over the state object and reads back identical"
        )
        return EXIT_OK
    ctx.report.line(f"NOT RESTORED: the copy is at `{matches[0]}`")
    return EXIT_BROKEN


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def raise_interrupt(_signum: int, _frame: FrameType | None) -> None:
    raise KeyboardInterrupt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(__doc__ or "").splitlines()[0], allow_abbrev=False
    )
    parser.add_argument("command", choices=("inspect", "rewrap", "restore"))
    parser.add_argument("--project-dir", required=True)
    parser.add_argument("--stack", default="production")
    parser.add_argument("--pulumi", default="pulumi")
    parser.add_argument(
        "--delete-guard",
        help="scripts/assert-no-hetzner-deletes.py, run on the plan after the rewrite",
    )
    parser.add_argument(
        "--run-tag",
        default=None,
        help="names this run's aside copy (default: Actions run id and attempt)",
    )
    parser.add_argument(
        "--drop-reproducible",
        action="store_true",
        help="inspect or rewrap: first remove the encrypted values on the allowlist "
        "(REPRODUCIBLE), which CI re-derives from its environment on every run",
    )
    parser.add_argument("--summary-file", default=None)
    parser.add_argument("--github-output", default=None)
    return parser


def execute(ctx: Context, command: str) -> int:
    try:
        if command == "inspect":
            return run_inspect(ctx)
        if command == "rewrap":
            signal.signal(signal.SIGTERM, raise_interrupt)
            return run_rewrap(ctx)
        return run_restore(ctx)
    except ToolError as exc:
        ctx.report.line(f"ERROR: {exc}")
        return EXIT_ERROR


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.drop_reproducible and args.command == "restore":
        parser.error("--drop-reproducible is for inspect and rewrap only")
    env_in = dict(os.environ if environ is None else environ)
    project_dir = pathlib.Path(args.project_dir).resolve()
    if shutil.which(args.pulumi) is None and not os.path.isfile(args.pulumi):
        print(f"error: no `{args.pulumi}` binary found", file=sys.stderr)
        return EXIT_USAGE
    run_tag = (
        args.run_tag or f"{env_in.get('GITHUB_RUN_ID', '')}-{env_in.get('GITHUB_RUN_ATTEMPT', '')}"
    )
    if args.command != "inspect" and not re.fullmatch(r"[A-Za-z0-9-]{3,64}", run_tag):
        print(
            "error: no usable run tag (set --run-tag, or run under GitHub Actions)", file=sys.stderr
        )
        return EXIT_USAGE
    try:
        project = read_top_level_scalar(
            (project_dir / "Pulumi.yaml").read_text(encoding="utf-8"), "name"
        )
    except OSError as exc:
        print(f"error: cannot read Pulumi.yaml: {exc.strerror or exc}", file=sys.stderr)
        return EXIT_USAGE
    if not project or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}", project):
        print("error: Pulumi.yaml names no usable project", file=sys.stderr)
        return EXIT_USAGE

    scratch = pathlib.Path(tempfile.mkdtemp(prefix="tenants-rewrap-"))
    report = Report(args.summary_file)
    try:
        try:
            backend = resolve_backend(project_dir, env_in, scratch)
            env = child_env(
                env_in, backend_url=backend.backend_url, with_passphrase=args.command == "rewrap"
            )
            pulumi = Pulumi(binary=args.pulumi, project_dir=project_dir, env=env)
            if args.command != "restore":
                assert_backend(pulumi, backend, scratch)
        except ToolError as exc:
            report.line(f"ERROR: {exc}")
            return EXIT_ERROR
        ctx = Context(
            pulumi=pulumi,
            store=backend.store,
            project=project,
            stack=args.stack,
            project_dir=project_dir,
            scratch=scratch,
            run_tag=run_tag,
            report=report,
            now=lambda: datetime.datetime.now(datetime.UTC),
            delete_guard=pathlib.Path(args.delete_guard).resolve() if args.delete_guard else None,
            github_output=args.github_output,
            drop_reproducible=args.drop_reproducible,
        )
        code = execute(ctx, args.command)
        report.flush_summary(f"Tenants state {args.command}")
        return code
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
