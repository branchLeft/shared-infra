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


def gate_problems(found: Inspection) -> list[str]:
    """Why this state may not be re-keyed. Empty when it may."""
    problems: list[str] = []
    if found.provider_type != "passphrase":
        problems.append(f"the secrets provider is `{found.provider_type}`, not `passphrase`")
    if found.encrypted_values:
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


def run_inspect(ctx: Context) -> int:
    """Read-only: the gate's counts, for the owner to read before approving the rewrap."""
    ctx.report.line(f"stack: {ctx.project}/{ctx.stack}")
    try:
        found = inspect_export(export_document(ctx, "inspect-export.json"))
    except RefusalError as exc:
        ctx.report.line(f"REFUSED: {exc}")
        return EXIT_REFUSED
    describe(found, ctx.report)
    problems = gate_problems(found)
    for problem in problems:
        ctx.report.line(f"REFUSED: {problem}")
    if problems:
        return EXIT_REFUSED
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


def mutate_and_verify(ctx: Context, old_doc: JsonObject) -> None:
    """The steps after the point of no return. Any exception here means: put the copy back.

    Raises:
        RefusalError: when the fresh stack is not empty or the rewrite changes more than one key.
    """
    ctx.pulumi.require("stack", "rm", ctx.stack, "--force", "--yes", "--preserve-config")
    ctx.pulumi.require("stack", "init", ctx.stack, "--secrets-provider", "passphrase")
    fresh = deployment_of(export_document(ctx, "fresh-export.json"))
    if fresh.get("resources"):
        raise RefusalError("the freshly initialised stack is not empty")
    new_doc = swap_secrets_provider(old_doc, fresh.get("secrets_providers"))
    new_file = ctx.scratch / "new-export.json"
    new_file.write_text(json.dumps(new_doc), encoding="utf-8")
    ctx.pulumi.require("stack", "import", "--stack", ctx.stack, "--file", str(new_file))
    ctx.report.line("imported: only `deployment.secrets_providers` differs from the old checkpoint")
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
        found = inspect_export(old_doc)
    except RefusalError as exc:
        ctx.report.line(f"REFUSED: {exc}")
        return EXIT_REFUSED
    describe(found, ctx.report)
    problems = gate_problems(found)
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
        mutate_and_verify(ctx, old_doc)
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
    args = build_parser().parse_args(argv)
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
        )
        code = execute(ctx, args.command)
        report.flush_summary(f"Tenants state {args.command}")
        return code
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
