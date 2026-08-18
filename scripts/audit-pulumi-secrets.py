#!/usr/bin/env python3
"""Report which Pulumi stacks still depend on the shared GCP KMS key.

Read-only. It reads committed files and never contacts a backend, a cloud API
or the Pulumi CLI, so it is safe to run from CI, from a pre-commit hook and
from a workstation with no credentials at all.

It exists because the constraint it guards has no other enforcement. Every
stack's secrets are wrapped by one KMS key; the key is destroyed during the
GCP wind-down; and once it is gone, the ciphertext committed in every
`Pulumi.<stack>.yaml` is undecryptable with no recovery path. The ordering
that prevents that is prose in a migration doc, which nothing checks. This
turns it into an exit code:

    --require-migrated   fail unless every stack has reached the terminal
                         state the inventory gives it, and every path that
                         can mint a new KMS-wrapped stack is retired. This
                         is the precondition the wind-down checks before it
                         destroys anything.

What it can and cannot see, stated plainly because a gate that overclaims is
worse than no gate:

- **It reads committed configuration, not checkpoints.** The KMS dependency
  lives in two places -- `secretsprovider`/`encryptedkey` in the committed
  `Pulumi.<stack>.yaml`, and `secrets_providers` inside the stack's
  checkpoint in its state bucket. Only the first is a committed file.
  A *half-finished* re-wrap is precisely the case where the two disagree,
  and this script cannot detect it. `pulumi stack export --show-secrets`
  against the stack is the only proof of the checkpoint side; the runbook
  requires it per stack and requires the result recorded.
- **Two stacks have no committed configuration at all**, so nothing about
  them is machine-checkable from this repo. They are satisfied by an
  `attestation` recorded in the inventory instead -- an operator statement
  under review in git, reported as attested rather than verified.
- **A migrated stack's own file cannot prove it either.** PUL-12 forbids
  committing `encryptionsalt` even for a passphrase stack, so the mandated
  end state is salt-injected-at-deploy: nothing about the provider survives
  in the tree. That file reads identically to a stack that was never
  created -- both classify as `absent` -- so these stacks are satisfied by
  an `attestation` too, the same as the two with no file at all.
- **Other repos' files are only visible with `--root`.** Without it their
  stacks are `unresolved`, which is never silently treated as a pass.

Two further failure modes it does catch, both of which present as success:

- **A backend reference nobody enumerated.** The `gs://` state backend is
  configured in each CI workflow's `pulumi login` step rather than anywhere
  central, so a new workflow adds a site silently, and the site is only
  discovered when it applies against the state everyone else has left.
- **A provider-selection site left live.** Separately from where state is
  read, some workflows select the shared KMS key via `--secrets-provider`
  when they *create* a stack. A sweep that re-wraps every existing stack
  while one of those survives is not finished: the next stack it mints is
  KMS-wrapped again, in a bucket that did not exist when this inventory was
  written.
- **A provider-selection site nobody enumerated.** The same shape as the
  backend-reference gap above: `provider_selection_sites` only verifies sites
  it already names, so a scan across the tree catches a new one.

Usage:

    audit-pulumi-secrets.py [--inventory PATH] [--root DIR]
                            [--require-migrated] [--json]

`--root` is the multi-repo workspace directory containing `shared-infra`,
`website`, `ghost-platform` and the tenant repos.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_INVENTORY = REPO_ROOT / "scripts" / "pulumi-stack-inventory.json"
THIS_REPO = "shared-infra"

# Written as an escape, never as the literal character, which is invisible in
# every diff and editor that would have to review it. Same constant, same
# reasoning, as assert-no-committed-pulumi-secrets.py next door.
BOM = "\ufeff"

# Matches a state-backend URL for either GCS bucket, and the pinned Hetzner
# one. Deliberately not a general URL matcher: the point is to notice the
# specific strings this estate uses, and a broad pattern would drown the
# report in unrelated `gs://` media-bucket references.
BACKEND_REFERENCE = re.compile(
    r"gs://branchleft-[a-z0-9-]*pulumi-state"
    r"|s3://branchleft-pulumi-state"
    r"|pulumi login \"?gs://\$"
)

# A `--secrets-provider` flag naming the KMS scheme -- i.e. *minting* a new
# KMS-wrapped stack, not merely mentioning the scheme in prose. Deliberately
# narrower than "gcpkms" alone: this inventory's own notes name the scheme
# while describing sites that used to pass it and no longer do, and a bare
# substring match would flag its own documentation on every run.
PROVIDER_SELECTION = re.compile(r"--secrets-provider[= ]+[\"']?gcpkms://")

# Files worth scanning. A backend is only ever selected from one of these.
SCANNABLE_SUFFIXES = (".yml", ".yaml", ".md", ".sh", ".ts", ".py", ".json")

# Where a stack is actually minted: CI workflows and the IaC/shell that runs
# unattended. Deliberately excludes `.md`: a runbook narrating a historical or
# example `pulumi stack init --secrets-provider=gcpkms://...` -- exactly what
# the migration and rehearsal runbooks in this repo do -- is not a site that
# creates a stack on its own, and scanning prose for the shape of the command
# it warns about would flag the warning as the violation.
PROVIDER_SELECTION_SUFFIXES = (".yml", ".yaml", ".sh", ".ts")

# Directories that either are not source or are a second copy of it. `vendor`
# holds a snapshot of another repo, and a snapshot's login steps are that
# repo's sites, counted there.
SKIP_DIRS = {
    ".git",
    ".worktrees",
    "node_modules",
    "graphify-out",
    "dist",
    "vendor",
}


class InventoryError(Exception):
    """Raised when the inventory itself is unusable, as opposed to a stack
    inside it having drifted."""


# --------------------------------------------------------------------------
# Parsing
#
# A real YAML parser is not available: this must run on a bare `python3` with
# no site-packages, the same constraint every other script in this repo works
# under. The files it reads are Pulumi-generated and shallow, so a top-level
# scalar reader plus one nested case covers them -- but it is a reader for
# these files, not a YAML parser, and it says so rather than pretending
# otherwise.
# --------------------------------------------------------------------------


def read_top_level_scalars(text: str) -> dict[str, str]:
    """Top-level `key: value` pairs, ignoring comments, blanks and any nested
    or multi-line construct."""
    found: dict[str, str] = {}
    # Stripped from the document, same reasoning and same fix as
    # assert-no-committed-pulumi-secrets.py next door: U+FEFF is not
    # whitespace to Python, so an unstripped BOM pushes line 1 past
    # `line[0].isspace()` below into looking like an indented (nested) line,
    # which this reader silently skips -- collapsing a canonical `gcpkms`
    # config to `absent` on nothing more than an editor's save-encoding.
    text = text[len(BOM) :] if text.startswith(BOM) else text
    for line in text.splitlines():
        if not line or line[0].isspace() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        value = value.strip()
        # A bare `key:` opens a block; a `>`/`|` opens a folded scalar. Neither
        # is a value, and treating one as an empty string would report a
        # configured provider as absent.
        if not value or value in (">", "|", ">-", "|-"):
            continue
        # The key is stripped of quotes too, not just the value: a quoted
        # key (`"secretsprovider": gcpkms://...`) is legal YAML naming the
        # same key, and reading it as the literal string `"secretsprovider"`
        # would also read as absent.
        found[key.strip().strip("'\"")] = value.strip("'\"")
    return found


def read_backend_url(text: str) -> str | None:
    """The `backend: url:` value from a `Pulumi.yaml`, if it pins one."""
    in_backend = False
    for line in text.splitlines():
        if line.startswith("backend:"):
            in_backend = True
            continue
        if in_backend:
            if line and not line[0].isspace():
                break
            stripped = line.strip()
            if stripped.startswith("url:"):
                return stripped[len("url:") :].strip().strip("'\"")
    return None


def classify_secrets_provider(config_text: str) -> tuple[str, str | None]:
    """`(kind, detail)` for a stack configuration file.

    `gcpkms` and `passphrase` are the two states that matter. `unknown` is
    reported rather than assumed migrated -- a file naming some third provider
    is a question, not a pass.
    """
    scalars = read_top_level_scalars(config_text)
    # `encryptedkey` is the KMS-wrapped data key itself, checked first and
    # unconditionally: it is more direct evidence than the `secretsprovider`
    # string beside it, and the only one of the pair that survives a hand-edit
    # deleting one line but not the other -- `RUNBOOK-existing-stack-
    # migration.md` describes the two moving together, which is exactly the
    # edit that leaves one behind. A stack carrying it is KMS-wrapped whatever
    # `secretsprovider` claims or omits.
    if "encryptedkey" in scalars:
        return "gcpkms", scalars.get("secretsprovider", scalars["encryptedkey"])
    provider = scalars.get("secretsprovider")
    if provider is None:
        if "encryptionsalt" in scalars:
            return "passphrase", scalars["encryptionsalt"]
        return "absent", None
    if provider.startswith("gcpkms://"):
        return "gcpkms", provider
    if provider == "passphrase":
        return "passphrase", scalars.get("encryptionsalt")
    return "unknown", provider


# --------------------------------------------------------------------------
# Auditing
# --------------------------------------------------------------------------


def load_inventory(path: os.PathLike[str] | str) -> dict:
    try:
        inventory = json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise InventoryError(f"cannot read inventory {path}: {exc}") from exc
    if not isinstance(inventory.get("stacks"), list) or not inventory["stacks"]:
        raise InventoryError(f"{path} lists no stacks")
    return inventory


def resolve_config_path(entry: dict, root: pathlib.Path | None) -> pathlib.Path | None:
    """Where this entry's configuration file should be, or None if it has no
    committed one or lives in a repo `--root` did not make reachable."""
    if not entry.get("config_path"):
        return None
    repo = entry.get("repo")
    if repo == THIS_REPO:
        return REPO_ROOT / entry["config_path"]
    if root is None or repo is None:
        return None
    return root / repo / entry["config_path"]


TERMINAL_STATES = {"migrate", "destroy", "migrate-or-destroy", "never-kms"}

# What each terminal state accepts as reaching it. `attested-*` is an operator
# statement recorded in the inventory rather than a fact read from a file, and
# is kept as a separate status so a report never presents the two as equal.
#
# `never-kms` is for a stack born on the passphrase provider that has no KMS
# dependency to migrate away from -- listed to be enumerated (a `pulumi stack
# ls --all` sweep still has to be able to find it and confirm that), not to
# be swept. Demanding an attestation from it would repeat the exact failure
# these comments warn against elsewhere: a gate red in its own success state
# gets routed around by an operator typing "migrated" for a migration that
# never happened. `needs-attestation` -- no committed evidence either way --
# is that success state here, so it satisfies this terminal state on its own.
# `pending` and `drift` still do not: if such a stack's file ever did show
# `gcpkms`, or an attestation contradicted it, that is a real anomaly this
# terminal state must not paper over.
SATISFIED_BY = {
    "migrate": {"migrated", "attested-migrated"},
    "destroy": {"attested-removed"},
    "migrate-or-destroy": {"migrated", "attested-migrated", "attested-removed"},
    "never-kms": {"needs-attestation", "migrated", "attested-migrated"},
}


ISO_DATE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")


def read_attestation(entry: dict) -> tuple[str | None, str]:
    """`(status, detail)` from an inventory `attestation`, or `(None, "")`.

    A stack with no committed configuration cannot be checked from a file, so
    the inventory carries what the operator observed. Requiring a date and an
    evidence line is the whole difference between an attestation and a
    checkbox: both are claims, but only one says what was run.
    """
    attestation = entry.get("attestation")
    if not attestation:
        return None, ""
    state = attestation.get("state")
    if state not in ("removed", "migrated"):
        return "drift", f"attestation records an unknown state: {state!r}"
    for field in ("date", "evidence"):
        if not attestation.get(field):
            return "drift", f"attestation for this stack has no {field}"
    if not ISO_DATE.match(str(attestation["date"])):
        return "drift", f"attestation date is not YYYY-MM-DD: {attestation['date']!r}"
    return f"attested-{state}", f"{attestation['date']}: {attestation['evidence']}"


# Which file-derived provider an attested state is allowed to sit next to. An
# attestation is an operator's word; a committed file is a fact, and where both
# exist the file decides. Without this a `"state": "migrated"` typed onto a
# stack whose `Pulumi.<stack>.yaml` still reads `gcpkms://` would turn the gate
# green over the one stack in the set that could actually be checked.
#
# `"absent"` belongs here alongside `"passphrase"`, not as a looser check but
# as the *correct* one: PUL-12 forbids a migrated stack from ever committing
# its `encryptionsalt` again, so the salt is injected at deploy and never
# lands in the tree. A fully migrated stack's config file is therefore
# indistinguishable, by content, from one whose stack was never created --
# both classify as `absent`. That ambiguity is exactly why an attestation is
# required for these stacks rather than inferred from the file; the file can
# only fail to contradict it. The rollback guarantee this table exists for
# survives that: a rolled-back checkpoint restores an explicit
# `secretsprovider: gcpkms://...` line, which is still outside this set and
# still turns the gate red.
ATTESTATION_AGREES_WITH = {
    "attested-migrated": {"passphrase", "absent"},
    # A removed stack's configuration file is removed with it. A file that is
    # still on disk means the stack is still there, or the removal was partial.
    "attested-removed": set(),
}


def audit_stack(entry: dict, root: pathlib.Path | None) -> dict:
    """One stack's finding. `status` is the whole result; everything else is
    context for a human reading the report."""
    name = f"{entry['project']}/{entry['stack']}"
    terminal_state = entry.get("terminal_state")
    finding = {
        "stack": name,
        "repo": entry.get("repo"),
        "terminal_state": terminal_state,
        "provider": None,
        "status": None,
        "detail": "",
    }

    if terminal_state not in TERMINAL_STATES:
        finding["status"] = "drift"
        finding["detail"] = f"inventory gives an unknown terminal_state: {terminal_state!r}"
        return finding

    attested, attested_detail = read_attestation(entry)
    if attested == "drift":
        finding["status"] = "drift"
        finding["detail"] = attested_detail
        return finding

    config_path = resolve_config_path(entry, root)

    # No committed configuration exists anywhere, so nothing in this repo can
    # check the stack and an attestation is the only evidence available.
    if config_path is None and not entry.get("config_path"):
        if attested:
            finding["status"] = attested
            finding["detail"] = attested_detail
            finding["attested"] = True
        else:
            finding["status"] = "needs-attestation"
            finding["detail"] = "no committed configuration file; nothing here can check this stack"
        return finding

    # A configuration file exists in some repo this run could not reach. An
    # attestation must not stand in for it: the file is the authority and it
    # was simply not read, which is a different thing from not existing.
    if config_path is None:
        finding["status"] = "unresolved"
        finding["detail"] = f"repo {entry.get('repo')!r} not reachable from --root"
        return finding

    file_exists = config_path.exists()

    if attested:
        # The file decides where both exist. This is what makes a rollback
        # self-correcting: restoring a KMS-wrapped checkpoint restores the
        # `gcpkms://` line with it, and the stale attestation stops agreeing.
        if not file_exists:
            if attested == "attested-removed":
                finding["status"] = attested
                finding["detail"] = attested_detail
                finding["attested"] = True
            else:
                finding["status"] = "drift"
                finding["detail"] = (
                    f"attestation claims {attested} but {entry['config_path']} is gone"
                )
            return finding
        kind, _ = classify_secrets_provider(config_path.read_text())
        if kind in ATTESTATION_AGREES_WITH[attested]:
            finding["status"] = attested
            finding["detail"] = attested_detail
            finding["attested"] = True
        else:
            finding["status"] = "drift"
            finding["detail"] = (
                f"attestation claims {attested} but {entry['config_path']} reports {kind}"
            )
        return finding

    try:
        text = config_path.read_text()
    except OSError as exc:
        finding["status"] = "missing"
        finding["detail"] = f"{config_path}: {exc.strerror}"
        return finding

    kind, detail = classify_secrets_provider(text)
    finding["provider"] = kind
    finding["detail"] = detail or ""

    if kind == "gcpkms":
        finding["status"] = "pending"
    elif kind == "passphrase":
        # A passphrase-managed stack with no salt cannot decrypt its own
        # committed ciphertext, which is a worse state than not having been
        # migrated at all.
        finding["status"] = "migrated" if detail else "drift"
        if not detail:
            finding["detail"] = "passphrase provider with no encryptionsalt"
    elif kind == "absent":
        # Not drift: this is what a *correctly* migrated, salt-injected-at-
        # deploy stack's own file looks like under PUL-12, indistinguishable
        # here from a stack that was never created. Either way the file
        # cannot settle it -- only an attestation can -- so a config file
        # this shape with no attestation reaches the same status as no
        # config file at all, rather than failing the default CI run (which
        # carries no --require-migrated and gates the production deploy) the
        # moment any stack is added to the inventory ahead of its attestation.
        finding["status"] = "needs-attestation"
        finding["detail"] = (
            "no secretsprovider, encryptedkey or encryptionsalt in the file -- "
            "record an attestation once this stack reaches its terminal state"
        )
    else:
        finding["status"] = "drift"
        finding["detail"] = f"unexpected secrets provider: {kind} {detail or ''}".strip()

    return finding


def audit_stacks(inventory: dict, root: pathlib.Path | None) -> list[dict]:
    return [audit_stack(entry, root) for entry in inventory["stacks"]]


def audit_provider_selection_sites(inventory: dict, root: pathlib.Path | None) -> list[dict]:
    """Sites that pass a secrets provider when *creating* a stack.

    Re-wrapping every stack that exists is only half the sweep. While one of
    these is live, the next stack minted is KMS-wrapped again -- and it lands
    in a bucket that did not exist when the inventory was written, so nothing
    downstream lists it.

    `retired` is a claim in a JSON file that one hand edit can flip, on the
    single gate the whole irreversible wind-down hangs on. So the flag is
    never sufficient: where `--root` makes the file reachable, the file is
    read and the claim checked against it. Unreachable is treated as not
    retired rather than as retired, because the failure this guards is
    unrecoverable and the other direction merely inconvenient.
    """
    findings = []
    for site in inventory.get("provider_selection_sites", []):
        label = f"{site.get('repo')}/{site['path']}"
        marker = site.get("must_not_contain", "gcpkms://")
        claimed = site.get("retired")

        # Strict identity, not truthiness: the string "false" and the string
        # "no" are both true in a boolean context, and both are exactly what a
        # hurried hand edit to a JSON file produces.
        if claimed is not True and claimed is not False:
            findings.append(
                {
                    "site": label,
                    "status": "drift",
                    "detail": f"`retired` must be true or false, not {claimed!r}",
                }
            )
            continue

        path = None
        if root is not None and site.get("repo"):
            path = root / site["repo"] / site["path"]

        if path is None or not path.exists():
            findings.append(
                {
                    "site": label,
                    "status": "retired-unverified" if claimed else "live",
                    "detail": (
                        "claims retired, but the file was not reachable to check "
                        "-- pass --root"
                        if claimed
                        else site.get("note", "")
                    ),
                }
            )
            continue

        still_there = marker in path.read_text(errors="replace")
        if claimed and still_there:
            status, detail = "drift", f"claims retired but still contains {marker!r}"
        elif claimed:
            status, detail = "retired", f"verified: no {marker!r} in the file"
        elif still_there:
            status, detail = "live", site.get("note", "")
        else:
            status, detail = "drift", (
                f"inventory says live but {marker!r} is gone -- flip `retired` to true"
            )
        findings.append({"site": label, "status": status, "detail": detail})
    return findings


def _scan_pattern(
    tree: pathlib.Path, pattern: re.Pattern[str], suffixes: tuple[str, ...] = SCANNABLE_SUFFIXES
) -> set[str]:
    """Tree-relative paths of every scannable file matching `pattern`."""
    hits: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(tree):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if not filename.endswith(suffixes):
                continue
            path = pathlib.Path(dirpath) / filename
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            if pattern.search(text):
                hits.add(path.relative_to(tree).as_posix())
    return hits


def scan_backend_references(tree: pathlib.Path) -> set[str]:
    """Tree-relative paths of every file naming a state backend."""
    return _scan_pattern(tree, BACKEND_REFERENCE)


def audit_backend_references(inventory: dict, tree: pathlib.Path) -> dict:
    declared = {site["path"] for site in inventory.get("backend_reference_sites", [])}
    found = scan_backend_references(tree)
    return {
        "undeclared": sorted(found - declared),
        "stale": sorted(declared - found),
    }


def scan_provider_selection_hits(tree: pathlib.Path) -> set[str]:
    """Tree-relative paths of every file passing a `gcpkms://` scheme to
    `--secrets-provider` -- i.e. *minting* a KMS-wrapped stack."""
    return _scan_pattern(tree, PROVIDER_SELECTION, PROVIDER_SELECTION_SUFFIXES)


def audit_provider_selection_scan(inventory: dict, root: pathlib.Path | None) -> list[str]:
    """Every provider-selection hit not already named in
    `provider_selection_sites` -- the regression assertion
    `hetzner/RUNBOOK-existing-stack-migration.md` describes: re-wrapping every
    stack that *exists* is not the whole sweep while something can still
    *mint* a new KMS-wrapped one in a bucket no earlier enumeration could
    list. `audit_provider_selection_sites` above verifies the sites this
    inventory already knows about; this instead looks for one it does not.

    Same reach as the backend-reference scan: this repo's own tree
    unconditionally (`REPO_ROOT`, via `main`), every sibling repo only with
    `--root` -- because that is what CI can reach without one, and the two
    provisioning sites this inventory does know about live in `ghost-platform`,
    not here.
    """
    declared = {(site.get("repo") or THIS_REPO, site["path"]) for site in inventory.get("provider_selection_sites", [])}
    undeclared: set[str] = set()

    for hit in scan_provider_selection_hits(REPO_ROOT):
        if (THIS_REPO, hit) not in declared:
            undeclared.add(hit)

    if root is not None:
        for repo_dir in sorted(p.name for p in root.iterdir() if p.is_dir() and p.name not in SKIP_DIRS):
            for hit in scan_provider_selection_hits(root / repo_dir):
                if (repo_dir, hit) not in declared:
                    undeclared.add(f"{repo_dir}/{hit}")

    return sorted(undeclared)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

# Any status outside this set is a defect in the inventory or in a stack, and
# fails the run whatever flags were passed. The in-progress statuses --
# `pending`, `unresolved`, `needs-attestation` -- are all normal before the
# sweep runs, and only `--require-migrated` makes them fatal.
ACCEPTABLE = {
    "migrated",
    "attested-migrated",
    "attested-removed",
    "pending",
    "unresolved",
    "needs-attestation",
}


def satisfies_terminal_state(finding: dict) -> bool:
    """Whether this stack has reached the end state the inventory gives it.

    Reached via `terminal_state` rather than by demanding `migrated` from
    everything: a stack that is meant to be destroyed can never report
    `migrated`, so requiring it of all seven made the gate permanently red --
    and a gate that is red in the success state gets routed around.
    """
    return finding["status"] in SATISFIED_BY.get(finding.get("terminal_state"), set())


def render(
    findings: list[dict],
    references: dict | None,
    sites: list[dict],
    provider_selection_undeclared: list[str] | None = None,
) -> str:
    width = max(len(f["stack"]) for f in findings)
    status_width = max(len(f["status"]) for f in findings)
    lines = [
        f"{f['stack']:<{width}}  {f['status']:<{status_width}}  {f['detail']}".rstrip()
        for f in findings
    ]

    if sites:
        lines.append("")
        for site in sites:
            lines.append(
                f"provider-selection site {site['status']:<18}  {site['site']}"
                f"{'  ' + site['detail'] if site['detail'] else ''}"
            )

    if provider_selection_undeclared:
        lines.append("")
        for path in provider_selection_undeclared:
            lines.append(f"undeclared provider-selection site: {path}")

    if references is not None:
        lines.append("")
        for path in references["undeclared"]:
            lines.append(f"undeclared backend reference: {path}")
        for path in references["stale"]:
            lines.append(f"inventory names a file with no backend reference: {path}")
        if not references["undeclared"] and not references["stale"]:
            lines.append("backend references: every site in this repo is enumerated")

    unmet = [f for f in findings if not satisfies_terminal_state(f)]
    open_sites = [s for s in sites if s["status"] != "retired"]
    lines.append("")
    if unmet or open_sites:
        lines.append(
            f"sweep incomplete: {len(unmet)} stack(s) short of their terminal state, "
            f"{len(open_sites)} provider-selection site(s) not verified retired"
        )
        for f in unmet:
            if f["status"] == "unresolved":
                lines.append(f"  {f['stack']}: pass --root to reach {f['repo']}")
            elif f["status"] == "needs-attestation":
                lines.append(
                    f"  {f['stack']}: record an attestation in the inventory "
                    "once it reaches its terminal state"
                )
            else:
                lines.append(f"  {f['stack']}: {f['status']}, wants {f['terminal_state']}")
    else:
        lines.append("sweep complete: no stack depends on the GCP KMS key")

    attested = [f for f in findings if f.get("attested")]
    if attested:
        lines.append("")
        lines.append(
            "operator-attested, not machine-verified -- re-confirm each of these "
            "immediately before destroying the key version:"
        )
        for f in attested:
            lines.append(f"  {f['stack']}: {f['detail']}")
    return "\n".join(lines)


def exit_code(
    findings: list[dict],
    references: dict | None,
    require_migrated: bool,
    sites: list[dict] | None = None,
    provider_selection_undeclared: list[str] | None = None,
) -> int:
    if any(f["status"] not in ACCEPTABLE for f in findings):
        return 1
    if any(s["status"] == "drift" for s in sites or []):
        return 1
    if require_migrated:
        if any(not satisfies_terminal_state(f) for f in findings):
            return 1
        if any(s["status"] != "retired" for s in sites or []):
            return 1
    if references and (references["undeclared"] or references["stale"]):
        return 1
    # Unconditional, like the backend-reference undeclared check above: a new
    # minting site is exactly as unrecoverable on the next tenant provisioned
    # as an unmigrated existing stack, so it does not wait for
    # --require-migrated to fail the run.
    if provider_selection_undeclared:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    parser.add_argument(
        "--root",
        help="workspace directory holding the sibling repos; without it, only this repo's stacks resolve",
    )
    parser.add_argument(
        "--require-migrated",
        action="store_true",
        help="fail unless every stack has left the GCP KMS provider",
    )
    parser.add_argument(
        "--skip-reference-scan",
        action="store_true",
        help="audit stack providers and declared sites only -- skip both tree scans",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    try:
        inventory = load_inventory(args.inventory)
    except InventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    root = pathlib.Path(args.root).resolve() if args.root else None
    findings = audit_stacks(inventory, root)
    sites = audit_provider_selection_sites(inventory, root)
    references = None if args.skip_reference_scan else audit_backend_references(inventory, REPO_ROOT)
    provider_selection_undeclared = (
        [] if args.skip_reference_scan else audit_provider_selection_scan(inventory, root)
    )

    if args.as_json:
        print(
            json.dumps(
                {
                    "stacks": findings,
                    "provider_selection_sites": sites,
                    "provider_selection_undeclared": provider_selection_undeclared,
                    "backend_references": references,
                },
                indent=2,
            )
        )
    else:
        print(render(findings, references, sites, provider_selection_undeclared))

    return exit_code(findings, references, args.require_migrated, sites, provider_selection_undeclared)


if __name__ == "__main__":
    sys.exit(main())
