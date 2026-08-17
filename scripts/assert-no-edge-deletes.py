#!/usr/bin/env python3
"""Fail if a `pulumi preview --json` plan would destroy part of the shared edge.

Run as a preflight inside the CI deploy job, against the same stack state
`pulumi up` is about to act on, seconds earlier and with the same credentials.

Usage:
    assert-no-edge-deletes.py <preview-json-file>
    assert-no-edge-deletes.py --self-test
    assert-no-edge-deletes.py --verify-coverage <program-dir>

Exit status 0 if clean, 1 if a protected resource would be destroyed (or if
any input could not be read or understood), 2 on usage error.

Two ways a resource is protected, because this stack has two shapes of
resource:

* By logical id (`PROTECTED_NAMES`) -- the singletons. One reserved anycast
  IP, one Cloud Armor policy, one URL map, one certificate map, one SSL
  policy. Their names are fixed in edge.ts and carry no tenant identity. The
  set is assembled from two subsets that retire on different days, one with
  the GCP edge and one with the GCP project; the comments on each say which.

* By resource type (`PROTECTED_TYPES`) -- the per-site families. Their logical
  ids are derived from a site's name, so a name list would have to be edited
  every time a tenant is onboarded, would be forgotten, and would put the
  tenant roster in a second file. Every instance of these types is protected
  regardless of what it is called, so a new tenant is covered on the day it is
  added with no change here.

What this cannot prove, both limits real:

1. `pulumi preview` compares the program to Pulumi *state*, never to live GCP.
   A resource already deleted out of band still reads as unchanged. This gate
   answers "will this apply destroy something", not "is the edge intact" --
   RUNBOOK-edge-state-move.md appendix A is the incident where those two
   answers differed.

2. A rename carrying Pulumi's `aliases` option produces an in-place update
   with no destructive step, so the plan check correctly reports clean while
   the old logical id silently leaves the program. `--verify-coverage` is
   what closes that, and is deliberately not a substring search: a mention in
   a comment or a string constant must not count as a declaration.
"""

import contextlib
import io
import json
import pathlib
import re
import sys

# Logical ids from edge.ts. Losing any of these is an outage across every
# hostname on the edge at once, and `edge-ip` does not come back at all --
# the anycast address is reserved, and a new one means a DNS change at the
# registrar for every site before anything serves again.
#
# Retires when the GCP edge does, and not before: every name here is a live
# resource for as long as any hostname still resolves to the anycast address.
# The Hetzner edge that replaces it is not protected by adding names here.
# Its resources are declared in another Pulumi project with no CI apply path,
# and they carry `protect: true` plus the provider's own `deleteProtection`
# instead -- a stronger control than a plan parser, because it also stops a
# console click and any other holder of the project token. Deleting this set
# is therefore the last step of retiring the GCP edge, not the first step of
# building its successor.
_GCP_EDGE_NAMES = {
    "edge-ip",
    "edge-armor",
    "edge-cert-map",
    # Deleting this one is silent rather than loud: the proxy keeps serving,
    # it just falls back to GCP's default TLS profile.
    "edge-ssl-policy",
    "edge-url-map",
    "edge-https-proxy",
    "edge-https-rule",
    "edge-http-redirect",
    "edge-http-proxy",
    "edge-http-rule",
}

# Destroying any of these four locks CI out of the project with no way back
# through CI. The pool id is additionally unavailable for 30 days after
# deletion.
#
# Kept apart from the edge set because the two retire on different days: these
# survive the edge itself, since the stack still needs a CI identity to apply
# whatever GCP resources outlive the cutover, and they go when the GCP project
# goes. Deleting one set must not sweep the other out with it.
_GCP_DEPLOY_IDENTITY_NAMES = {
    "shared-infra-gha-pool",
    "shared-infra-gha-provider",
    "shared-infra-deployer-sa",
    "shared-infra-gha-can-impersonate-deployer",
}

PROTECTED_NAMES = _GCP_EDGE_NAMES | _GCP_DEPLOY_IDENTITY_NAMES

# Pulumi type tokens whose every instance is protected, mapped to the
# constructor `--verify-coverage` expects to still find in the program. The
# per-site resources: destroying one takes a single site off the edge rather
# than all of them, which is a smaller blast radius and still not a merge.
PROTECTED_TYPES = {
    "gcp:compute/regionNetworkEndpointGroup:RegionNetworkEndpointGroup": (
        "gcp.compute.RegionNetworkEndpointGroup"
    ),
    "gcp:compute/backendService:BackendService": "gcp.compute.BackendService",
    "gcp:certificatemanager/certificate:Certificate": "gcp.certificatemanager.Certificate",
    "gcp:certificatemanager/dnsAuthorization:DnsAuthorization": (
        "gcp.certificatemanager.DnsAuthorization"
    ),
    "gcp:certificatemanager/certificateMapEntry:CertificateMapEntry": (
        "gcp.certificatemanager.CertificateMapEntry"
    ),
}

# Any Pulumi step op containing either word destroys, or schedules the
# destruction of, the resource it names. Covers `delete`, `delete-replaced`,
# `replace`, `create-replacement`, `read-replacement`, `import-replacement`,
# `discard-replaced` and `remove-pending-replace` without enumerating them, so
# a future op name has to actively avoid both words to slip through.
DESTRUCTIVE_SUBSTRINGS = ("delete", "replace")


def _split_urn(urn: str) -> tuple[str, str]:
    """Return (type token, logical name) from a Pulumi URN.

    A URN is `urn:pulumi:<stack>::<project>::<type>::<name>`, and `<type>` is
    itself `::`-free while a parent chain would appear as `<parent>$<type>`.
    Splitting from the right is therefore correct for both shapes.
    """
    parts = urn.rsplit("::", 2)
    if len(parts) != 3:
        raise ValueError(f"not a resource URN: {urn!r}")
    return parts[1].rsplit("$", 1)[-1], parts[2]


def destructive_steps(plan: dict) -> list[tuple[str, str]]:
    """Return (name, op) for every protected resource this plan would destroy.

    Raises ValueError if `plan` is not a preview plan, rather than returning
    an empty list -- "I could not find any steps" and "there are no
    destructive steps" must not share an exit code.
    """
    steps = plan.get("steps")
    if not isinstance(steps, list):
        raise ValueError("no 'steps' array in the preview JSON")

    found: list[tuple[str, str]] = []
    for step in steps:
        if not isinstance(step, dict):
            raise ValueError(f"malformed step entry: {step!r}")
        op = step.get("op")
        urn = step.get("urn")
        if not isinstance(op, str) or not isinstance(urn, str):
            raise ValueError(f"step missing op/urn: {step!r}")
        if not any(word in op for word in DESTRUCTIVE_SUBSTRINGS):
            continue
        type_token, name = _split_urn(urn)
        if name in PROTECTED_NAMES or type_token in PROTECTED_TYPES:
            found.append((name, op))
    return sorted(found)


def _declaration_pattern(constructor_or_name: str, *, is_name: bool) -> re.Pattern[str]:
    """Match a resource *declaration*, not a mention of the same text.

    The obvious implementation -- searching the sources for the bare string --
    reports a false pass, because a logical id that has been renamed usually
    survives elsewhere in the program as a GCP-side name or in a comment.
    """
    if is_name:
        return re.compile(rf"""\bnew\s+[\w.]+\(\s*['"]{re.escape(constructor_or_name)}['"]""")
    return re.compile(rf"\bnew\s+{re.escape(constructor_or_name)}\s*\(")


def verify_coverage(program_dir: str) -> int:
    """Fail if anything in PROTECTED_* is no longer declared by the program.

    The quiet way this gate dies is not the matcher breaking. It is a resource
    renamed in edge.ts while the sets here keep the old id: nothing errors,
    the plan's URNs simply stop matching, and the gate passes forever while
    guarding nothing. A bare rename is still caught by the plan check, which
    sees a real delete + create; a rename carrying `aliases` is not, and this
    is the only thing standing between that and an empty gate.
    """
    directory = pathlib.Path(program_dir)
    if not directory.is_dir():
        print(f"::error::not a directory: {program_dir}")
        return 1

    sources = sorted(directory.glob("*.ts"))
    if not sources:
        print(f"::error::no .ts files found in {program_dir}; nothing was checked")
        return 1

    blob = "\n".join(path.read_text(encoding="utf-8") for path in sources)

    missing_names = [
        name
        for name in sorted(PROTECTED_NAMES)
        if not _declaration_pattern(name, is_name=True).search(blob)
    ]
    missing_types = [
        ctor
        for ctor in sorted(PROTECTED_TYPES.values())
        if not _declaration_pattern(ctor, is_name=False).search(blob)
    ]

    if missing_names:
        print(
            "::error::these logical ids are in PROTECTED_NAMES but are not the "
            f"first argument to any resource constructor in {program_dir}/*.ts: "
            f"{', '.join(missing_names)}. Either a resource was renamed and this "
            "set was not updated -- in which case the gate now protects nothing "
            "-- or it was removed on purpose and belongs out of PROTECTED_NAMES "
            "in the same change. A mention in a comment or a string constant "
            "does not count."
        )
    if missing_types:
        print(
            "::error::these constructors are in PROTECTED_TYPES but no longer "
            f"appear in {program_dir}/*.ts: {', '.join(missing_types)}. A type "
            "listed here that the program never instantiates guards nothing, and "
            "hides the fact that the resource family it covered has moved or "
            "gone."
        )
    if missing_names or missing_types:
        return 1

    print(
        f"OK: {len(PROTECTED_NAMES)} protected ids and {len(PROTECTED_TYPES)} "
        f"protected types all still declared across {len(sources)} program files."
    )
    return 0


_STACK = "urn:pulumi:production::branchleft-shared-infra::"
_URN_IP = f"{_STACK}gcp:compute/globalAddress:GlobalAddress::edge-ip"
_URN_ARMOR = f"{_STACK}gcp:compute/securityPolicy:SecurityPolicy::edge-armor"
_URN_CERT_MAP = f"{_STACK}gcp:certificatemanager/certificateMap:CertificateMap::edge-cert-map"
_URN_POOL = f"{_STACK}gcp:iam/workloadIdentityPool:WorkloadIdentityPool::shared-infra-gha-pool"
# A per-site resource, protected by type. Its logical id is derived from a
# site name, so the fixture uses the marketing site -- already public, and
# the only entry that can be named here without putting a tenant in a file
# that is not the roster.
_URN_SITE_BACKEND = f"{_STACK}gcp:compute/backendService:BackendService::website-backend"
_URN_UNPROTECTED = f"{_STACK}gcp:compute/uRLMap:URLMap::some-future-experiment"


def _plan(*steps: tuple[str, str]) -> dict:
    return {"steps": [{"op": op, "urn": urn} for op, urn in steps]}


def _quarantine(fn, *args):
    """Run fn with stdout captured, returning its result and what it printed.

    `verify_coverage` emits `::error::`-prefixed lines on the failure fixtures
    by design, and that prefix is a GitHub Actions annotation trigger. Letting
    it through would flag a fully passing self-test run as an error in the
    Actions UI, indistinguishable from a real one.
    """
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        result = fn(*args)
    return result, buffer.getvalue()


def _print_quarantined(output: str, ok: bool) -> None:
    label = (
        "fixture output, expected -- not a gate failure"
        if ok
        else "fixture output -- this case FAILED, inspect"
    )
    lines = output.rstrip("\n").splitlines()
    if not lines:
        if not ok:
            print(f"    ({label}, but nothing was captured -- inspect verify_coverage)")
        return
    for line in lines:
        print(f"    {label}: {line}")


def _coverage_self_test() -> int:
    """Prove `--verify-coverage` still tells a declaration from a mention."""
    import tempfile

    declarations = "\n".join(
        f"export const r{i} = new gcp.some.Type(\n  '{name}',\n  {{}}\n);"
        for i, name in enumerate(sorted(PROTECTED_NAMES))
    ) + "\n" + "\n".join(
        f"export const t{i} = new {ctor}(`x-${{name}}`, {{}});"
        for i, ctor in enumerate(sorted(PROTECTED_TYPES.values()))
    )

    renamed = declarations.replace("'edge-armor'", "'edge-armor-v2'", 1) + (
        # The old id survives as a comment and a constant -- the exact shape
        # that made a substring check report a clean pass.
        "\n// was edge-armor before the rename\n"
        "export const policyName = 'edge-armor';\n"
    )

    dropped_type = declarations.replace(
        "new gcp.compute.BackendService(", "new gcp.compute.SomethingElse(", 1
    )

    cases = [
        ("everything declared", declarations, 0),
        ("id renamed, old id still mentioned", renamed, 1),
        ("a protected type no longer instantiated", dropped_type, 1),
    ]

    failed = False
    with tempfile.TemporaryDirectory() as root:
        for name, source, expected in cases:
            directory = pathlib.Path(root) / name.replace(" ", "_").replace(",", "")
            directory.mkdir()
            (directory / "program.ts").write_text(source, encoding="utf-8")
            actual, output = _quarantine(verify_coverage, str(directory))
            ok = actual == expected
            failed |= not ok
            print(f"{'PASS' if ok else 'FAIL'}: coverage, {name} -> exit {actual} (expected {expected})")
            _print_quarantined(output, ok)

        empty = pathlib.Path(root) / "empty"
        empty.mkdir()
        actual, output = _quarantine(verify_coverage, str(empty))
        ok = actual == 1
        failed |= not ok
        print(f"{'PASS' if ok else 'FAIL'}: coverage, no .ts files -> exit {actual} (expected 1)")
        _print_quarantined(output, ok)

    return 1 if failed else 0


def self_test() -> int:
    cases: list[tuple[str, dict, list[tuple[str, str]]]] = [
        ("clean create-only plan", _plan(("create", _URN_IP)), []),
        ("no-op plan", _plan(("same", _URN_IP), ("same", _URN_ARMOR)), []),
        (
            "updating the Cloud Armor policy is not a destroy",
            _plan(("update", _URN_ARMOR)),
            [],
        ),
        ("outright delete", _plan(("delete", _URN_IP)), [("edge-ip", "delete")]),
        (
            "replacement, which a regex gate keyed on '(delete)' would miss",
            _plan(("replace", _URN_CERT_MAP)),
            [("edge-cert-map", "replace")],
        ),
        (
            "the create half of a replacement still counts",
            _plan(("create-replacement", _URN_POOL)),
            [("shared-infra-gha-pool", "create-replacement")],
        ),
        (
            "delete-replaced counts",
            _plan(("delete-replaced", _URN_POOL)),
            [("shared-infra-gha-pool", "delete-replaced")],
        ),
        (
            "a per-site resource is protected by type, not by a name list",
            _plan(("delete", _URN_SITE_BACKEND)),
            [("website-backend", "delete")],
        ),
        (
            "an unprotected resource of an unprotected type may be deleted",
            _plan(("delete", _URN_UNPROTECTED)),
            [],
        ),
        (
            "one protected delete hidden among unprotected churn",
            _plan(
                ("create", _URN_UNPROTECTED),
                ("delete", _URN_UNPROTECTED),
                ("update", _URN_POOL),
                ("delete", _URN_CERT_MAP),
            ),
            [("edge-cert-map", "delete")],
        ),
        ("empty plan", _plan(), []),
    ]

    failed = False
    for name, plan, expected in cases:
        actual = destructive_steps(plan)
        ok = actual == expected
        failed |= not ok
        print(f"{'PASS' if ok else 'FAIL'}: {name} -> {actual!r} (expected {expected!r})")

    for name, bad in [
        ("plan with no steps key", {}),
        ("steps is not a list", {"steps": "nope"}),
        ("step missing urn", {"steps": [{"op": "delete"}]}),
        ("urn is not a resource urn", {"steps": [{"op": "delete", "urn": "urn:pulumi:x"}]}),
    ]:
        try:
            destructive_steps(bad)
        except ValueError:
            print(f"PASS: {name} raises rather than reporting clean")
        else:
            failed = True
            print(f"FAIL: {name} returned clean instead of raising")

    # The two subsets exist so that retiring one does not silently take the
    # other with it. A name that fell out of both, or landed in both, would
    # make that split meaningless in exactly the way nothing else here notices.
    overlap = _GCP_EDGE_NAMES & _GCP_DEPLOY_IDENTITY_NAMES
    union_is_whole = _GCP_EDGE_NAMES | _GCP_DEPLOY_IDENTITY_NAMES == PROTECTED_NAMES
    if overlap or not union_is_whole:
        failed = True
        print(f"FAIL: the protected-name subsets no longer partition PROTECTED_NAMES ({overlap!r})")
    else:
        print("PASS: the protected-name subsets partition PROTECTED_NAMES")

    failed |= _coverage_self_test() != 0

    if failed:
        print("\nThis gate no longer behaves as written. It would report success")
        print("against a plan that destroys part of the shared edge.")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) == 3 and argv[1] == "--verify-coverage":
        return verify_coverage(argv[2])
    if len(argv) != 2:
        print(__doc__)
        return 2

    try:
        with open(argv[1], encoding="utf-8") as handle:
            plan = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        # Must fail. Treating an unreadable plan as an empty one would report
        # "nothing will be destroyed" without having looked at anything.
        print(f"::error::cannot read preview JSON: {error}")
        return 1

    try:
        found = destructive_steps(plan)
    except ValueError as error:
        print(f"::error::preview JSON is not a plan this gate understands: {error}")
        return 1

    if found:
        detail = ", ".join(f"{name} ({op})" for name, op in found)
        print(
            f"::error::this apply would DESTROY shared edge infrastructure: {detail}. "
            "Nothing has been applied. Every hostname branchLeft serves is behind "
            "these resources, so if it is genuinely intended it is a gated "
            "migration rather than a merge -- see RUNBOOK-ci-bootstrap.md."
        )
        return 1

    steps = plan.get("steps", [])
    summary = plan.get("changeSummary", {})
    print(
        "OK: no protected edge resource is destroyed by this plan "
        f"({len(steps)} steps checked, changeSummary={summary})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
