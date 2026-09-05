#!/usr/bin/env python3
"""Assert the committed Cloud Armor baseline capture matches edge.ts's declared shape.

Usage:
    assert-cloud-armor-baseline-parity.py
    assert-cloud-armor-baseline-parity.py --self-test
    assert-cloud-armor-baseline-parity.py --edge-ts PATH --sites-ts PATH \
        --baseline PATH --accepted-failures PATH

Exit status 0 if the committed
`cloud-armor-baseline/branchleft-edge-armor.normalized.json` matches what
`edge.ts` (read together with `sites.ts`'s current preview-only hosts)
declares for the whole `branchleft-edge-armor` Cloud Armor policy -- every
rule it builds, the rate-limit rule's actual threshold parameters, and the
policy's own name/type -- plus a check that the baseline carries no rule
`edge.ts` does not declare at all, and that every rule in it is
structurally readable. See "Scope" below for the fields this still does not
compare, and "Accepted failures" for the one way a known divergence is
allowed to exit 0. Exit 1 on any unaccepted mismatch, on an accepted
divergence that has stopped occurring, or if the source has drifted away
from a pattern this script depends on to extract a value (this fails closed
rather than silently comparing against zero expected rules and reporting
clean). Exit 2 on usage error.

Reads only committed files -- `edge.ts`, `sites.ts` and the normalized
baseline JSON. No `gcloud` call, no network access, safe to run on every
commit.

## Why this exists

CLOUD-ARMOR-BASELINE.md is a *capture*: it records what a `gcloud` read saw
at one point in time, and nothing re-verified afterwards that the capture
still describes an enforcing edge matching the code. Two ways that capture
has already been shown to diverge from `edge.ts`, both missed for a time by
the capture's own prose even though the committed JSON already showed them:

1. A rule `edge.ts` declares `preview: false` (enforcing) can be live with
   `preview: true` (merely logging) -- Cloud Armor rule updates are
   independent per-priority API calls, so a partial apply leaves some rules
   enforcing and others not, with no error anywhere. CLOUD-ARMOR-BASELINE.md
   Finding #2.
2. A WAF rule's *match expression* can drift independently of its `preview`
   flag -- the injection rules gained a preview-only-host carve-out in a
   later change to `edge.ts`, and a capture taken before the live policy was
   updated to match records the pre-change expression as current.
   CLOUD-ARMOR-BASELINE.md Finding #1.

The edge cutover gate and the wind-down's parity check both lean on this
baseline to decide the Hetzner edge reproduces the GCP edge's protections. A
baseline that silently diverges from what the code declares makes that
decision on a false premise -- this script is the thing that has to keep
saying so on every future change, not a one-time correction to the prose.

## Scope

This compares every rule `edge.ts`'s `createEdge` builds (the four base WAF
rules, the preview-only-host copies at 1100+ when any exist, the rate-limit
rule including its actual threshold/key/action parameters, and the
default-allow rule), plus the policy's own `name` and `type`. It also
asserts the baseline carries **no rule at a priority `edge.ts` does not
declare** -- Cloud Armor evaluates rules by ascending priority and stops at
the first match, so an undeclared rule can silently override every rule
below it regardless of whether every declared rule individually matches.

What it does **not** compare, and so says nothing about:

- `adaptiveProtectionConfig` and `advancedOptionsConfig`. Both affect
  enforcement (layer-7 DDoS auto-defence; JSON body parsing and log level,
  which changes what the WAF rules above can see). `edge.ts` declares
  neither, so there is no committed shape to compare against -- a live
  value there is invisible here.
- The policy-level `description`, rule-level `description` text, and the
  policy's `labels` (Pulumi-managed metadata `edge.ts` does not declare).
  None carries enforcement behaviour.
- Anything outside this one `SecurityPolicy` resource -- the URL map,
  certificate map, SSL policy and per-site backends are separate GCP
  resources this baseline does not capture and this script does not touch.

This is a *static* check: it proves the committed baseline is internally
consistent with the committed code, not that either one matches live GCP
state. Re-running "Reproducing this capture" in CLOUD-ARMOR-BASELINE.md
against live GCP is still the only way to learn whether the policy has
drifted again since the last capture.

## Accepted failures

Some divergences are known, recorded and waiting on a change this repo
cannot make (promoting the live rules out of preview is a platform-owner
action against live GCP). A permanently-red check has no differential
signal: a *new* divergence introduced tomorrow looks identical to the ones
already known, so nobody reads it, and it cannot gate anything without
blocking every unrelated deploy.

`cloud-armor-baseline/accepted-parity-failures.json` therefore enumerates
each known divergence explicitly, and the check exits 0 when the set it
finds is exactly the set recorded. The recording is deliberately narrow:

- An entry matches one divergence and one only -- same rule priority, same
  field, and the same **observed baseline value**, compared by value *and*
  by type. There is no wildcard, no priority range and no bare
  "ignore this field" form, so an entry cannot grow to swallow a divergence
  nobody decided to accept. A field whose observed value changes to
  anything else is a different divergence, and fails.
- Only rule-level divergences at a real integer priority can be accepted.
  Policy identity (`name`/`type`) and a structurally unreadable baseline
  never can: those say the file is not the policy this repo describes, and
  no pre-recorded reason answers that.
- An entry that **stops matching because the divergence stopped happening**
  fails the check, naming the entry to delete. A stale acceptance is how a
  fixed problem gets silently re-broken later. Deleting it is an edit to a
  committed file in the same commit as the fresh capture -- no live GCP
  access, so this never blocks its own remedy.
- Every entry carries the reason it is accepted and what closes it, in
  prose. Both are required and must be non-empty.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_EDGE_TS = _REPO_ROOT / "edge.ts"
_DEFAULT_SITES_TS = _REPO_ROOT / "sites.ts"
_DEFAULT_BASELINE = _REPO_ROOT / "cloud-armor-baseline" / "branchleft-edge-armor.normalized.json"
_DEFAULT_ACCEPTED_FAILURES = _REPO_ROOT / "cloud-armor-baseline" / "accepted-parity-failures.json"


class ExtractionError(ValueError):
    """A pattern this script depends on to read a value out of source is gone.

    Raised rather than returning an empty/default result, because a silent
    empty result here means "compare against zero expected rules", which
    reports a clean pass while checking nothing -- the exact failure mode
    this whole script exists to catch one level up, reproduced in its own
    implementation if extraction is allowed to fail soft.
    """


def _extract(pattern: str, text: str, what: str, *, source: str = "edge.ts") -> str:
    match = re.search(pattern, text, re.DOTALL)
    if not match:
        raise ExtractionError(
            f"could not find {what} in {source} -- its shape has changed and "
            "this script needs updating alongside it. Until then it must "
            "fail rather than silently check nothing."
        )
    return match.group(1)


def extract_owasp_rulesets(edge_ts: str) -> list[str]:
    """The ordered ruleset list; array index `i` sets Cloud Armor priority `1000 + i`."""
    raw = _extract(r"const OWASP_RULESETS\s*=\s*\[(.*?)\];", edge_ts, "OWASP_RULESETS")
    if not re.search(r"priority:\s*1000\s*\+\s*i\b", edge_ts):
        raise ExtractionError(
            "OWASP_RULESETS's priority formula ('priority: 1000 + i') was not "
            "found in edge.ts -- the base WAF rules may no longer start at "
            "priority 1000, and this script's priority assumption is stale."
        )
    return [item.strip().strip("'\"") for item in raw.split(",") if item.strip()]


def extract_content_sensitive_rulesets(edge_ts: str) -> set[str]:
    raw = _extract(
        r"const CONTENT_SENSITIVE_RULESETS\s*=\s*new Set\(\[(.*?)\]\);",
        edge_ts,
        "CONTENT_SENSITIVE_RULESETS",
    )
    return {item.strip().strip("'\"") for item in raw.split(",") if item.strip()}


def extract_rate_limit_priority(edge_ts: str) -> int:
    raw = _extract(
        r"action:\s*'throttle',\s*priority:\s*(\d+)",
        edge_ts,
        "the rate-limit rule's priority",
    )
    return int(raw)


def extract_rate_limit_params(edge_ts: str) -> tuple[int, int]:
    """(requests, interval_seconds) the rate-limit rule actually throttles at."""
    requests = _extract(r"const RATE_LIMIT_REQUESTS\s*=\s*(\d+);", edge_ts, "RATE_LIMIT_REQUESTS")
    interval = _extract(
        r"const RATE_LIMIT_INTERVAL_SEC\s*=\s*(\d+);", edge_ts, "RATE_LIMIT_INTERVAL_SEC"
    )
    return int(requests), int(interval)


def extract_preview_copy_base_priority(edge_ts: str) -> int:
    """The priority the preview-only-host rule copies start at (1100 + i)."""
    if not re.search(r"priority:\s*1100\s*\+\s*i\b", edge_ts):
        raise ExtractionError(
            "could not find the preview-only-host copies' priority formula "
            "('priority: 1100 + i') in edge.ts -- their base priority may "
            "have changed, and this script's assumption of 1100 is stale."
        )
    return 1100


def extract_default_allow_priority(edge_ts: str) -> int:
    raw = _extract(
        r"action:\s*'allow',\s*priority:\s*(\d+),\s*description:\s*'Default: allow'",
        edge_ts,
        "the default-allow rule's priority",
    )
    return int(raw)


def extract_policy_name(edge_ts: str) -> str:
    return _extract(
        r"new gcp\.compute\.SecurityPolicy\(\s*['\"]edge-armor['\"],\s*\{\s*name:\s*['\"]([^'\"]+)['\"]",
        edge_ts,
        "the Cloud Armor policy's declared name",
    )


def _confirm_literal(edge_ts: str, literal: str, what: str) -> None:
    """Guard a Python-side re-implementation of a small edge.ts code fragment.

    Several values below (the expression builders, the rate-limit action
    names, the policy `type`) are mirrored in Python by hand rather than by
    parsing TypeScript -- there is no JS engine here to evaluate the real
    code. That mirror silently going stale is exactly the "protects nothing
    after a rename" failure mode, so every literal it depends on is confirmed
    present in the real source before it is trusted.
    """
    if literal not in edge_ts:
        raise ExtractionError(
            f"could not find {what} ({literal!r}) in edge.ts -- the "
            "code this script mirrors in Python has changed shape; this "
            "script needs updating alongside it."
        )


def preconfigured_waf_expression(ruleset: str) -> str:
    """Mirrors edge.ts's `preconfiguredWaf`."""
    return f"evaluatePreconfiguredWaf('{ruleset}', {{'sensitivity': 1}})"


def host_equals_expression(hostname: str) -> str:
    """Mirrors edge.ts's `hostEquals`."""
    return f"request.headers['host'].lower() == '{hostname}'"


def _split_top_level_objects(array_body: str) -> list[str]:
    """Split a `{...}, {...}` array body into each top-level object's inner text.

    Tracks brace depth by hand rather than a non-greedy regex brace match, so
    a *future* site entry with a nested object (an options bag, say) does not
    get truncated at its own first inner `}` -- a regex-based
    `\\{(.*?)\\n\\s*\\},?` would silently stop there, and a
    `injectionWafPreviewOnly: true` sitting after the nested object would be
    missed with no error raised at all. `sites.ts` has no such nesting today;
    this exists so that staying true does not depend on it staying true.
    """
    objects: list[str] = []
    depth = 0
    start: int | None = None
    for i, ch in enumerate(array_body):
        if ch == "{":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                objects.append(array_body[start:i])
                start = None
    return objects


def extract_preview_only_hosts(sites_ts: str) -> list[str]:
    """Every hostname of a site with `injectionWafPreviewOnly: true` in sites.ts.

    Parses each top-level object literal in the `sites` array rather than
    grepping for `hostnames:` anywhere in the file, so a `hostnames:` array
    belonging to a *different* site cannot be misattributed to one that sets
    `injectionWafPreviewOnly`. This does not strip comments, so a flag
    commented out *within its own site's object* is still matched -- only
    cross-object misattribution is what this guards against.

    A site with no `cloudRunService` is skipped, mirroring `previewOnlyHosts`
    in edge.ts. This function re-implements that derivation rather than reading
    it, so the two can silently diverge -- and would have: when
    `cloudRunService` became optional, edge.ts stopped exempting Hetzner-only
    hosts while this script went on including them, turning the production
    edge's deploy gate red against a model of a program that no longer existed.
    The mirroring is asserted by this module's own self-test rather than left
    to review.
    """
    body = _extract(
        r"export const sites:\s*EdgeSite\[\]\s*=\s*\[(.*?)\n\];",
        sites_ts,
        "the `sites` array",
        source="sites.ts",
    )

    hosts: list[str] = []
    for site_text in _split_top_level_objects(body):
        if not re.search(r"injectionWafPreviewOnly\s*:\s*true", site_text):
            continue
        # No cloudRunService means edge.ts skips the site entirely, so it has
        # no rule here to be exempted from. See `previewOnlyHosts` in edge.ts.
        if not re.search(r"cloudRunService\s*:", site_text):
            continue
        hostnames_match = re.search(r"hostnames\s*:\s*\[(.*?)\]", site_text, re.DOTALL)
        if not hostnames_match:
            raise ExtractionError(
                "a site in sites.ts sets injectionWafPreviewOnly: true but "
                "this script could not find its hostnames array"
            )
        hosts.extend(
            item.strip().strip("'\"") for item in hostnames_match.group(1).split(",") if item.strip()
        )
    return hosts


@dataclass
class ExpectedRule:
    priority: int
    label: str
    action: str
    preview: bool
    # Exactly one of these two is set, for the two match shapes this policy's
    # rules use: a CEL expression (the WAF rules) or a wildcard IP range (the
    # throttle and default-allow rules).
    expression: str | None = None
    src_ip_ranges: list[str] | None = None
    # Dotted-path -> expected value, for fields nested deeper than `action`/
    # `preview`/`match` -- currently only the rate-limit rule's
    # `rateLimitOptions.*`.
    extra: dict[str, object] = field(default_factory=dict)


def expected_rules(edge_ts: str, sites_ts: str) -> list[ExpectedRule]:
    """Every rule edge.ts's `createEdge` declares for this policy."""
    _confirm_literal(edge_ts, "evaluatePreconfiguredWaf(", "the preconfigured-WAF expression builder")
    _confirm_literal(edge_ts, "{'sensitivity': 1}", "the WAF sensitivity literal")
    _confirm_literal(edge_ts, "request.headers['host'].lower() ==", "the host-match expression builder")
    _confirm_literal(edge_ts, "conformAction: 'allow'", "the rate-limit conform action")
    _confirm_literal(edge_ts, "exceedAction: 'deny(429)'", "the rate-limit exceed action")
    _confirm_literal(edge_ts, "enforceOnKey: 'IP'", "the rate-limit enforcement key")
    _confirm_literal(edge_ts, "type: 'CLOUD_ARMOR'", "the policy's declared type")
    _confirm_literal(edge_ts, "action: 'deny(403)'", "the WAF rules' deny action")
    _confirm_literal(edge_ts, "srcIpRanges: ['*']", "the wildcard source-IP match")
    _confirm_literal(edge_ts, "preview: false", "an enforcing rule's preview literal")
    _confirm_literal(edge_ts, "preview: true", "a preview-only copy's preview literal")

    rulesets = extract_owasp_rulesets(edge_ts)
    content_sensitive = extract_content_sensitive_rulesets(edge_ts)
    preview_only_hosts = extract_preview_only_hosts(sites_ts)
    rate_limit_priority = extract_rate_limit_priority(edge_ts)
    rate_limit_requests, rate_limit_interval = extract_rate_limit_params(edge_ts)
    preview_copy_base_priority = extract_preview_copy_base_priority(edge_ts)
    default_allow_priority = extract_default_allow_priority(edge_ts)

    is_not_preview_only_host = " && ".join(f"!({host_equals_expression(h)})" for h in preview_only_hosts)
    is_preview_only_host = " || ".join(host_equals_expression(h) for h in preview_only_hosts)

    rules: list[ExpectedRule] = []

    # The four base WAF rules.
    for i, ruleset in enumerate(rulesets):
        expression = preconfigured_waf_expression(ruleset)
        if ruleset in content_sensitive and preview_only_hosts:
            expression = f"{expression} && {is_not_preview_only_host}"
        rules.append(
            ExpectedRule(
                priority=1000 + i,
                label=ruleset,
                action="deny(403)",
                preview=False,
                expression=expression,
            )
        )

    # The preview-only-host copies -- only exist when there is at least one
    # such host, and MUST stay preview: true (flipping one to enforcing means
    # blocking the authenticated-authoring host these exist to exempt).
    if preview_only_hosts:
        content_sensitive_in_order = [r for r in rulesets if r in content_sensitive]
        for i, ruleset in enumerate(content_sensitive_in_order):
            rules.append(
                ExpectedRule(
                    priority=preview_copy_base_priority + i,
                    label=f"{ruleset} (preview-only hosts)",
                    action="deny(403)",
                    preview=True,
                    expression=f"{preconfigured_waf_expression(ruleset)} && ({is_preview_only_host})",
                )
            )

    # The rate-limit rule -- action, preview and its actual threshold/key
    # parameters. A rule that is "throttle, enforcing" but throttles nothing
    # (a huge count, a defeated key, an `allow` exceedAction) is not caught
    # by action/preview alone.
    rules.append(
        ExpectedRule(
            priority=rate_limit_priority,
            label="rate-limit",
            action="throttle",
            preview=False,
            src_ip_ranges=["*"],
            extra={
                "rateLimitOptions.conformAction": "allow",
                "rateLimitOptions.exceedAction": "deny(429)",
                "rateLimitOptions.enforceOnKey": "IP",
                "rateLimitOptions.rateLimitThreshold.count": rate_limit_requests,
                "rateLimitOptions.rateLimitThreshold.intervalSec": rate_limit_interval,
            },
        )
    )

    # The default-allow catch-all. edge.ts sets no `preview` key on this rule
    # at all (falsy/absent), and the committed baseline already carries an
    # explicit `preview: false` for it -- comparing against False here does
    # not introduce new noise against the already-correct live data.
    rules.append(
        ExpectedRule(
            priority=default_allow_priority,
            label="default-allow",
            action="allow",
            preview=False,
            src_ip_ranges=["*"],
        )
    )

    return rules


def _get_path(value: object, path: str) -> object:
    """Walk a dotted path through nested dicts. None on any missing/non-dict step.

    Never raises -- a rule field that is `null`, missing, or a differently
    shaped value than expected must be reported as a mismatch by the caller,
    not crash the comparison before it can be reported.
    """
    current = value
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _is_real_int(value: object) -> bool:
    """True for a JSON integer. `bool` is a subclass of `int` in Python, and
    `true` is not a priority."""
    return isinstance(value, int) and not isinstance(value, bool)


def _baseline_rules_by_priority(baseline: object) -> dict[int, dict]:
    """Index the baseline's rules by priority, refusing anything unreadable.

    Every rejection here was a silent drop in an earlier version, and each
    one reopened the bypass the extra-rule check below exists to close: a
    rule this function does not return is a rule no later check can see, so
    an `allow`-everything entry carrying a string priority, no priority at
    all, a non-object shape, or a duplicate of a real priority read as
    parity. An unparseable rule is an unanswered question about what the
    edge enforces, not an absent one -- it fails closed and says which
    entry it could not read.
    """
    if not isinstance(baseline, dict):
        raise ExtractionError(
            f"baseline is not a JSON object (got {type(baseline).__name__}) -- "
            "this is not a Cloud Armor policy capture."
        )
    rules = baseline.get("rules")
    if not isinstance(rules, list):
        raise ExtractionError("baseline JSON has no 'rules' array")
    by_priority: dict[int, dict] = {}
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ExtractionError(
                f"baseline rules[{index}] is not a JSON object (got "
                f"{type(rule).__name__}) -- this script cannot tell what rule "
                "it declares, and a rule it cannot read is one no parity "
                "check below can see."
            )
        if "priority" not in rule:
            raise ExtractionError(
                f"baseline rules[{index}] has no 'priority' -- Cloud Armor "
                "evaluates by ascending priority, so a rule without one has "
                "no defined position relative to the rules edge.ts declares."
            )
        priority = rule["priority"]
        if not _is_real_int(priority):
            raise ExtractionError(
                f"baseline rules[{index}] has priority {priority!r}, which is "
                "not a JSON integer -- a real capture never emits one, and "
                "silently skipping it would hide the rule from every check."
            )
        if priority in by_priority:
            raise ExtractionError(
                f"baseline has two rules at priority {priority} -- Cloud Armor "
                "would reject that policy, so this file is hand-edited or "
                "badly merged. Neither entry can be trusted over the other, "
                "and picking one would let the other bypass every check."
            )
        by_priority[priority] = rule
    return by_priority


@dataclass(frozen=True)
class Problem:
    """One divergence, in a form an accepted-failures entry can name exactly.

    `priority`/`field`/`observed` are the identity an acceptance matches on;
    `message` is what a human reads. `priority is None` marks a divergence
    about the policy itself rather than one of its rules, which no
    acceptance may match.
    """

    priority: int | None
    field: str
    observed: object
    message: str


def check_parity(edge_ts: str, sites_ts: str, baseline: object) -> list[Problem]:
    """Return every way the baseline diverges from edge.ts's declared shape.

    An empty list means clean. Only ExtractionError propagates -- for a
    *mismatch* this returns findings rather than raising, so a caller can
    report all of them at once instead of stopping at the first.
    """
    problems: list[Problem] = []
    by_priority = _baseline_rules_by_priority(baseline)
    expected = expected_rules(edge_ts, sites_ts)

    for rule in expected:
        live = by_priority.get(rule.priority)
        if live is None:
            problems.append(
                Problem(
                    rule.priority,
                    "rule",
                    None,
                    f"priority {rule.priority} ({rule.label}): edge.ts declares "
                    "this rule but the baseline has none at this priority.",
                )
            )
            continue

        live_action = live.get("action")
        if live_action != rule.action:
            problems.append(
                Problem(
                    rule.priority,
                    "action",
                    live_action,
                    f"priority {rule.priority} ({rule.label}): baseline action="
                    f"{live_action!r}, edge.ts declares {rule.action!r}.",
                )
            )

        # Absent means "not in preview" -- edge.ts omits the key entirely on
        # the default-allow rule. Anything that is neither absent nor a JSON
        # boolean is reported rather than coerced: `bool("false")` is True,
        # so coercing reads a non-enforcing rule as enforcing.
        raw_preview = live.get("preview", False)
        if not isinstance(raw_preview, bool):
            problems.append(
                Problem(
                    rule.priority,
                    "preview",
                    raw_preview,
                    f"priority {rule.priority} ({rule.label}): baseline preview="
                    f"{raw_preview!r} is not a JSON boolean. A real capture "
                    "never emits one, and reading it as either true or false "
                    "would be a guess about whether this rule enforces.",
                )
            )
        elif raw_preview != rule.preview:
            problems.append(
                Problem(
                    rule.priority,
                    "preview",
                    raw_preview,
                    f"priority {rule.priority} ({rule.label}): baseline preview="
                    f"{raw_preview!r}, edge.ts declares preview: {rule.preview!r} -- "
                    + (
                        "this rule is not enforcing on the live policy even though "
                        "the code says it should be."
                        if not rule.preview
                        else "this rule is enforcing on the live policy even though it "
                        "is meant to stay in preview -- it would block the "
                        "preview-only-host exemption exists to protect."
                    ),
                )
            )

        if rule.expression is not None:
            live_expression = _get_path(live, "match.expr.expression")
            if live_expression != rule.expression:
                problems.append(
                    Problem(
                        rule.priority,
                        "match.expr.expression",
                        live_expression,
                        f"priority {rule.priority} ({rule.label}): baseline match "
                        "expression does not match edge.ts's declared shape.\n"
                        f"        expected: {rule.expression!r}\n"
                        f"        baseline: {live_expression!r}",
                    )
                )

        if rule.src_ip_ranges is not None:
            live_ranges = _get_path(live, "match.config.srcIpRanges")
            if live_ranges != rule.src_ip_ranges:
                problems.append(
                    Problem(
                        rule.priority,
                        "match.config.srcIpRanges",
                        live_ranges,
                        f"priority {rule.priority} ({rule.label}): baseline "
                        f"match.config.srcIpRanges={live_ranges!r}, edge.ts declares "
                        f"{rule.src_ip_ranges!r}.",
                    )
                )

        for path, expected_value in rule.extra.items():
            actual_value = _get_path(live, path)
            if actual_value != expected_value:
                problems.append(
                    Problem(
                        rule.priority,
                        path,
                        actual_value,
                        f"priority {rule.priority} ({rule.label}): baseline {path}="
                        f"{actual_value!r}, edge.ts declares {expected_value!r}.",
                    )
                )

    # No rule the baseline carries that edge.ts does not declare. Cloud Armor
    # evaluates ascending by priority and stops at the first match, so an
    # undeclared rule here -- at any priority, not only below the checked
    # rules -- can silently pre-empt or shadow enforcement that every check
    # above would otherwise report as clean.
    expected_priorities = {rule.priority for rule in expected}
    for extra_priority in sorted(set(by_priority) - expected_priorities):
        problems.append(
            Problem(
                extra_priority,
                "undeclared-rule",
                by_priority[extra_priority].get("action"),
                f"priority {extra_priority}: the baseline has a rule here that edge.ts "
                "does not declare at all. Cloud Armor evaluates rules by ascending "
                "priority and stops at the first match, so an undeclared rule can "
                "silently override every declared rule's enforcement regardless of "
                "whether each of those individually matches edge.ts.",
            )
        )

    # Policy identity carries priority=None deliberately: an acceptance can
    # only name a rule-level divergence, so neither of these can ever be
    # accepted. A capture of a different policy answers no question about
    # this one.
    expected_name = extract_policy_name(edge_ts)
    live_name = baseline.get("name")
    if live_name != expected_name:
        problems.append(
            Problem(
                None,
                "name",
                live_name,
                f"baseline policy name={live_name!r}, edge.ts declares {expected_name!r}.",
            )
        )
    live_type = baseline.get("type")
    if live_type != "CLOUD_ARMOR":
        problems.append(
            Problem(
                None,
                "type",
                live_type,
                f"baseline policy type={live_type!r}, edge.ts declares 'CLOUD_ARMOR'.",
            )
        )

    return problems


# --------------------------------------------------------------------------
# Accepted failures
# --------------------------------------------------------------------------

_ACCEPTED_FAILURE_KEYS = {"priority", "field", "observed", "reason", "closedBy"}


@dataclass(frozen=True)
class AcceptedFailure:
    priority: int
    field: str
    observed: object
    reason: str
    closed_by: str

    def describe(self) -> str:
        return f"priority {self.priority}, field {self.field!r}, observed {self.observed!r}"


def _same_value(left: object, right: object) -> bool:
    """Equality that does not conflate types.

    `True == 1` and `1 == 1.0` in Python. An acceptance names one observed
    value; a baseline that changed a boolean to a number changed what the
    edge does, and must not match the entry recorded for the boolean.
    """
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_same_value(a, b) for a, b in zip(left, right))
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(_same_value(left[k], right[k]) for k in left)
    if type(left) is not type(right):
        return False
    return left == right


def parse_accepted_failures(document: object) -> list[AcceptedFailure]:
    """Validate the accepted-failures document and return its entries.

    Strict by design. Every rejection below is a shape that would let one
    entry cover more than the single divergence someone decided to accept --
    a missing key, an unknown key that was meant to widen the match, a
    non-integer priority, or two entries fighting over the same field. The
    file's whole value is that it cannot become a blanket suppressor, and
    that property lives here.
    """
    if not isinstance(document, dict):
        raise ExtractionError(
            f"accepted-failures file is not a JSON object (got {type(document).__name__})."
        )
    entries = document.get("accepted")
    if not isinstance(entries, list):
        raise ExtractionError("accepted-failures file has no 'accepted' array.")

    parsed: list[AcceptedFailure] = []
    seen: set[tuple[int, str]] = set()
    for index, entry in enumerate(entries):
        where = f"accepted[{index}]"
        if not isinstance(entry, dict):
            raise ExtractionError(f"{where} is not a JSON object.")
        keys = set(entry)
        missing = _ACCEPTED_FAILURE_KEYS - keys
        if missing:
            raise ExtractionError(
                f"{where} is missing required key(s): {', '.join(sorted(missing))}."
            )
        unknown = keys - _ACCEPTED_FAILURE_KEYS
        if unknown:
            raise ExtractionError(
                f"{where} has unrecognised key(s): {', '.join(sorted(unknown))}. "
                "This file has no wildcard or range form; an entry names one "
                "priority, one field and one observed value."
            )
        if not _is_real_int(entry["priority"]):
            raise ExtractionError(
                f"{where} has priority {entry['priority']!r}, which is not an "
                "integer. Only a rule-level divergence at a real priority can "
                "be accepted -- policy identity and an unreadable baseline "
                "never can."
            )
        for text_key in ("field", "reason", "closedBy"):
            value = entry[text_key]
            if not isinstance(value, str) or not value.strip():
                raise ExtractionError(f"{where} has an empty or non-string {text_key!r}.")
        key = (entry["priority"], entry["field"])
        if key in seen:
            raise ExtractionError(
                f"{where} duplicates priority {entry['priority']} field "
                f"{entry['field']!r}. Two entries for one field cannot both be "
                "the divergence that is happening, so one is already stale."
            )
        seen.add(key)
        parsed.append(
            AcceptedFailure(
                priority=entry["priority"],
                field=entry["field"],
                observed=entry["observed"],
                reason=entry["reason"],
                closed_by=entry["closedBy"],
            )
        )
    return parsed


def apply_accepted_failures(
    problems: list[Problem], accepted: list[AcceptedFailure]
) -> tuple[list[Problem], list[AcceptedFailure], list[AcceptedFailure]]:
    """Split problems by what the accepted-failures file records.

    Returns (unaccepted problems, entries that matched, entries that did
    not). The third list is the stale ones: a divergence that has stopped
    occurring, whose entry must be deleted rather than left to suppress a
    future recurrence of the same field silently.
    """
    remaining = list(problems)
    matched: list[AcceptedFailure] = []
    stale: list[AcceptedFailure] = []
    for entry in accepted:
        hit = next(
            (
                problem
                for problem in remaining
                if problem.priority == entry.priority
                and problem.field == entry.field
                and _same_value(problem.observed, entry.observed)
            ),
            None,
        )
        if hit is None:
            stale.append(entry)
        else:
            remaining.remove(hit)
            matched.append(entry)
    return remaining, matched, stale


_FLAGS = ("--edge-ts", "--sites-ts", "--baseline", "--accepted-failures")


def _parse_args(argv: list[str]) -> tuple[Path, Path, Path, Path] | None:
    """Return the four input paths, or None on a usage error.

    Override flags exist for tests -- to point this at a temp-directory
    fixture representing a doctored input, real or synthetic, rather than
    only at this checkout's own files. There is no default-invocation code
    path that skips a real file read.

    An explicitly-supplied *empty* value is a usage error, not a fall-back
    to the default path. Truthiness here would make `--baseline "$CAPTURE"`
    with `CAPTURE` unset check the committed file and print a green result
    about a file it was never pointed at -- and an unset variable in a test
    harness is exactly where that goes unnoticed.
    """
    defaults = (_DEFAULT_EDGE_TS, _DEFAULT_SITES_TS, _DEFAULT_BASELINE, _DEFAULT_ACCEPTED_FAILURES)
    flags: dict[str, str | None] = {name: None for name in _FLAGS}
    args = argv[1:]
    i = 0
    while i < len(args):
        if args[i] in flags and i + 1 < len(args):
            if flags[args[i]] is not None:
                return None
            flags[args[i]] = args[i + 1]
            i += 2
        else:
            return None
    resolved = []
    for name, default in zip(_FLAGS, defaults):
        value = flags[name]
        if value is None:
            resolved.append(default)
            continue
        if not value.strip():
            print(f"::error::{name} was given an empty value.")
            return None
        resolved.append(Path(value))
    return resolved[0], resolved[1], resolved[2], resolved[3]


def _report(problems: list[Problem], accepted_path: Path) -> None:
    print(
        f"::error::the committed Cloud Armor baseline diverges from edge.ts's "
        f"declared shape in {len(problems)} way(s) that "
        f"{accepted_path.name} does not record:"
    )
    for problem in problems:
        print(f"  - {problem.message}")
    print(
        "This means the edge parity gate would read this baseline as "
        "evidence the edge enforces what edge.ts declares, when it does not. Do "
        "not silence this check by widening the accepted-failures file to cover "
        "a divergence nobody decided to accept. Either fix the divergence, or -- "
        "if it is genuinely known and waiting on a live change this repo cannot "
        "make -- add an entry naming its exact priority, field and observed "
        "value, with the reason and what closes it."
    )


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()

    parsed = _parse_args(argv)
    if parsed is None:
        print(__doc__)
        return 2
    edge_ts_path, sites_ts_path, baseline_path, accepted_path = parsed

    try:
        edge_ts = edge_ts_path.read_text(encoding="utf-8")
        sites_ts = sites_ts_path.read_text(encoding="utf-8")
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        accepted_document = json.loads(accepted_path.read_text(encoding="utf-8"))
    except OSError as error:
        print(f"::error::could not read input: {error}")
        return 1
    except json.JSONDecodeError as error:
        print(f"::error::baseline is not valid JSON: {error}")
        return 1

    try:
        accepted = parse_accepted_failures(accepted_document)
        problems = check_parity(edge_ts, sites_ts, baseline)
    except ExtractionError as error:
        print(f"::error::{error}")
        return 1

    unaccepted, matched, stale = apply_accepted_failures(problems, accepted)

    if unaccepted:
        _report(unaccepted, accepted_path)
        return 1

    if stale:
        print(
            f"::error::{len(stale)} entry/entries in {accepted_path.name} record a "
            "divergence that is no longer happening:"
        )
        for entry in stale:
            print(f"  - {entry.describe()} -- accepted because: {entry.reason}")
        print(
            "This is good news that must not be left implicit. Delete these "
            "entries in the same commit as the change that closed them. Leaving "
            "one in place would let the same field silently diverge again later "
            "and still read as accepted."
        )
        return 1

    checked = len(expected_rules(edge_ts, sites_ts))
    if matched:
        print(
            f"OK: committed baseline matches edge.ts's declared shape for all "
            f"{checked} checked rules, except {len(matched)} recorded, still-open "
            f"divergence(s) in {accepted_path.name}:"
        )
        for entry in matched:
            print(f"  - {entry.describe()}\n      closed by: {entry.closed_by}")
    else:
        print(f"OK: committed baseline matches edge.ts's declared shape for all {checked} checked rules.")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

_FIXTURE_EDGE_TS = """
const OWASP_RULESETS = ['sqli-v33-stable', 'xss-v33-stable', 'rce-v33-stable', 'lfi-v33-stable'];

const CONTENT_SENSITIVE_RULESETS = new Set(['sqli-v33-stable', 'xss-v33-stable', 'rce-v33-stable']);

const preconfiguredWaf = (ruleset) =>
  `evaluatePreconfiguredWaf('${ruleset}', {'sensitivity': 1})`;

const hostEquals = (hostname) => `request.headers['host'].lower() == '${hostname}'`;

const RATE_LIMIT_REQUESTS = 200;
const RATE_LIMIT_INTERVAL_SEC = 60;

const ALL_SOURCE_IPS = {
  versionedExpr: 'SRC_IPS_V1',
  config: { srcIpRanges: ['*'] },
};

  const securityPolicy = new gcp.compute.SecurityPolicy('edge-armor', {
    name: 'branchleft-edge-armor',
    description: 'Shared Cloud Armor policy for the branchLeft edge load balancer',
    type: 'CLOUD_ARMOR',
    rules: [
      ...OWASP_RULESETS.map((ruleset, i) => ({
        action: 'deny(403)',
        priority: 1000 + i,
        match: { expr: { expression: preconfiguredWaf(ruleset) } },
        preview: false,
      })),
      ...OWASP_RULESETS.filter((ruleset) => CONTENT_SENSITIVE_RULESETS.has(ruleset)).map(
        (ruleset, i) => ({
          action: 'deny(403)',
          priority: 1100 + i,
          match: { expr: { expression: `${preconfiguredWaf(ruleset)} && (${isPreviewOnlyHost})` } },
          preview: true,
        })
      ),
      {
        action: 'throttle',
        priority: 2000,
        match: ALL_SOURCE_IPS,
        rateLimitOptions: {
          conformAction: 'allow',
          exceedAction: 'deny(429)',
          enforceOnKey: 'IP',
          rateLimitThreshold: {
            count: RATE_LIMIT_REQUESTS,
            intervalSec: RATE_LIMIT_INTERVAL_SEC,
          },
        },
        preview: false,
      },
      {
        action: 'allow',
        priority: 2147483647,
        description: 'Default: allow',
        match: ALL_SOURCE_IPS,
      },
    ],
  });
"""

_FIXTURE_EDGE_TS_NO_OWASP_CONST = _FIXTURE_EDGE_TS.replace("const OWASP_RULESETS", "const RENAMED_RULESETS")

_FIXTURE_SITES_TS_ONE_PREVIEW_HOST = """
export const sites: EdgeSite[] = [
  {
    name: 'marketing',
    hostnames: ['example.test'],
    cloudRunService: 'svc',
    region: 'us',
  },

  {
    name: 'blog',
    hostnames: ['blog.example.test'],
    cloudRunService: 'svc2',
    region: 'us',
    injectionWafPreviewOnly: true,
  },
];
"""

_FIXTURE_SITES_TS_TWO_PREVIEW_HOSTS = """
export const sites: EdgeSite[] = [
  {
    name: 'blog',
    hostnames: ['blog.example.test'],
    cloudRunService: 'svc',
    region: 'us',
    injectionWafPreviewOnly: true,
  },

  {
    name: 'docs',
    hostnames: ['docs.example.test', 'help.example.test'],
    cloudRunService: 'svc2',
    region: 'us',
    injectionWafPreviewOnly: true,
  },
];
"""

_FIXTURE_SITES_TS_NO_PREVIEW_HOSTS = """
export const sites: EdgeSite[] = [
  {
    name: 'marketing',
    hostnames: ['example.test'],
    cloudRunService: 'svc',
    region: 'us',
  },
];
"""


def _baseline_from_expected(rules: list[ExpectedRule], *, name: str = "branchleft-edge-armor", type_: str = "CLOUD_ARMOR") -> dict:
    """A committed-baseline-shaped dict that matches `rules` exactly."""
    out = []
    for rule in rules:
        entry: dict = {"action": rule.action, "priority": rule.priority, "preview": rule.preview}
        if rule.expression is not None:
            entry["match"] = {"expr": {"expression": rule.expression}}
        elif rule.src_ip_ranges is not None:
            entry["match"] = {"config": {"srcIpRanges": list(rule.src_ip_ranges)}, "versionedExpr": "SRC_IPS_V1"}
        for path, value in rule.extra.items():
            parts = path.split(".")
            cursor = entry
            for part in parts[:-1]:
                cursor = cursor.setdefault(part, {})
            cursor[parts[-1]] = value
        out.append(entry)
    return {"name": name, "type": type_, "rules": out}


def _messages(problems: list[Problem]) -> list[str]:
    return [problem.message for problem in problems]


def _accepting(*entries: tuple[int, str, object]) -> list[AcceptedFailure]:
    """Accepted-failure entries for a test, with placeholder prose."""
    return [
        AcceptedFailure(priority=p, field=f, observed=o, reason="TEST", closed_by="TEST")
        for p, f, o in entries
    ]


def self_test() -> int:
    """Hermetic. Every assertion below runs against a fixture built in this
    file or a temp directory.

    Deliberately says nothing about this checkout's own `edge.ts`,
    `sites.ts` or committed baseline. An assertion here that the real files
    are currently *broken* would start failing the moment someone fixed
    them -- turning the self-test, which every pre-commit edit to this
    script runs, into a second copy of the real check that only a live GCP
    change could satisfy. The real files' state is what the real check
    reports, and that is the only thing that should report it.
    """
    failed = False

    def check(condition: bool, message: str) -> None:
        nonlocal failed
        if not condition:
            print(f"FAIL: {message}")
            failed = True

    # --- extraction -------------------------------------------------------
    rulesets = extract_owasp_rulesets(_FIXTURE_EDGE_TS)
    check(
        rulesets == ["sqli-v33-stable", "xss-v33-stable", "rce-v33-stable", "lfi-v33-stable"],
        f"unexpected OWASP_RULESETS extraction: {rulesets}",
    )
    content_sensitive = extract_content_sensitive_rulesets(_FIXTURE_EDGE_TS)
    check(
        content_sensitive == {"sqli-v33-stable", "xss-v33-stable", "rce-v33-stable"},
        f"unexpected CONTENT_SENSITIVE_RULESETS extraction: {content_sensitive}",
    )
    check(extract_rate_limit_priority(_FIXTURE_EDGE_TS) == 2000, "unexpected rate-limit priority extraction")
    check(
        extract_rate_limit_params(_FIXTURE_EDGE_TS) == (200, 60),
        "unexpected rate-limit params extraction",
    )
    check(extract_preview_copy_base_priority(_FIXTURE_EDGE_TS) == 1100, "unexpected preview-copy base priority")
    check(
        extract_default_allow_priority(_FIXTURE_EDGE_TS) == 2147483647,
        "unexpected default-allow priority extraction",
    )
    check(
        extract_policy_name(_FIXTURE_EDGE_TS) == "branchleft-edge-armor",
        "unexpected policy name extraction",
    )

    hosts_one = extract_preview_only_hosts(_FIXTURE_SITES_TS_ONE_PREVIEW_HOST)
    check(hosts_one == ["blog.example.test"], f"unexpected single-host extraction: {hosts_one}")
    hosts_two = extract_preview_only_hosts(_FIXTURE_SITES_TS_TWO_PREVIEW_HOSTS)
    check(
        hosts_two == ["blog.example.test", "docs.example.test", "help.example.test"],
        f"unexpected multi-host extraction: {hosts_two}",
    )
    hosts_none = extract_preview_only_hosts(_FIXTURE_SITES_TS_NO_PREVIEW_HOSTS)
    check(hosts_none == [], f"a site with no injectionWafPreviewOnly leaked a host: {hosts_none}")

    # A Hetzner-only site -- `injectionWafPreviewOnly: true` but no
    # `cloudRunService` -- is skipped by edge.ts and must be skipped here too.
    # Including it makes this gate red against rules edge.ts never declares,
    # and the fix that suggests itself (widening accepted-parity-failures.json)
    # would silence a real divergence. The `cloudRunService` on the third site
    # is what proves this case discriminates rather than matching nothing.
    sites_ts_hetzner_only = """
export const sites: EdgeSite[] = [
  {
    name: 'website',
    hostnames: ['example.test'],
    cloudRunService: 'svc',
  },

  {
    name: 'hetzner-only',
    hostnames: ['hetzner-only.example.test'],
    privateUpstream: { host: 'app1', port: 8081 },
    injectionWafPreviewOnly: true,
  },

  {
    name: 'gcp-blog',
    hostnames: ['blog.example.test'],
    cloudRunService: 'blog-svc',
    injectionWafPreviewOnly: true,
  },
];
"""
    hosts_hetzner_only = extract_preview_only_hosts(sites_ts_hetzner_only)
    check(
        hosts_hetzner_only == ["blog.example.test"],
        "a site with injectionWafPreviewOnly but no cloudRunService must not be exempted "
        f"-- edge.ts skips it entirely: {hosts_hetzner_only}",
    )

    # A nested `{}` inside one site object must not truncate the object early
    # and silently drop a later injectionWafPreviewOnly in it. The nesting is
    # spread over several lines on purpose: the non-greedy regex this
    # replaced only truncated at a `}` preceded by a newline, so a
    # single-line nested object is handled identically by both and proves
    # nothing. Prettier splits an options bag across lines as soon as it
    # exceeds the print width, so this is the shape that actually occurs.
    sites_ts_nested_braces = """
export const sites: EdgeSite[] = [
  {
    name: 'blog',
    hostnames: ['blog.example.test'],
    cloudRunService: 'svc',
    region: 'us',
    someFutureOptions: {
      nested: {
        deeper: true,
      },
    },
    injectionWafPreviewOnly: true,
  },
];
"""
    hosts_nested = extract_preview_only_hosts(sites_ts_nested_braces)
    check(
        hosts_nested == ["blog.example.test"],
        f"a nested object inside a site entry broke extraction: {hosts_nested}",
    )

    # A source shape this script no longer recognises must raise, not return
    # an empty/default result that would compare against zero expected rules.
    try:
        extract_owasp_rulesets(_FIXTURE_EDGE_TS_NO_OWASP_CONST)
        check(False, "a renamed OWASP_RULESETS constant did not raise ExtractionError")
    except ExtractionError:
        pass

    # --- expected_rules: one preview-only host -----------------------------
    expected_one_host = expected_rules(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST)
    check(
        len(expected_one_host) == 9,
        f"expected 9 rules (4 WAF + 3 preview copies + throttle + default-allow), got {len(expected_one_host)}",
    )
    sqli = next(r for r in expected_one_host if r.label == "sqli-v33-stable")
    check(
        sqli.expression
        == "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1}) && "
        "!(request.headers['host'].lower() == 'blog.example.test')",
        f"unexpected sqli expression with one preview-only host: {sqli.expression!r}",
    )
    lfi = next(r for r in expected_one_host if r.label == "lfi-v33-stable")
    check(
        lfi.expression == "evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': 1})",
        f"lfi must never carry the carve-out (it enforces regardless): {lfi.expression!r}",
    )
    sqli_copy = next(r for r in expected_one_host if r.label == "sqli-v33-stable (preview-only hosts)")
    check(
        sqli_copy.priority == 1100 and sqli_copy.preview is True
        and sqli_copy.expression
        == "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1}) && "
        "(request.headers['host'].lower() == 'blog.example.test')",
        f"unexpected preview-only-host copy: {sqli_copy}",
    )
    check(
        sum(1 for r in expected_one_host if "preview-only hosts" in r.label) == 3,
        "expected exactly 3 preview-only-host copies (sqli/xss/rce; lfi excluded)",
    )
    throttle = next(r for r in expected_one_host if r.label == "rate-limit")
    check(
        throttle.priority == 2000
        and throttle.action == "throttle"
        and throttle.preview is False
        and throttle.src_ip_ranges == ["*"]
        and throttle.extra["rateLimitOptions.rateLimitThreshold.count"] == 200
        and throttle.extra["rateLimitOptions.rateLimitThreshold.intervalSec"] == 60
        and throttle.extra["rateLimitOptions.enforceOnKey"] == "IP"
        and throttle.extra["rateLimitOptions.exceedAction"] == "deny(429)"
        and throttle.extra["rateLimitOptions.conformAction"] == "allow",
        f"unexpected throttle rule: {throttle}",
    )
    default_allow = next(r for r in expected_one_host if r.label == "default-allow")
    check(
        default_allow.priority == 2147483647
        and default_allow.action == "allow"
        and default_allow.preview is False
        and default_allow.src_ip_ranges == ["*"],
        f"unexpected default-allow rule: {default_allow}",
    )

    # --- expected_rules: two preview-only hosts, joined with ' && ' / ' || ' --
    expected_two_hosts = expected_rules(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_TWO_PREVIEW_HOSTS)
    xss_two = next(r for r in expected_two_hosts if r.label == "xss-v33-stable")
    check(
        xss_two.expression
        == "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1}) && "
        "!(request.headers['host'].lower() == 'blog.example.test') && "
        "!(request.headers['host'].lower() == 'docs.example.test') && "
        "!(request.headers['host'].lower() == 'help.example.test')",
        f"unexpected multi-host carve-out join: {xss_two.expression!r}",
    )
    xss_copy_two = next(r for r in expected_two_hosts if r.label == "xss-v33-stable (preview-only hosts)")
    check(
        xss_copy_two.expression
        == "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1}) && "
        "(request.headers['host'].lower() == 'blog.example.test' || "
        "request.headers['host'].lower() == 'docs.example.test' || "
        "request.headers['host'].lower() == 'help.example.test')",
        f"unexpected multi-host preview-copy OR-join: {xss_copy_two.expression!r}",
    )

    # --- expected_rules: no preview-only hosts -> no carve-out, no copies --
    expected_no_hosts = expected_rules(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_NO_PREVIEW_HOSTS)
    check(
        len(expected_no_hosts) == 6,
        f"expected 6 rules (4 WAF + throttle + default-allow, no preview copies) with zero preview-only hosts, got {len(expected_no_hosts)}",
    )
    sqli_no_hosts = next(r for r in expected_no_hosts if r.label == "sqli-v33-stable")
    check(
        sqli_no_hosts.expression == "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1})",
        f"a carve-out appeared with zero preview-only hosts: {sqli_no_hosts.expression!r}",
    )

    # --- check_parity: clean baseline matching expected_rules exactly -----
    clean_baseline = _baseline_from_expected(expected_one_host)
    check(check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, clean_baseline) == [], "a clean baseline was reported as diverging")

    # --- check_parity: this repo's actual known-broken shape ---------------
    # Mirrors CLOUD-ARMOR-BASELINE.md's real Findings #1 and #2: the WAF and
    # throttle rules are live in preview, and the content-sensitive rules are
    # missing their carve-out. This is the "run against the broken state and
    # observe it fail" check -- proving the gate is not vacuous.
    broken_baseline = json.loads(json.dumps(clean_baseline))  # deep copy
    for entry in broken_baseline["rules"]:
        if entry["priority"] in {1000, 1001, 1002, 1003, 2000}:  # the 4 base WAF rules + throttle
            entry["preview"] = True
            expr = (entry.get("match") or {}).get("expr")
            if expr is not None:
                expr["expression"] = expr["expression"].split(" && !(")[0]  # drop the carve-out
    problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, broken_baseline)
    check(
        len(problems) == 8,
        f"expected 8 problems (5 preview flips + 3 missing carve-outs) against the known-broken fixture, got {len(problems)}: {problems}",
    )
    check(any("preview" in m for m in _messages(problems)), "no problem mentioned 'preview' against the preview-broken fixture")
    check(any("match expression" in m for m in _messages(problems)), "no problem mentioned 'match expression' against the carve-out-broken fixture")
    check(
        not any("lfi-v33-stable" in m and "match expression" in m for m in _messages(problems)),
        "lfi has no carve-out and must never be reported for a match-expression mismatch",
    )

    # --- check_parity: an extra/foreign rule at an undeclared priority -----
    # The concrete bypass a subset-only check misses: Cloud Armor stops at
    # the first *matching* rule in ascending priority order, so a rule
    # inserted below the WAF rules can nullify all of them even though every
    # rule this check otherwise looks for is individually correct.
    foreign_rule_baseline = json.loads(json.dumps(clean_baseline))
    foreign_rule_baseline["rules"].insert(
        0, {"action": "allow", "priority": 500, "preview": False, "match": {"config": {"srcIpRanges": ["*"]}}}
    )
    problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, foreign_rule_baseline)
    check(
        len(problems) == 1 and "priority 500" in problems[0].message and "does not declare" in problems[0].message,
        f"an undeclared rule at priority 500 was not caught: {problems}",
    )

    # --- check_parity: rate-limit threshold silently defeated --------------
    for field_path, bad_value, expect_substring in [
        ("rateLimitOptions.rateLimitThreshold.count", 2_000_000, "rateLimitOptions.rateLimitThreshold.count"),
        ("rateLimitOptions.enforceOnKey", "HTTP-HEADER", "rateLimitOptions.enforceOnKey"),
        ("rateLimitOptions.exceedAction", "allow", "rateLimitOptions.exceedAction"),
    ]:
        doctored = json.loads(json.dumps(clean_baseline))
        throttle_entry = next(r for r in doctored["rules"] if r["priority"] == 2000)
        cursor = throttle_entry
        parts = field_path.split(".")
        for part in parts[:-1]:
            cursor = cursor[part]
        cursor[parts[-1]] = bad_value
        problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, doctored)
        check(
            len(problems) == 1 and expect_substring in problems[0].message,
            f"a defeated rate limit ({field_path}={bad_value!r}) was not caught: {problems}",
        )

    # --- check_parity: a preview-copy flipped to enforcing (locks the author
    # out, per edge.ts's own carve-out rationale) ---------------------------
    doctored = json.loads(json.dumps(clean_baseline))
    for entry in doctored["rules"]:
        if entry["priority"] == 1100:
            entry["preview"] = False
    problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, doctored)
    check(
        len(problems) == 1 and "meant to stay in preview" in problems[0].message,
        f"a preview-copy flipped to enforcing was not caught: {problems}",
    )

    # --- check_parity: default-allow rule silently changed to deny ---------
    doctored = json.loads(json.dumps(clean_baseline))
    for entry in doctored["rules"]:
        if entry["priority"] == 2147483647:
            entry["action"] = "deny(403)"
    problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, doctored)
    check(
        len(problems) == 1 and "2147483647" in problems[0].message and "baseline action=" in problems[0].message,
        f"a default-allow rule changed to deny was not caught: {problems}",
    )

    # --- check_parity: policy identity (name/type) --------------------------
    doctored = json.loads(json.dumps(clean_baseline))
    doctored["name"] = "some-other-policy"
    problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, doctored)
    check(
        len(problems) == 1 and "policy name=" in problems[0].message,
        f"a renamed policy was not caught: {problems}",
    )
    doctored = json.loads(json.dumps(clean_baseline))
    doctored["type"] = "CLOUD_ARMOR_EDGE"
    problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, doctored)
    check(
        len(problems) == 1 and "policy type=" in problems[0].message,
        f"a changed policy type was not caught: {problems}",
    )

    # --- check_parity: a single missing rule --------------------------------
    missing_rule_baseline = json.loads(json.dumps(clean_baseline))
    missing_rule_baseline["rules"] = [r for r in missing_rule_baseline["rules"] if r["priority"] != 1003]
    problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, missing_rule_baseline)
    check(
        len(problems) == 1 and "baseline has none at this priority" in problems[0].message,
        f"expected exactly one 'missing rule' problem, got: {problems}",
    )

    # --- check_parity: an action mismatch (a rule masquerading correctly on
    # preview/expression but declaring the wrong action) --------------------
    wrong_action_baseline = json.loads(json.dumps(clean_baseline))
    for rule in wrong_action_baseline["rules"]:
        if rule["priority"] == 2000:
            rule["action"] = "allow"
    problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, wrong_action_baseline)
    check(
        len(problems) == 1 and "baseline action=" in problems[0].message,
        f"expected exactly one action-mismatch problem, got: {problems}",
    )

    # --- check_parity: a null `match` must not crash, only be reported -----
    null_match_baseline = json.loads(json.dumps(clean_baseline))
    for rule in null_match_baseline["rules"]:
        if rule["priority"] == 1000:
            rule["match"] = None
    problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, null_match_baseline)
    check(
        any("1000" in m and "match expression" in m for m in _messages(problems)),
        f"a null match field was not reported as a mismatch: {problems}",
    )

    # --- check_parity: a rule this script cannot read fails closed ---------
    # Each of these was a silent skip once, and each one let an
    # allow-everything rule through as parity: dropped from the index, so
    # invisible to the undeclared-rule check that would otherwise catch it.
    hostile_rule = {
        "action": "allow",
        "preview": False,
        "match": {"config": {"srcIpRanges": ["*"]}},
    }
    for label, entry in [
        ("a string priority", {**hostile_rule, "priority": "500"}),
        ("no priority key", dict(hostile_rule)),
        ("a boolean priority", {**hostile_rule, "priority": True}),
        ("a non-object rule", [{**hostile_rule, "priority": 500}]),
        ("a duplicate of priority 1000", {**hostile_rule, "priority": 1000}),
    ]:
        hostile_baseline = json.loads(json.dumps(clean_baseline))
        hostile_baseline["rules"].insert(0, entry)
        try:
            problems = check_parity(
                _FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, hostile_baseline
            )
            check(False, f"an allow-everything rule with {label} was accepted as parity: {problems}")
        except ExtractionError:
            pass

    # --- check_parity: a non-boolean preview is reported, never coerced ----
    # bool("false") is True, so coercing reads a non-enforcing rule as
    # enforcing on the one field this whole check exists for.
    string_preview_baseline = json.loads(json.dumps(clean_baseline))
    for entry in string_preview_baseline["rules"]:
        if entry["priority"] == 1100:
            entry["preview"] = "true"
    problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, string_preview_baseline)
    check(
        len(problems) == 1 and "not a JSON boolean" in problems[0].message,
        f"a string 'preview' value was not reported: {problems}",
    )

    # --- ExtractionError propagates through check_parity, not swallowed ----
    try:
        check_parity(_FIXTURE_EDGE_TS_NO_OWASP_CONST, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, clean_baseline)
        check(False, "check_parity swallowed an ExtractionError instead of raising")
    except ExtractionError:
        pass

    # --- _baseline_rules_by_priority: malformed baseline raises ------------
    for label, malformed in [
        ("no 'rules' array", {"no_rules_key": True}),
        ("a top-level array", []),
        ("a top-level null", None),
    ]:
        try:
            check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, malformed)
            check(False, f"a baseline with {label} did not raise ExtractionError")
        except ExtractionError:
            pass

    # --- accepted failures --------------------------------------------------
    known = _accepting((1000, "preview", True), (1000, "match.expr.expression", None))
    real_shape_problems = check_parity(
        _FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, broken_baseline
    )
    priority_1000 = [p for p in real_shape_problems if p.priority == 1000]
    check(len(priority_1000) == 2, f"expected 2 problems at priority 1000, got {priority_1000}")
    exact = _accepting(*((p.priority, p.field, p.observed) for p in priority_1000))
    remaining, matched, stale = apply_accepted_failures(real_shape_problems, exact)
    check(
        len(matched) == 2 and not stale and len(remaining) == len(real_shape_problems) - 2,
        f"accepting two exact divergences did not remove exactly those two: {remaining}",
    )

    # An entry only matches the value it names -- a field that diverged some
    # *other* way is a divergence nobody accepted.
    wrong_value = _accepting((1000, "preview", "true"))
    remaining, matched, stale = apply_accepted_failures(priority_1000, wrong_value)
    check(
        not matched and len(stale) == 1 and len(remaining) == 2,
        "an entry naming a different observed value still suppressed the divergence",
    )

    # True == 1 in Python, and a rule whose preview became a number is not
    # the rule whose preview is a boolean.
    remaining, matched, stale = apply_accepted_failures(priority_1000, _accepting((1000, "preview", 1)))
    check(not matched and len(stale) == 1, "an integer 1 matched an entry recorded as boolean true")

    # A recorded divergence that stopped happening is reported, not ignored.
    remaining, matched, stale = apply_accepted_failures([], known)
    check(len(stale) == 2 and not matched, f"a stale acceptance was not reported: {stale}")

    # Policy identity is never acceptable: those problems carry priority None
    # and the file cannot express one.
    renamed = json.loads(json.dumps(clean_baseline))
    renamed["name"] = "some-other-policy"
    name_problems = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, renamed)
    check(
        all(p.priority is None for p in name_problems),
        "a policy-name divergence did not carry priority None",
    )

    for label, document in [
        ("a non-object document", []),
        ("no 'accepted' array", {"acc": []}),
        ("a non-object entry", {"accepted": ["everything"]}),
        (
            "a missing key",
            {"accepted": [{"priority": 1000, "field": "preview", "observed": True, "reason": "r"}]},
        ),
        (
            "an unrecognised key meant to widen the match",
            {
                "accepted": [
                    {
                        "priority": 1000,
                        "field": "preview",
                        "observed": True,
                        "reason": "r",
                        "closedBy": "c",
                        "anyPriority": True,
                    }
                ]
            },
        ),
        (
            "a wildcard priority",
            {
                "accepted": [
                    {"priority": "*", "field": "preview", "observed": True, "reason": "r", "closedBy": "c"}
                ]
            },
        ),
        (
            "an empty reason",
            {
                "accepted": [
                    {"priority": 1000, "field": "preview", "observed": True, "reason": " ", "closedBy": "c"}
                ]
            },
        ),
        (
            "two entries for one field",
            {
                "accepted": [
                    {"priority": 1000, "field": "preview", "observed": True, "reason": "r", "closedBy": "c"},
                    {"priority": 1000, "field": "preview", "observed": False, "reason": "r", "closedBy": "c"},
                ]
            },
        ),
    ]:
        try:
            parse_accepted_failures(document)
            check(False, f"an accepted-failures document with {label} was accepted")
        except ExtractionError:
            pass

    # --- main(): CLI plumbing, exercised against real files on disk --------
    # Output is suppressed: several of these calls print the full problem
    # block or the module docstring, and ~40 lines of ::error:: text on a
    # *passing* pre-commit hook reads as a failure to anyone watching.
    import contextlib
    import io
    import tempfile

    def quiet_main(args: list[str]) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return main(args)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        edge_ts_path = root / "edge.ts"
        sites_ts_path = root / "sites.ts"
        baseline_path = root / "baseline.json"
        accepted_path = root / "accepted.json"
        edge_ts_path.write_text(_FIXTURE_EDGE_TS, encoding="utf-8")
        sites_ts_path.write_text(_FIXTURE_SITES_TS_ONE_PREVIEW_HOST, encoding="utf-8")
        accepted_path.write_text(json.dumps({"accepted": []}), encoding="utf-8")

        cli_args = [
            "prog",
            "--edge-ts",
            str(edge_ts_path),
            "--sites-ts",
            str(sites_ts_path),
            "--baseline",
            str(baseline_path),
            "--accepted-failures",
            str(accepted_path),
        ]

        baseline_path.write_text(json.dumps(clean_baseline), encoding="utf-8")
        check(quiet_main(cli_args) == 0, "main() did not exit 0 against a clean baseline on disk")

        baseline_path.write_text(json.dumps(broken_baseline), encoding="utf-8")
        check(quiet_main(cli_args) == 1, "main() did not exit 1 against a doctored baseline on disk")

        # The same doctored baseline, with every divergence recorded, is the
        # accepted-failures design end to end: green, and still saying so.
        recorded = check_parity(_FIXTURE_EDGE_TS, _FIXTURE_SITES_TS_ONE_PREVIEW_HOST, broken_baseline)
        accepted_path.write_text(
            json.dumps(
                {
                    "accepted": [
                        {
                            "priority": p.priority,
                            "field": p.field,
                            "observed": p.observed,
                            "reason": "TEST",
                            "closedBy": "TEST",
                        }
                        for p in recorded
                    ]
                }
            ),
            encoding="utf-8",
        )
        check(quiet_main(cli_args) == 0, "main() did not exit 0 with every divergence recorded")

        # ...and the moment the divergences are fixed, the now-stale records
        # fail until they are deleted. Deleting them is an edit to this file,
        # so the gate never blocks its own remedy.
        baseline_path.write_text(json.dumps(clean_baseline), encoding="utf-8")
        check(quiet_main(cli_args) == 1, "main() did not exit 1 on a fully stale accepted-failures file")
        accepted_path.write_text(json.dumps({"accepted": []}), encoding="utf-8")
        check(quiet_main(cli_args) == 0, "main() did not exit 0 once the stale records were deleted")

        baseline_path.unlink()
        check(quiet_main(cli_args) == 1, "main() did not exit 1 when the baseline file is missing")

        baseline_path.write_text("{not valid json", encoding="utf-8")
        check(quiet_main(cli_args) == 1, "main() did not exit 1 against invalid JSON")

        check(quiet_main(["prog", "--nonsense"]) == 2, "main() did not exit 2 on an unrecognised flag")
        check(
            quiet_main(["prog", "--baseline", ""]) == 2,
            "main() did not exit 2 on an empty --baseline value",
        )

    if failed:
        print("\nassert-cloud-armor-baseline-parity.py self-test FAILED")
    else:
        print("OK: assert-cloud-armor-baseline-parity.py self-test passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
