#!/usr/bin/env python3
"""Unit tests for assert-cloud-armor-baseline-parity.

The property this checker exists to guarantee has a specific failure shape: a
baseline that has quietly drifted from what `edge.ts` declares, read as a
match. A checker that reports "clean" no matter what it is given is worse
than no checker -- it is exactly the false green CLOUD-ARMOR-BASELINE.md's
Findings #1 and #2 already shipped once. Every test below is aimed at that
shape, not at the happy path: a genuinely clean baseline must pass, and a
baseline *doctored* to look almost right -- built by taking a clean one and
flipping exactly one field a real attacker or a real partial apply could
flip -- must still be caught, at both the function level (`check_parity`) and
the CLI level (`main`, invoked end-to-end against real files on disk).

Run directly:
    python3 -m unittest scripts/test_assert_cloud_armor_baseline_parity.py -v

Also picked up automatically by `python3 -m unittest discover -s scripts -p
'test_*.py'`, which the `scripts-tests` pre-commit hook and the CI job of the
same name both run over every file matching that pattern in `scripts/`.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest


def _load_module():
    """Import the script by path: its filename has hyphens, so it is not a
    legal module name for a plain `import` statement.

    Registers the module in `sys.modules` *before* executing it -- the
    checker's `ExpectedRule` is a `@dataclass`, and `dataclasses` resolves
    its owning module via `sys.modules[cls.__module__]` while the class body
    runs. Skipping this step doesn't fail quietly: it raises inside
    `dataclass()` itself with an `AttributeError` on `None`, but only for a
    module that happens to define a dataclass -- another script's
    equivalent loader doesn't need this because it has none.
    """
    path = pathlib.Path(__file__).resolve().parent / "assert-cloud-armor-baseline-parity.py"
    spec = importlib.util.spec_from_file_location("assert_cloud_armor_baseline_parity", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


parity = _load_module()


# A minimal, realistic edge.ts fixture carrying every pattern the script's
# extraction functions depend on. Deliberately not a copy-paste of the real
# edge.ts -- these tests must keep working even if the real file's comments
# or formatting change, as long as the load-bearing patterns survive.
EDGE_TS = """
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

SITES_TS_ONE_HOST = """
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

SITES_TS_NO_HOSTS = """
export const sites: EdgeSite[] = [
  {
    name: 'marketing',
    hostnames: ['example.test'],
    cloudRunService: 'svc',
    region: 'us',
  },
];
"""


def _baseline_from_expected(rules: list) -> dict:
    """A committed-baseline-shaped dict that matches `rules` exactly."""
    return parity._baseline_from_expected(rules)


def _quiet_main(argv: list[str]) -> int:
    """Run main() with stdout captured.

    Several of these calls deliberately exercise the failure paths, which
    print the whole problem block or the module docstring. Unsuppressed,
    a *passing* run of this suite emits screenfuls of ::error:: text.
    """
    with contextlib.redirect_stdout(io.StringIO()):
        return parity.main(argv)


def _messages(problems: list) -> list[str]:
    return [problem.message for problem in problems]


def _accept(priority, field, observed, reason="TEST", closed_by="TEST") -> dict:
    """One accepted-failures entry, in the on-disk shape."""
    return {
        "priority": priority,
        "field": field,
        "observed": observed,
        "reason": reason,
        "closedBy": closed_by,
    }


def _doctor_to_match_the_real_known_broken_shape(baseline: dict) -> dict:
    """Corrupt a clean baseline into exactly the shape the live policy is
    actually in right now: the four base WAF rules and the throttle rule live
    in preview, and the content-sensitive WAF rules missing their
    preview-only-host carve-out.

    This is deliberately not a random or convenient corruption -- it mirrors
    CLOUD-ARMOR-BASELINE.md's real Findings #1 and #2, so a passing test here
    is direct evidence the checker catches the actual defect this PR exists
    to fix, not just an arbitrary fixture it happens to have been tuned for.
    """
    doctored = json.loads(json.dumps(baseline))  # deep copy
    for rule in doctored["rules"]:
        if rule["priority"] in {1000, 1001, 1002, 1003, 2000}:
            rule["preview"] = True
            expr = (rule.get("match") or {}).get("expr")
            if expr is not None:
                expr["expression"] = expr["expression"].split(" && !(")[0]
    return doctored


class ExtractionTests(unittest.TestCase):
    def test_owasp_rulesets(self):
        self.assertEqual(
            parity.extract_owasp_rulesets(EDGE_TS),
            ["sqli-v33-stable", "xss-v33-stable", "rce-v33-stable", "lfi-v33-stable"],
        )

    def test_owasp_rulesets_raises_when_priority_formula_missing(self):
        broken = EDGE_TS.replace("priority: 1000 + i,", "priority: computePriority(i),")
        with self.assertRaises(parity.ExtractionError):
            parity.extract_owasp_rulesets(broken)

    def test_owasp_rulesets_raises_when_constant_renamed(self):
        broken = EDGE_TS.replace("const OWASP_RULESETS", "const RENAMED_RULESETS")
        with self.assertRaises(parity.ExtractionError):
            parity.extract_owasp_rulesets(broken)

    def test_content_sensitive_rulesets(self):
        self.assertEqual(
            parity.extract_content_sensitive_rulesets(EDGE_TS),
            {"sqli-v33-stable", "xss-v33-stable", "rce-v33-stable"},
        )

    def test_rate_limit_priority(self):
        self.assertEqual(parity.extract_rate_limit_priority(EDGE_TS), 2000)

    def test_rate_limit_params(self):
        self.assertEqual(parity.extract_rate_limit_params(EDGE_TS), (200, 60))

    def test_preview_copy_base_priority(self):
        self.assertEqual(parity.extract_preview_copy_base_priority(EDGE_TS), 1100)

    def test_default_allow_priority(self):
        self.assertEqual(parity.extract_default_allow_priority(EDGE_TS), 2147483647)

    def test_policy_name(self):
        self.assertEqual(parity.extract_policy_name(EDGE_TS), "branchleft-edge-armor")

    def test_preview_only_hosts_one(self):
        self.assertEqual(parity.extract_preview_only_hosts(SITES_TS_ONE_HOST), ["blog.example.test"])

    def test_preview_only_hosts_none(self):
        self.assertEqual(parity.extract_preview_only_hosts(SITES_TS_NO_HOSTS), [])

    def test_preview_only_hosts_multiple_on_one_site(self):
        sites_ts = """
export const sites: EdgeSite[] = [
  {
    name: 'docs',
    hostnames: ['docs.example.test', 'help.example.test'],
    cloudRunService: 'svc',
    region: 'us',
    injectionWafPreviewOnly: true,
  },
];
"""
        self.assertEqual(
            parity.extract_preview_only_hosts(sites_ts),
            ["docs.example.test", "help.example.test"],
        )

    def test_preview_only_hosts_survives_a_nested_object_in_a_site_entry(self):
        # A future site entry with a nested config object must not truncate
        # the object early and silently drop a later
        # injectionWafPreviewOnly -- a regex-based non-greedy brace match
        # would do exactly that.
        #
        # The nesting spans several lines deliberately. The regex this
        # replaced (`\{(.*?)\n\s*\},?`) only truncated at a `}` preceded by a
        # newline, so it handles a *single-line* nested object identically to
        # the brace scanner and a one-line fixture proves nothing. This repo's
        # own Prettier hook splits an options bag across lines as soon as it
        # exceeds the print width, so the multi-line form is the one that
        # actually occurs and the only one that distinguishes the two.
        sites_ts = """
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
        self.assertEqual(parity.extract_preview_only_hosts(sites_ts), ["blog.example.test"])

    def test_preview_only_hosts_raises_when_sites_array_missing(self):
        with self.assertRaises(parity.ExtractionError):
            parity.extract_preview_only_hosts("export const somethingElse = [];")

    def test_confirm_literal_raises_when_expression_builder_changed(self):
        broken = EDGE_TS.replace("evaluatePreconfiguredWaf(", "runWafRuleset(")
        with self.assertRaises(parity.ExtractionError):
            parity.expected_rules(broken, SITES_TS_ONE_HOST)


class ExpectedRulesTests(unittest.TestCase):
    def test_nine_rules_with_one_preview_only_host(self):
        rules = parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST)
        self.assertEqual(len(rules), 9)  # 4 WAF + 3 preview copies + throttle + default-allow
        self.assertEqual(
            sorted(r.priority for r in rules),
            [1000, 1001, 1002, 1003, 1100, 1101, 1102, 2000, 2147483647],
        )

    def test_six_rules_with_zero_preview_only_hosts(self):
        rules = parity.expected_rules(EDGE_TS, SITES_TS_NO_HOSTS)
        self.assertEqual(len(rules), 6)  # 4 WAF + throttle + default-allow, no preview copies
        self.assertEqual(sorted(r.priority for r in rules), [1000, 1001, 1002, 1003, 2000, 2147483647])

    def test_content_sensitive_rule_carries_carve_out(self):
        rules = parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST)
        sqli = next(r for r in rules if r.label == "sqli-v33-stable")
        self.assertEqual(
            sqli.expression,
            "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1}) && "
            "!(request.headers['host'].lower() == 'blog.example.test')",
        )

    def test_lfi_never_carries_a_carve_out(self):
        # lfi is deliberately excluded from CONTENT_SENSITIVE_RULESETS in
        # edge.ts -- it enforces regardless of injectionWafPreviewOnly.
        rules = parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST)
        lfi = next(r for r in rules if r.label == "lfi-v33-stable")
        self.assertEqual(lfi.expression, "evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': 1})")
        self.assertFalse(any("lfi" in r.label and "preview-only hosts" in r.label for r in rules))

    def test_preview_only_copy_rule(self):
        rules = parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST)
        copy = next(r for r in rules if r.label == "sqli-v33-stable (preview-only hosts)")
        self.assertEqual(copy.priority, 1100)
        self.assertTrue(copy.preview, "preview-only copies must stay preview:true")
        self.assertEqual(
            copy.expression,
            "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1}) && "
            "(request.headers['host'].lower() == 'blog.example.test')",
        )

    def test_no_carve_out_or_copies_with_zero_preview_only_hosts(self):
        rules = parity.expected_rules(EDGE_TS, SITES_TS_NO_HOSTS)
        sqli = next(r for r in rules if r.label == "sqli-v33-stable")
        self.assertEqual(sqli.expression, "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1})")
        self.assertFalse(any("preview-only hosts" in r.label for r in rules))

    def test_throttle_rule_carries_full_rate_limit_parameters(self):
        rules = parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST)
        throttle = next(r for r in rules if r.label == "rate-limit")
        self.assertEqual(throttle.priority, 2000)
        self.assertEqual(throttle.action, "throttle")
        self.assertFalse(throttle.preview)
        self.assertEqual(throttle.src_ip_ranges, ["*"])
        self.assertEqual(
            throttle.extra,
            {
                "rateLimitOptions.conformAction": "allow",
                "rateLimitOptions.exceedAction": "deny(429)",
                "rateLimitOptions.enforceOnKey": "IP",
                "rateLimitOptions.rateLimitThreshold.count": 200,
                "rateLimitOptions.rateLimitThreshold.intervalSec": 60,
            },
        )

    def test_default_allow_rule(self):
        rules = parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST)
        default_allow = next(r for r in rules if r.label == "default-allow")
        self.assertEqual(default_allow.priority, 2147483647)
        self.assertEqual(default_allow.action, "allow")
        self.assertFalse(default_allow.preview)
        self.assertEqual(default_allow.src_ip_ranges, ["*"])


class CheckParityTests(unittest.TestCase):
    """The core property: does the comparison itself distinguish clean from broken."""

    def setUp(self):
        self.expected = parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST)
        self.clean_baseline = _baseline_from_expected(self.expected)

    def test_clean_baseline_reports_no_problems(self):
        self.assertEqual(parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, self.clean_baseline), [])

    def test_doctored_to_the_real_known_broken_shape_is_caught(self):
        """The property this PR exists to prove: fed a baseline doctored into
        exactly the shape CLOUD-ARMOR-BASELINE.md's own committed capture is
        actually in (5 rules live in preview.., 3 missing carve-outs), the
        checker does not report clean. A checker that passed this input would
        be the exact "fails open" defect the story is about."""
        doctored = _doctor_to_match_the_real_known_broken_shape(self.clean_baseline)
        problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self.assertEqual(len(problems), 8)
        messages = _messages(problems)
        self.assertTrue(any("preview" in m and "1000" in m for m in messages))
        self.assertTrue(any("match expression" in m and "1000" in m for m in messages))
        self.assertFalse(
            any("lfi-v33-stable" in m and "match expression" in m for m in messages),
            "lfi has no carve-out to lose and must not be reported for a match-expression mismatch",
        )

    def test_an_extra_undeclared_rule_is_caught(self):
        """The concrete bypass a subset-only comparison misses: Cloud Armor
        stops at the first *matching* rule in ascending priority order, so a
        rule inserted below the WAF rules can nullify all of them even though
        every rule this check looks for is individually correct."""
        doctored = json.loads(json.dumps(self.clean_baseline))
        doctored["rules"].insert(
            0,
            {"action": "allow", "priority": 500, "preview": False, "match": {"config": {"srcIpRanges": ["*"]}}},
        )
        problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self.assertEqual(len(problems), 1)
        self.assertIn("priority 500", problems[0].message)
        self.assertIn("does not declare", problems[0].message)

    def test_rate_limit_threshold_silently_defeated_is_caught(self):
        for field_path, bad_value in [
            ("rateLimitOptions.rateLimitThreshold.count", 2_000_000),
            ("rateLimitOptions.enforceOnKey", "HTTP-HEADER"),
            ("rateLimitOptions.exceedAction", "allow"),
        ]:
            with self.subTest(field_path=field_path):
                doctored = json.loads(json.dumps(self.clean_baseline))
                throttle_entry = next(r for r in doctored["rules"] if r["priority"] == 2000)
                cursor = throttle_entry
                parts = field_path.split(".")
                for part in parts[:-1]:
                    cursor = cursor[part]
                cursor[parts[-1]] = bad_value
                problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(field_path, problems[0].message)

    def test_preview_copy_flipped_to_enforcing_is_caught(self):
        doctored = json.loads(json.dumps(self.clean_baseline))
        for rule in doctored["rules"]:
            if rule["priority"] == 1100:
                rule["preview"] = False
        problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self.assertEqual(len(problems), 1)
        self.assertIn("meant to stay in preview", problems[0].message)

    def test_default_allow_rule_changed_to_deny_is_caught(self):
        doctored = json.loads(json.dumps(self.clean_baseline))
        for rule in doctored["rules"]:
            if rule["priority"] == 2147483647:
                rule["action"] = "deny(403)"
        problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self.assertEqual(len(problems), 1)
        self.assertIn("2147483647", problems[0].message)

    def test_policy_renamed_is_caught(self):
        doctored = json.loads(json.dumps(self.clean_baseline))
        doctored["name"] = "some-other-policy"
        problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self.assertEqual(len(problems), 1)
        self.assertIn("policy name=", problems[0].message)

    def test_policy_type_changed_is_caught(self):
        doctored = json.loads(json.dumps(self.clean_baseline))
        doctored["type"] = "CLOUD_ARMOR_EDGE"
        problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self.assertEqual(len(problems), 1)
        self.assertIn("policy type=", problems[0].message)

    def test_missing_rule_is_caught(self):
        doctored = json.loads(json.dumps(self.clean_baseline))
        doctored["rules"] = [r for r in doctored["rules"] if r["priority"] != 1003]
        problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self.assertEqual(len(problems), 1)
        self.assertIn("baseline has none at this priority", problems[0].message)

    def test_action_mismatch_is_caught(self):
        doctored = json.loads(json.dumps(self.clean_baseline))
        for rule in doctored["rules"]:
            if rule["priority"] == 2000:
                rule["action"] = "allow"
        problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self.assertEqual(len(problems), 1)
        self.assertIn("baseline action=", problems[0].message)

    def test_malformed_baseline_raises_rather_than_reporting_clean(self):
        for label, malformed in [
            ("no 'rules' array", {"no_rules_key": True}),
            ("'rules' is not an array", {"rules": {"1000": {}}}),
            ("a top-level array", []),
            ("a top-level null", None),
            ("a top-level string", "{}"),
        ]:
            with self.subTest(label=label), self.assertRaises(parity.ExtractionError):
                parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, malformed)

    def test_a_rule_this_script_cannot_read_fails_closed(self):
        """Every shape below was silently dropped from the priority index by
        an earlier version, and each drop reopened the same bypass: a rule
        the index does not carry is a rule the undeclared-rule check cannot
        see, so an `allow`-everything entry ahead of the WAF rules read as
        parity. The rule inserted here is exactly that entry."""
        allow_everything = {
            "action": "allow",
            "preview": False,
            "match": {"config": {"srcIpRanges": ["*"]}},
        }
        for label, entry in [
            ("a string priority", {**allow_everything, "priority": "500"}),
            ("a float priority", {**allow_everything, "priority": 500.0}),
            ("a null priority", {**allow_everything, "priority": None}),
            ("a boolean priority", {**allow_everything, "priority": True}),
            ("no priority key at all", dict(allow_everything)),
            ("a rule wrapped in a list", [{**allow_everything, "priority": 500}]),
            ("a rule that is a bare string", "allow everything"),
            ("a duplicate of the real priority 1000", {**allow_everything, "priority": 1000}),
        ]:
            with self.subTest(label=label):
                doctored = json.loads(json.dumps(self.clean_baseline))
                doctored["rules"].insert(0, entry)
                with self.assertRaises(parity.ExtractionError):
                    parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)

    def test_a_non_boolean_preview_is_reported_not_coerced(self):
        """`bool("false")` is True. Coercing would read a rule that is not
        enforcing as one that is, on the single field this whole check
        exists for."""
        for bad_value in ["true", "false", 1, 0, None, []]:
            with self.subTest(bad_value=bad_value):
                doctored = json.loads(json.dumps(self.clean_baseline))
                for rule in doctored["rules"]:
                    if rule["priority"] == 1100:
                        rule["preview"] = bad_value
                problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("not a JSON boolean", problems[0].message)

    def test_an_absent_preview_key_means_not_in_preview(self):
        # edge.ts omits `preview` entirely on the default-allow rule, so an
        # absent key is the legitimate spelling of False -- this must stay a
        # pass, or the fail-closed rule above would flag a correct capture.
        doctored = json.loads(json.dumps(self.clean_baseline))
        for rule in doctored["rules"]:
            if rule["priority"] == 2147483647:
                del rule["preview"]
        self.assertEqual(parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored), [])

    def test_extraction_error_propagates_not_swallowed(self):
        broken_edge_ts = EDGE_TS.replace("const OWASP_RULESETS", "const RENAMED")
        with self.assertRaises(parity.ExtractionError):
            parity.check_parity(broken_edge_ts, SITES_TS_ONE_HOST, self.clean_baseline)

    def test_a_rule_with_a_null_match_does_not_crash(self):
        doctored = json.loads(json.dumps(self.clean_baseline))
        for rule in doctored["rules"]:
            if rule["priority"] == 1000:
                rule["match"] = None
        problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self.assertTrue(any("1000" in m and "match expression" in m for m in _messages(problems)))

    def test_duplicate_priority_fails_closed(self):
        """An earlier version let the last entry win, reasoning that Cloud
        Armor would reject a duplicate-priority policy anyway. The thing
        being checked is a *file*, though, and a hand-edited or badly-merged
        one is the threat model -- last-one-wins turns a one-line
        duplication into a full bypass of that priority."""
        doctored = json.loads(json.dumps(self.clean_baseline))
        doctored["rules"].append(dict(doctored["rules"][0]))
        with self.assertRaises(parity.ExtractionError):
            parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)

    def test_policy_identity_problems_carry_no_priority(self):
        """Policy `name`/`type` divergences must be unacceptable, and the
        accepted-failures file expresses acceptance only by rule priority --
        so these problems must carry None, or an entry could name one."""
        for key, value in [("name", "some-other-policy"), ("type", "CLOUD_ARMOR_EDGE")]:
            with self.subTest(key=key):
                doctored = json.loads(json.dumps(self.clean_baseline))
                doctored[key] = value
                problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
                self.assertEqual([p.priority for p in problems], [None])


class AcceptedFailuresTests(unittest.TestCase):
    """The accepted-failures file is the only route by which this check
    reports success while a real divergence is present, so it is the one
    place a doctored input buys silence. Every test here is aimed at that:
    an entry must cover exactly the divergence someone wrote down, must stop
    covering anything the moment that divergence changes, and must fail the
    check once the divergence is gone rather than lying dormant."""

    def setUp(self):
        self.expected = parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST)
        self.clean_baseline = _baseline_from_expected(self.expected)
        self.broken = _doctor_to_match_the_real_known_broken_shape(self.clean_baseline)
        self.problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, self.broken)

    def _entries_for(self, problems):
        return parity.parse_accepted_failures(
            {"accepted": [_accept(p.priority, p.field, p.observed) for p in problems]}
        )

    def test_recording_every_divergence_leaves_nothing_unaccepted(self):
        remaining, matched, stale = parity.apply_accepted_failures(
            self.problems, self._entries_for(self.problems)
        )
        self.assertEqual(remaining, [])
        self.assertEqual(len(matched), len(self.problems))
        self.assertEqual(stale, [])

    def test_an_entry_covers_only_the_divergence_it_names(self):
        """A new, unrelated divergence next to an accepted one must still
        fail -- this is the differential signal the whole design is for."""
        one = [p for p in self.problems if p.priority == 1000]
        entries = self._entries_for(one)
        doctored = json.loads(json.dumps(self.broken))
        for rule in doctored["rules"]:
            if rule["priority"] == 2147483647:
                rule["action"] = "deny(403)"
        remaining, matched, stale = parity.apply_accepted_failures(
            parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored), entries
        )
        self.assertEqual(len(matched), len(one))
        self.assertEqual(stale, [])
        self.assertTrue(any(p.priority == 2147483647 for p in remaining))

    def test_a_different_observed_value_in_the_same_field_is_not_accepted(self):
        """The field diverging *further* is a different divergence. An entry
        keyed on priority and field alone would swallow it."""
        entries = parity.parse_accepted_failures(
            {
                "accepted": [
                    _accept(1000, "match.expr.expression", "evaluatePreconfiguredWaf('something-else')")
                ]
            }
        )
        remaining, matched, stale = parity.apply_accepted_failures(self.problems, entries)
        self.assertEqual(matched, [])
        self.assertEqual(len(stale), 1)
        self.assertTrue(any(p.field == "match.expr.expression" for p in remaining))

    def test_observed_values_are_compared_by_type_not_only_by_value(self):
        """`True == 1` in Python. A preview flag that became a number is not
        the divergence recorded for a boolean."""
        for lookalike in [1, 1.0, "true"]:
            with self.subTest(lookalike=lookalike):
                entries = parity.parse_accepted_failures(
                    {"accepted": [_accept(1000, "preview", lookalike)]}
                )
                _, matched, stale = parity.apply_accepted_failures(self.problems, entries)
                self.assertEqual(matched, [])
                self.assertEqual(len(stale), 1)

    def test_an_entry_whose_divergence_stopped_happening_is_reported_stale(self):
        """The mechanism against a stale acceptance quietly re-accepting a
        fixed problem later. It is reported, not dropped."""
        entries = self._entries_for(self.problems)
        remaining, matched, stale = parity.apply_accepted_failures(
            parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, self.clean_baseline), entries
        )
        self.assertEqual(remaining, [])
        self.assertEqual(matched, [])
        self.assertEqual(len(stale), len(entries))

    def test_one_entry_consumes_one_problem(self):
        """Two identical divergences cannot be silenced by one entry."""
        one = [p for p in self.problems if p.priority == 1000 and p.field == "preview"]
        entries = self._entries_for(one)
        duplicated = self.problems + one
        remaining, matched, stale = parity.apply_accepted_failures(duplicated, entries)
        self.assertEqual(len(matched), 1)
        self.assertEqual(stale, [])
        self.assertEqual(sum(1 for p in remaining if p.field == "preview" and p.priority == 1000), 1)

    def test_a_document_that_could_widen_the_match_is_rejected(self):
        for label, document in [
            ("not an object", []),
            ("no 'accepted' array", {"acceptedFailures": []}),
            ("'accepted' is not an array", {"accepted": {}}),
            ("an entry that is not an object", {"accepted": ["priority 1000"]}),
            ("a missing reason", {"accepted": [{"priority": 1000, "field": "preview", "observed": True, "closedBy": "c"}]}),
            ("a missing closedBy", {"accepted": [{"priority": 1000, "field": "preview", "observed": True, "reason": "r"}]}),
            ("a missing observed", {"accepted": [{"priority": 1000, "field": "preview", "reason": "r", "closedBy": "c"}]}),
            ("an unknown key", {"accepted": [{**_accept(1000, "preview", True), "matchAnyValue": True}]}),
            ("a wildcard priority", {"accepted": [_accept("*", "preview", True)]}),
            ("a null priority", {"accepted": [_accept(None, "preview", True)]}),
            ("a boolean priority", {"accepted": [_accept(True, "preview", True)]}),
            ("a wildcard field", {"accepted": [_accept(1000, "", True)]}),
            ("a blank reason", {"accepted": [_accept(1000, "preview", True, reason="  ")]}),
            ("a blank closedBy", {"accepted": [_accept(1000, "preview", True, closed_by="")]}),
            (
                "two entries for one priority and field",
                {"accepted": [_accept(1000, "preview", True), _accept(1000, "preview", False)]},
            ),
        ]:
            with self.subTest(label=label), self.assertRaises(parity.ExtractionError):
                parity.parse_accepted_failures(document)

    def test_an_empty_accepted_list_is_valid_and_accepts_nothing(self):
        entries = parity.parse_accepted_failures({"accepted": []})
        remaining, matched, stale = parity.apply_accepted_failures(self.problems, entries)
        self.assertEqual(remaining, self.problems)
        self.assertEqual(matched, [])
        self.assertEqual(stale, [])


class MainEndToEndTests(unittest.TestCase):
    """Exercises main()'s actual CLI path -- file I/O, JSON parsing, exit
    codes -- none of which check_parity()'s own tests touch directly."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.edge_ts_path = self.root / "edge.ts"
        self.sites_ts_path = self.root / "sites.ts"
        self.baseline_path = self.root / "baseline.json"
        self.accepted_path = self.root / "accepted.json"
        self.edge_ts_path.write_text(EDGE_TS, encoding="utf-8")
        self.sites_ts_path.write_text(SITES_TS_ONE_HOST, encoding="utf-8")
        self._write_accepted([])

    def _write_accepted(self, entries: list) -> None:
        self.accepted_path.write_text(json.dumps({"accepted": entries}), encoding="utf-8")

    def _argv(self) -> list[str]:
        return [
            "prog",
            "--edge-ts",
            str(self.edge_ts_path),
            "--sites-ts",
            str(self.sites_ts_path),
            "--baseline",
            str(self.baseline_path),
            "--accepted-failures",
            str(self.accepted_path),
        ]

    def test_clean_baseline_on_disk_exits_zero(self):
        expected = parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST)
        self.baseline_path.write_text(json.dumps(_baseline_from_expected(expected)), encoding="utf-8")
        self.assertEqual(_quiet_main(self._argv()), 0)

    def test_doctored_baseline_on_disk_exits_one(self):
        """The end-to-end version of the doctored-green-input property above:
        a file on disk, read through main()'s real argument parsing and JSON
        loading, in exactly the shape the real live policy is in."""
        expected = parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST)
        doctored = _doctor_to_match_the_real_known_broken_shape(_baseline_from_expected(expected))
        self.baseline_path.write_text(json.dumps(doctored), encoding="utf-8")
        self.assertEqual(_quiet_main(self._argv()), 1)

    def test_missing_baseline_file_exits_one_not_zero(self):
        # No baseline.json written -- must fail, not report a clean pass
        # because there was nothing to compare against.
        self.assertEqual(_quiet_main(self._argv()), 1)

    def test_invalid_json_baseline_exits_one(self):
        self.baseline_path.write_text("{not valid json", encoding="utf-8")
        self.assertEqual(_quiet_main(self._argv()), 1)

    def test_unknown_flag_is_a_usage_error(self):
        self.assertEqual(_quiet_main(["prog", "--nonsense"]), 2)

    def test_an_empty_flag_value_is_a_usage_error_not_a_silent_default(self):
        """`--baseline "$CAPTURE"` with `CAPTURE` unset must not fall back to
        the committed file and print a green result about a file it was never
        pointed at. A test harness is exactly where an unset variable goes
        unnoticed."""
        for flag in ["--baseline", "--edge-ts", "--sites-ts", "--accepted-failures"]:
            with self.subTest(flag=flag):
                self.assertEqual(_quiet_main(["prog", flag, ""]), 2)
                self.assertEqual(_quiet_main(["prog", flag, "   "]), 2)

    def test_a_repeated_flag_is_a_usage_error(self):
        self.assertEqual(_quiet_main(["prog", "--baseline", "a", "--baseline", "b"]), 2)

    def test_self_test_flag_runs_the_embedded_self_test(self):
        self.assertEqual(_quiet_main(["prog", "--self-test"]), 0)

    def test_every_divergence_recorded_exits_zero(self):
        """The accepted-failures design end to end: a baseline in exactly the
        shape the live policy is in, with every divergence written down,
        exits 0 -- so the job has a green state, and a *new* divergence is
        visible against it."""
        doctored = _doctor_to_match_the_real_known_broken_shape(
            _baseline_from_expected(parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST))
        )
        self.baseline_path.write_text(json.dumps(doctored), encoding="utf-8")
        problems = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self._write_accepted([_accept(p.priority, p.field, p.observed) for p in problems])
        self.assertEqual(_quiet_main(self._argv()), 0)

    def test_a_new_divergence_beside_recorded_ones_still_exits_one(self):
        clean = _baseline_from_expected(parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST))
        doctored = _doctor_to_match_the_real_known_broken_shape(clean)
        recorded = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self._write_accepted([_accept(p.priority, p.field, p.observed) for p in recorded])
        for rule in doctored["rules"]:
            if rule["priority"] == 2147483647:
                rule["action"] = "deny(403)"
        self.baseline_path.write_text(json.dumps(doctored), encoding="utf-8")
        self.assertEqual(_quiet_main(self._argv()), 1)

    def test_a_fixed_divergence_with_its_record_left_behind_exits_one(self):
        """And the fix for that exit 1 is deleting the record -- an edit to a
        committed file, needing no GCP access. The gate never blocks its own
        remedy."""
        clean = _baseline_from_expected(parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST))
        doctored = _doctor_to_match_the_real_known_broken_shape(clean)
        recorded = parity.check_parity(EDGE_TS, SITES_TS_ONE_HOST, doctored)
        self._write_accepted([_accept(p.priority, p.field, p.observed) for p in recorded])
        self.baseline_path.write_text(json.dumps(clean), encoding="utf-8")
        self.assertEqual(_quiet_main(self._argv()), 1)
        self._write_accepted([])
        self.assertEqual(_quiet_main(self._argv()), 0)

    def test_a_missing_accepted_failures_file_exits_one(self):
        self.baseline_path.write_text(
            json.dumps(_baseline_from_expected(parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST))),
            encoding="utf-8",
        )
        self.accepted_path.unlink()
        self.assertEqual(_quiet_main(self._argv()), 1)

    def test_a_malformed_accepted_failures_file_exits_one(self):
        self.baseline_path.write_text(
            json.dumps(_baseline_from_expected(parity.expected_rules(EDGE_TS, SITES_TS_ONE_HOST))),
            encoding="utf-8",
        )
        self.accepted_path.write_text(json.dumps({"accepted": ["everything"]}), encoding="utf-8")
        self.assertEqual(_quiet_main(self._argv()), 1)


class RealRepoFilesTests(unittest.TestCase):
    """Assertions about this checkout's actual files that hold whatever
    state the live policy is in.

    Deliberately says nothing about whether the real baseline currently
    matches. That verdict is the real check's to report, and encoding
    "the repo must currently be broken" here would fail this suite -- which
    `deploy` transitively depends on -- on the day someone lands the very fix
    the parity job is waiting for. What is asserted instead is that the script
    can still read the real files at all: an `edge.ts` refactor that defeats
    one of the extraction patterns is a real regression in every state of the
    world.
    """

    def setUp(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        self.edge_ts = (root / "edge.ts").read_text(encoding="utf-8")
        self.sites_ts = (root / "sites.ts").read_text(encoding="utf-8")
        self.baseline = json.loads(
            (root / "cloud-armor-baseline" / "branchleft-edge-armor.normalized.json").read_text(
                encoding="utf-8"
            )
        )
        self.accepted_document = json.loads(
            (root / "cloud-armor-baseline" / "accepted-parity-failures.json").read_text(encoding="utf-8")
        )

    def test_the_real_edge_ts_still_yields_every_rule_the_script_expects(self):
        rules = parity.expected_rules(self.edge_ts, self.sites_ts)
        priorities = {rule.priority for rule in rules}
        self.assertTrue({1000, 1001, 1002, 1003, 2000, 2147483647} <= priorities)

    def test_the_real_baseline_is_structurally_readable(self):
        problems = parity.check_parity(self.edge_ts, self.sites_ts, self.baseline)
        self.assertIsInstance(problems, list)
        self.assertTrue(all(isinstance(p, parity.Problem) for p in problems))

    def test_the_committed_accepted_failures_file_is_valid(self):
        entries = parity.parse_accepted_failures(self.accepted_document)
        self.assertTrue(all(isinstance(entry.priority, int) for entry in entries))

    def test_the_committed_acceptances_can_be_applied_to_the_real_problems(self):
        """Whether any entry is currently stale is the real check's verdict
        to report, not this suite's -- asserting either outcome here would
        break the day the real state changed. What must hold in every state
        is that the two files can be compared at all."""
        problems = parity.check_parity(self.edge_ts, self.sites_ts, self.baseline)
        entries = parity.parse_accepted_failures(self.accepted_document)
        remaining, matched, stale = parity.apply_accepted_failures(problems, entries)
        self.assertEqual(len(matched) + len(remaining), len(problems))
        self.assertEqual(len(matched) + len(stale), len(entries))


if __name__ == "__main__":
    unittest.main()
