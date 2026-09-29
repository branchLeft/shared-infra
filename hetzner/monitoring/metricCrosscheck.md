# metricCrosscheck.ts

## Module overview

Cross-checks the metric names (and, where derivable, the label keys) an
alert rule expression queries against the metric names a collector this
repo owns actually emits.

Why this exists, and what it does not replace: `render.test.ts` proves
`alerts.yml` matches what `render.ts` generates -- self-consistency
between a generator and its own output, never a check against the thing
that actually produces a metric's samples. `alert_rules_test.yml` proves
an expression evaluates the way a human expects against hand-typed
synthetic series -- it never reads a collector either. A rule and its
collector can each be internally consistent this way and still disagree
on a name, and that failure is silent in production: a broken selector
returns no results, which reads exactly like "nothing is wrong".

A collector, for this module's purposes, is any non-test `.py` file
beneath a given root that declares at least one Prometheus text-exposition
`# TYPE <name> <type>` line -- the format's own metric-name declaration,
never a name this module invents. A queried name with no such declaration
is assumed to belong to a third-party binary this repo does not author;
`EXTERNAL_METRICS` is the reasoned, per-entry account of which one.

## Known limitations, disclosed rather than silently accepted

- **Label-value matching is out of scope.** `findUnemittedLabelKeys` only
  ever checks that a selected label KEY is one the collector emits for
  that metric, never that the VALUES on either side can actually meet --
  a selector whose pattern never matches a real emitted value (the
  `remote_ip`/IPv6 shape) is a live failure mode this cannot see, since
  values are only known at scrape time.
- **No control-flow or reachability analysis.** A `# TYPE` line is read
  as text, not as a statement proven to execute. `extractEmittedMetrics`
  strips triple-quoted (`"""..."""`/`'''...'''`) spans before scanning,
  specifically because this codebase's docstrings are exclusively
  triple-quoted (see `collect_snds_metrics.py`, `configure_stalwart.py`)
  and a documentation example quoting `# TYPE foo gauge` must not count
  as this file emitting `foo`. That removes the demonstrated failure
  shape, not every one: a bare, non-string Python `#` comment that
  happens to read exactly `# TYPE name gauge` on its own line, or a real
  single-quoted exposition string sitting in a genuinely dead branch
  (behind an `if False:`, or otherwise never reached), still reads as
  emitted. Closing that fully needs a real Python parse (AST/tokenize)
  this module does not perform. Prefer deleting dead exposition code
  over leaving it -- this check cannot tell the difference.
- **The allowlist is reviewed, not verified.** `EXTERNAL_METRICS` is
  reasoned per entry so it is not a wholesale copy of `alerts.yml`'s
  query list, and one test asserts no entry in it names a metric a local
  collector already emits -- but nothing stops a plausible-sounding
  reason being written for a metric that is, in fact, local. It narrows
  the risk; it does not eliminate it.

## EXTERNAL_METRICS

Metric names this repo's alert rules query but does not own the source
of: each is written by a third-party binary, or built into Prometheus or
Alertmanager themselves, so a rename can only originate upstream, never in
a commit to this repo. Listed and reasoned individually -- copying
`alerts.yml`'s query list wholesale here would recreate exactly the
incidental, self-referential catch this module exists to replace; an
unrecognised name must be added with its own reason, never assumed.

This list is reviewed, not verified: a plausible-sounding reason can still
be written for a metric that is, in fact, local. The one automated guard
is narrow -- a test asserts no entry here names a metric a local collector
already emits -- and does not by itself prove every reason given is true.
