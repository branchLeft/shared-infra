# The page register

The page register: the single, committed list of what may page a phone.

Adding an entry here is a decision, not a configuration change -- the
register exists to stay short, so it is reviewed by hand rather than
derived from anything else. `render.ts`'s `renderAlertmanagerTemplate`
renders the page route from this list and nothing else: a producer that
starts raising `severity: "page"` without an entry here must not reach a
phone by accident, and `findUnregisteredPageSeverityAlerts` below is what
makes that a build failure rather than a silent gap.

Alerts group on the cause, not the entry -- the page route's `group_by`
is the `tenant` label, deliberately not `alertname`, so two different
entries firing for the same tenant collapse into one notification. An
entry with no tenant of its own (the estate-wide ones) still has a
`tenant` label of the empty string, which groups those alerts with each
other the same way.

## Dormant entries

An entry marked `dormant` renders no route and is left out of
`pageAlertNames`, so it cannot page. Two entries are dormant today:
appeal latency, until a target is set for how long an appeal may wait, and
the stopped demo reaper (`stopped-demo-reaper`, alertname
`StoppedDemoReaper`), until the reaper that ends a demo at the close of its
lease exists and the threshold for how long it may stay silent is set. The
reaper entry is not tenant-scoped: a stopped reaper is an estate-wide
condition, so its page carries no `tenant` label of its own and groups with
the other estate-wide alerts.

Registering the reaper first is deliberate -- the register is the reviewed
list of what may page, so the owner's decision that a stopped reaper pages
the phone is recorded in code before the reaper exists. The alert rule that
raises `StoppedDemoReaper` arrives with the reaper, in the same change that
flips `dormant` to false; until then `findUnregisteredPageSeverityAlerts`
reports any rule that carries `severity: page` under that alertname, because
a dormant entry reaches no phone. `pageRegister.test.ts` proves both halves:
the dormant entry is absent from the rendered route, and switching it on is
the only thing that puts it there.

## The metric-crosscheck discipline applied to severity

The metric-crosscheck discipline applied to severity, not to a metric
name: every `alert:` block in `rulesYamlText` that carries `severity:
page` must name an alertname `pageAlertNames(register)` already covers,
or the route rendered from the register can never have been reachable by
it in the first place -- a producer that raises `severity: page` under an
alertname the register does not know is a page with nowhere to go, not a
page that reaches a phone by some other, unaudited route.

A small hand-rolled reader over the rendered YAML text, matching
`metricCrosscheck.ts`'s own reasoning for not taking a YAML dependency:
the shape read here is exactly the shape `renderAlertRules` produces.
