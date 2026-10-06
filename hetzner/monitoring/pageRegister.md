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
