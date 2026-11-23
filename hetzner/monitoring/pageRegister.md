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

## How fast a page goes, and how often it repeats

The critical node and the page node carry their own `group_wait: 10s`,
`group_interval: 1m` and `repeat_interval: 30m`, from `renderPageTimingLines`
in `pageRegister.ts`. The owned-ban node (`EdgeBanIssued`, see below) keeps
its own timings and inherits the root's repeat.
The root route's `group_interval: 1h` and `repeat_interval: 24h` are for
email, where repeats spend the mail host's sending reputation, and the email
routes are separate sibling nodes that keep them. Left to inherit, a page
behaved as email does:

- a recovery notice (`send_resolved: true`) waited up to an hour, so a cleared
  probe read as an open outage;
- a ban that started after the first ban of the hour waited up to an hour, and
  a ban that ended sooner never paged;
- a page nobody saw was sent again a day later.

Now a new or resolved alert in a group that has already notified is sent within
about a minute on the critical and page nodes, and a page on either node that is
still firing is sent again every half hour until it clears or is silenced.

`amtool config routes test` proves where an alert goes and not how fast, so
`pageRegister.test.ts` reads the intervals from the rendered tree, resolving
what a node inherits from the root, and fails any page node slower than those
bounds or an email node that has been made faster.

Owned bans are paced by the owned-ban node, not the page node. For an owned
ban, `EdgeBanIssued` sums by `(reason, decision_id)`, so each owned ban is its
own alert, and it pages within the owned node's 5-minute group interval (30
seconds for a new scenario). That node keeps main's `group_wait: 30s` and
`group_interval: 5m`, and inherits the root's `repeat_interval: 24h`: the
30-minute repeat holds for the critical and page nodes only. While the
classifier is stale or absent, the fallback raises the same `EdgeBanIssued`
alertname, summed by `reason`, which the owned node also matches, so it is
paced on the owned node's timings too.

Each page also carries a tap target and one button, both the public status
page (`NTFY_PAGE_CLICK_URL`), and no secret. There is no acknowledge or silence
button: Alertmanager has no address a phone can reach, and the call would need
a credential. CI publishes a firing and a resolved test notice to the pinned
ntfy with the rendered URL, so a value ntfy refuses fails there.

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

## The opposite direction: a live entry needs a rule or a named exemption

`findUnregisteredPageSeverityAlerts` catches a rule with no entry. The other
gap is an entry with no rule: a live Alertmanager entry whose alertname no
`severity: page` rule raises registers a route for a page that silently never
fires. `findLiveEntriesWithoutPageRule` reports every live Alertmanager entry
that is neither raised by a `severity: page` rule in the rendered rules nor
carries a `ruleExemption`, the reason it is raised some other way. Dormant and
Healthchecks-delivered entries are not checked. `pageRegister.test.ts` runs it
against the real register and the real rendered rules, and against the reaper
entry flipped to live with no rule, which must report it.

Two `severity: page` rules come from the edge's ban classifier on edge1, and their
entries carry no exemption. `EdgeBanIssued` pages for each ban on an owned address
(`edge_ban_owned{owned="true"}`, one sample per decision id); `EdgeBanOwnerStale` pages
when the classifier has not run for over 15 minutes, once that has lasted 5 minutes.
`EdgeBanIssued` also pages every ban while the classifier is stale (at once) or has
reported and then been absent for 10 minutes; a classifier that has never reported
pages at once. While the role is disabled (`EDGE_BAN_OWNER_ENABLED` is `false`),
`EdgeBanOwnerStale` is routed to the `discard` receiver, not to a page. A ban on any other address is
`EdgeBanUnowned`, a warning that goes to email and is not registered. Each of the other three live Alertmanager entries carries a
`ruleExemption`: the tier-two safety
match and the failed-unsafe tenant have no producer yet: the platform is planned to raise them, and nothing does today. The
reader-facing probe's page is per tenant, which this stack's instance-labelled
blackbox probes cannot express. When a rule that raises one of them lands, drop
that entry's exemption in the same change.

## A page that never becomes an alert: the abuse report

The `abuse-report` entry has `deliveryPath: 'ntfy_direct'` and no alertname. The mail host posts
it straight to the pager with a publish-only grant on a topic of its own (`NTFY_ABUSE_TOPIC`),
so it renders no Alertmanager route, no rule raises it, and neither direction of the
rule-and-register check applies to it, as for the Healthchecks-delivered entry. It is listed so
the register still names every path that can reach the phone. Its contract is the page's content:
it says only that an abuse report arrived, with no sender, no message text and no tenant. The
register has no label schema, so no test can enforce that; the producer's own tests do
(`ansible/roles/mx1_abuse_page`), and `pageRegister.test.ts` pins that the server config gives the
mail host one grant, write-only, on this topic and none on the page topic.
