# render.ts

## Module overview

Renders the monitoring stack's Prometheus scrape configuration and alert
rules from the estate address plan and the hostname registry in `sites.ts`.

Pure string building, deliberately -- the same discipline `../edge/render.ts`
uses and for the same reason: the output is committed under `stack/` and
copied onto the host by hand, so the only thing that can differ between what
a reviewer reads and what the host runs is the copy step. `render.test.ts` is
what keeps the committed files and this file from drifting apart.

Alertmanager's own configuration is _not_ rendered here in final form: it has
no way to read an environment variable from inside its config file, unlike
Caddy's `{env.X}`, so the committed file is a template carrying placeholder
tokens and `stack/render_alertmanager_config.py` substitutes them from
`/etc/branchleft/monitoring.env` on the host, once, before each start.

The registry is the only hostname list: a blackbox probe target written
here rather than derived from `sites.ts` is exactly the class of stray
record a cutover has to hunt for. Every hostname below is derived.

## MonitoredHost / MONITORED_NODE_HOSTS

The estate hosts this stack watches, and whether each node_exporter target
is expected to answer today. `app1` is base-provisioned but carries no
node_exporter yet -- provisioning it is a separate story -- so only the
edge1, db1 and ops1 node targets contribute to the `HostOrServiceDown` alert
`renderAlertRules` emits below.

**`db1` is expected up because its node_exporter reads the nightly dump's
textfile directory.** The dump writes its lock wait, hold and abort gauges
under `tenant="db1-all-databases"`, and only a node_exporter on db1 can
publish them; the backup alerts then see db1 with no rule change. The flag
flips in the same change as the install step, which is why
`RUNBOOK-monitoring.md` §17 puts the install and its read-back first and
the config redeploy last: the flag takes effect only when the rendered
config reaches edge1, so installing first means the target is never
expected-up while absent. A target that has never been available must not page anyone;
a target that stops answering after being available must.

**`ops1` joins the list once the host it names has actually been renamed,
not before.** A separate, sequenced-first change already renamed
`nextcloud1` to `ops1` across this estate -- the Pulumi resource, the
`HOST_IPS` key, the `sites.ts` `privateUpstream` -- precisely so this
entry could land second, after, rather than in the same change: a failure
following a rename alone has one candidate cause, a rename and a new
monitoring target together would have two. The Compose stack itself
keeps the name `nextcloud1` (renaming it would start Nextcloud on empty
volumes), which is why `hetzner/nextcloud1/` and this repository's
`nextcloud1` unit/env-file references are untouched by either change --
only the host's own identity moved. `expectedUp` is `true` only because
`RUNBOOK-monitoring.md`'s ops1 section read the exporter back answering
live first: a target that has never answered must not page anyone the
moment its config deploys, which is why app1 stays `false`. The flip
is a reviewed change, never a hand edit -- a hand edit of this flag, on a
different host's exporter, once hid a four-day outage (see this file's
`MONITORED_MYSQLD_HOST` comment below).

Deliberately not every entry in `HOST_IPS`/`APP_HOST_IPS`: `mon1`'s address
is reserved for the eventual split (doc 14 §3.1) and nothing listens there
yet, and `app2`/`app3` are scale-out rungs with no host behind them either.
Listing a reserved address as a scrape target is not a mistake this file
can catch on its own -- it would just be a target nobody set up, scraped
forever. The membership below is reviewed, not derived, for that reason.

## mx1's two watch paths

`mx1` is watched two ways, and the pair is deliberate.

**Liveness, from outside.** `mail/firewall.ts` opens 25, 465, 587 and 993
to the whole internet, so a blackbox probe from edge1 reaches them the way
any other client on the internet does, with no new firewall rule. It
cannot be a plain TCP-connect probe: a scan-banned or dead-backend
connection still completes the handshake and then EOFs, so every one of
those ports can read as healthy while Stalwart serves nothing behind them.
`smtp_banner` (25, 587) reads the `220` greeting and sends `QUIT`;
`tls_connect` (465, 993, both implicit-TLS) requires a completed
handshake. See `mailProbeStaticConfig()` and the `blackbox_mail` job below.

**Delivery outcomes, from inside.** A liveness probe cannot distinguish a
mail host that is delivering from one that is up and bouncing everything,
and that difference is the whole of the sender-reputation question. That
needs Stalwart's own counters, which is why `mail/provision/`
`configure_stalwart.py` enables its Prometheus exporter on the existing
public 443 listener -- see the `stalwart` job below.

mx1 is in its own hcloud project (`edge/render.ts`'s `NOT_AN_UPSTREAM`
carries the same fact for the edge), so it shares no private network with
this host and neither of these can be a private-address scrape. Both cross
the public internet, which is why the exporter is authenticated and
source-pinned rather than merely enabled.

## The `backup` rule group

Every alert in this group watches the same producer, `backup_worker.py` in
`branchLeft/ghost-platform` -- one on-demand call, one nightly loop, never
a second code path (see that repo's `backup_worker.md`). One group, not
two, since a reader hunting "the backup alerts" should find both without
also having to remember which of two similarly-named groups holds which:
`TenantBackupAgeHigh` (is a tenant's backup happening at all) and
`BackupLockWaitHigh` (did the dump that DID happen wait over the 1 s
server bound for its tenant's table lock) and `BackupLockAbortsRising`
(did any lock attempt get abandoned on a bound in the last day, even when a
retry then succeeded). The worker measures the wait in the lock's own
session; see ghost-platform's `db/provision/bounded_snapshot.md`.

`TenantBackupAgeHigh` is the producer-side signal, not a liveness check:
the worker advances this gauge only after a floor-verified successful
dump for that tenant, so a stopped or consistently-refused worker leaves
one tenant's series frozen while every other tenant's keeps climbing --
the metric carries a `tenant` label already, so one alert instance per
stale tenant is what `time()` minus the gauge naturally produces, with no
group-by needed. The rule's own `or absent(...)` branch covers the other
failure shape: the whole metric family gone (exporter down, textfile
deleted), which no per-tenant series can ever be stale enough to represent
on its own. Warning, never page: a stale backup is a chore on its own
timescale, not an outage, and this estate has no page register entry for
it by design -- routing carries no `notify: on-host` label either, since
the producer host is not mx1, so this reaches the same off-host email
receiver `HostMemoryPressure` and `HostDiskSpaceLow` already use.

`StateCopyStale` sits in the same group because its producer is the same host
and the same exporter directory: `state_copy.py` in `branchLeft/ghost-platform`
copies the two Pulumi state buckets into backup copy 1 each night and writes
`state_copy_last_success_timestamp_seconds` and `state_copy_bucket_configured`
per bucket. It has three branches, so a stale gauge, a configured bucket that
has never succeeded, and a vanished family each fire. Warning, never page,
same receiver as `TenantBackupAgeHigh`.

## The `replica-tunnel` rule group

Watches the blog's migration replica on `db-t1`, which receives `db1`'s
changes through `db1`'s `branchleft-db-tunnel.service`
(`../provision/45-install-db-tunnel.md`). The replica's mysqld_exporter is
read through the same ssh session, on `db1`'s `10.20.1.20:9105`, so one scrape
answers two questions: is the tunnel up, and what does the replica report.

| Alert                       | Fires when                                                                                               | Severity |
| --------------------------- | -------------------------------------------------------------------------------------------------------- | -------- |
| `ReplicaTunnelDown`         | the scrape through the tunnel fails for 5m                                                               | critical |
| `ReplicaNotReplicating`     | the IO or SQL thread is not running for 5m (`Connecting` counts as not running)                          | critical |
| `ReplicaLagHigh`            | both threads run and the replica is over 300s behind for 10m                                             | warning  |
| `ReplicaStatusMissing`      | the exporter answers but publishes no replica status for 10m: MySQL unreadable, or no channel configured | critical |
| `ReplicaTunnelPastDeadline` | the scrape is up and the time is past `REPLICA_TUNNEL_DEADLINE`                                          | critical |

A NULL `Seconds_Behind_Source` publishes no series at all; the container
proof saw NULL while the IO thread was `Connecting`. So the lag rule never
reads NULL as zero, and the thread rule is what covers that state. The
promtool cases in `alert_rules_test.yml` use the series names and labels a
live mysqld_exporter v0.20.0 published through the tunnel.

`ReplicaTunnelDown` inhibits `HostOrServiceDown` and `ServiceFlapping` on the
same instance: they read the same `up` series and would add only a second
message.

`MySQLUnreachable` and `MySQLConnectionsHigh` are scoped to `job="mysqld"`.
Both name `db1` in their summary, and a second mysqld_exporter job would
otherwise raise them for the replica under `db1`'s name.

## REPLICA_TUNNEL_DEADLINE

The tunnel's exposure is accepted for the migration window only.
`REPLICA_TUNNEL_DEADLINE` in `render.ts` is that window's end, a UTC timestamp
like `2026-11-01T00:00:00Z`, set in the same reviewed change that flips
`MONITORED_REPLICA_HOST.expectedUp`. The other rules in the group watch a
cleared or stopped replica; this one is the only one that fires while
replication is healthy and the move has stalled. Rendering throws on an
absent or malformed value rather than emit a rule that cannot fire. Its
promtool cases live in `alert_rules_deadline_test.yml`, a separate file
because promtool's clock starts at the epoch and needs a 1000h evaluation
interval to reach a real calendar date, so CI runs it as its own invocation.

## MONITORED_REPLICA_HOST

`expectedUp` is `false` until the tunnel is installed on `db1`, and every rule
in the group above selects `expected_up="true"`, so nothing fires before then.
Once the tunnel is live, `ExpectedDownTargetAnswering` warns that this target
answers, which is the prompt to flip it: the flip is a one-line reviewed
change here, then a monitoring delivery to `edge1`.

The target is temporary. After the migration's cutover the replica is
promoted and replication stops on purpose, so the target and the rule group
are removed in the same change that tears the tunnel down.

## The `snds-reputation` rule group

Microsoft's own feedback-loop data, not a proxy: mail-delivery alerts
read Stalwart's own counters, which can only see bounces mx1 itself
generates. Complaint rate is reported by the receiving provider out of
band -- a message that is accepted, delivered and then marked as junk
by the recipient never touches any of Stalwart's delivery counters at
all, which is exactly the shape of a signup flood aimed at harvested
real addresses (`RUNBOOK-monitoring.md`'s SNDS section).

Every rule here carries `notify: on-host`: SNDS alerts are expected to
fire while mx1's volume is too low for Microsoft to report on, and each
repeat that leaves mx1 for an external mailbox is unengaged machine mail
spending the very reputation these rules watch.

## renderAlertmanagerTemplate

Alertmanager's config template. `__SMTP_USERNAME__`, `__SMTP_PASSWORD__`,
`__HEALTHCHECKS_PING_URL__`, `__ALERT_RECIPIENT_EMAIL__` and
`__MAILHOST_PING_URL__`, with `__NTFY_PAGER_TOKEN__` in the page receiver, are substituted by
`stack/render_alertmanager_config.py` from `/etc/branchleft/monitoring.env`
before every start -- see that script's docstring for why this file cannot
just read the environment itself.

The page route (`pageRegister.ts`) is the one part of this template not
hand-typed below: `register` defaults to the committed `PAGE_REGISTER`,
and the parameter exists so a caller can prove the route is actually
derived from it rather than from a hardcoded duplicate -- see
`pageRegister.test.ts`.

## MX1_PUBLIC_IPV4

The Stalwart exporter is reached by **address, not by name**, with the
hostname carried in `tls_config.server_name` so certificate verification
still checks the thing it is supposed to check.

mx1 publishes an AAAA record as well as an A record, and Stalwart's
access-control rule admits only edge1's public IPv4. The IPv6 half of that
rule was dropped when this endpoint was built, because `remote_ip` did not
compare equal to the compressed literal and the rendered form was never
established -- a rule written against a guess reads as coverage while
never matching. A Go dialer handed the hostname resolves both families and
may reach for the AAAA first, exactly as `curl` did during that
verification, and every scrape that does is refused with a 421. Naming the
address removes the choice rather than relying on resolver preference.

`instance` is relabelled back to the hostname below, so what a human reads
in an alert is still `mx1.branchleft.co.uk`.

## STALWART_METRICS_PORT

Basic auth over TLS, with the password read from a file rather than
written into this config: `stack/prometheus/prometheus.yml` is committed
to a public repository.

That file is not in the committed tree. `stack/render_alertmanager_config.py`
writes it on the host from `STALWART_PROMETHEUS_SECRET` in
`/etc/branchleft/monitoring.env` before every start, exactly as it writes
`alertmanager.yml`, and every deploy's `rsync --delete` removes it for the
same reason.

A missing file does not stop Prometheus starting. Neither `promtool check
config` nor the config loader stats it -- it is read per request -- so the
failure mode is `up{job="stalwart"} == 0` and a HostOrServiceDown page.
That is the right way round: one unreachable scrape target must never take
down the alerting path for the whole estate.

## MONITORED_MYSQLD_HOST

`db1`'s MySQL exporter is live, so unlike the `node` targets above this one
is expected to answer and pages when it does not.

It was `false` while the exporter did not exist, which was correct then and
became wrong the moment the exporter shipped -- the flip is a hand edit in
this repo, satisfied by a deploy in another, with nothing connecting the
two. That gap hid a four-day crash loop: the suppression that made the
target quiet is the same suppression that would have reported it shipped
broken. Anything set `false` here is a claim about the present that needs
re-checking against `up` on `edge1`, not a permanent property.

## EDGE1_SERVICE_LABELS / APP1_SERVICE_LABELS

Labels for services set up as inline scrape configs, expected to answer.
Each constant names a specific host and sets expected_up=true directly,
rather than deriving from MonitoredHost. `HostOrServiceDown`'s `expr`
picks up every `up{expected_up="true"}` series without any change to the
alert rule itself.

`alertmanager` is included for the same reason as the rest: Prometheus
keeps running and evaluating while only Alertmanager is down, so a
crash-and-restart still produces a real, if delayed, alert once
Alertmanager is back to receive it. `prometheus`'s own self-scrape cannot
behave the same way -- while the Prometheus process itself is down nothing
evaluates or records a sample at all, and the instant it restarts its
self-scrape immediately succeeds, so `up{job="prometheus"}==0` can never
be observed true for a sustained window. It is labelled `true` anyway for
consistency with `RUNBOOK-monitoring.md` §8's verification list, not
because this rule can ever catch a Prometheus outage: a sustained loss of
the whole monitoring stack is caught by the `Watchdog` heartbeat's
external dead-man's switch (`RUNBOOK-monitoring.md` §11) instead, which
observes from outside this process entirely.

`blackbox_http` carries this label across multiple targets: one per
hostname in `sites.ts`. If the blackbox_exporter dies, `HostOrServiceDown`
fires once per probed hostname rather than once total. That is correct
behaviour — `up{job="blackbox_http"}` measures whether Prometheus can reach
the exporter, not whether a probe succeeded.

## Selector and target label join

A rule test and a config test can each pass without proving the two meet. One
proves a rule's own text, another proves a target's own labels, but a selector
reading `expected_up="true"` against a target labelled `expected_up='True'`, or
a host name typo'd as `ops-1`, still passes every promtool rule test written
against hand-typed series: `alert_rule_test` never reads the rendered scrape
config, and the mismatch reads at the API as `inactive`, identical to healthy.
The test in `render.test.ts` reads both sides of the join from the two render
functions themselves, not a retyped copy of either.
