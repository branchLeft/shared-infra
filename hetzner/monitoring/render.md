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
is expected to answer today. The first four entries are `true`, so those node
targets (edge1, app1, db1 and ops1) contribute to the `HostOrServiceDown` alert
`renderAlertRules` emits below. The tenant hosts after them are `false`; see
[the tenant hosts' node targets](#the-tenant-hosts-node-targets). `app1` flipped with the `node_exporter` role
joining its playbook (ws#885): the flag takes effect when the rendered config
reaches edge1, so the gated apply that installs the exporter on app1 comes first.

**`db1` is expected up because its node_exporter reads the nightly dump's
textfile directory.** The dump writes its lock wait, hold and abort gauges
under `tenant="db1-all-databases"`, and only a node_exporter on db1 can
publish them; the backup alerts then see db1 with no rule change. The flag
flips in the same change as the install step: the flag takes effect only
when the rendered config reaches edge1, so installing first means the
target is never expected-up while absent. A target that has never been available must not page anyone;
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
moment its config deploys, which is why app1 stayed `false` until its exporter was delivered. The flip
is a reviewed change, never a hand edit -- a hand edit of this flag, on a
different host's exporter, once hid a four-day outage (see this file's
`MONITORED_MYSQLD_HOST` comment below).

Deliberately not every entry in `HOST_IPS`/`APP_HOST_IPS`: `mon1`'s address
is reserved for the eventual split (doc 14 §3.1) and nothing listens there
yet, and `app2`/`app3` are scale-out rungs with no host behind them either.
Listing a reserved address as a scrape target is not a mistake this file
can catch on its own -- it would just be a target nobody set up, scraped
forever. The membership below is reviewed, not derived, for that reason.

## The tenant hosts' node targets

`db-t1`, `app-t1` and `edge-t` (the tenants project, branchLeft/workspace#1810) are the last three
entries of `MONITORED_NODE_HOSTS`, each `expectedUp: false`, at the addresses in `TENANTS_HOST_IPS`
(`10.20.1.200`, `.201`, `.210`). The label is what keeps `HostOrServiceDown` and `ServiceFlapping`
silent for a host that has never answered, and `ExpectedDownTargetAnswering` is the tripwire if one
starts answering while still labelled `false`: the same arrangement every host above went through.

Two facts shape them. The tenants project has its own network, and a network does not span projects,
so these addresses are the tenants network's, which reuses the estate's range (ruling 5a of 2 Nov
2026). The Prometheus on edge1 cannot reach them directly, so it reads each through the restricted
tunnel to edge-t (see [Tunnelled tenant node targets](#tunnelled-tenant-node-targets)) and each
scrape fails until that tunnel is applied, and no host is flipped before a query for it returns `1` (`RUNBOOK-monitoring.md`,
15f). And the disk and memory rules (`HostDiskSpaceLow`, `HostMemoryPressure`) select on neither
`host` nor `expected_up`, which is what makes them evaluate for these hosts the moment their series
arrive, flipped or not. `render.test.ts` holds both statements: the rendered rules carry no such
selector, and every tenant host's address appears in a promtool case for the disk, memory and
host-down alerts (`alert_rules_test.yml`, and `alert_rules_memory_test.yml` for the 24-hour memory
rule, a separate file because its evaluation interval is coarser). `tenants.metricsPorts.test.ts`
holds that no firewall of the tenants program opens an exporter's port.

The tenant edge's outside reachability probe is not here: it is route-specific and belongs to
branchLeft/shared-infra#947 (branchLeft/workspace#1640).

The `db_t1_replica` job reads db-t1's MySQL exporter, which listens on `127.0.0.1:9104` there, through
db1's replica tunnel; it has its own host label and is unchanged. The `node` job's `db-t1` row is the
host's own node_exporter and is a different series.

## mx1's two watch paths

`mx1` is watched two ways, and the pair is deliberate.

**Liveness, from outside.** `mail/firewall.ts` opens 25, 465, 587, 993 and
8443 to the whole internet, so a blackbox probe from edge1 reaches them the way
any other client on the internet does, with no new firewall rule. It
cannot be a plain TCP-connect probe: a scan-banned or dead-backend
connection still completes the handshake and then EOFs, so every one of
those ports can read as healthy while Stalwart serves nothing behind them.
`smtp_banner` (25, 587) reads the `220` greeting and sends `QUIT`;
`tls_connect` (465 and 993, both implicit-TLS, and 8443, the mailgun shim's
Caddy endpoint, which `mail/firewall.ts` also opens) requires a completed
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

The producers are `backup_worker.py` in `branchLeft/ghost-platform` -- one
on-demand call, one nightly loop, never a second code path (see that repo's
`backup_worker.md`) -- which runs on `ops1`, the control host; `dump_nightly.py`,
which runs on `db1`; and, for `StateCopyStale`, `state_copy.py`, also on
`ops1`. `TenantBackupAgeHigh` has one producer, on `ops1`: `db1`'s dump
never writes `backup_worker_last_success_timestamp_seconds` (it publishes its
own `db_nightly_dump_last_success_timestamp_seconds`, which no rule in this
group reads). `BackupLockWaitHigh` and `BackupLockAbortsRising` have two, one
on each host: the same lock gauge names come from `ops1`'s per-tenant worker
and from `db1`'s dump under `tenant="db1-all-databases"`.
One group, not two, since a reader hunting "the backup alerts" should find
them all without also having to remember which of two similarly-named
groups holds which:
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
group-by needed. The rule's own `or label_replace(absent(...))` branch covers the other
failure shape: the whole metric family gone (exporter down, textfile
deleted), which no per-tenant series can ever be stale enough to represent
on its own. That branch is tagged `scope="family"` and renders a summary
without a tenant name. Warning, never page: a stale backup is a chore on its own
timescale, not an outage, and this estate has no page register entry for
it by design -- routing carries no `notify: on-host` label either, since
the producer host is not mx1, so this reaches the same off-host email
receiver `HostMemoryPressure` and `HostDiskSpaceLow` already use.

`StateCopyStale` sits in the same group because it is the same kind of
signal, a backup that has stopped, and shares `TenantBackupAgeHigh`'s host.
`state_copy.py` in `branchLeft/ghost-platform` runs on `ops1` as the
`backup-worker` account, from the same staged release as the backup worker.
It copies the two Pulumi state buckets into backup copy 1 each night and
writes `state_copy_last_success_timestamp_seconds` and
`state_copy_bucket_configured` per bucket to `state_copy.prom` in the
worker's exporter directory, `/var/lib/branchleft/backup-worker-exporter`,
which `ops1`'s node_exporter reads
(`hetzner/provision/node-exporter.service`). It has three branches, so a
stale gauge, a configured bucket that has never succeeded, and a vanished
family each fire. Warning, never page, same receiver as `TenantBackupAgeHigh`.

### db1's own dump and binlog shipping

`TenantBackupAgeHigh` reads the control host's copy. Five more rules in the
same group read db1 itself, from the two status files db1's `dump_nightly.py`
and `ship_binlogs.py` write to the textfile directory db1's node_exporter
reads (`db/provision/dump_nightly.md` and `ship_binlogs.md` in
branchLeft/ghost-platform). All five select on `host="db1"`, the label the db1
node target carries, and are warnings on the same route as the rest of the group.

| Alert                       | Fires when                                           | `for:` |
| --------------------------- | ---------------------------------------------------- | ------ |
| `DbNightlyDumpStale`        | the last stored dump is over 108000s (30h) old       | none   |
| `DbNightlyDumpFailed`       | the latest dump run's status gauge reads 0           | none   |
| `DbNightlyDumpMetricAbsent` | no dump success time is published for db1            | 30h    |
| `DbBinlogShipStale`         | the last fully shipped run is over 3600s (1h) old    | none   |
| `DbBinlogShipMetricAbsent`  | no binlog shipping success time is published for db1 | 1h     |

The thresholds follow the two timers. The dump fires at 03:00 UTC with up to 5
minutes of random delay and its unit stops at 30 minutes, so two healthy
successes are at most 24h35m (88500s) apart and 30h leaves 5h25m of margin. The
shipper fires every 15 minutes and its unit stops at 10, so a healthy run
completes within about 25 minutes of the last; 1h is three runs in a row failed
or missed. The stale rules carry no `for:` because the files are written once
per run and are otherwise flat, the same reasoning as `BackupLockWaitHigh`.

The `absent` rules wait as long as the matching stale threshold. A script
delivered after its rule writes its first status inside that wait (within about
24h35m for the dump, 25 minutes for the shipper), so the order of delivery cannot
raise a false alert; the rules are still best applied once the scripts are on
db1. The series are named for db1,
not for the control host's worker, so the worker's series can never hide db1's
absence.

### The control plane's own backup

Two more rules in the same group read the backup of the control plane's portal and
sign-in databases on `ops1`, from two textfile gauges the program installed by the
`control_plane_backup` Ansible role writes (`ansible/roles/control_plane_backup`).
Both select on `host="ops1"`, are warnings on the same route as the rest of the
group, and carry no `for:`, because the files are written once per run and are
otherwise flat.

| Alert                         | Fires when                                                                 | `for:` |
| ----------------------------- | -------------------------------------------------------------------------- | ------ |
| `ControlPlaneBackupStale`     | a stage's last success is over 129600s (36h) old, per `stage` label        | none   |
| `ControlPlaneBackupRunFailed` | the unit last failed more recently than the last `shipped_offsite` success | none   |

`ControlPlaneBackupStale` reads `control_plane_backup_last_success_timestamp_seconds`,
which the program advances per stage: `verified_on_host` after the copy has been
restored into a throwaway server and counted equal to live, `shipped_offsite` after
the sealed copy is put to backup copy 1. The timer fires at 02:40 UTC with up to 5
minutes of random delay and the unit is stopped at 2 hours, so two healthy
successes are at most 26h05m apart and 36h leaves 9h55m of margin. Backup copy 1
expires an object 10 days after it is put, so the alert leaves about 8.5 days to
run the backup by hand before copy 1 holds no control-plane backup.

`ControlPlaneBackupRunFailed` is the same night's signal. The service's
`OnFailure=` starts `branchleft-control-plane-backup-failed.service`, which runs the
program's `mark-failed` command to write `control_plane_backup_last_failure_timestamp_seconds`
to its own file (`control_plane_backup_failed.prom`). A hook outside the program is
what lets a kill, the two-hour timeout or a crash before the program printed a line
be seen at all. The mark holds while it is strictly newer than the last
`shipped_offsite` success, so only a copy that reached backup copy 1 clears it: a
restore that proved a newer copy on the host does not, and a failure that comes
after a ship (the prune that follows it) is not hidden by that ship.

Named limits. Neither rule uses `absent()`: the role's timer stays off until the
owner's apply turns it on, and a rule that fired for a backup nobody has switched
on would be noise from the day it is deployed. So a timer that has never run, and
never failed, is not seen. The names are not emitted by a collector under this
directory, so `metricCrosscheck.ts` lists them under `EXTERNAL_METRICS`, and a unit
test in the role pins both names and the `shipped_offsite` stage to these
expressions.

## The compose-unit rule group

Two warnings on the compose template's own units
(`hetzner/provision/branchleft-compose@.service`), added with the one-hour start
limit. A stack that hangs to the template's 600 second
start timeout fails about every ten minutes; with the old 900 second window the
start limit never tripped and the unit retried for ever with no alert. The limit now
trips after five starts (2520 seconds in), and these two rules are how the owner
hears of it, by email and never by page (the severity is `warning`).

- `ComposeUnitRestartLoop`: `increase(node_systemd_service_restart_total[1h]) >= 2`
  for a `branchleft-compose@*` instance. It sees the loop from its third start, before
  the limit stops it, and ignores a single retry (a start that raced a `containerd`
  restart). There is no `for:`: the counter is the window.
- `ComposeUnitFailed`: `node_systemd_unit_state{state="failed"} == 1` for ten minutes.
  `start-limit-hit` is a failed state that nothing clears until `systemctl reset-failed`,
  so this is the alert that stays up after the loop has ended.

Both series come from the node exporter's systemd collector, which
`hetzner/provision/node-exporter.service` switches on, limits to the compose
instances with `--collector.systemd.unit-include`, and gives the restart counter
(`--collector.systemd.enable-restarts-metrics`). Both rules are scoped to
`expected_up="true"`, as the scanner group is. They see app1, db1 and ops1, whose
exporters are the native one. edge1's exporter is the Compose container of the
monitoring stack, which has no systemd bus, so a loop of an edge1 stack is not seen:
the follow-up is a mount of the bus socket into that container, which is a change to
a live stack and is not made here. `alert_rules_test.yml` holds a promtool case for
each rule, including the single retry, a host not yet expected up and a unit that is
not a compose instance.

## The `scanner` rule group

Watches the upload scanner inside each tenant's Ghost process. The series are
the scanning storage adapter's own, written as a node_exporter textfile by that
process on its app host and read by the host's node target, so they carry that
target's `job="node"`, `host` and `expected_up` labels plus the adapter's
`tenant` label. The names, types and label values are a contract owned by
`branchLeft/ghost-platform` (`adapters/scanning-storage/src/metrics.md`);
`metricCrosscheck.ts` lists them under `EXTERNAL_METRICS` for that reason, since
this repository cannot scan JavaScript in another one.

| Alert                          | Fires when                                                              | Severity |
| ------------------------------ | ----------------------------------------------------------------------- | -------- |
| `ScannerNotConfigured`         | an adapter has no verdict source for 10m (fresh file only)              | warning  |
| `ScannerUploadsRefused`        | an upload was refused for want of a verdict source in the last 15m      | warning  |
| `ScannerVerdictChannelFailing` | verdict requests time out or throw in every 5m window for 10m, per kind | warning  |

Why nothing here can fire from absence. Every rule selects
`job="node", expected_up="true"`, so a host whose exporter is not yet confirmed
live (any host carrying `expected_up="false"`) is silent however its series look,
and none uses `absent()`: a host or tenant with no scanner series, or with
export switched off, is not a fault. The flip is the same reviewed hand edit as
every other `expectedUp`, in `MONITORED_NODE_HOSTS`, and it is a claim that
the textfile directory is mounted into the tenant containers as well as that
the exporter answers. Until the mount exists no series is produced and the
group is inert.

Why there is no threshold here. The latency, error-rate and held-age bounds
are the owner's targets (`SLO_VERDICT_P95_MS`, `SLO_ERROR_RATE`,
`SLO_HELD_AGE_MAX`, placeholders until set), and a rule rendered with an
invented number would page on it. The three rules above need none: refusal and
unconfigured are binary, and sustained errors are a pattern, not a level. A
rule that reads a target is added in the change that sets the target.

`ScannerNotConfigured` ends in a freshness clause on the file's own
`scanning_storage_metrics_written_timestamp_seconds`. A textfile outlives its
writer, so without it a torn-down tenant's last `1` would hold the alert open
forever. The counter rules need no such clause: a frozen counter has no
`increase()`.

Routing is the default for a warning (the on-host mailbox) and none of these
carries `owner_action` or a page register entry. Both are the owner's to decide
and are one reviewed line each; see `pageRegister.md` and the
`owner_action` test in `render.test.ts`.

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

## The release watcher scrape path

The Ghost release watcher is a scheduled GitHub Actions workflow in
`branchLeft/ghost-platform` (`release-watcher-run.yml`, every six hours); no
host of ours runs it. After each poll it commits `release-watcher.prom` to the
`state/release-watcher` branch, carrying
`ghost_release_watcher_last_success_timestamp_seconds` (the time of the last
successful poll) and `ghost_release_watcher_pr_writes_enabled`.

The `release_watcher` scrape job reads that file from the raw-content host
over HTTPS. The repository is public, so the job needs no credential and
nothing is pushed anywhere: the path is a pull, and a watcher that stops
leaves the file, and so the gauge, where it was. Two details are deliberate:

- **`scrape_interval: 2m`.** The raw host caches the file for five minutes, so
  faster reads return the same bytes, and a sample must land inside
  Prometheus's five-minute lookback or the series would vanish between
  scrapes and `ReleaseWatcherStale`'s `absent()` branch would fire for a
  healthy watcher.
- **No `expected_up` label.** The job is named in the exemption list in
  `render.test.ts`. `true` would send `HostOrServiceDown`, a critical page,
  for five minutes of GitHub's own outage; `false` would raise
  `ExpectedDownTargetAnswering` the moment it answered. Left unmarked,
  `TargetDownUnmarked` reads a sustained outage at 24 hours as a warning.

## The `release-watcher` rule group

`ReleaseWatcherStale` fires when the gauge is more than 24 hours old (four
missed six-hour ticks) or absent, after `for: 30m` so one failed scrape of the
raw host does not fire it. Severity `warning` with no `notify` label: it
reaches the on-host mailbox through the existing warning route, and never
pages. It cannot tell a watcher that errors on every run from one that is
switched off, and does not need to: both leave the timestamp where it was. The
promtool cases are at the end of `alert_rules_test.yml`.

It exists because the watcher failed every run from 11 November 2026 and
nothing alerted. The alert rule is an owner merge; the gauge appears in
Prometheus once the
rendered `prometheus.yml` and `alerts.yml` are applied to edge1.

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

`renderAlertmanagerTemplate` takes a second parameter, `edgeBanOwnerEnabled`, which
defaults to `EDGE_BAN_OWNER_ENABLED`, the constant that must equal the role's
`edge_ban_owner_enabled`. While it is false, the classifier's `EdgeBanOwnerStale`
entry is held dormant, so it is left out of the page routes, and a `discard` route,
placed before the owned-ban child route, sends it to the `discard` receiver, which
has no integrations and so notifies no one. The owned-ban child route for
`EdgeBanIssued` (grouped by `alertname` and `reason`, `group_wait` 30s,
`group_interval` 5m) is rendered in both modes and matches first without `continue`;
the generic page route still groups tenant-scoped pages by `tenant`. The alert rules
are the same in both modes. `render.test.ts` checks that the discard route and
receiver appear only while the parameter is false, and that the constant equals
`edge_ban_owner_enabled` in the role's defaults, failing with a message that names
both files when they differ.

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
`alertmanager.yml`, and the `monitoring_stack` role, which never deletes,
leaves it in place.

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

## Tunnelled tenant node targets

`tenantTunnel.ts` lists the tenant hosts whose node_exporter `edge1` reads
through an SSH tunnel to `edge-t`, rather than directly on the tenants
network. Each tunnel is a fixed local port on `edge1`'s private address
(`TENANT_TUNNEL_TARGETS`: `db-t1` 19100, `app-t1` 19101, `edge-t` 19102).
They are listed in the `node` job as targets with `expectedUp: false`, and
one `relabel_configs` rule per tunnel sets `instance` back to the tenant's
own `address:9100`, so an alert sees the same series a direct scrape would.

The tunnel rows must agree with the direct rows. `hostsScrapedDirectly`
drops any direct row whose name is tunnelled, so no host is scraped twice,
and it throws `TunnelRowMismatchError` when that direct row's address or
`expectedUp` differs from the tunnel row. A host is flipped by editing both
rows; the render refuses one without the other.

The local ports must stay clear of every `*_PORT` constant here, every port
in `stack/compose.yml`, and the sweego receiver ports in
`ansible/owner_vars/edge1.yml`; `tenantTunnel.test.ts` checks each one.
