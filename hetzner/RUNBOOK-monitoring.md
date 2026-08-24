# Runbook — the monitoring stack on `edge1`

Deploying Prometheus, Alertmanager, Grafana and their exporters onto `edge1`,
colocated with the edge stack until TENANT_1
(`ghost-platform-docs/14-hetzner-migration-programme.md` §3.1), and verifying
the three mitigations that ride with that collocation: cgroup bounds on both
compose stacks' containers, Grafana bound to the private address only, and a
heartbeat wired to an external dead-man's switch.

`edge1` is `46.225.95.167` (private `10.20.1.10`), a `cx23` in `nbg1`. Every
`ssh`/`scp` below uses the platform owner's key, `~/.ssh/id_ed25519_hetzner`.
Run every workstation command from the root of a `branchLeft/shared-infra`
checkout, same convention as `RUNBOOK-edge.md`.

## What has to be true first

`RUNBOOK-edge.md` must already be deployed and running -- this runbook adds a
second Compose stack beside it, does not create the host, and assumes
`branchleft-compose@.service`, Docker and `/usr/local/sbin/branchleft-deploy`
are already installed.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  systemctl is-active branchleft-compose@edge &&
  test -x /usr/bin/python3 &&
  echo ready'
```

Expect `active` then `ready`. `python3` is what
`stack/render_alertmanager_config.py` runs under -- see "Colocation cgroup
bounds" below for why that script exists at all.

## Colocation cgroup bounds -- the sizing arithmetic and where it actually lives

The amendment accepted onto this story asks for `MemoryMax` and `CPUWeight`
bounds on the CrowdSec and Prometheus units so that neither can starve the
other.

**Where the real containment lives is not the systemd units.**
`branchleft-compose@edge`/`@monitoring` are `Type=oneshot` running `docker
compose up -d`, which detaches and exits the moment the containers are
created -- dockerd then runs each container in its own sibling scope under
`system.slice`, not nested inside the calling unit's cgroup. A `MemoryMax` or
`CPUWeight` set on the unit therefore bounds the `docker compose` CLI
invocation and this stack's `ExecStartPre` script, not Caddy, CrowdSec,
Prometheus or any of the other five containers. The systemd drop-ins below
are still installed -- `systemctl show` on them is part of the amendment's
literal acceptance text, and they are a real (if narrow) backstop on whatever
does run inside that cgroup -- but they are not what makes the mitigation
real. **The actual per-process containment is `mem_limit`/`cpu_shares` set
directly on each service in both `compose.yml` files** -- Docker's own
per-container `HostConfig`, applied at container creation regardless of
which process asked for it, so it holds whether or not the containers are
cgroup-descendants of the systemd unit that started them.

**Worst-case memory, per doc 14 §3.1's own arithmetic plus this story's
additions:**

| Component | Worst case | Stack |
|---|---|---|
| Caddy | 100 MB | edge |
| CrowdSec agent | 150 MB | edge |
| AppSec + CRS | 400 MB | edge |
| **edge subtotal** | **650 MB** | |
| Prometheus | 500 MB | monitoring |
| Alertmanager | 50 MB | monitoring |
| Grafana | 250 MB | monitoring |
| node_exporter | 30 MB | monitoring |
| blackbox_exporter | 30 MB | monitoring |
| cAdvisor | 200 MB | monitoring |
| **monitoring subtotal** | **1060 MB** | |

Doc 14's own figure (1.2-1.8 GB of 4 GB) predates this story's exporters,
cAdvisor and Grafana; 650 MB + 1060 MB = 1710 MB is the like-for-like update.
OS, Docker and sshd overhead (300-400 MB per doc 14) sits outside every
container's cgroup by construction.

**Per-container `mem_limit`s, committed in each `compose.yml`:**

- `edge`: Caddy `256m` (~2.5x the 100 MB worst case), CrowdSec `1024m`
  (~1.9x the combined 550 MB agent+AppSec+CRS worst case, headroom for
  rule-set growth during a real attack) -- 1280 MB committed.
- `monitoring`: `768+128+384+64+64+256 = 1664 MB` committed (Prometheus,
  Alertmanager, Grafana, node_exporter, blackbox_exporter, cAdvisor in that
  order).

1280 + 1664 = 2944 MB of 4096 MB committed across every container ceiling,
leaving 1152 MB (28%) for OS/Docker/sshd overhead and burst above any single
container's own limit -- comfortably above the 300-400 MB doc 14 estimates
needs there. The systemd drop-ins' `MemoryMax` (`1536M` edge, `2048M`
monitoring) are set above each stack's own container-limit total for the
same reason: whatever they do bound should never be the thing that trips
first.

**`cpu_shares` (containers) and `CPUWeight` (systemd units) are both
asymmetric, for the same reason.** Doc 14 §3.1 names what separating the
hosts would buy that collocation does not get for free: "an Alertmanager
that can still evaluate and dispatch" while the edge is CPU-saturated.
`edge`'s two containers total `1024` shares (Caddy `768`, CrowdSec `256` --
CrowdSec's bouncer is `appsec_fail_open`, so under pressure it is designed to
be the one that degrades, not Caddy's TLS termination and reverse-proxying).
`monitoring`'s six containers total `2048` shares (Prometheus `1024`,
Alertmanager `512`, Grafana `256`, node_exporter `128`, blackbox_exporter
`64`, cAdvisor `64` -- weighted so the evaluate-and-dispatch chain wins first
call on whatever CPU is available). `2048:1024` is the same `2:1` ratio the
systemd drop-ins' `CPUWeight=200`/`CPUWeight=100` express -- implemented
twice, once where the amendment's text points and once where it actually
takes effect, so that when the two stacks compete for a saturated CPU,
Prometheus keeps evaluating rules and Alertmanager keeps dispatching. That is
what lets the Watchdog heartbeat (§11 below) keep firing through an edge
incident rather than only after it.

**Verified locally** (not on `edge1` -- this workstation has no `10.20.1.10`
to bind, so only the container-creation half of each stack could be brought
up): `docker inspect --format '{{.HostConfig.Memory}} {{.HostConfig.CPUShares}}'`
against every container in both stacks read back exactly the bytes and
shares above. The host-side verification in step 10 below is the same check,
plus the one thing this workstation cannot show: that the containers are
*not* nested under either systemd unit's cgroup.

## Why every `rsync` here carries `--no-owner --no-group --chmod`

`-a` implies `-p`, `-o` and `-g`, and the last two take effect because the
receiving side is `root`. A plain `rsync -av` therefore reproduces the
*workstation's* file modes and uid/gid on the host -- and every container in
both stacks reads its config through a bind mount **as the container-side
user**, not as root.

That combination has already broken a deploy. `hetzner/monitoring/stack/prometheus/prometheus.yml`
is written by `npm run render` (a Vitest file snapshot), which left it `0600` in
one workstation checkout. Git records `100644` and cannot see the difference --
it tracks only the executable bit -- so the mode is invisible to review, to
`git status` and to CI, which checks out its own copy at `0644`. `rsync -av`
copied `0600 uid=501 gid=20` onto `edge1`, where uid 501 does not exist, and
Prometheus (running as `nobody`) crash-looped on

```
Error loading config (--config.file=/etc/prometheus/prometheus.yml) ... permission denied
```

`--no-owner --no-group` drops the meaningless workstation uid/gid, and
`--chmod=u=rwX,go=rX` sets modes on the receiving side rather than copying
them -- `0644` for files, `0755` for directories -- **regardless of what the
source happens to carry**. It also repairs a destination file that is already
wrong, which `--no-perms` does not: `--no-perms` leaves an existing file's mode
untouched, so it would not have fixed the host.

The `--chmod=u=rwX,go=rX` spelling is deliberate. The `--chmod=D755,F644` form
is rsync 3.0 syntax, and macOS still ships rsync 2.6.9, which rejects it with
`Invalid argument passed to --chmod`.

Nothing in either `stack/` directory is secret -- `alertmanager.yml.tmpl` holds
placeholders, and the real secrets live in `/etc/branchleft/monitoring.env` and
in the rendered `alertmanager.yml`, which is generated on the host and never
copied. See §7's note on that file's ownership.

## 1. Copy the updated edge stack (metrics endpoints + cgroup containment)

`hetzner/edge/render.ts` and `hetzner/edge/stack/compose.yml` already carry
this PR's edge-side changes: Caddy's own Prometheus metrics on `:9091`,
CrowdSec's built-in metrics moved off its default `127.0.0.1` via
`PROMETHEUS_LISTEN_ADDR=0.0.0.0` onto `:6060`, both published at
`10.20.1.10:<port>` only, and the `mem_limit`/`cpu_shares` from the section
above. Copy it, but **do not restart yet** -- step 6 restarts once, after the
cgroup drop-in below is also in place, so `edge` does not need reloading
twice.

```bash
rsync -av --delete --no-owner --no-group --chmod=u=rwX,go=rX \
  -e 'ssh -i ~/.ssh/id_ed25519_hetzner' \
  hetzner/edge/stack/ root@46.225.95.167:/opt/branchleft/edge/
```

## 2. Provision the Alertmanager submission credential

`mail/` needed one change for this story, and only one: the mailbox. Its
credential tooling is genuinely generic -- but
`provision_website_submission_credential.py` authenticates into an *existing*
account, and `provision_mailboxes.py`'s `MAILBOXES` is a hardcoded tuple with
no environment override, so `alerts@` had to be added there and provisioned on
mx1 before any of this works.
`mail/provision/provision_website_submission_credential.py` provisions one
submission-only SMTP credential per invocation, parameterised by
`SEND_AS_LOCAL`, `CREDENTIAL_LABEL` and `APP_PASSWORD_DESCRIPTION` (see
`mail/provision/61-provision-blog-submission-credential.sh` for the pattern
this follows). It authenticates into an *existing* mailbox restricted to send
as that address -- provision an `alerts` mailbox first via
`mail/provision/provision_mailboxes.py` if one does not already exist, per
`mail/RUNBOOK-mx1-provision.md`.

Both steps are `run-all.sh` entries, so a rebuilt host restores them without a
runbook: `50-provision-mailboxes.sh` creates the mailbox and its copy-forward
to `rob@`, and `64-provision-alerting-submission-credential.sh` provisions the
credential itself.

```bash
scp -i ~/.ssh/id_ed25519_hetzner -r mail/provision/. root@mx1.branchleft.co.uk:/root/mail-provision
ssh -i ~/.ssh/id_ed25519_hetzner root@mx1.branchleft.co.uk '
  chmod +x /root/mail-provision/*.sh /root/mail-provision/*.py &&
  /root/mail-provision/50-provision-mailboxes.sh &&
  /root/mail-provision/64-provision-alerting-submission-credential.sh'
```

The trailing `/.` is load-bearing -- without it a recursive copy nests the tree
inside the existing directory and the *old* scripts run, printing `no-op` and
looking like success. See `mail/RUNBOOK-mx1-provision.md`.

**`SMTP_USERNAME` is `alerts@branchleft.co.uk`, the full address**, not the
local part: Stalwart's `must_match_sender` rejects a submission whose
authenticated identity does not match the `From:`, and `monitoring/render.ts`
renders `smtp_from: 'alerts@branchleft.co.uk'`. `SMTP_PASSWORD` is the secret
the script records under the `alerting-submission` label -- see
`mail/RUNBOOK-mx1-provision.md`'s "Alerting submission credential".

`alerts@` copies inbound mail to `rob@` only, and carries no second redirect to
an address off mx1 -- one is the cap, and the reasoning is in
`mail/RUNBOOK-mx1-provision.md#mailbox-provisioning`. **This is not a mitigated
gap, it is an accepted one:** alert email is submitted *through* mx1, so when
mx1 is down no alert mail is sent at all, and no Sieve rule on that host could
have helped either. `ALERT_RECIPIENT_EMAIL` being off-mx1 covers a different
case -- mx1 up, the alerting mailbox unreachable or unread. The only thing that
reports an mx1-down or edge1-down condition is the Healthchecks.io dead-man's
switch in 11, which is why 12's second proof is not optional.

This step, the mailbox decision and the resulting credential are all
platform-owner-gated -- mx1 is live production mail.

## 3. Write the stack's secrets on the host

`/etc/branchleft/monitoring.env` is what `branchleft-compose@monitoring`
loads for stack secrets (`EnvironmentFile=-/etc/branchleft/%i.env` in the
shared unit template), and it is also what
`render_alertmanager_config.py` reads to produce `alertmanager.yml` -- see
that script's docstring for why Alertmanager's own config format cannot read
an environment variable itself, unlike Caddy's `{env.X}`.

| Variable | Used by | Where the value comes from |
|---|---|---|
| `SMTP_USERNAME` | Alertmanager (via the render script) | Step 2's submission credential |
| `SMTP_PASSWORD` | Alertmanager (via the render script) | Step 2's submission credential |
| `HEALTHCHECKS_PING_URL` | Alertmanager (via the render script) | The Healthchecks.io check's ping URL (PR's handover steps) |
| `ALERT_RECIPIENT_EMAIL` | Alertmanager (via the render script) | A mailbox someone actually reads -- not mx1, so the mx1-circularity dead-man's-switch reasoning (doc 14 §9.2) does not apply to routine alert delivery too |
| `GRAFANA_ADMIN_PASSWORD` | Grafana (native `GF_SECURITY_ADMIN_PASSWORD`) | Generated fresh, stored in the password manager |

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  test -f /etc/branchleft/monitoring.env && grep -c . /etc/branchleft/monitoring.env || echo "absent"'
```

`absent` means there is nothing to lose. Anything else: edit the file in
place rather than overwriting it.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  install -d -m 0755 -o root -g root /etc/branchleft &&
  umask 077 &&
  { printf "SMTP_USERNAME=%s\n" "<SUBMISSION_USERNAME>";
    printf "SMTP_PASSWORD=%s\n" "<SUBMISSION_PASSWORD>";
    printf "HEALTHCHECKS_PING_URL=%s\n" "<HEALTHCHECKS_PING_URL>";
    printf "ALERT_RECIPIENT_EMAIL=%s\n" "<ALERT_RECIPIENT_EMAIL>";
    printf "GRAFANA_ADMIN_PASSWORD=%s\n" "$(openssl rand -base64 24)"; } \
    > /etc/branchleft/monitoring.env &&
  chmod 0600 /etc/branchleft/monitoring.env &&
  ls -l /etc/branchleft/monitoring.env'
```

Expect `-rw------- 1 root root`. Do not print the file.

## 4. Copy the monitoring stack directory onto the host

```bash
rsync -av --delete --no-owner --no-group --chmod=u=rwX,go=rX \
  -e 'ssh -i ~/.ssh/id_ed25519_hetzner' \
  hetzner/monitoring/stack/ root@46.225.95.167:/opt/branchleft/monitoring/
```

`--delete` matters here specifically: `render_alertmanager_config.py` writes
`alertmanager/alertmanager.yml` on the host, which does not exist in the
committed tree, so every copy deletes the previous render. That is expected
-- step 7's `ExecStartPre` regenerates it before every start.

## 5. Install the systemd cgroup drop-ins

```bash
hetzner/provision/install-systemd-drop-ins.sh root@46.225.95.167
```

The script walks every committed `*/systemd/*.override.conf` under
`hetzner/` -- the same search `drop_in_for()` in
`test_compose_unit_contract.py` uses -- so it installs `edge.override.conf`
and `monitoring.override.conf` today, and any future drop-in with no script
change. It creates each unit's `.service.d` directory, copies the drop-in
in, and reloads systemd once at the end.

Neither drop-in takes effect until the affected unit next starts or
restarts -- step 6 does that for `edge`, and step 7's first-ever start does
it for `monitoring`.

## 6. Restart the edge stack

One restart picks up everything queued since step 1: the metrics endpoints,
the `mem_limit`/`cpu_shares` containment, and the systemd drop-in installed
in step 5.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'systemctl restart branchleft-compose@edge'
```

No new image and no `branchleft-deploy` invocation -- every change since the
digest currently running is Compose- or systemd-config-only. Do this before
step 8 below, or the `caddy` and `crowdsec` scrape targets read as `down`
for a reason unrelated to this stack.

## 7. Enable and start the monitoring unit

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  systemctl enable branchleft-compose@monitoring &&
  systemctl start branchleft-compose@monitoring'
```

`ExecStartPre` runs `render_alertmanager_config.py` before `docker compose
up`; a missing or blank secret in `/etc/branchleft/monitoring.env` fails the
unit start with the exact variable name, before any container starts.

`render_alertmanager_config.py` writes `alertmanager.yml` `0600` and chowns it
to uid 65534, the `nobody` the Alertmanager image runs as. The mode alone would
lock out the only process the file exists for -- a bind mount is read as the
container-side user however the file was written -- and widening the mode to
`0644` instead would expose an SMTP password to every other account on the
host. Ownership is the narrower of the two fixes.

**Step 5 is a hard precondition for this step, not just tidiness.** The shared
unit template loads `/etc/branchleft/%i.image.env` with no leading dash, so
systemd fails the start on a missing pin file before `ExecStartPre` runs at
all. This stack pins all six images inline and resolves no `${IMAGE}`, so
`branchleft-deploy` refuses to write that pin -- correctly, since nothing would
read it. `monitoring.override.conf` resets `EnvironmentFile=` for this instance
to close that gap. Starting the unit without the drop-in installed fails with:

```
branchleft-compose@monitoring.service: Failed to load environment files: No such file or directory
```

which names nothing. It has one cause: the drop-in is not installed. A missing
or blank `/etc/branchleft/monitoring.env` cannot produce it -- the drop-in
re-adds that file with a leading dash precisely so the failure comes from
`ExecStartPre` or from Compose, naming the variable.

## 8. Verify the stack is up

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  docker ps --filter label=com.docker.compose.project=monitoring'
```

Expect six containers, all `Up`: `prometheus`, `alertmanager`, `grafana`,
`node-exporter`, `blackbox-exporter`, `cadvisor`.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -L 9090:127.0.0.1:9090 root@46.225.95.167 -N &
curl -s http://127.0.0.1:9090/api/v1/targets | python3 -m json.tool | grep -E '"job"|"health"'
```

Expect `caddy`, `crowdsec`, `cadvisor`, `blackbox_http` (three targets, one
per `sites.ts` hostname) and the `node` target for `edge1` all `up`. `node`
for `app1`, `mysqld` for `db1` and `node` for `db1` are expected `down` --
those hosts have no exporter yet (see `render.ts`'s `MONITORED_NODE_HOSTS`
docstring). A `down` target with `expected_up: "true"` in its labels is the
only one worth investigating.

## 9. Verify Grafana is private-only

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://46.225.95.167:3000/  # from the workstation, over the public address
```

Expect a connection failure or timeout, never an HTTP response -- Compose
publishes Grafana on `10.20.1.10:3000` only, and `10.20.1.10` does not route
from the public internet.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -L 3000:10.20.1.10:3000 root@46.225.95.167 -N &
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/login
```

Expect `200`, reached only through the tunnel. Confirm the registry side too:

```bash
grep -R 'grafana\|10.20.1.10' sites.ts hetzner/edge/stack/Caddyfile
```

Expect no match in either file -- Grafana carries no hostname, no Caddy
route and no public listener anywhere in this repository.

## 10. Verify the cgroup containment reaches the containers

**The systemd unit properties, for completeness -- but this alone proves
nothing about the containers** (see "Colocation cgroup bounds" above):

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  systemctl show -p MemoryMax -p CPUWeight branchleft-compose@edge.service &&
  systemctl show -p MemoryMax -p CPUWeight branchleft-compose@monitoring.service'
```

Expect `MemoryMax=1610612736` (1536M) / `CPUWeight=100` for `edge`, and
`MemoryMax=2147483648` (2048M) / `CPUWeight=200` for `monitoring`. This
reports the unit's *configured* property whether or not any container
process actually sits in that cgroup, so a pass here is not evidence the
mitigation reached anything -- it only confirms the drop-in loaded.

**The real check -- per-container limits, read from each container's own
`HostConfig`:**

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  for c in $(docker ps --filter label=com.docker.compose.project=edge -q) \
           $(docker ps --filter label=com.docker.compose.project=monitoring -q); do
    docker inspect "$c" --format \
      "{{.Name}}: Memory={{.HostConfig.Memory}} CPUShares={{.HostConfig.CPUShares}}"
  done'
```

Expect (bytes): `caddy` `268435456`/`768`, `crowdsec` `1073741824`/`256`,
`prometheus` `805306368`/`1024`, `alertmanager` `134217728`/`512`, `grafana`
`402653184`/`256`, `node-exporter` `67108864`/`128`, `blackbox-exporter`
`67108864`/`64`, `cadvisor` `268435456`/`64`. A `0`/`0` on any container
means its `mem_limit`/`cpu_shares` did not make it into the compose file
that shipped, not that the systemd bound is compensating for it -- there is
no compensation.

**Confirm the containers are genuinely not nested under either systemd
unit's cgroup** (the reason the check above is necessary at all, not just
belt-and-braces):

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  CADDY_PID=$(docker inspect --format "{{.State.Pid}}" \
    $(docker ps --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=caddy -q)) &&
  cat /proc/$CADDY_PID/cgroup &&
  systemctl show -p ControlGroup branchleft-compose@edge.service'
```

Expect the container's cgroup path to read something like
`0::/system.slice/docker-<container-id>.scope` and the unit's `ControlGroup`
to read `/system.slice/branchleft-compose@edge.service` -- two different,
sibling paths under `system.slice`, not one nested inside the other. If a
future Docker/systemd upgrade changes this and the container's path *does*
start with the unit's path, the systemd-level bound has started doing real
work and this section is due a rewrite -- but do not assume that from a
version bump alone; re-run this check.

## 11. Verify the heartbeat is wired to the dead-man's switch

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -L 9093:127.0.0.1:9093 root@46.225.95.167 -N &
curl -s http://127.0.0.1:9093/api/v2/alerts | python3 -m json.tool | grep -A3 '"alertname": "Watchdog"'
```

Expect an active `Watchdog` alert with `status.state: "active"`. Then check
Alertmanager actually dispatched it to the heartbeat receiver rather than
only evaluating it:

```bash
curl -s http://127.0.0.1:9093/api/v2/status | python3 -m json.tool | grep -A2 lastNotificationTime
```

On the Healthchecks.io side: the check named in the PR's handover steps
should show "Last ping" within the last couple of minutes and never move to
"Late" or "Down" while the stack is healthy.

## 12. The proof standard

A `200`/`204` proves an HTTP endpoint answered, not that an alert reaches a
human or that a real silence is caught. This estate's standard, same as
`RUNBOOK-edge.md`'s detect-only verification, is a real delivery and a real
alarm:

1. **A real alert via mx1.** Trigger `HostDiskSpaceLow` or similar by hand
   (`amtool alert add alertname=ManualTest severity=critical --alertmanager.url=http://127.0.0.1:9093`
   over the tunnel from step 11) and confirm an email actually arrives at
   `ALERT_RECIPIENT_EMAIL`, not only that Alertmanager's API reports it
   dispatched.
2. **A real dead-man alarm.** Stop the monitoring stack
   (`systemctl stop branchleft-compose@monitoring`) and confirm Healthchecks.io
   moves the check to "Late" and then "Down" and sends its own alert --
   without that, the amendment's heartbeat requirement is unverified, not
   satisfied. Restart the stack afterwards
   (`systemctl start branchleft-compose@monitoring`) and confirm the check
   recovers.

Both are owner-executed, one-time, real-world proofs -- listed in the PR's
handover steps rather than performed by CI or by an agent.

## 13. Rolling back

Same shape as `RUNBOOK-edge.md` §12: restore the previous `stack/` from git,
re-copy, restart.

```bash
git checkout <PREVIOUS_MERGED_SHA> -- hetzner/monitoring/stack
rsync -av --delete --no-owner --no-group --chmod=u=rwX,go=rX \
  -e 'ssh -i ~/.ssh/id_ed25519_hetzner' \
  hetzner/monitoring/stack/ root@46.225.95.167:/opt/branchleft/monitoring/
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'systemctl restart branchleft-compose@monitoring'
```

Then `git checkout HEAD -- hetzner/monitoring/stack` on the workstation. If
the rollback also needs to undo an edge-side change (the metrics endpoints
or the cgroup containment), the same pattern applies to
`hetzner/edge/stack`, followed by `systemctl restart branchleft-compose@edge`.

## What this stack deliberately does not do

- **It does not scrape mx1.** mx1 is exclusively the SMTP path for alert
  delivery -- it is in a different hcloud project, off the private network
  entirely (doc 14 §3.4), and adding it as a scrape target here would be
  outside this repository's authority over that host in every sense.
- **It does not run on its own host.** Doc 14 §3.1's `mon1` split is gated on
  TENANT_1, not on this story; everything here is sized on the assumption
  that it shares `edge1`'s 4 GB with the edge stack.
- **It does not alert on `app1` or `db1` node metrics yet.** Both hosts carry
  `expected_up: "false"` in `render.ts` until their own exporters land in
  later stories -- see that file's `MONITORED_NODE_HOSTS` docstring.
- **It does not send application-level alerts** (contact-form failures,
  per-tenant p95 latency, shim queue drain time). Doc 14 §9.2 and §4 name
  these as later, separately-scoped additions; this story covers the host
  and platform-component layer only.
- **It does not rely on `--cgroup-parent`/`Delegate=yes` to nest containers
  under either systemd unit.** That would make the unit-level `MemoryMax`
  genuinely bound the containers, but it depends on the host's configured
  cgroup driver (systemd vs. cgroupfs) in a way this repository cannot see
  or test without SSH access to a live host, and a wrong `cgroup_parent`
  value fails container *creation* -- a materially worse outcome than the
  gap it would close. `mem_limit`/`cpu_shares` per container is the
  guaranteed-correct alternative and is what this stack actually ships.
