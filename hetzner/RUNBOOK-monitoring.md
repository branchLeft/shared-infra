# Runbook — the monitoring stack on `edge1`

Deploying Prometheus, Alertmanager, Grafana and their exporters onto `edge1`,
colocated with the edge stack until TENANT_1
(`ghost-platform-docs/14-hetzner-migration-programme.md` §3.1), and verifying
the three mitigations that ride with that collocation: cgroup bounds on both
compose units, Grafana bound to the private address only, and a heartbeat
wired to an external dead-man's switch.

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

## Colocation cgroup bounds -- the sizing arithmetic

The amendment accepted onto this story asks for `MemoryMax` and `CPUWeight`
bounds on the CrowdSec and Prometheus units so that neither can starve the
other. The two systemd instances involved are `branchleft-compose@edge` and
`branchleft-compose@monitoring` -- a Compose stack has no per-container
systemd unit of its own, so a bound "on the CrowdSec unit" is a bound on the
whole edge stack it runs in, and likewise for Prometheus and the monitoring
stack.

**Worst-case memory, per doc 14 §3.1's own arithmetic plus this story's
additions:**

| Component | Worst case | Unit |
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
OS, Docker and sshd overhead (300-400 MB per doc 14) sits outside both cgroups
-- `branchleft-compose@X.service`'s slice bounds only that unit's own
processes, not `docker.service` itself.

**Chosen ceilings:**

- `edge`: `MemoryMax=1536M` -- roughly 2.4x the 650 MB worst case, headroom
  for AppSec/CRS rule-set growth during an actual attack rather than a tight
  budget.
- `monitoring`: `MemoryMax=2048M` -- roughly 1.9x the 1060 MB worst case,
  headroom for Prometheus series growth as the estate scales before this
  number gets revisited at the TENANT_1 split.

1536 + 2048 = 3584 MB of 4096 MB, leaving 512 MB (12.5%) for everything
outside both slices -- comfortably above the 300-400 MB doc 14 estimates
needs there.

**`CPUWeight` is asymmetric on purpose.** Doc 14 §3.1 names what separating
the hosts would buy that collocation does not get for free: "an Alertmanager
that can still evaluate and dispatch" while the edge is CPU-saturated
(cgroup2 CPUWeight range is 1-10000; unprivileged default is 100). `edge` gets
the default, 100 -- it is the side most likely to be under attack, and boosting
it further would only take proportional CPU share away from the alerting
path under exactly the contention this bound exists for. `monitoring` gets
`CPUWeight=200`, double weight, so that when the two compete for a saturated
CPU, Prometheus keeps evaluating rules and Alertmanager keeps dispatching --
which is what lets the Watchdog heartbeat (below) keep firing through an edge
incident rather than only after it, and is what turns "the edge is flooded"
into a distinguishable alert instead of total silence.

Per-container `mem_limit`s inside `hetzner/monitoring/stack/compose.yml` give
the individual containers real containment within the monitoring unit's own
2048 MB ceiling (768+128+384+64+64+256 = 1664 MB committed, leaving headroom
within the slice); `hetzner/edge/stack/compose.yml` is deliberately left
without new per-container limits here -- the amendment's fix for that side is
the unit-level bound, and adding per-container limits there would be
unrelated churn in a file this story is only scoped to touch for the metrics
endpoints below.

## 1. Enable metrics endpoints on the edge stack (already in this PR)

`hetzner/edge/render.ts` and `hetzner/edge/stack/compose.yml` already carry
this change; nothing to do here except know it happened. Caddy now serves its
own Prometheus metrics on `:9091` inside its container, and CrowdSec's
built-in metrics endpoint (`PROMETHEUS_LISTEN_ADDR=0.0.0.0`, its own default
is `127.0.0.1`, invisible to any other container) is on `:6060`. Compose
publishes both at `10.20.1.10:<port>` -- edge1's private address, never the
public one -- so redeploying the edge stack is a precondition for this
stack's `caddy` and `crowdsec` scrape jobs to have anything to read.

Re-run `RUNBOOK-edge.md` step 4 (`rsync hetzner/edge/stack/` to
`/opt/branchleft/edge/`) to pick up the new `compose.yml`, then:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'systemctl restart branchleft-compose@edge'
```

No new image and no `branchleft-deploy` invocation -- this change is
Compose-only, the digest already running is unaffected. Do this before step 7
below, or the `caddy` and `crowdsec` scrape targets read as `down` for a
reason unrelated to this stack.

## 2. Provision the Alertmanager submission credential

`mail/` is read-only to this story -- its provisioning tooling is generic and
already supports a new credential without any code change.
`mail/provision/provision_website_submission_credential.py` provisions one
submission-only SMTP credential per invocation, parameterised by
`SEND_AS_LOCAL`, `CREDENTIAL_LABEL` and `APP_PASSWORD_DESCRIPTION` (see
`mail/provision/61-provision-blog-submission-credential.sh` for the pattern
this follows). It authenticates into an *existing* mailbox restricted to send
as that address -- provision an `alerts` mailbox first via
`mail/provision/provision_mailboxes.py` if one does not already exist, per
`mail/RUNBOOK-mx1-provision.md`.

This step, the mailbox decision and the resulting credential are all
Rob-gated -- see the PR's "Rob-gated steps" section for the exact command.

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
| `HEALTHCHECKS_PING_URL` | Alertmanager (via the render script) | The Healthchecks.io check's ping URL (PR's "Rob-gated steps") |
| `ALERT_RECIPIENT_EMAIL` | Alertmanager (via the render script) | A mailbox someone actually reads -- not mx1, so the mx1-circularity dead-man's-switch reasoning (doc 14 §9.2) does not apply to routine alert delivery too |
| `GRAFANA_ADMIN_PASSWORD` | Grafana (native `GF_SECURITY_ADMIN_PASSWORD`) | Generated fresh, stored in the password manager |

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'test -f /etc/branchleft/monitoring.env && grep -c . /etc/branchleft/monitoring.env || echo "absent"'
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

## 4. Copy the stack directory onto the host

```bash
rsync -av --delete -e 'ssh -i ~/.ssh/id_ed25519_hetzner' \
  hetzner/monitoring/stack/ root@46.225.95.167:/opt/branchleft/monitoring/
```

`--delete` matters here specifically: `render_alertmanager_config.py` writes
`alertmanager/alertmanager.yml` on the host, which does not exist in the
committed tree, so every copy deletes the previous render. That is expected
-- step 6's `ExecStartPre` regenerates it before every start.

## 5. Install the systemd cgroup drop-ins

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  install -d -m 0755 /etc/systemd/system/branchleft-compose@edge.service.d \
                      /etc/systemd/system/branchleft-compose@monitoring.service.d'

scp -i ~/.ssh/id_ed25519_hetzner \
  hetzner/monitoring/systemd/edge.override.conf \
  root@46.225.95.167:/etc/systemd/system/branchleft-compose@edge.service.d/override.conf

scp -i ~/.ssh/id_ed25519_hetzner \
  hetzner/monitoring/systemd/monitoring.override.conf \
  root@46.225.95.167:/etc/systemd/system/branchleft-compose@monitoring.service.d/override.conf

ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 'systemctl daemon-reload'
```

The edge drop-in takes effect on that unit's next restart -- part of step 1
above.

## 6. Enable and start the monitoring unit

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  systemctl enable branchleft-compose@monitoring &&
  systemctl start branchleft-compose@monitoring'
```

`ExecStartPre` runs `render_alertmanager_config.py` before `docker compose
up`; a missing or blank secret in `/etc/branchleft/monitoring.env` fails the
unit start with the exact variable name, before any container starts.

## 7. Verify the stack is up

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

## 8. Verify Grafana is private-only

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

## 9. Verify the colocation cgroup bounds

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  systemctl show -p MemoryMax -p CPUWeight branchleft-compose@edge.service &&
  systemctl show -p MemoryMax -p CPUWeight branchleft-compose@monitoring.service'
```

Expect `MemoryMax=1610612736` (1536M) / `CPUWeight=100` for `edge`, and
`MemoryMax=2147483648` (2048M) / `CPUWeight=200` for `monitoring`. Both
`[Service]` drop-ins take effect only after `daemon-reload` plus a restart of
the affected unit -- if either value reads `infinity`/`100` unexpectedly,
re-check `systemctl cat branchleft-compose@edge.service` for the drop-in
actually loading.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  systemctl status branchleft-compose@edge.service --no-pager | grep Memory &&
  systemctl status branchleft-compose@monitoring.service --no-pager | grep Memory'
```

Live usage should sit far below each ceiling -- these are circuit breakers
against a leak or an attack, not a tight budget.

## 10. Verify the heartbeat is wired to the dead-man's switch

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

On the Healthchecks.io side: the check named in the PR's "Rob-gated steps"
should show "Last ping" within the last couple of minutes and never move to
"Late" or "Down" while the stack is healthy.

## 11. The proof standard

A `200`/`204` proves an HTTP endpoint answered, not that an alert reaches a
human or that a real silence is caught. This estate's standard, same as
`RUNBOOK-edge.md`'s detect-only verification, is a real delivery and a real
alarm:

1. **A real alert via mx1.** Trigger `HostDiskSpaceLow` or similar by hand
   (`amtool alert add alertname=ManualTest severity=critical --alertmanager.url=http://127.0.0.1:9093`
   over the tunnel from step 10) and confirm an email actually arrives at
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
"Rob-gated steps" rather than performed by CI or by an agent.

## 12. Rolling back

Same shape as `RUNBOOK-edge.md` §12: restore the previous `stack/` from git,
re-copy, restart.

```bash
git checkout <PREVIOUS_MERGED_SHA> -- hetzner/monitoring/stack
rsync -av --delete -e 'ssh -i ~/.ssh/id_ed25519_hetzner' \
  hetzner/monitoring/stack/ root@46.225.95.167:/opt/branchleft/monitoring/
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'systemctl restart branchleft-compose@monitoring'
```

Then `git checkout HEAD -- hetzner/monitoring/stack` on the workstation.

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
