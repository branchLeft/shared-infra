# Runbook — enable Stalwart's Prometheus exporter on mx1

Delivers the `mx1` half of [branchLeft/shared-infra#42](https://github.com/branchLeft/shared-infra/issues/42),
which is the last unmet acceptance criterion of
[branchLeft/workspace#222](https://github.com/branchLeft/workspace/issues/222).

## What is wrong

Ghost's members magic-link endpoint is an unauthenticated trigger that makes the
platform send email. The edge now throttles it on a hostname-routed path,
but doc 12 §1 is explicit that a flood which stays under the rate limit, or
arrives from rotating sources, moves **reputation** rather than request rate.
Reputation is bounce and rejection behaviour, and none of it currently reaches
the monitoring stack: `mx1` is scraped by nothing, and its only monitoring is
four blackbox liveness probes that stay green through a deliverability
collapse.

Stalwart does export the counters — `delivery.double-bounce`,
`delivery.dsn-perm-fail`, `delivery.rcpt-to-rejected`, `queue.count` and the
rest — on a Prometheus endpoint that is simply switched off.

## Blast radius

- **Changes:** Stalwart's `Metrics` singleton (exporter on, with credentials),
  and its `Http` endpoint policy, which gains two allow rules ahead of the
  existing blanket 421.
- **Restarts `stalwart` twice** — once by `docker compose up -d` picking up the
  new environment variable, once by the reconciler applying settings. **Mail is
  down for the duration of each restart**, seconds rather than minutes. Inbound
  senders retry; this is not a silent loss, but do not run it during a send.
- **Does not change:** listeners, ports, ACME, DKIM, mailboxes, the firewall,
  the shim. No Pulumi runs. `mail/firewall.ts` already opens 443 and is
  untouched.
- **Widens what 443 serves**, from nothing-but-ACME to one additional path.
  That path is pinned to `edge1`'s two addresses _and_ requires basic auth;
  neither alone is the control.
- **Reversible.** See "Rollback".

## Before you start

1. **[branchLeft/shared-infra#129](https://github.com/branchLeft/shared-infra/pull/129) is merged**, and `main` is pulled locally. Without it the compose
   file has no `STALWART_PROMETHEUS_SECRET` and the reconciler has no
   `x:Metrics` step, so nothing here applies.
2. **You have a generated secret.** Generate it now, on your Mac, and paste it
   into ProtonPass as `mx1 Stalwart Prometheus exporter` before going further —
   it is written to two hosts and read back from neither:

   ```bash
   LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 48; echo
   ```

   Alphanumeric only, deliberately: this value goes into a shell-sourced `.env`
   on `mx1` and a `KEY=value` env file on `edge1`, and a `$` or a quote in
   either is a silent truncation rather than an error.

3. `~/.ssh/id_ed25519_hetzner` present. Every `ssh`/`rsync` below needs `-i`
   with it.

Throughout: **never paste the secret into an issue, a PR, a commit or a chat
message.** It reaches its two files by the commands below and nowhere else.

---

## Step 1 — stage the updated provisioning scripts on mx1

```bash
cd ~/branchLeft/shared-infra && git checkout main && git pull --ff-only
rsync -av -e "ssh -i ~/.ssh/id_ed25519_hetzner" \
  mail/provision/ root@167.233.252.240:/root/mail-provision/
```

Expect a file list including `configure_stalwart.py` and `docker-compose.yml`,
and a `sent … bytes` summary. Staging only — nothing has changed on the running
server yet.

## Step 2 — write the secret into the compose environment file

**If `/opt/stalwart/.env` already exists, skip to step 3 and take the secret
from it** — `30-deploy-stalwart.sh` mints one on a rebuilt host and never
overwrites an existing file, so writing over it here would break a scrape that
is already working:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@167.233.252.240 \
  'test -f /opt/stalwart/.env && echo EXISTS || echo ABSENT'
```

Otherwise run this and **paste the secret at the prompt**; it is not echoed and
does not enter your shell history.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@167.233.252.240 \
  'read -rs -p "secret: " S; echo; printf "STALWART_PROMETHEUS_SECRET=%s\n" "$S" > /opt/stalwart/.env; chmod 600 /opt/stalwart/.env; unset S; ls -l /opt/stalwart/.env'
```

Expect `-rw------- 1 root root 6? … /opt/stalwart/.env`. The byte count should
be `len(secret) + 30`; for a 48-character secret, **78**.

**Check that number.** A `read -rs -p` that received nothing writes a file of
30 bytes and fails silently rather than erroring — the same shape that has
already cost a passphrase write elsewhere in this estate. 30 bytes here means
re-run this step.

## Step 3 — recreate the container so it carries the variable

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@167.233.252.240 \
  'bash /root/mail-provision/30-deploy-stalwart.sh'
```

Expect `30-deploy-stalwart: updated /opt/stalwart/docker-compose.yml`, compose
recreating the container, then `30-deploy-stalwart: stalwart is healthy`.

If it fails with `STALWART_PROMETHEUS_SECRET: set in .env beside this compose
file`, step 2 did not write the file where compose reads it. That is the
fail-closed path working — fix step 2 rather than working around it.

Confirm the variable actually reached the process:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@167.233.252.240 \
  'docker inspect stalwart --format "{{range .Config.Env}}{{println .}}{{end}}" | cut -d= -f1 | grep STALWART'
```

Expect `STALWART_HOSTNAME` and `STALWART_PROMETHEUS_SECRET`. **Names only** —
`cut` drops the values deliberately.

## Step 4 — apply the settings

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@167.233.252.240 \
  'bash /root/mail-provision/40-configure-stalwart.sh'
```

Expect, among the other reconcilers' no-ops:

```
configure_stalwart: enabled the authenticated Prometheus metrics exporter
configure_stalwart: set the HTTP access-control rule (webadmin off 443, metrics path open to edge1 only)
configure_stalwart: restarted stalwart to apply changes
```

A second run of this script must print `no-op` for both lines. If it does not,
the reconciler is fighting the live state — stop and report rather than
re-running.

---

## Verify

Three checks. **All three are required**: the first two each pass identically
under failures the third one catches.

**V1 — the endpoint answers `edge1`, authenticated.** Run from `edge1`, reading
the credential from the file rather than the command line:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'S=$(sed -n "s/^STALWART_PROMETHEUS_SECRET=//p" /etc/branchleft/monitoring.env); \
   curl -sS -o /tmp/m.txt -w "%{http_code}\n" -u "prometheus:$S" \
     https://mx1.branchleft.co.uk/metrics/prometheus; \
   grep -c "^delivery_\|^queue_" /tmp/m.txt; rm -f /tmp/m.txt'
```

Expect `200`, then a count **greater than 0**. A `200` with a count of `0`
means the exporter is on but exporting nothing named as expected — report the
metric names actually present rather than assuming.

This step needs **Step 5** below to have run first.

**V2 — the webadmin is still refused on 443.** From your Mac:

```bash
curl -sk -o /dev/null -w "%{http_code}\n" https://mx1.branchleft.co.uk/
```

Expect `421`.

Anything else means the endpoint policy is not what this repo says it is —
`x:Http/set` applied something other than `HTTP_ENDPOINT_POLICY`, or an
operator has since edited the rule in the admin UI. It is **not** an ordering
mistake: the allow rules match one exact path, so no ordering of them can let
`/` through. Read the live rule before doing anything else:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@167.233.252.240 \
  'curl -sS -u "$(cut -d: -f1 /root/.stalwart-admin-credentials):$(cut -d: -f2 /root/.stalwart-admin-credentials)" \
     -H "Content-Type: application/json" \
     -d "{\"using\":[\"urn:ietf:params:jmap:core\"],\"methodCalls\":[[\"x:Http/get\",{\"ids\":[\"singleton\"]},\"0\"]]}" \
     http://127.0.0.1:8080/jmap'
```

**Treat a non-421 as an incident** — the admin interface is reachable on a
public listener — and roll back before diagnosing further.

**V3 — the metrics path is refused from anywhere that is not `edge1`.** From
your Mac, with the real credential:

```bash
curl -sk -o /dev/null -w "%{http_code}\n" \
  -u "prometheus:PASTE_THE_SECRET" https://mx1.branchleft.co.uk/metrics/prometheus
```

Expect `421`. **A `200` here is the finding that matters**: it means the source
pin is inert and the endpoint is internet-reachable behind one password. V1 and
V2 both pass in that state, which is why this check exists.

(This is the one command that puts the secret on a command line. It is on your
own machine, and it is worth it: nothing else distinguishes "pinned to edge1"
from "open to the world with a password". Clear it afterwards with
`history -d` or run it prefixed by a space.)

## Step 5 — write the credential on edge1

V1 depends on this, so run it before V1. Same prompt-based pattern:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'read -rs -p "secret: " S; echo; printf "STALWART_PROMETHEUS_SECRET=%s\n" "$S" >> /etc/branchleft/monitoring.env; unset S; grep -c "^STALWART_PROMETHEUS_SECRET=" /etc/branchleft/monitoring.env'
```

Expect `1`. **A `2` means the line was appended twice** — the last one wins for
most parsers, but two copies drift the moment one is rotated. Remove the
duplicate before continuing.

Note this **appends** to an existing file that already holds other credentials
and a personal email address. Do not rewrite the file.

## Rollback

**A plain `git revert` does not undo this, and that is the trap worth stating
first.** Stalwart's settings live in its database, not in a file this repo
owns. Reverting deletes `_reconcile_metrics` from the script — so nothing is
left that would ever turn the exporter _off_, and it stays `Enabled` on the
running server indefinitely. The revert closes the endpoint policy but leaves
the exporter running behind it.

To actually roll back, **disable through the reconciler first, then revert**:

1. On your Mac, in a checkout of the merge commit (not a revert of it), set
   `METRICS_TARGET["prometheus"]` to `{"@type": "Disabled"}` and delete
   `METRICS_PATH` from `METRICS_SCRAPE_SOURCES`' allow rules by setting
   `METRICS_SCRAPE_SOURCES = ()`.
2. Re-run steps 1 and 4 of this runbook. Expect `enabled the authenticated
Prometheus metrics exporter` to be replaced by an update, and the
   access-control line to reapply with the blanket 421 alone.
3. Verify with V2 (`421` for `/`) and V3 (`421` for the metrics path, now
   because it is disabled rather than pinned).
4. Only then `git revert` the merge commit, so the repo and the server agree.

`/opt/stalwart/.env` can be left in place — `30-deploy-stalwart.sh` never
overwrites an existing one, and a secret for a disabled exporter is inert.

There is no faster lever. Stalwart has no config file to edit and no CLI flag
for this; the API is the only interface, and the reconciler is how this
platform drives it.

## After it succeeds

Comment on [branchLeft/shared-infra#42](https://github.com/branchLeft/shared-infra/issues/42)
citing V1's status code and metric count, V2's `421`, and V3's `421` — **never
the secret**. Leave the issue **open**: the scrape target and the alert rules
are a separate PR, and the issue is not done until an alert exists that can
fire.

Then `branchLeft/workspace#222` criterion 3 is unblocked but not met; it is met
when that second PR is merged and deployed.

## What this deliberately does not do

- **No alert rule.** A rule against a metric nobody has scraped yet never
  evaluates and reads as covered — the reasoning already recorded on #42.
- **No complaint-rate signal.** Feedback loops are reported out of band by
  receiving providers; no self-hosted MTA produces them. `#222`'s criterion 3
  asks for something Stalwart cannot give, and the honest substitute is a
  rejection/DSN **ratio**, decided when the rules are written.
- **No firewall change.** 443 was already open.
