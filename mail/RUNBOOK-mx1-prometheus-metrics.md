# Runbook — enable Stalwart's Prometheus exporter on mx1

Delivers the `mx1` half of [branchLeft/shared-infra#42](https://github.com/branchLeft/shared-infra/issues/42),
which is the last unmet acceptance criterion of
[branchLeft/workspace#222](https://github.com/branchLeft/workspace/issues/222).

## What is wrong

Ghost's members magic-link endpoint is an unauthenticated trigger that makes the
platform send email. The edge now throttles it (proven on `edge1`, 2026-09-01),
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

Run this and **paste the secret at the prompt**; it is not echoed and does not
enter your shell history.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@167.233.252.240 \
  'read -rs -p "secret: " S; echo; printf "STALWART_PROMETHEUS_SECRET=%s\n" "$S" > /opt/stalwart/.env; chmod 600 /opt/stalwart/.env; unset S; ls -l /opt/stalwart/.env'
```

Expect `-rw------- 1 root root 6? … /opt/stalwart/.env`. The byte count should
be `len(secret) + 30`; for a 48-character secret, **78**.

**Check that number.** A `read -rs -p` that received nothing writes a file of
30 bytes and fails silently — the exact trap that cost a session on the Pulumi
passphrase (`session-close-2026-08-18`). 30 bytes here means re-run this step.

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

Expect `421`. Anything else means the new allow rules were ordered ahead of the
blanket deny and the admin interface is exposed — **treat as an incident and
roll back immediately.**

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

The exporter and the endpoint policy revert together, from the same reconciler:

```bash
cd ~/branchLeft/shared-infra && git revert --no-edit <merge commit of #129>
```

…then re-run steps 1, 3 and 4. Step 3 will fail on the missing variable if
`/opt/stalwart/.env` is still present and the reverted compose file no longer
declares it — that is harmless; remove `/opt/stalwart/.env` and re-run.

For an **immediate** stop without waiting on a revert, turn the exporter off in
place; the endpoint policy still refers to a path that then 404s, which is
inert:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@167.233.252.240 \
  'docker exec stalwart /bin/sh -c "true"'   # confirm the container is up first
```

then re-run step 4 from a checkout with `METRICS_TARGET["prometheus"]` set to
`{"@type": "Disabled"}`. There is no faster lever — Stalwart has no config file
to edit and no CLI flag for this.

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
