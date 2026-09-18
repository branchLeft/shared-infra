# Runbook — the nextcloud1 stack

Deploying plain Nextcloud (official images, no AIO) onto `nextcloud1`. Closes
branchLeft/workspace#1083's remaining "deploy plain Nextcloud" step.

## What has to be true first

`nextcloud1` is private-only, reached through the `edge1` jump host, the same
shape as `db1`. `RUNBOOK-provision-host.md` must have been run against it
first (base provisioning, then `app-host-isolation.sh`) — confirm:

```bash
EDGE1_IPV4=$(hcloud server describe edge1 -o json | python3 -c "import json, sys; print(json.load(sys.stdin)['public_net']['ipv4']['ip'])")
HOST_PRIVATE_IP=10.20.1.50
JUMP="ssh -i ~/.ssh/id_ed25519_hetzner -W %h:%p root@$EDGE1_IPV4"
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  systemctl is-active docker &&
  test -x /usr/local/sbin/branchleft-deploy &&
  systemctl is-enabled branchleft-docker-user-policy.service &&
  echo "provisioned"'
```

Expect `active`, then `enabled`, then `provisioned`.

`edge1`'s Caddy config must already route `book.branchleft.co.uk` to
`nextcloud1:11000` — `RUNBOOK-edge.md` §11, already done as of
branchLeft/shared-infra#215's deploy. Confirm with a curl from the
workstation, not through the jump — a `502` with an empty body here means
routing is correct and nothing is listening yet, which is the expected state
until this runbook's own step 5:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://book.branchleft.co.uk/
```

## 1. Write the stack's secrets on the host

`/etc/branchleft/nextcloud1.env` is what `branchleft-compose@nextcloud1`
loads (`EnvironmentFile=-/etc/branchleft/%i.env` in the shared unit
template) and what `stack/compose.yml` reads via `${VAR:?...}`.

| Variable                   | Used by        | Where the value comes from                                                                                                                                                               |
| -------------------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NEXTCLOUD_DB_PASSWORD`    | `app`, `db`    | Generated fresh — a new internal credential, not one the platform owner picks                                                                                                            |
| `NEXTCLOUD_REDIS_PASSWORD` | `app`, `redis` | Generated fresh, same reasoning                                                                                                                                                          |
| `NEXTCLOUD_ADMIN_PASSWORD` | `app`          | Generated fresh. Consumed by the entrypoint's install script only on a genuinely empty `/var/www/html` — changing it after first install has no effect on the account it already created |

All three generated the same way Grafana's admin password is in
`RUNBOOK-monitoring.md` §3 — nothing here is chosen or typed.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  test -f /etc/branchleft/nextcloud1.env && grep -c . /etc/branchleft/nextcloud1.env || echo "absent"'
```

`absent` means there is nothing to lose. Anything else: edit the file in
place rather than overwriting it.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  install -d -m 0755 -o root -g root /etc/branchleft &&
  umask 077 &&
  { printf "NEXTCLOUD_DB_PASSWORD=%s\n" "$(openssl rand -base64 24)";
    printf "NEXTCLOUD_REDIS_PASSWORD=%s\n" "$(openssl rand -base64 24)";
    printf "NEXTCLOUD_ADMIN_PASSWORD=%s\n" "$(openssl rand -base64 24)"; } \
    > /etc/branchleft/nextcloud1.env &&
  chmod 0600 /etc/branchleft/nextcloud1.env &&
  ls -l /etc/branchleft/nextcloud1.env'
```

Expect `-rw------- 1 root root`. Do not print the file. The admin password
needs to reach the password manager separately (`openssl rand` output is
never echoed to a terminal here) — read it back once, deliberately, after
step 6 confirms the stack is healthy:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" \
  'sed -n "s/^NEXTCLOUD_ADMIN_PASSWORD=//p" /etc/branchleft/nextcloud1.env'
```

## 2. Copy the stack directory onto the host

```bash
cd ~/branchLeft/shared-infra
rsync -av --delete --no-owner --no-group --chmod=u=rwX,go=rX \
  -e "ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand=\"$JUMP\"" \
  hetzner/nextcloud1/stack/ root@"$HOST_PRIVATE_IP":/opt/branchleft/nextcloud1/ &&
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" \
  'chown -R root:root /opt/branchleft/nextcloud1/'
```

## 3. Install the systemd instance override

`hetzner/nextcloud1/systemd/nextcloud1.override.conf` resets the mandatory
image-pin assert and file this stack doesn't use (all three images are
pinned inline) and switches `ExecStart` to `--force-recreate`, matching
`monitoring`'s pattern — see that file's own comments for the full
reasoning.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" \
  'install -d -m 0755 /etc/systemd/system/branchleft-compose@nextcloud1.service.d'
scp -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" \
  hetzner/nextcloud1/systemd/nextcloud1.override.conf \
  root@"$HOST_PRIVATE_IP":/etc/systemd/system/branchleft-compose@nextcloud1.service.d/override.conf
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" \
  'systemctl daemon-reload'
```

## 4. Enable the unit

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" \
  'systemctl enable branchleft-compose@nextcloud1'
```

## 5. Start the stack

First bring-up, so `start`, not `restart` — the unit is a `RemainAfterExit`
oneshot with no prior successful run to restart.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" \
  'systemctl start branchleft-compose@nextcloud1'
```

`--wait` in the unit's `ExecStart` blocks until all three services report
healthy or `TimeoutStartSec` (600s) is reached. A cold pull of three images
plus Postgres's own first-init can take a couple of minutes — this command
does not return instantly, and that is not a hang.

## 6. Verify the stack is up

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" \
  'systemctl is-active branchleft-compose@nextcloud1 &&
   docker compose -f /opt/branchleft/nextcloud1/compose.yml ps &&
   docker compose -f /opt/branchleft/nextcloud1/compose.yml exec -T app curl -fsS http://localhost/status.php'
```

Expect `active`, all three services `healthy` in the `ps` table, and the
`curl` printing a JSON blob with `"installed":true`. **This is also the
first live confirmation that curl exists in the `nextcloud:31-apache`
image** — `stack/compose.yml`'s healthcheck assumes it; if this command
itself fails with "curl: not found" rather than a connection or HTTP error,
the healthcheck needs a different probe and this runbook needs updating
before relying on `--wait` again.

Then, from the workstation, the same check this runbook opened with:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://book.branchleft.co.uk/
```

Expect `200`, not `502` — the whole chain (DNS, Caddy, this stack) is live.

## 7. What this runbook does not cover

Nextcloud's own first-run app configuration — enabling Calendar and Talk,
setting up the Appointments booking page, TURN/STUN for Talk — is a separate
piece of work through the admin web UI, not a provisioning step this runbook
scripts. Do it once step 6 above is green.

## 8. Closing the admin-panel warnings

A freshly-deployed instance surfaces four warnings on Settings → Administration
→ Overview: no maintenance window start time, a missing `filecache` DB index
(`fs_storage_path_prefix`), pending mimetype migrations, and no default phone
region. **None of the four is exposed as a `nextcloud:31-apache` image
environment variable** — confirmed against the image's own
`docker-entrypoint.sh` (the script that reads every environment-driven
config the image supports; it references no `maintenance_window_start`,
`default_phone_region` or `phone`/`maintenance window` anything) and a
GitHub code search across `nextcloud/docker` for both config keys, zero hits
either way. All four are one-off `occ` commands run by hand — nothing here
changes `stack/compose.yml`.

An interactive shell over a fresh SSH session has none of the env files
`branchleft-compose@nextcloud1` supplies at start (`/etc/branchleft/nextcloud1.env`,
loaded only via systemd's `EnvironmentFile=`), so a bare `docker compose
exec` here re-parses `stack/compose.yml` and refuses on the missing
`NEXTCLOUD_DB_PASSWORD` et al. before it reaches the container. Go straight
at the running container with `docker exec`, found by Compose's own labels
rather than by name — `compose.yml` pins no `container_name` — matching
`RUNBOOK-edge.md` §8's pattern. `$JUMP` and `$HOST_PRIVATE_IP` are set under
"What has to be true first" above; re-set them first if entering this
section independently.

**These four change live application config and are not covered by the
non-mutating-diagnostics grant in `AUTHORISATIONS.md`** (that grant is
explicitly "verifying a deploy, never performing one"), so each command
below is the platform owner's to run, not an agent's.

### 8.1 No maintenance window start time

`maintenance_window_start` takes an hour, 0–23, UTC — background jobs that
don't advertise themselves as time-sensitive are held to the 4-hour window
starting at that hour. `1` (01:00–05:00 UTC) is the low-usage choice here.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  APP_CTR=$(docker ps -q --filter label=com.docker.compose.project=nextcloud1 --filter label=com.docker.compose.service=app) &&
  docker exec "$APP_CTR" php occ config:system:set maintenance_window_start --type=integer --value=1'
```

Expect no output and exit status 0 — `config:system:set` is silent on
success.

### 8.2 Missing `filecache` index

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  APP_CTR=$(docker ps -q --filter label=com.docker.compose.project=nextcloud1 --filter label=com.docker.compose.service=app) &&
  docker exec "$APP_CTR" php occ db:add-missing-indices'
```

Expect a `Check indices of the <table> table.` line for each table it
inspects, and among them a line naming `fs_storage_path_prefix` on
`filecache` as being added (wording varies by version; the load-bearing part
is that `filecache` is named as changed, not merely checked). Exit status 0.

### 8.3 Pending mimetype migrations

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  APP_CTR=$(docker ps -q --filter label=com.docker.compose.project=nextcloud1 --filter label=com.docker.compose.service=app) &&
  docker exec "$APP_CTR" php occ maintenance:repair --include-expensive'
```

Expect a long list of `- OC\Repair\...` / repair-step lines (mimetype
migration among them) and exit status 0. This is the "expensive" repair
pass — it can take a while on a fresh instance even with no user data.

### 8.4 No default phone region

`GB` — an ISO 3166-1 alpha-2 code — so a phone number typed without a
leading `+44` still validates.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  APP_CTR=$(docker ps -q --filter label=com.docker.compose.project=nextcloud1 --filter label=com.docker.compose.service=app) &&
  docker exec "$APP_CTR" php occ config:system:set default_phone_region --value=GB'
```

Expect no output and exit status 0.

### 8.5 Verify

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  APP_CTR=$(docker ps -q --filter label=com.docker.compose.project=nextcloud1 --filter label=com.docker.compose.service=app) &&
  docker exec "$APP_CTR" php occ config:system:get maintenance_window_start &&
  docker exec "$APP_CTR" php occ config:system:get default_phone_region'
```

Expect `1` then `GB`. For 8.2 and 8.3, re-open Settings → Administration →
Overview in the admin web UI (no `occ` command surfaces the same aggregate
check) and confirm the DB-index and mimetype-migration warnings are gone;
the maintenance-window and phone-region warnings clear from the same page
and from 8.5's two values matching.

## Rolling back

**Configuration** — restore the previous `hetzner/nextcloud1/stack/` from git
and re-copy, same shape as `RUNBOOK-edge.md` §12:

```bash
git checkout <PREVIOUS_MERGED_SHA> -- hetzner/nextcloud1/stack
rsync -av --delete --no-owner --no-group --chmod=u=rwX,go=rX \
  -e "ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand=\"$JUMP\"" \
  hetzner/nextcloud1/stack/ root@"$HOST_PRIVATE_IP":/opt/branchleft/nextcloud1/ &&
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" \
  'chown -R root:root /opt/branchleft/nextcloud1/ &&
   systemctl restart branchleft-compose@nextcloud1'
```

`--force-recreate` on this instance's `ExecStart` means a plain
`systemctl restart` is enough here — unlike `edge`, there is no selective
Compose recreate to work around. Then `git checkout HEAD -- hetzner/nextcloud1/stack`
on the workstation, so the checkout stops describing a state the repository
does not hold.

**Data** — `nextcloud-app` and `nextcloud-db` are named Docker volumes, not
removed by any command above. A rollback that needs to discard them entirely
is a decision, not a mechanical step; it is not scripted here.
