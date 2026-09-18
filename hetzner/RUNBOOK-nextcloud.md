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

`edge1`'s Caddy config must already route `cloud.branchleft.co.uk` to
`nextcloud1:11000` — `RUNBOOK-edge.md` §11, already done as of
branchLeft/shared-infra#215's deploy. Confirm with a curl from the
workstation, not through the jump — a `502` with an empty body here means
routing is correct and nothing is listening yet, which is the expected state
until this runbook's own step 5:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://cloud.branchleft.co.uk/
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
  'systemctl is-active branchleft-compose@nextcloud1'
```

Expect `active`. That alone is real evidence, not a formality: `ExecStart`
is `docker compose up -d --wait`, and `--wait` only reports success once
every service with a `healthcheck:` is actually healthy — an active unit
means the deploy already succeeded, sourced through `EnvironmentFile=` the
way `systemd` does it.

**Do not follow this with `docker compose -f .../compose.yml ps` or
`exec` over a fresh SSH session.** Found live on the first real deploy: an
ad-hoc `docker compose` invocation re-parses and re-interpolates the whole
Compose file itself, and a plain interactive shell over SSH carries none of
the `EnvironmentFile=` variables systemd sourced for `ExecStart` — every
`${VAR:?...}` in `stack/compose.yml` fails with "required variable ... is
missing a value", which reads exactly like a broken deploy when the unit
is in fact already healthy. Use plain `docker` with label filters instead,
which never re-reads the Compose file at all — the same pattern
`RUNBOOK-edge.md`'s throttle-derivation section already uses for the same
reason:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  docker ps --filter label=com.docker.compose.project=nextcloud1 --format "{{.Names}}\t{{.Status}}"
  docker exec $(docker ps -q --filter label=com.docker.compose.project=nextcloud1 --filter label=com.docker.compose.service=app) curl -fsS http://localhost/status.php
'
```

Expect three containers `Up ... (healthy)`, and the `curl` printing a JSON
blob with `"installed":true`. **This is also the first live confirmation
that curl exists in the `nextcloud:31-apache` image** — `stack/compose.yml`'s
healthcheck assumes it; if this command itself fails with "curl: not found"
rather than a connection or HTTP error, the healthcheck needs a different
probe and this runbook needs updating before relying on `--wait` again.

Then, from the workstation, the same check this runbook opened with:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://cloud.branchleft.co.uk/
```

Expect `302`, not `502` — a healthy, unauthenticated `/` redirects to
`/login`, observed live on this instance's first deploy. `curl -sI ... |
grep -i ^location` confirms the target is `https://cloud.branchleft.co.uk/login`;
anything else is worth a closer look. `302` here means the whole chain
(DNS, Caddy, this stack) is live, not that anything is wrong.

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

## 9. Upgrading to a new major version

`stack/compose.yml` pins `nextcloud:32-apache` by tag-plus-digest, same as
every other image here. Bumping that pin and redeploying is **not** the
same action as the redeploys above: it moves the on-disk schema forward,
and Nextcloud's own docs are explicit that the move cannot be undone by
re-pinning the old tag (9.6 below). Everything in this section is the
platform owner's to run, for the same reason section 8's warning-closing
commands are — no grant in `AUTHORISATIONS.md` covers a mutating change to
this stack's data, and this one is irreversible in a way those aren't.

### 9.1 What the image actually does on a version bump

Confirmed against `nextcloud/docker`'s own `docker-entrypoint.sh` (the file
is at the repository root and shared, unmodified, by every version
directory including `32/apache` — not a per-version copy), pulled live
rather than assumed:

The entrypoint compares two version numbers on every container start —
`installed_version`, read from `/var/www/html/version.php` on the
persistent `nextcloud-app` volume, against `image_version`, read from
`/usr/src/nextcloud/version.php` baked into the image. If the image is
newer, it **runs the upgrade itself, with no separate trigger**: it
`rsync`s the new release's files over `/var/www/html` (excluding `config`,
`data`, `custom_apps`, `themes` per `upgrade.exclude`, but `version.php`
itself is synced unconditionally), then runs `php occ upgrade` as the
`www-data` user. There is no `NEXTCLOUD_UPDATE` or similar opt-out for this
stack's case — the check runs whenever the container's first argument is
`apache2*` (which is how the `app` service's default `CMD` starts), so
simply redeploying with the new tag is the trigger.

Two guards, both fail-closed:

- **Downgrade refusal.** If `installed_version` is ever higher than
  `image_version`, the entrypoint prints "Can't start Nextcloud because the
  version of the data... is higher than the docker image version... and
  downgrading is not supported" and `exit 1` — the container never reaches
  `exec apache2`. This is the same rule Nextcloud's admin manual states for
  `occ upgrade` itself: reverting to an older Nextcloud version is not
  supported once the newer one has touched the data (9.6).
- **One major version at a time.** If the image's major version is more
  than one ahead of the installed one, the entrypoint refuses to start
  rather than attempt a multi-version jump. 31 → 32 is exactly one major
  version, so this stack clears that guard directly — no intermediate hop
  needed.

What the entrypoint does **not** do: it does not take any backup of its
own, and it does not explicitly toggle maintenance mode before calling
`occ upgrade` — that is `occ upgrade`'s own job internally (Nextcloud's
manual-upgrade troubleshooting page gives `occ maintenance:mode --off` as
the recovery command for an upgrade stuck mid-run, which only makes sense
if `occ upgrade` itself is what turns maintenance mode on).

**The real risk if `occ upgrade` fails partway**, worth naming precisely
because it is not obvious from the script's shape: the `rsync` that copies
`version.php` onto the volume runs _before_ `occ upgrade` is invoked, so
the on-disk `installed_version` already reads as the new version the
moment the file copy finishes — regardless of whether the database
migration that follows succeeds. The script carries `set -eu`, so a
failing `occ upgrade` does kill the entrypoint and the container exits
without ever starting Apache (the half-migrated instance is never exposed
to traffic). But because `installed_version` was already bumped, a
subsequent restart — including the `--force-recreate` this unit already
does on every `systemctl restart` — sees `installed_version ==
image_version` and **skips the upgrade branch entirely** on the next
attempt, rather than retrying `occ upgrade`. A crash mid-upgrade does not
self-heal on restart; it needs the manual step in 9.6.

### 9.2 Precondition: there is no backup mechanism for this stack

Checked, not assumed: nothing under `hetzner/` schedules a Postgres dump,
a volume snapshot, or any `restic`/`borg`-style job for `nextcloud1` or for
`db1`'s own data. `nextcloud-db` and `nextcloud-app` are ordinary unmanaged
Docker volumes with no export configured anywhere in this repo. This is a
real gap, not a formality being skipped here — flagged as such rather than
worked around, since building an actual backup pipeline is its own piece
of work, not part of this change.

Until that pipeline exists, take a manual snapshot immediately before
starting 9.3, kept off this host:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  DB_CTR=$(docker ps -q --filter label=com.docker.compose.project=nextcloud1 --filter label=com.docker.compose.service=db) &&
  docker exec "$DB_CTR" pg_dump -U nextcloud nextcloud | gzip > /root/nextcloud1-pre-upgrade-db.sql.gz &&
  docker run --rm -v nextcloud1_nextcloud-app:/volume -v /root:/backup alpine \
    tar czf /backup/nextcloud1-pre-upgrade-app.tar.gz -C /volume .'
scp -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" \
  root@"$HOST_PRIVATE_IP":/root/nextcloud1-pre-upgrade-db.sql.gz \
  root@"$HOST_PRIVATE_IP":/root/nextcloud1-pre-upgrade-app.tar.gz \
  ./
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" \
  'rm -f /root/nextcloud1-pre-upgrade-db.sql.gz /root/nextcloud1-pre-upgrade-app.tar.gz'
```

Confirm both files landed on the workstation and are non-empty before
proceeding — a backup nobody checked is not a backup. Move them somewhere
durable off the workstation too (the password manager's attached-file
storage, or wherever `RUNBOOK-monitoring.md`'s own backups land); this
runbook does not pick that location for you.

**A non-empty file is not evidence it is restorable.** `gzip`/`tar` exiting
0 over a truncated stream, or a dump that fails partway through a table,
both still leave a non-empty file — the only check above that stopped at
"non-empty" would pass either. Prove each backup actually restores, once,
on a throwaway target, before relying on it as this section's precondition
for 9.3:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  gunzip -t /root/nextcloud1-pre-upgrade-db.sql.gz &&
  docker run --rm -d --name nc1-restore-drill \
    -e POSTGRES_PASSWORD=drill -e POSTGRES_DB=nextcloud -e POSTGRES_USER=nextcloud \
    postgres:16-alpine &&
  sleep 5 &&
  gunzip -c /root/nextcloud1-pre-upgrade-db.sql.gz \
    | docker exec -i nc1-restore-drill psql -U nextcloud -d nextcloud -v ON_ERROR_STOP=1 &&
  docker exec nc1-restore-drill psql -U nextcloud -d nextcloud -tAc "select count(*) from oc_users;" &&
  docker stop nc1-restore-drill'
```

Expect the `psql` load to complete with no `ERROR:` output (`ON_ERROR_STOP=1`
aborts on the first one rather than silently skipping it) and the row
count to come back as a plausible non-zero number matching this instance's
real user count, not `0` or a connection failure. Give the structural
equivalent to the volume tarball — a plain byte count proves nothing about
whether the paths inside are the ones a restore would need:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" \
  'tar tzf /root/nextcloud1-pre-upgrade-app.tar.gz | grep -E "^(config/config\.php|data/)$"'
```

Expect both lines. Only once both checks are clean does either backup
count as verified rather than merely produced — proceed to 9.3 from there.

### 9.3 Redeploy with the new pin

Same `rsync` + `chown` + restart shape as every other redeploy in this
file — this instance's `ExecStart` already carries `--force-recreate`
(§3), so a plain `systemctl restart` is sufficient, exactly as the
Rolling-back section below relies on:

```bash
cd ~/branchLeft/shared-infra
rsync -av --delete --no-owner --no-group --chmod=u=rwX,go=rX \
  -e "ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand=\"$JUMP\"" \
  hetzner/nextcloud1/stack/ root@"$HOST_PRIVATE_IP":/opt/branchleft/nextcloud1/ &&
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" \
  'chown -R root:root /opt/branchleft/nextcloud1/ &&
   systemctl restart branchleft-compose@nextcloud1'
```

### 9.4 What to watch for during the upgrade

`systemctl restart` blocks on `--wait` until every service reports
healthy or `TimeoutStartSec` (600s) is hit, same as first bring-up (§5) —
but this run does more work than a routine restart: a cold pull of the
`32-apache` image plus 9.1's `rsync`-then-`occ upgrade` inside it,
which the Nextcloud admin manual describes as taking "a few minutes to a
few hours" depending on install size. Do not treat a restart command that
takes several minutes as a hang.

**A non-`active` unit here is very plausibly a false failure signal, not
proof the upgrade broke — confirmed against `docker/compose`'s own source,
not assumed.** `exec "$@"` (the line that starts Apache) is the _last_
line of the entrypoint, after the whole upgrade block — per 9.1, nothing
answers `app`'s healthcheck (`curl localhost/status.php`) until `occ
upgrade` has already finished. `--wait` polls exactly that healthcheck,
and `pkg/compose/service_containers.go`'s `isServiceHealthy` treats a
container reporting `unhealthy` as an immediate, non-retryable error
(`case container.Unhealthy: return false, fmt.Errorf(...)`) — it does not
keep waiting through it the way it keeps waiting through `starting`.
Working the healthcheck's own numbers (`start_period: 60s`,
`interval: 30s`, `retries: 5`): the container is judged `unhealthy`, and
`--wait` fails, at roughly the 3.5-minute mark (60 + 5×30 = 210s) —
regardless of whether `occ upgrade` is proceeding correctly in the
background. Nextcloud's own docs put a real upgrade's duration at "a few
minutes to a few hours," so there is no reason to expect this instance
clears Apache's restart before that 3.5-minute window closes. **Treat a
failed or non-`active` `systemctl restart` here as unknown, not as
failed, and go to 9.6's first check before doing anything else —
including before re-running 9.3.**

`https://cloud.branchleft.co.uk/` will serve Nextcloud's own maintenance
page (occ upgrade puts the instance into maintenance mode for the
migration's duration) rather than the usual `302` to `/login` for as long
as the upgrade is running — that response, not a `502` or a connection
failure, is the expected shape of the downtime window here. An `active`
unit plus 9.5 below is the proof the upgrade actually finished; a
non-`active` unit is not, by itself, proof it didn't.

### 9.5 Verify the upgrade completed

Same label-filter pattern as §6 and §8 — never a fresh-session `docker
compose exec`, for the reason §6 already gives (no `EnvironmentFile=`
variables on an interactive shell):

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
  docker ps --filter label=com.docker.compose.project=nextcloud1 --format "{{.Names}}\t{{.Status}}"
  APP_CTR=$(docker ps -q --filter label=com.docker.compose.project=nextcloud1 --filter label=com.docker.compose.service=app) &&
  docker exec "$APP_CTR" php occ status'
```

Expect `installed: true`, `maintenance: false` (confirming the upgrade's
own maintenance-mode window closed cleanly rather than getting stuck —
9.6 covers the case where it doesn't), and `versionstring: 32.0.x`
matching whatever the pinned digest resolved to at PR time (the admin
panel named `32.0.15` as current when this pin was written). Then, from
the workstation, the same check §6 closed with:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://cloud.branchleft.co.uk/
```

Expect `302` to `/login` again, not the maintenance page.

### 9.6 If it fails partway

**Re-pinning `compose.yml` back to `nextcloud:31-apache` and redeploying
is not a working rollback once `occ upgrade` has touched the database** —
confirmed against Nextcloud's own admin manual, not assumed: "Downgrading
is not supported and risks corrupting your data! If you want to revert to
an older Nextcloud version, make a new, fresh installation and then
restore your data from backup." 9.1's downgrade guard makes this concrete
here too: the `31-apache` entrypoint would see `installed_version` (32.x,
already written by the interrupted run's `rsync`) higher than its own
`image_version` and refuse to start at all.

If the restart in 9.3 fails or the unit never reaches `active`:

0. **Find out what is actually true before touching the container again —
   9.4's false-failure window means a reported restart failure is not
   itself evidence of a real one.** Check ground truth, not the restart
   command's own exit status:

   ```bash
   ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@"$HOST_PRIVATE_IP" '
     docker ps -a --filter label=com.docker.compose.project=nextcloud1 --format "{{.Names}}\t{{.Status}}"
     APP_CTR=$(docker ps -aq --filter label=com.docker.compose.project=nextcloud1 --filter label=com.docker.compose.service=app) &&
     docker logs --tail 80 "$APP_CTR"'
   ```

   - If `docker ps` still lists the `app` container as `Up ...`
     (`(unhealthy)` or `(health: starting)` both count as `Up`), it has
     not exited — the entrypoint script may still genuinely be running
     `occ upgrade` in the background. `docker logs` will show the
     entrypoint's own progress lines (`Upgrading nextcloud from...`,
     ongoing repair-step output) if so, and its own completion marker
     (`Initializing finished`, printed once, right before Apache starts)
     if the migration side is actually done and only the healthcheck
     grace window is what tripped. **In either of these cases, wait and
     re-check — do not re-run 9.3.** Re-running it force-recreates this
     same container and kills whatever is still running mid-transaction,
     which is precisely 9.1's undetected half-upgrade scenario.
   - Only if `docker ps -a` shows the container as `Exited` (the
     entrypoint's own `set -eu` killed it — a genuine `occ upgrade`
     failure, not a healthcheck timing artefact) does step 1 below apply.

1. With a genuinely exited container confirmed by step 0: check whether
   the instance is stuck in maintenance mode rather than fully broken —
   `occ status` (9.5) showing `maintenance: true` with the container
   otherwise running is the documented stuck-upgrade shape, and the
   documented recovery is re-running the migration by hand:
   `docker exec "$APP_CTR" php occ upgrade`, using the same label-filter
   pattern as 9.5. Nextcloud's docs do not commit to `occ upgrade` being
   fully resumable after every kind of interruption, only that this is the
   published remediation for a stuck-but-otherwise-intact instance.
2. If that does not bring the instance back — or the failure looks like
   data corruption rather than a stuck migration — the only recovery path
   the docs name is 9.2's backup: a fresh install at the old version,
   restoring the pre-upgrade `pg_dump` and volume tarball into it. That is
   a rebuild, not a redeploy, and is out of scope for this runbook to
   script; it starts from `RUNBOOK-new-stack.md`'s general shape with
   9.2's dump substituted for a first install. 9.2's restore drill is what
   makes that substitution trustworthy rather than merely hoped-for.
3. Whichever path is taken, do not re-attempt 9.3 against the same
   half-upgraded volume without first resolving (0), (1) or (2) — a second
   `occ upgrade` invocation against a database in an unknown state is not
   something either this runbook or Nextcloud's own docs vouch for.

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
