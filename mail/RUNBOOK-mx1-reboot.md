# Runbook — reboot mx1 to restore `docker exec`

Runs the fix for branchLeft/workspace#433. The issue closes by hand on the
Step 3 output, not on this merge — the reboot is executed here, not by CI.

## What is wrong

Every container healthcheck on `mx1` fails, identically:

```
OCI runtime exec failed: unable to retrieve OCI runtime error (unexpected EOF):
runc did not terminate successfully: exit status 255
```

Both containers serve traffic correctly. It is `docker exec` itself that is
broken, so anything that shells into a container fails — healthchecks first,
but also `30-deploy-stalwart.sh`, which polls `.State.Health.Status` and exits
non-zero after 30 attempts. **The next provisioning run on this host will fail
at that gate even when the deploy itself succeeded.**

The host has been up 20 days on a single boot with `unattended-upgrades`
enabled. A `docker`/`runc` upgrade that was never rebooted into fits the
evidence: the on-disk `runc` no longer matches what the running daemon
expects, so `exec` fails while already-running containers keep serving.

Two consequences worth stating plainly. `unhealthy` on this host currently
carries no information at all, so it cannot be used as a monitoring signal.
And a healthcheck that has never passed hides whatever it was meant to catch —
the shim's failing streak indicates it has never once succeeded.

## Blast radius

**Mail stops for the duration of the reboot — roughly two minutes.**

- Inbound SMTP is refused while the host is down. Sending mail servers treat
  a refused connection as a temporary failure and retry; nothing is lost.
- IMAP clients disconnect and reconnect on their own.
- The bulk-mail shim API is unavailable for the same window.
- **Not irreversible.** No data is touched. All three containers carry
  `restart: unless-stopped`, so Docker restores them at boot.

Do not run this during a send window or while a newsletter is going out.

## Before you start

- SSH access to `mx1` with `~/.ssh/id_ed25519_hetzner`.
- No newsletter or bulk send in progress.
- Step 1 must pass before you reboot. It is the check that the containers
  will actually come back.

---

## Step 0 — capture the ban trigger before it ages out

Read-only. This is the one piece of evidence that explains _why_ the scan-ban
fired, and container logs rotate.

```
ssh -i ~/.ssh/id_ed25519_hetzner -o StrictHostKeyChecking=accept-new root@mx1.branchleft.co.uk '
docker logs --since 2026-08-24T15:30:00Z --until 2026-08-24T16:20:00Z stalwart 2>&1 | tail -60
'
```

**Expected output:** the log lines spanning the ban at `16:14:01Z`. What
matters is what appears in the minutes immediately before it — HTTP requests
against the `https` listener (which would mean `scanBanPaths` matched a path
and banned on sight) versus repeated connect/disconnect churn on 993 and 587
(which would mean the rate heuristic tripped).

**Empty output is ambiguous** — it means either that nothing happened in that
window or that the logs have already rotated past it. Tell the two apart:

```
ssh -i ~/.ssh/id_ed25519_hetzner root@mx1.branchleft.co.uk 'docker logs stalwart 2>&1 | head -1'
```

If that first line is dated later than the window above, the evidence is gone
and Step 0 has no more to give. Move on rather than digging.

Save this output. It does not gate the reboot and it does not change the fix,
but it decides whether `scanBanPaths` also needs managing later.

Log lines carry recipient email addresses. Redact before pasting anywhere.

---

## Step 1 — confirm the containers will come back

Read-only, and the precondition for Step 2.

```
ssh -i ~/.ssh/id_ed25519_hetzner root@mx1.branchleft.co.uk '
echo "== policy AND current state ==";
for c in stalwart mailgun-shim mailgun-shim-caddy; do
  printf "%s\t" "$c";
  docker inspect --format "{{.HostConfig.RestartPolicy.Name}}\t{{.State.Status}}" "$c";
done
echo "== docker enabled at boot ==";
systemctl is-enabled docker
echo "== when docker/runc were last upgraded ==";
grep -hE " (upgrade|install) (docker-ce|containerd|runc)" /var/log/dpkg.log* 2>/dev/null | tail -5
echo "== runc / docker versions ==";
dpkg -l | grep -E "^ii\s+(docker-ce|containerd|runc)" | awk "{print \$2, \$3}"
'
```

**Expected output:** all three containers print `unless-stopped` **and**
`running`; `docker` prints `enabled`. The upgrade log and versions are
informational — an upgrade entry postdating the last boot corroborates the
diagnosis, but its absence does not refute it.

**Both columns matter, and the second is the one that is easy to miss.**
`unless-stopped` restores a container at boot only if it was running when the
host went down; a container already stopped stays stopped, whatever its
policy says. A policy-only check would pass identically in both cases.

**Stop here if any container prints anything other than
`unless-stopped` + `running`,** or if `docker` prints `disabled`. That
container will not return on its own and the reboot would turn a two-minute
outage into an indefinite one. Report the output instead.

---

## Step 2 — reboot

```
ssh -i ~/.ssh/id_ed25519_hetzner root@mx1.branchleft.co.uk 'systemctl reboot'
```

**Expected output:** the connection closes, usually with
`Connection to mx1.branchleft.co.uk closed by remote host.` That is success,
not an error.

Wait about 90 seconds before Step 3. A reconnect attempt that is refused or
times out means the host is still booting; wait and retry rather than
concluding anything.

---

## Step 3 — verify

Run all of it in one go once the host answers again.

```
ssh -i ~/.ssh/id_ed25519_hetzner root@mx1.branchleft.co.uk '
echo "== uptime =="; uptime
echo "== containers (-a, so a restart-looping one is still listed) ==";
docker ps -a --format "{{.Names}}\t{{.Status}}"
echo "== exec works, on all three ==";
for c in stalwart mailgun-shim mailgun-shim-caddy; do
  printf "%s\t" "$c";
  docker exec "$c" true >/dev/null 2>&1 && echo "EXEC OK" || echo "EXEC STILL BROKEN";
done
echo "== health =="
for c in stalwart mailgun-shim; do
  printf "%s\t" "$c";
  docker inspect --format "{{.State.Health.Status}} streak={{.State.Health.FailingStreak}}" "$c";
done
'
```

**A pass looks like:** `uptime` under five minutes; all three containers
listed and showing `Up`; `EXEC OK` three times; and both healthchecks
reporting `healthy` with `streak=0`.

`docker ps -a` rather than `docker ps` is deliberate — a container caught
between restart attempts sits in `Exited` and is simply absent from the
plain listing, which reads as though it were never expected. `Restarting` or
`Exited` in that column is a failure, not a slow start.

`mailgun-shim-caddy` has no healthcheck of its own, so the exec probe is the
only proof of life it gets here; that is why the loop covers all three
rather than just the two with health status.

`starting` rather than `healthy` immediately after boot is normal — re-run
the health block after a minute rather than treating it as a failure.

**If any container still prints `EXEC STILL BROKEN`,** the runc-upgrade
diagnosis was wrong. Stop and report; do not reboot a second time.

Then confirm from outside, in a separate local terminal, that mail is
actually serving again:

```
printf 'QUIT\r\n' | nc -w 8 mx1.branchleft.co.uk 25
```

**Expected output:** a line beginning `220 mx1.branchleft.co.uk`. An empty
response means the port accepted the connection and served nothing — that is
the incident's original signature and means Stalwart is not serving.

Run that command **once**. Repeated bare connections to mail ports are what
the scan-ban treats as probing.

Then confirm the two properties a reboot could plausibly disturb and that
nothing above would notice. Both commands run locally, not on the host —
`RUNBOOK-mx1-provision.md`'s acceptance list is the authority for both.

**TLS is intact:**

```
openssl s_client -connect mx1.branchleft.co.uk:465 -servername mx1.branchleft.co.uk </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

**Expected output:** a subject naming `mx1.branchleft.co.uk`, a Let's Encrypt
issuer, and a `notAfter` date still in the future. A certificate whose
`notBefore` reads about an hour earlier than expected is normal — Let's
Encrypt backdates it for clock skew — and is not evidence of a re-issue.

**The admin interface is still blocked:**

```
curl -k -s -o /dev/null -w '%{http_code}\n' https://mx1.branchleft.co.uk/
```

**Expected output:** `421`. Anything else — a `200` above all — means the
webadmin is reachable from the internet and is an immediate stop: report it
rather than continuing.

These two exist because the reboot restarts Stalwart, and Stalwart's
certificate handling and its HTTP access-control rule are both applied at
start. A start that half-succeeded would still pass every check above.

---

## Rollback

None, and none is needed. A reboot changes no state. If the host does not
return, that is a Hetzner console matter rather than a rollback.

## After it succeeds

Close the tracked item citing the Step 3 output. The evidence is all five
checks, not just the first: `EXEC OK` for all three containers, both
healthchecks at `streak=0`, the `220` SMTP banner, `Verify return code: 0`
with a Let's Encrypt subject, and `421` from the admin probe. Never paste a
credential value, and redact recipient addresses from any Step 0 log
excerpt.

If Step 0 showed HTTP requests against the `https` listener immediately before
the ban, say so in the closing comment: that makes `scanBanPaths` the trigger,
and it is managed by neither this runbook nor the ban-policy change.
