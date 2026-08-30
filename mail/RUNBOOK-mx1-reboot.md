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

Save this output. It does not gate the reboot and it does not change the fix,
but it decides whether `scanBanPaths` also needs managing later.

Log lines carry recipient email addresses. Redact before pasting anywhere.

---

## Step 1 — confirm the containers will come back

Read-only, and the precondition for Step 2.

```
ssh -i ~/.ssh/id_ed25519_hetzner root@mx1.branchleft.co.uk '
echo "== restart policies ==";
for c in stalwart mailgun-shim mailgun-shim-caddy; do
  printf "%s\t" "$c"; docker inspect --format "{{.HostConfig.RestartPolicy.Name}}" "$c";
done
echo "== docker enabled at boot ==";
systemctl is-enabled docker
echo "== pending reboot marker ==";
test -f /var/run/reboot-required && echo "REBOOT REQUIRED" || echo "no marker"
echo "== runc / docker versions ==";
dpkg -l | grep -E "^ii\s+(docker-ce|containerd|runc)" | awk "{print \$2, \$3}"
'
```

**Expected output:** all three containers print `unless-stopped`; `docker`
prints `enabled`. The reboot marker and versions are informational — a
`REBOOT REQUIRED` marker corroborates the diagnosis but its absence does not
refute it.

**Stop here if any container prints `no` or `never`,** or if `docker` prints
`disabled`. That container will not return on its own and the reboot would
turn a two-minute outage into an indefinite one. Report the output instead.

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
echo "== containers =="; docker ps --format "{{.Names}}\t{{.Status}}"
echo "== exec works =="; docker exec stalwart true && echo "EXEC OK" || echo "EXEC STILL BROKEN"
echo "== health =="
for c in stalwart mailgun-shim; do
  printf "%s\t" "$c";
  docker inspect --format "{{.State.Health.Status}} streak={{.State.Health.FailingStreak}}" "$c";
done
'
```

**A pass looks like:** `uptime` under five minutes; all three containers
listed; `EXEC OK`; and both healthchecks reporting `healthy` with
`streak=0`.

`starting` rather than `healthy` immediately after boot is normal — re-run
the health block after a minute rather than treating it as a failure.

**If it still prints `EXEC STILL BROKEN`,** the runc-upgrade diagnosis was
wrong. Stop and report; do not reboot a second time.

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

---

## Rollback

None, and none is needed. A reboot changes no state. If the host does not
return, that is a Hetzner console matter rather than a rollback.

## After it succeeds

Close the tracked item citing the Step 3 output — specifically the `EXEC OK`
line and both healthchecks at `streak=0`. Never paste a credential value, and
redact recipient addresses from any Step 0 log excerpt.

If Step 0 showed HTTP requests against the `https` listener immediately before
the ban, say so in the closing comment: that makes `scanBanPaths` the trigger,
and it is managed by neither this runbook nor the ban-policy change.
