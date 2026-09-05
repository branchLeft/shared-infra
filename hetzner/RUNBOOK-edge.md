# Runbook — the edge stack on `edge1`

Deploying Caddy and CrowdSec onto `edge1`, verifying that the edge detects
without acting, and later turning enforcement on.

`edge1` is `46.225.95.167` (private `10.20.1.10`), a `cx23` in `nbg1`. Every
`ssh`/`scp` below uses the platform owner's key, `~/.ssh/id_ed25519_hetzner` —
the one registered in the hcloud project and injected on `root` at server
creation. The CI deploy account cannot run any of this and is not meant to.

Run every workstation command from the root of a `branchLeft/shared-infra`
checkout.

Addresses are threaded through a variable, `$EDGE1_IPV4`, derived once under
"What has to be true first" below, rather than written out or left as a
placeholder to resolve by hand — the same convention `RUNBOOK-provision-host.md`
uses, reminder sentences included: a section a reader might enter on its own
says where the variable comes from and to re-derive it first. The old
convention's goal — nothing to resolve, every command runnable as read — was
right; a threaded variable serves that goal better than a committed literal,
because it survives `edge1` being rebuilt on a new address and the literal
does not.

## What has to be true first

`RUNBOOK-provision-host.md` must have been run against `edge1`. This runbook
assumes Docker, `branchleft-compose@.service` and
`/usr/local/sbin/branchleft-deploy` are already installed. Confirm in one
command:

```bash
EDGE1_IPV4=$(hcloud server describe edge1 -o json | python3 -c "import json, sys; print(json.load(sys.stdin)['public_net']['ipv4']['ip'])")
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  systemctl is-active docker &&
  test -x /usr/local/sbin/branchleft-deploy &&
  systemctl cat branchleft-compose@.service >/dev/null &&
  echo provisioned'
```

Expect `active` then `provisioned`. Anything else: run
`RUNBOOK-provision-host.md` first and come back.

**No hostname resolves to `edge1` yet**, and nothing in this runbook changes
that. The rendered Caddy configuration contains a site block only for a site
whose registry entry carries a `privateUpstream`, and no site does today, so
Caddy binds no public port and requests no certificate. That is deliberate: a
hostname whose DNS still points at the GCP edge would fail HTTP-01 validation
in a loop and spend the Let's Encrypt failure budget for the whole account.
Everything below is verified through the loopback probe listener instead.

## 1. Build and publish the Caddy image

Caddy needs the rate-limit and CrowdSec modules compiled in; neither ships in
the official binary and Caddy has no runtime plugin loading. `hetzner/edge/Dockerfile`
is that build.

The workstation is arm64 and `edge1` is amd64, so the platform is named
explicitly — a native build would push an image the host cannot run, and the
failure appears as a restart loop rather than as a pull error.

```bash
gh auth token | docker login ghcr.io -u Rob-branchLeft --password-stdin
```

If that is rejected, the `gh` token lacks `write:packages`; re-authenticate
with `gh auth refresh -h github.com -s write:packages` and repeat.

```bash
docker buildx build \
  --platform linux/amd64 \
  --push \
  --tag ghcr.io/branchleft/edge-caddy:caddy-2.11.4-1 \
  hetzner/edge
```

The build fails rather than succeeding quietly if either module is missing: the
final stage asserts that `rate_limit`, `appsec` and `crowdsec` are all
registered Caddy modules.

**First push only — make the package public.** A container package is created
private, and a private package needs a pull credential on the host, which this
estate deliberately does not carry. Go to
<https://github.com/orgs/branchLeft/packages/container/edge-caddy/settings>,
"Change package visibility", choose Public, confirm. This is a platform-owner
action; there is no reviewed path to it.

Read the digest the deploy will pin:

```bash
docker buildx imagetools inspect ghcr.io/branchleft/edge-caddy:caddy-2.11.4-1 \
  --format '{{.Manifest.Digest}}' | grep -o 'sha256:[0-9a-f]*' | head -1
```

Keep that value. Everywhere below it is written `<DIGEST>`, and it means the
**full** `sha256:<hex>` form: `branchleft-deploy` refuses a bare hex digest
with `image reference must be digest-pinned`, because `name@<hex>` without
the algorithm prefix is not a valid OCI reference. The `grep` is not
decoration: `imagetools inspect` has been observed printing a
`Name:`/`MediaType:`/`Digest:` block despite the `--format`, and the filter
yields the bare `sha256:…` value on either output shape. Both traps bit the
2026-08-22 redeploy.

## 2. Validate the configuration against the image that will run it

Catches an unrecognised directive or a module that did not make it into the
build, before anything is deployed:

```bash
docker run --rm --platform linux/amd64 \
  --env CROWDSEC_BOUNCER_KEY=validation-only \
  --env ACME_EMAIL=validation@example.invalid \
  --volume "$PWD/hetzner/edge/stack/Caddyfile:/etc/caddy/Caddyfile:ro" \
  ghcr.io/branchleft/edge-caddy@<DIGEST> \
  caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile
```

Expect `Valid configuration`. Both environment variables are placeholders: this
parses and adapts the file, it does not contact CrowdSec and it issues no
certificate.

CI runs this same check on every push, over the deployed configuration and over
the ones the posture flips would produce, so a failure here means the local
checkout differs from what was merged rather than that the configuration is
broken.

## 3. Write the stack's two secrets on the host

`/etc/branchleft/edge.env` is the file `branchleft-compose@edge` loads for stack
secrets, and nothing automated ever writes it — the deploy wrapper writes
`/etc/branchleft/edge.image.env` and only that. It needs two values:

- `CROWDSEC_BOUNCER_KEY`, which Caddy and CrowdSec must both hold. Generated
  once here, registered on the CrowdSec side from the same variable, never
  committed.
- `ACME_EMAIL`, the address Let's Encrypt attaches the account to and sends
  expiry warnings to. The stack refuses to start without it. Use a mailbox
  someone reads; a certificate-expiry warning delivered nowhere is the failure
  mode this exists to prevent.

**This command writes the file whole and discards anything already in it.**
Nothing else belongs there today, but check before running it a second time.
`$EDGE1_IPV4` is set under "What has to be true first" above; re-set it first
if you are entering here independently:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  'test -f /etc/branchleft/edge.env && grep -c . /etc/branchleft/edge.env || echo "absent"'
```

`absent`, or `2`, means there is nothing to lose. Anything else: edit the file
in place instead of running the next command.

Substituting a real mailbox for `ACME_EMAIL`:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  install -d -m 0755 -o root -g root /etc/branchleft &&
  umask 077 &&
  { printf "CROWDSEC_BOUNCER_KEY=%s\n" "$(openssl rand -hex 32)";
    printf "ACME_EMAIL=%s\n" "<ACME_MAILBOX>"; } > /etc/branchleft/edge.env &&
  chmod 0600 /etc/branchleft/edge.env &&
  ls -l /etc/branchleft/edge.env'
```

Expect `-rw------- 1 root root`. Do not print the file; nothing below needs the
key's value.

Re-running this **rotates** the bouncer key. Both containers read it at start,
so a rotation is followed by step 6's restart and nothing else.

## 4. Copy the stack directory onto the host

`hetzner/edge/stack/` is the deployment: a Compose file, the generated Caddy
configuration, and the generated CrowdSec acquisition files. It is copied
verbatim. `$EDGE1_IPV4` is set under "What has to be true first" above;
re-set it first if you are entering here independently.

```bash
rsync -av --delete --no-owner --no-group --chmod=u=rwX,go=rX \
  -e 'ssh -i ~/.ssh/id_ed25519_hetzner' \
  hetzner/edge/stack/ root@"$EDGE1_IPV4":/opt/branchleft/edge/ &&
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  'chown -R root:root /opt/branchleft/edge/'
```

`--delete` is deliberate: a stale acquisition file left behind from an earlier
copy is a CrowdSec configuration nobody is reading in the repository. The `chown`
corrects file ownership on the receiving end, covering both files and directories;
`rsync --no-owner --no-group` does not modify existing file ownership, so an
explicit chown is needed to fix files that were copied with incorrect ownership
from a previous deployment.

## 5. Enable the unit

Once, so the stack comes back after a reboot. `$EDGE1_IPV4` is set under
"What has to be true first" above; re-set it first if you are entering here
independently:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  'systemctl enable branchleft-compose@edge'
```

## 6. Deploy

`$EDGE1_IPV4` is set under "What has to be true first" above; re-set it
first if you are entering here independently.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  '/usr/local/sbin/branchleft-deploy edge ghcr.io/branchleft/edge-caddy@<DIGEST>'
```

Expect `branchleft-deploy: edge now pinned to ghcr.io/branchleft/edge-caddy@<DIGEST>`.

The wrapper refuses anything that is not digest-pinned, writes the pin
atomically, and restarts the unit. If the restart fails it puts the previous
digest back and restarts again, so a bad image leaves the host on the last one
that worked — except on the very first deploy, where there is nothing to fall
back to and it says so.

If that rollback restart also fails, `branchleft-compose@edge` ends up
`failed` on both pins — but the unit carries no `ExecStop`, so `docker
compose down` never fires regardless of whether that restart succeeded or
failed, and whatever the most recent `up -d` attempt started is still
running, healthy or not. `systemctl is-active branchleft-compose@edge`
reading `failed` here is not proof the stack is down; use the `docker ps`
check in step 7 below to see what is actually running before treating it as
an outage.

CrowdSec downloads its hub items on first start, so allow a couple of minutes
before the checks below.

## 7. Verify the stack is up

An interactive shell has none of the env files `branchleft-compose@edge`
supplies at start, so a bare `docker compose` command here re-parses
`compose.yml` and refuses on the missing `ACME_EMAIL` and
`CROWDSEC_BOUNCER_KEY` before it does anything. The checks below go straight
at the running containers with `docker ps`/`docker exec` instead, found by
Compose's own labels rather than by name — `compose.yml` pins no
`container_name`, so the container Compose v2 would create by default,
`edge-crowdsec-1`, is not a contract. Reading a container's labels needs
neither secret. `$EDGE1_IPV4` is set under "What has to be true first"
above; re-set it first if you are entering here independently.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  docker ps --filter label=com.docker.compose.project=edge &&
  CROWDSEC_CTR=$(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=crowdsec) &&
  docker exec "$CROWDSEC_CTR" cscli appsec-configs list &&
  docker exec "$CROWDSEC_CTR" cscli bouncers list'
```

Expect two containers listed, both `Up (healthy)`, and one bouncer named
`caddy` with a recent "last pull". A bare `Up` alongside a `systemctl restart`
that exited 0 means the deployed `compose.yml` on the host carries no
`healthcheck:` for that service — `--wait` cannot return success on a container
whose probe is merely failing, so it is the copy in step 4 that did not land,
not the probe.

`appsec-configs list` shows more than the two configurations `compose.yml`
enables: the hub installs their dependencies too, on first start. On `edge1`,
2026-08-19, the four enabled were `crowdsecurity/appsec-default`,
`crowdsecurity/crs`, `crowdsecurity/generic-rules` and
`crowdsecurity/virtual-patching` — the last two pulled in by the first two,
not set anywhere in this repo. Seeing four names rather than two is not a
fault to chase. Which of them is _loaded_ is decided by
`crowdsec/acquis.d/appsec.yaml`, so turning enforcement on later does not
depend on the CrowdSec hub being reachable at that moment.

## 8. Verify the deployed posture

The posture is not one thing, so do not verify it as though it were. Three
independent switches in `hetzner/edge/posture.ts`, and this section proves each
is in the state that file says:

| Switch                      | Committed state | What that means here                                                |
| --------------------------- | --------------- | ------------------------------------------------------------------- |
| `crowdsec`                  | `detect-only`   | sees everything, records what it would act on, blocks nothing       |
| `rateLimit`                 | `off`           | the general 200/60s page-serving throttle renders no handler at all |
| `membersMagicLinkRateLimit` | `enforcing`     | POSTs to Ghost's magic-link path are throttled at 5/60s             |

All checks go through the loopback probe listener, which carries the same
handler chain as a public site and answers 204.

**Both directions matter.** Checks (a) and (b) are a matched pair: (a) proves
the general throttle is absent, (b) proves the magic-link throttle is present
and actually fires. Running only the negative one would pass identically if the
whole `rate_limit` module had silently failed to load, which is the failure this
pair exists to distinguish (`branchLeft/workspace#209`).

`$EDGE1_IPV4` is set under "What has to be true first" above; re-set it
first if you are entering this section independently — every check below
reuses it.

**a. The general throttle is off.** 250 requests inside the 60-second window
that would trip a 200-request limit:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  for i in $(seq 1 250); do
    curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/
  done | sort | uniq -c'
```

Expect `250 204` and no `429`. A `429` here means `rateLimit` is enforcing when
the committed posture says `off` — stop and read `hetzner/edge/posture.ts` in
the deployed commit. Note this is a `GET` to `/`, so it never touches the
magic-link zone; the two counters are independent by construction.

**b. The members magic-link throttle is on, and trips.** Five events per 60
seconds, matching `POST` only, on `/members/api/send-magic-link` and its
trailing-slash form. **Leave at least 60 seconds between each of the four
checks below** — loop 3 and loop 4b are each a single unbroken sequence
internally, but the gap goes _between_ them. They all share one counter, so
running them back to back exhausts the budget once and every later loop reads
`429` regardless of what it is actually testing. Check 4a is two requests and
does not need its own window, but it does spend two events.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  for i in $(seq 1 8); do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST \
      http://127.0.0.1:8080/members/api/send-magic-link
  done | sort | uniq -c'
```

Expect `5 204` followed by `3 429`, tripped well inside the general throttle's
own budget, which check (a) has already confirmed is absent entirely.

Then confirm the matcher keys on the **method**, not only the path — a `GET` to
the same path must not count against this budget at all:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  for i in $(seq 1 8); do
    curl -s -o /dev/null -w "%{http_code}\n" \
      http://127.0.0.1:8080/members/api/send-magic-link
  done | sort | uniq -c'
```

Expect `8 204`.

Then confirm the trailing-slash variant draws from the **same** budget as the
bare path rather than falling through unthrottled — Express's default router
treats the two as the same route, and this is the exact gap a wildcard-free,
two-pattern matcher exists to close. Run bare and trailing-slash requests in one
unbroken loop, not two separate ones: two loops each land in their own
60-second window and would each read as a fresh, misleadingly clean
`5 204, 3 429` rather than proving anything shared.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  for i in $(seq 1 5); do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST \
      http://127.0.0.1:8080/members/api/send-magic-link
  done
  for i in $(seq 1 3); do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST \
      http://127.0.0.1:8080/members/api/send-magic-link/
  done' | sort | uniq -c
```

Expect `5 204` then `3 429` — five bare-path successes exhaust the shared
budget, so every trailing-slash request that follows in the same window is
already throttled. `8 204` here would mean the trailing slash carries its own
separate budget, i.e. that it is not matched by this rule at all.

**The three loops above prove the throttle logic, not hostname routing.** They
answer on a bare port with no `Host` match, so they exercise the same handler
chain every site gets but never Caddy's selection of a site by host. The fourth
loop is what closes that.

**4. The rule is reached through a site block, and the zone spans hostnames.**

`edge-probe.invalid` is a second probe address on the same port, differing only
in carrying a host. It is reserved by RFC 2606 and never resolves, so this runs
entirely on the host and touches no production hostname.

**4a. Confirm the host-qualified block is actually deployed and selected.** Run
this first, and do not read 4b's result without it.

The bare `:8080` block is a **catch-all** — it matches every Host, so if
`hetzner/edge/stack/Caddyfile` was never `rsync`ed onto the host, or the
restart in step 6 was skipped, the catch-all answers a request for
`edge-probe.invalid` exactly as the host-qualified block would. Status code
alone cannot tell those apart, so each block names itself in an
`X-Edge-Probe` response header, and that header is the thing to read:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  for h in edge-probe.invalid 127.0.0.1; do
    curl -s -o /dev/null -D - -X POST -H "Host: $h" \
      http://127.0.0.1:8080/members/api/send-magic-link |
      awk -v h="$h" "tolower(\$1) ~ /^x-edge-probe:/ { print h, \$2 }"
  done'
```

Expect exactly:

```
edge-probe.invalid host-routed
127.0.0.1 bare-port
```

`edge-probe.invalid bare-port` means the catch-all served it — the
host-qualified block is not on the host, and **4b below would still print
`5 204, 3 429`**, proving nothing. Empty output means the config predates this
header entirely; re-check step 4 and step 6.

**4b. The zone spans hostnames.** Wait a full 60 seconds after 4a, then run
this as one unbroken sequence — the point is that the second half inherits the
first half's budget:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  for i in $(seq 1 5); do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST \
      http://127.0.0.1:8080/members/api/send-magic-link
  done
  for i in $(seq 1 3); do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST \
      -H "Host: edge-probe.invalid" \
      http://127.0.0.1:8080/members/api/send-magic-link
  done' | sort | uniq -c
```

Expect `5 204` then `3 429`. Given 4a passed, this shows two things:

- The host-qualified requests were **routed through a site block** Caddy
  selected by `Host`, and the throttle was reached inside it. A bare-port trip
  cannot show this.
- The magic-link zone is **global across hostnames** — the budget spent on the
  bare port was already spent when the same client arrived on a different host.
  This is the one thing this control adds that Ghost cannot do for itself:
  `membersAuthEnumeration` counts per Ghost instance, so it would have let all
  three through.

`8 204` here means the host-qualified address got its own counter, i.e. the
global zone is not global and the cross-tenant property is not holding.

Once a real tenant hostname is served by this edge, repeat loops 1 and 2
against `https://<hostname>/members/api/send-magic-link` from a workstation as
well. That proves the same thing on a path carrying TLS and a real upstream;
until then, this loop is the proof.

**A throttled member sees Ghost's generic portal error, not a wait time.**
Caddy's `rate_limit` answers a bodyless 429 and Ghost's JSON-error parsing falls
back to its generic message. That is a known, accepted cost of this control, not
a defect to chase.

**c. An attack is seen and not blocked.**

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  curl -s -o /dev/null -w "%{http_code}\n" \
    "http://127.0.0.1:8080/?id=1%27%20OR%20%271%27%3D%271"'
```

Expect `204`. The request reached the WAF, tripped an OWASP Core Rule Set rule,
and was answered normally — which is the whole of what detect-only means.

**d. The detection is recorded.**

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  CROWDSEC_CTR=$(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=crowdsec) &&
  docker exec "$CROWDSEC_CTR" cscli alerts list --limit 20 &&
  docker exec "$CROWDSEC_CTR" cscli decisions list'
```

Expect at least one alert naming an AppSec scenario. Decisions may be empty or
may list bans that nothing is enforcing — either is correct in this posture, and
the second is the evidence the review in step 9 is about.

## 9. The detect-only period, and the review that ends it

Leave the edge in this posture until it has carried real traffic, which means
until at least one site has a `privateUpstream` and its hostname resolves here.
Detect-only over no traffic proves nothing.

What the review is looking for, on the host. `$EDGE1_IPV4` is set under
"What has to be true first" above; re-set it first if you are entering here
independently:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  CROWDSEC_CTR=$(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=crowdsec) &&
  docker exec "$CROWDSEC_CTR" cscli alerts list --limit 100 &&
  docker exec "$CROWDSEC_CTR" cscli metrics'
```

- Alerts against addresses that are plainly hostile: expected, and the argument
  for enforcing.
- Alerts against the platform owner's own address, a member's, or a search
  engine's: false positives, and each one has to be understood before
  enforcement, because after the flip the same request bans that address.
- The per-address request rates in `cscli metrics`, read against the
  200-per-60-seconds threshold: that is the only observation available for the
  throttle, which has no non-enforcing mode of its own.

## 10. Turning enforcement on

Enforcement is **three** independent switches in `hetzner/edge/posture.ts`, and
each is flipped by a pull request, never by a redeploy. Flipping one changes the
rendered files under `hetzner/edge/stack/`, so the diff a reviewer reads is
literally the configuration the host will run.

| Switch                      | State                             | Where it is verified                                    |
| --------------------------- | --------------------------------- | ------------------------------------------------------- |
| `membersMagicLinkRateLimit` | **`enforcing`** — already flipped | §8b                                                     |
| `rateLimit`                 | `off`                             | §10a below turns it on; §8a proves it is off until then |
| `crowdsec`                  | `detect-only`                     | §10b below turns it on                                  |

Turn the remaining two on one at a time, in this order, with time between them:
the throttle is reversible and low-consequence, and the WAF is the one that can
lock an author out.

### 10a. The general page-serving throttle

**Do not flip this on the inherited threshold.** `RATE_LIMIT_EVENTS` is 200 per
60 seconds because the captured Cloud Armor policy says so, and that rule has
never enforced anything — it is live at `preview: true`, so 200/60s is a number
no traffic on either edge has ever been measured against. `edge1` averages well
under 1 req/s but has 1-minute bursts two orders of magnitude above that, and
nothing currently attributes those to one client or to many. Enabling on the
inherited number picks one of those on faith.

Derive it first, from the access log — which `posture.ts` names as this
throttle's observation instrument, and which is enabled in every posture. The
command below prints the distribution of requests per client address per minute
and **no addresses**, so client IPs stay on the host. `$EDGE1_IPV4` is set
under "What has to be true first" above; re-set it first if you are entering
this section independently:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  'docker exec $(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=caddy) \
     sh -c "cat /var/log/caddy/access.log"' |
python3 -c '
import sys, json, collections
buckets = collections.Counter()
for line in sys.stdin:
    try: e = json.loads(line)
    except ValueError: continue
    ip = e.get("request", {}).get("remote_ip")
    ts = e.get("ts")
    if ip and ts: buckets[(ip, int(ts // 60))] += 1
counts = sorted(buckets.values())
n = len(counts)
print("IP-minutes observed:", n)
for pct in (50, 90, 99, 99.9):
    print(f"p{pct}:", counts[min(n - 1, int(n * pct / 100))])
print("max:", counts[-1] if counts else 0)
'
```

Check the window the log actually covers before trusting the percentiles — it
rotates. Set the threshold above the legitimate p99.9 with headroom, and record
the derivation in `posture.ts` the way the magic-link one is recorded. A
threshold nobody derived is not a threshold. Tracked as
`branchLeft/workspace#323`.

Then:

1. In a branch, set `rateLimit: 'enforcing'` in `hetzner/edge/posture.ts`, with
   `RATE_LIMIT_EVENTS` at the derived value.
2. `cd hetzner && npm run render` — this rewrites `hetzner/edge/stack/Caddyfile`.
3. Commit both files together and open a pull request. `npm test` fails if the
   rendered file and the posture disagree, so they cannot land apart.
4. After merge, on an up-to-date checkout of `main`, repeat step 4 (`rsync`) and
   then restart, which needs no new image:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  'docker restart $(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=caddy)'
```

**Not `systemctl restart branchleft-compose@edge`.** That unit carries no
`ExecStop` since `hetzner/provision/branchleft-compose@.service` changed, so a
restart runs `docker compose up -d` and Compose recreates only services whose
_config hash_ moved. A bind-mounted file's **contents** are not part of that
hash, so a Caddyfile-only change is a silent no-op: the command exits 0,
`--wait` passes because the unchanged containers are already healthy, and Caddy
goes on serving the configuration it loaded at container start. This was
observed on the monitoring stack the same day it landed
(branchLeft/workspace#666) and again here.

The `edge` instance is deliberately **not** given the blanket
`--force-recreate` that the monitoring instance gets: recreating this stack
wholesale on every unit restart would also recreate CrowdSec, and
`branchleft-deploy` restarts this unit for image bumps where a selective
recreate is the correct behaviour. So the recreate is explicit here, at the one
step that needs it.

**Validate before restarting.** The copy is already on disk at this point, so
the running container can parse it without adopting it:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'docker exec $(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=caddy) caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile'
```

Expect `Valid configuration`. CI validates the file in the repository; this
validates the bytes that survived the `rsync`, in the pinned binary, with the
file where Caddy will actually read it. Caddy terminates TLS for every hostname
this edge serves, so restarting onto a config it cannot parse is an outage.

5. Confirm it took, with §8a's loop. Expect roughly `200 204` followed by
   `50 429` rather than `250 204` — the inverse of what §8a asserts today, and
   the point at which §8a's expected output must be updated in this file.

**Counters are in-memory and per-process, so this restart resets every client's
budget.** Harmless, and the reason sustained-attack behaviour cannot be reasoned
about across a deploy.

**Neither the flip nor its verification runs itself:** merging the posture
change does not deploy it, and does not run the loop. Both are steps 4 and 5
above, performed by whoever holds `~/.ssh/id_ed25519_hetzner`.

### 10b. The WAF and IP remediation

Same four steps with `crowdsec: 'enforcing'`, which changes both the Caddy
route chain and `crowdsec/acquis.d/appsec.yaml`.

Confirm it took. `$EDGE1_IPV4` is set under "What has to be true first"
above; re-set it first if you are entering this section independently:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/.env'
```

Expect `403`. `/.env` trips an in-band virtual-patching rule, so it is refused
before the request proceeds — the behaviour the retiring Cloud Armor policy
declared for its `lfi` ruleset.

**A block is not where it ends.** In-band blocks feed
`crowdsecurity/appsec-vpatch`, a leaky bucket at `capacity: 1` counting distinct
rule names per address, so a **second** distinct in-band rule match from the same
address inside 60 seconds becomes a ban across every hostname on the edge for
the profile's duration. Out-of-band matches do the same at `capacity: 5`. The
Cloud Armor rules being replaced answered 403 and never touched the address.
This is the difference the parity artifact records, and it is the reason the
detect-only review in step 9 is about false positives rather than about counts.

Run the check above twice and you will ban yourself. For a command run on the
host that address is the Docker bridge gateway. Clear it, or the host's own
container traffic stays banned for the decision's lifetime:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  CROWDSEC_CTR=$(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=crowdsec) &&
  docker exec "$CROWDSEC_CTR" cscli decisions list &&
  docker exec "$CROWDSEC_CTR" cscli decisions delete --ip 172.17.0.1'
```

Read the listed decisions first and delete the address the list actually shows —
the bridge subnet depends on how many Compose networks the host has.

## 11. Adding a site to the edge

One registry entry, then a re-render. Nothing else.

1. Add `privateUpstream: { host: 'app1', port: 2368 }` to the site's entry in
   `sites.ts` (`host` is a name from the estate address plan, not an address;
   an unknown name fails the render rather than producing a config that proxies
   to nothing).
2. `cd hetzner && npm run render`, commit both files, open a pull request.
3. After merge: `rsync` (step 4) and restart (step 10a.4).
4. **Only then** cut the hostname's DNS at IONOS to `46.225.95.167`. The order
   is forced: Caddy issues its certificate over HTTP-01, which cannot succeed
   until the hostname resolves here, and it will not attempt issuance at all
   until the site block exists.
5. Watch issuance. `$EDGE1_IPV4` is set under "What has to be true first"
   above; re-set it first if you are entering this section independently:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  'journalctl -u branchleft-compose@edge --since "10 min ago" | grep -i certificate'
```

## 12. Rolling back

A bad configuration and a bad image roll back differently. `$EDGE1_IPV4` is
set under "What has to be true first" above; re-set it first if you are
entering here independently — this is the section most likely to be entered
mid-incident, days after the deploy.

**Configuration** — restore the previous `hetzner/edge/stack/` from git and
re-copy:

```bash
git checkout <PREVIOUS_MERGED_SHA> -- hetzner/edge/stack
rsync -av --delete --no-owner --no-group --chmod=u=rwX,go=rX \
  -e 'ssh -i ~/.ssh/id_ed25519_hetzner' \
  hetzner/edge/stack/ root@"$EDGE1_IPV4":/opt/branchleft/edge/ &&
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  'chown -R root:root /opt/branchleft/edge/ &&
   docker restart $(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=caddy)'
```

**The recreate matters more here than on the forward path.** A rollback is
reached for during an outage, and `systemctl restart branchleft-compose@edge`
would restore the previous file to disk and leave the broken configuration
running in memory — exit 0, containers healthy, nothing fixed, and the one
signal saying the rollback worked pointing the wrong way. See §10a.4 for why
the unit no longer recreates on a bind-mount content change.

Then `git checkout HEAD -- hetzner/edge/stack` on the workstation, so the
checkout stops describing a state the repository does not hold.

**Image** — re-run the deploy wrapper with the previous digest:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  '/usr/local/sbin/branchleft-deploy edge ghcr.io/branchleft/edge-caddy@<PREVIOUS_DIGEST>'
```

The wrapper does this itself when a restart fails. Running it by hand is for the
case where the stack started cleanly and is behaving wrongly.

## What this stack deliberately does not do

- **It does not share signals with the CrowdSec community blocklist.**
  `DISABLE_ONLINE_API` is `true` in `compose.yml`. Enabling it sends observed
  client addresses to a third party, which is a sub-processor and a personal-data
  decision rather than a configuration default. It stays off until that decision
  is taken and the DPIA is updated.
- **It does not fail closed on the WAF.** The Caddy configuration carries a bare
  `appsec_fail_open`: a CrowdSec restart or stall degrades inspection rather
  than answering 500 for every site at once, because both containers share one
  `cx23`. IP decisions are unaffected — the bouncer serves those from its own
  cache. Absent, the bouncer's default is fail-**closed**, and the AppSec
  handler is in the route in every posture, detect-only included.
- **It does not serve HTTP/3.** The Caddy configuration sets
  `servers { protocols h1 h2 }` and Compose publishes no UDP port, because the
  `edge1` firewall opens tcp/22, tcp/80, tcp/443 and ICMP and no UDP at all.
  Left on, Caddy would advertise `Alt-Svc: h3` on every response and clients
  would retry QUIC against a dropped port — survivable, but it presents as
  intermittent slow first connections rather than as a firewall rule. Turning
  HTTP/3 on means adding the firewall rule first; the rule lives in
  `@branchleft/hetzner-host`'s `EDGE_RULES`, not in this stack.
- **It does not open the probe port.** Compose publishes `8080` on `127.0.0.1`
  only and the Hetzner firewall on `edge1` opens 22, 80, 443 and ICMP. Reaching
  the probe requires SSH to the host.
