# Runbook — the edge stack on `edge1`

Deploying Caddy and CrowdSec onto `edge1`, verifying that the edge detects
without acting, and later turning enforcement on.

`edge1` is a `cx23` in `nbg1` (private `10.20.1.10`). Every
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

**Select the hcloud project first.** The lookups below ask hcloud, so its active context
must be the one for the project that holds the server. Which of your contexts that is
is not recorded here. List them, read the name, then select it, each as its own paste:

```bash
hcloud context list
```

```bash
read -r HCLOUD_CONTEXT
```

```bash
hcloud context use "${HCLOUD_CONTEXT}"
```

```bash
EDGE1_IPV4=$(hcloud server ip edge1)
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  systemctl is-active docker &&
  test -x /usr/local/sbin/branchleft-deploy &&
  systemctl cat branchleft-compose@.service >/dev/null &&
  echo provisioned'
```

Expect `active` then `provisioned`. Anything else: run
`RUNBOOK-provision-host.md` first and come back.

The rendered Caddy configuration contains a site block only for a site whose
registry entry carries a `privateUpstream`. A hostname whose DNS points anywhere
but edge1 would fail HTTP-01 validation in a loop and spend the Let's Encrypt
failure budget for the whole account, so everything below is verified through
the loopback probe listener.

## 1. Build and publish the Caddy image

Caddy needs the rate-limit and CrowdSec modules compiled in; neither ships in
the official binary and Caddy has no runtime plugin loading. `hetzner/edge/Dockerfile`
is that build.

The `publish-edge-caddy.yml` workflow builds and pushes it. It builds
`hetzner/edge/Dockerfile` on a native amd64 runner from the commit the run
names, pushes with the run's own short-lived token, and reads the pushed
digest back from the image store. Nothing is built or pushed from a
workstation, and no personal token with `write:packages` is involved. The
workflow runs from `main` only; started from any other ref it fails before it
builds anything.

The tag is `caddy-<CADDY_VERSION>-<revision>`. `<CADDY_VERSION>` is read from
the `ARG CADDY_VERSION=` line in the Dockerfile, so a change there changes the
tag with it. `<revision>` is a positive integer you choose: the next one not
yet used for that Caddy version. Rebuilding a revision that exists is refused (the run fails at the
step that checks for the tag and pushes nothing), so a pushed tag is never
overwritten; dispatch again with the next number. There is no `latest` tag.

Start the run, with `<N>` the revision:

```bash
gh workflow run publish-edge-caddy.yml --repo branchLeft/shared-infra --ref main -f revision=<N>
```

Wait for it, then read the digest. The job summary names the commit that was
built, the tag, and the reference to pin on a `Pin this:` line; the same
reference is in the log of the digest step:

```bash
run_id="$(gh run list --workflow publish-edge-caddy.yml --repo branchLeft/shared-infra --limit 1 --json databaseId --jq '.[0].databaseId')"
gh run watch "$run_id" --repo branchLeft/shared-infra --exit-status
gh run view "$run_id" --repo branchLeft/shared-infra --log | grep -o 'ghcr.io/branchleft/edge-caddy@sha256:[0-9a-f]*' | sort -u
```

The workflow builds from `hetzner/edge/Dockerfile` unchanged, so the build
still fails rather than succeeding quietly if either module is missing: the
final stage asserts that `rate_limit`, `appsec` and `crowdsec` are all
registered Caddy modules.

**First push only — make the package public.** A container package is created
private, and a private package needs a pull credential on the host, which this
estate deliberately does not carry. Go to
<https://github.com/orgs/branchLeft/packages/container/edge-caddy/settings>,
"Change package visibility", choose Public, confirm. This is a platform-owner
action; there is no reviewed path to it.

**First run only — let the workflow write the package.** The package was first
created with a personal token, so the `shared-infra` repository has no access
to it yet. If the first run is refused with `denied` at the check for the tag
or at the push, open the same settings page, add the `shared-infra` repository
under "Manage Actions access" with the Write role, and dispatch again.

Once the package is public, the digest can be cross-checked against the
registry, with `<N>` the revision that was dispatched:

```bash
docker buildx imagetools inspect ghcr.io/branchleft/edge-caddy:caddy-2.11.4-<N> \
  --format '{{.Manifest.Digest}}' | grep -o 'sha256:[0-9a-f]*' | head -1
```

Keep the digest. Everywhere below it is written `<DIGEST>`, and it means the
**full** `sha256:<hex>` form: `branchleft-deploy` refuses a bare hex digest
with `image reference must be digest-pinned`, because `name@<hex>` without
the algorithm prefix is not a valid OCI reference. The `grep` in the
cross-check is not decoration: `imagetools inspect` has been observed printing
a `Name:`/`MediaType:`/`Digest:` block despite the `--format`, and the filter
yields the bare `sha256:…` value on either output shape. Both traps have
caught a redeploy before.

## 2. Validate the configuration against the image that will run it

Catches an unrecognised directive or a module that did not make it into the
build, before anything is deployed:

```bash
docker run --rm --platform linux/amd64 \
  --env CROWDSEC_BOUNCER_KEY=validation-only \
  --env ACME_EMAIL=validation@example.invalid \
  --volume "$PWD/hetzner/edge/stack/caddy/Caddyfile:/etc/caddy/Caddyfile:ro" \
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

The Caddyfile now lives in the `caddy/` directory, and the container mounts that
directory, so the file a deploy puts there is the file the container reads. On a
host that was deployed before this layout, the copy above creates
`caddy/Caddyfile` and `--delete` removes the old top-level `Caddyfile`. The
running container keeps its old mount of the removed file until the unit is
recreated, so the first deploy of this layout is followed by a recreate of the
caddy service (step 6), not a reload.

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

| Switch                      | Committed state | What that means here                                           |
| --------------------------- | --------------- | -------------------------------------------------------------- |
| `crowdsec`                  | `enforcing`     | in-band 403 on known-bad shapes, and banned addresses refused  |
| `rateLimit`                 | `enforcing`     | the general 200/60s per-address throttle is on for every block |
| `membersMagicLinkRateLimit` | `enforcing`     | POSTs to Ghost's magic-link path are throttled at 5/60s        |

All checks go through the loopback probe listener, which carries the same
handler chain as a public site and answers 204.

**Both directions matter.** Checks (a) and (b) are a matched pair: (a) proves
the general throttle is present and trips, (b) proves the magic-link throttle is
present and trips on its own, tighter budget. Both expect a `429`, so neither
passes if the whole `rate_limit` module has silently failed to load
(`branchLeft/workspace#209`).

`$EDGE1_IPV4` is set under "What has to be true first" above; re-set it
first if you are entering this section independently — every check below
reuses it.

**a. The general throttle is on, and trips.** 250 requests inside the 60-second
window, against a 200-request limit on the loopback probe's own zone
(`probe_per_ip`):

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  for i in $(seq 1 250); do
    curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/
  done | sort | uniq -c'
```

Expect about `200 204` followed by about `50 429`. No `429` at all means the
general throttle is not rendered in the deployed Caddyfile — stop and read
`hetzner/edge/posture.ts` and `hetzner/edge/stack/caddy/Caddyfile` in the deployed
commit. Note this is a `GET` to `/`, so it never touches the magic-link zone; the
two counters are independent by construction. **Leave 60 seconds before check
(b)**: `probe_per_ip` is now spent, and check (b)'s `POST`s pass through the same
general throttle first, so running them straight away reads `429` for the wrong
reason.

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
own 200-request budget, which check (a) has already confirmed is on.

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
`hetzner/edge/stack/caddy/Caddyfile` was never `rsync`ed onto the host, or the
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
and was answered normally, because the Core Rule Set is loaded out-of-band: it
alerts and never refuses a request, in every posture.

**d. The detection is recorded.**

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  CROWDSEC_CTR=$(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=crowdsec) &&
  docker exec "$CROWDSEC_CTR" cscli alerts list --limit 20 &&
  docker exec "$CROWDSEC_CTR" cscli decisions list'
```

Expect at least one alert naming an AppSec scenario. Decisions may be empty or
may list bans; with the IP-decision handler committed, a listed ban is refused
at the edge, and the review in step 9 is about whether each one is deserved.

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

| Switch                      | State                             | Where it is verified                                                 |
| --------------------------- | --------------------------------- | -------------------------------------------------------------------- |
| `membersMagicLinkRateLimit` | **`enforcing`** — already flipped | §8b                                                                  |
| `rateLimit`                 | **`enforcing`** — committed       | §10a: the pre-apply check gates the apply; §8a proves it trips after |
| `crowdsec`                  | **`enforcing`** — committed       | §10b: the in-band 403 and the IP-decision handler are both in force  |

`rateLimit` is committed as `enforcing`, but committing does not deliver it:
`hetzner/edge/stack/**` reaches `edge1` only through the gated apply, and §10a's
pre-apply check is the go/no-go for that apply. Turn the remaining switch
(`crowdsec`) on after it, with time between them: the throttle is reversible and
low-consequence, and the WAF is the one that can lock an author out.

### 10a. The general page-serving throttle

The general throttle is committed as `enforcing` at the parity value:
`RATE_LIMIT_EVENTS` is 200 per 60 seconds per direct peer address, answered
`429`, on the owner's ruling to turn it on. It throttles every block built
through the protection chain — site, redirect, static and probe blocks — and not
the `:9091` metrics listener. Steps 1 to 3 below are done in the pull request
that committed it.

The number was carried over from the retired edge, whose rule was live at
`preview: true` and never enforced anything. The key is the direct peer (`{http.request.remote.host}`), which can
also collapse real clients onto a Docker bridge address such as `172.18.0.1`
behind the docker-proxy, so that every collapsed client shares one budget per
site. `RateLimitDecliningRealClients` excludes `172.16.0.0/12` keys, so that
collapse would not alert on its own; the tripwire is the blackbox probes seeing
`429`.

**Pre-apply check: the go/no-go, run before step 4.** Read the access
log, which `posture.ts` names as this throttle's observation instrument and
which is enabled in every posture. The command below prints the distribution of
requests per client address per minute, and the count and share of IP-minutes
whose address is in `172.16.0.0/12` (the bridge check), and **no addresses**, so
client IPs stay on the host. `$EDGE1_IPV4` is set under "What has to be true
first" above; re-set it first if you are entering this section independently:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  'docker exec $(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=caddy) \
     sh -c "cat /var/log/caddy/access.log"' |
python3 -c '
import sys, json, collections, ipaddress
buckets = collections.Counter()
bridge = ipaddress.ip_network("172.16.0.0/12")
for line in sys.stdin:
    try: e = json.loads(line)
    except ValueError: continue
    ip = e.get("request", {}).get("remote_ip")
    ts = e.get("ts")
    if ip and ts: buckets[(ip, int(ts // 60))] += 1
counts = sorted(buckets.values())
n = len(counts)
def in_bridge(ip):
    try: return ipaddress.ip_address(ip) in bridge
    except ValueError: return False
bridged = sum(1 for (ip, _minute) in buckets if in_bridge(ip))
print("IP-minutes observed:", n)
print("IP-minutes keyed on 172.16.0.0/12:", bridged, f"({100 * bridged / n:.1f}%)" if n else "")
for pct in (50, 90, 99, 99.9):
    print(f"p{pct}:", counts[min(n - 1, int(n * pct / 100))] if n else 0)
print("max:", counts[-1] if counts else 0)
'
```

Check the window the log actually covers before trusting the figures — it
rotates. **Go** means p99.9 sits well below 200 per IP-minute and no material
share of IP-minutes is keyed on `172.16.0.0/12`. **No-go** means p99.9 is near or
above 200, or a material share is bridge-keyed: hold the apply and request a
change to the threshold or the key as a separate pull request. The code that
renders the throttle is the same either way. Also read the figures for the
traffic most likely to exceed 200 per minute from one address: Nextcloud sync on
`cloud.branchleft.co.uk` (100MiB bodies), shared office or NAT addresses, and the
Prometheus blackbox prober.

Then:

1. Done: `rateLimit: 'enforcing'` is set in `hetzner/edge/posture.ts`, with
   `RATE_LIMIT_EVENTS` at the parity value.
2. Done: `cd hetzner && pnpm run render` rewrote `hetzner/edge/stack/caddy/Caddyfile`.
3. Done: both landed in one pull request. `pnpm run test` fails if the rendered
   file and the posture disagree, so they cannot land apart.
4. After the go decision above and after merge, on an up-to-date checkout of `main`, repeat step 4 (`rsync`) and
   then reload Caddy in place, which needs no new image. The reload hands the
   new configuration to the running process and keeps its listeners, so the blog
   keeps answering while it happens. Use it for every Caddyfile or snippet
   change, including the posture flips in this section.

   A successful reload prints nothing: it exits `0` and writes no line. Caddy
   v2.11.4 (the pinned version) returns an error and keeps the previous
   configuration running when the new one fails to load.

**Not `systemctl restart branchleft-compose@edge`.** That unit carries no
`ExecStop` since `hetzner/provision/branchleft-compose@.service` changed, so a
restart runs `docker compose up -d` and Compose recreates only services whose
_config hash_ moved. The **contents** of a bind-mounted file or directory are not part of that
hash, so a Caddyfile-only change is a silent no-op: the command exits 0,
`--wait` passes because the unchanged containers are already healthy, and Caddy
goes on serving the configuration it loaded at container start. This was
observed on the monitoring stack the same day it landed
(branchLeft/workspace#666) and again here.

The `edge` instance is deliberately **not** given the blanket
`--force-recreate` that the monitoring instance gets: recreating this stack
wholesale on every unit restart would also recreate CrowdSec, and
`branchleft-deploy` restarts this unit for image bumps where a selective
recreate is the correct behaviour. A Caddyfile change therefore goes through
the reload below, which needs no recreate. The recreate survives only for a host
still on the old single-file mount: its first deploy of the directory layout
recreates caddy, as step 4 describes and the restart in step 6 performs.

**Validate before reloading.** The copy is already on disk at this point, so
the running container can parse it without adopting it:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  'docker exec $(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=caddy) caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile'
```

Expect `Valid configuration`. CI validates the file in the repository; this
validates the bytes that survived the `rsync`, in the pinned binary, with the
file where Caddy will actually read it. Caddy terminates TLS for every hostname
this edge serves, so a reload onto a config it cannot parse fails and leaves the
previous configuration running. Validate first anyway, so the error is seen
before the reload rather than in its output.

**Check the mount before reloading.** The container mounts the directory
`caddy/`, not the file, so a file that `rsync` renames into place is the file the
container reads. This check is what proves it on the running container: a host
still on the earlier single-file mount, or a container started before the copy,
can hold an older file, and a reload would then load bytes that are not the ones
in the repository. The two hashes below must match:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  cd /opt/branchleft/edge && set -a && . /etc/branchleft/edge.image.env && . /etc/branchleft/edge.env && set +a
  sha256sum caddy/Caddyfile | cut -c1-64
  docker compose exec -T caddy cat /etc/caddy/Caddyfile | sha256sum | cut -c1-64'
```

Expect two identical 64-character lines. Different lines: do not reload; use the
fallback below.

**Reload, with the probe running across it.** The probe loop starts before the
reload, so it samples the edge before, during and after:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  cd /opt/branchleft/edge && set -a && . /etc/branchleft/edge.image.env && . /etc/branchleft/edge.env && set +a
  ( for i in $(seq 1 60); do
      curl -s -o /dev/null -w "%{http_code}\n" -H "Host: edge-probe.invalid" http://127.0.0.1:8080/
      sleep 0.5
    done | sort | uniq -c > /tmp/edge-reload-probe.txt ) &
  LOOP=$!
  docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
  RELOAD=$?
  wait $LOOP
  echo "reload exit $RELOAD"
  cat /tmp/edge-reload-probe.txt'
```

Expect `reload exit 0`, and the probe lines `60 204` and nothing else. Any `000`
or `5xx` line is an outage during the reload: stop and report it before going
further.

**The blog's continuity.** Until `blog.branchleft.co.uk` resolves to edge1
(§11 step 4), the probe loop is the only path this runbook can take through the
edge, so it is the blog's continuity check too. Once the hostname resolves here,
run the same loop from the workstation against `https://blog.branchleft.co.uk/`
in a second terminal while the reload runs, and expect only the blog's normal
success code, `200`.

**Read-back that the new rule is live.** Step 5 reads the rate-limit rule through
§8a's loop. This marker shows the host-qualified site block is the one answering
after the reload. It spends one event of the magic-link budget, so leave 60
seconds before the §8 checks:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  curl -s -o /dev/null -D - -X POST -H "Host: edge-probe.invalid" \
    http://127.0.0.1:8080/members/api/send-magic-link | tr -d "\r" | grep -i "^x-edge-probe"'
```

Expect `X-Edge-Probe: host-routed`.

**Fallback: restart.** Use a restart only if the reload exits non-zero and
`caddy validate` above still passes, or the mount hashes differ. A restart drops
every site for a few seconds, which is why it is not the first choice. Re-create
the container so it binds the file on disk; a plain `docker restart` is not the
fallback, because it keeps the mount the container was created with:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  cd /opt/branchleft/edge && set -a && . /etc/branchleft/edge.image.env && . /etc/branchleft/edge.env && set +a &&
  docker compose up -d --force-recreate caddy'
```

Then run the §7 check. Expect `Up (healthy)` for the Caddy container.

5. Confirm it took, with §8a's loop. Expect roughly `200 204` followed by
   `50 429`, as §8a now asserts, and then watch for `429`s on the public
   hostnames from addresses that are not the bridge.

**Rollback.** Revert the posture change (`rateLimit: 'off'`), re-run
`pnpm run render`, merge, and redeliver as in step 4.

**Counters are in-memory and per-process.** This runbook has not observed whether
a reload resets them, so read §8a's figures after the reload rather than assuming
a fresh budget for every client. The reason sustained-attack behaviour cannot be
reasoned about across a deploy still holds.

**Neither the flip nor its verification runs itself:** merging the posture
change does not deploy it, and does not run the loop. Both are steps 4 and 5
above, performed by whoever holds `~/.ssh/id_ed25519_hetzner`.

### 10b. The WAF and IP remediation

Same four steps. The committed `crowdsec: 'enforcing'` loads the in-band AppSec
configuration in `crowdsec/acquis.d/appsec.yaml`, so a known-bad request shape
gets a 403, and puts the IP-decision handler in every protected Caddy route
chain, so a banned address is refused ahead of the proxy. Setting
`crowdsec: 'inband-only'` takes the handler out again and leaves the 403.

When the checker is slow or down the edge lets requests through: the AppSec
verdict is bounded at one second and then waived (`appsec_fail_open`), and the
bouncer is not set to refuse when it cannot reach CrowdSec, so a stopped
CrowdSec leaves the last decisions in force and everything else served.

Confirm it took. `$EDGE1_IPV4` is set under "What has to be true first"
above; re-set it first if you are entering this section independently:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/.env'
```

Expect `403`. `/.env` trips an in-band virtual-patching rule, so it is refused
before the request proceeds — the behaviour the retired edge declared for its
`lfi` ruleset.

**A block is not where it ends.** In-band blocks feed
`crowdsecurity/appsec-vpatch`, a leaky bucket at `capacity: 1` counting distinct
rule names per address, so a **second** distinct in-band rule match from the same
address inside 60 seconds becomes a ban across every hostname on the edge for
the profile's duration. Out-of-band matches do the same at `capacity: 5`. The
retired edge's rules answered 403 and never touched the address.
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
2. `cd hetzner && pnpm run render`, commit both files, open a pull request.
3. After merge: `rsync` (step 4) and reload (step 10a.4).
4. **Only then** cut the hostname's DNS at IONOS to `$EDGE1_IPV4`. The order
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
   cd /opt/branchleft/edge && set -a && . /etc/branchleft/edge.image.env && . /etc/branchleft/edge.env && set +a &&
   docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile'
```

Then run §10a.4's mount check and probe read-back in full, and expect the same
results.

**A rollback is applied by the reload, not by the unit.** A rollback is reached
for during an outage, and `systemctl restart branchleft-compose@edge` would
restore the previous file to disk and leave the broken configuration running in
memory — exit 0, containers healthy, nothing fixed, and the one signal saying the
rollback worked pointing the wrong way. The reload is what loads the restored
file. If it fails, Caddy keeps the broken configuration running; use the fallback
in §10a.4 step 4.

Then `git checkout HEAD -- hetzner/edge/stack` on the workstation, so the
checkout stops describing a state the repository does not hold.

**Image** — re-run the deploy wrapper with the previous digest:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" \
  '/usr/local/sbin/branchleft-deploy edge ghcr.io/branchleft/edge-caddy@<PREVIOUS_DIGEST>'
```

The wrapper does this itself when a restart fails. Running it by hand is for the
case where the stack started cleanly and is behaving wrongly.

## Log retention

Every edge log keeps 30 days (`roll_keep_for 720h`), rolls daily at 00:00 UTC
(`roll_at 00:00`) and keeps up to 31 rolled files (`roll_keep 31`). The values are
`LOG_RETENTION`, `LOG_ROLL_AT` and `LOG_ROLL_KEEP` in `hetzner/edge/render.ts`.

A change to any of these is a log output option, and Caddy reads those only when the
server starts. `caddy reload` does not apply it. After a deploy that changes retention or
rotation, recreate the caddy container with the `--force-recreate caddy` command in the
§10a restart fallback, and then run the check below. Do not change the role's reload behaviour to get around this.

Read-only check on edge1, after the deploy. It asks the running Caddy for the configuration
it loaded and prints the rotation settings it found, with a count for each:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"$EDGE1_IPV4" '
  cd /opt/branchleft/edge && set -a && . /etc/branchleft/edge.image.env && . /etc/branchleft/edge.env && set +a
  docker compose exec -T caddy wget -qO- http://127.0.0.1:2019/config/ | grep -o "\"roll_[a-z_]*\":[^,}]*" | sort | uniq -c
  grep -c "output file" caddy/Caddyfile'
```

Expect, on every log, `"roll_at":["00:00"]`, `"roll_keep":31` and `"roll_keep_days":30`,
each with the same count, and that count equal to the last line (the number of `output
file` blocks on disk). A `"roll_keep_days":90`, a `"roll_keep":10`, or no `"roll_at"` line
means edge1 is still running the old configuration: recreate the caddy container and run the
check again.

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
