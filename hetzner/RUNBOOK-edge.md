# Runbook — the edge stack on `edge1`

Deploying Caddy and CrowdSec onto `edge1`, verifying that the edge detects
without acting, and later turning enforcement on.

`edge1` is `46.225.95.167` (private `10.20.1.10`), a `cx23` in `nbg1`. Every
`ssh`/`scp` below uses the platform owner's key, `~/.ssh/id_ed25519_hetzner` —
the one registered in the hcloud project and injected on `root` at server
creation. The CI deploy account cannot run any of this and is not meant to.

Run every workstation command from the root of a `branchLeft/shared-infra`
checkout.

Addresses are written out rather than left as `<host-ipv4>` placeholders, unlike
the sibling `RUNBOOK-provision-host.md`. That runbook is generic — it applies to
any newly created host — and this one is about one host that already exists, so
every command here is meant to be runnable as read, with nothing to resolve
first.

## What has to be true first

`RUNBOOK-provision-host.md` must have been run against `edge1`. This runbook
assumes Docker, `branchleft-compose@.service` and
`/usr/local/sbin/branchleft-deploy` are already installed. Confirm in one
command:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
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
Nothing else belongs there today, but check before running it a second time:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'test -f /etc/branchleft/edge.env && grep -c . /etc/branchleft/edge.env || echo "absent"'
```

`absent`, or `2`, means there is nothing to lose. Anything else: edit the file
in place instead of running the next command.

Substituting a real mailbox for `ACME_EMAIL`:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
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
verbatim.

```bash
rsync -av --delete -e 'ssh -i ~/.ssh/id_ed25519_hetzner' \
  hetzner/edge/stack/ root@46.225.95.167:/opt/branchleft/edge/
```

`--delete` is deliberate: a stale acquisition file left behind from an earlier
copy is a CrowdSec configuration nobody is reading in the repository.

## 5. Enable the unit

Once, so the stack comes back after a reboot:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'systemctl enable branchleft-compose@edge'
```

## 6. Deploy

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  '/usr/local/sbin/branchleft-deploy edge ghcr.io/branchleft/edge-caddy@<DIGEST>'
```

Expect `branchleft-deploy: edge now pinned to ghcr.io/branchleft/edge-caddy@<DIGEST>`.

The wrapper refuses anything that is not digest-pinned, writes the pin
atomically, and restarts the unit. If the restart fails it puts the previous
digest back and restarts again, so a bad image leaves the host on the last one
that worked — except on the very first deploy, where there is nothing to fall
back to and it says so.

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
neither secret.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  docker ps --filter label=com.docker.compose.project=edge &&
  CROWDSEC_CTR=$(docker ps -q --filter label=com.docker.compose.project=edge --filter label=com.docker.compose.service=crowdsec) &&
  docker exec "$CROWDSEC_CTR" cscli appsec-configs list &&
  docker exec "$CROWDSEC_CTR" cscli bouncers list'
```

Expect two containers listed, both `Up`, and one bouncer named `caddy` with a
recent "last pull".

`appsec-configs list` shows more than the two configurations `compose.yml`
enables: the hub installs their dependencies too, on first start. On `edge1`,
2026-08-19, the four enabled were `crowdsecurity/appsec-default`,
`crowdsecurity/crs`, `crowdsecurity/generic-rules` and
`crowdsecurity/virtual-patching` — the last two pulled in by the first two,
not set anywhere in this repo. Seeing four names rather than two is not a
fault to chase. Which of them is _loaded_ is decided by
`crowdsec/acquis.d/appsec.yaml`, so turning enforcement on later does not
depend on the CrowdSec hub being reachable at that moment.

## 8. Verify detect-only

Detect-only means: CrowdSec sees everything and records what it would act on,
and nothing is blocked or throttled. Three checks, all through the loopback
probe listener, which carries the same handler chain as a public site and
answers 204.

**a. Nothing is throttled.** 250 requests inside the 60-second window that
would trip a 200-request limit:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  for i in $(seq 1 250); do
    curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/
  done | sort | uniq -c'
```

Expect `250 204` and no `429`. A `429` here means the posture is not
detect-only — stop and read `hetzner/edge/posture.ts` in the deployed commit.

**b. An attack is seen and not blocked.**

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
  curl -s -o /dev/null -w "%{http_code}\n" \
    "http://127.0.0.1:8080/?id=1%27%20OR%20%271%27%3D%271"'
```

Expect `204`. The request reached the WAF, tripped an OWASP Core Rule Set rule,
and was answered normally — which is the whole of what detect-only means.

**c. The detection is recorded.**

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
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

What the review is looking for, on the host:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
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

Enforcement is two independent switches in `hetzner/edge/posture.ts`, and each
is flipped by a pull request, never by a redeploy. Flipping one changes the
rendered files under `hetzner/edge/stack/`, so the diff a reviewer reads is
literally the configuration the host will run.

Turn them on one at a time, in this order, with time between them: the throttle
is reversible and low-consequence, and the WAF is the one that can lock an
author out.

### 10a. The throttle

1. In a branch, set `rateLimit: 'enforcing'` in `hetzner/edge/posture.ts`.
2. `cd hetzner && npm run render` — this rewrites `hetzner/edge/stack/Caddyfile`.
3. Commit both files together and open a pull request. `npm test` fails if the
   rendered file and the posture disagree, so they cannot land apart.
4. After merge, on an up-to-date checkout of `main`, repeat step 4 (`rsync`) and
   then restart, which needs no new image:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'systemctl restart branchleft-compose@edge'
```

5. Confirm it took, with step 8a's loop. Expect roughly `200 204` followed by
   `50 429` rather than `250 204`.

### 10b. The WAF and IP remediation

Same four steps with `crowdsec: 'enforcing'`, which changes both the Caddy
route chain and `crowdsec/acquis.d/appsec.yaml`.

Confirm it took:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
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
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 '
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
5. Watch issuance:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'journalctl -u branchleft-compose@edge --since "10 min ago" | grep -i certificate'
```

## 12. Rolling back

A bad configuration and a bad image roll back differently.

**Configuration** — restore the previous `hetzner/edge/stack/` from git and
re-copy:

```bash
git checkout <PREVIOUS_MERGED_SHA> -- hetzner/edge/stack
rsync -av --delete -e 'ssh -i ~/.ssh/id_ed25519_hetzner' \
  hetzner/edge/stack/ root@46.225.95.167:/opt/branchleft/edge/
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
  'systemctl restart branchleft-compose@edge'
```

Then `git checkout HEAD -- hetzner/edge/stack` on the workstation, so the
checkout stops describing a state the repository does not hold.

**Image** — re-run the deploy wrapper with the previous digest:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@46.225.95.167 \
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
