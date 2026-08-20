# Runbook — provisioning a newly created host

Run this immediately after the stack that creates a host first applies, and
re-run it any time `provision/` changes. Until it has run, the host is
running the four packages cloud-init installed and nothing else: **no
`fail2ban`, no unattended security upgrades, no Docker, and no deploy
wrapper**, with SSH on the public interface. Treat the gap between creation
and this runbook as the exposure it is, and close it in the same session.

Nothing automates this today. It is a deliberate ordering rather than an
omission — the deploy account this installs does not exist until it has run,
so the first run cannot come from the deploy path it bootstraps.

**A host with no public address needs the estate's egress path to exist first,
and to have existed before the host was created.** "The estate's egress path"
below is the whole of that, and it is a precondition for this runbook rather
than a step inside it.

## What each script does

| Script                          | Effect                                                                                                                  |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `00-harden-ssh.sh`              | Reasserts the key-only SSH drop-in, then fails the run if `sshd -T` shows another drop-in outranking it                 |
| `10-harden-updates-fail2ban.sh` | Installs and enables `unattended-upgrades` and `fail2ban`, with an SSH jail this repo owns                              |
| `20-install-docker.sh`          | Installs Docker CE from Docker's apt repo, and reconciles the signing key and apt source on every run                   |
| `30-install-deploy-tooling.sh`  | Installs `branchleft-compose@.service` and `/usr/local/sbin/branchleft-deploy`, and verifies the sudoers drop-in parses |
| `nat-gateway.sh`                | **Gateway host only.** Installs the NAT reconciler and the unit that reasserts it at boot, then runs it once            |

`run-all.sh` runs the first four in order. Every one of them is idempotent:
re-running the set is a no-op on a host that is already correct, which is what
makes this the right response to "I am not sure whether that host is current".

`nat-gateway.sh` is deliberately outside `run-all.sh`. Exactly one host in the
estate is the gateway, and the script refuses to run anywhere the estate's
egress could not work from.

## The estate's egress path

A host created with `publicNetworking: false` has no public interface, so its
only route off the subnet is the private network's own gateway. Nothing is
routed there until the network stack declares a default route, and nothing
forwards at the far end until one host has been provisioned as the gateway.
Both halves are `branchLeft/shared-infra`'s: the route is in
`hetzner/network.ts`, the forwarding is `provision/nat-gateway.sh`.

**Both have to be live before the private-only host is created**, not merely
before this runbook is run against it. Cloud-init installs `ca-certificates`,
`curl` and `gnupg` at first boot, and `20-install-docker.sh` calls `curl` — a
host that booted without egress is missing all three, and re-running these
scripts is not on its own enough to repair that.

The gateway is `edge1`, at `10.20.1.10`, which is the address the route names.
It is the only host in the estate that already terminates public traffic, so
it is the only one whose forwarding adds no exposure that did not exist.

### 1. Apply the route

`hetzner/` has no CI apply path, so this is run by hand, by the platform
owner, from a checkout of `main` that already contains the route.

Four values have to be in the environment before any command that reads
state: the Object Storage credential for the backend `Pulumi.yaml` pins, and
the stack passphrase. `RUNBOOK-new-stack.md` §1 and §3 are the authority for
both, and for why each is supplied the way it is. The shape is repeated here
rather than cross-referenced alone, because a step whose first command needs
another file is a step nobody completes in one pass.

`read -rs "VAR?prompt"` and not `read -rs -p`: this runs under zsh, where `-p`
reads from a coprocess instead of prompting, and every command downstream then
succeeds against an empty value.

Each read is followed by a non-empty check, and **the check gates the command
that consumes the value rather than trying to abort the block.** That is the
only construct that works here. This is pasted into an interactive shell, so
nothing can stop the lines already in the paste buffer from running: `exit`
would close the terminal, and `return` at an interactive top level sets a
status and carries on. What can be made safe is each step individually — an
empty value writes no file and exports no variable, so the next command fails
for the reason that is true instead of inheriting a bad value.

```bash
cd ~/branchLeft/shared-infra/hetzner

export AWS_REGION=hel1
read -rs "AWS_ACCESS_KEY_ID?Object Storage access key: "; echo
read -rs "AWS_SECRET_ACCESS_KEY?Object Storage secret:     "; echo
if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
else
    echo "empty Object Storage credential: nothing exported, run this block again" >&2
fi

umask 077
read -rs "PASSPHRASE?Stack passphrase: "; echo
if [ -n "$PASSPHRASE" ]; then
    install -m 600 /dev/null ~/.pulumi-passphrase-tmp
    printf '%s' "$PASSPHRASE" > ~/.pulumi-passphrase-tmp
    export PULUMI_CONFIG_PASSPHRASE_FILE=~/.pulumi-passphrase-tmp
else
    echo "empty passphrase: no file written, PULUMI_CONFIG_PASSPHRASE_FILE not set" >&2
fi
unset PASSPHRASE

pulumi stack select production
pulumi stack export --file /tmp/hetzner-network.json
SALT=$(python3 -c "import json; print(json.load(open('/tmp/hetzner-network.json'))['deployment']['secrets_providers']['state']['salt'])")
rm /tmp/hetzner-network.json
printf '\nencryptionsalt: %s\n' "$SALT" >> Pulumi.production.yaml
pulumi config set --secret hcloud:token
pulumi preview --diff
pulumi up
```

The passphrase is the check worth having. Pulumi's passphrase provider does
not distinguish an empty value from an unset one, so a zero-byte file is
accepted as a valid passphrase and the run then fails unwrapping the stack's
data key — an error that names the key, not the passphrase, and sends whoever
debugs it at the stack's secrets rather than at the prompt they fumbled. The
tenant infrastructure CI guards the same thing for the same stated reason.

An empty Object Storage credential is milder but easier to misread: it is a 403. Not exporting it does mean the AWS SDK falls back to any unrelated
profile on the workstation, which `RUNBOOK-new-stack.md` §1 warns about — so
the message says run the block again rather than carry on, and
`pulumi whoami --verbose` is the way to tell which credential is in play.

A 403 from the first `pulumi` command is the credential block above, not a
wrong bucket. `Pulumi.yaml`'s own comment is explicit that a location or
credential mismatch here "reads as a credential problem and sends you to the
wrong place entirely" — check `pulumi whoami --verbose` before believing
anything else about it.

Expect exactly one create, `platform-internet-egress`, and no change to the
network or the subnet. Anything proposing to replace either is a stop — both
are `protect: true`, and a route is additive to both.

Then tear the session down. The `cd` is repeated rather than assumed: a
`git checkout` of a relative path from the wrong directory fails or silently
matches nothing, and what it would have reverted is a passphrase verifier and
a token ciphertext left sitting in the working tree.

```bash
cd ~/branchLeft/shared-infra/hetzner
git checkout -- Pulumi.production.yaml
rm -f ~/.pulumi-passphrase-tmp
unset PULUMI_CONFIG_PASSPHRASE_FILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION
git status --porcelain Pulumi.production.yaml
```

**The last line must print nothing.** Any output means the file still differs
from `main`, which means the checkout did not take and the appended salt and
token ciphertext are still there. `git status` rather than grepping for
`encryptionsalt`: the committed file's own comments discuss that key at
length, so a grep matches whether or not a real value was appended.

None of those lines is optional. The two the recipe appends to
`Pulumi.production.yaml` are a stack passphrase verifier and a token
ciphertext, and neither may be committed.

### 2. Make the gateway forward

From the repository root, not from `hetzner/` — the paths below are
repo-root-relative, and step 1 left the shell one directory down:

```bash
cd ~/branchLeft/shared-infra
scp -i ~/.ssh/id_ed25519_hetzner -r hetzner/provision/. root@<edge1-ipv4>:/root/platform-provision
ssh -i ~/.ssh/id_ed25519_hetzner root@<edge1-ipv4> 'chmod +x /root/platform-provision/*.sh /root/platform-provision/*.py && /root/platform-provision/nat-gateway.sh'
```

Idempotent, and the right response to "is that host still the gateway". Re-run
it after a Docker reinstall: the rules live in netfilter, and the chain they
are inserted into is one Docker owns.

The trailing `/.` on the `scp` source is load-bearing: without it, `scp -r`
copies the directory *inside* the destination once the destination already
exists, nesting a stale copy under a fresh one on any re-run. The destination
itself must carry **no** trailing slash — `scp` in SFTP mode fails outright on
a destination with one if the destination does not yet exist, which is
exactly the first-provision case.

### 3. Confirm the gateway is forwarding

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@<edge1-ipv4> '
  set -e
  test "$(sysctl -n net.ipv4.ip_forward)" = 1
  iptables -t nat -S POSTROUTING | grep -- "-s 10.20.1.0/24 .*-j MASQUERADE"
  iptables -t filter -S DOCKER-USER | grep -- "-s 10.20.1.0/24 .*-j ACCEPT"
  iptables -t filter -S DOCKER-USER | grep -E -- "-d 10.20.1.0/24 .*ctstate (RELATED,ESTABLISHED|ESTABLISHED,RELATED) -j ACCEPT"
  systemctl is-enabled branchleft-nat.service
  echo "gateway ok"
'
```

Expect three rule lines, `enabled`, and `gateway ok`. It exits non-zero on the
first thing that is missing, and the output stops there — so the last line
printed is the check that passed, and the one after it is what to fix.

**All three rules are checked, not just the masquerade, and that is the point
of this block.** The masquerade lives in the `nat` table, which Docker does not
own, so it survives almost everything. The two rules that carry the actual
permission are the filter-chain accepts, and they live in `DOCKER-USER` — a
chain Docker does own, and which `iptables -F`, a `firewall-cmd --reload` or a
change of firewall backend removes on its own. With those gone, the masquerade
still present and the `FORWARD` policy still `DROP`, the estate has **zero
egress** while a masquerade-only check reports success.

`test` rather than reading the `sysctl` output: `sysctl -n` exits 0 whether it
prints `0` or `1`, so a chained `&&` proves only that the command ran.

The return-path rule matches either `ctstate` ordering: `iptables -S` renders
the bitmask `branchleft_nat.sh` sets as `RELATED,ESTABLISHED`, not the order
the script passed it in, and nothing here should depend on which order a given
`iptables` build chooses.

On a gateway with no Docker installed the two filter rules are in `FORWARD`
instead — substitute the chain name. Neither is true of `edge1`, which runs
the Caddy and CrowdSec stack.

A missing `enabled` is the failure that only shows up at the next reboot, when
the estate silently loses its egress.

The three rule checks above only prove the rules are present now, not that
anything caused them to be re-asserted. Docker never flushes `DOCKER-USER`
across a restart, and the masquerade rule lives in the `nat` table, which
Docker does not own at all -- so on a host that is already correctly
configured, all three rules survive a `docker.service` restart whether or
not `PartOf=docker.service` actually reran the reconciler. Proving that needs
a second signal: `branchleft-nat.service`'s own activation timestamp,
captured before and after the restart. Prove both, once, after provisioning:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@<edge1-ipv4> '
  set -e
  BEFORE="$(systemctl show -p ActiveEnterTimestamp --value branchleft-nat.service)"
  systemctl restart docker.service
  AFTER="$(systemctl show -p ActiveEnterTimestamp --value branchleft-nat.service)"
  test "$BEFORE" != "$AFTER"
  iptables -t nat -S POSTROUTING | grep -- "-s 10.20.1.0/24 .*-j MASQUERADE"
  iptables -t filter -S DOCKER-USER | grep -- "-s 10.20.1.0/24 .*-j ACCEPT"
  iptables -t filter -S DOCKER-USER | grep -E -- "-d 10.20.1.0/24 .*ctstate (RELATED,ESTABLISHED|ESTABLISHED,RELATED) -j ACCEPT"
  echo "gateway survives a docker restart, reconciler reran at $AFTER"
'
```

The timestamp check runs first and is the one that actually exercises
`PartOf=docker.service`: if it never fired, `branchleft-nat.service` was
never restarted, `$BEFORE` and `$AFTER` are identical, and the command stops
there -- before the three rule checks get a chance to pass for the wrong
reason. Those still run afterward, on the same exit-on-first-miss shape as
the boot-time check above, because a reconciler that reran and still left a
rule missing is a different failure worth telling apart from one that never
ran at all. A command that hangs instead of returning means the restart
wedged rather than completed; `systemctl status branchleft-nat.service
docker.service` on the host is the first thing to read.

### 4. Provision a host that has no public address

Reached through the gateway, over the private network — no firewall rule
filters private traffic, so nothing had to be opened for this.

```bash
JUMP="ssh -i ~/.ssh/id_ed25519_hetzner -W %h:%p root@<edge1-ipv4>"
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@<host-private-ip> '
  getent hosts deb.debian.org &&
  curl -fsS -o /dev/null https://download.docker.com/linux/debian/gpg &&
  echo "egress ok"
'
```

`ProxyCommand` rather than `-J`: the identity given with `-i` applies to the
target connection only, and the jump host needs the same key. Both hosts carry
the platform owner's key on `root`, so one `-i` in each half of the command is
all it takes.

Run that check **before** the provisioning set, not after. `egress ok` is the
proof that step 1 and step 2 both took; without it every failure downstream
presents as a broken package mirror.

Then the same two commands as "Run the whole set" below, with the jump added,
from the repository root:

```bash
cd ~/branchLeft/shared-infra
scp -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" -r hetzner/provision/. root@<host-private-ip>:/root/platform-provision
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="$JUMP" root@<host-private-ip> 'chmod +x /root/platform-provision/*.sh /root/platform-provision/*.py && /root/platform-provision/run-all.sh'
```

That `scp -r` copies the whole of `provision/` — `nat-gateway.sh`,
`branchleft_nat.sh` and the unit file included. They land on the host and must
never be run there: a second host masquerading the subnet builds a path
nothing routes to, and `run-all.sh` does not touch any of the three.

### What this does not solve

The gateway is a single point of failure for every private host's outbound
traffic, including the security updates `unattended-upgrades` fetches for the
life of the host. An `edge1` that is down or wedged is an estate whose private
hosts stop being patched, and nothing reports that today — the failure is
silent until someone looks. Monitoring it belongs with the monitoring host.

## Run the whole set

Substituting the host's own name and public address. A host with no public
address is provisioned through the gateway instead — step 4 above carries the
same two commands with the jump added:

```bash
scp -i ~/.ssh/id_ed25519_hetzner -r hetzner/provision/. root@<host-ipv4>:/root/platform-provision
ssh -i ~/.ssh/id_ed25519_hetzner root@<host-ipv4> 'chmod +x /root/platform-provision/*.sh /root/platform-provision/*.py && /root/platform-provision/run-all.sh'
```

The key is the platform owner's — the one registered in the hcloud project and
injected on `root` at server creation. The CI deploy key cannot do this and is
not meant to: it reaches one command, and installing that command is the step
being performed here.

## Confirm it took

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@<host-ipv4> '
  systemctl is-active fail2ban unattended-upgrades docker &&
  test -x /usr/local/sbin/branchleft-deploy &&
  systemctl cat branchleft-compose@.service >/dev/null &&
  sshd -T | grep -E "^(passwordauthentication|permitrootlogin) "
'
```

Expect three `active` lines, no output from the two `test`/`cat` checks, and
`passwordauthentication no` with `permitrootlogin` reading either
`prohibit-password` or `without-password` -- OpenSSH treats them as the same
setting, and `sshd -T` on some distributions normalises to the deprecated
spelling. Any other value means the run did not complete, and the host
should be treated as unhardened until it does.

`00-harden-ssh.sh` already asserts the same values from `sshd -T` and exits
non-zero if any drop-in outranks its own, so a clean `run-all.sh` has proved
this too. It is repeated here because this block is also the answer to "is
that host still correct" months later, when nobody has run the scripts
recently.

## Rotating the deploy key

The programme accepts a long-lived SSH deploy key in GitHub Actions secrets —
a weaker posture than the federated identity the GCP stacks use — on the
condition that rotation is a documented procedure rather than an intention.
This is that procedure.

**It cannot go through Pulumi.** `deployPublicKey` reaches the host through
cloud-init, and `userData` is in the component's `ignoreChanges` because
cloud-init has already run and the provider would otherwise propose rebuilding
the host. Changing the value in stack config is therefore a permanent silent
no-op: the preview is clean, the apply succeeds, and the host keeps the old
key. Update the config for accuracy if you like, but it is documentation, not
a mechanism.

Rotation is: write the new key, prove it works, then remove the old one. Never
collapse those into one step — a single-step swap that fails leaves no way in.

```bash
# 1. Generate the replacement, on the workstation.
ssh-keygen -t ed25519 -N '' -C 'deploy@<host>' -f ~/.ssh/id_ed25519_deploy_<host>_new

# 2. Append the public half, as root. The deploy account cannot edit its own
#    authorized_keys -- that is deliberate, and it is why this needs the
#    owner key.
ssh -i ~/.ssh/id_ed25519_hetzner root@<host-ipv4> \
  "printf 'restrict %s\n' \"$(cat ~/.ssh/id_ed25519_deploy_<host>_new.pub)\" \
   >> /home/deploy/.ssh/authorized_keys"

# 3. Prove the new key works before anything is removed.
ssh -i ~/.ssh/id_ed25519_deploy_<host>_new deploy@<host-ipv4> \
  'sudo -n /usr/local/sbin/branchleft-deploy 2>&1 | head -1'
```

Expect the wrapper's usage line. That proves the key authenticates _and_ that
sudo still grants the one command — a key that logs in but cannot deploy is
not a working rotation.

4. Replace the private half in the GitHub Actions secret for the repository
   that deploys this host, then run one real deploy through CI and watch it
   succeed.

5. Only then remove the old key's line from `/home/deploy/.ssh/authorized_keys`
   on the host, and delete the old private key from the workstation.

The `restrict` prefix in step 2 is not optional. Without it the new key has
agent and port forwarding that the old one did not, which is a quiet
privilege upgrade in the middle of a rotation.

## Then deploy a stack onto it

Per-role service provisioning — Caddy and CrowdSec on the edge, MySQL on the
database host, the Prometheus stack on the monitoring host — is not here. It
belongs with the stack that owns that role. What this runbook guarantees is
the base every one of them assumes: a hardened host with Docker, the Compose
unit template, and a deploy account that can pin an image and restart a stack.
