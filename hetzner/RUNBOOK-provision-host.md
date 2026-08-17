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

## What each script does

| Script                          | Effect                                                                                                                  |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `00-harden-ssh.sh`              | Reasserts the key-only SSH drop-in, then fails the run if `sshd -T` shows another drop-in outranking it                 |
| `10-harden-updates-fail2ban.sh` | Installs and enables `unattended-upgrades` and `fail2ban`, with an SSH jail this repo owns                              |
| `20-install-docker.sh`          | Installs Docker CE from Docker's apt repo, and reconciles the signing key and apt source on every run                   |
| `30-install-deploy-tooling.sh`  | Installs `branchleft-compose@.service` and `/usr/local/sbin/branchleft-deploy`, and verifies the sudoers drop-in parses |

`run-all.sh` runs all four in order. Every one of them is idempotent: re-running
the set is a no-op on a host that is already correct, which is what makes this
the right response to "I am not sure whether that host is current".

## Run the whole set

Substituting the host's own name and public address:

```bash
scp -i ~/.ssh/id_ed25519_hetzner -r hetzner/provision root@<host-ipv4>:/root/platform-provision
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
`passwordauthentication no` with `permitrootlogin prohibit-password`. Anything
else means the run did not complete, and the host should be treated as
unhardened until it does.

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
