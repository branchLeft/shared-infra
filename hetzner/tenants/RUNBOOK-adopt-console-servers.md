# Runbook — adopting the tenants project's hand-made servers

`edge-t`, `db-t1` and `app-t1` were made by hand in the Hetzner Console, in the
`tenants` project, as CX23, in `nbg1`, on Debian 13, with the SSH key registered
as `rob@branchleft.co.uk`. This runbook brings them under the tenants stack
(`hetzner/tenants.ts`) without creating, replacing or rebuilding any of them.
Everything here is the platform owner's: it reads and changes production, and
nothing in it is run by an agent.

The tenants stack is **not** applied by CI. Merging the change that carries this
runbook changes no server. The applies below are the owner's hand applies, which
`CLAUDE.md` allows for first-time provisioning and gated migrations.

## What the servers look like when this starts

- One console firewall, `hold-no-inbound`, is attached to all three. It has no
  inbound rule (SSH and ICMP included are dropped) and no outbound rule (all
  outbound is allowed). It is the only thing between each public server and the internet,
  so **it is never detached from a public server before the stack's own firewall is attached to that same server**. A public server with no firewall attached is open to the internet. A private-only server has no public interface for a firewall to filter: `hold-no-inbound` stays attached to it and is never detached.
- `edge-t` has a public IPv4 and IPv6 address.
- `db-t1` and `app-t1` have no IPv4 address. Each is in one of two states, and
  this runbook has a path for each:
  - **Case A.** Attached to the tenants network, with no public address at all.
    `db-t1` is at `10.20.1.200`.
  - **Case B.** Not attached to the network, with a public IPv6 address only.
- Cloud-init has run, but only the image's own: none of this repository's user-data
  ran. The `deploy` account, the SSH hardening and the packages it would have
  installed are not there. Step 4 does by hand what that document does.

## How the stack adopts them

`Host` takes an optional `adopt` argument (`hetzner-host/README.md`, "Adopting a
server made by hand"), set per host in the stack config as `edgetAdopt` and
`dbt1Adopt`. It imports the server and, for a public host, its two primary IPs, by
id. `userData`, `sshKeys`, `image` and `firewallIds` are ignored, so none of the
fields the provider treats as replacing can plan a replacement. `publicNets` is
ignored too, at both stages and on both hosts: the provider never reads a server's
public interface into state, so declaring it would make the first apply power the
server off and delete the primary IP it unassigns. The addresses are held by the
imported primary IP resources.

Adoption has two stages, set with `adopt.stage`:

| Stage                  | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                    | Why                                                                                                                                       |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `import` (the default) | Imports by id and leaves protection, labels and the primary IPs' names and settings alone. Attaches the stack's firewall on a public host.                                                                                                                                                                                                                                                                                                      | Pulumi refuses an import whose inputs differ from the live resource, and a console-made server differs from the program in exactly those. |
| `converge`             | The same program with them declared: an in-place update that turns on delete and rebuild protection, sets the labels, renames the addresses `edge-t-ipv4` and `edge-t-ipv6` and turns off their auto-delete. On a private-only host it checks the network and attaches no firewall: a private-only host has no public interface for one to filter. The absence of a public address is the owner's check in step 9: the stack does not check it. | The host ends exactly as the program declares it.                                                                                         |

Leave `stage: converge` set for the life of the host. Do not remove the adopt
config afterwards: on a public host the firewall attachment is part of it, and removing it would
detach the stack's firewall.

**No unfiltered window.** This applies to hosts with a public interface only. The stack's firewall is attached with a
`FirewallAttachment`, which adds to the firewalls already on the server. The
owner's `hold-no-inbound` stays attached until the stack's firewall is attached and
checked, and is detached by hand after. At no point does a server have no
firewall. The stack never declares `firewallIds` on an adopted server, so it never
plans to rewrite the live set.

**Why `db-t1` and `app-t1` get no firewall attachment.** A Hetzner Cloud Firewall
filters only a server's public interface, and a private-only host has none, so the
provider refuses the attachment ("no public network interfaces found"). The stack
still declares their own firewalls, and `hold-no-inbound` stays on them as an inert
second line. While a leftover public IPv6 address is on the server (case B),
`hold-no-inbound` is what filters it; step 9 removes that address.

**Why the stack does not remove a leftover public address itself.** Unassigning a
primary IP needs the server powered off, and the component's own notes record that
flipping a live host from public to private wedges the stack mid-update. It is a
console step here, done once, with the server off.

## 0. Before anything

The merge of the change that carries this runbook is done, and this checkout is
that commit:

```bash
git -C ~/branchLeft/shared-infra log -1 --oneline
```

Select the hcloud context for the `tenants` project (the same three pastes as
`../RUNBOOK-estate-project-move.md`, step 4):

```bash
hcloud context list
```

```bash
read -r HCLOUD_CONTEXT
```

```bash
hcloud context use "${HCLOUD_CONTEXT}"
```

Check the project is the tenants one. It holds the three servers and the marker
firewall, and nothing else:

```bash
hcloud server list
```

```bash
hcloud firewall list
```

Expect `edge-t`, `db-t1` and `app-t1`, and the firewalls `hold-no-inbound` and
`project-marker-tenants`. If `edge1`, `db1`, `mx1` or any other name appears, the
context is the wrong project: stop.

## 1. Read the ids

The ids are recorded nowhere. Read each from the Console and paste it. In the
Console (the `tenants` project), open **Servers**, then each server: the numeric id
is the number after `/servers/` in the page address and under **Overview**. Primary
IPs are under **Networking**, **Primary IPs**; open `edge-t`'s IPv4 and IPv6 and
read the id from the address the same way.

```bash
read -r EDGET_SERVER_ID
```

```bash
read -r EDGET_IPV4_ID
```

```bash
read -r EDGET_IPV6_ID
```

```bash
read -r DBT1_SERVER_ID
```

Check that each id names the thing you think it does. Each line must print the
name shown:

```bash
hcloud server describe "${EDGET_SERVER_ID}" -o format='{{.Name}}{{"\n"}}'
```

Expect `edge-t`.

```bash
hcloud server describe "${DBT1_SERVER_ID}" -o format='{{.Name}}{{"\n"}}'
```

Expect `db-t1`.

```bash
hcloud primary-ip describe "${EDGET_IPV4_ID}" -o format='{{.Type}} {{.AssigneeID}}{{"\n"}}'
```

Expect `ipv4` and `edge-t`'s server id.

```bash
hcloud primary-ip describe "${EDGET_IPV6_ID}" -o format='{{.Type}} {{.AssigneeID}}{{"\n"}}'
```

Expect `ipv6` and `edge-t`'s server id.

## 2. Checks that stop the runbook

Each of these is read-only. Any answer other than the expected one is a stop, not a
workaround.

The type and location of each server (`cx23`, `nbg1`):

```bash
hcloud server describe "${EDGET_SERVER_ID}" -o format='{{.ServerType.Name}} {{.Datacenter.Location.Name}}{{"\n"}}'
```

```bash
hcloud server describe "${DBT1_SERVER_ID}" -o format='{{.ServerType.Name}} {{.Datacenter.Location.Name}}{{"\n"}}'
```

`edge-t` must **not** already be on a network. The stack attaches it (an in-place
action on the running server), and a hand attachment makes the stack's attachment
fail:

```bash
hcloud server describe "${EDGET_SERVER_ID}" -o format='{{len .PrivateNet}}{{"\n"}}'
```

Expect `0`. If it is `1`, detach it in the Console (**Networking**, the network's
menu, **Detach**) and ask again.

The tenants network. Either it does not exist, or the stack made it. A network
named `tenants` that the stack's state does not hold would make the stack's create
fail on the name, and adopting it is not covered here:

```bash
hcloud network list
```

```bash
cd ~/branchLeft/shared-infra/hetzner/tenants
```

```bash
pulumi stack --show-urns
```

If `hcloud network list` shows `tenants` and `pulumi stack --show-urns` shows no
`hcloud:index/network:Network::tenants`, stop and hand the two outputs back.

For `db-t1` and `app-t1`, which case is each? The first number is how many networks
it is attached to (case A is `1`, case B is `0`); the second is its IPv4 address
(`<nil>` or empty in both cases: if it has one, stop):

```bash
hcloud server describe "${DBT1_SERVER_ID}" -o format='{{len .PrivateNet}} {{.PublicNet.IPv4.IP}}{{"\n"}}'
```

For case A, the address on the network must be the register address, `10.20.1.200`:

```bash
hcloud server describe "${DBT1_SERVER_ID}" -o format='{{range .PrivateNet}}{{.IP}}{{"\n"}}{{end}}'
```

And the firewall on each of the three must be `hold-no-inbound` alone:

```bash
hcloud firewall describe hold-no-inbound -o format='{{range .AppliedTo}}{{.Server.ID}}{{"\n"}}{{end}}'
```

## 3. Open SSH on edge-t for the owner, and only on edge-t

`hold-no-inbound` is shared by all three servers and stays untouched. A separate
temporary firewall carries one rule, on `edge-t` alone, and is deleted in step 11.

The address SSH is accepted from is read, not typed into a file. It is the public
IPv4 address the workstation reaches Hetzner from:

```bash
read -r OWNER_IPV4
```

```bash
case "${OWNER_IPV4}" in ''|*[!0-9.]*) echo "not an IPv4 address: ${OWNER_IPV4}"; false;; esac
```

```bash
hcloud firewall create --name bootstrap-ssh-edge-t
```

```bash
hcloud firewall add-rule bootstrap-ssh-edge-t --direction in --protocol tcp --port 22 --source-ips "${OWNER_IPV4}/32" --description 'owner bootstrap SSH, temporary'
```

```bash
hcloud firewall apply-to-resource bootstrap-ssh-edge-t --type server --server edge-t
```

```bash
EDGET_IPV4=$(hcloud server describe "${EDGET_SERVER_ID}" -o format='{{.PublicNet.IPv4.IP}}')
```

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"${EDGET_IPV4}" 'hostname; id -un'
```

Expect `edge-t` and `root`. The key is `~/.ssh/id_ed25519_hetzner`, the one the other
runbooks here use for the key registered as `rob@branchleft.co.uk`. If SSH is
refused, the Console's server page lists the firewalls it carries: the temporary
one must be there.

## 4. Do by hand what first-boot user-data would have done

The user-data is `renderCloudInit` in `hetzner-host/cloudInit.ts`: it creates the
`deploy` account with the host's CI key (restricted, no shell grants, one sudo
command), writes the SSH hardening drop-in, installs three packages and creates two
directories. This block does the same on a host it did not run on. Run it on
`edge-t` now and on `db-t1` in step 9; it is safe to run twice.

Generate the deploy key for `edge-t`, on the workstation. The private half goes to
the repository's deploy secret as `RUNBOOK-provision-host.md`, "Rotating the deploy
key", describes; the public half goes into the stack config in step 5:

```bash
ssh-keygen -t ed25519 -N '' -C 'deploy@edge-t' -f ~/.ssh/id_ed25519_deploy_edge-t
```

Run the bootstrap on `edge-t`:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"${EDGET_IPV4}" "DEPLOY_PUBLIC_KEY='$(cat ~/.ssh/id_ed25519_deploy_edge-t.pub)' HOST_NAME=edge-t sh -s" <<'BOOTSTRAP'
set -eu
[ "$(hostname)" = "$HOST_NAME" ]
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --comment 'CI deploy account' deploy
passwd -l deploy
install -d -m 0700 -o deploy -g deploy /home/deploy/.ssh
printf 'restrict %s\n' "$DEPLOY_PUBLIC_KEY" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 0600 /home/deploy/.ssh/authorized_keys
printf 'deploy ALL=(root) NOPASSWD: /usr/local/sbin/branchleft-deploy\n' > /etc/sudoers.d/50-branchleft-deploy
chmod 0440 /etc/sudoers.d/50-branchleft-deploy
visudo -cf /etc/sudoers.d/50-branchleft-deploy
install -d -m 0755 -o root -g root /etc/branchleft /opt/branchleft
cat > /etc/ssh/sshd_config.d/01-branchleft-hardening.conf <<'HARDENING'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
HARDENING
chmod 0644 /etc/ssh/sshd_config.d/01-branchleft-hardening.conf
/usr/sbin/sshd -t
systemctl reload ssh
echo bootstrap ok
BOOTSTRAP
```

Expect `bootstrap ok`. The hostname line fails the block, with nothing changed, if
the server's hostname is not `edge-t`. Then confirm the hardening is the one in
force, and that the owner key still gets in:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"${EDGET_IPV4}" 'sshd -T | grep -E "^(passwordauthentication|permitrootlogin) "'
```

Expect `passwordauthentication no` and `permitrootlogin prohibit-password`.

The `deploy` account's one sudo command, `/usr/local/sbin/branchleft-deploy`, is
installed by the provisioning run (`../RUNBOOK-provision-host.md`), not by this
block, exactly as it is for a host that cloud-init created.

## 5. Set up the stack and adopt edge-t (first apply)

The stack needs its token, its passphrase and its backend credentials, set the way
`../RUNBOOK-estate-project-move.md` step 6 sets the estate stack's: the token with
`pulumi config set --secret hcloud:token` (it prompts; pass no value), in the
working copy only, and never committed.

```bash
cd ~/branchLeft/shared-infra/hetzner/tenants
```

Record the deploy key and the adoption of `edge-t`:

```bash
pulumi config set edgetDeployPublicKey "$(cat ~/.ssh/id_ed25519_deploy_edge-t.pub)"
```

```bash
pulumi config set --path edgetAdopt.serverId "${EDGET_SERVER_ID}"
```

```bash
pulumi config set --path edgetAdopt.ipv4Id "${EDGET_IPV4_ID}"
```

```bash
pulumi config set --path edgetAdopt.ipv6Id "${EDGET_IPV6_ID}"
```

The stage is `import` by default; set it so the file says so:

```bash
pulumi config set --path edgetAdopt.stage import
```

Preview, and keep the plan for the delete guard:

```bash
pulumi preview --diff
```

What the preview must show for the first apply:

- `import` of `hcloud:index/server:Server edge-t` and of the two primary IPs
  `edge-t-ipv4` and `edge-t-ipv6`.
- `create` of: the tenants network, its subnet, the `edge-t` firewall, the
  `edge-t-firewall-attachment`, the `edge-t-network` attachment, and the default
  route. Nothing for `db-t1` (`dbt1Enabled` is absent).
- No `replace`, no `delete`, no `update` of `edge-t`'s server naming `userData`,
  `sshKeys`, `image` or `firewallIds`, and no warning that inputs to an import do
  not match the existing resource.

Any `replace` or `delete`, any `create` of an `hcloud:index/server:Server` or of a
primary IP, or an import warning is a stop. A `create` of a server means the adopt
config did not take: do not apply, and do not "fix" it by removing the config.

Run the delete guard against the same plan:

```bash
pulumi preview --json > ~/tenants-adopt-plan.json
```

```bash
python3 ~/branchLeft/shared-infra/scripts/assert-no-hetzner-deletes.py ~/tenants-adopt-plan.json
```

Expect exit status 0. Then apply:

```bash
pulumi up
```

## 6. Detach hold-no-inbound from edge-t, after checking the stack's firewall is on

Two firewalls must be attached to `edge-t`: `hold-no-inbound` and `edge-t`. The
applied-to list of the stack's firewall must name `edge-t`'s id:

```bash
hcloud firewall describe edge-t -o format='{{range .AppliedTo}}{{.Server.ID}}{{"\n"}}{{end}}'
```

Expect `${EDGET_SERVER_ID}`. Its rules must be SSH from edge1's public address as a
/32, 80, 443 and ICMP, and nothing else:

```bash
hcloud firewall describe edge-t
```

Only then:

```bash
hcloud firewall remove-from-resource hold-no-inbound --type server --server edge-t
```

If the first check printed nothing, **do not run the detach**. `edge-t` is held by
`hold-no-inbound` and the temporary firewall alone: stop and hand back the output of
`pulumi preview`.

## 7. Provision edge-t and prove the gateway before db-t1

`edge-t` is the tenants network's gateway. Everything below is in
`../RUNBOOK-provision-host.md`; the part that must be true before step 9 is its
"A second network, a second gateway": the `egress_nat` role converged on `edget`
and the forwarding proven with Docker running. The stack's firewall accepts SSH on
`edge-t` from `edge1`'s address only, so that runbook's commands run from `edge1`;
the temporary firewall from step 3 stays until step 11, so the workstation can
still reach `edge-t` directly for step 9.

"Forwarding proven" is scripted: `RUNBOOK-edget-gateway-proof.md`, its sections 2 and
3, run from the workstation through `edge1`, prove that a source inside
`10.20.1.0/24` reaches the internet only through the masquerade and that a source
outside it gets no reply, red then green. Run them here, before step 9.

## 8. Converge edge-t and adopt db-t1 (second apply)

Generate `db-t1`'s deploy key first, on the workstation. Its public half is read by
the next commands and by step 9:

```bash
ssh-keygen -t ed25519 -N '' -C 'deploy@db-t1' -f ~/.ssh/id_ed25519_deploy_db-t1
```

```bash
cd ~/branchLeft/shared-infra/hetzner/tenants
```

```bash
pulumi config set --path edgetAdopt.stage converge
```

```bash
pulumi config set dbt1Enabled true
```

```bash
pulumi config set dbt1DeployPublicKey "$(cat ~/.ssh/id_ed25519_deploy_db-t1.pub)"
```

```bash
pulumi config set --path dbt1Adopt.serverId "${DBT1_SERVER_ID}"
```

```bash
pulumi config set --path dbt1Adopt.stage import
```

```bash
pulumi preview --diff
```

Expect:

- `edge-t`: updates in place only, to protection, labels, the primary IPs' names
  (`edge-t-ipv4`, `edge-t-ipv6`), their auto-delete (off) and their delete
  protection (on). The addresses themselves do not change. No replace.
- `db-t1`: `import` of the server, `create` of the `db-t1` firewall (declared and never
  attached: a private-only host gets no attachment). No primary IP, no attachment, no update to the network or the public
  interface.

The same stops as step 5 apply. Then the delete guard and the apply, as there:

```bash
pulumi preview --json > ~/tenants-adopt-plan.json
```

```bash
python3 ~/branchLeft/shared-infra/scripts/assert-no-hetzner-deletes.py ~/tenants-adopt-plan.json
```

```bash
pulumi up
```

## 9. Make db-t1 private-only, and bootstrap it

`db-t1` is reached from the workstation through `edge-t`, over the private network,
which no Hetzner firewall filters.

### Case B only: attach the network, bootstrap, then remove the public address

Skip to "Case A and B" if step 2 showed the server on the network at `10.20.1.200`.

Attach the network at the register address. This works on a running server:

```bash
hcloud server attach-to-network "${DBT1_SERVER_ID}" --network tenants --ip 10.20.1.200
```

Bootstrap `db-t1` through `edge-t` (the block below), and prove it, **before**
removing the public address: it is the way in until the private path works.

### Case A and B: bootstrap db-t1

A private-only host's DHCP lease carries the subnet route and never a default, so the
bootstrap sets the default route and the resolvers first. They are the same two
commands `renderCloudInit` runs on every boot of a private-only host, and the
provisioning run installs the permanent unit that replaces them.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="ssh -i ~/.ssh/id_ed25519_hetzner -W %h:%p root@${EDGET_IPV4}" root@10.20.1.200 'hostname; ip -4 route show'
```

Expect `db-t1`, and a route for `10.20.1.0/24` via a gateway. Then the bootstrap
itself:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="ssh -i ~/.ssh/id_ed25519_hetzner -W %h:%p root@${EDGET_IPV4}" root@10.20.1.200 "DEPLOY_PUBLIC_KEY='$(cat ~/.ssh/id_ed25519_deploy_db-t1.pub)' HOST_NAME=db-t1 sh -s" <<'BOOTSTRAP'
set -eu
[ "$(hostname)" = "$HOST_NAME" ]
GW=$(ip -4 route show | awk '$1 != "default" && $1 != "169.254.169.254" { for (i=1;i<=NF;i++) if ($i=="via") { print $(i+1); exit } }')
[ -n "$GW" ] && ip route replace default via "$GW"
mkdir -p /etc/resolvconf/resolv.conf.d
{ echo 'nameserver 185.12.64.1'; echo 'nameserver 185.12.64.2'; } > /etc/resolvconf/resolv.conf.d/head
resolvconf -u || true
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --comment 'CI deploy account' deploy
passwd -l deploy
install -d -m 0700 -o deploy -g deploy /home/deploy/.ssh
printf 'restrict %s\n' "$DEPLOY_PUBLIC_KEY" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 0600 /home/deploy/.ssh/authorized_keys
printf 'deploy ALL=(root) NOPASSWD: /usr/local/sbin/branchleft-deploy\n' > /etc/sudoers.d/50-branchleft-deploy
chmod 0440 /etc/sudoers.d/50-branchleft-deploy
visudo -cf /etc/sudoers.d/50-branchleft-deploy
install -d -m 0755 -o root -g root /etc/branchleft /opt/branchleft
cat > /etc/ssh/sshd_config.d/01-branchleft-hardening.conf <<'HARDENING'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
HARDENING
chmod 0644 /etc/ssh/sshd_config.d/01-branchleft-hardening.conf
/usr/sbin/sshd -t
systemctl reload ssh
echo bootstrap ok
BOOTSTRAP
```

Expect `bootstrap ok`. The `apt-get` lines are the proof that the NAT path from step 7
works; if they fail on name resolution or a timeout, the gateway is not proven: go
back to step 7, do not continue.

Then provision `db-t1` as `../RUNBOOK-provision-host.md`, "5. Provision a host that
has no public address", describes. That installs the permanent default-route unit.

### Case B only: remove the public IPv6 address

Only after the private path above works. The leftover address is filtered by
`hold-no-inbound`, which has no inbound rule, and the stack's firewall is never
attached to a private-only host. Read the primary IP id from the Console (**Primary IPs**, the
IPv6 assigned to `db-t1`):

```bash
read -r DBT1_LEFTOVER_IPV6_ID
```

```bash
hcloud primary-ip describe "${DBT1_LEFTOVER_IPV6_ID}" -o format='{{.Type}} {{.AssigneeID}}{{"\n"}}'
```

Expect `ipv6` and `${DBT1_SERVER_ID}`. If it says anything else, stop. Then, with the
server powered off:

```bash
hcloud server shutdown "${DBT1_SERVER_ID}"
```

```bash
hcloud server describe "${DBT1_SERVER_ID}" -o format='{{.Status}}{{"\n"}}'
```

Expect `off` (ask again until it is). If it will not stop, use
`hcloud server poweroff "${DBT1_SERVER_ID}"`: `db-t1` holds no data yet.

```bash
hcloud primary-ip unassign "${DBT1_LEFTOVER_IPV6_ID}"
```

```bash
hcloud primary-ip delete "${DBT1_LEFTOVER_IPV6_ID}"
```

```bash
hcloud server poweron "${DBT1_SERVER_ID}"
```

### Case A and B: confirm it is private-only

Both IDs must be `0`: there is no public address of either family on the server.

```bash
hcloud server describe "${DBT1_SERVER_ID}" -o format='{{.PublicNet.IPv4.ID}} {{.PublicNet.IPv6.ID}}{{"\n"}}'
```

And the private path still answers, over the way the stack and Ansible use:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="ssh -i ~/.ssh/id_ed25519_hetzner -W %h:%p root@${EDGET_IPV4}" root@10.20.1.200 'hostname; ip -4 route show default'
```

## 10. Converge db-t1 (third apply)

```bash
cd ~/branchLeft/shared-infra/hetzner/tenants
```

```bash
pulumi config set --path dbt1Adopt.stage converge
```

```bash
pulumi preview --diff
```

Expect for `db-t1` only: updates in place to protection and labels, and no firewall
attachment, since a private-only host gets none. Nothing for the network or the public interface: if the
preview proposes a change to either, the server is not in the state step 9 left it,
and the apply stops there. No replace, no delete, nothing on `edge-t`.

```bash
pulumi preview --json > ~/tenants-adopt-plan.json
```

```bash
python3 ~/branchLeft/shared-infra/scripts/assert-no-hetzner-deletes.py ~/tenants-adopt-plan.json
```

```bash
pulumi up
```

Do not detach `hold-no-inbound` from `db-t1`. It stays on as an inert second line:
with no public interface it filters nothing, and it would filter again if one were
ever added. There is no firewall attachment on `db-t1` to check.

## 11. Remove the temporary SSH firewall and prove nothing is left to change

Detach and delete the firewall from step 3:

```bash
hcloud firewall remove-from-resource bootstrap-ssh-edge-t --type server --server edge-t
```

```bash
hcloud firewall delete bootstrap-ssh-edge-t
```

Do not delete `hold-no-inbound` here. It stays on `db-t1` and `app-t1` as an inert
second line (step 10), so this step does not apply to it. Whether to delete it later
is the owner's decision.

Run the SSH probe of `RUNBOOK-edget-gateway-proof.md` (its section 4) now: from the
workstation it must show SSH to `edge-t` refused, and from `edge1` accepted. Run it once
before the first command of this step as well, when it must show SSH accepted from the
workstation: the red case.

The stack and the live project now agree. This must report no changes, for either
host and for the addresses:

```bash
cd ~/branchLeft/shared-infra/hetzner/tenants
```

```bash
pulumi preview --diff
```

```bash
pulumi refresh --preview-only
```

Record the config in git. The ids, the stage and the two public deploy keys are not
secret. The stack file gets `edgetAdopt`, `dbt1Adopt` (both with `stage:
converge`), `dbt1Enabled: "true"`, `edgetDeployPublicKey` and `dbt1DeployPublicKey`;
the token and the passphrase salt never do (`CLAUDE.md`). Reverting a working-copy
`hcloud:token` is not needed when the token is supplied through the `HCLOUD_TOKEN` environment variable, as nothing is then written to the working copy. Only if the token was set in the working copy with `pulumi config set`, revert it as step 6 of `../RUNBOOK-estate-project-move.md` describes, and open that as its own change.

## app-t1

`app-t1` is declared in `hetzner/tenants.ts` behind `appt1Enabled`, which the stack file does
not set, so a merge of that change plans and creates nothing. Its register address is
`10.20.1.201` (`TENANTS_HOST_IPS.appT1`), its type is CX23 and its location is `nbg1`, as for the
other two. It is adopted the same way as `db-t1`, with the same `adopt` argument on the same
`Host`, and its console state is one of the two cases above. Its steps are step 2 (the case),
step 9 (network attach at `10.20.1.201`, bootstrap, leftover address removal, confirming it is
private-only), and the converge update, in that order and with the same stops.

The owner's change that brings it under the stack sets `appt1Enabled: "true"`,
`appt1DeployPublicKey` (the public half of the key generated at step 8, for app-t1) and
`appt1Adopt` (`serverId`, `stage: converge`) in `Pulumi.production.yaml`, and nothing else. Before
the apply, the preview must show an import of the server and updates in place, and no create:
a create in the preview means `appt1Adopt` is missing or misspelled, and is not applied. The
plan then goes through `assert-no-hetzner-deletes.py` as for `db-t1`.

As for `db-t1` (step 10), `hold-no-inbound` is not detached from it, and the stack attaches no
firewall to it. The final delete of `hold-no-inbound` is not part of this series.

## If something goes wrong

- **A preview proposes to replace or delete a server or address.** Do not apply. The
  adopt config is what stops a replacement, so a replace means a field outside the
  ignored set differs: hand back the output.
- **A preview proposes to create a server.** The adopt config for that host is
  missing or misspelled. Do not apply.
- **An apply fails part-way.** The imports are in state and are harmless; re-run
  `pulumi preview --diff` and read it again. Do not detach `hold-no-inbound` on the
  strength of a failed apply.
- **The stack's firewall is not on a public server whose hold you were about to detach.**
  Do not detach. A public server with no firewall is open to the internet. A private-only
  host (`db-t1`, `app-t1`) has no public interface, so a firewall is neither needed nor
  possible on it: `hold-no-inbound` stays attached to it, and the owner never detaches it.
- **Rolling an adopted host back out of the stack.** `pulumi state delete` on the
  server and its addresses leaves the servers as they are in the Console. Do that
  rather than removing the adopt config, which would plan to create duplicates.
