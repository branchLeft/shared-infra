# Runbook — move the estate into its own hcloud project

Executes the project split decided in
[branchLeft/workspace#171](https://github.com/branchLeft/workspace/issues/171)
and recorded in `ghost-platform-docs` doc 14 §3.4: `mx1` stays in the existing
project alone, and the `platform` network plus every platform host moves to a
new one.

**This runs exactly once.** After it, `hetzner/projectGuard.ts` refuses either
stack against the mail project, and there is no supported way back.

**Platform-owner work throughout.** Creating an hcloud project is console-only,
minting a token is console-only, and every `pulumi up` and `pulumi destroy`
below is a production apply.

## What this costs and what it risks

**No spend.** hcloud projects are free, no server changes class, and the state
bucket is not moved — a second bucket would be free at the margin too, but
moving state is not part of this split and is tracked separately.

**`edge1` is destroyed and rebuilt, and comes back on a different public IP.**
That is affordable only because nothing points at the current one. Verify that
is still true immediately before starting — this is the gate, not a formality:

```bash
dig +short branchleft.co.uk www.branchleft.co.uk blog.branchleft.co.uk blog2.branchleft.co.uk A
```

Expected: the first three answer `34.149.131.244` (the GCP load balancer) and
`blog2` answers nothing. **If any of them answers `46.225.95.167`, stop** — the
edge is serving live traffic, and this runbook would take it down for the
length of a rebuild plus a re-provision with no DNS undo (the zone is manual at
IONOS).

**Between step 4 and step 6 the estate does not exist.** Recovery from a failed
bring-up is to finish the bring-up: the resources are declarative and nothing
in them holds state. Budget an afternoon, not five minutes, because steps 7
and 8 re-provision a host from bare.

## Which checkout each phase runs from

Steps 4 and 5 destroy estate resources that are sitting **in the mail
project**. `projectGuard.ts` exists to refuse exactly that, and it has no
bypass, so those two steps must run from a checkout that predates it.

| Steps           | Checkout                                         |
| --------------- | ------------------------------------------------ |
| 1–3             | Anything — console work                          |
| 4–5 (teardown)  | `main` **before** the project-split commit lands |
| 6–10 (bring-up) | `main` **after** it lands, or the branch itself  |

Confirm before step 4: `git log --oneline -1 -- hetzner/projectGuard.ts` must
print nothing.

## 1. Create the project

1. Open <https://console.hetzner.cloud> and sign in.
2. Create a project named exactly `branchLeft estate`.

The existing project keeps its name and its contents narrow to `mx1` alone.
Renaming it to something that says "mail" is optional and touches nothing here
— no code, no config and no runbook resolves an hcloud project by name.

## 2. Register the owner SSH key in the new project

In `branchLeft estate`, open **Security → SSH keys** and add
`~/.ssh/id_ed25519_hetzner.pub` under the name exactly `rob@branchleft.co.uk`
— the same key and the same name the mail project already carries. Confirm you
have the right file before pasting it:

```bash
ssh-keygen -lf ~/.ssh/id_ed25519_hetzner.pub
# 256 SHA256:UZLm2m1fvggsRn3wQ7Y/oJ66dqiAhexsgkKkvTshRzk rob@branchleft.co.uk (ED25519)
```

Not `id_ed25519` (a personal GitHub key), not `id_ed25519_signing` (git commit
signing), and not `id_ed25519_deploy_edge1` — that last one is the deploy
user's key, it reaches the host through cloud-init as `edge1DeployPublicKey`,
and it is never registered as an hcloud SSH key.

**Do this before step 6, not after.** SSH keys are per-project, `estate.ts`
passes `ownerSshKeyNames` through to `hcloud.Server.sshKeys`, and that field is
create-time-only: a missing key name fails the apply, and a host created
without the key cannot be logged into to add it. For the same reason, this
rebuild is the only cheap moment to change which key the owner uses — after
it, the path is writing `authorized_keys` over SSH, per
`RUNBOOK-provision-host.md`.

**Why the same key rather than a project-specific one.** The split bounds the
blast radius of _API tokens_, which multiply into a repository secret per
applying pipeline. The owner SSH key does the opposite: it stays on one
workstation, never enters a runner or a repository, and so has nothing to
multiply. A second key would share a `~/.ssh` with the first, so a compromise
reaching one reaches both, and what a project holds is the _public_ half,
which grants nothing on its own. Set against that, a third Hetzner-context key
makes every future SSH handover ambiguous about which `-i` to pass. Revisit
this only if someone other than the platform owner is given estate access —
revoking one person from the estate without touching mx1 is the case a
separate key would actually serve.

## 3. Mint the estate token

1. In `branchLeft estate`, open **Security → API tokens**.
2. Create a token named exactly `estate-pulumi`, with **Read & Write**.
3. Copy it immediately — Hetzner shows a token once and never again.
4. Store it in ProtonPass under an entry named `hcloud estate-pulumi token`.
5. Confirm which project it addresses before using it anywhere:

```bash
HCLOUD_TOKEN='<the estate-pulumi token>' hcloud server list
```

Expected: an empty list. **If this prints `mx1`, the token was created in the
mail project** — delete it and repeat this step inside `branchLeft estate`.

Do not put this token in a repository, a `.env`, a `Pulumi.<stack>.yaml`, or a
GitHub Actions secret yet. The CI apply path that needs it as a secret is a
later story.

## 4. Destroy the estate stack in the mail project

From a pre-guard checkout (see the table above), in `hetzner/estate/`, with the
state-backend credentials, the passphrase and the **old** project's token
supplied the way `RUNBOOK-new-stack.md` §1–§4 describes.

`edge1` carries `deleteProtection` and `rebuildProtection` at the API, so a
destroy fails until they come off, and they come off through an apply:

1. In `hetzner/estate.ts`, add `protection: false` to the `new Host({ … })`
   argument object. **Working copy only — this is never committed.**
2. `pulumi up` — expect an update of `edge1` and its two primary IPs, no
   replacement.
3. `pulumi destroy`.
4. `git checkout -- hetzner/estate.ts`.

Once done: the mail project holds `mx1`, the `platform` network and its subnet.

## 5. Destroy the network stack in the mail project

Same checkout, in `hetzner/`. The network is protected twice over and both have
to come off, at two different layers:

1. In `hetzner/network.ts`, set `deleteProtection: false` on the network.
   **Working copy only.**
2. `pulumi up` — expect an update of `platform`, no replacement.
3. `pulumi state unprotect --all` — clears Pulumi's own `protect: true` on the
   network and the subnet. `protect` blocks deletion, not update, which is why
   it does not need to come off before step 2.
4. `pulumi destroy`.
5. `git checkout -- hetzner/network.ts`.

Once done: **the mail project holds `mx1` and nothing else.** Confirm with
`hcloud server list`, `hcloud network list` and `hcloud firewall list` against
the old token before going further.

## 6. Point both stacks at the estate project and apply the network

From a post-guard checkout. In `hetzner/`:

```bash
pulumi config set --secret hcloud:token
```

The command prompts. Pass no value on the command line — an argument lands in
shell history and in the process table, and a token that has been in either is
a token that has to be rotated. Revert the working-copy config afterwards the
way `Pulumi.production.yaml`'s own comment describes; the ciphertext is never
committed.

```bash
pulumi preview     # expect: create network, subnet, route. And the guard passing.
pulumi up
```

`estateProjectVerified` in the outputs is the guard reporting that it could
not see a mail-project server. It rules the mail project out; it cannot
confirm this is the estate project, because an empty project passes. Step 3's
`hcloud server list` is what confirms which project the token came from. A preview that fails here with
`hcloud:token addresses the mail project` means the token set above is the old
one.

## 7. Apply the estate stack

In `hetzner/estate/`: set the same token the same way, then

```bash
pulumi preview     # expect: create edge1, its firewall, two primary IPs, the network attachment
pulumi up
```

Record the new `edge1PublicIpv4` and the new IPv6 range. Both differ from the
old ones and every note that quotes `46.225.95.167` is now stale.

## 8. Re-provision the host

`edge1` is a bare Debian image again. Everything that was ever installed on it
was installed by a runbook, and each has to run again in this order:

1. `RUNBOOK-provision-host.md` — base hardening, Docker, deploy tooling, and
   the NAT gateway that gives private-only hosts their egress.
2. `RUNBOOK-edge.md` — Caddy and CrowdSec.

The host key changed, so the first SSH connection presents an unknown host.
Remove the stale entry (`ssh-keygen -R <old address>`) rather than accepting
past a warning you have not read.

## 9. Prove it

- `hcloud server list` with the **estate** token prints `edge1` and not `mx1`.
- `hcloud server list` with the **mail** token prints `mx1` and not `edge1`.
- The edge answers on its new address, and a probe still raises a `waf` alert
  with an empty decisions column — `RUNBOOK-edge.md` carries that check. A
  `204` alone does not prove detect-only is working; the alert does.
- A private-only host's egress cannot be proven until `db1` exists. The route
  and the NAT service are verifiable on their own —
  `RUNBOOK-provision-host.md` carries both checks.

## 10. Close it out

Comment on [branchLeft/workspace#171](https://github.com/branchLeft/workspace/issues/171)
with the new public addresses and the date, then close it. That unblocks
[branchLeft/workspace#110](https://github.com/branchLeft/workspace/issues/110),
which creates `app1` and `db1` in the project this runbook just made.

Update `ghost-platform-docs` doc 14 §3.1's applied-state note — it quotes
`edge1`'s old public address as live fact.
