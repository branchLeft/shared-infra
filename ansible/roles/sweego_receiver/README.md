# sweego_receiver

This role delivers the Sweego complaint-webhook receiver to edge1 as a Compose project, and
limits the receiver's drain port to one source with one host firewall rule. It reads the host
and the running container back and refuses to finish if either is not what the receiver's safety
depends on.

This README is self-contained and is written for a maintainer new to the repository. It follows
the order the standard sets for a role README (ANS-14).

Nothing in this role is wired in. It is not listed in `ansible/playbooks/edge1.yml` or in
`ansible/checks/host_roles.yml`, and it holds no value the owner names (the hostname, the two
ports, the image). Applying it is a separate, gated step (below, "What the owner does").

## What the role does, and what it does not

In this order, and it stops at the first refusal:

1. **Inputs** (`_inputs.yml`). The two ports are whole numbers from 1024 to 65535 and differ. The
   secret file paths are each one plain name directly under `/etc/branchleft` and are three
   different files.
2. **The compose file** (`_compose_check.yml`). The role renders its own template once, parses it
   and holds the result to the posture below, so a template edit that drops a control is refused at
   the plan and not found on the host.
3. **The host** (`_preconditions.yml`, read only). The host's own name is `edge1`. Docker is
   active and `DOCKER-USER` exists. `/etc/branchleft`, `/opt/branchleft` and `/usr/local/sbin` are
   real directories owned by root and not writable by group or others. The shared Compose template
   unit is loaded from its one path and is owned by root.
4. **The secret files** (`_secrets.yml`). Each exists, is a regular file (not a link), is owned by
   `root`, group `31100`, mode `0440`, and is not empty. The role looks at the file's metadata
   only. It never opens a secret, never hashes one and never prints one. A missing or wrong file
   stops the run with a message that names the path and the fault.
5. **The drain-port rule** (`_rule.yml`). Installs a small root-run program and its boot unit, loads
   the rule, and reads `DOCKER-USER` back. **This happens before the receiver is delivered or
   started**, so there is no moment when the drain port is published and unguarded.
6. **The receiver** (`_stack.yml`). Creates the state directory, places the compose file and a
   drop-in that orders the receiver's unit after, and binds it to, the rule's unit, and enables
   and starts the unit once an image pin exists.
7. **Read-back** (`_readback.yml`). Reads the container and the listeners and asserts the posture
   again on what is running.

What it does **not** do, each on purpose:

- It does not contain, write or read a secret. The signing secret and the drain token are files
  the owner places; the role holds only their paths.
- It does not publish or pull an image. The image comes from the pin file
  `/etc/branchleft/sweego-receiver.image.env`, which `branchleft-deploy` writes, as the other
  stacks on the estate do.
- It does not install Docker, write the shared `branchleft-compose@.service`, open a port on the
  Hetzner firewall, touch DNS or Caddy, or reboot the host.
- It does not cover IPv6, remove a rule left for an old port, or restrict the host's own
  processes (below, "Limits").

## What it lets through

| What             | Port                         | Reachable from                                                                   |
| ---------------- | ---------------------------- | -------------------------------------------------------------------------------- |
| Webhook endpoint | `sweego_receiver_port`       | Anything on edge1's private network (10.20.1.10). Intended: Caddy on edge1 only. |
| Drain endpoint   | `sweego_receiver_drain_port` | ops1 (10.20.1.50) only. Every other source is dropped in `DOCKER-USER`.          |

Neither port is bound to a public address, so neither is reachable from the internet. The Hetzner
Cloud firewall filters the public interface only; private exposure is set by what a service
binds to, which is why both ports are published on 10.20.1.10 and the receiver itself binds one
container address, not a wildcard.

The webhook endpoint is not source-limited by this role. Anything on the private network can
send it a request, and each request is accepted only with a valid HMAC-SHA256 signature over
`{webhook-id}.{webhook-timestamp}.{raw body}`. The drain endpoint additionally needs the bearer
token, so the source rule is not its only factor.

## The container posture

Held by `_compose_check.yml` on the template, by `_readback.yml` on the running container, and by
`tests/unit/test_role_contract.py` on both:

- Runs as the fixed numeric account `31100:31100`, never root.
- `read_only: true`. The only writable place is the state directory, mounted at `/state`.
- `cap_drop: [ALL]`, no `cap_add`, `no-new-privileges:true`.
- Not privileged. No host network, pid, ipc, devices or `volumes_from`. No Docker socket.
- Secrets reach the container as read-only file mounts. The environment holds only paths.
- Healthcheck, `restart: on-failure:5`, memory, swap, pid and CPU limits.
- Both ports published on `10.20.1.10` only. The receiver binds a fixed address on its own bridge
  network, never `0.0.0.0`.
- The image is `${IMAGE}` from the pin file; there is no tag in the template.

## The drain-port rule

A published Docker port is a DNAT in `nat`, which bypasses the host's `INPUT` chain, so the rule
lives in `DOCKER-USER`, the chain Docker leaves for the host. The sibling firewall rules on the
estate use the same chain and match on the original destination (`--ctorigdst`,
`--ctorigdstport`) because by the time `DOCKER-USER` sees the packet its destination is the
container. This rule adds `--ctdir ORIGINAL`, so only the client-to-server direction is judged and
replies are never dropped:

```
-p tcp -m conntrack --ctorigdst 10.20.1.10 --ctorigdstport <drain port> --ctdir ORIGINAL ! -s 10.20.1.50 -j DROP
```

The program (`files/branchleft_sweego_drain_rule.py`, installed at
`/usr/local/sbin/branchleft-sweego-drain-rule`) inserts it at position 1, and when it is already
there checks that it is the first rule. Anything it cannot decide (no `iptables`, no
`DOCKER-USER`, an unexpected exit status) is a refusal, never a guess. Its boot unit
(`branchleft-sweego-drain-rule.service`) runs after `docker.service` and is `PartOf` it, so a
Docker restart, which rebuilds the chain, loads the rule again.

Default deny is the rule's shape: the one allowed source is named, everything else to that port is
dropped. A source given as a network, a wildcard or loopback is refused by the program, and so is
a source equal to the host's own address.

## Interface

Two required inputs, with no default. Both are the owner's to name:

| Variable                     | Meaning                                            |
| ---------------------------- | -------------------------------------------------- |
| `sweego_receiver_port`       | Host port for the webhook endpoint, on 10.20.1.10. |
| `sweego_receiver_drain_port` | Host port for the drain endpoint, on 10.20.1.10.   |

Three optional paths (see `defaults/main.yml`): `sweego_receiver_signing_secret_file`,
`sweego_receiver_drain_token_file`, and `sweego_receiver_previous_signing_secret_file` (empty means
no rotation is in progress). Everything else is a constant in `vars/main.yml`, because the
addresses, the account and the container paths are the estate's, not a choice a caller makes.

## Requirements

A host named `edge1`, with Docker running, `iptables`, the shared `branchleft-compose@.service`
template unit, and `branchleft-deploy` to write the image pin.

## What the owner does

The role never needs these values from a caller, and the build does not know them, so none is
written here as a placeholder. In order:

1. Name the two ports in the host's owner variables, wire the role into the edge1 playbook and the
   host-role map, and add the ports to the edge allow-list of ports and the site constants.
   (Each of those files is owner-merged.)
2. Place the signing secret and the drain token as root-owned files (`root:31100`, mode `0440`) at
   the paths above.
3. Publish the receiver image, and run `branchleft-deploy` for the stack `sweego-receiver` so the
   pin file exists.
4. Approve the gated plan and apply, then run it again: the second run in check mode reports no
   change.
5. Add the Caddy route to the webhook port, in the edge files (not in this role).

## Defaults for what Sweego has not documented

The receiver is built to the documented behaviour: HMAC-SHA256 over
`{webhook-id}.{webhook-timestamp}.{raw body}`, with Sweego retrying every five minutes up to
twenty times. For anything undocumented the receiver's own conservative settings apply, and a
change to them is a change to the receiver, not to this role:

- Timestamp tolerance: five minutes into the future, two hours into the past.
- Replay set: a webhook-id is remembered for three hours.
- Rotation: two signing secrets at once (current and previous).
- Response codes: 401 for a bad signature, 503 when the queue is full so Sweego retries.
- No source-IP allow-list on the webhook endpoint: Sweego's addresses are not documented.
- Body cap: 16 KiB. Queue cap: 5 MiB, fixed in the receiver, not an environment setting.

## Limits

Named here, not hidden:

- The webhook endpoint accepts a request from any host on the private network. It is gated by
  the HMAC, not by the firewall.
- The drain rule trusts the source address. Another host on the private network could forge ops1's
  address; the bearer token is the second factor.
- Processes on edge1 itself reach the drain port through Docker's own proxy, which does not pass
  through `DOCKER-USER`. They still need the token.
- IPv4 only. Nothing is published on IPv6.
- A rule left for an old port is not removed when the port changes. Remove it by hand.
- Whether the receiver starts before its rule at a cold boot is held by the unit ordering and by
  `restart: on-failure:5`, and is proven only by a reboot drill on the real host.

## How to test

```
cd ansible/roles/sweego_receiver
PYTHONPATH=files python3 -m unittest discover -b -s tests/unit -p 'test_*.py'
```

`tests/unit/test_drain_rule.py` runs the real program against a stand-in `iptables`.
`tests/unit/test_role_contract.py` renders the template and checks every posture field, the
coupling between the rule and the published port, and that no secret is in the role. The Molecule
scenarios `default` and `refusals` (under `molecule/`) run the role on a systemd container with a
real `iptables` and a `DOCKER-USER` chain, and check the second run is a no-op.

## How it is delivered, and how to change it safely

It is delivered only through the gated pull workflow; nothing applies it from a workstation. To
change a control, change it in the template or the program, and change the test that holds it in
the same pull request: each test fails when its control is removed, and that is how a change is
proven.
