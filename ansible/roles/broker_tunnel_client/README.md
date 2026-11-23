# broker_tunnel_client

This role holds ops1's half of the broker tunnel: one supervised `ssh -N` that ops1 dials to
demo1, carrying one local forward from `127.0.0.1:18090` on ops1 to the demo broker on demo1's
`127.0.0.1:8090`. The control plane's broker client (`controlPlaneDemoBroker.ts` in
`branchLeft/ghost-platform`) dials the local end.

The transport is the owner's ruling `control=a` of 28 Sep 2026: ops1 reaches the broker through an
SSH tunnel, and port 22 on demo1 is open to edge1's address only. ops1 has no public address and
leaves the estate through edge1's NAT, so it arrives from the one address demo1's firewall allows.
ops1 initiates every connection; the demo host never dials in.

demo1's half is in the `demo1_build` role: the `brokertunnel` account, with no shell, whose one key
carries `restrict,port-forwarding,permitopen="127.0.0.1:8090"`, and an sshd `Match` block that sets
each restriction again. The grant is stated once, in ghost-platform's
`demo-host/provision/render_broker_tunnel.py`, which also proves it against a real sshd.

This README follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role:

1. Checks its two inputs (Interface): both set or both unset, a public IPv4 address and one
   ed25519 host key with no comment. A wrong value stops the run before anything is written, and
   the message names the input, never its value.
2. Checks that `/etc/branchleft` is root's and that no one else can change it (`host_inputs` makes
   it, first in the play).
3. Makes `/etc/branchleft/broker-tunnel` (root's, `0700`) and installs
   `branchleft-broker-tunnel.service`.
4. With both inputs set, writes `demo1.conf` (the ssh client configuration, `0600`, because it
   holds demo1's address) and `known_hosts` (demo1's pinned key under the alias `demo1`). With both
   unset it writes neither and says "Broker tunnel NOT configured" in a visible line: a stated skip
   (ANS-10), not a pass.
5. Enables the unit, starts it once the owner's key is there (it looks for the file and never
   reads it), and restarts it when the unit or either file changed.

What it does not do, each on purpose:

- It never creates, reads, hashes, writes or removes the private key. The owner places it.
- It does not change demo1, open a port or add a firewall rule.
- It does not install `ssh`.
- It does not point the control plane at the tunnel; the control plane's configuration does that.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the two inputs. On ops1 both come
from `host_inputs` as optional keys, with no default (ANS-16): absent from
`/etc/branchleft/host-inputs.json`, they are unset, which the role reads as empty, and the tunnel
stays unconfigured.

| Variable                              | Default | Meaning                                             |
| ------------------------------------- | ------- | --------------------------------------------------- |
| `broker_tunnel_client_demo1_address`  | none    | demo1's public IPv4 address. Private: never logged  |
| `broker_tunnel_client_demo1_host_key` | none    | demo1's `ssh-ed25519 <base64>` host key, no comment |

The paths, the remote account, the destination and the local end are constants in `vars/main.yml`
and the unit file, not inputs: an inventory value cannot move them.

## The owner's file

| File                                       | Owner | Mode   | Meaning                                         |
| ------------------------------------------ | ----- | ------ | ----------------------------------------------- |
| `/etc/branchleft/broker-tunnel/id_ed25519` | root  | `0600` | The tunnel's private key, used for nothing else |

Its public half goes to demo1 as `/etc/branchleft/broker-tunnel/ops1_public_key` (the
`demo1_build` README). The unit starts only when the configuration, the pinned key and this file
are all there: a missing one leaves the unit inactive and not failed, and the next gated apply (or a
`systemctl start`) brings it up once the file is there.

## What the path is

The unit runs `ssh -F /etc/branchleft/broker-tunnel/demo1.conf -N demo1`. The configuration holds:

- `LocalForward 127.0.0.1:18090 127.0.0.1:8090`, and no other forward;
- `User brokertunnel`, `IdentityFile` of the owner's key, `IdentitiesOnly yes`, `IdentityAgent none`,
  `PreferredAuthentications publickey`, `BatchMode yes`: one key is offered, and no agent or password;
- `StrictHostKeyChecking yes` against the role's `known_hosts`, `HostKeyAlias demo1`,
  `GlobalKnownHostsFile /dev/null`: a changed host key fails the unit instead of being trusted;
- `ExitOnForwardFailure yes`, `ServerAliveInterval 10`, `ServerAliveCountMax 3`: a link that goes
  silent is given up on in about thirty seconds, and a tunnel that cannot bind its end exits.

The unit has `Restart=always`, no start limit and a growing delay (`RestartSec=5`, `RestartSteps=6`,
`RestartMaxDelaySec=120`), the shape of the `spool_paths` unit.

## Failure behaviour

| Condition                                       | What the broker's callers see                                                         |
| ----------------------------------------------- | ------------------------------------------------------------------------------------- |
| Tunnel down (link lost, key refused, sshd gone) | Nothing listens on `127.0.0.1:18090`: the connection is refused at once, `unanswered` |
| A link that goes silent without closing         | The keepalive ends `ssh` in about thirty seconds, then as above                       |
| Tunnel up, broker down                          | demo1's sshd cannot open `127.0.0.1:8090` and closes the channel: `unanswered`        |
| Tunnel restored                                 | The unit restarts within its delay; the next call succeeds                            |

No call ever reaches another host instead: the forward has one destination on each side.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with systemd 254 or later (`RestartSteps`) and `/usr/bin/ssh`.
- `/etc/branchleft` made by `host_inputs`, first on ops1.

## What it changes on a host

| Path                                                   | Owner | Mode   | What                                         |
| ------------------------------------------------------ | ----- | ------ | -------------------------------------------- |
| `/etc/branchleft/broker-tunnel`                        | root  | `0700` | The directory of the files below and the key |
| `/etc/branchleft/broker-tunnel/demo1.conf`             | root  | `0600` | The ssh client configuration                 |
| `/etc/branchleft/broker-tunnel/known_hosts`            | root  | `0644` | demo1's pinned host key                      |
| `/etc/systemd/system/branchleft-broker-tunnel.service` | root  | `0644` | The unit                                     |

It also enables the unit. It names, and never writes, the owner's key file.

## How to test it

From the repository root, with the pinned tools installed as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/broker_tunnel_client
```

`molecule/default` runs the role with a documentation address and a test host key and no private
key. `verify` first scans the log of every earlier run of the scenario, check runs with `--diff`
included, for the address, after requiring the log to hold the role's own task names. It then reads
back the directory and file modes, requires the configuration's only forward to be
`LocalForward 127.0.0.1:18090 127.0.0.1:8090`, the pinned key and the user, and the unit enabled,
loaded and inactive on its condition. Last, it runs the refusal cases: one input without the other,
a private address, an address with a second line, a host key with a comment and an RSA host key.

## Limits

- The container has no demo1 and no private key, so the tunnel is never connected here. That the
  forward reaches the broker and nothing else is proven against a real sshd by ghost-platform's
  `demo-host-broker-tunnel-ci.yml`; that it does so between ops1 and demo1 needs the live hosts.
- The local end is on ops1's loopback. A control plane that runs in a container reaches it only
  with host networking or a further forward; wiring the control plane to the tunnel is separate work.

## Licence

PolyForm Shield 1.0.0.
