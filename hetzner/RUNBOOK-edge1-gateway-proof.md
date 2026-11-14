# Runbook — proving edge1 is the estate network's gateway

`edge1` is the estate network's one internet gateway: the `egress_nat` role makes it forward and
masquerade the private subnet (`10.20.1.0/24`), and every private-only host (`db1`, `ops1`) reaches
the internet through it. The read-back in `RUNBOOK-provision-host.md` (step 3) shows the three rules
are present. This runbook proves what a read-back cannot: that a source inside the subnet reaches the
internet only through the masquerade, with the packet counters of those rules rising, and that a
source outside the subnet is not carried.

Everything here is the platform owner's: it runs on a production host, and nothing in it is run by
an agent. It is the same probe as `hetzner/tenants/RUNBOOK-edget-gateway-proof.md` uses for edge-t
(`hetzner/scripts/probe-edget-gateway.py`), run with the `gateway` command and no other flag.

## What the probe adds and removes

It is one Python file, fed on stdin, and leaves no copy on the host. While it runs it adds, and on
every exit removes:

1. two network namespaces, `gwproof-in` and `gwproof-out`;
2. two veth pairs, `gwp-in-h`/`gwp-in-n` and `gwp-out-h`/`gwp-out-n`;
3. a point-to-point address on each host-side end (`10.20.1.253` and `192.0.2.2`), and in the
   namespaces the sources `10.20.1.254` (inside the subnet) and `192.0.2.1` (outside it), each with
   a default route inside its own namespace.

It writes no firewall rule, no route outside a namespace and no setting. The packet counters of the
masquerade rule and of the two `DOCKER-USER` accepts move; the rules do not. It connects to Quad9's
resolver (`9.9.9.9`, TCP 53) from each source; any reply counts, and the connection is closed with a
reset.

The probe refuses to run on any host that is not in its profile table (`edge-t`, `edge1`): the
hostname must be one of them, that host's private address must be on it (`10.20.1.10` for edge1), and
the other gateway's private address must not be. It refuses `--sabotage` on edge1 outright: that
flag deletes the masquerade rule for about six seconds, and every private host's egress rides on it.
It has no flag that names a host.

## 1. Set the address

It is read, never typed into a file. `EDGE1_IPV4` is `edge1`'s public address (`hcloud server ip
edge1` in the estate project):

```bash
read -r EDGE1_IPV4
```

```bash
case "${EDGE1_IPV4}" in ''|*[!0-9.]*) echo "not an IPv4 address: '${EDGE1_IPV4}'"; false;; esac
```

## 2. Prove the gateway (nothing that outlives the run changes)

The script is read from `origin/main`, so a stale checkout cannot deliver an old copy:

```bash
git -C "$HOME/branchLeft/shared-infra" fetch --quiet origin main
```

```bash
git -C "$HOME/branchLeft/shared-infra" show origin/main:hetzner/scripts/probe-edget-gateway.py | ssh -i ~/.ssh/id_ed25519_hetzner -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=30 root@"${EDGE1_IPV4}" python3 - gateway; echo "exit=$?"
```

Expect a first line naming the host, the uplink, the forwarding chain (`DOCKER-USER`, because
`host_baseline` has installed Docker) and the target, then exactly:

```text
probe-edget-gateway: <UTC time> on edge1, uplink <interface>, forwarding chain DOCKER-USER, target 9.9.9.9:53
GREEN inside-subnet-egress-via-masquerade [live]: source 10.20.1.254 got a reply from 9.9.9.9:53 (REPLY connected); counters rose: MASQUERADE a->b, DOCKER-USER out a->b, DOCKER-USER return a->b
GREEN outside-subnet-no-reply [live]: source 192.0.2.1 got no reply from 9.9.9.9:53 (NOREPLY timeout); the host received N packet(s) on gwp-out-h and no gateway rule counter moved
RESULT PASS
exit=0
```

with the real interface name and counters. Exit codes:

| Exit | Meaning                                                                                         |
| ---- | ----------------------------------------------------------------------------------------------- |
| `0`  | every control GREEN (`RESULT PASS`)                                                             |
| `1`  | a control RED (`RESULT FAIL`): the line names what failed                                       |
| `2`  | `REFUSED:` nothing was proven; read the reason                                                  |
| `3`  | a namespace or veth could not be removed (`CLEANUP FAILED`): remove it by hand as the line says |
| 255  | `ssh` itself could not connect; the probe did not run                                           |

A `RED` line names a missing rule, forwarding off, `branchleft-nat.service` not enabled or not
active, no reply, or a counter that did not rise. Two readings on edge1 need care, because it carries
every private host's traffic:

- A `REFUSED:` line saying the rule counters kept moving, or an outside-control `RED` saying a
  counter moved, means another source used the gateway during the run. That is not a failed gateway:
  run it again when the private hosts are quiet.
- An outside-control `RED` that says the outside source **GOT A REPLY** is a real finding: the
  gateway carried a source it must not. Stop and hand back the output.

If it refuses because `docker.service` is active but there is no `DOCKER-USER` chain, Docker is not
enforcing through iptables here: stop and hand back the output.

## 3. Check nothing was left behind

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"${EDGE1_IPV4}" 'ip netns list; ip -o link show | grep -c -E " gwp-"; echo listed'
```

Expect `0` and then `listed`, with nothing before the `0`. If a namespace or link remains, remove it
as root on edge1 with `ip netns del NAME` or `ip link del NAME`, using the name it printed.

## Not run here

`gateway --sabotage` is not part of this runbook and is refused on edge1. The red case (the
masquerade deleted, the inside probe going RED, the unit restart bringing it back) is run on edge-t
only, by `hetzner/tenants/RUNBOOK-edget-gateway-proof.md`.
