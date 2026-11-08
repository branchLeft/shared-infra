# Runbook — proving edge-t is the tenants network's gateway

`edge-t` is the tenants network's one internet gateway: the network's default route
names it, and the `egress_nat` role has made it forward and masquerade the
tenants subnet (`10.20.1.0/24`). This runbook proves the two things the
declarations cannot: that a source inside that subnet reaches the internet only
through the masquerade, and that SSH to `edge-t` is refused to everything but
`edge1`.

Everything here is the platform owner's: it runs on, or against, a production host,
and nothing in it is run by an agent. It changes no rule, route or firewall,
except the one sabotage block, which deletes the masquerade rule for about six
seconds and restores it.

It sits inside `RUNBOOK-adopt-console-servers.md`: the gateway proof belongs
**between its step 7 and its step 9** (the `egress_nat` role converged on
`edget`, Docker running, and no private host booted yet), and the SSH probe is
run twice, once before and once after its step 11. It is its own file because the
adopt runbook's count of hand steps may only go down
(`ansible/checks/hand_runbook_steps.yml`).

## What the probe does

`hetzner/scripts/probe-edget-gateway.py` is one Python file with two commands. It
needs no install and leaves no copy on the host: it is fed on stdin.

**`gateway`** runs on `edge-t` as root. It builds two throwaway network namespaces,
each joined to the host by a veth pair, and connects to a public address (Quad9's
resolver on TCP 53; `--target IPV4:PORT` changes it) from each:

| Control                               | Source                | GREEN means                                                                                                                                                                         |
| ------------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `inside-subnet-egress-via-masquerade` | `10.20.1.254`, inside | A reply came back, and the packet counters of the masquerade rule and of both accepts in `DOCKER-USER` (the rules `branchleft_nat.sh` writes) all rose.                             |
| `outside-subnet-no-reply`             | `192.0.2.1`, outside  | No reply, the host's veth did receive the packets (so the silence is the gateway's), and no gateway counter moved. It counts only when the inside control is GREEN in the same run. |

A private source address cannot be answered by the internet, so a reply to the
inside source is itself the proof that its packets left masqueraded; the counters
name which rules carried them. The namespaces and veths are removed on every exit,
the host's default route is never written, and the Hetzner network is never
touched. The probe refuses to run on any host that is not `edge-t`: the hostname
must be `edge-t`, `10.20.1.210` must be on it and edge1's `10.20.1.10` must not.

**`gateway --sabotage`** is the red case, explicit and owner-run only. It first runs
the two controls above and goes no further unless both are GREEN. Then it deletes
the masquerade rule, shows the inside probe go RED naming that mechanism, restores
the rule by restarting `branchleft-nat.service` (the unit that reasserts it at
boot, so this also shows the self-heal), and shows GREEN again. It prints the one
command that undoes it before it deletes anything, and restores on any exit
including `Ctrl-C` and a dropped SSH session. Only a `kill -9` of the process can
skip the restore. It refuses while another source is using the gateway, so it never
cuts someone else's connection.

**`ssh`** runs on whichever machine is under test. It makes a plain TCP connection
to port 22 and reads the banner; it needs no key and logs in nowhere.
`--expect refused` is GREEN only when port 22 times out (Hetzner firewalls drop,
they do not reset) **and** port 443, which the stack's firewall opens to everyone,
answers: without the second reading, a timeout could be that machine's own network.
`--expect accepted` is GREEN only when an SSH banner comes back.

Every command exits `0` when every control is GREEN, `1` when one is RED, `2` when it
refused to run, and `3` when it could not clean up or restore. `2` and `3` are never
a pass.

## 1. Set the addresses

Both are read, never typed into a file. `EDGET_IPV4` is `edge-t`'s public address
(`hcloud server describe` in the tenants project, as step 3 of the adopt runbook
reads it); `EDGE1_IPV4` is `edge1`'s, from the estate project:

```bash
read -r EDGET_IPV4
```

```bash
read -r EDGE1_IPV4
```

```bash
case "${EDGET_IPV4}${EDGE1_IPV4}" in ''|*[!0-9.]*) echo "not an IPv4 address"; false;; esac
```

## 2. Prove the gateway (read-only)

Every `ssh` below goes through `edge1`, which the stack's firewall always allows, so
the same commands work before and after the temporary firewall is removed. The
script is read from this checkout:

```bash
cd ~/branchLeft/shared-infra
```

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="ssh -i ~/.ssh/id_ed25519_hetzner -W %h:%p root@${EDGE1_IPV4}" root@"${EDGET_IPV4}" python3 - gateway < hetzner/scripts/probe-edget-gateway.py
```

Expect a first line naming the uplink, the forwarding chain (`DOCKER-USER` on
`edge-t`, because `host_baseline` has installed Docker) and the target, then exactly:

```text
GREEN inside-subnet-egress-via-masquerade [live]: source 10.20.1.254 got a reply from 9.9.9.9:53 (REPLY connected); counters rose: MASQUERADE a->b, DOCKER-USER out a->b, DOCKER-USER return a->b
GREEN outside-subnet-no-reply [live]: source 192.0.2.1 got no reply from 9.9.9.9:53 (NOREPLY timeout); the host received N packet(s) on gwp-out-h and no gateway rule counter moved
RESULT PASS
```

with the counters' real numbers. Any `RED` line names what failed: a missing rule, forwarding
off, `branchleft-nat.service` not enabled or not active, no reply, a counter that did
not rise. A `REFUSED:` line (exit `2`) means nothing was proven and, except for the
wrong-host refusals, nothing was built: read it, fix the host, run it again. If it
refuses because the counters keep moving, another source is using the gateway: run
it again when that has stopped.

If `docker.service` is active but the script refuses for want of a `DOCKER-USER`
chain, Docker is not enforcing through iptables on this host and the gateway is not
up: stop, and hand back the output.

## 3. The red case (owner-run, deletes the masquerade for about six seconds)

Run this once, with nothing else behind the gateway: before `db-t1` is bootstrapped
(adopt step 9), or while it is idle. The gateway is without its masquerade for the
length of one probe, six seconds, and then restored.

```bash
ssh -i ~/.ssh/id_ed25519_hetzner -o ProxyCommand="ssh -i ~/.ssh/id_ed25519_hetzner -W %h:%p root@${EDGE1_IPV4}" root@"${EDGET_IPV4}" python3 - gateway --sabotage < hetzner/scripts/probe-edget-gateway.py
```

Expect, in this order: `GREEN inside-subnet-egress-via-masquerade [live]`, `GREEN
outside-subnet-no-reply [live]`, a `sabotage:` line carrying the recovery command,
then

```text
RED inside-subnet-egress-via-masquerade [masquerade rule deleted]: source 10.20.1.254 got NO reply from 9.9.9.9:53 (NOREPLY timeout) with the nat/POSTROUTING MASQUERADE rule for 10.20.1.0/24 deleted ...
restoring: systemctl restart branchleft-nat.service
GREEN inside-subnet-egress-via-masquerade [restored by restarting branchleft-nat.service]: source 10.20.1.254 got a reply from 9.9.9.9:53 ...
RECORD red-then-green: ...
RESULT PASS
```

That is the red-then-green record for the first clause. If the output ends in
`RESTORE FAILED`, the gateway is down: run, on `edge-t` as root through the same
`ssh`, `systemctl restart branchleft-nat.service`, and hand back the output. If the
connection dropped before any `RESULT` line, run the same restart.

## 4. Prove SSH is refused to everything but edge1

Run these from the owner's machine. The first has two readings, and both are the
record.

**Before step 11 of the adopt runbook**, the temporary firewall `bootstrap-ssh-edge-t`
still lets the owner's address in, so this must be RED. That is the red case:

```bash
python3 hetzner/scripts/probe-edget-gateway.py ssh --target "${EDGET_IPV4}" --expect refused
```

Expect `RED ssh-to-edge-t-refused-from-non-edge1 [this source]: ... ssh (SSH-2.0-...); SSH IS ACCEPTED from this source`.

**After step 11** has detached and deleted that firewall, the same command must be GREEN:

```bash
python3 hetzner/scripts/probe-edget-gateway.py ssh --target "${EDGET_IPV4}" --expect refused
```

Expect two lines, `GREEN edge-t-reachable-on-443 [this source]: port 443 ... refused` (or
`connected`) and `GREEN ssh-to-edge-t-refused-from-non-edge1 [this source]: port 22 ... timeout`.
`edge-t`'s address must also be probed over IPv6 if it has one: the same command with
`--target` set to the IPv6 address, from a machine that has IPv6.

And from `edge1`, which the firewall does allow, SSH must be accepted:

```bash
ssh -i ~/.ssh/id_ed25519_hetzner root@"${EDGE1_IPV4}" python3 - ssh --target "${EDGET_IPV4}" --expect accepted < hetzner/scripts/probe-edget-gateway.py
```

Expect `GREEN ssh-to-edge-t-accepted-from-edge1 [this source]: port 22 ... ssh (SSH-2.0-...)`.

The firewall's own rules are read by step 6 of the adopt runbook
(`hcloud firewall describe edge-t`): SSH from `edge1`'s public address as a /32, 80,
443 and ICMP, and nothing else. This probe shows the rules do what they say.

## 5. Record it

Paste the whole output of each block, including the RED case before step 11 and the
sabotage run, on the issue that tracks the gateway. That is the live evidence for its
two proof clauses; the route in the Hetzner network and the rules' presence are read by
their own steps.
