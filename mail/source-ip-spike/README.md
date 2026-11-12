# Source-IP spike

A throwaway local experiment. It answers one question for the mail lanes design: when the mail host has a second IPv4 address (IP2), which mechanism makes outbound SMTP from a Dockerised Stalwart leave from IP2 for newsletter mail and from IP1 for transactional mail, and does Stalwart v0.16.17 pick the address per sender domain?

It runs nothing on any host. The lab is a privileged `docker:dind` container on a local Docker engine standing in for mx1 (one Docker host, one NIC, IP1 primary, IP2 added as a `/32` secondary), and an SMTP sink that records the TCP peer of every message. Nothing here touches mx1, DNS, the Hetzner API or any spend, and `mail/provision/docker-compose.yml` is not edited.

## Decision

**Host networking works and is the mechanism to adopt; the second-network option (`com.docker.network.host_ipv4`) also works but cannot give one Stalwart container two outbound addresses.** Red then green in one recorded run: E1 (the shape mx1 runs today) is red, E2 (host networking) and E4 (the pinned Stalwart image with a `sender_domain` rule, on host networking) are green.

The design asked for host networking if both pass. Both did, so the decision is host networking.

## Results (2026-11-12)

Host: Docker Desktop engine 29.9.2, linux/arm64, kernel 7.0.14-linuxkit. Lab engine (`docker:dind` pinned by digest in `run_spike.py`): 29.9.3. Stalwart: the image digest pinned in `mail/provision/docker-compose.yml` (v0.16.17). Lab addresses: IP1 `10.77.0.2`, IP2 `10.77.0.3`, sink `10.77.0.50:2525`.

| Experiment                                                       | Result           | What the sink saw                                                                                                                                                                                                      |
| ---------------------------------------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| E1 default bridge, as mx1 runs Stalwart today                    | RED (expected)   | Binding the sender to IP2 fails with `OSError: [Errno 99] Address not available`. Unbound, the message arrives from `10.77.0.2` (IP1).                                                                                 |
| E2 host networking                                               | GREEN            | Bound to IP2: peer `10.77.0.3`. Bound to IP1: peer `10.77.0.2`.                                                                                                                                                        |
| E3 second Docker network with `com.docker.network.host_ipv4=IP2` | GREEN            | Container on the new network: peer `10.77.0.3`. Container on the default network: peer `10.77.0.2`. Accepted by engines 24.0.9, 27.5.1 and 29.9.3 (see below).                                                         |
| E3b host SNAT rule for a second network                          | GREEN            | Run on request although E3 was supported: `iptables -t nat -I POSTROUTING 1 -s 172.30.0.0/24 ! -o spike-br3 -j SNAT --to-source 10.77.0.3` gave peer `10.77.0.3`.                                                      |
| E4 Stalwart v0.16.17, `sender_domain` rule, host networking      | GREEN            | `nl@bounce-nl...` from `10.77.0.3` (EHLO `nl.helo.spike.test`); `tx@bounce-tx...` from `10.77.0.2` (EHLO `tx.helo.spike.test`). Stalwart's own `delivery.connect` events say `localIp = 10.77.0.3` and `10.77.0.2`.    |
| E5 IPv4-only outbound setting                                    | UNPROVEN (found) | The field exists: `ipLookupStrategy` on the `Mx` route, and `v4Only` is accepted and reads back. Its effect against a target with both A and AAAA records is not shown by this lab (no dual-stack target, no lab DNS). |

Evidence lines from the recorded run (sink log, one per message):

```
{"ehlo": "sender.spike.test", "mail_from": "e2-ip2@spike.test", "peer": "10.77.0.3", "rcpt_to": ["rcpt@sink.spike.test"]}
{"ehlo": "nl.helo.spike.test", "mail_from": "nl@bounce-nl.spike.test", "peer": "10.77.0.3", "rcpt_to": ["rcpt@sink.spike.test"]}
{"ehlo": "tx.helo.spike.test", "mail_from": "tx@bounce-tx.spike.test", "peer": "10.77.0.2", "rcpt_to": ["rcpt@sink.spike.test"]}
```

### Field names on v0.16.17 (read from the running server)

- Source address: `MtaConnectionStrategy.sourceIps`, a map of objects each carrying `sourceIp`. (The public documentation's `localIps` shape is rejected by this version.)
- Per-strategy EHLO/HELO name: **exists**, `MtaConnectionStrategy.ehloHostname` (nullable). It is honoured per lane: the sink logged `nl.helo.spike.test` for the newsletter lane and `tx.helo.spike.test` for the transactional lane.
- The lane is chosen by the `connection` expression of the `MtaOutboundStrategy` singleton, which sees `sender_domain`. `route` and `connection` are separate expressions, so the `Mx` route is unchanged.
- IPv4-only: `MtaRoute` of type `Mx` has `ipLookupStrategy`, default `v4ThenV6`. `v4Only` is accepted. Only the `Mx` route has the field; the `Relay` route used in this lab does not.
- Objects written over JMAP took effect only after a container restart in this lab, as the design's comment predicted.
- To see `delivery.connect` events the tracer has to be `Stdout` at level `trace`; at `info` the event is not printed.
- Submission accounts here authenticate on port 465 (implicit TLS) with an app password; there is no listener on 587 by default.

### Negative and partial results

- **E3 limitation, by construction.** `host_ipv4` sets the outbound address for a whole Docker network. A Stalwart container sits on one network, so it would send everything from one address. Choosing the address per sender domain from one Stalwart would need either two Stalwart containers or policy routing. Neither was built or tested here. This is why host networking is the decision rather than a tie.
- **Engine versions for E3.** The option was accepted and worked on 24.0.9, 27.5.1 and 29.9.3. No engine that rejects it was found, so the `unsupported-option` path of the verdict code is pinned by unit tests only, not by a live case. Docker 24 is the oldest tried.
- **E5 is unproven**: field found, effect not shown. What would show it: a lab DNS that returns both A and AAAA for a delivery domain, an `Mx` route (not `Relay`), and `delivery.connect` events with `v4ThenV6` against `v4Only`.
- The lab's sink is on-link. It has no provider hop, so it says nothing about how Hetzner routes a Floating IP.

## What the spike does NOT prove

- That a PTR record can be set on a Floating IP. The Hetzner page on persistent configuration for a Floating IP (read 2026-11-12) does not mention reverse DNS at all.
- That port 25 is unblocked for the Floating IP. Hetzner enforces the port 25 rule per account, so it is likely, but nothing here shows it.
- How Gmail scores IP2 beside IP1. The 25 September deferral named the netblock, so a second address in the same range may not isolate reputation.
- How Hetzner routes a Floating IP configured as a secondary address on the server.
- mx1's real Docker engine version. mx1 installs unpinned `docker-ce` from Docker's apt repository, so the owner reads `docker version` on mx1 before adopting anything.
- The real `Mx` route, TLS to a real peer, or IPv6. The lab used a `Relay` route to the sink with plain SMTP.
- That the address survives a reboot. The lab adds IP2 with `ip addr add`; on mx1 it has to be persistent network configuration.
- The Hetzner Cloud firewall, and what host networking does to inbound exposure.

## What adopting host networking on mx1 would change (text only, not applied)

1. The Floating IP is added to the host as a `/32` on the primary interface and made persistent. The Hetzner persistent-configuration page gives the `/32` form (for example a netplan file with the address under the interface, then `netplan apply`). Applying it is an owner or Ansible step.
2. `docker-compose.yml`: add `network_mode: host` and remove the `ports:` list. The test that checks published ports against the firewall (`test_published_ports_match_firewall.py`) parses that list and needs a new basis.
3. Stalwart's administration listener is bound to `[::]:8080` by `configure_stalwart.py`. Today the compose file publishes it to `127.0.0.1` only. Under host networking the listener's own bind decides, so it has to become `127.0.0.1:8080`, and the Cloud firewall stays the control for every other port.
4. Stalwart objects: two `MtaConnectionStrategy` objects (`sourceIps` with IP1 and IP2, `ehloHostname` with a name whose forward and PTR records match the address), and the `connection` expression of `MtaOutboundStrategy` chosen on `sender_domain`. Then a container restart.
5. DNS and SPF for the newsletter lane: an `ip4:` entry for IP2 or a second host name, and the PTR set at Hetzner.

## Running it

The Docker experiments run only with `SPIKE_DOCKER=1`; without it `run_spike.py` refuses and exits 2.

```
SPIKE_DOCKER=1 python3 mail/source-ip-spike/run_spike.py --experiments e1,e2,e3,e4,e5
```

Options: `--experiments` (any of e1, e2, e3, e3b, e4, e5), `--subnet` (default `10.77.0.0/24`), `--dind-image` (a digest-pinned image), `--json FILE`, `--remove-pulled-images`, and the two sabotage switches below. It needs about 1 GB of images (`docker:dind`, `python:3.12-alpine`, the Stalwart image) and takes a few minutes. It exits 1 when any experiment except E1 is red or swapped.

The unit tests (verdict logic, guards, sink and sender against each other on loopback) need no Docker:

```
python3 -m unittest discover -s mail/source-ip-spike -p 'test_*.py' -v
```

`SPIKE_DOCKER=1` adds one test that runs E1 and E2 for real.

### Guards

The runner refuses when `DOCKER_HOST` is set or the current Docker context is not a local Docker socket; when the lab subnet overlaps an existing Docker network; and when an outer-engine `run` or `create` asks for host networking (the Docker Desktop VM's own network is never used; host networking is only used inside `spike-host`). It creates and removes only objects named `spike-*`, in a `finally`. It never uses ssh.

### Sabotage

Both are recorded in the pull request.

1. `--no-ip2` builds the lab without IP2. E2 (bound to IP2) goes red with errno 99, E3 goes red with a connect timeout, and E4 goes red because the newsletter message never reaches the sink. The sink measures the packet, so a pass is not vacuous.
2. `--swap-domains` swaps the two sender domains in the E4 rule. The verdict is `SWAPPED`, reached from the peers the sink logged: `judge_lane_pair` takes the observed peers and the fixed expectation and is given no configuration.

### Where this runs in CI

The `mail-provision-checks` job discovers Python tests only under `mail/provision` (`unittest discover -s mail/provision`), so it neither runs nor breaks on this directory. These tests are not discovered by any existing CI job. Wiring them in means editing `.github/workflows/ci.yml` and the test that pins that step in `scripts/test_ci_skip.py`; both are outside this change.
