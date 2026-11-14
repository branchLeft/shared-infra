#!/usr/bin/env python3
"""Proves the mail spool's drain-bridge rules in
hetzner/provision/branchleft_docker_user_policy.sh against a real dockerd
inside a privileged Docker-in-Docker stand-in for an app host. Creates only
containers and a network under one prefix.

Usage: python3 hetzner/scripts/prove_spool_bridge_egress.py
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from subprocess import DEVNULL, PIPE

from lib.docker_pull import ensure_image
from lib.proof_harness import (
    ProofAbort,
    StandIn,
    Tally,
    count_lines_containing,
    keep_containers,
    network_address,
    packet_count,
    remove_resources,
    run,
    wait_until,
)

HERE = Path(__file__).resolve().parents[1]
DIND_IMAGE = "docker:27-dind"
PROBE_IMAGE = "python:3.12-alpine"
SPOOL_SUBNET = "172.29.50.0/24"
GATEWAY = "172.29.50.1"
POLICY = "/policy/branchleft_docker_user_policy.sh"


def prove(tally: Tally, host_name: str, outside: str, net: str) -> None:
    ensure_image(PROBE_IMAGE)
    ensure_image(DIND_IMAGE)

    run(["docker", "network", "create", net], out=DEVNULL)
    # NET_ADMIN so it can be given a return route to the spool bridge: the spool
    # network has masquerade off, so without one no reply could ever come back and
    # the "before" control would prove nothing.
    run(
        [
            "docker",
            "run",
            "-d",
            "--cap-add",
            "NET_ADMIN",
            "--name",
            outside,
            "--network",
            net,
            PROBE_IMAGE,
            "python",
            "-m",
            "http.server",
            "8080",
        ],
        out=DEVNULL,
    )
    outside_ip = network_address(outside, net)

    run(
        [
            "docker",
            "run",
            "-d",
            "--privileged",
            "--name",
            host_name,
            "--hostname",
            "app-proof",
            "--network",
            net,
            "-e",
            "DOCKER_TLS_CERTDIR=",
            "-v",
            f"{HERE}/provision:/policy:ro",
            DIND_IMAGE,
            "--ipv6",
            "--ip6tables",
            "--fixed-cidr-v6=fd00:d0c::/64",
        ],
        out=DEVNULL,
    )
    host_ip = network_address(host_name, net)
    host = StandIn(host_name)

    wait_until(
        lambda: host.ok("docker info"),
        limit=60,
        message="the stand-in host's dockerd never came up",
    )
    host.dockerd_path = host.output(
        r'tr "\0" "\n" < /proc/$(pidof dockerd)/environ | sed -n "s/^PATH=//p"'
    ).strip()
    if not host.dockerd_path:
        raise ProofAbort("could not read dockerd's PATH on the stand-in host")

    # The policy script is bash; the dind image is alpine.
    host.run("apk add --no-cache bash >/dev/null")
    save = subprocess.Popen(["docker", "save", PROBE_IMAGE], stdout=PIPE)
    try:
        run(
            ["docker", "exec", "-i", host_name, "docker", "load"],
            out=DEVNULL,
            stdin=save.stdout,
        )
    finally:
        if save.stdout is not None:
            save.stdout.close()
        save.wait()
    run(["docker", "exec", outside, "ip", "route", "add", SPOOL_SUBNET, "via", host_ip])

    # The spool's networks as render-core renders them: one non-internal bridge
    # with a fixed name and masquerade off, one internal network for a tenant.
    host.run(
        f"docker network create --driver bridge --ipv6 --subnet {SPOOL_SUBNET} --gateway {GATEWAY} "
        "--subnet fd00:50::/64 -o com.docker.network.bridge.name=br-mailspool "
        "-o com.docker.network.bridge.enable_ip_masquerade=false drain >/dev/null"
    )
    host.run("docker network create --internal tenant >/dev/null")
    host.run(
        f"docker run -d --name spool --network drain -p 127.0.0.1:18080:8080 {PROBE_IMAGE} python -m http.server 8080 >/dev/null"
    )
    host.run("docker network connect tenant spool")
    # An ordinary application network, with masquerade, standing in for Ghost.
    host.run("docker network create app >/dev/null")
    run(
        [
            "docker",
            "exec",
            "-d",
            host_name,
            "sh",
            "-c",
            "while true; do echo ok | nc -l -p 9099 >/dev/null 2>&1; done",
        ]
    )

    wait_until(
        lambda: host.ok("wget -q -T 2 -O /dev/null http://127.0.0.1:18080/"),
        limit=30,
        message="the spool container never answered",
    )

    to_outside = f"wget -q -T 3 -O /dev/null http://{outside_ip}:8080/"
    to_host = "sh -c 'echo | nc -w 3 " + GATEWAY + " 9099 | grep -q ok'"
    to_spool_on_tenant_net = "wget -q -T 3 -O /dev/null http://spool:8080/"

    def probe(network: str, command: str) -> bool:
        # A one-shot probe container on the stand-in host. Exit 0 means it connected.
        return host.ok(f"docker run --rm --network {network} {PROBE_IMAGE} {command}")

    tally.heading("controls, before the policy")
    tally.expect_reach(
        "a container on the drain bridge reaches the outside",
        lambda: probe("drain", to_outside),
    )
    tally.expect_reach(
        "a container on the drain bridge reaches a host service",
        lambda: probe("drain", to_host),
    )
    tally.expect_reach(
        "an application-network container reaches the outside",
        lambda: probe("app", to_outside),
    )

    tally.heading("the policy")
    host.run(f"bash {POLICY}")
    first = count_lines_containing(host.output("iptables-save"), "br-mailspool")
    host.run(f"bash {POLICY}", out=DEVNULL)
    second = count_lines_containing(host.output("iptables-save"), "br-mailspool")
    if first == second and first >= 3:
        tally.passed(f"a second run leaves the same {first} drain-bridge rules")
    else:
        tally.failed(
            f"a second run changed the drain-bridge rule count from {first} to {second}"
        )

    # A host that already has the policy: drop the spool's forward rule and re-run;
    # it must come back directly under the conntrack accept, as it does at boot.
    host.run("iptables -D DOCKER-USER -i br-mailspool ! -o br-mailspool -j DROP")
    host.run(f"bash {POLICY}", out=DEVNULL)
    tally.expect_reach(
        "a re-run puts the forward drop second, under the conntrack accept",
        lambda: host.ok(
            "iptables -S DOCKER-USER | sed -n 2p | grep -q ctstate && iptables -S DOCKER-USER | sed -n 3p | grep -q 'br-mailspool'"
        ),
    )
    tally.expect_reach(
        "the IPv6 family carries the INPUT rules",
        lambda: host.ok(
            "ip6tables -S INPUT | grep -q -- '-i br-mailspool -j DROP' && "
            "ip6tables -S INPUT | grep -Eq -- '-i br-mailspool .*ctstate (RELATED,ESTABLISHED|ESTABLISHED,RELATED) -j ACCEPT'"
        ),
    )
    # Position, not presence: a drop beneath Docker's own RETURN is never reached.
    tally.expect_reach(
        "the IPv6 forward drop is the first rule, above any RETURN",
        lambda: host.ok(
            "ip6tables -S DOCKER-USER | sed -n 2p | grep -q -- '-i br-mailspool ! -o br-mailspool -j DROP'"
        ),
    )
    # Behaviour: a packet forwarded from the drain bridge to an off-bridge IPv6
    # destination must hit the drop (its counter moves) and so must be dropped.
    host.run(
        "ip link add proofdummy type dummy && ip link set proofdummy up && ip -6 route add 2001:db8:1::/64 dev proofdummy"
    )
    # The policy's own IPv6 INPUT drop also blocks neighbour discovery (types 135
    # and 136), so the probe could never find its gateway and forward a packet.
    # Allow just those two for the probe, then remove them. Production is untouched.
    for nd in (135, 136):
        host.run(
            f"ip6tables -I INPUT 1 -i br-mailspool -p icmpv6 --icmpv6-type {nd} -j ACCEPT"
        )
    v6_before = host.output("ip6tables -nvxL DOCKER-USER 1 | awk '{print $1}'").strip()
    host.run(
        f"docker run --rm --network drain {PROBE_IMAGE} ping -6 -c 1 -W 2 2001:db8:1::1",
        out=DEVNULL,
        err=DEVNULL,
        check=False,
    )
    v6_after = host.output("ip6tables -nvxL DOCKER-USER 1 | awk '{print $1}'").strip()
    for nd in (135, 136):
        host.run(
            f"ip6tables -D INPUT -i br-mailspool -p icmpv6 --icmpv6-type {nd} -j ACCEPT"
        )
    before_n = packet_count(v6_before)
    after_n = packet_count(v6_after)
    if before_n is not None and after_n is not None and after_n > before_n:
        tally.passed(
            f"a forwarded IPv6 packet from the drain bridge hit the drop ({v6_before} -> {v6_after})"
        )
    else:
        tally.failed(
            f"a forwarded IPv6 packet from the drain bridge did not hit the drop ({v6_before} -> {v6_after})"
        )

    tally.heading("after the policy")
    tally.expect_blocked(
        "a container on the drain bridge cannot reach the outside",
        lambda: probe("drain", to_outside),
    )
    tally.expect_blocked(
        "a container on the drain bridge cannot reach a host service",
        lambda: probe("drain", to_host),
    )
    tally.expect_reach(
        "an application-network container still reaches the outside",
        lambda: probe("app", to_outside),
    )
    tally.expect_reach(
        "the host still reaches the spool on its published loopback port",
        lambda: host.reaches("wget -q -T 3 -O /dev/null http://127.0.0.1:18080/"),
    )
    tally.expect_reach(
        "a container on the spool's tenant network still reaches the spool",
        lambda: probe("tenant", to_spool_on_tenant_net),
    )
    tally.expect_reach(
        "the host itself still reaches the outside", lambda: host.reaches(to_outside)
    )


def main() -> int:
    tally = Tally()
    prefix = f"bl-spool-egress-proof-{os.getpid()}"
    host_name = f"{prefix}-host"
    outside = f"{prefix}-outside"
    net = f"{prefix}-net"
    try:
        prove(tally, host_name, outside, net)
        return tally.summary()
    except ProofAbort as abort:
        print(abort)
        return 1
    except subprocess.CalledProcessError as failed:
        print(f"command failed: {failed.cmd}")
        return 1
    finally:
        if not keep_containers():
            remove_resources([host_name, outside], [net])


if __name__ == "__main__":
    raise SystemExit(main())
