#!/usr/bin/env python3
"""Proves ops1's control-plane port rules in
hetzner/provision/branchleft_docker_user_policy.sh against a real dockerd
inside a privileged Docker-in-Docker stand-in for ops1. Two outside
containers stand in for edge1 and db1; the stand-in publishes 8300, 8301,
8302 and an unrelated port (Nextcloud's stand-in) on its own address. Creates
only containers and a network under one prefix.

Usage: python3 hetzner/scripts/prove_control_plane_port_policy.py
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
    ok,
    reaches,
    remove_resources,
    run,
    wait_until,
)

HERE = Path(__file__).resolve().parents[1]
DIND_IMAGE = "docker:27-dind"
PROBE_IMAGE = "python:3.12-alpine"
LABEL = "branchleft.agent=port-policy-proof"
POLICY = "/policy/branchleft_docker_user_policy.sh"


def prove(tally: Tally, host_name: str, edge: str, other: str, net: str) -> None:
    ensure_image(PROBE_IMAGE)
    ensure_image(DIND_IMAGE)

    run(["docker", "network", "create", "--label", LABEL, net], out=DEVNULL)
    run(
        [
            "docker",
            "run",
            "-d",
            "--label",
            LABEL,
            "--name",
            edge,
            "--network",
            net,
            PROBE_IMAGE,
            "sleep",
            "3600",
        ],
        out=DEVNULL,
    )
    run(
        [
            "docker",
            "run",
            "-d",
            "--label",
            LABEL,
            "--name",
            other,
            "--network",
            net,
            PROBE_IMAGE,
            "sleep",
            "3600",
        ],
        out=DEVNULL,
    )
    edge_ip = network_address(edge, net)

    run(
        [
            "docker",
            "run",
            "-d",
            "--privileged",
            "--label",
            LABEL,
            "--name",
            host_name,
            "--hostname",
            "ops1-proof",
            "--network",
            net,
            "-e",
            "DOCKER_TLS_CERTDIR=",
            "-v",
            f"{HERE}/provision:/policy:ro",
            DIND_IMAGE,
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

    # Published ports, each on the host's own address as the control plane's
    # compose publishes them: portal, console and an unrelated one.
    for port, name in ((8301, "portal"), (8302, "console"), (11000, "nextcloud")):
        host.run(
            f"docker run -d --name {name} -p {host_ip}:{port}:8080 {PROBE_IMAGE} python -m http.server 8080 >/dev/null"
        )
    # The sign-in service is published twice, on the host's address and on its
    # loopback, as the compose does: the loopback one is the host's own recovery
    # path, which the policy must leave alone.
    host.run(
        f"docker run -d --name signin -p {host_ip}:8300:8080 -p 127.0.0.1:8300:8080 {PROBE_IMAGE} "
        "python -m http.server 8080 >/dev/null"
    )

    # The stand-in is ops1 by address (the guard on the policy), so the same
    # env-free code path as a boot is used wherever possible. This host's NET
    # address is not 10.20.1.50, so the two values the real host gets from its
    # defaults are given explicitly; the gateway is the edge stand-in.
    policy_env = (
        f"BRANCHLEFT_DOCKER_USER_POLICY_PROTECTED_ADDRESS={host_ip} "
        f"BRANCHLEFT_DOCKER_USER_POLICY_GATEWAY_IP={edge_ip} "
        "BRANCHLEFT_DOCKER_USER_POLICY_DB_HOST="
    )

    def run_policy(*, quiet: bool = False) -> None:
        host.run(f"env {policy_env} bash {POLICY}", out=DEVNULL if quiet else None)

    # Every server answers before any control runs, so no control races a start.
    for port in (8300, 8301, 8302, 11000):
        wait_until(
            lambda p=port: ok(
                [
                    "docker",
                    "exec",
                    other,
                    "wget",
                    "-q",
                    "-T",
                    "2",
                    "-O",
                    "/dev/null",
                    f"http://{host_ip}:{p}/",
                ]
            ),
            limit=30,
            message=f"the stand-in server on {port} never answered",
        )

    def from_(container: str, port: int) -> bool:
        return reaches(
            [
                "docker",
                "exec",
                container,
                "wget",
                "-q",
                "-T",
                "3",
                "-O",
                "/dev/null",
                f"http://{host_ip}:{port}/",
            ]
        )

    tally.heading("controls, before the policy")
    tally.expect_reach("the other host reaches 8300", lambda: from_(other, 8300))
    tally.expect_reach("the gateway reaches 8300", lambda: from_(edge, 8300))
    tally.expect_reach("the other host reaches 8301", lambda: from_(other, 8301))
    tally.expect_reach("the other host reaches 8302", lambda: from_(other, 8302))
    tally.expect_reach("the gateway reaches 8301", lambda: from_(edge, 8301))
    tally.expect_reach(
        "the other host reaches the unrelated port", lambda: from_(other, 11000)
    )

    tally.heading("the policy")
    run_policy()
    first = count_lines_containing(host.output("iptables-save"), "ctorigdstport")
    run_policy(quiet=True)
    second = count_lines_containing(host.output("iptables-save"), "ctorigdstport")
    if first == second and first == 3:
        tally.passed(f"a second run leaves the same {first} port rules")
    else:
        tally.failed(
            f"a second run changed the port rule count from {first} to {second}"
        )
    tally.expect_reach(
        "the conntrack accept is still the first rule",
        lambda: host.ok("iptables -S DOCKER-USER | sed -n 2p | grep -q ctstate"),
    )

    tally.heading("after the policy")
    tally.expect_blocked("the other host is refused 8300", lambda: from_(other, 8300))
    tally.expect_blocked("the other host is refused 8301", lambda: from_(other, 8301))
    tally.expect_blocked("the other host is refused 8302", lambda: from_(other, 8302))
    tally.expect_reach("the gateway still reaches 8300", lambda: from_(edge, 8300))
    tally.expect_reach("the gateway still reaches 8301", lambda: from_(edge, 8301))
    tally.expect_reach("the gateway still reaches 8302", lambda: from_(edge, 8302))
    tally.expect_reach(
        "the other host still reaches the unrelated port", lambda: from_(other, 11000)
    )
    tally.expect_reach(
        "the host itself still reaches 8300 on loopback",
        lambda: host.reaches("wget -q -T 3 -O /dev/null http://127.0.0.1:8300/"),
    )
    tally.expect_reach(
        "the host itself still reaches 8301",
        lambda: host.reaches(f"wget -q -T 3 -O /dev/null http://{host_ip}:8301/"),
    )

    tally.heading("sabotage: the 8301 rule removed, the other host reaches 8301 again")
    host.run(
        f"iptables -D DOCKER-USER -p tcp -m conntrack --ctorigdst {host_ip} --ctorigdstport 8301 ! -s {edge_ip} -j DROP"
    )
    tally.expect_reach(
        "with the 8301 rule removed the other host is not refused",
        lambda: from_(other, 8301),
    )
    tally.expect_blocked(
        "the 8302 rule is untouched, the other host is still refused 8302",
        lambda: from_(other, 8302),
    )
    run_policy(quiet=True)
    tally.expect_blocked(
        "a re-run restores the refusal on 8301", lambda: from_(other, 8301)
    )

    tally.heading("sabotage: the 8300 rule removed, the other host reaches 8300 again")
    host.run(
        f"iptables -D DOCKER-USER -p tcp -m conntrack --ctorigdst {host_ip} --ctorigdstport 8300 ! -s {edge_ip} -j DROP"
    )
    tally.expect_reach(
        "with the 8300 rule removed the other host is not refused",
        lambda: from_(other, 8300),
    )
    tally.expect_blocked(
        "the 8301 rule is untouched, the other host is still refused 8301",
        lambda: from_(other, 8301),
    )
    tally.expect_blocked(
        "the 8302 rule is untouched, the other host is still refused 8302",
        lambda: from_(other, 8302),
    )
    run_policy(quiet=True)
    tally.expect_blocked(
        "a re-run restores the refusal on 8300", lambda: from_(other, 8300)
    )


def main() -> int:
    tally = Tally()
    prefix = f"bl-cp-ports-proof-{os.getpid()}"
    host_name = f"{prefix}-host"
    edge = f"{prefix}-edge"
    other = f"{prefix}-other"
    net = f"{prefix}-net"
    try:
        prove(tally, host_name, edge, other, net)
        return tally.summary()
    except ProofAbort as abort:
        print(abort)
        return 1
    except subprocess.CalledProcessError as failed:
        print(f"command failed: {failed.cmd}")
        return 1
    finally:
        if not keep_containers():
            remove_resources([host_name, edge, other], [net])


if __name__ == "__main__":
    raise SystemExit(main())
