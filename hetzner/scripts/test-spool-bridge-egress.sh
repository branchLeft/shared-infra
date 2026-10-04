#!/bin/sh
# Proves the mail spool's drain-bridge rules in
# hetzner/provision/branchleft_docker_user_policy.sh against a real dockerd
# inside a privileged Docker-in-Docker stand-in for an app host. Creates only
# containers and a network under one prefix.
# Usage: ./hetzner/scripts/test-spool-bridge-egress.sh
set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="bl-spool-egress-proof-$$"
HOST="$PREFIX-host"
OUTSIDE="$PREFIX-outside"
NET="$PREFIX-net"
DIND_IMAGE="docker:27-dind"
PROBE_IMAGE="python:3.12-alpine"
SPOOL_SUBNET="172.29.50.0/24"

PASSES=0
FAILURES=0

cleanup() {
    docker rm -f -v "$HOST" "$OUTSIDE" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
[ -n "${KEEP_PROOF_CONTAINERS:-}" ] || trap cleanup EXIT INT TERM

pass() { PASSES=$((PASSES + 1)); echo "PASS: $*"; }
fail() { FAILURES=$((FAILURES + 1)); echo "FAIL: $*"; }

# dockerd's own PATH, so the policy writes to the iptables backend dockerd uses.
DOCKERD_PATH=""
on_host() {
    if [ -n "$DOCKERD_PATH" ]; then
        docker exec -e PATH="$DOCKERD_PATH" "$HOST" sh -c "$1"
    else
        docker exec "$HOST" sh -c "$1"
    fi
}

# A one-shot probe container on the stand-in host. Exit 0 means it connected.
probe() {
    network="$1"
    shift
    on_host "docker run --rm --network $network $PROBE_IMAGE $*" >/dev/null 2>&1
}

expect_reach() {
    if eval "$2"; then pass "$1"; else fail "$1"; fi
}

expect_blocked() {
    if eval "$2"; then fail "$1"; else pass "$1"; fi
}

docker image inspect "$PROBE_IMAGE" >/dev/null 2>&1 || docker pull -q "$PROBE_IMAGE" >/dev/null
docker image inspect "$DIND_IMAGE" >/dev/null 2>&1 || docker pull -q "$DIND_IMAGE" >/dev/null

docker network create "$NET" >/dev/null
# NET_ADMIN so it can be given a return route to the spool bridge: the spool
# network has masquerade off, so without one no reply could ever come back and
# the "before" control would prove nothing.
docker run -d --cap-add NET_ADMIN --name "$OUTSIDE" --network "$NET" "$PROBE_IMAGE" \
    python -m http.server 8080 >/dev/null
OUTSIDE_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$OUTSIDE")"

docker run -d --privileged --name "$HOST" --hostname app-proof --network "$NET" \
    -e DOCKER_TLS_CERTDIR= \
    -v "$HERE/provision:/policy:ro" \
    "$DIND_IMAGE" >/dev/null
HOST_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$HOST")"

tries=0
until on_host "docker info" >/dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt 60 ] || { echo "the stand-in host's dockerd never came up"; exit 1; }
    sleep 1
done
# shellcheck disable=SC2016 # expanded on the stand-in host, not here
DOCKERD_PATH="$(on_host 'tr "\0" "\n" < /proc/$(pidof dockerd)/environ | sed -n "s/^PATH=//p"')"
[ -n "$DOCKERD_PATH" ] || { echo "could not read dockerd's PATH on the stand-in host"; exit 1; }

# The policy script is bash; the dind image is alpine.
on_host "apk add --no-cache bash >/dev/null"
docker save "$PROBE_IMAGE" | docker exec -i "$HOST" docker load >/dev/null
docker exec "$OUTSIDE" ip route add "$SPOOL_SUBNET" via "$HOST_IP"

# The spool's networks as render-core renders them: one non-internal bridge
# with a fixed name and masquerade off, one internal network for a tenant.
on_host "docker network create --driver bridge --subnet $SPOOL_SUBNET --gateway 172.29.50.1 \
    -o com.docker.network.bridge.name=br-mailspool \
    -o com.docker.network.bridge.enable_ip_masquerade=false drain >/dev/null"
on_host "docker network create --internal tenant >/dev/null"
on_host "docker run -d --name spool --network drain -p 127.0.0.1:18080:8080 $PROBE_IMAGE python -m http.server 8080 >/dev/null"
on_host "docker network connect tenant spool"
# An ordinary application network, with masquerade, standing in for Ghost.
on_host "docker network create app >/dev/null"
docker exec -d "$HOST" sh -c "while true; do echo ok | nc -l -p 9099 >/dev/null 2>&1; done"
GATEWAY=172.29.50.1

tries=0
until on_host "wget -q -T 2 -O /dev/null http://127.0.0.1:18080/" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -lt 30 ] || { echo "the spool container never answered"; exit 1; }
    sleep 1
done

TO_OUTSIDE="wget -q -T 3 -O /dev/null http://$OUTSIDE_IP:8080/"
TO_HOST="sh -c 'echo | nc -w 3 $GATEWAY 9099 | grep -q ok'"
TO_SPOOL_ON_TENANT_NET="wget -q -T 3 -O /dev/null http://spool:8080/"

echo "== controls, before the policy"
expect_reach "a container on the drain bridge reaches the outside" "probe drain \"$TO_OUTSIDE\""
expect_reach "a container on the drain bridge reaches a host service" "probe drain \"$TO_HOST\""
expect_reach "an application-network container reaches the outside" "probe app \"$TO_OUTSIDE\""

echo "== the policy"
on_host "bash /policy/branchleft_docker_user_policy.sh"
FIRST="$(on_host "iptables-save" | grep -c br-mailspool)"
on_host "bash /policy/branchleft_docker_user_policy.sh" >/dev/null
SECOND="$(on_host "iptables-save" | grep -c br-mailspool)"
if [ "$FIRST" = "$SECOND" ] && [ "$FIRST" -ge 3 ]; then
    pass "a second run leaves the same $FIRST drain-bridge rules"
else
    fail "a second run changed the drain-bridge rule count from $FIRST to $SECOND"
fi

echo "== after the policy"
expect_blocked "a container on the drain bridge cannot reach the outside" "probe drain \"$TO_OUTSIDE\""
expect_blocked "a container on the drain bridge cannot reach a host service" "probe drain \"$TO_HOST\""
expect_reach "an application-network container still reaches the outside" "probe app \"$TO_OUTSIDE\""
expect_reach "the host still reaches the spool on its published loopback port" \
    "on_host \"wget -q -T 3 -O /dev/null http://127.0.0.1:18080/\""
expect_reach "a container on the spool's tenant network still reaches the spool" \
    "probe tenant \"$TO_SPOOL_ON_TENANT_NET\""
expect_reach "the host itself still reaches the outside" "on_host \"$TO_OUTSIDE\""

echo
echo "$PASSES passed, $FAILURES failed"
[ "$FAILURES" -eq 0 ]
