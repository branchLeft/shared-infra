#!/bin/sh
# Proves ops1's control-plane port rules in
# hetzner/provision/branchleft_docker_user_policy.sh against a real dockerd
# inside a privileged Docker-in-Docker stand-in for ops1. Two outside
# containers stand in for edge1 and db1; the stand-in publishes 8301, 8302
# and an unrelated port (Nextcloud's stand-in) on its own address. Creates only
# containers and a network under one prefix.
# Usage: ./hetzner/scripts/test-control-plane-port-policy.sh
set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="bl-cp-ports-proof-$$"
HOST="$PREFIX-host"
EDGE="$PREFIX-edge"
OTHER="$PREFIX-other"
NET="$PREFIX-net"
DIND_IMAGE="docker:27-dind"
PROBE_IMAGE="python:3.12-alpine"

PASSES=0
FAILURES=0

cleanup() {
    docker rm -f -v "$HOST" "$EDGE" "$OTHER" >/dev/null 2>&1 || true
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

expect_reach() {
    if eval "$2"; then pass "$1"; else fail "$1"; fi
}

expect_blocked() {
    if eval "$2"; then fail "$1"; else pass "$1"; fi
}

docker image inspect "$PROBE_IMAGE" >/dev/null 2>&1 || docker pull -q "$PROBE_IMAGE" >/dev/null
docker image inspect "$DIND_IMAGE" >/dev/null 2>&1 || docker pull -q "$DIND_IMAGE" >/dev/null

docker network create --label branchleft.agent=port-policy-proof "$NET" >/dev/null
docker run -d --label branchleft.agent=port-policy-proof --name "$EDGE" --network "$NET" "$PROBE_IMAGE" sleep 3600 >/dev/null
docker run -d --label branchleft.agent=port-policy-proof --name "$OTHER" --network "$NET" "$PROBE_IMAGE" sleep 3600 >/dev/null
EDGE_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$EDGE")"

docker run -d --privileged --label branchleft.agent=port-policy-proof --name "$HOST" --hostname ops1-proof --network "$NET" \
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

# The three published ports, each on the host's own address as the control
# plane's compose publishes them: portal, console and an unrelated one.
for pair in 8301:portal 8302:console 11000:nextcloud; do
    port="${pair%%:*}"
    name="${pair##*:}"
    on_host "docker run -d --name $name -p $HOST_IP:$port:8080 $PROBE_IMAGE python -m http.server 8080 >/dev/null"
done

# The stand-in is ops1 by address (the guard on the policy), so the same
# env-free code path as a boot is used wherever possible. This host's NET
# address is not 10.20.1.50, so the two values the real host gets from its
# defaults are given explicitly; the gateway is the edge stand-in.
POLICY_ENV="BRANCHLEFT_DOCKER_USER_POLICY_PROTECTED_ADDRESS=$HOST_IP BRANCHLEFT_DOCKER_USER_POLICY_GATEWAY_IP=$EDGE_IP BRANCHLEFT_DOCKER_USER_POLICY_DB_HOST="
run_policy() { on_host "env $POLICY_ENV bash /policy/branchleft_docker_user_policy.sh"; }

# Every server answers before any control runs, so no control races a start.
for port in 8301 8302 11000; do
    tries=0
    until docker exec "$OTHER" wget -q -T 2 -O /dev/null "http://$HOST_IP:$port/" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -lt 30 ] || { echo "the stand-in server on $port never answered"; exit 1; }
        sleep 1
    done
done

from() { docker exec "$1" wget -q -T 3 -O /dev/null "http://$HOST_IP:$2/"; }

echo "== controls, before the policy"
expect_reach "the other host reaches 8301" "from $OTHER 8301"
expect_reach "the other host reaches 8302" "from $OTHER 8302"
expect_reach "the gateway reaches 8301" "from $EDGE 8301"
expect_reach "the other host reaches the unrelated port" "from $OTHER 11000"

echo "== the policy"
run_policy
FIRST="$(on_host "iptables-save" | grep -c ctorigdstport || true)"
run_policy >/dev/null
SECOND="$(on_host "iptables-save" | grep -c ctorigdstport || true)"
if [ "$FIRST" = "$SECOND" ] && [ "$FIRST" -eq 2 ]; then
    pass "a second run leaves the same $FIRST port rules"
else
    fail "a second run changed the port rule count from $FIRST to $SECOND"
fi
expect_reach "the conntrack accept is still the first rule" \
    "on_host \"iptables -S DOCKER-USER | sed -n 2p | grep -q ctstate\""

echo "== after the policy"
expect_blocked "the other host is refused 8301" "from $OTHER 8301"
expect_blocked "the other host is refused 8302" "from $OTHER 8302"
expect_reach "the gateway still reaches 8301" "from $EDGE 8301"
expect_reach "the gateway still reaches 8302" "from $EDGE 8302"
expect_reach "the other host still reaches the unrelated port" "from $OTHER 11000"
expect_reach "the host itself still reaches 8301" \
    "on_host \"wget -q -T 3 -O /dev/null http://$HOST_IP:8301/\""

echo "== sabotage: the 8301 rule removed, the other host reaches 8301 again"
on_host "iptables -D DOCKER-USER -p tcp -m conntrack --ctorigdst $HOST_IP --ctorigdstport 8301 ! -s $EDGE_IP -j DROP"
expect_reach "with the 8301 rule removed the other host is not refused" "from $OTHER 8301"
expect_blocked "the 8302 rule is untouched, the other host is still refused 8302" "from $OTHER 8302"
run_policy >/dev/null
expect_blocked "a re-run restores the refusal on 8301" "from $OTHER 8301"

echo
echo "$PASSES passed, $FAILURES failed"
[ "$FAILURES" -eq 0 ]
