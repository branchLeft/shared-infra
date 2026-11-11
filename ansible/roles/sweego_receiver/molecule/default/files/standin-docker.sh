#!/bin/sh
# Test stand-in for docker, installed by prepare.yml. It is not a Docker and proves nothing
# about the real one: it answers the few commands the role and the shared Compose unit make,
# and starts a stub that listens where the compose file says the receiver is published. It
# reports the container healthy from the file prepare.yml and the converge step write.
echo "docker $*" >> /var/log/docker-standin.calls

state=/var/lib/standin-docker
project=/opt/branchleft/sweego-receiver

case $1 in
  inspect)
    [ "$2" = sweego-receiver-receiver-1 ] || exit 1
    image=$(cat "$state/running-image" 2>/dev/null || true)
    sed "s|@@IMAGE@@|$image|" "$state/inspect.json"
    ;;
  compose)
    case $2 in
      config)
        # The role validates its own file before placing it. The stand-in only checks the
        # file is there; it does not parse the compose file.
        exit 0
        ;;
      pull) exit 0 ;;
      up)
        [ -f "$project/compose.yml" ] || {
          echo "no configuration file provided: not found" >&2
          exit 1
        }
        [ -n "${IMAGE:-}" ] || {
          echo "required variable IMAGE is missing a value" >&2
          exit 1
        }
        printf '%s' "$IMAGE" > "$state/running-image"
        # The port lines are quoted in the file; the quotes are dropped before they are read.
        published=$(tr -d "'" < "$project/compose.yml")
        address=$(echo "$published" | sed -n 's/^ *- \([0-9.]*\):[0-9]*:8080$/\1/p')
        public=$(echo "$published" | sed -n 's/^ *- [0-9.]*:\([0-9]*\):8080$/\1/p')
        drain=$(echo "$published" | sed -n 's/^ *- [0-9.]*:\([0-9]*\):8081$/\1/p')
        systemctl stop standin-receiver.service 2>/dev/null || true
        systemd-run --quiet --collect --unit=standin-receiver \
          /usr/bin/python3 -I /usr/local/lib/standin/receiver-stub.py "$address" "$public" "$drain"
        tries=0
        while [ "$tries" -lt 40 ]; do
          if ss -H -ltn "sport = :$drain" | grep -q LISTEN; then
            exit 0
          fi
          tries=$((tries + 1))
          sleep 0.5
        done
        echo "standin: the receiver stub did not start listening" >&2
        exit 1
        ;;
      down)
        systemctl stop standin-receiver.service 2>/dev/null || true
        ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 0 ;;
esac
