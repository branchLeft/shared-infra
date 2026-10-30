#!/bin/sh
# Test stand-in for docker, installed by prepare.yml. It is not a Docker and proves
# nothing about the real one: it answers the few commands the role and the shared
# Compose unit make from files in /var/lib/standin-docker, which tasks/standin_state.yml
# writes, so a case can make it report a bad value. The spool itself is the stub in
# drain-stub.py, started and stopped as `compose up` and `compose down`.
echo "docker $*" >> /var/log/docker-standin.calls

state=/var/lib/standin-docker
project=/opt/branchleft/mail-spool
volumes=/var/lib/docker/volumes

case $1 in
  volume)
    case $2 in
      inspect)
        [ -d "$volumes/$3/_data" ] || {
          echo "Error: No such volume: $3" >&2
          exit 1
        }
        printf '[{"Name": "%s", "Mountpoint": "%s/%s/_data"}]\n' "$3" "$volumes" "$3"
        ;;
      create)
        mkdir -p "$volumes/$3/_data"
        echo "$3"
        ;;
      *) exit 1 ;;
    esac
    ;;
  inspect)
    [ "$2" = mail-spool-mail-spool-1 ] || exit 1
    # The image the container was started with is filled in where the file holds the
    # marker; a case that wants another image writes it into the file instead.
    image=$(cat "$state/running-image" 2>/dev/null || true)
    sed "s|@@IMAGE@@|$image|" "$state/inspect.json"
    ;;
  port)
    [ "$2" = mail-spool-mail-spool-1 ] || exit 1
    cat "$state/port.txt"
    ;;
  compose)
    # The unit runs in the project directory. A missing Compose file is an error.
    [ -f "$project/compose.yml" ] || {
      echo "no configuration file provided: not found" >&2
      exit 1
    }
    case $2 in
      pull) exit 0 ;;
      up)
        # The Compose file interpolates this with ${SHIM_DRAIN_TOKEN:?...}, which
        # fails the run when the owner's environment file is missing or empty.
        [ -n "${SHIM_DRAIN_TOKEN:-}" ] || {
          echo "required variable SHIM_DRAIN_TOKEN is missing a value" >&2
          exit 1
        }
        # With the override beside the Compose file, Compose runs the image from the
        # environment the unit loads from the pin file. Without it, it runs the image
        # the Compose file carries, which is what the role must never leave in place.
        if [ -f "$project/compose.override.yml" ]; then
          [ -n "${IMAGE:-}" ] || {
            echo "required variable IMAGE is missing a value" >&2
            exit 1
          }
          image=$IMAGE
        else
          image=$(sed -n "s/^ *image: *'\(.*\)' *$/\1/p" "$project/compose.yml" | head -n 1)
        fi
        printf '%s' "$image" > "$state/running-image"
        systemctl start standin-drain-stub.service
        # Compose --wait returns once the service is up.
        tries=0
        while [ "$tries" -lt 40 ]; do
          if ss -H -ltn 'sport = :8095' | grep -q LISTEN; then
            exit 0
          fi
          tries=$((tries + 1))
          sleep 0.5
        done
        echo "standin: the drain stub did not start listening" >&2
        exit 1
        ;;
      down)
        systemctl stop standin-drain-stub.service
        ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 0 ;;
esac
