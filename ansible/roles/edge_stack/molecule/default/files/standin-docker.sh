#!/bin/sh
# Test stand-in for docker, installed by prepare.yml. It is not a Docker and proves
# nothing about the real one (README, "Named limits"). It does what the role's tests
# rely on:
#   - appends every call to /var/log/docker-standin.calls, so a test can count and
#     order what the role did;
#   - checks the arguments the real Compose needs and the role must pass: the
#     project directory and both env files, and refuses a call that lacks them;
#   - answers `run ... caddy validate` and `compose config` by looking for a marker
#     in the file it is given, so a test can make a candidate invalid;
#   - models the container's view of a single-file bind mount as a hard link in
#     /var/lib/standin-mount, so a file replaced by rename leaves the view on the
#     old bytes, as a real container's mount would be, and a write in place does not;
#   - fails, or lies, where a flag file in /run asks (standin.fail.crowdsec,
#     standin.fail.reload, standin.lapi.down, standin.stale.caddy), and reports the
#     services listed in /run/standin.running as running.
echo "docker $*" >> /var/log/docker-standin.calls

project=/opt/branchleft/edge
view=/var/lib/standin-mount
expected_env_files=" /etc/branchleft/edge.image.env /etc/branchleft/edge.env"

short_sha() {
  sha256sum < "$1" 2> /dev/null | cut -c1-12
}

case $1 in
  run)
    shift
    candidate=
    for arg in "$@"; do
      case $arg in
        /*:/etc/caddy/Caddyfile:ro) candidate=${arg%%:*} ;;
        *) ;;
      esac
    done
    [ -n "$candidate" ] || {
      echo "standin: no volume mounts a file at /etc/caddy/Caddyfile" >&2
      exit 2
    }
    if grep -q BROKEN-CADDYFILE "$candidate"; then
      echo "Error: adapting config using caddyfile: broken"
      exit 1
    fi
    echo "Valid configuration"
    exit 0
    ;;
  compose)
    shift
    have_project=
    env_files=
    file=
    while :; do
      case $1 in
        --project-directory)
          [ "$2" = "$project" ] && have_project=1
          shift 2
          ;;
        --env-file)
          env_files="$env_files $2"
          shift 2
          ;;
        -f)
          file=$2
          shift 2
          ;;
        *) break ;;
      esac
    done
    [ -n "$have_project" ] || {
      echo "standin: compose was called without --project-directory $project" >&2
      exit 2
    }
    [ "$env_files" = "$expected_env_files" ] || {
      echo "standin: compose was called with env files '$env_files'" >&2
      exit 2
    }
    sub=$1
    shift
    case $sub in
      config)
        grep -q BROKEN-COMPOSE "$file" && exit 1
        exit 0
        ;;
      ps)
        [ -e /run/standin.running ] && cat /run/standin.running
        exit 0
        ;;
      restart)
        [ -e /run/standin.fail.crowdsec ] && exit 1
        ln -f "$project/crowdsec/config.yaml.local" "$view/config.yaml.local"
        echo "RESTART-CROWDSEC config=$(short_sha "$project/crowdsec/config.yaml.local")" >> /var/log/docker-standin.calls
        exit 0
        ;;
      exec)
        shift
        service=$1
        shift
        case $service:$1 in
          crowdsec:cscli)
            [ -e /run/standin.lapi.down ] && exit 1
            exit 0
            ;;
          crowdsec:ls)
            ls -1 "$project/crowdsec/acquis.d"
            exit 0
            ;;
          crowdsec:sha256sum)
            case $2 in
              /etc/crowdsec/config.yaml.local) source=$view/config.yaml.local ;;
              /etc/crowdsec-acquis.d/*) source=$project/crowdsec/acquis.d/${2#/etc/crowdsec-acquis.d/} ;;
              *) exit 1 ;;
            esac
            sum=$(sha256sum < "$source") || exit 1
            echo "${sum%% *}  $2"
            exit 0
            ;;
          caddy:caddy)
            [ -e /run/standin.fail.reload ] && exit 1
            echo "RELOAD caddyfile=$(short_sha "$project/Caddyfile")" >> /var/log/docker-standin.calls
            exit 0
            ;;
          caddy:sha256sum)
            if [ -e /run/standin.stale.caddy ]; then
              echo "0000000000000000000000000000000000000000000000000000000000000000  $2"
              exit 0
            fi
            sum=$(sha256sum < "$view/Caddyfile") || exit 1
            echo "${sum%% *}  $2"
            exit 0
            ;;
          *) exit 1 ;;
        esac
        ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 0 ;;
esac
