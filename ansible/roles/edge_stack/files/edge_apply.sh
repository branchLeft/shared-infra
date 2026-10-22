#!/bin/sh
# The part of the edge_stack role that runs under the deploy lock, in two modes
# (validate, apply). It opens no secrets file itself and prints one marker line
# "EDGE_APPLY <name>" per thing done and read back. Exit codes 64 to 74; 75 is the
# lock's, never ours. README.md, "The locked script", says what each one means.
set -eu

mode=$1

fail() {
  code=$1
  shift
  echo "edge_apply: $*" >&2
  exit "$code"
}

say() {
  echo "EDGE_APPLY $1"
}

# Compose as the unit runs it: the project directory, and both env files, so that
# ${IMAGE} and the required keys interpolate exactly as they do for the unit.
dcf() {
  file=$1
  shift
  docker compose --project-directory "$EDGE_PROJECT_DIR" \
    --env-file "$EDGE_IMAGE_ENV" --env-file "$EDGE_ENV_FILE" -f "$file" "$@"
}

dc() {
  dcf "$EDGE_PROJECT_DIR/compose.yml" "$@"
}

# sha256 of a file, the hash alone.
sha_of() {
  sha256sum < "$1" | cut -d ' ' -f 1
}

# A service is running: it is listed by `ps --status running`.
is_running() {
  listed=$(dc ps --status running --services) || return 1
  printf '%s\n' "$listed" | grep -qx "$1"
}

# What is inside the container equals what is on the host: one file.
same_inside() {
  service=$1
  inside_path=$2
  host_path=$3
  code=$4
  want=$(sha_of "$host_path")
  got=$(dc exec -T "$service" sha256sum "$inside_path" | cut -d ' ' -f 1) || fail "$code" "could not read $inside_path inside $service"
  [ "$want" = "$got" ] || fail "$code" "$inside_path inside $service is not the file on the host"
}

# The pin is read again inside the lock, whatever the role read before it.
lines=$(grep -c '' "$EDGE_IMAGE_ENV") || lines=0
[ "$lines" = 1 ] || fail 64 "$EDGE_IMAGE_ENV is not exactly one line"
grep -Eq -- "$EDGE_IMAGE_PATTERN" "$EDGE_IMAGE_ENV" || fail 64 "$EDGE_IMAGE_ENV is not IMAGE=<reference>@sha256:<64 hex digits>"
image=$(sed -e 's/^IMAGE=//' "$EDGE_IMAGE_ENV")

if [ "$mode" = validate ]; then
  # The reference the candidates are validated in. The role hands it to apply, which
  # refuses to act on a different one.
  echo "EDGE_PIN $image"
  # The placeholders are the ones CI and the runbook use. The check parses and
  # adapts the file; it contacts nothing and issues no certificate. The Caddy
  # check needs no real value, so edge.env is not given to it. The Compose check
  # below is different: dcf passes edge.env to Compose, which reads it.
  if [ -n "${EDGE_CADDY_CANDIDATE:-}" ]; then
    out=$(docker run --rm \
      --env CROWDSEC_BOUNCER_KEY=validation-only \
      --env ACME_EMAIL=validation@example.invalid \
      --volume "$EDGE_CADDY_CANDIDATE:/etc/caddy/Caddyfile:ro" \
      "$image" caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile 2>&1) || {
      printf '%s\n' "$out" >&2
      fail 65 "Caddy refused the candidate Caddyfile"
    }
    case $out in
      *"Valid configuration"*) ;;
      *)
        printf '%s\n' "$out" >&2
        fail 65 "Caddy did not report a valid configuration"
        ;;
    esac
    say caddy-validated
  fi
  if [ -n "${EDGE_COMPOSE_CANDIDATE:-}" ]; then
    dcf "$EDGE_COMPOSE_CANDIDATE" config -q || fail 67 "docker compose refused the candidate Compose file"
    say compose-validated
  fi
  exit 0
fi

[ "$mode" = apply ] || fail 64 "unknown mode $mode"

# The digest the candidates were validated in is the digest the classes are applied
# with. Only the whole reference is compared: a pin that merely still matches the
# pattern is a different digest. Nothing has been done when this fails.
[ -n "${EDGE_VALIDATED_PIN:-}" ] || fail 74 "no validated pin was given, so nothing was validated in this run"
[ "$EDGE_VALIDATED_PIN" = "$image" ] || fail 74 "$EDGE_IMAGE_ENV changed since the candidates were validated"

# 1. The Caddyfile, written into the existing file, so the inode the container's
# single-file bind mount holds is the inode that changes. A rename would leave the
# container reading the old file. A power cut during the write can leave a torn
# file; the next run's comparison sees it (README, "Named limits").
if [ "$EDGE_CADDY_WRITE" = 1 ]; then
  dest=$EDGE_PROJECT_DIR/Caddyfile
  if [ -e "$dest" ] || [ -L "$dest" ]; then
    { [ -f "$dest" ] && [ ! -L "$dest" ]; } || fail 66 "$dest is not a regular file"
  else
    install -m 0644 -o root -g root /dev/null "$dest"
  fi
  cat "$EDGE_CADDY_CANDIDATE" > "$dest" || fail 66 "could not write $dest"
  [ "$(sha_of "$dest")" = "$(sha_of "$EDGE_CADDY_CANDIDATE")" ] || fail 66 "$dest is not the candidate after the write"
  say caddy-written
fi

# 2. The unit: the only path that runs `docker compose up`. A restart of it runs
# `up -d --remove-orphans --wait` and recreates only a service whose configuration moved.
if [ "$EDGE_COMPOSE_RESTART" = 1 ]; then
  systemctl restart "$EDGE_UNIT" || fail 68 "restarting $EDGE_UNIT failed"
  systemctl is-active --quiet "$EDGE_UNIT" || fail 69 "$EDGE_UNIT is not active after the restart"
  for service in caddy crowdsec; do
    is_running "$service" || fail 69 "$service is not running after the restart"
  done
  say compose-restarted
fi

# 3. CrowdSec: a restart of the container, never an `up`. Its API must answer
# again, and each file it reads must be the file on the host, read inside it.
if [ "$EDGE_CROWDSEC_RESTART" = 1 ]; then
  if is_running crowdsec; then
    dc restart crowdsec || fail 70 "restarting the crowdsec container failed"
    tries=0
    until dc exec -T crowdsec cscli lapi status > /dev/null 2>&1; do
      tries=$((tries + 1))
      [ "$tries" -lt "$EDGE_WAIT_TRIES" ] || fail 71 "CrowdSec's Local API did not answer after $tries tries"
      sleep "$EDGE_WAIT_INTERVAL"
    done
    same_inside crowdsec /etc/crowdsec/config.yaml.local "$EDGE_PROJECT_DIR/crowdsec/config.yaml.local" 71
    for host_path in "$EDGE_PROJECT_DIR"/crowdsec/acquis.d/*; do
      [ -e "$host_path" ] || continue
      same_inside crowdsec "/etc/crowdsec-acquis.d/$(basename "$host_path")" "$host_path" 71
    done
    host_names=$(ls -1 "$EDGE_PROJECT_DIR/crowdsec/acquis.d")
    inside_names=$(dc exec -T crowdsec ls -1 /etc/crowdsec-acquis.d) || fail 71 "could not list the acquisition directory inside crowdsec"
    [ "$host_names" = "$inside_names" ] || fail 71 "the acquisition directory inside crowdsec lists different files from the host"
    say crowdsec-restarted
  else
    say crowdsec-not-running
  fi
fi

# 4. Caddy: validated before the write, so a reload is the whole action. The file
# is read back inside the container, which shows the mount sees these bytes; that
# Caddy loaded them is the exit status of the reload.
if [ "$EDGE_CADDY_RELOAD" = 1 ]; then
  if is_running caddy; then
    dc exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile || fail 72 "caddy reload failed"
    same_inside caddy /etc/caddy/Caddyfile "$EDGE_PROJECT_DIR/Caddyfile" 73
    say caddy-reloaded
  else
    say caddy-not-running
  fi
fi
