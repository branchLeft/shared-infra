#!/bin/sh
# What the placeholder branchleft-compose@.service runs as its ExecStart in the
# role's test, installed by prepare.yml. The real unit runs
# `docker compose up -d --remove-orphans --wait`; this logs one line to the
# stand-in's call log, with the first twelve characters of the sha256 of the
# Caddyfile and the Compose file on the host at that moment, so a test can see
# both were placed before the unit started, and marks both services running. It
# fails while /run/edge-unit.fail exists.
short_sha() {
  sha256sum < "$1" 2> /dev/null | cut -c1-12
}

if [ -e /run/edge-unit.fail ]; then
  echo "UNIT-START-FAILED" >> /var/log/docker-standin.calls
  exit 1
fi
echo "UNIT-START caddyfile=$(short_sha /opt/branchleft/edge/Caddyfile) compose=$(short_sha /opt/branchleft/edge/compose.yml)" >> /var/log/docker-standin.calls
# `up -d --wait` leaves both services running, as the real unit does.
printf 'caddy\ncrowdsec\n' > /run/standin.running
