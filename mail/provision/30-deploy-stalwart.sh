#!/usr/bin/env bash
# Deploys Stalwart via Docker Compose. Idempotent: `docker compose up -d`
# is itself a no-op when the running container already matches the compose
# file, so this script just keeps the on-box copy of the compose file in
# sync with the one committed here and lets compose decide whether anything
# needs to change.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR=/opt/stalwart
DEST_COMPOSE="$DEST_DIR/docker-compose.yml"

mkdir -p "$DEST_DIR"

if [[ -f "$DEST_COMPOSE" ]] && cmp -s "$SCRIPT_DIR/docker-compose.yml" "$DEST_COMPOSE"; then
    echo "30-deploy-stalwart: $DEST_COMPOSE already up to date"
else
    cp "$SCRIPT_DIR/docker-compose.yml" "$DEST_COMPOSE"
    echo "30-deploy-stalwart: updated $DEST_COMPOSE"
fi

docker compose -f "$DEST_COMPOSE" up -d

echo "30-deploy-stalwart: waiting for the container to report healthy"
for _ in $(seq 1 30); do
    status="$(docker inspect --format '{{.State.Health.Status}}' stalwart 2>/dev/null || echo "starting")"
    if [[ "$status" == "healthy" ]]; then
        echo "30-deploy-stalwart: stalwart is healthy"
        exit 0
    fi
    sleep 2
done

echo "30-deploy-stalwart: stalwart did not report healthy within 60s (last status: ${status:-unknown})" >&2
docker logs --tail 50 stalwart >&2 || true
exit 1
