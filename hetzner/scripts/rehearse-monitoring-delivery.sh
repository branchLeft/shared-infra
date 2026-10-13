#!/usr/bin/env bash
# Rehearses the monitoring delivery with no host: the real archive, through the
# real branchleft-sync-stack in --rehearse mode, into a scratch directory.
# Proves the archive is accepted, that the result matches the committed tree,
# that a second sync changes nothing (so no restart), and that a truncated
# archive is refused. Needs no credentials, so it runs on pull requests.
# Usage: hetzner/scripts/rehearse-monitoring-delivery.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYNC="$HERE/provision/branchleft_sync_stack.py"
ARCHIVE="$HERE/scripts/monitoring-stack-archive.sh"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

"$ARCHIVE" > "$scratch/stack.tar"

echo "--- first sync into an empty directory"
python3 "$SYNC" --rehearse "$scratch/host" monitoring < "$scratch/stack.tar" | tee "$scratch/first.log"
grep -q 'would restart' "$scratch/first.log" || { echo "rehearse: a first sync should report a restart" >&2; exit 1; }

echo "--- the result matches the committed stack"
diff -r \
    -x alertmanager.yml -x server.yml -x mx1-metrics-password -x __pycache__ \
    "$HERE/monitoring/stack" "$scratch/host/monitoring"

echo "--- a second sync changes nothing"
python3 "$SYNC" --rehearse "$scratch/host" monitoring < "$scratch/stack.tar" | tee "$scratch/second.log"
grep -q 'unchanged, no restart' "$scratch/second.log" || { echo "rehearse: a repeat sync should change nothing" >&2; exit 1; }

echo "--- a truncated archive is refused and leaves the host as it was"
before="$(cd "$scratch/host" && find . -type f -exec cksum {} + | sort)"
size="$(wc -c < "$scratch/stack.tar")"
head -c "$((size / 2))" "$scratch/stack.tar" > "$scratch/truncated.tar"
if python3 "$SYNC" --rehearse "$scratch/host" monitoring < "$scratch/truncated.tar"; then
    echo "rehearse: a truncated archive was accepted" >&2
    exit 1
fi
after="$(cd "$scratch/host" && find . -type f -exec cksum {} + | sort)"
[[ "$before" == "$after" ]] || { echo "rehearse: a refused archive changed the host" >&2; exit 1; }

echo "rehearse: ok"
