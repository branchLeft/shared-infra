#!/usr/bin/env bash
# Runs a command under the Node version named in the repository's .nvmrc,
# never under whichever `node` happens to be first on PATH. The commit hooks
# that run Node go through this, so a commit made from a shell on another
# Node cannot change which runtime the suites run under.
#
# Usage: scripts/nvmrc-node-exec.sh <command> [args...]
#
# Resolves the binary from the nvm install layout
# ($HOME/.nvm/versions/node/v<version>/bin). When that version is not
# installed, prints one line naming the required version and exits 1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

raw=""
if [[ -r "$ROOT/.nvmrc" ]]; then
    raw="$(tr -d '[:space:]' < "$ROOT/.nvmrc")"
fi
ver="${raw#v}"
if [[ ! "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "nvmrc-node-exec: .nvmrc must name one exact Node version (found '${raw}')" >&2
    exit 1
fi

bin="$HOME/.nvm/versions/node/v$ver/bin"
if [[ ! -x "$bin/node" ]]; then
    echo "nvmrc-node-exec: this repository needs Node v$ver (.nvmrc); install it with 'nvm install $ver'" >&2
    exit 1
fi

export PATH="$bin:$PATH"
exec "$@"
