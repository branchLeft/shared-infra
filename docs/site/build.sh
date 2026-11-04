#!/bin/sh
# Builds the site into docs/site/public. The one network step is fetching the pinned release
# binary, which is checked against its sha256 before it is unpacked; the build itself needs no
# network. Built output is not committed (see .gitignore).
#
#   sh docs/site/build.sh            fetch the binary if it is absent, then build
#   sh docs/site/build.sh --offline  build only; fail if the binary is absent
set -eu

cd "$(dirname "$0")"

VERSION=0.19.2
ARCHIVE="zola-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
URL="https://github.com/getzola/zola/releases/download/v${VERSION}/${ARCHIVE}"
SHA256=0798e69b86c628ddcb264ebd86c8cc8dce7670b9049060bf94faa73f6857cd9c
BIN=.bin/zola

if [ ! -x "$BIN" ]; then
  [ "${1:-}" != "--offline" ] || { echo "build.sh: $BIN is absent and --offline was given" >&2; exit 1; }
  mkdir -p .bin
  curl -fsSL -o ".bin/${ARCHIVE}" "$URL"
  echo "${SHA256}  .bin/${ARCHIVE}" | sha256sum -c -
  tar -xzf ".bin/${ARCHIVE}" -C .bin zola
fi

"$BIN" --root . build --output-dir public --force
