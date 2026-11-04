#!/bin/sh
# Builds the site into docs/site/public. The one network step is fetching the pinned release
# binary, which is checked against its sha256 before it is unpacked; the build itself needs no
# network. Built output is not committed (see .gitignore).
#
#   sh docs/site/build.sh            fetch the binary if it is absent, then build
#   sh docs/site/build.sh --offline  build only; fail if the binary is absent
set -eu

cd "$(dirname "$0")"

VERSION=0.139.3
ARCHIVE="hugo_${VERSION}_linux-amd64.tar.gz"
URL="https://github.com/gohugoio/hugo/releases/download/v${VERSION}/${ARCHIVE}"
SHA256=fcf9265c4d72f713a07c73b7fcf32f4aa31a1d9cf13444e6d22ae1926d527652
BIN=.bin/hugo

if [ ! -x "$BIN" ]; then
  [ "${1:-}" != "--offline" ] || { echo "build.sh: $BIN is absent and --offline was given" >&2; exit 1; }
  mkdir -p .bin
  curl -fsSL -o ".bin/${ARCHIVE}" "$URL"
  echo "${SHA256}  .bin/${ARCHIVE}" | sha256sum -c -
  tar -xzf ".bin/${ARCHIVE}" -C .bin hugo
fi

rm -rf public
"$BIN" --source . --destination public --quiet
