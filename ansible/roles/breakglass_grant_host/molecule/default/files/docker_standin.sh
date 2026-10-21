#!/bin/sh
# A stand-in for the docker command, for the role tests of the break-glass roles.
# The test container has no Docker daemon (ANS-15 keeps the engine socket out of
# it), so this program takes the place of /usr/local/bin/docker and
# /usr/bin/docker. It does three things only:
#
#   1. Records each call: the path it was started as, then each argument, one
#      call per line, separated by three bars. The tests read the record to learn what the
#      roles, the wrapper and the unit asked Docker to do.
#   2. Keeps a list of the image digests that were pulled, so that a probe
#      (`image inspect`) answers "present" only after a pull.
#   3. Answers `run` with an empty JSON list, as the wrapper's `status` does.
#
# What it does NOT prove: that the image pulls, that the tool runs, or that the
# unit starts a real container. Those are proved on the host by the gated run.
set -eu

state=/var/lib/docker-standin
calls="$state/calls.log"
images="$state/images"
# The digest a registry would resolve a bare tag to. Set by the test's prepare
# play from the role's default, so a pull by tag still stores the pinned digest
# and the tests see the pull's arguments, not a read-back failure.
registry_digest="$state/registry_digest"

{
  printf '%s' "$0"
  for arg in "$@"; do
    printf '|||%s' "$arg"
  done
  printf '\n'
} >>"$calls"

# The reference a pull or an inspect names is its last argument.
last=''
for last in "$@"; do :; done

case "${1:-}" in
  --version)
    echo 'Docker version 29.8.2, build stand-in'
    ;;
  pull)
    # A test can make the pull succeed and store nothing, to show that the role
    # reads the image back instead of trusting the exit status.
    if [ -e "$state/pull_stores_nothing" ]; then
      echo "$last"
      exit 0
    fi
    case "$last" in
      *@sha256:*) printf '%s\n' "${last##*@}" >>"$images" ;;
      *) cat "$registry_digest" >>"$images" ;;
    esac
    echo "$last"
    ;;
  image)
    if [ "${2:-}" != inspect ]; then
      echo "docker stand-in: unsupported image command" >&2
      exit 2
    fi
    digest=${last##*@}
    if [ -f "$images" ] && grep -qxF "$digest" "$images"; then
      printf '[node@%s]\n' "$digest"
    else
      echo "Error response from daemon: No such image: $last" >&2
      exit 1
    fi
    ;;
  run)
    echo '[]'
    ;;
  *)
    echo "docker stand-in: unsupported command" >&2
    exit 2
    ;;
esac
