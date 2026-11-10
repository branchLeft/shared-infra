#!/bin/sh
# Test stand-in for docker, installed by prepare.yml. It is not a Docker and proves nothing
# about the real one, except where tests/unit/test_caddy_judge.py runs it beside a real
# Docker and requires the same answers to the calls below. The role asks docker two things:
#
#   docker image inspect REF   whether the Caddy image is on the host, by the digest in REF
#   docker run ... caddy adapt the config Caddy would run for the candidate on standard
#                              input, which the stand-in answers with the recorded file
#                              /etc/stand-in-caddy-adapt.json whatever it is given (with no
#                              file it fails as Caddy does on a text it cannot adapt)
#
# It answers `docker images` as a real Docker does for a digest reference: with nothing. A
# real Docker takes the argument of `docker images` for a repository filter, so an image ID
# or a name@digest matches no repository, loaded or not. Answering it otherwise is what let
# the role pass here while it could never find the image on a host.
#
# Only an image named in $state/images (one reference per line) is on this stand-in host.
# By default it lists one image whose RepoDigests is the asked reference, as an image loaded
# into a Docker on the containerd image store lists. $state/image-digests replaces the
# digests (one per line, an empty file for none, as on the classic image store),
# $state/image-count the number of images listed, and $state/image-raw replaces the whole
# output, so a case can make it report a bad value.
state=${STANDIN_DOCKER_STATE:-/var/lib/standin-docker}
adapt=${STANDIN_DOCKER_ADAPT:-/etc/stand-in-caddy-adapt.json}

case "$1" in
  images)
    exit 0
    ;;
  image)
    [ "$2" = inspect ] || exit 1
    ref=$3
    # An empty name is refused first: grep -x would match it against any blank line.
    if [ -z "$ref" ] || ! grep -qxF -- "$ref" "$state/images" 2>/dev/null; then
      echo "[]"
      echo "Error response from daemon: No such image: $ref" >&2
      exit 1
    fi
    if [ -f "$state/image-raw" ]; then
      cat "$state/image-raw"
      exit 0
    fi
    digests=""
    if [ -f "$state/image-digests" ]; then
      while IFS= read -r line; do
        case $line in '#'* | '') continue ;; esac
        digests="$digests${digests:+, }\"$line\""
      done < "$state/image-digests"
    else
      case $ref in *@sha256:*) digests="\"$ref\"" ;; esac
    fi
    count=$(sed -n 's/^count=//p' "$state/image-count" 2>/dev/null)
    count=${count:-1}
    out=""
    n=0
    while [ "$n" -lt "$count" ]; do
      out="$out${out:+, }{\"Id\": \"sha256:0000000000000000000000000000000000000000000000000000000000000000\", \"RepoTags\": [], \"RepoDigests\": [$digests]}"
      n=$((n + 1))
    done
    echo "[$out]"
    ;;
  run)
    cat > /dev/null
    [ -f "$adapt" ] || { echo "stand-in caddy: cannot adapt" >&2; exit 1; }
    cat "$adapt"
    ;;
  *)
    exit 1
    ;;
esac
