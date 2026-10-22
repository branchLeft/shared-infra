# shellcheck shell=sh
# Sourced by the Docker-in-Docker proofs in hetzner/scripts. The one home for the
# registry pull retry: a script sources this file, it never copies the function.
#
# Registry pulls can time out on a shared runner: retry, then fail loudly. The
# caller runs under set -e, so a return of 1 ends the job; no try is ever skipped.
pull_with_retry() {
    attempt=1
    until docker pull -q "$1" >/dev/null; do
        [ "$attempt" -lt 3 ] || { echo "could not pull $1 after $attempt attempts"; return 1; }
        attempt=$((attempt + 1))
        sleep 5
    done
}
