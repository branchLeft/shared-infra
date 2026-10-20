#!/usr/bin/env bash
# Test stand-in for OpenSSH's sshd: the test image has no sshd and no network.
# It models what the role depends on and nothing else, as the role's README
# lists: -t fails on a keyword outside a closed set, -T prints the resolved
# settings, Include expands in glob order, the first value for a keyword wins,
# and permitrootlogin prohibit-password prints as without-password.
set -euo pipefail

mode=""
config=/etc/ssh/sshd_config
while getopts "tTf:" option; do
    case "$option" in
        t) mode=syntax ;;
        T) mode=dump ;;
        f) config="$OPTARG" ;;
        *) exit 64 ;;
    esac
done

known=" include passwordauthentication kbdinteractiveauthentication permitrootlogin pubkeyauthentication port "
declare -A resolved=(
    [passwordauthentication]=yes
    [kbdinteractiveauthentication]=no
    [permitrootlogin]=prohibit-password
    [pubkeyauthentication]=yes
    [port]=22
)
declare -A seen=()
status=0

read_file() {
    local file="$1" number=0 line keyword value path
    local -a paths
    while IFS= read -r line || [[ -n "$line" ]]; do
        number=$((number + 1))
        line="${line%%#*}"
        [[ -z "${line//[[:space:]]/}" ]] && continue
        read -r keyword value <<<"$line"
        keyword="${keyword,,}"
        if [[ "$known" != *" $keyword "* ]]; then
            echo "$file line $number: Bad configuration option: $keyword" >&2
            status=255
            continue
        fi
        if [[ "$keyword" == include ]]; then
            mapfile -t paths < <(compgen -G "$value" | LC_ALL=C sort || true)
            for path in "${paths[@]}"; do
                read_file "$path"
            done
            continue
        fi
        if [[ -z "${seen[$keyword]+x}" ]]; then
            seen[$keyword]="$value"
            resolved[$keyword]="$value"
        fi
    done <"$file"
}

read_file "$config"
if [[ "$status" -ne 0 ]]; then
    exit "$status"
fi

if [[ "$mode" == dump ]]; then
    for keyword in "${!resolved[@]}"; do
        value="${resolved[$keyword]}"
        if [[ "$keyword" == permitrootlogin && "$value" == prohibit-password ]]; then
            value=without-password
        fi
        printf '%s %s\n' "$keyword" "$value"
    done | LC_ALL=C sort
fi
