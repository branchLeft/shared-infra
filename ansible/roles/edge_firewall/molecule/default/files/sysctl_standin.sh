#!/bin/sh
# Test scaffolding, not part of the role. A container's /proc/sys is read-only whatever
# capability it holds, so the real sysctl command fails there. This stands in for it with
# a small state: `sysctl -w key=value` stores the value, `sysctl -n key` prints it (0 until
# it is written), and every call is recorded. It accepts the forms the ansible.posix.sysctl
# module and the role use: [-e] -n KEY, [-e] -w KEY=VALUE.
state=/run/edge-firewall-sysctl-state
mkdir -p "$state"
printf '%s\n' "$*" >> /run/edge-firewall-sysctl-calls
mode="read"
key=
for arg in "$@"; do
    case "$arg" in
        -w) mode="write" ;;
        -n | -e | -q) ;;
        *=*)
            printf '%s\n' "${arg#*=}" > "$state/${arg%%=*}"
            ;;
        -*) ;;
        *) key=$arg ;;
    esac
done
if [ "$mode" = read ] && [ -n "$key" ]; then
    if [ -f "$state/$key" ]; then
        cat "$state/$key"
    else
        echo 0
    fi
fi
exit 0
