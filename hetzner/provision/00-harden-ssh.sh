#!/usr/bin/env bash
# Keeps SSH locked to key-only auth. Cloud-init writes this same drop-in at
# first boot; this script is what makes it stay true, and is safe to re-run.
set -euo pipefail

# `01-` rather than a high number, and the reason is the opposite of the
# usual convention. OpenSSH takes the **first** value it obtains for a
# keyword and ignores every later one, and `Include
# /etc/ssh/sshd_config.d/*.conf` expands in glob order -- so the
# lowest-sorting drop-in wins, not the highest. A `99-` file loses to every
# sibling, including the `50-cloud-init.conf` cloud-init writes whenever
# `ssh_pwauth` is set, which would restore password authentication while a
# byte-comparison check on this file kept reporting it up to date.
#
# Overridable so tests can point this at a throwaway path; production always
# gets the default since nothing sets DROPIN in the environment.
DROPIN="${DROPIN:-/etc/ssh/sshd_config.d/01-branchleft-hardening.conf}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# Debian's stock sshd_config already sets `PermitRootLogin without-password`
# but leaves the global PasswordAuthentication at its compiled-in default of
# "yes" -- `sshd -T` on a stock image confirms the effective value is yes
# despite root already being key-only. This drop-in closes that gap for every
# account. Root stays key-reachable deliberately: it is the provisioning
# identity, and the alternative recovery path is the Hetzner console.
cat > "$TMP" <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
EOF

if [[ -f "$DROPIN" ]] && cmp -s "$TMP" "$DROPIN"; then
    echo "00-harden-ssh: $DROPIN already up to date"
else
    install -m 644 "$TMP" "$DROPIN"
    echo "00-harden-ssh: wrote $DROPIN"
fi

# `sshd -t` resolves the config exactly as the running daemon would, without
# restarting anything.
if ! sshd -t -f /etc/ssh/sshd_config; then
    echo "00-harden-ssh: sshd -t reported a config error, refusing to reload" >&2
    exit 1
fi

systemctl reload ssh

# The file being present is not the property that matters; the daemon's
# resolved value is. `sshd -T` prints what the running configuration actually
# evaluates to across every drop-in, so a sibling that outranks this one is
# caught here rather than by an operator wondering why password logins still
# work.
#
# `permitrootlogin` is compared through this normaliser rather than by
# string equality: `prohibit-password` and `without-password` are the same
# setting to sshd, and `sshd -T` echoes back whichever spelling it parsed --
# on Debian 13 that is the deprecated `without-password`, even when our own
# drop-in (and this script's here-doc) writes `prohibit-password`. A literal
# compare treats that as a competing drop-in when nothing is actually
# competing.
normalize_permitrootlogin() {
    case "$1" in
        prohibit-password|without-password) printf 'prohibit-password' ;;
        *) printf '%s' "$1" ;;
    esac
}

effective="$(sshd -T)"
failed=0
while read -r keyword expected; do
    [[ -z "$keyword" ]] && continue
    actual="$(printf '%s\n' "$effective" | awk -v k="$keyword" '$1 == k {print $2; exit}')"
    if [[ "$keyword" == "permitrootlogin" ]]; then
        actual_cmp="$(normalize_permitrootlogin "$actual")"
        expected_cmp="$(normalize_permitrootlogin "$expected")"
    else
        actual_cmp="$actual"
        expected_cmp="$expected"
    fi
    if [[ "$actual_cmp" != "$expected_cmp" ]]; then
        echo "00-harden-ssh: effective $keyword is '${actual:-unset}', expected '$expected'" >&2
        failed=1
    fi
done <<'EOF'
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin prohibit-password
pubkeyauthentication yes
EOF

if [[ "$failed" -ne 0 ]]; then
    echo "00-harden-ssh: another drop-in in /etc/ssh/sshd_config.d/ outranks $DROPIN" >&2
    exit 1
fi

echo "00-harden-ssh: sshd reloaded, effective config verified"
