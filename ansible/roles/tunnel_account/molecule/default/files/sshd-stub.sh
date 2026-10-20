#!/bin/sh
# Test stand-in for sshd. The pinned test image has no OpenSSH server, so this
# answers the two calls the role makes. It is not a control, and it is not
# OpenSSH: real sshd enforcement is proven by the lab run or the live run.
#
#   sshd -t                   Reads every drop-in. Refuses a keyword it does not
#                             know and a keyword placed outside a Match block.
#   sshd -T -C user=U,...     Prints, lowercased, each keyword inside the
#                             "Match User U" block of the drop-ins, as written.
#                             Prints nothing for another user. Reads -C only for
#                             its user=. The role's drop-in has to be on disk.
DIR=/etc/ssh/sshd_config.d
KNOWN=" match authorizedkeysfile authenticationmethods allowtcpforwarding permitlisten permitopen gatewayports allowagentforwarding allowstreamlocalforwarding x11forwarding permittty permittunnel permituserrc forcecommand "

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

case "$1" in
  -t)
    for f in "$DIR"/*.conf; do
      [ -e "$f" ] || continue
      in_match=no
      while read -r first rest; do
        [ -n "$first" ] || continue
        case "$first" in '#'*) continue ;; esac
        key=$(lower "$first")
        case "$KNOWN" in
          *" $key "*) ;;
          *) echo "stub sshd: $f: unknown keyword $first" >&2; exit 1 ;;
        esac
        if [ "$key" = match ]; then
          in_match=yes
        elif [ "$in_match" = no ]; then
          echo "stub sshd: $f: $first is outside a Match block" >&2
          exit 1
        fi
      done < "$f"
    done
    exit 0
    ;;
  -T)
    user=
    [ "$2" = "-C" ] && user=$(echo "$3" | tr ',' '\n' | sed -n 's/^user=//p')
    [ -n "$user" ] || { echo "stub sshd: -C user= is required" >&2; exit 1; }
    for f in "$DIR"/*.conf; do
      [ -e "$f" ] || continue
      active=no
      while read -r first rest; do
        [ -n "$first" ] || continue
        case "$first" in '#'*) continue ;; esac
        key=$(lower "$first")
        if [ "$key" = match ]; then
          if [ "$rest" = "User $user" ]; then active=yes; else active=no; fi
          continue
        fi
        [ "$active" = yes ] || continue
        echo "$key $rest"
      done < "$f"
    done
    exit 0
    ;;
  *)
    exit 2
    ;;
esac
