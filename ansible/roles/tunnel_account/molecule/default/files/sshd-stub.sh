#!/bin/sh
# Test stand-in for sshd. The pinned test image has no OpenSSH server, so this
# answers the two calls the role makes. It is not a control, and it is not
# OpenSSH: real sshd enforcement is proven by the lab run or the live run.
#
#   sshd -t                   Reads every drop-in. Refuses a keyword it does not
#                             know and a keyword placed outside a Match block.
#   sshd -T -C user=U,addr=A  Prints, lowercased, each keyword of the Match
#                             blocks that apply to user U connecting from
#                             address A, in file order, as written. Like sshd it
#                             prints every value it finds, so the first one
#                             wins when the caller reads it. A Match block
#                             applies when every criterion it names holds:
#                             "all", "User U", "Address A" or a pair of them.
#                             Requires user= and requires addr= to be the
#                             from_address input the role was given, which is
#                             the address db1 connects from: the role has to
#                             ask about that connection and not another.
#                             Prints no address in any message.
DIR=/etc/ssh/sshd_config.d
FROM_ADDRESS_FILE=/etc/branchleft/db-tunnel/inputs/from_address
KNOWN=" match authorizedkeysfile authenticationmethods allowtcpforwarding permitlisten permitopen gatewayports allowagentforwarding allowstreamlocalforwarding x11forwarding permittty permittunnel permituserrc forcecommand "

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# matches USER ADDR CRITERIA...: succeeds when every criterion holds.
matches() {
  m_user=$1
  m_addr=$2
  shift 2
  [ "$#" -gt 0 ] || return 1
  if [ "$#" -eq 1 ]; then
    [ "$(lower "$1")" = all ]
    return
  fi
  while [ "$#" -ge 2 ]; do
    case "$(lower "$1")" in
      user) [ "$2" = "$m_user" ] || return 1 ;;
      address) [ "$2" = "$m_addr" ] || return 1 ;;
      *) return 1 ;;
    esac
    shift 2
  done
  [ "$#" -eq 0 ]
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
    addr=
    [ "$2" = "-C" ] && user=$(echo "$3" | tr ',' '\n' | sed -n 's/^user=//p')
    [ "$2" = "-C" ] && addr=$(echo "$3" | tr ',' '\n' | sed -n 's/^addr=//p')
    [ -n "$user" ] || { echo "stub sshd: -C user= is required" >&2; exit 1; }
    [ -n "$addr" ] || { echo "stub sshd: -C addr= is required" >&2; exit 1; }
    expected=$(tr -d '[:space:]' < "$FROM_ADDRESS_FILE") || exit 1
    [ "$addr" = "$expected" ] || { echo "stub sshd: -C addr= is not the from address input" >&2; exit 1; }
    for f in "$DIR"/*.conf; do
      [ -e "$f" ] || continue
      active=no
      while read -r first rest; do
        [ -n "$first" ] || continue
        case "$first" in '#'*) continue ;; esac
        key=$(lower "$first")
        if [ "$key" = match ]; then
          # The words of a Match line are split here, and must not be expanded.
          set -f
          # shellcheck disable=SC2086
          if matches "$user" "$addr" $rest; then active=yes; else active=no; fi
          set +f
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
