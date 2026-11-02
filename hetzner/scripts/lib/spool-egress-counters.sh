# shellcheck shell=sh
# Sourced by test-spool-bridge-egress.sh and its unit test. Reads a DOCKER-USER
# listing from stdin, as `ip6tables -nvxL DOCKER-USER --line-numbers` prints it,
# and prints the packet count of the spool's forward drop. The drop is found by
# its fields, never its line: on the IPv6 family Docker's own RETURN sits above
# it, so a counter read from line 1 moves while the drop is gone. No match
# exits 1 with nothing printed, so a missing drop fails the check; it is not a 0.
spool_forward_drop_packets() {
    awk '
        $4 == "DROP" && $7 == "br-mailspool" && $8 == "!br-mailspool" { print $2; found = 1; exit }
        END { exit found ? 0 : 1 }
    '
}
