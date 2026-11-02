#!/bin/sh
# Test scaffolding, not part of the role. The NAT reconciler asks `nft` whether
# the edge_firewall role's masquerade table is loaded. That role has its own
# scenario; here the table is a file with the text the kernel prints for it
# (the words of a real capture, nftables 1.1.3 on Debian 13), and the answer is
# the kernel's failure while /run/egress-nat-no-nat-table exists. No ruleset is
# loaded by this stand-in and none is needed: the reconciler reads, it never writes.
case "$*" in
    "list table ip branchleft_edge_nat")
        if [ -f /run/egress-nat-no-nat-table ]; then
            echo "Error: No such file or directory" >&2
            exit 1
        fi
        cat /run/egress-nat-nft-table
        exit 0
        ;;
esac
exit 1
