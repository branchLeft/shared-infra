#!/bin/sh
# Test scaffolding, not part of the role. Stands for the previous release of
# the NAT reconciler: it does nothing except leave a marker, so that the test
# can tell that the role ran it again after putting it back.
printf 'ran\n' > /run/egress-nat-old-reconciler-ran
exit 0
