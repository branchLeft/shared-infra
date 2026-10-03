# test_suite_size.py

## Module overview

Two ways a test module can vanish from a run both leave `unittest discover`
reporting a smaller number with no other signal: an interpreter below a
module's declared minimum (see test_compose_unit_contract.py's own version
guard) turns the whole module into one `_FailedTest` placeholder, and a
module deleted from disk is simply not there to find. Either way the suite
can still exit 0 if everything it did collect passes -- a shrunken run looks
identical to a smaller, still-complete one unless something states what the
count should be.

This can only guard the rest of the directory, never itself: a test that
vanished along with this file would leave nothing here to notice the drop.
Bump EXPECTED_TEST_COUNT in the same change that adds or removes a test
method anywhere under hetzner/provision, including in this file.
