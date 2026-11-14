# test_mail_collector_paths_agree.py: one credentials file and one drain list for the collector

The `mail_collector` role installs the unit that reads the owner's credentials file and the
descriptor directory, and the `mail_collector_inputs` role reads the same two paths to refuse a bad
file before the unit can start on it. A role may not load another (ANS-12), so each keeps its own
copy and the test holds every copy that is in the tree to one literal each:
`/etc/branchleft/mail-collector/credentials.env` and `/etc/branchleft/mail-collector/descriptors`,
and the collector's unit to the same two. It requires that at least one of the two roles is in the
tree, so it cannot pass on nothing. The two land in separate changes, so each check on the other
role runs once that role is there. When both are applied on `ops1` the input check must come before
the collector, so a refusal stops the play before a descriptor is written or the unit is started.
A rename of the file in either role alone runs red.
