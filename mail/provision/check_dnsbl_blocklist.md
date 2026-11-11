# check_dnsbl_blocklist.py

## Module overview

Checks the mail host's public IP against the major DNSBLs (DNS-based
blocklists) and raises a clear, actionable signal the moment any of them
lists it. A listed address silently kills deliverability for every sender
behind this host, which is exactly the kind of failure that must not wait
for someone to notice complaints.

Query mechanics (verified against each list's own docs and live DNS, not
assumed identical -- see mail/RUNBOOK-mx1-provision.md's "DNSBL blocklist
monitoring" section for the executed checks): every list in this set uses
the same reversed-octet query -- `<reversed IP>.<zone>` -- and answers with
either NXDOMAIN (not listed) or one or more A records in 127.0.0.0/8
(listed; the last octet encodes the sub-list/reason and differs per list,
irrelevant to this script beyond logging it). Spamhaus additionally
documents a distinct 127.255.255.0/24 range for _query_ errors (e.g. "this
resolver is a public/open one and is blocked") that must never be read as
a reputation signal -- applied defensively to every zone here, since no
other list in this set is known to use that range for a real listing.

Self-test before trusting a "not listed" result: every run also queries
each zone for the industry-standard always-listed test address 127.0.0.2
(confirmed live for Spamhaus/Barracuda/SpamCop/UCEPROTECT). If that
sentinel doesn't come back listed, the zone isn't answering meaningfully --
dead, unreachable, or rate-limiting this host -- and the real target's
result for that zone is reported as inconclusive rather than clean. This
is not hypothetical: dnsbl.sorbs.net currently has no DNS delegation at
all (NXDOMAIN at the .net level, confirmed live) despite being in the
minimum DNSBL set here, so without this self-test the SORBS entry would
silently and permanently report "clean" while providing zero real signal.
See the RUNBOOK for the live evidence.

Queries go to the host's own local recursive resolver (127.0.0.1, unbound,
installed by 65-install-local-resolver.sh) addressed explicitly rather than
through the system resolver: Spamhaus answers 127.255.255.254 ("query
blocked") to anything reaching it from a high-volume shared resolver, which
a hosting provider's default resolvers and every public one are. If that local resolver is
down or broken every lookup fails, the zone self-test below fails with it,
and the run reports inconclusive -- never a false clean.

Uses only the standard library, consistent with this directory's other
scripts (see configure_stalwart.py's docstring for why) -- including the
DNS query itself, which is why there is a small wire-format encoder and
parser here rather than a dnspython dependency.

## Forwarding findings

Every run also reports to a Healthchecks.io check: a success ping when every list is clean, and a `/fail` ping carrying the finding lines when any list is listed or inconclusive, or when the check crashes. The journal stays the record. The ping is what tells the owner about a finding, and its absence is what tells the owner the hourly run has stopped. The ping URL is a credential: it is read from the environment or a root-only file and is never logged. See the runbook section "Forwarding findings to Healthchecks.io" in mail/RUNBOOK-mx1-provision.md.
