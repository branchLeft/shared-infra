# zonecheck.py

Captures a DNS zone from its authoritative servers, and compares two sets of
authoritative servers against the checked-in zone file record by record.

    zonecheck.py capture --server ns1049.ui-dns.de --out zone.json
    zonecheck.py compare --left ns1049.ui-dns.de,ns1067.ui-dns.com \
                         --right hydrogen.ns.hetzner.com,oxygen.ns.hetzner.com

Every query goes straight to a named server with recursion off, and every
answer must carry the authoritative-answer flag. Asking a recursive resolver
instead would answer from whichever provider the registry currently delegates
to, so both sides of a comparison would silently be the same side.

**The registrar refuses zone transfers**, so no enumeration is exhaustive: a
name is only captured if it is on the probe list. `probe_names` in the zone
file is that list, and every name on it is compared on both sides, present or
absent. A name present at one provider and NXDOMAIN at the other is a diff
like any other. The cutover runbook pairs this with a count check against the
registrar's own record listing, which is the only exhaustive view there is.

**An empty diff is only reported after the check has proved it can fail.**
Two controls run on every comparison. The apex NS set must differ between the
two sides, because each provider serves its own, which proves the two server
lists really are different servers. And the comparison is re-run once with one
record in the expected zone deliberately altered, which must be reported as a
diff. If it is not, the run fails rather than printing an all-clear.

`capture --transcript PATH` also writes every dig answer verbatim, the apex SOA
included. `check-capture` re-reads such a transcript, with no query at all, and
exits 1 unless the zone file declares exactly what the transcript shows: the
committed pair is the proof that no record was dropped on the way into the file.

Needs `dig` on PATH and nothing outside the standard library.

Exit codes: 0 no differences, 1 differences, 2 a server did not answer
authoritatively (or a transcript could not be read), 3 a control failed.
