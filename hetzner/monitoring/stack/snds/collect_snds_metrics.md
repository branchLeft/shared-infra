# collect_snds_metrics.py

The module docstring of `collect_snds_metrics.py` kept its summary paragraph; the rest of the narrative, usage notes and rationale is below, unchanged.

SNDS refreshes at most once a day, so this is invoked by a systemd timer
(`../../systemd/snds-collector.timer`) rather than run continuously. A run
that fails to fetch or parse leaves the previous reputation textfile
untouched -- the last known-good snapshot keeps serving
`snds_complaint_rate` and `snds_reputation_status` at their last real
values. Overwriting the file with nothing on a transient failure would trade
a stale-but-real reading for a silent gap indistinguishable from "no
complaints" -- the wrong failure mode for a sender-reputation signal.

That preservation is also what makes a failing collector look healthy on a
dashboard, so health is published SEPARATELY and unconditionally, into its
own textfile (`HEALTH_FILENAME`) that every run rewrites whether it
succeeded or not. node_exporter reads every `*.prom` in its textfile
directory, so the two files scrape as one set: reputation values stay at
their last real reading while `snds_collector_last_run_success` goes to 0 on
the very next run after a break. Inferring the failure from a timestamp that
stopped advancing takes 36 hours; reading it off a gauge takes one scrape.

CREDENTIAL. `SNDS_DATA_URL` is a complete SNDS "Automated Data Access" URL
with its access key embedded in the query string -- the whole URL is the
secret, which is why nothing here ever prints it (see `redact`). Microsoft
issues it from the SNDS portal's automated-access page and expires it after
30 days; rotation is `RUNBOOK-monitoring.md`'s job, not this script's. The
portal's other automated path, an OAuth bearer token, is deliberately not
used: it lives about 8 hours with no `refresh_token`, which cannot serve a
6-hourly unattended collector at all. RUNBOOK-monitoring.md's SNDS
section carries the history and the rotation procedure.
