# test_tenant_host_monitoring.py: the tenant hosts' exporter, its bind and its log retention

`branchLeft/workspace#1810` puts the tenants project's three hosts (`db-t1`, `app-t1`, `edge-t`)
under the monitoring. The Prometheus side is held in `hetzner/monitoring/render.test.ts` and the
promtool files beside it; this test holds the Ansible side to the same statement.

It fails when a tenant playbook stops applying `node_exporter` or applies it twice; when the
database host's play runs the exporter after `db_t1` (a refusal in the database role would then
hold monitoring back); when the other two hosts stop having it last; when a host's row in
`host_roles/` lacks it; when a tenant playbook moves the exporter's subnet prefix away from the
default that finds the tenants addresses (the tenants network reuses the estate's range); when the
unit file listens on anything but the address the role found, or on every address; and when the
role stops refusing a host with no address in the estate subnet, which is what keeps the exporter
off a public interface.

It also holds the journal retention. Each tenant playbook sets `host_baseline_journal_retention_days`
to 30, which is inside the 90 days the website's privacy notice states for server logs. No other
playbook sets it, so the live hosts are unchanged. The role's own default is 0, which writes
nothing, and it refuses a figure over 90.

What it does not prove: that a host answers on its address, that a port is closed from outside, and
that the alerts fire. Those are the promtool files (alerts), `hetzner/tenants.metricsPorts.test.ts`
(no firewall rule opens a metrics port) and, on a live host, the outside check in
`hetzner/RUNBOOK-monitoring.md`.
