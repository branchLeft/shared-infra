# dashboards.ts

## Module overview

Reads the Grafana dashboards committed under
`stack/grafana/provisioning/dashboard-json/` and names every PromQL query they
run, so `dashboards.test.ts` can hold each one to a series that something
really emits.

The dashboards are provisioned, not drawn in the UI. `stack/grafana/provisioning/dashboards/dashboards.yaml`
tells Grafana to load that directory, read-only (`allowUiUpdates: false`,
`disableDeletion: true`), and the `monitoring_stack` Ansible role delivers the
files with the rest of the stack. Grafana is reached over an SSH tunnel to its
private address; its hostname and TLS are not part of this module.

| Dashboard      | Reads                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------ |
| Host health    | `up`, node exporter CPU, memory, disk, load, network, boot time, cAdvisor, `ALERTS`              |
| Tenant health  | blackbox HTTP probes, the scanning storage adapter's export, `mysqld` on db1, the db-t1 replica  |
| Backups        | the backup worker, state copy, db1 dump and binlog shipper, control-plane backup, object storage |
| Mail queue     | mx1's Stalwart delivery counters, the mail port probes, Alertmanager email, SNDS                 |
| Support access | the edge's own signals (Caddy status codes, rate-limit declines, CrowdSec bans), admin probes    |

## What counts as a series that exists

A queried name passes when one of these names it, in this order of trust:

1. A collector this repo owns: a `# TYPE` line in a non-test `.py` file under
   `hetzner/monitoring/` or `ansible/roles/` (`metricCrosscheck.ts`'s reader). Its label keys are
   checked too: a selector on a label the collector never writes fails.
2. A rule: `ALERTS` and `ALERTS_FOR_STATE` exist exactly when the rendered alert rules hold an
   alert, and a `record:` rule's name is a series it writes.
3. `EXTERNAL_METRICS` in `metricCrosscheck.ts`, the alert rules' reasoned list of third-party names.
4. `DASHBOARD_EXTERNAL_METRICS` in `dashboards.ts`, the same kind of list for names only a dashboard
   queries. Each entry names its exporter. A test fails an entry a local collector or the alert list
   already covers.

## Known limitations, disclosed rather than silently accepted

- **Names, not values.** A name that exists can still return nothing for a selector whose label
  values never match. Only a running Prometheus shows that.
- **The external lists are reviewed, not verified.** A reason can be written for a name that does
  not exist upstream. The names in `DASHBOARD_EXTERNAL_METRICS` are the exporters' documented ones;
  a first look at each panel on the live Grafana is the real proof.
- **Support access has no series of its own yet.** Opening and closing a break-glass grant is not
  exported as a metric, so that dashboard shows the surfaces around it and says so in its first
  panel. A grant gauge is a change to the grant tool in `branchLeft/ghost-platform`, after which
  its name joins the list above and a panel is added.
- **No query for the mail queue length.** Nothing in this repo names Stalwart's queue-size gauge,
  so the Mail queue dashboard reads the delivery and reschedule counters the alert rules already
  rely on, not a name taken from memory.
