# exporters_and_collectors

This role installs the SNDS complaint-rate collector on a host: its program, its
systemd service and its systemd timer. It replaces the hand `scp` and
`systemctl enable --now` of the monitoring runbook's SNDS section.

The collector program itself stays as code. The role delivers the repository's
`collect_snds_metrics.py` byte for byte and does not rewrite it.

The `node_exporter` metrics exporter is a separate role, `node_exporter`, which
every host that runs the exporter applies. This role does not install it.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does

It runs in this order, and each step changes only what it names.

1. Creates `/opt/branchleft/monitoring/snds` (root, 0755), the directory the
   collector's unit runs it from.
2. Installs `collect_snds_metrics.py` into that directory (root, 0644).
3. Creates `/var/lib/branchleft/snds-exporter` (root, 0755) for the collector's
   textfile output.
4. Installs `snds-collector.service` and `snds-collector.timer` into
   `/etc/systemd/system` (root, 0644), and reloads systemd when they changed.
5. Enables and starts `snds-collector.timer`.

The SNDS textfile directory (`/var/lib/branchleft/snds-exporter`) is read by the
Compose node_exporter on edge1, not by the native `node_exporter` unit.

## Where the files come from

The collector program and its units are not copied into this role. They are read
through symbolic links in `files/`, which point at the one copy each file has in
the repository:

| In `files/`              | Points at                                           |
| ------------------------ | --------------------------------------------------- |
| `snds/`                  | `hetzner/monitoring/stack/snds/`                    |
| `snds-collector.service` | `hetzner/monitoring/systemd/snds-collector.service` |
| `snds-collector.timer`   | `hetzner/monitoring/systemd/snds-collector.timer`   |

This is the same arrangement `monitoring_stack` uses for its stack directory, so
there is one copy of each file. The monitoring stack role does not carry
`snds/collect_snds_metrics.py`; this role does.

## Inputs

The role takes no input. Its paths are in `vars/main.yml`, because the unit files
name them. A caller that changed one would install a unit that disagrees with its
own program.

## Where it is applied

`edge1` only, after `edge_stack`, in `ansible/playbooks/edge1.yml`. The collector's
timer is edge1-specific, so the role is not applied to any other host.

## What the test proves, and what it does not

The Molecule scenario runs the role in one systemd container on the estate's
Debian release. Its `verify.yml` reads the installed program, service and timer and
compares them byte for byte with their sources in the repository, checks their
modes, and asks systemd that the SNDS timer is active and enabled.

It does not prove:

- the collector's first output, which the monitoring runbook's SNDS section reads
  by hand;
- the metrics reaching Prometheus, which the monitoring stack's own checks cover.

## Owner steps

None. The role is applied by the edge1 gated pull, after its merge and the gate
approval.
