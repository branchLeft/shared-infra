# exporters_and_collectors

This role installs two things on a host, both moved from hand steps and install
scripts into Ansible:

1. The `node_exporter` metrics exporter, as a native binary and a systemd unit
   bound to the host's own estate-subnet address. It replaces
   `hetzner/provision/40-install-node-exporter.sh`, with the same unit file, and
   the install steps (sections 1 to 3) of the db1 node_exporter runbook.
2. The SNDS complaint-rate collector, its systemd service and its timer. It
   replaces the hand `scp` and `systemctl enable --now` of the monitoring
   runbook's SNDS section. The collector program itself stays as code: the role
   delivers the repository's `collect_snds_metrics.py` byte for byte and does not
   rewrite it.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does

It runs in this order, and each step changes only what it names.

1. Refuses its inputs before it changes anything: the version, the digest, the
   subnet prefix and the stop percentage must have the shape the role takes.
2. Refuses to install when the host has no address in the estate subnet, so the
   exporter can never bind a public interface. The address is taken from the
   facts the play gathers.
3. Refuses to install when a real mount of the host is at or above the stop
   percentage (70 by default). This is the first section of the db1 runbook, now
   a check the role makes.
4. Installs the pinned node_exporter binary. If the installed binary already
   reports the pinned version, nothing is downloaded. Otherwise the release
   tarball is downloaded with its sha256 digest checked by `get_url`, extracted
   into a directory the role removes afterwards, and the binary is installed as
   `/usr/local/bin/node_exporter`, owned by root, mode 0755.
5. Creates the system user `node-exporter` with no home and no login shell, only
   when it is absent.
6. Creates `/var/lib/branchleft/backup-worker-exporter` (root, 0755) for the
   textfile collector.
7. Writes `/etc/default/node-exporter` with the one line
   `NODE_EXPORTER_LISTEN_ADDRESS=<the host's private address>`, rewritten every
   run so a rebuilt host does not keep a stale address.
8. Installs `node-exporter.service` as `/etc/systemd/system/node_exporter.service`,
   the same unit file on every host. Changing the binary, the environment file or
   the unit restarts the exporter once; systemd is reloaded first.
9. Enables `node_exporter.service` and starts it.
10. Installs `collect_snds_metrics.py` into `/opt/branchleft/monitoring/snds/`
    (root, 0644), the directory its unit runs it from.
11. Creates `/var/lib/branchleft/snds-exporter` (root, 0755) for the collector's
    textfile output.
12. Installs `snds-collector.service` and `snds-collector.timer` into
    `/etc/systemd/system` (root, 0644) and reloads systemd when they changed.
13. Enables and starts `snds-collector.timer`.

The SNDS textfile directory (`/var/lib/branchleft/snds-exporter`) is read by the
Compose node_exporter on edge1, not by the native unit this role installs.

## Where the files come from

The unit files and the collector program are not copied into this role. They are
read through symbolic links in `files/`, which point at the one copy each file
has in the repository:

| In `files/`              | Points at                                           |
| ------------------------ | --------------------------------------------------- |
| `node-exporter.service`  | `hetzner/provision/node-exporter.service`           |
| `snds/`                  | `hetzner/monitoring/stack/snds/`                    |
| `snds-collector.service` | `hetzner/monitoring/systemd/snds-collector.service` |
| `snds-collector.timer`   | `hetzner/monitoring/systemd/snds-collector.timer`   |

This is the same arrangement `monitoring_stack` uses for its stack directory, so
there is one copy of each file. The monitoring stack role does not carry
`snds/collect_snds_metrics.py`; this role does.

## Inputs

Set in `defaults/main.yml`, and listed with their rules in `meta/argument_specs.yml`:

- `exporters_and_collectors_node_exporter_version` and
  `exporters_and_collectors_node_exporter_sha256` pin the release. The digest is
  copied from the upstream release's own checksum list. Nothing else is accepted.
- `exporters_and_collectors_node_exporter_download_url` is the release tarball.
- `exporters_and_collectors_node_exporter_subnet_prefix` is the estate subnet, as a
  prefix ending in a dot. It is `10.20.1.` in production.
- `exporters_and_collectors_disk_stop_percent` is the disk stop, `70` in production.

The paths and the port are in `vars/main.yml`, not in `defaults/`. The unit file
names them, so a caller that changed one would install a unit that disagrees with
its own binary, file or directory. None of the variables is a secret. The SNDS
access URL is not read or written by this role.

## Deliberate differences from the scripts

The port is one-to-one for files, modes, owners, units and order. These differ,
and each is why:

- The download is verified by `get_url` with `checksum:`, and extracted with
  `unarchive`. The script ran `sha256sum` or `shasum` itself. `get_url` checks
  the same digest with no portability branch.
- The private address comes from the facts (`ansible_all_ipv4_addresses`), not
  from `ip -4 -o addr show`. The shell `ip` command is not a task here (ANS-3),
  and the facts give the same set of addresses.
- The disk check reads `ansible_mounts`, with the size and the space available.
  `df` reports use as used divided by used plus available, and that can differ
  from this check by the reserved blocks of a volume. A mount's figure is rounded
  up, as `df` rounds it.
- The restart rule is a handler, not a `systemctl is-active` branch. The effect
  is the same: a change restarts the exporter, and an unchanged run does not. The
  service is also started when it is not running.
- Check mode skips the download and the extraction, with the reason stated in the
  task file (ANS-10). A check-mode run still reports the unit, the environment
  file and the collector.

## What the role leaves out, and why

- **The `expected_up` flip** (db1 runbook sections 6 and 8). Flipping
  `expected_up` is a change to the monitoring render, which the monitoring stack's
  own runbook owns. Its owner runs it after the read-back in section 4 passes, and
  this role does not make it. The flip and the rollback stay as owner steps.
- **The read-back and the gate** (section 4 and 5 of the db1 runbook). Those are
  reads made by a person against the live Prometheus, and the role does not run
  them. They remain in the runbook.
- **The owner's stop, and the owner's start of the collector.** The runbook's
  verify step starts `snds-collector.service` by hand to read its first output.
  The timer starts it on its own schedule, so the role does not start it.
- **The collector's access URL.** It lives in `/etc/branchleft/monitoring.env`,
  written by hand (monitoring runbook section 14). The role never reads or writes
  that file.
- **The disk check's threshold for molecule.** The test sets it to 100 because the
  container's mounts belong to the test host, not to db1.

## What the test proves, and what it does not

The Molecule scenario runs the role in one systemd container on the estate's
Debian release. Its `verify.yml` reads every installed file and compares the unit
and the collector byte for byte with its source in the repository, checks the
binary's owner and mode, reads the exporter's environment file for the container's
own bridge address, and asks systemd that the exporter and the SNDS timer are
active and enabled.

It does not prove:

- the three refusals (no estate-subnet address, a mount at or above the stop,
  a download with a wrong digest). Their assertions are in `tasks/main.yml` and
  `tasks/_node_exporter.yml`; no scenario makes them fail on purpose yet;
- that the exporter binds the estate address on a real host, because the test
  uses the container's bridge address;
- the scrape, the textfile collector and the alerts. Those are the read-back in the
  db1 runbook, section 4, and the monitoring stack's own checks.
