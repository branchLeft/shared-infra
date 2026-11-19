# binlog_pull

This role installs the program that pulls the tenant database host's closed binary
logs to `ops1` every 15 minutes, seals each to the estate recipient with `age`, and puts
the ciphertext and a plain manifest to backup copy 1. It also holds the coverage check
(a gap in the shipped sequence is red), the read-back audit, and the restore-to-a-time
replay. The role installs the program, its service and its timer, and keeps the timer off
until a variable turns it on.

This README is written for a maintainer who is new to the repository. It follows the
order the standard sets for a role README (ANS-14).

The design is the owner's ruling of 5 October 2026 (page 21 of `ghost-platform-docs`,
decision 5): `ops1` pulls the binary logs every 15 minutes over a TLS account, and the
database host holds no credential to its own backups and runs no listener for it.
`db1`'s push pipeline (`db1_backup_timers`, `ship_binlogs.py`) stops at the cut-over;
this role is its replacement for the tenant database host, `db-t1`, and shares nothing
with it but the object key shape.

## What the role does, and what it does not

1. **Makes three directories**: `/opt/branchleft/binlog-pull` (`root:root` `0755`) for
   the program, `/var/lib/branchleft/binlog-pull` (`root:root` `0700`) for the ledger
   and the run lock, and `/etc/branchleft` if it is absent.
2. **Installs the program** `branchleft_binlog_pull.py` (`root:root` `0755`) after the
   program's own `--check` passes on a temporary copy. A program that does not load is
   never installed and the previous one stays.
3. **Writes the environment file** `/etc/branchleft/binlog-pull.env` (`root:root` `0600`)
   and the database CA `/etc/branchleft/dbt1-ca.pem` (`0644`) from the role's inputs. The
   file is created empty at its final owner and mode before a value goes into it, and its
   owner and mode are set back on every run.
4. **Installs the service and the timer** (`root:root` `0644`) and reloads systemd once
   when either changed. The service is a oneshot with `UMask=0077`, a tmpfs
   `RuntimeDirectory` for the fetched plaintext, and a 10 minute timeout under the 15
   minute period.
5. **Holds the timer to a variable.** `binlog_pull_timer_enabled` (default `false`). True
   enables and starts it, and is refused while `/etc/branchleft/state-copy.env` or the
   backup worker's staged signing client is not on the host: a run every 15 minutes with
   nowhere to put its ciphertext would fail all day. False leaves a timer as it is on the
   host, unless `binlog_pull_timer_may_disable` is true: then it stops and disables it.

It does not create the database account, a key, a bucket, a firewall rule or a network
path, take a first pull, or start anything. It does not run on `ops1` yet: the role is in
no playbook (see "Not in this role").

### What the program does

Commands, run as root on `ops1` (all but `pull` and `check` can be run anywhere that has the
copy-1 read key). Exit 0 proven, 1 a check failed, 2 a precondition is missing so nothing was
proven.

| Command  | What it does                                                                                                                                                                                                                |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pull`   | What the timer runs. Flushes the server's binary log, lists the logs, fetches every closed log not yet shipped, proves each whole, seals it, puts it and its manifest, records it in the ledger, and publishes the gauges.  |
| `check`  | The coverage check. Compares the server's closed logs with the ledger and goes red on a closed log that is not shipped or a hole in the shipped sequence. Changes nothing.                                                  |
| `audit`  | With the copy-1 read key (`--read-env-file`): reads every shipped log back and requires the digest the ledger recorded, and the manifest beside it. Red on a log missing from copy 1 or changed.                            |
| `plan`   | With `--server-uuid`, `--from` and `--to` (UTC): names the logs, in order, that carry a restored copy from `--from` to `--to`, and goes red if one is missing, the start is not covered or the stop is past the newest log. |
| `replay` | `plan`, then reads those logs from copy 1, opens each with the private identity, requires the digest the manifest holds, and (only with `--apply`) pipes `mysqlbinlog --stop-datetime` into a scratch server.               |

**One log at a time, keeping going.** A log that fails to fetch, is not whole or cannot be
put is left unshipped and named; the run goes on to the next one and ends red. It is not
skipped silently: the ledger does not hold it, so the coverage names it, the next run fetches
it again while the server still holds it, and the gap gauge is non-zero until it does.

**A fetch is proven whole before it is sealed.** `read_span` walks every event of the raw log.
A fetch cut short ends inside an event, and an event whose recorded end is not where the next
begins is not a binary log: both are refused. The same walk gives the log's first and last
time and its first and last GTID, which go in the manifest.

**Ciphertext only leaves the host.** `require_ciphertext` refuses a file that does not start as
an age file or holds other than one recipient stanza, before a connection to copy 1 is opened.
The private half of the recipient is never on `ops1`. The fetched plaintext lives only in the
service's tmpfs directory and is removed after each log, success or failure.

**The login value is never an argument.** Each `mysql` and `mysqlbinlog` child reads its option
file from an inherited pipe (`--defaults-extra-file=/dev/fd/N`). The child's environment is
`PATH` only. Only log names, counts, times and the server's numeric error code are printed.

**The put key cannot read, so the ledger is the record.** Copy 1's put key may not list or read
(the bucket policy denies both), so `pull` cannot ask the bucket what it holds. The ledger at
`/var/lib/branchleft/binlog-pull/ledger.json` records each shipped log with the digest of its
ciphertext, rewritten whole and atomically after each log. `audit` is the check against the
bucket, and needs the read key.

**Object keys.** `binlogs/<server uuid>/dbt1-mysql-bin.NNNNNN.age` and
`binlogs/<server uuid>/dbt1-mysql-bin.NNNNNN.manifest.json`: the shape `db/RUNBOOK-db.md`
restores from, with `dbt1` for `db1`. The incarnation id is in the key because a rebuilt data
directory gets a new id and restarts the numbering at 1. The manifest is plain JSON (sequence,
times, GTID range, byte count, both digests): it names no tenant and holds no row, and it is
what `plan` reads without the private identity. It is put after the ciphertext, so a manifest
on copy 1 is the completion mark of its log.

### The gauges and the alerts

`pull` writes `binlog_pull.prom` to the textfile directory `node_exporter` reads, after every run
(and after a refused one):

| Gauge                                        | Meaning                                                                        |
| -------------------------------------------- | ------------------------------------------------------------------------------ |
| `binlog_pull_last_run_success`               | 1 when the run shipped every closed log, else 0.                               |
| `binlog_pull_last_success_timestamp_seconds` | Time of the last such run. A failed run carries the old value forward.         |
| `binlog_pull_gap_logs`                       | Sequence numbers missing from the shipped series: holes plus lost logs.        |
| `binlog_pull_lost_logs`                      | Of those, the ones the server no longer holds, which a later pull cannot fill. |
| `binlog_pull_unshipped_logs`                 | Closed logs the server holds that are not shipped.                             |
| `binlog_pull_newest_shipped_sequence`        | Sequence of the newest shipped log.                                            |

`BinlogPullGap` and `BinlogPullStale` read them in `hetzner/monitoring/render.ts` (see
`hetzner/monitoring/render.md`).

### Owner steps the role does not do

Each is a thing only the owner can place or decide. The role takes the results as inputs.

| Step                                                                                                                                       | Why the role does not                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| Make the account on `db-t1` (SQL below), as MySQL root through the socket                                                                  | Needs the database host's root. The role never creates or alters an account.                                        |
| Place the four inputs for `ops1` (database host, account, login value, CA certificate) in `ops1`'s host inputs, with `seed_host_inputs.py` | A secret's source is the owner's. Wiring the role and its inputs is a separate owner-merged change.                 |
| Make a network path from `ops1` to `db-t1`'s MySQL port, and open the port on `db-t1` to it                                                | The tenants project is its own network and its database listens on loopback only (below).                           |
| Keep the estate age identity (the private half) in the password manager, and give `replay` its drill key                                   | Key custody is the owner's (PRIN-6).                                                                                |
| Turn the timer on, by setting `binlog_pull_timer_enabled`                                                                                  | Starts a pull of every tenant's data off the database host: a production apply through the gated workflow (ANS-17). |

The account (rights are the least that `pull` needs: `SHOW BINARY LOGS` and the dump thread
need replication client and slave, and `FLUSH BINARY LOGS` needs reload):

```text
CREATE USER 'binlog_pull'@'<the address db-t1 sees ops1 from>' IDENTIFIED BY '<the login value>' REQUIRE SSL;
GRANT REPLICATION SLAVE, REPLICATION CLIENT, RELOAD ON *.* TO 'binlog_pull'@'<the address db-t1 sees ops1 from>';
```

The login value is 32 to 128 letters and digits, read into the shell and never typed into a
command line. With `binlog_pull_flush: false` the reload right is not needed, and the
recovery point is then only as fresh as the server's own rotation (one gigabyte of log).
`REPLICATION SLAVE` reads every tenant's rows in the log: that is inherent in a shared log,
which is why the account is host-restricted and TLS-only and the host holds the one copy.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every variable and
[`defaults/main.yml`](defaults/main.yml) holds the public ones.

| Variable                        | Default | Meaning                                                                          |
| ------------------------------- | ------- | -------------------------------------------------------------------------------- |
| `binlog_pull_db_host`           | none    | Required, private. The database host, as `ops1` reaches it.                      |
| `binlog_pull_db_user`           | none    | Required, private. The account above.                                            |
| `binlog_pull_db_password`       | none    | Required, private, `no_log`. The account's login value.                          |
| `binlog_pull_db_ca_pem`         | none    | Required, private. The CA that signed the database host's TLS certificate.       |
| `binlog_pull_db_port`           | `3306`  | The server's port, or the local port of a tunnel to it.                          |
| `binlog_pull_flush`             | `true`  | Flush the server's log at the start of each pull (needs the reload right).       |
| `binlog_pull_timer_enabled`     | `false` | True enables and starts the timer (refused without the two files above).         |
| `binlog_pull_timer_may_disable` | `false` | True, with the first false, stops and disables the timer. False leaves it alone. |

`vars/main.yml` holds the constants (paths, unit names, patterns). A caller cannot override
them: role variables outrank play and inventory values (an `include_role` parameter still
beats them, which the Molecule scenario uses for the one stand-in path). Unit tests pin each
path to the program, to `backup_worker` and to `backup_restore`.

The estate recipient and copy 1's put key are not inputs. The program reads
`STATE_COPY_RECIPIENT` and `STATE_COPY_DEST_*` from `/etc/branchleft/state-copy.env`, the file
`backup_restore` writes for the state copy, as `control_plane_backup` does: one recipient and one
put key serve every off-host job on `ops1`, so the owner has no new key to make or place. The
recipient is the one the state copy calls the estate recipient and page 20 calls the platform
recipient; if the owner means two, `recipient_of` is the one function to change.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 with `/usr/bin/python3` (3.12 or later) and systemd.
- At run time, from earlier roles in the same play: `age` and the `mysql` and `mysqlbinlog` 8.0
  clients (installed by `backup_worker`'s prerequisite step), the signing client staged at
  `/opt/branchleft/backup-worker/current` by `backup_worker`, and `/etc/branchleft/state-copy.env`
  from `backup_restore`. The program stops with exit 2 and says which one is missing.
- A network path from `ops1` to the database host's MySQL port, and a server that listens on it.

## What it changes on a host

- `/opt/branchleft/binlog-pull` (`0755`) and the program in it (`0755`).
- `/var/lib/branchleft/binlog-pull` (`root:root` `0700`).
- `/etc/branchleft/binlog-pull.env` (`root:root` `0600`) and `/etc/branchleft/dbt1-ca.pem` (`0644`).
- `/etc/systemd/system/branchleft-binlog-pull.service` and `.timer`, `0644`, and one systemd
  reload when either changed.
- The timer's enabled and active state, only when a variable asks.

A run of the program, when the timer or the owner starts it, additionally: connects to the
database host, flushes its binary log, writes the ledger and `binlog_pull.prom`, and puts two
objects to copy 1 per new log.

## How to restore to a chosen time

1. Restore the nightly dump of the tenant into a scratch server (the restore drill's steps).
   Note the dump's time and its recovery GTID set.
2. `plan`, from anywhere with the read key, with the dump's time as `--from`:
   `branchleft_binlog_pull.py --read-env-file READ.env plan --server-uuid ID --from 2026-11-19T03:10:00Z --to 2026-11-19T09:42:00Z`.
   Red means a log in the window is not on copy 1; the message names it.
3. `replay` the same arguments with `--identity`, `--target-option-file` (a MySQL option file
   for the scratch server) and, to restore one tenant, `--database`. It opens each log, checks it
   against its manifest and stops. Add `--apply` to pipe the logs into the scratch server. The
   server skips every transaction the dump already holds, because the logs carry their GTIDs.
   The stop time is exclusive: events at or after it are not replayed.

The target is always a scratch server first. `--apply` is never the default.

## How to test it

Unit tests, from the role directory (they run no container and touch nothing):

```text
PYTHONPATH=files python3 -B -m unittest discover -b -s tests/unit -p "test_*.py"
```

Then `mypy --strict files tests/unit` and `ruff check` and `ruff format --check` from the role
directory with the repository's pinned tools (`ansible/requirements.txt`).

The harness, with Docker running locally:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/binlog_pull
```

The scenario runs the role on one systemd container. `converge.yml` applies it, proves the timer
is refused while the state-copy file is absent (the assertion names the file), proves a login
value the environment file cannot hold is refused before anything changes, and proves the
defaults leave an enabled timer on. `verify.yml` checks the installed program and both units
equal the role's files byte for byte, the owner and mode of every path, that a widened
environment file is closed again and holds the six names with the inputs' values, that the timer
is off, that systemd reads a 15 minute period, that the program passes its own check, and that
a pull with no environment stops with exit 2 and names the missing file.

### Sabotage: skip one log, the gap alert fires

`SkippedLogScenario` in the unit tests is the sabotage control. It pulls five logs with the
fetch of the third failing. The ledger holds 1, 2, 4 and 5; `check` is red and names `[3]`;
`binlog_pull_gap_logs` is 1; `BinlogPullGap` has its input in
`hetzner/monitoring/alert_rules_test.yml`, where it fires. Reverting the skip ships log 3
on the next run, `check` is green and the gauge is 0. The alert rule's own test is the same
numbers in a promtool unit test, so a rule edit that stops it firing goes red too.

### What breaks which test

One row per edit to the program or role, with the unit suite run over it.

| Edit                                                                      | Test that fails                                                                                                                              |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `coverage` stops reporting a hole between two shipped logs                | `test_the_skipped_log_is_a_hole_and_the_gap_gauge_says_one` and the rest of `SkippedLogScenario`                                             |
| `coverage` stops counting a missing log the server dropped as lost        | `test_a_skipped_log_the_server_has_dropped_is_lost_for_good`                                                                                 |
| `pull` stops past a failed log instead of going on                        | `test_the_ledger_is_written_after_each_log_so_a_killed_run_keeps_what_it_shipped`                                                            |
| `pull` ships the log the server still has open                            | `test_it_ships_every_closed_log_and_never_the_open_one`                                                                                      |
| `read_span` accepts a cut-short file                                      | `test_a_fetch_cut_inside_an_event_is_refused`, `test_a_log_that_is_cut_short_is_not_shipped`                                                 |
| `require_ciphertext` is not called before the put                         | `test_a_seal_that_is_not_one_recipient_is_not_shipped`                                                                                       |
| The manifest is put before the ciphertext                                 | `test_the_ciphertext_is_put_before_its_manifest`                                                                                             |
| The login value goes into an argument                                     | `test_the_login_value_reaches_the_child_by_pipe_and_never_by_argument`                                                                       |
| The TLS mode or the CA is dropped from a call                             | `test_every_call_is_over_tls_to_the_named_host_with_no_login_value_in_the_arguments`                                                         |
| The fetch streams (`--stop-never`) or reads to the last log               | `test_a_fetch_is_a_raw_remote_read_of_one_named_log_into_a_directory`, `test_the_program_fetches_only_closed_logs_by_name_and_never_streams` |
| `plan_replay` accepts a window with a log missing                         | `test_a_missing_log_inside_the_window_is_refused_and_named`                                                                                  |
| `plan_replay` accepts a stop after the newest shipped log                 | `test_a_stop_after_the_newest_shipped_log_is_refused`                                                                                        |
| `replay` skips the digest check of an opened log                          | `test_a_log_that_opens_to_other_bytes_than_were_shipped_stops_the_replay`                                                                    |
| `replay` applies without `--apply`                                        | `test_a_replay_dry_run_opens_every_log_and_touches_no_database`                                                                              |
| A line of the program reads as a credential assignment to the plan's scan | `test_no_line_reads_as_a_credential_assignment_to_the_plan_scan`                                                                             |
| The timer task loses its `may_disable` gate                               | `test_the_timer_task_is_gated_on_both_switches`; Molecule `converge`                                                                         |
| The environment file is written before it is closed                       | `test_the_environment_file_is_closed_before_the_value_is_written`; Molecule `verify`                                                         |

### Named limits

- **The replay is proven against synthetic logs and a fake `mysql`, not a server.** The unit
  suite builds binary logs byte for byte in the server's event layout and checks the walk, the
  window, the digests and the commands. No test starts a MySQL, so that the logs, replayed over a
  restored dump, give back the data at a chosen time is proven only by the first live drill (the
  steps above on a scratch server). A CI proof against the pinned Percona image is a separate
  piece of work.
- **The fetch and the account are proven only by the first live pull.** Whether `mysqlbinlog`
  accepts those flags over TLS against the tenant host's server and whether the account's rights
  are enough are read from the clients' documentation and the sibling `ship_binlogs.py`, not
  seen against `db-t1`.
- **Nothing reaches `db-t1` today.** Its MySQL listens on loopback only on `main`, and the
  tenants project is its own network: there is no path from `ops1` to the port. Both are owner
  or other work (the listener is the private-listener change for the tenant database host) and the role assumes
  them done. The program takes a host and a port, so a tunnel's local port serves.
- **The put key is put-only.** `pull` can report that a put succeeded; only `audit`, with a read
  key, shows the object came back byte for byte. The timer does not run `audit`, because the
  read key is not placed on `ops1` today (the drill key is the drill runner's).
- **A lost ledger forgets the past.** With the ledger gone, the next pull ships everything the
  server still holds again (bucket versioning keeps the older copies) and the coverage can only
  say what it can see: holes from before are not reported. The ledger is therefore not on the
  backup-excluded list of anything; keep it where it is.
- **A log that is bigger than 256 MiB is never shipped.** The program holds a log in memory to
  put it. A log that large stays unshipped and loud (the gap and unshipped gauges, then the
  alert) instead of being cut. A flush every 15 minutes keeps logs far below that.
- **Copy 2 is not written.** Only copy 1. The second copy is the owner's spend
  (a separate piece of work); the put is one function, `ReleaseStore.put`, and a second
  store added beside it writes the same ciphertext to both.
- **No `absent()` alert.** Like the control plane's backup, a pull nobody has switched on is not
  an alert. A pull that has run once and stopped is `BinlogPullStale`.

## Not in this role

- **The wiring into `ops1`'s playbook and the host-role map**, and the four inputs in the host
  inputs loader. All are owner-merged files (`ansible/playbooks/ops1.yml`,
  `ansible/checks/host_roles/ops1.yml`, `ansible/roles/host_inputs/`,
  `ansible/tools/seed_host_inputs.py`); the role is in none of them yet. It goes after
  `backup_worker` and `backup_restore`, so their files and client are in place.
- **The listener and firewall on `db-t1`, and the path from `ops1`.** See the named limits.
- **Per-tenant log encryption.** The log is one stream of every tenant, so it is encrypted to
  one recipient (page 20). Erasure of a tenant's rows from the logs is bounded by retention
  (10 days current, 35 noncurrent on `binlogs/`), not by destroying a key. Per-tenant log
  encryption is the later trigger of decision 5.
- **Expiry on copy 1.** The `binlogs/` prefix is already expired by the bucket's lifecycle, so
  no rule is added, and a put-only key cannot delete.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after the approval of
its protected environment. The role is not in a playbook yet, so a merge changes no host.

## How to change it safely

1. A change to a path or a name goes in the program and in `vars/main.yml` together; the
   contract tests in `tests/unit` fail when they differ.
2. Keep every task able to run under `--check --diff`, and keep every line of the program free of
   a credential assignment: `test_no_line_reads_as_a_credential_assignment_to_the_plan_scan`
   holds the plan scan's pattern against the file (`ansible/checks/test_plan_diff_scan.py`).
3. A private value never becomes a default, and the program never prints a row, an argument's
   login value or a client's message beyond its numeric code.
4. Do not turn the coverage check into a warning to make a run pass: a green `pull` after a
   skipped log is the failure this program exists to stop.
5. Run the unit suite and the harness before a pull request, then break the control you touched
   and see the named test fail.
