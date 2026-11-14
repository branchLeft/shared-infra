# control_plane_backup

This role installs the program that backs up the control plane's own data on
`ops1`: the tenant portal's database `portal` and the sign-in service's database
`zitadel`. The program takes both in one snapshot, restores the copy into a
throwaway PostgreSQL and compares the row counts, seals the copy with `age` to the
estate recipient, and puts the ciphertext to backup copy 1. The role installs the
program and its two units and keeps the nightly timer off unless a variable turns
it on.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

1. **Makes two directories**: `/opt/branchleft/control-plane-backup` (`root:root`
   `0755`) for the program, and `/var/backups/branchleft/control-plane` (`root:root`
   `0700`) for the on-host copies. The second is outside the stack's own volumes, so
   `docker compose down -v` cannot take a backup with it.
2. **Installs the program** `branchleft_control_plane_backup.py` (`root:root`
   `0755`) after the program's own `--check` passes on a temporary copy. A program that
   does not load is never installed and the previous one stays.
3. **Installs the service and the timer** (`root:root` `0644`) and reloads systemd
   once when either changed. The service is a oneshot that runs `run` as root
   (`docker` needs it) with `UMask=0077`.
4. **Holds the timer to a variable.** `control_plane_backup_timer_enabled` (default
   `false`). True enables and starts the timer, and is refused while
   `/etc/branchleft/state-copy.env` is not on the host: a nightly run with nowhere to
   put its ciphertext would fail every night. False leaves the timer as it is on the
   host, unless `control_plane_backup_timer_may_disable` is true: then it stops and
   disables it.

The role takes **no private value and no secret**. The program reads the estate
recipient and copy 1's put key at run time from `/etc/branchleft/state-copy.env`,
the file the `backup_restore` role writes for the state copy. One recipient and one
put key serve both jobs, so the owner has no new key to make or place.

It does not create a key, a secret, a bucket or a database login, take the first
backup, enable the timer on its own, or touch the stack.

### What the program does

Commands, all run as root on `ops1`. Exit 0 proven, 1 a check failed, 2 a
precondition is missing so nothing was proven.

| Command                | What it does                                                                                                                                                                                    |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `take`                 | Under the stack's deploy lock, dumps `portal` and `zitadel` into `/var/backups/branchleft/control-plane/<UTC stamp>/` and records the live row count of every table.                            |
| `verify DIR`           | Restores `DIR` into a throwaway PostgreSQL and requires the same tables and the same count in each.                                                                                             |
| `seal DIR`             | Encrypts `DIR` with `age -r` to the estate recipient into `DIR.tar.age`, and writes its sha256 beside it.                                                                                       |
| `ship SEALED`          | Puts the sealed file to backup copy 1 at `state/ops1-control-plane/generations/<stamp>/control-plane.tar.age`. Refuses anything that is not an age file with one recipient.                     |
| `offsite-check SEALED` | Downloads that object with a **read** key (`--read-env-file`, in the `restore-drill.env` format) and requires the digest sealed on the host. The put key cannot read, so `ship` cannot do this. |
| `run`                  | `take`, `verify`, `seal`, `ship`, then prunes on-host copies past the newest seven. This is what the timer runs.                                                                                |

Only table names and counts are printed. The output of docker, psql, pg_dump and
age is withheld, because an error message can quote a row.

**One snapshot.** For each database the program opens a read-only repeatable-read
transaction, exports its snapshot, runs `pg_dump --snapshot` on it, and counts every
table in the same transaction. The recorded counts are therefore exactly what the
dump holds, while the sign-in service keeps writing. A count taken before and after
the dump could not say that. The count is made by the server (`query_to_xml`), so no
row leaves it.

**One throwaway.** `verify` starts one PostgreSQL from the exact image id the live
database runs, with no network, no logs, a memory cap and trust authentication
(safe, because the only way in is `docker exec`). It waits for readiness over TCP,
because the image's init server listens on the socket only. It creates each database,
loads its dump with `ON_ERROR_STOP`, counts, and always removes the container and
its volume.

**Two controls stop a vacuous pass.** A restored database with no tables fails, and
a live database with no tables is refused, because equal emptiness proves nothing.
A table with zero rows is a table: the check holds the table set, so a restore that
lost a table fails even when the counts it kept are right.

**Ciphertext only leaves the host.** `ship` refuses a file that does not start as an
age file or that holds other than one recipient stanza, before it opens a connection.
The private half of the recipient is never on `ops1`, so the sealed copy cannot be
opened there. That is the property: a copy of everything `ops1` holds is ciphertext.

**The master key is not copied.** The sign-in service's master key is
`/etc/branchleft/control-plane/zitadel-masterkey`. The program never reads it. A
restored `zitadel` database is unreadable without it, so a restore needs the key from
its custody (the owner's password manager) as well as the database.

### Owner steps the role does not do

| Step                                                                                                                   | Why the role does not                                                                             |
| ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Place `/etc/branchleft/state-copy.env`: apply `backup_restore` with its inputs and the secret file of copy 1's put key | A secret's source is the owner's. The role never reads or writes the file's content.              |
| The first `run` by hand on `ops1`, and its `offsite-check` with a read key                                             | An owner decision after the program is installed, and a read key the host does not hold.          |
| Turn the timer on, by setting `control_plane_backup_timer_enabled`                                                     | Starts a nightly copy of production data: a production apply through the gated workflow (ANS-17). |
| Keep the estate age identity (the private half) and the sign-in service's master key in the password manager           | Key custody is the owner's (PRIN-6).                                                              |

### Not in this role

- **The wiring into `ops1`'s playbook and the host-role map.** Both are owner-merged
  files (`ansible/playbooks/ops1.yml`, `ansible/checks/host_roles.yml`); the role is
  not in either yet. The program needs `backup_worker` and `backup_restore` applied
  first, so it goes after them.
- **The alert on a stale backup.** The program writes
  `control_plane_backup_last_success_timestamp_seconds{stage=...}` to the backup
  worker's textfile directory. The alert rule that reads it lives in the monitoring
  stack.
- **Expiry of the off-site copies.** The object sits under `state/`, which copy 1's
  lifecycle already expires (current 10 days, noncurrent 35 days, set by
  `configure_backup_bucket.py`), so no lifecycle rule is added. A put-only key cannot
  delete, so the program never prunes off-site.
- **Prospect retention.** A prospect record past the retention the privacy notice
  states must be absent from new backups. That is a rule on the portal's data, not on
  this program.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the two variables and
[`defaults/main.yml`](defaults/main.yml) holds them.

| Variable                                 | Default | Meaning                                                                          |
| ---------------------------------------- | ------- | -------------------------------------------------------------------------------- |
| `control_plane_backup_timer_enabled`     | `false` | True enables and starts the nightly timer (refused without the state-copy file). |
| `control_plane_backup_timer_may_disable` | `false` | True, with the first false, stops and disables the timer. False leaves it alone. |

`vars/main.yml` holds the constants (paths, unit names). A caller cannot override
them. Unit tests pin each one to the program, to `backup_worker`, `backup_restore`,
`control_plane` and `control_plane_db`, so a rename in one place fails here.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 with `/usr/bin/python3` (3.12 or later), systemd and Docker.
- At run time, from earlier roles in the same play: `age` and the object-store client
  staged by `backup_worker` (`/opt/branchleft/backup-worker/current`), and
  `/etc/branchleft/state-copy.env` from `backup_restore`. The program stops with exit
  2 and says which one is missing.

## What it changes on a host

- `/opt/branchleft/control-plane-backup` (`0755`) and the program in it (`0755`).
- `/var/backups/branchleft/control-plane` (`root:root` `0700`).
- `/etc/systemd/system/branchleft-control-plane-backup.service` and `.timer`, `0644`,
  and one systemd reload when either changed.
- The timer's enabled and active state, only when a variable asks.

A run of the program, when the owner starts it, additionally: reads the two databases
(read-only transactions), starts and removes one throwaway container, writes
`<stamp>/` and `<stamp>.tar.age` under the backup directory, writes the textfile
metric, and puts one object to copy 1.

## How to restore

1. Fetch the object `state/ops1-control-plane/generations/<stamp>/control-plane.tar.age`
   from copy 1 with the read key, or take `<stamp>.tar.age` from the host.
2. Decrypt it where the estate identity is held:
   `age -d -i IDENTITY control-plane.tar.age | tar -xf -`.
3. Check the three files against `manifest.json`, then load each
   `<database>.sql.gz` into an empty database: `gunzip -c portal.sql.gz | psql -v
ON_ERROR_STOP=1 -d portal`. The dumps carry no owner and no grants; the roles and
   logins come from the `control_plane_db` role's steps.
4. Put the sign-in service's master key back at its path, with its owner and mode,
   before the service starts. Without that exact key its encrypted data cannot be read.

`verify` is this procedure against a throwaway server, with the counts compared.

## How to test it

Unit tests, from the repository root (they run no container and touch nothing):

```text
cd ansible/roles/control_plane_backup && PYTHONPATH=files python3 -B -m unittest discover -b -s tests/unit -p "test_*.py"
```

The harness, with Docker running locally:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/control_plane_backup
```

The scenario runs the role on one systemd container. `converge.yml` applies it, proves
the timer is refused while the state-copy file is absent (the assertion names that
file), and proves a default apply leaves an enabled timer on. `verify.yml` checks the
installed program and both units equal the role's files byte for byte, the owner and
mode of every path (the backup directory `0700`), that the timer is disabled and
inactive, and that the installed program passes its own check.

### What breaks which test

One row per edit to the program or role, with the unit suite run over it and a restore
afterwards.

| Edit                                                   | Test that fails                                                                                 |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| `compare_counts` stops comparing the counts of a table | `test_a_different_count_names_the_table`, `test_a_restore_that_counts_differently_fails_...`    |
| `compare_counts` accepts a restore with no tables      | `test_an_empty_restore_fails_against_a_live_database_with_tables`, `..._into_an_empty_database` |
| `require_ciphertext` is not called in `ship`           | `test_nothing_that_is_not_an_age_file_leaves_the_host`                                          |
| `take` stops removing its directory on failure         | `test_a_failed_dump_leaves_no_directory_to_be_mistaken_for_a_backup`                            |
| The dump runs without the exported snapshot            | `test_the_dump_reads_the_snapshot_the_counts_were_taken_in`                                     |
| The timer task loses its `may_disable` gate            | `test_the_timer_task_is_gated_on_both_switches`; Molecule `converge`                            |
| The program's `--check` fails                          | Molecule `converge` (the copy's validator)                                                      |

### Named limits

- **The throwaway's Docker arguments are tested against a fake docker.** The real
  `psql`, `pg_dump` and snapshot protocol were run against a real PostgreSQL 14 by
  hand, with a stand-in `docker` that mapped the containers to two local servers;
  the unit suite does not run PostgreSQL. The first real run on `ops1` is the proof
  against PostgreSQL 17 in the stack's image (ANS-17).
- **The object-store client is the backup worker's, loaded at run time.** The test
  uses a fake. The real put is proven only by the owner's first run and its
  `offsite-check`.
- **The put key is put-only.** `ship` can report that the put succeeded; only
  `offsite-check`, with a read key, shows the object came back byte for byte.
- **The timer-on path is not proven by a change.** The scenario enables the timer by
  test setup and runs the role with the timer asked for, so the task runs and reports
  no change; a role run that enables or disables the timer would fail the idempotence
  step.
- **The restore is not a recovery drill.** It proves the dumps load and count the
  same in an empty PostgreSQL. It does not start the sign-in service on them.
- **Two roles' units run on one disk.** The 02:40 UTC timer sits between the dump
  worker's 01:40 run and the state copy's 03:40 run; a long run could still overlap
  one. Nothing orders them.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after the
approval of its protected environment. The role is not in a playbook yet (above), so
a merge changes no host. The wiring is a small owner-merged change after the
`backup_worker` and `backup_restore` roles are applied on `ops1`.

## How to change it safely

1. A change to a path or a name goes in the program and in `vars/main.yml` together;
   the contract tests in `tests/unit` fail when they differ.
2. Keep every task able to run under `--check --diff`. Keep a line of the program
   that is not a credential assignment (`ansible/checks/test_plan_diff_scan.py`
   reads the copied program once the role is reached by a playbook); the shell
   wrapper in the program is written for that reason.
3. A private value never becomes a default, and the program never prints a row.
4. Run the unit suite and the harness before a pull request, then break the control
   you touched and see the named test fail.
