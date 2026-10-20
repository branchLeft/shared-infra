# db1_backup_timers

Puts the nightly dump, the retention prune and the binary-log ship of db1 on the
host, and enables their three timers. It is the Ansible form of the timers that
the runbooks for db1 currently describe as hand steps.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

1. It copies the programs under `files/provision/` to `/opt/branchleft/db/provision`
   and the programs under `files/recovery/` to `/opt/branchleft/db/recovery`. Each
   is root-owned with mode 0644, byte for byte as it is in the ghost-platform
   repository at `db/provision` and `db/recovery`.
2. It copies the six unit files under `files/units/` to `/etc/systemd/system`, and
   reloads systemd when one changed.
3. It enables and starts the three timers: `branchleft-db-dump.timer` (03:10 UTC,
   random delay of up to five minutes), `branchleft-db-prune.timer` (03:45 UTC) and
   `branchleft-db-binlog-ship.timer` (five minutes after boot, then every 15 minutes).

It does not write `/etc/branchleft/db.env`. The units read that file, and it holds
the backup credentials, so it stays the host's own and is outside this role. It does
not start any service, and it does not touch MySQL, the Compose unit
`branchleft-compose@db.service` the two MySQL-facing units require, or the backup
bucket.

## How it relates to the patterns

The role follows the `program_and_timer` and `files_and_units` patterns: explicit
owner, group and mode on each file, a notify and a handler for the daemon reload, a
`flush_handlers` before the timers are enabled, and a stat in check mode so a fresh
host with no unit file is not asked about one. The program directory checks in the
`program_and_timer` pattern (dedicated directory, real path, foreign content) are not
carried: this role's directories are the fixed paths the units name, shared with
the other programs of the backup, so taking them over as dedicated would be wrong.

## Where the copies come from

The programs and units are copies of the ghost-platform files at the commit the
PR body names. The ticket says the programs stay as code in ghost-platform, and a
role in shared-infra cannot read another repository at run time. The copies are
therefore the one place this role reads from, and they must be refreshed from
ghost-platform when those files change. This is a gap a reviewer should weigh:
see the PR body.

## Inputs

None. The paths and file lists are in `vars/main.yml`, because the unit files fix
the paths they run.

## Tests

- `molecule/default` runs the role in a systemd container (ANS-15) and verifies the
  files, modes, owners and the three enabled timers, byte for byte against the
  role's own copies.
- `tests/unit/test_db1_backup_timers.py` checks the schedule values in the units,
  that every program a unit runs is in `files/`, and that every module a program
  imports from its own directory is in `files/`.

## Not covered

- The restore drill (runbook section 7) and the marker writes (sections 5a and
  7.1) are run by a person and stay in the runbook.
- The retention runbook's section 6 copy of `db/provision` to db1 is replaced by
  this role only once the role is applied on the host; until then that section
  still applies.
