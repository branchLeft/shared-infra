# db1_backup_timers

Puts the nightly dump, the retention prune and the binary-log ship of db1 on the
host, and enables their three timers. It is the Ansible form of the timers that
the runbooks for db1 currently describe as hand steps.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

1. It fetches the programs that the units run, and the modules they import, from
   the ghost-platform repository at `db/provision` and `db/recovery`, at the one
   pinned commit in `vars/main.yml`. Each is installed root-owned with mode 0644 at
   `/opt/branchleft/db/provision` or `/opt/branchleft/db/recovery`. Each fetch is
   checked against its pinned sha256 digest, and a file whose bytes differ fails.
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

## Why the programs are fetched and not copied

The programs are the code of ghost-platform, and that repository is their one home.
The role used to hold copies of them under `files/`; the DB-1 raw-SQL gate of the
standards then flagged the copies, which are correct where they live. Keeping a copy
is the second home the reuse rule forbids, so the role no longer holds a `.py` file
at all. The unit test `test_no_program_is_copied_into_the_role` keeps it that way.

The fetch names one full 40-character commit, never a branch or a tag, so the bytes
are fixed. `db1_backup_timers_program_sha256` pins the digest of each program at
that commit. The verify play checks each installed file against the same digest.

## Where the copies still come from

The units are still copies of the ghost-platform files at the pinned commit. They are
not Python, so the DB-1 gate does not read them, and the role keeps them as copies
until they are fetched the same way. A unit copy must be refreshed when the unit
changes in ghost-platform, and nothing checks for drift. This is a gap a reviewer
should weigh; see the PR body.

## How it relates to the patterns

The role follows the `program_and_timer` and `files_and_units` patterns: explicit
owner, group and mode on each file, a notify and a handler for the daemon reload, a
`flush_handlers` before the timers are enabled, and a stat in check mode so a fresh
host with no unit file is not asked about one. The program directory checks in the
`program_and_timer` pattern (dedicated directory, real path, foreign content) are not
carried: this role's directories are the fixed paths the units name, shared with
the other programs of the backup, so taking them over as dedicated would be wrong.

## Inputs

None. The paths, file lists, pinned commit and digests are in `vars/main.yml`,
because the unit files fix the paths they run.

## Tests

- `molecule/default` runs the role in a systemd container (ANS-15). The programs are
  fetched over the network from raw.githubusercontent.com at the pinned commit, so
  the container needs that network. The verify play checks each program against its
  pinned digest, and each unit byte for byte against the role's own copy.
- `tests/unit/test_db1_backup_timers.py` checks the schedule values in the units,
  that every program a unit runs is fetched, that every fetched program has a
  digest, that the commit is a full sha, and that no `.py` file is in `files/`.

## Not covered

- The restore drill (runbook section 7) and the marker writes (sections 5a and
  7.1) are run by a person and stay in the runbook.
- The retention runbook's section 6 copy of `db/provision` to db1 is replaced by
  this role only once the role is applied on the host; until then that section
  still applies.
