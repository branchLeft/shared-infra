# media_backup

This role installs the weekly media backup on the control host. A systemd timer
runs `media_backup_weekly.py` once a week: for every enrolled tenant it reads
that tenant's folder on the shared media buckets directly (not through the
storage gateway), encrypts it to that tenant's own age recipient, and writes a
dated copy in the backup bucket, where a lifecycle rule expires copies after 28
days. The program and its tests live in `branchLeft/ghost-platform`
(`infra/provisioning/scripts/media_backup_weekly.md`); this role puts it on the
host and holds the timer.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

1. **Stages a release.** Each of the five files (the program and the four it
   imports) is downloaded with `get_url` from `branchLeft/ghost-platform` at a
   pinned full commit and held to a `sha256`. They land in
   `/opt/branchleft/media-backup/releases/<commit>/`, owned by root and
   writable by no one else, and `current` points at the release.
2. **Installs two units**, `branchleft-media-backup.service` and `.timer`, from
   the role's templates, then reloads systemd. The service runs as the nightly
   worker's account with the same hardening, runs the program's own `--check`
   first, and sets the request ceiling.
3. **Creates the two files the owner fills**, empty when absent, and sets their
   owner, group and mode on every run: `/etc/branchleft/media-backup.env`
   (`root:root` `0600`) and `/etc/branchleft/backup-worker-media-folders`
   (`root:backup-worker` `0640`).
4. **Holds the timer to a variable.** `media_backup_timer_enabled` is false by
   default. True enables and starts the timer, and is refused until the settings
   file, the folders file, the recipients file and the manifest signing key are
   all in place. False leaves the timer as it is on the host, unless
   `media_backup_timer_may_disable` is true.

It does not make the service account, the recipients file or the age keys (the
`backup_worker` role does the first two and the owner the keys), create a bucket
or a key, make the manifest signing key, start a run, or read the content of any
file the owner places. It never writes a value.

### Owner steps the role does not do

Each is a one-time step on the host as root. The role refuses to enable the
timer until each is done.

1. Write `/etc/branchleft/media-backup.env` with the nine names the program
   reads: `MEDIA_LIVE_ENDPOINT`, `MEDIA_LIVE_REGION`, `MEDIA_LIVE_ACCESS_KEY_ID`,
   `MEDIA_LIVE_SECRET_ACCESS_KEY` (the shared read-and-list key), and
   `MEDIA_BACKUP_ENDPOINT`, `MEDIA_BACKUP_REGION`, `MEDIA_BACKUP_BUCKET`,
   `MEDIA_BACKUP_ACCESS_KEY_ID`, `MEDIA_BACKUP_SECRET_ACCESS_KEY` (the backup
   bucket's put-only key). One `NAME=value` per line.
2. Write `/etc/branchleft/backup-worker-media-folders`, one line per enrolled
   tenant: `slug bucket folder`, where the bucket and folder are the ones the
   storage gateway holds for that tenant. Add `no-media` as a fourth word only
   for a tenant known to have no media.
3. Make the manifest signing key: `ssh-keygen -t ed25519 -N '' -f
/etc/branchleft/media-backup-manifest-signing-key`, then `chown root:backup-worker`
   and `chmod 0640` on the private file. The public half goes to whatever host
   restores. Where this key is kept is the owner's decision: it sits on the same
   host as the put key, so it authenticates the worker, not a separate custodian.

### Not in this role

- The lifecycle rule that expires the copies after 28 days is the backup
  bucket's (`db/provision/configure_backup_bucket.py` in `ghost-platform`).
- A missed or overrunning run alert is its own work
  ([ISSUE branchLeft/workspace#1767](https://github.com/branchLeft/workspace/issues/1767)).

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables and
[`defaults/main.yml`](defaults/main.yml) holds their defaults. None is a secret.
The secret values are in the settings file the owner places, which the role never
reads. `media_backup_max_requests_per_second` (default 50, from 1 to 400) is the
request ceiling and is to be set from a measured run. The paths, the account and
the patterns are constants in `vars/main.yml`, which a caller cannot override by
accident.

## Requirements

Debian 13 with `python3` 3.12 or later, `age` and `ssh-keygen` on the host, and
the `backup-worker` account and the recipients file the `backup_worker` role makes
(apply that role first in the same play). Ansible 2.21.6 or later on the machine
that applies it.

## What it changes on a host

- `/opt/branchleft/media-backup/` and the release below it, and the `current` link.
- `/etc/systemd/system/branchleft-media-backup.service` and `.timer`.
- `/etc/branchleft/media-backup.env` and `/etc/branchleft/backup-worker-media-folders`,
  created empty if absent, and their attributes.
- The timer's enabled and active state, only as the two variables ask.

It makes no network call except the download of the five files.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` says:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/media_backup
.venv/bin/python -m unittest discover -s ansible/roles/media_backup/tests/unit
```

The scenario points the download at a test-only copy of five placeholder files
and checks the link, each file's checksum and ownership, the unit text, the
owner-placed files' attributes, that a wrong checksum is refused, that enabling is
refused until the files are placed, that a run with the defaults leaves an enabled
timer on, and that the service never ran.

Named limits: check mode skips the refusal cases (they need a real run); the
`media_backup_timer_may_disable` path is read in the tasks and the unit test but not
run in the scenario, because enabling and disabling the timer in one converge would
report a change on every run; the program is not run in the scenario.

## How it is delivered

`ansible/**` changes reach a host only through the gated workflow (ANS-17): plan in
check mode, the `ansible-hosts` approval, apply, then a second run that reports no
change. A merge makes nothing live. The role is on no host's list yet: adding it to
`checks/host_roles/ops1.yml` and `playbooks/ops1.yml` (after `backup_worker`) is the
owner's merge (rule R9). The first run of the timer is the owner's step: enable it,
read the journal's per-tenant lines, and read the copies back in the backup bucket.

## How to change it safely

- Bump the commit and all five checksums together. The checksum of each file is
  `sha256` of the bytes at that commit; a mismatch fails the download.
- A new import in the program is a new pin and a new entry in `media_backup_required_paths`.
- Keep the ceiling at or below 400; the program refuses more, and the provider's limit
  is 750 a second per address and per bucket.
- Never add a task that reads a file the owner places.
