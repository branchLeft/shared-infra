# db1_grants

This role makes the database host's accounts and grants match a declaration. It
covers the dump account on the database host, the dump account the ops1 backup
worker connects with, and the accounts of the tenants' databases. It replaces the
hand-run SQL of the bounded-snapshot runbooks and the by-hand run of the tenant
provisioning program.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

On the database host (`db1`, and only there) it reads the accounts through the
`mysql` client, compares them with the declaration and changes the difference.

1. **The dump account (`backup@localhost`).** It must exist. The role makes its
   global privileges exactly `SELECT`, `PROCESS`, `LOCK TABLES`,
   `REPLICATION CLIENT`, `SHOW VIEW`, `EVENT`, `TRIGGER` and `BACKUP_ADMIN`: it
   grants what is missing and revokes what is surplus (the old set held `RELOAD`),
   in one batch, grants first. It never creates this account.
2. **The ops1 dump account (`backup_ops1`).** It creates the account at the one
   address given as an input, with `REQUIRE SSL` and the password from a host file,
   and makes its global privileges exactly `SELECT`, `SHOW VIEW`, `TRIGGER`,
   `LOCK TABLES` and `BACKUP_ADMIN`. A rotation is one file replacement: the role
   sets the password when the sha256 of the password file differs from the stamp
   written beside it, and only then.
3. **The tenants' accounts.** For each tenant it runs the pinned provisioning
   program only when the tenant's account exists and the account's grant is the
   escaped form (below), to bring the grant and the connection limit (10) to the
   program's values.

It does not create a tenant account (see "Why it never mints a tenant"), does not
escape an existing unescaped tenant grant (the escape runbook does, by hand,
first), does not deliver the program directory or the dump code, does not start,
stop or restart anything, and does not touch any account not named above
(`exporter`, the replicator, `root`).

**Why it never mints a tenant.** The provisioning program creates an account and
a password and prints them once. A role cannot hold that safely, so the role runs
the program only for an account that already exists, and a post-run assertion
fails the run if the program printed a `database=` or `password=` line anyway.
A tenant whose account is absent stops the run with `tenant-absent`.

**Why it refuses an unescaped tenant grant.** An underscore in a grant target is a
one-character wildcard, so `ghost_blog` also covers `ghostXblog`. The pinned
program writes the escaped form; a grant written by the older program is
unescaped and also covers the neighbouring databases. The role checks every tenant
against that, and refuses with `tenant-unescaped` rather than rewrite a production
tenant's grant. The escape rule is the pinned program's: the backslash first, then
the underscore, then the percent sign.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every input.
[`defaults/main.yml`](defaults/main.yml) holds none: there are no defaults, so a
missing input stops the run.

| Variable               | Default        | Meaning                                                            |
| ---------------------- | -------------- | ------------------------------------------------------------------ |
| `db1_grants_tenants`   | none, required | The slugs of the tenants on this host: a list, no duplicates.      |
| `db1_grants_ops1_host` | none, required | The one IPv4 address the ops1 account connects from (no wildcard). |

Both are private: they identify a host and its tenants. They live where the
delivery of this host puts them, never in a file of this repository (see "Live
blockers"). **There is no secret input.** The admin password is read from the
host's own root-only file, `/etc/branchleft/db.env` (key `MYSQL_ROOT_PASSWORD`),
and the ops1 password from `/etc/branchleft/db1-backup-ops1.pw`; the role keeps
no copy of either.

Everything else is a constant in [`vars/main.yml`](vars/main.yml), each with its
reason: the pinned program digests and the commit they were taken at, the
privilege sets, the one tenant host (`10.20.1.%`), the account name rule, the
socket path and the uid that must own it, and the dump window. An inventory value
does not change them. A tenant account is `ghost_` and the slug with hyphens as
underscores; the slug rule and the 26-character limit are the pinned program's.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Python 3 and the MySQL 8.0 client (`mysql`), which the
  `db1_stack` role installs.
- The database running, with its socket at `/opt/branchleft/db/run/mysqld/mysqld.sock`
  owned by uid 999 (the uid the official image runs `mysqld` as).
- The program directory `/opt/branchleft/db/provision` delivered, root-owned and
  not writable by group or others, holding the three pinned programs.

## What it changes on a host

- Database accounts, through the `mysql` client over the socket: grants and
  revokes on `backup@localhost` and `backup_ops1`; the creation of `backup_ops1`
  and its password and `REQUIRE SSL`; and, through the pinned program, the grant
  and connection limit of a tenant that exists.
- `/etc/branchleft/db1-backup-ops1.pw.sha256` (root, `0600`): the stamp. It holds
  the sha256 of the password file and no password.
- A private directory under `/run` for the staged program during a tenant run,
  removed afterwards whether the run succeeded or not.

It changes no other file, starts no service and opens no port. The password is
never on a command line, and never in a task's `environment` either, which Ansible
writes in front of the command it runs (readable by every local account while that
shell lives, and printed by the controller at verbosity 3). The admin password is
the first line of the client's standard input, the statements follow it, and one
fixed `/bin/sh -c` wrapper (`db1_grants_secret_wrapper`, the same text on every
call) reads that line into `MYSQL_PWD` and replaces itself with the client or the
provisioning program.

**Checks before anything changes.** The role stops, by name, before any statement
when: an input has the wrong shape (`tenants-shape`, `tenant-slug`, `ops1-host`);
a directory or file it relies on is writable by others or not root's (`config-dir`,
`db-env-mode`, `db-env-key`, `ops1-password-file-mode`, `ops1-password-shape`,
`program-dir`, `program-missing`); the socket is not owned by uid 999
(`socket-owner`); the dump account is absent, holds a grant the role cannot compare
or every privilege (`backup-absent`, `account-extra-grant`,
`account-all-privileges`); the ops1 account exists at another host
(`ops1-other-host`); the clone plugin is loaded (`clone-plugin`); a tenant account
is absent, unescaped or holds anything but the escaped grant (`tenant-absent`,
`tenant-unescaped`, `tenant-unexpected-grant`); a program's bytes are not the
pinned ones (`program-digest`); the dump account would change while the dump code
is not delivered or inside the dump window, 02:55 to 03:40 UTC
(`dump-code-not-delivered`, `dump-window`); a program run failed or minted
(`program-failed`, `mint-detected`); or the state after the run still differs
(`post-apply-drift`).

**Check mode** reads the database and reports what a real run would change,
without a statement that changes anything. The reads are the only tasks that run
in check mode, and each is marked so (ANS-10).

## How to run its test

From the repository root, with the pinned tools installed as `ansible/README.md`
describes:

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/roles/db1_grants
.venv/bin/python -m unittest discover -b -s ansible/roles/db1_grants/tests/unit -p "test_*.py"
```

To run only the refusal cases a change touches, on an instance kept up with
`molecule converge`, run `DB1_GRANTS_VERIFY_ONLY=REGEX molecule verify`: the regex
is matched against the cases' names in `molecule/default/vars/cases.yml`, and the
positive cases are skipped unless `DB1_GRANTS_VERIFY_POSITIVE=true`. The harness
sets neither, so it always runs everything.

The harness needs Docker and creates one container with no network. The unit tests
need no container and are not run by CI; run them before proposing a change.
One of them reads the vars of the `db1_backup_timers` role, which pins two of the
same programs, and fails while that role is not in the tree.

## How it is delivered

Delivery to a host is the gated workflow only (ANS-17): a plan job in check mode,
the approval of the protected environment, a pull of that exact commit of `main`
on the host, and a second run that must report zero changes. The playbook is
[`playbooks/db1.yml`](../../playbooks/db1.yml): it refuses any host but `db1` (or the
`localhost` the trigger names), applies `db1_stack` and then this role. The role
has not been applied to the live host.

## How to change it safely

- A pin changes in one place and in one change: the digest in `vars/main.yml` and
  the fixture under `molecule/default/files/fixtures`, which the unit test holds
  to the digest byte for byte. Take the program from the commit named in
  `vars/main.yml`, and update that commit with it.
- Run the whole harness and the unit tests, not only the step you touched. Every
  refusal above has a case in `molecule/default/vars/cases.yml` that fails when the
  refusal is removed; keep it that way.
- Never turn `no_log` off to see why a task failed on a real host. Reproduce on a
  lab host with a throwaway value. The unit test fails a task that handles a secret
  without `no_log: true` and `diff: false`.
- Never loosen a privilege set, the digest check, the escaped-grant check or the
  window to make a run pass. A run that cannot satisfy them is the thing to fix.
- Write no private value (a host name, an address, a tenant's slug) into this
  directory. The test uses documentation addresses and made-up slugs.

## What the test proves

The scenario runs the role in a container against a named fake of the `mysql`
client (`molecule/default/files/fakes/fake_mysql.py`): a small table of accounts,
a log of every call it received, and the real pinned programs, byte for byte,
running through it.

- The refusal cases each start from the configured host, spoil one thing, run the
  role and require that it stops with the code named, with the database unchanged.
- The repairs case spoils the ops1 account, the dump account and a tenant's limit
  at once and requires one run to bring the database back to the configured state.
- The rotation case requires the password set exactly once for a replaced file and
  not again for the same file.
- Across the whole run, no password appears on a command line the fake recorded or
  in the log at the highest verbosity, and the role leaves no directory behind.
- A stray module in the program directory does not run: the program runs from a
  private copy.

**Named limits.** The fake is not a MySQL server. It proves what was sent, in what
order and with what secrecy. It does not prove the real server accepts the
statements, that the real `SHOW GRANTS` prints what the fake prints, that a real
account has the shape the fake gives it, or the effect of `REQUIRE SSL`. The live
verification after the gated apply is the proof against the real server: the role's
own post-run assertion, and then a read of the accounts by a human.

## Live blockers

The role must not be applied to the live host until each of these is true.

1. The program directory `/opt/branchleft/db/provision` is delivered with the
   pinned bytes (the dump programs and the provisioning program).
2. The ops1 password file is placed once, by hand, as `printf '%s'` of the password
   into `/etc/branchleft/db1-backup-ops1.pw`, root-owned, mode `0600`, no trailing
   newline.
3. The socket's owner on the live host is uid 999. The role refuses otherwise.
4. Every tenant's grant on `db1` is already escaped. The escape is a by-hand
   runbook; the role refuses an unescaped grant and never rewrites it.
5. The channel that delivers the two private inputs to a host that pulls its
   commit exists. This is the owner's decision; until it is made nothing supplies
   them.
6. The `db1_backup_timers` role is in the tree and in the playbook before this one,
   so the dump code is delivered before the dump account changes.

## Differences from the family base

The first member of this family is `db1_stack`. This role differs in three ways.

| Base (`db1_stack`)                      | This role                                                                  |
| --------------------------------------- | -------------------------------------------------------------------------- |
| One secret input, supplied at run time  | No secret input: both passwords are read from root-only files on the host  |
| Changes files, packages and apt sources | Changes database state through a client, then proves the state afterwards  |
| No program run                          | Runs a pinned program from a private, digest-checked copy, never as minted |

## Clauses this role exercises

ANS-3 (no shell), ANS-10 (check mode and what is skipped in it), ANS-11 (a second
run changes nothing), ANS-14 (this order), ANS-15 (the test runs in a container
only), ANS-16 (secrets, `no_log`, no diff of a secret) and ANS-17 (delivery through
the gated workflow only).
