# db1_stack

This role prepares the database host. This first part installs the host's
prerequisites (`age` and a MySQL 8.0 client toolchain held to that line) and
renders the credentials file of the database's metrics exporter from a password
given at run time. It replaces two hand-run scripts, one that installed the
prerequisites and one that rendered the credentials file.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

It does two things on a Debian 13 host.

1. It installs the host prerequisites. It delivers the MySQL repository as a key
   file, a source file and an apt pin that holds the toolchain to the 8.0 line;
   it downloads one pinned package file and installs it; it installs `age` and
   the two MySQL packages; and it checks that the two MySQL packages are on the
   8.0 line.
2. It writes the exporter's credentials file, `/etc/branchleft/db-exporter.my.cnf`,
   from a password the caller supplies, owned by the account the exporter runs
   as, readable by that account only.

This is part one of two. It does not deliver the compose stack, the systemd
drop-in, the MySQL configuration or the units that run the database, and it does
not start or restart anything. A second part adds those and retires the
runbook steps that do these jobs by hand. The role has not been applied to the
host: the live run waits on the pull trigger and the gated workflow (see "How it
is delivered"). After it is applied, the hand-run prerequisites script must not
be run again: it would put back the repository entry the role removes (see
"What it changes on a host").

It does not decide where the password comes from, create the database account the
password belongs to, or rotate the password in the database. The role makes the
file match a password it is given; putting the same password in the database is a
separate step.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every input, and
[`defaults/main.yml`](defaults/main.yml) holds the same defaults. Ansible checks
the inputs when the role starts.

| Variable                      | Default                    | Meaning                                                                                   |
| ----------------------------- | -------------------------- | ----------------------------------------------------------------------------------------- |
| `db1_stack_exporter_password` | none, required, **secret** | The exporter account's password: at least 20 characters of `A-Za-z0-9._~-`, nothing else. |
| `db1_stack_apt_packages`      | `age`, the two MySQL ones  | Packages installed from the apt index.                                                    |
| `db1_stack_downloads`         | the `libaio1` package file | Pinned downloads: `url`, `dest` and a `sha256:` or `sha512:` `checksum`.                  |
| `db1_stack_debs`              | the same package file      | Local package files installed by path; each must be the `dest` of a download.             |

**The password is the only secret.** It reaches the role as a variable supplied
at run time, never as a default and never in a file of this repository. Every task
that reads, templates or passes it sets `no_log: true`, and `diff: false` where a
diff would show it (ANS-16). Where the value comes from, and how it reaches a host
that pulls its commit, is the owner's decision (PRIN-6) and not this role's; until
it is made, nothing can supply the password on a real host.

The pins that are not inputs (the repository, its suite and component, the key
digest, the version line, the packages the pin file covers, the exporter's uid and
the file mode, the password rules) are in [`vars/main.yml`](vars/main.yml), each
with the reason for it. An inventory value does not change them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` in
  `meta/main.yml` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Python 3 and `python3-apt`. Debian 13 is the release
  every production host runs.
- A controller that can reach `deb.debian.org` (the download) and, from the host,
  `repo.mysql.com` (the index). The test needs neither.

## What it changes on a host

- `/var/cache/db1-stack/` (root, `0755`) and the pinned package files in it
  (root, `0644`).
- `/etc/apt/keyrings/mysql-community.asc` (root, `0644`): the vendored repository
  keys. `/etc/apt/sources.list.d/mysql-community.sources` (root, `0644`): the
  repository, signed by that file. `/etc/apt/preferences.d/mysql-community-8.0`
  (root, `0644`): the pin that holds the toolchain to the 8.0 line, with priority
  1001 so a newer candidate is never chosen.
- Removes `/etc/apt/sources.list.d/mysql-community.list` and
  `/usr/share/keyrings/mysql.gpg`, which the hand-run script made. They name the
  same repository with another key file, and apt refuses two entries for one
  repository that disagree about the key. If either was there, the role refreshes
  the apt index.
- Installs the packages in `db1_stack_debs` and `db1_stack_apt_packages`.
- `/etc/branchleft/` (root, `0755`), the directory the host's provisioning
  creates; the role states its owner and mode so a run puts them back.
- `/etc/branchleft/db-exporter.my.cnf`: owner and group uid 65534 (`nobody`, the
  user the exporter image runs as), mode `0400`. Content: `[client]`, then the
  `user`, `password` and `socket` lines.

It starts no service, opens no port and creates no user.

## How to run its test

From the repository root, with the pinned tools installed as `ansible/README.md`
describes:

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/roles/db1_stack
```

The harness runs lint, yamllint, a fresh-state check-mode run, converge, a second
converge that must change nothing, verify, a configured-state check-mode run,
Molecule's own check action and destroy. It needs Docker on the machine and
creates one container with no network. It never touches a host.

CI runs the harness over every role and every pattern (the Ansible workflow), so
this scenario runs on each pull request.

## How it is delivered

Delivery to a host is the gated workflow only (ANS-17): a plan job in check mode,
the approval of the protected environment, a pull of that exact commit of `main`
on the host, and a second run that must report zero changes. Nothing in this
repository applies the role by hand, and an author's local run is the container
test. The live run is waiting on the pull trigger and the gated workflow being
available for this host; until then this role is tested and not delivered.

## How to change it safely

- A pin changes in one place and in one change: the value in `vars/main.yml` or
  `defaults/main.yml`, the digest or text the test expects in
  `molecule/default/verify.yml`, and (for the key) the key file.
- Run the whole harness, not only the step you touched. Every control below has a
  test that fails when the control is removed; keep it that way.
- Never turn `no_log` off to see why a task failed on a real host. Reproduce on a
  lab host with a throwaway value.
- Never loosen `scan-downloads.j2` (in the `packages_and_downloads` pattern), the
  assertions at the top of `tasks/main.yml`, or the password rules to make a run
  pass. A download that cannot satisfy the first, or a password the second
  refuses, is the thing to fix.

PLACEHOLDER_README_REST
