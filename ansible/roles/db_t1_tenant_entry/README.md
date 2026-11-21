# db_t1_tenant_entry

This role gives the tenant database host (`db-t1`, the `dbt1` host in this repository) one
narrow way in for the platform's controller: an SSH key whose only permitted command creates
one tenant's database and account, from a validated name, and prints a generated password once.
It replaces creating a tenant's database over root SSH with a pasted root password.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

It does, in order:

1. Refuses a controller key that is not one `ssh-ed25519` public key on one line, and an
   address that is not one IPv4 address.
2. Makes the account `tenantdb`, with a shell (sshd runs a forced command through it), no
   password and no home it owns.
3. Installs the program `/usr/local/sbin/branchleft-tenant-db-entry` as root.
4. Installs a sudoers rule that lets the account run that one path, as root, with no argument.
5. Installs the controller's key as the account's only authorized key, as
   `restrict,from="ADDRESS",command="/usr/bin/sudo -n /usr/local/sbin/branchleft-tenant-db-entry"`.

The program, `files/tenant_db_entry.py`, is what a client reaches. sshd runs it whatever the
client asked for and leaves the client's request in `SSH_ORIGINAL_COMMAND`. The request is
accepted in exactly one shape, `create-tenant-db NAME`. For a name that is valid and free the
program makes the database `ghost_NAME` (hyphens become underscores), one account of the same
name that may connect only from the application host, and one grant on that database alone. It
prints three lines on standard output (`database=`, `user=` and `password=`), and that is the
only place the password is ever written.

The program refuses, and changes and prints nothing:

- any request that is not that command: a shell, a second command in any shape, an empty request,
  a request with a line break, a request longer than 128 characters (reason `bad-command`,
  `no-command`, `request-too-long`; exit 2);
- a name that fails the tenant-name rule, or has a character outside lower-case letters, digits
  and hyphens, such as a quote (reason `bad-name` or `bad-command`; exit 2);
- a name whose database or account already exists (reason `exists`; exit 3). A second request
  cannot read, reset or take over an existing tenant;
- a request made while another is running (`busy`; exit 4), and one made when the database
  container is not found or a statement fails (`no-database`, `sql-failed`; exit 5).

Standard error carries one line of fixed text, never the request and never the server's own message.

It does not:

- read, store, print or pass the database's root value. The program asks the running container to
  run the database client, and the client takes the value from the container's own environment, so
  nothing on the host holds it for this program to read and it is never on a command line. The
  role reads no secret file either.
- create the application host's entry point, deliver the password to its secrets file, or decide
  how the controller runs the command. The password is on standard output so that the controller
  can pipe it straight into the application host's channel, and the controller and that channel
  are other work (see "Named limits").
- delete, change or grant anything on an existing tenant, make a backup, open a port or touch the
  firewall, or start or stop the database.
- add itself to any host's play. See "How it is delivered".

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the two inputs and Ansible checks
them when the role starts. Neither has a default (ANS-7): a host that is not given them gets no
access at all.

| Variable                                | Meaning                                                                      |
| --------------------------------------- | ---------------------------------------------------------------------------- |
| `db_t1_tenant_entry_controller_key`     | The controller's SSH public key, one `ssh-ed25519 AAAA...` line, no comment. |
| `db_t1_tenant_entry_controller_address` | The one IPv4 address the controller connects from.                           |

The key is a public half and holds no secret, but the key and the address are private to the
estate, so they are supplied at run time and never committed (ANS-16), and every task that handles
the key hides its result and its diff. A key with a comment or an option, a second line, another
key type, a wildcard, a mask or a list of addresses is refused by name before anything changes: the
line is written into an authorized_keys file, and a second line there would be a second,
unrestricted key. Everything else is fixed in [`vars/main.yml`](vars/main.yml) with its reason
beside it, and an inventory value does not move it.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; no collection beyond `ansible.builtin`.
- Target: Debian 13 with `/usr/bin/python3` (3.13), `sudo` and `visudo`, an SSH server that reads
  the account's `authorized_keys`, and Docker at `/usr/bin/docker`.
- The `db_t1` role's stack running: one container of the compose project `dbt1`, service `mysql`.
  The program finds it by those two labels and refuses if there is not exactly one.

## What it changes on a host

| Path                                           | Owner : group   | Mode   | What                                      |
| ---------------------------------------------- | --------------- | ------ | ----------------------------------------- |
| `/usr/local/sbin/branchleft-tenant-db-entry`   | root : root     | `0755` | The program                               |
| `/etc/sudoers.d/60-branchleft-tenant-db-entry` | root : root     | `0440` | The one rule, checked with `visudo -csf`  |
| `/home/tenantdb`, `/home/tenantdb/.ssh`        | root : root     | `0755` | The account's home, which it cannot write |
| `/home/tenantdb/.ssh/authorized_keys`          | root : tenantdb | `0640` | The one restricted line                   |

and the system account `tenantdb`. At run time the program also keeps a lock file,
`/run/lock/branchleft-tenant-db-entry.lock`, and writes one line to the system log for each request
(a fixed reason or the new database's name, never the request text and never a password).

The sudoers file holds two lines: `Defaults:tenantdb env_keep += "SSH_ORIGINAL_COMMAND"`, which
keeps the one variable the program needs through sudo, and the rule
`tenantdb ALL=(root) NOPASSWD: /usr/local/sbin/branchleft-tenant-db-entry ""`. The empty string
at the end means no argument; a rule with no argument at all would allow any.

Decisions a reviewer should know the reasons for:

- **Three layers, each holding alone for what it holds.** The key's options (`restrict`, one source
  address, one command) decide what sshd will run; the sudoers rule decides what the account can
  run as root if it ever got a shell; the program decides what a request may ask. Loosening one
  leaves the other two. The scenario tries each.
- **The account cannot loosen its own restrictions.** Its home, `.ssh` directory and key file belong
  to root. The account has no password and no shell login by any key but this one.
- **Run as root, no `docker` group.** Membership of the `docker` group is root-equivalent. The
  program runs as root through the one sudo rule instead, with a fixed environment for every child
  it starts, an absolute path for every program, and no shell line anywhere.
- **Create, never ensure.** The by-hand program (`provision_tenant_db.py` in ghost-platform, which
  `db1_grants` and `db1_backup_timers` pin for `db1`) leaves an existing account in place and
  re-applies its grant. This program refuses an existing name, so a request can never touch a
  tenant that already runs. The statements use no `IF NOT EXISTS`.
- **One host for the account.** The account connects from the application host's private address
  (`10.20.1.201`, `TENANTS_HOST_IPS.appT1` in `hetzner-host/addressPlan.ts`, held by a test), not the
  subnet, so no other host of the project can use a tenant's password.
- **The grant is on the one database, with the underscore escaped.** An underscore in a grant target
  is a one-character wildcard, so `ghost_a_b` would also cover `ghost_a1b`. The escape is the same
  as the by-hand program's, and a test compares the two.
- **The tenant-name rule is a copy.** No role imports another (ANS-12), so the rule, the prefix and
  the 26-character limit are copied from ghost-platform's `naming.py` and held to it by a test that
  fetches the file at the commit the database roles pin.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/db_t1_tenant_entry
```

The unit tests run without Docker, from `ansible/roles/db_t1_tenant_entry`:

```text
PYTHONPATH=files ../../../.venv/bin/python -m unittest discover -b -s tests/unit -p "test_*.py"
../../../.venv/bin/mypy --strict files tests/unit
```

`test_tenant_db_entry.py` holds the request parsing and the one action to a stand-in container
runtime (about 99 percent of the program's statements and branches). `test_db_t1_tenant_entry_role.py`
holds the key line, the sudoers rule, the inputs and the pins, and fetches ghost-platform's
`naming.py` and `provision_tenant_db.py` at the pinned commit, so it needs the network.

The Molecule scenario starts a real `sshd` of its own in a container, a stand-in for `docker` and
the database client with one tenant already on it, and the real `sudo`. It connects with the
controller's key and asks for: one tenant (made, three lines, once); the same tenant again and the
one that was there before (refused); a shell and twenty other commands, names with a quote, bad
names, and no command (each refused, nothing made, no marker file written); a pty, port forwards,
sftp and scp (refused); a key that is not listed, and the controller's key from another address
(turned away). It then reads every log for the password and the key. It cannot prove the real
database, Docker or the attestation of any image; those are the first live run's.

## How it is delivered

Only through the gated workflow (ANS-17): the plan in check mode, the approval, the pull of that
exact commit on the host, and a second run that must report no change. **Nothing delivers this
role yet.** It is in no host's play, so merging it changes no host. Adding it is the owner's merge
(R9, `ansible/checks/host_roles/dbt1.yml`), and it needs the two inputs, which `dbt1` has no route
for today because it has no `host_inputs`:

1. Add `db_t1_tenant_entry` to `ansible/checks/host_roles/dbt1.yml` and the `dbt1` playbook, after
   `db_t1`.
2. Supply `db_t1_tenant_entry_controller_key` and `db_t1_tenant_entry_controller_address` for that
   host through the owner's route for it (`ansible/owner_vars/`, the owner's merge).
3. After the gated apply and a second run that reports no change, the live proof is that the
   controller creates a test tenant's database through it, and that a shell command, a name with a
   quote and an existing name sent with the controller's key are each refused.

Check mode shows less than an apply, and the gaps are named. The sudoers syntax check is the
module's `validate`, which does not run in check mode, so a plan shows the file as a change where
an apply may still refuse it. On a fresh host the plan shows the account's creation and the files;
every later task is not gated on anything that does not yet exist.

## How to change it safely

1. The key line, the sudoers rule and the program's accepted shape are one boundary. A change to
   any of them is read with the other two, and the scenario's hostile cases are extended in the
   same pull request.
2. Never widen the rule: no wildcard, no argument, no second command, no `SETENV`, no `docker`
   group. The tests name each.
3. Never let the program read a file other than its lock, take an argument, run a shell line, or
   print what the server said. A test holds each.
4. A new command word is a new boundary, not a flag on this one: file it as its own entry point.
5. A control is proven by sabotage: loosen it, see the named test go red, restore it with
   `git restore`, see green.

## Named limits

- **The application host's side is not built.** The password goes to standard output. The
  controller, the channel that carries it into the application host's secrets file and the entry
  point on that host are other work. Until they exist nothing calls this program.
- **A delivery failure leaves an account with no known password.** If the password cannot be
  written (the client went away after the account was made), the program exits 5 with
  `reason=undelivered`. A retry is refused as `exists`, so someone with root on the host removes the
  tenant's database and account by hand before asking again. The program never reprints a password.
- **A failed statement can leave a half-made tenant.** The database is created before the account.
  If the server fails between the two, the name exists and is refused on retry until removed by hand.
  The program does not roll back, because a rollback that dropped a database it did not make would
  be worse.
- **The account's host part is a decision still open.** `10.20.1.201` assumes the application host
  connects over the private network. If the tunnel makes connections arrive from the loopback
  address instead, the account must be made for that address; change the constant and its test in
  one pull request.
- **The password is in the statement.** It is sent on standard input to the client in the container
  and never in an argument. MySQL's own documentation says the server rewrites a statement that
  carries a password before it writes the binary log or the general log; that was read, not
  measured on the pinned image.
- **Every non-matching request is refused by the program, not by sshd.** sshd starts the forced
  command for any session request, so a refused request is a process that ran and exited 2. The
  program does nothing before it parses the request.
- **The lock is on the host.** Two controllers asking at once get `busy` for one of them, which is
  retried by the caller.

## Clauses this role exercises

ANS-2 (typed program), ANS-3 (modules before commands), ANS-7 (no defaults for the inputs), ANS-9,
ANS-10 (check mode), ANS-11 (idempotent), ANS-12 (no role imports another), ANS-14, ANS-15, ANS-16
(no secret reaches a log) and ANS-17.
