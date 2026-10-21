# breakglass_mint_host

Installs on the control host the one program that mints a break-glass grant
token, pulls the image that program runs in, and checks that the signing key the
owner made by hand is in place. It never opens the key.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role makes the plain, repeatable part of the break-glass minter's setup on the
control host (`ops1`):

1. Refuses an input that is not a full 40-character commit, or a constant that is
   not an image pinned by digest, before anything is touched.
2. Refuses a host with no working `docker`.
3. Makes the directories above the tool and the log, each with an owner and a
   mode.
4. Probes for the Node image under its digest and pulls it only when the host
   lacks it, then reads the digest back and refuses if it is not there.
5. Downloads `break-glass-mint.mjs` from the pinned commit of the
   `ghost-platform` repository and holds it to its sha256.
6. Looks at the signing key with `stat` and nothing else, and refuses unless it
   is a regular file owned by root in mode 0600, in a directory owned by root in
   mode 0700. This is the last task, so a missing or wrong key is a stop.

It does not create the key (the owner makes it by hand, once, at the host), does
not place or rotate it, does not mint a token, does not run the minter, and does
not set any secret. It also does not install the grant side (`breakglass_grant_host`,
for the application hosts).

The role never opens the key. The key is looked at with `ansible.builtin.stat`
with `get_checksum`, `get_mime` and `get_attributes` all false and `follow`
false, so the module reads neither its content nor a hash of it, and a link in
its place is refused as not being a regular file. The refusal text names the path
only: no stat field and no part of the key. The test proves this against a
placeholder, not the real key (see "Named limits").

## Interface

The variable, its type and default are in `meta/argument_specs.yml`; the same
default is in `defaults/main.yml`. Ansible checks it when the role starts.

| Variable                             | Meaning                                                             |
| ------------------------------------ | ------------------------------------------------------------------- |
| `breakglass_mint_host_source_commit` | The full commit of `ghost-platform` the program is downloaded from. |

It must be the same as the same-named input of `breakglass_grant_host`, the
role for the application hosts: the minter and the grant tool are two halves of
one protocol and must come from one commit. The test of each role reads the
other's defaults and fails if they differ. The Node image is not an input: it is a
constant in `vars/main.yml`, and it must equal the grant role's constant, which the
shipped wrapper and expire unit also carry. The test of each role compares the two
constants. The sha256 of the downloaded file, the download base, the directories
and the key path are constants in `vars/main.yml` too, not inputs: an inventory
value cannot change them. No variable is a secret.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version.
- No collections beyond `ansible.builtin`.
- Target system: Debian 13, with `docker` installed by another role or by hand, and
  network access to `raw.githubusercontent.com` and to the image registry on the
  first apply.

## What it changes on a host

| Path                                    | Owner | Mode | What                                     |
| --------------------------------------- | ----- | ---- | ---------------------------------------- |
| `/usr/local/lib/branchleft`             | root  | 0755 | Shared parent, also made by other roles. |
| `/usr/local/lib/branchleft/break-glass` | root  | 0755 | The tool directory.                      |
| `.../break-glass/break-glass-mint.mjs`  | root  | 0644 | The program, held to its sha256.         |
| `/var/log/branchleft`                   | root  | 0700 | Shared parent, also made by other roles. |
| The Node image, in Docker's store       | n/a   | n/a  | Pulled by digest when absent.            |

Nothing is started and no unit is installed. The key directory
`/etc/branchleft/break-glass` and the key in it are not touched: they are only
looked at.

## Refusals leave the host untouched

Each of these stops the run at the named task, before any later task writes
anything. The test converge applies the role in each state and asserts which task
stopped it.

- An input that is not a full commit, or a constant that is not a digest-pinned image.
- No `docker` on the host.
- A key that is missing, is a link, is a directory, is not owned by root, is not
  mode 0600, or sits in a directory that is not root-owned and mode 0700.

The key check is the last task and comes after the program and the image are in
place. That is on purpose: the owner makes the key by hand, so the first apply
may well run before the key exists, and the apply then stops with the files and
the image already installed and a clear message. Run it again after the key is
made.

Rotating the key means the key is replaced by hand. While it is being replaced
the key check can fail, and the role does not repair that: a missing or wrong key
is a stop for the owner, never something the role writes over.

## Taking over by hand

The role is the way this host is set up. The hand steps for the key (creating
it, putting it in `/etc/branchleft/break-glass`, escrowing a copy) stay as
written in the break-glass runbook, because they are one-off and hold a secret.
Until the first apply of this role on the host is cited, the runbook's hand steps
for the tool and the image stay as the fallback.

## Named limits

- **The test stands in for Docker.** A small program takes the place of the
  `docker` command (`breakglass_grant_host/molecule/default/files/docker_standin.sh`,
  which is its one home; this scenario copies it from there). The test proves what
  the role asked Docker to do, in what order, and how many times (one pull over two
  applies). It does not prove that the image pulls from a real registry. The gated
  run on the host is that proof.
- **The test key is a placeholder.** It has a made-up text at a path of the test's
  own, never the real key path. The test proves the role looked at the key's
  metadata and never at its content, and that the Ansible log (at verbosity 3)
  holds neither the placeholder's text nor its SHA-1, MD5 or base64 (the form
  `slurp` prints a file in). A control file whose SHA-1 the test asks `stat` for,
  with the default arguments, and whose base64 the test asks `slurp` for, must
  appear in that log, which shows the scan can see a digest and a base64 content at
  all. The real key's content is never read by the role, by the test or by an agent.
- **The role has one tasks file and nothing else that runs tasks.** The key checks
  read `tasks/main.yml`. The test lists the role directory and requires exactly
  `README.md`, `defaults`, `meta`, `molecule`, `tasks` and `vars`, a tasks directory
  holding only `main.yml`, and no meta dependency, so a handlers file, a second
  tasks file or a library cannot add a route to the key that those checks do not
  read.
- **`command` is used for `docker`.** The Docker modules need the Docker API
  library on the host, which these hosts do not carry (ANS-9). The probes are
  read-only, so they run in check mode; the pull runs only after a probe finds the
  digest absent.
- **Check mode.** The pull is skipped in check mode when the digest is absent,
  and the read-back after the pull is skipped in check mode, because nothing was
  pulled to read. The download is skipped in check mode on a fresh host, where the
  tool directory does not exist yet. Each skip is only for that reason.
- **One network dependency.** The first apply needs `raw.githubusercontent.com`
  and the registry. A failed download is a failed run, not a partial install: the
  download is held to its sha256.
- **Not a secret store.** Nothing here is a secret, and no task has `no_log`
  except those of the test that write the placeholder.

## How to test it

From the repository root, with the toolchain installed as `ansible/README.md`
describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/breakglass_mint_host
```

The harness runs the lint steps, then Molecule in a container: create, prepare,
a check-mode pass on a fresh host, converge, idempotence, verify, a check-mode
pass on the configured host, and destroy. `molecule/default/converge.yml` applies
every refusal state first and then the role once. `molecule/default/verify.yml`
checks:

- the two roles agree on the commit and the image;
- the download URL is at the pinned commit and each file holds its sha256;
- the role uses only the modules and `docker` arguments on its allow-list, with
  the exact task counts the design has, so a loop cannot be emptied unseen;
- the owner and mode of every path, written independently from the role's own
  table;
- no grant-side file was installed;
- one pull over two applies, by digest, never by tag;
- the role directory holds no handlers file and no second tasks file;
- the placeholder key is unchanged and the log scan above.

The playbook `ansible/playbooks/ops1.yml` is a host-guarded playbook that lists
this role. The test runs it against a host name that is not `ops1` and requires
it to refuse, and lists its tasks for `ops1`.

## How it is delivered

A role reaches a host only through the gated pull (ANS-17), never by running
`ansible-playbook` by hand. `playbooks/ops1.yml` is the playbook for the control
host. It is applied once the host is enrolled in the gated pull; until then a
merge of this role changes no host.

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together.
2. Bump the commit, the sha256 and the Node image in `vars/main.yml` together, and
   bump the same commit and image in `breakglass_grant_host` in the same pull
   request.
3. Keep every task able to run under `--check --diff`, and keep the role
   idempotent.
4. Never add a task that opens, copies, reads or hashes the key.
5. A control is changed only with its proof: weaken the control in a copy, see the
   named assertion in `verify.yml` fail, restore it, see it pass.
