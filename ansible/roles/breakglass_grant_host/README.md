# breakglass_grant_host

Installs on an application host the break-glass grant tool, its root-only
wrapper and the unit and timer that close expired grants, and pulls the image
they run in. It never opens or closes a grant.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role makes the plain, repeatable state of the break-glass grant side on an
application host (`app1`):

1. Refuses an input that is not a full 40-character commit, or a constant that is
   not an image pinned by digest, before anything is touched.
2. Refuses a host with no working `/usr/bin/docker` (the binary the expire unit
   runs) or no Docker socket. Every Docker command of the role names that path, so
   a `docker` elsewhere on the PATH, a snap install for example, does not pass.
3. Makes the directories above the tool, the grant records and the log, each with
   an owner and a mode.
4. Probes for the Node image under its digest and pulls it only when the host
   lacks it, then reads the digest back and refuses if it is not there.
5. Downloads six files from the pinned commit of the `ghost-platform` repository,
   each held to its sha256: three programs, the root-only wrapper
   `/usr/local/sbin/branchleft-break-glass`, and the expire unit and timer.
6. Loads the changed units into systemd, then enables and starts the timer.

The order matters. The expire unit starts the image with `--pull never`, so a host
without the image would fail the unit every minute and no grant would ever close.
The image is therefore confirmed before the files, and the timer is enabled last.

It does not mint a token, open a grant, close a grant, run the wrapper, set a
secret, or create the minting key: that belongs to `breakglass_mint_host` on the
control host and to the owner. It does not install Docker. The tool is only ever
run by a person at the host, as root; the timer runs only the expire command.

## Interface

The variable, its type and default are in `meta/argument_specs.yml`; the same
default is in `defaults/main.yml`. Ansible checks it when the role starts.

| Variable                              | Meaning                                                            |
| ------------------------------------- | ------------------------------------------------------------------ |
| `breakglass_grant_host_source_commit` | The full commit of `ghost-platform` the files are downloaded from. |

It must be the same as the same-named input of `breakglass_mint_host`: the
minter and the grant tool are two halves of one protocol and must come from one
commit. The test of each role reads the other's defaults and fails if they
differ. The Node image is not an input. It is a constant in `vars/main.yml`, set
together with the file hashes, because the wrapper and the expire unit this role
installs carry their own copy of its digest and run it with `--pull never`: an
inventory value that named another image would be pulled and read back green while
the unit failed every minute. The test of each role compares the two roles'
constants, and runs the shipped wrapper and unit with this role's constant. The
sha256 of each file, the download base, the paths and the Docker socket are
constants in `vars/main.yml` too. No variable is a secret.

Neither an inventory value nor a playbook value may change those constants. The
check that enforces it is the playbook guard, `ansible/harness/playbook_guard.yml`,
which the role's test includes for `playbooks/app1.yml`. It requires the play keys
to be on an allow-list, the `roles` entry to be exactly this role with no other key,
and every task of the playbook to call a module on the allow-list (so a `set_fact`
or an `include_vars` that sets a constant is refused), and it scans the playbook's
text for `lookup`, `query`, `q` and `pipe`. Play-level `vars` and `vars_files` are
refused as keys. Extra vars on the pull command line are not read by this check
and are outside it: they are held by the gated pull's approval (ws#2483).

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version.
- No collections beyond `ansible.builtin`.
- Target system: Debian 13 with systemd, with `docker` installed and its socket at
  `/var/run/docker.sock`, and network access to `raw.githubusercontent.com` and to
  the image registry on the first apply.

## What it changes on a host

| Path                                                        | Owner | Mode | What                                                 |
| ----------------------------------------------------------- | ----- | ---- | ---------------------------------------------------- |
| `/usr/local/lib/branchleft`                                 | root  | 0755 | Shared parent, also made by other roles.             |
| `/usr/local/lib/branchleft/break-glass`                     | root  | 0755 | The tool directory.                                  |
| `.../break-glass/break-glass-grant.mjs`                     | root  | 0644 | The grant tool.                                      |
| `.../break-glass/docker-engine.mjs`                         | root  | 0644 | Its Docker client.                                   |
| `.../break-glass/provision-support-account.mjs`             | root  | 0644 | Its account helper.                                  |
| `/usr/local/sbin/branchleft-break-glass`                    | root  | 0700 | The wrapper. Root-only: an operator runs it as root. |
| `/etc/systemd/system/branchleft-break-glass-expire.service` | root  | 0644 | The expire unit.                                     |
| `/etc/systemd/system/branchleft-break-glass-expire.timer`   | root  | 0644 | The timer, enabled and started.                      |
| `/var/lib/branchleft`                                       | root  | 0755 | Shared parent, also made by other roles.             |
| `/var/lib/branchleft/break-glass-grants`                    | root  | 0700 | Where the grant records are kept.                    |
| `/var/log/branchleft`                                       | root  | 0700 | Shared parent, also made by other roles.             |
| The Node image, in Docker's store                           | n/a   | n/a  | Pulled by digest when absent.                        |

Besides these the role reloads the systemd manager when a unit file changed, and
enables and starts the timer.

## Refusals leave the host untouched

Each of these stops the run at the named task, before any later task writes
anything, and leaves the timer not enabled. The test converge applies the role in
each state and asserts which task stopped it and that nothing was written.

- An input that is not a full commit, or a constant that is not a digest-pinned image.
- No `docker` at `/usr/bin/docker` on the host, including a host whose only
  `docker` is elsewhere on the PATH.
- No Docker socket, or a path that is not a socket.
- A pull that exits 0 and leaves the digest absent (the read-back refuses).

## Taking over by hand

The role is the way this host is set up. The one-off steps and anything that holds
a secret stay as written in the break-glass runbook, run by the owner at the host.
Until the first apply of this role on the host is cited, the runbook's hand steps
for the files, the image and the timer stay as the fallback; after that, use the
digest in this role's `vars/main.yml`, not a copy of it.

## Named limits

- **The test stands in for Docker.** A small program takes the place of the
  `docker` command (`molecule/default/files/docker_standin.sh`, the one home of the
  stand-in; the mint role's test copies it from here). The test proves what the
  role and the shipped wrapper asked Docker to do. The wrapper's whole argument
  list, and the unit's, is compared with a list written out in the test from the
  intent: `--pull never`, `--network none`, `--read-only`, `--cap-drop ALL`, the
  resource limits, the label, the pinned image and exactly the four expected mounts,
  and nothing else, so an added `--privileged`, `-v`, `--device`, `--add-host` or
  second `--security-opt` fails. The unit's command also matches the wrapper's apart
  from the one environment pair. It does not prove that the image pulls from a real registry, or
  that the unit starts a real container. The gated run on the host is that proof.
- **The test runs the wrapper in `status` mode only.** The grant and close commands
  need a real Ghost and are never run by the test.
- **A systemd container.** The test needs a systemd platform to prove the timer is
  enabled and active. That platform is a third-party image trusted by digest. It
  runs with a cgroup mount, the host's cgroup namespace and a `tmpfs`, each stated
  and explained in `molecule.yml`, and no privileged mode.
- **`command` is used for `docker`.** The Docker modules need the Docker API
  library on the host, which these hosts do not carry (ANS-9). The probes are
  read-only and run in check mode; the pull runs only when a probe finds the digest
  absent.
- **Check mode.** The pull and its read-back are skipped in check mode when the
  digest is absent, because nothing was pulled. The downloads are skipped in check
  mode on a fresh host, where the tool directory does not exist yet. The timer task
  is skipped in check mode on a fresh host, where the unit file does not exist yet.
  Each skip is only for that reason.
- **One network dependency.** The first apply needs `raw.githubusercontent.com`
  and the registry. A failed download is a failed run, not a partial install: each
  file is held to its sha256.
- **Not a secret store.** Nothing here is a secret.

## How to test it

From the repository root, with the toolchain installed as `ansible/README.md`
describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/breakglass_grant_host
```

The harness runs the lint steps, then Molecule in a systemd container: create,
prepare, a check-mode pass on a fresh host, converge, idempotence, verify, a
check-mode pass on the configured host, and destroy. `converge.yml` applies every
refusal state first and then the role once. `verify.yml` checks:

- the two roles agree on the commit and the image;
- the download URL is at the pinned commit and each file holds its sha256;
- the role uses only the modules and `docker` arguments on its allow-list, with the
  exact task counts the design has, so a loop cannot be emptied unseen;
- the owner and mode of every path, written independently from the role's own
  table;
- one pull over two applies, by digest, never by tag;
- the wrapper's recorded `docker` command and the unit's, as in "Named limits";
- the timer is enabled and active, and still is after the wrapper and unit runs.

The playbook `ansible/playbooks/app1.yml` is a host-guarded playbook that lists
this role. The test runs it against a host name that is not `app1` and requires
it to refuse, and lists its tasks for `app1`.

## How it is delivered

A role reaches a host only through the gated pull (ANS-17), never by running
`ansible-playbook` by hand. `playbooks/app1.yml` is the playbook for the
application host. It is applied once the host is enrolled in the gated pull; until
then a merge of this role changes no host.

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together.
2. Bump the commit, every sha256 and the Node image in `vars/main.yml` together, and
   bump the same commit and image in `breakglass_mint_host` in the same pull request.
3. Keep every task able to run under `--check --diff`, and keep the role
   idempotent.
4. Never make the role run the grant tool or the wrapper's grant commands.
5. A control is changed only with its proof: weaken the control in a copy, see the
   named assertion in `verify.yml` fail, restore it, see it pass.
