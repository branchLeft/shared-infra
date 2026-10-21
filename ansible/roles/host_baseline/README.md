# host_baseline

This role is the baseline every container host needs, in three parts that run in
this order: a key-only sshd, unattended upgrades with fail2ban, and Docker CE.
It replaces three provisioning scripts, one for each part, and keeps their
files, modes, owners and order.

This README is written for a maintainer who is new to the repository. It
follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

1. **sshd.** It checks that sshd's configuration is valid, writes the drop-in
   `/etc/ssh/sshd_config.d/01-branchleft-hardening.conf` (password and
   keyboard-interactive logins off, root key-only, public keys on), checks the
   whole configuration again, reloads sshd, and reads the resolved settings back
   with `sshd -T`. It refuses to reload sshd when either check fails, and fails
   when another drop-in outranks its own.
2. **Updates and fail2ban.** It installs `unattended-upgrades`, `apt-listchanges`
   and `fail2ban` when one is missing, turns on the daily index refresh and
   unattended upgrade, adds Docker's origin to the unattended-upgrades origins,
   writes the one jail (`sshd`), reloads fail2ban when the jail file changed, and
   enables and starts both services.
3. **Docker.** It delivers Docker's apt signing key and source, installs
   `docker-ce`, `docker-ce-cli`, `containerd.io` and `docker-compose-plugin`
   when one is missing, and enables and starts Docker.

It does not set up host egress, install the deploy tooling, configure the
firewall or the NAT gateway, create users, or write any secret. Those belong to
other roles and tickets. It does not remove anything, and it does not pin a
Docker version (see "Why Docker is unpinned").

### How it relates to the patterns

The role copies, as the standard directs, the shapes of `files_and_units` (explicit
owner, group and mode on every file; a notify, a handler and a `flush_handlers`
before the next step reads the result) and `packages_and_downloads` (an apt
repository delivered as a key file and a source that names it, with the key
pinned by a sha256 the role checks before it writes anything). It does not call
them: a pattern is a recipe a service role copies and renames, and ANS-12 keeps
composition in playbooks. How it differs from the scripts, and why, is under
"Where it differs from the scripts".

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the interface and
[`defaults/main.yml`](defaults/main.yml) holds its defaults. There are no inputs:
every value the role writes is the same on every container host. None of the
role's values is a secret and the role handles no secret.

`vars/main.yml` holds the constants of the baseline: the settings sshd must
resolve to, the package names, the pinned digest and fingerprint of Docker's key,
and the table of apt architecture names. A caller cannot change them with an
inventory variable.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 on `x86_64` or `aarch64`, with Python 3 and `python3-apt`
  (the `apt` and `package_facts` modules need it), systemd, and `openssh-server`
  installed with `/etc/ssh/sshd_config` including `/etc/ssh/sshd_config.d/*.conf`
  (Debian's stock file does). The role runs as root. Another machine type stops
  the role at a stated task.
- Network access to the Debian mirrors and `download.docker.com`, only on a host
  where a package is missing. A host that has every package makes no apt call.
- The key file comes from this repository: `files/docker.asc` is a link (below),
  so the role must be run from a checkout of the whole repository, which is what
  the gated pull delivers (ANS-17).

## What it changes on a host

| Path                                                  | Kind      | Owner:group | Mode   |
| ----------------------------------------------------- | --------- | ----------- | ------ |
| `/etc/ssh/sshd_config.d/01-branchleft-hardening.conf` | file      | root:root   | `0644` |
| `/etc/apt/apt.conf.d/20auto-upgrades`                 | file      | root:root   | `0644` |
| `/etc/apt/apt.conf.d/51branchleft-unattended-origins` | file      | root:root   | `0644` |
| `/etc/fail2ban/jail.local`                            | file      | root:root   | `0644` |
| `/etc/apt/keyrings`                                   | directory | root:root   | `0755` |
| `/etc/apt/keyrings/docker.asc`                        | file      | root:root   | `0644` |
| `/etc/apt/sources.list.d/docker.list`                 | file      | root:root   | `0644` |

- Packages installed when missing: `unattended-upgrades`, `apt-listchanges`,
  `fail2ban`, `docker-ce`, `docker-ce-cli`, `containerd.io`,
  `docker-compose-plugin`.
- Services enabled and started: `unattended-upgrades`, `fail2ban`, `docker`.
- sshd and fail2ban are reloaded, each only when its file changed.
- No port, no user and no firewall rule is created.

The sshd drop-in is named `01-`, not `99-`, on purpose: OpenSSH takes the first
value it finds for a keyword, and the `Include` expands in glob order, so the
lowest-sorting drop-in wins. A `99-` file would lose to `50-cloud-init.conf`,
which cloud-init writes whenever `ssh_pwauth` is set, and would restore password
logins while a check of this one file reported it up to date. Root stays
key-reachable on purpose: it is the provisioning identity, and the other recovery
path is the Hetzner console.

### One home for every file

The content of each configuration file is the content of the script heredoc it
came from, byte for byte, so adopting the role on a host the scripts already set
up reports no change for them. The key file reports a change if the key Docker
served to the script differs byte for byte from the pinned one. `files/docker.asc` is a link to
`hetzner/provision/fixtures/docker-apt-key.asc` (relative), the file the key's tests already read, so there is one copy of the
key. When the Docker script and its tests are retired, that file moves into this
role's `files/` and the link is replaced by it.

### Why Docker is unpinned

Docker's version is unpinned deliberately. That is only defensible because the
second part adds Docker's origin to the unattended-upgrades origins: without it
the repository is outside Debian's security origins and the runtime under every
tenant would freeze at whatever version first provisioning installed. An
unattended `docker-ce` upgrade restarts the daemon: containers carry
`restart: unless-stopped` and come back, but a stack mid-request loses it.

## Where it differs from the scripts

| Script behaviour                                                                                                                                | Role behaviour                                                                                                                                                             | Why                                                                                                                                                                                                                                                                                                                                                     |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fetches Docker's key from `download.docker.com` on every run and checks that the file holds exactly one key with the pinned primary fingerprint | Ships the key as a file and checks its sha256 before writing anything                                                                                                      | This is the recipe the merged `packages_and_downloads` pattern gives, and its scan refuses a download with no checksum. The cost: a refreshed key (same primary key, new subkey or expiry) is not picked up until the file, the digest and the fingerprint are changed in a pull request. The failure is loud (apt refuses the repository), not silent. |
| The fingerprint is checked on the host with `gpg` on every run                                                                                  | The fingerprint is checked by the test, on the machine that runs it; the host checks the digest                                                                            | The digest pins the exact bytes, which is stronger than the primary fingerprint, and the host needs no `gpg`. The test still requires exactly one key with the pinned fingerprint.                                                                                                                                                                      |
| `sshd -t` after the drop-in is written, then reload                                                                                             | `sshd -t` before the drop-in is written as well, the new file is checked alone before it replaces anything, and the whole configuration is checked again before the reload | A configuration another file had broken would otherwise leave the new drop-in in place: the next run would find it unchanged, queue no reload, and sshd would keep running the old settings.                                                                                                                                                            |
| `systemctl reload ssh` on every run                                                                                                             | Reload only when the drop-in changed                                                                                                                                       | An unconditional reload is reported as a change on every run, and the second run must report none. The ordering above makes sure a change is never left without its reload.                                                                                                                                                                             |
| `apt-get update` and install when a package is missing                                                                                          | The same, decided from the installed-package list read once at the start                                                                                                   | Same behaviour as `dpkg -s`; a host that has every package makes no apt call, so the drift run needs no network.                                                                                                                                                                                                                                        |
| A new apt drop-in is written, then `apt-config dump` parses all of apt's configuration, and the file is removed when apt rejects it             | The new file is parsed with `apt-config -c` before it replaces anything                                                                                                    | Same end state (a rejected file is never in place), reached without ever having the bad file on the host.                                                                                                                                                                                                                                               |
| `systemctl enable --now ... \|\| true` and `systemctl reload fail2ban \|\| systemctl restart fail2ban`                                          | Enable and start fail, and the reload fails, instead of being ignored or replaced by a restart                                                                             | A baseline that cannot start its services should say so. If a reload ever fails on a real host, change the handler on purpose.                                                                                                                                                                                                                          |
| Prints `docker --version` at the end                                                                                                            | Not carried                                                                                                                                                                | It changed nothing and recorded nothing.                                                                                                                                                                                                                                                                                                                |
| The architecture comes from `dpkg --print-architecture`, the codename from `/etc/os-release`                                                    | Both come from the host's facts (`architecture`, `distribution_release`)                                                                                                   | A fact is a module result, not a command (ANS-9). A machine type the table does not name stops the role.                                                                                                                                                                                                                                                |

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes (Docker running locally, Python 3.12 or later; `gpg` on the machine,
which the key check uses):

```text
python3 -m venv .venv
# Install the lock with the one recipe: ansible/README.md, "Install, and install with no network".
.venv/bin/python ansible/harness/run_harness.py ansible/roles/host_baseline
```

The harness lints the role and runs the scenario in `molecule/default/` on one
systemd container (the same Debian 13 image and settings as the `files_and_units`
pattern; the reason for each platform key is in `molecule.yml`). It removes its
container when it finishes and never touches a host.

The test image has no sshd, none of the packages and no network use, so
`prepare.yml` puts stand-ins in place, all marked PLACEHOLDER:

- a package of each name the role installs, built in the container with
  `dpkg-deb` and installed from the local file, so the role finds every package
  installed and makes no apt call;
- a unit for `ssh`, `unattended-upgrades`, `fail2ban` and `docker`; `ssh` and
  `fail2ban` count their reloads in a file;
- `sshd`, a script (`files/sshd_standin.sh`) that models only what the role
  depends on: `-t` fails on a keyword outside a closed set, `-T` prints the
  resolved settings, the first value for a keyword wins, `Include` expands in
  glob order, and `permitrootlogin prohibit-password` prints as
  `without-password`, as Debian 13's sshd prints it;
- a `50-cloud-init.conf` that allows passwords, as cloud-init writes it.

What each part of the scenario does:

- `check-fresh`, `check-configured` and `molecule-check`: the role runs under
  `--check --diff` before the first apply and against the configured instance and
  shows no drift.
- `converge`, then `idempotence`: a second converge reports zero changed tasks.
- `verify.yml` asserts, from the instance and with the expected contents written
  out in the test (not read from the role):
  every file is a regular file owned by root with mode `0644` and holds exactly
  the required content; the key is the pinned file in a `0755` directory; the
  resolved sshd settings are the hardened ones although the `50-cloud-init.conf`
  sibling allows passwords; the three services are enabled and running; sshd and
  fail2ban were each reloaded exactly once, by the first converge and not the
  second; and, with `gpg` on the machine that runs the test, the key file holds
  exactly one key with the pinned primary fingerprint.
- It then runs four refusal cases. Each sets up one fault, applies the role,
  requires the role to stop at one named task, and undoes the fault:
  1. another drop-in has broken the sshd configuration while the role's own file
     is out of date: the role stops at the first check, leaves its file as it
     was, and does not reload sshd;
  2. a sibling that sorts first sets `PasswordAuthentication yes`: the role stops
     at the read-back and says which setting differs;
  3. the host holds a stale key and the role is given a wrong digest: the role
     refuses the digest and the stale key is still there;
  4. the table of apt architecture names is empty: the role stops at the
     architecture check.

### What breaks which step

Each row is one edit to the role, one harness run, and a restore with a clean
tree afterwards. The harness run is the retrieval: make the row's edit and run it
to see the message.

| Edit to the role                                                            | Harness step that goes red | The message                                                                                                                                      |
| --------------------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Remove the first `sshd -t` (before the drop-in)                             | `verify`                   | Expected the role to stop at the first check; it stopped at the check before the reload.                                                         |
| Remove both `sshd -t` checks                                                | `verify`                   | Expected the role to stop at the first check; it stopped at "Read the sshd settings the configuration resolves to". Does not isolate the second. |
| Name the drop-in `99-` instead of `01-`                                     | `converge`                 | effective passwordauthentication is 'yes', expected 'no': another drop-in outranks the role's file.                                              |
| Remove the Docker key digest assertion                                      | `verify`                   | Expected the role to stop at the digest check; it stopped at "NOTHING: the role accepted it".                                                    |
| Drop the `without-password` to `prohibit-password` mapping in the read-back | `converge`                 | effective permitrootlogin is 'without-password', expected 'prohibit-password'.                                                                   |
| Remove `notify: Reload sshd` from the drop-in task                          | `verify`                   | ssh was not reloaded exactly once (0 times).                                                                                                     |
| Break the quote in the unattended-upgrades origins file                     | `converge`                 | failed to validate: Syntax error: Malformed tag.                                                                                                 |
| Remove the resolved-settings assertion                                      | `verify`                   | Expected the role to stop at the read-back; it stopped at "NOTHING: the role accepted it".                                                       |
| Remove the architecture-name assertion                                      | `verify`                   | the role stopped at "Work out the architecture name apt uses" instead of the architecture check.                                                 |
| Change one character of the pinned primary fingerprint in `vars/main.yml`   | `verify`                   | The key file does not hold exactly one key with the primary fingerprint ...EBFCD89.                                                              |

Reviewed or asserted, but not proven by a sabotage run (a control with no row
above is not shown to fail):

- the second `sshd -t` (before the reload): the first check, the validate of the
  new file and the role's own file cannot all pass and then fail here, so no
  test reaches it. It is kept because the script has it and it costs nothing;
- the mode `0755` of `/etc/apt/keyrings`, and `owner` and `group` of every file
  (the instance runs as root, so omitting them gives the same result);
- the `validate` of the sshd drop-in on its own (the role's file is a constant
  that is valid, so only an edit to it can fail the check);
- the always-changed variant of the idempotence step: the step is the harness's.

### Named limits

- **The path that installs a missing package is not run.** Every package is
  installed before the role runs, so no `apt` task runs and the index refresh,
  Docker's repository and the install itself are exercised only on a host. The
  first live apply is the proof (ANS-17).
- **The stand-ins are only as faithful as their list.** The test shows the role
  against a script that models first-value-wins and `Include` order, not against
  OpenSSH, and against units that run `/bin/true`, not against the real
  `fail2ban`, `unattended-upgrades` or `docker`. The effective-settings read-back
  and the drop-in name are proven against the model; that the model matches
  OpenSSH is from OpenSSH's documentation and the script's own comments.
- **A reload that sshd rejects is not run.** The stand-in's reload cannot fail.
- **A silent skip passes.** The enable and start of each service, and the
  read-back of the resolved sshd settings, are skipped in check mode when their
  package or drop-in is not on the host yet (ANS-10); the harness does not catch
  a silent skip, and review is what checks the stated reason. On a host that has
  them, they run in check mode.
- **A rotated Docker key is not picked up.** See "Where it differs".
- **A file removed from the repository stays on the host.** The role removes
  nothing, as the scripts did not.
- **CI runs this scenario.** The Ansible workflow runs the harness over every
  directory under `ansible/roles/`. The harness does not install `gpg`: the
  runner has it. The image is the third-party Debian 13 systemd base the
  `files_and_units` pattern records, trusted by digest; nothing here bumps it.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after
the approval of its protected environment. A plan job shows the host's diff in
check mode first; after the approval the host pulls that exact commit of `main`
and applies it, and a second run must report zero changes. Nothing is applied
from a laptop. This role is not applied to any host yet.

## How to change it safely

1. To change a setting, change the file under `files/` and the same lines in
   `molecule/default/verify.yml`, which holds the expected content separately.
   A change to one without the other fails `verify`.
2. To change Docker's key, change `files/docker.asc` (and the fixture it links
   to), `host_baseline_docker_key_sha256` and
   `host_baseline_docker_key_fingerprint` in `vars/main.yml` together. Read the
   fingerprint from the vendor's published value, not from the file. The test
   fails if the digest and the file disagree, or the file holds more than one key.
3. Keep every task able to run under `--check --diff`, and keep the modes
   explicit.
4. Do not move the sshd checks after the write, or the reload before them: the
   order is the control. The reload is a handler flushed after the checks.
5. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
6. Run the test command above before opening a pull request, then break the
   control you touched (the table above) and see the same step fail.
