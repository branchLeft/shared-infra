# demo1_build

This role builds the demo host's slots on demo1: it stages the demo-host
provisioning programs from `branchLeft/ghost-platform` at a pinned commit,
installs the three that something else runs, and declares everything the runbook's
Phase A (`demo1-host-build-and-broker-runbook.md` in ghost-platform-docs, steps
A-1 to A-12) used to do by hand, as far as it can be done without the owner. It
reads what the `broker_deploy` role leaves behind and never writes it.

This README is self-contained and is written for a maintainer new to the
repository. It follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role is a host build for seven slots, each a pair of colours (`a`, `b`).
Every slot has its own uid (30001 and up), a socket directory the health router
serves from, two colour units and two drain flags. One account, `demo-router`
(uid and gid 30008), runs the health routers.

What the role does, in the order of `tasks/main.yml`:

1. **Checks its inputs** (`_inputs.yml`): the pinned commit is a full sha, every
   program has a 64-digit sha256, the slot table is digits and not repeated, and
   the wrapper path is an absolute path with no dot segment, doubled slash or
   trailing slash.
2. **Checks what `broker_deploy` left** (`_preconditions.yml`), read-only: the
   `broker` account exists; `/etc/branchleft`, `/var/lib/branchleft`, `/usr/local`,
   `/usr/local/sbin`, `/usr/local/lib` and `/opt` are root-owned directories that
   are not links and not writable by group or others (root runs programs from
   them); the broker's slots directory is `broker:broker` `0755`; and, when
   `broker.env` exists, it holds exactly one drain-flag line,
   `BROKER_DRAIN_FLAG_DIR=/var/lib/branchleft-broker/drain-flags`.
3. **Stages the programs** (`_release.yml`): ten programs, each fetched on its own
   with `get_url` from `raw.githubusercontent.com` at the pinned commit and held to
   its pinned sha256, into `/opt/branchleft/demo-host/releases/<commit>/demo-host/provision/`
   (root, `0755` directories, `0644` files). `current` links to the release. The
   role then reads each file back and decides whether the release is whole.
4. **Compares the sudoers grant with the pinned generator** (`_sudoers_check.yml`),
   read-only, and before any program is installed, so a grant it refuses leaves
   the wrapper uninstalled by that run: the file is a regular file, `root:root`,
   `0440`, and passes `visudo -csf`; every rule runs exactly `demo1_build_wrapper_path`,
   the path step 5 installs the wrapper at, so a path the grant does not name is
   refused before anything is written there; every rule is one literal `NOPASSWD`
   line for the broker with no wildcard; the number of rules is what the slot table implies;
   the sorted rules equal the sorted output of the pinned `render_slot_sudoers.py`;
   and the slots in the generator's rules are the slots in the role's table. It
   needs only the staged release, so it follows step 3.
5. **Installs three programs where something else runs them** (`_programs.yml`):
   the slot wrapper at the path of the sudoers grant, and the drain sidecar and the
   health router in `/usr/local/lib/branchleft/` (root, `0755`), the paths the
   rendered units name. Before installing the sidecar it reads it and refuses a
   file that reads another drain-flag directory or names flags another way.
6. **Records the uid claims and makes the router's account** (`_accounts.yml`):
   see the next section.
7. **Declares the directories** (`_dirs.yml`): the router's socket tree, the
   broker's state directory, the drain-flag directory and, on a host with no flag
   at all, the fourteen flags a build starts drained.
8. **Writes the units** (`_units.yml`): the fourteen colour drop-ins and the
   health router's template unit, from the pinned renderers' output; one systemd
   reload when any changed.
9. **Stages the edge candidate** (`_candidate.yml`): the edge's upstream snippets,
   rendered by the pinned edge renderer, into a root-only candidate directory.
10. **Reads back what root will run** (`_integrity.yml`): each installed program is
    the pinned file, `root:root`, mode `0755`, not a link, and every directory
    above it is root-owned and not writable by anyone else.

### What each Phase A step becomes

| Runbook step                                              | Becomes                                                                                                    | Where                                 |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| A-1 stage the scripts in a root-only directory            | RUN as a pinned release, kept (not removed)                                                                | `_release.yml`                        |
| A-2 install sudo and xz-utils                             | NOT ROLE: the role requires `visudo` and refuses without it; xz belongs to the Node step                   | `_sudoers_check.yml`                  |
| A-3 claim the uids                                        | RUN the pinned `demo_uid_claims.py`, only when a claim is missing                                          | `_accounts.yml`                       |
| A-4 the two accounts                                      | `demo-router` created here (create or assert, never `usermod`); `broker` is `broker_deploy`'s and asserted | `_accounts.yml`, `_preconditions.yml` |
| A-5 wrapper, then the sudoers boundary                    | wrapper INSTALL; the boundary is `broker_deploy`'s and is compared, never written                          | `_programs.yml`, `_sudoers_check.yml` |
| A-6 read the boundary back                                | the assertions of the sudoers check                                                                        | `_sudoers_check.yml`                  |
| A-7 compose template and drop-ins                         | the fourteen drop-ins are written; the compose template unit is not (named gap)                            | `_units.yml`                          |
| A-8 health routers                                        | the template unit is written and systemd reloaded; no router is enabled or started                         | `_units.yml`                          |
| A-9, A-9b drain-flag directory                            | declared with modules; flags pre-seeded only on a host with none                                           | `_dirs.yml`                           |
| A-10 the seven slot directories, by the wrapper's `reset` | NOT ROLE: `reset` wipes and recreates a tenancy and is the owner's to run                                  | none                                  |
| A-11 remove the staging directory                         | retired: the release is the staging and is kept                                                            | none                                  |
| A-12 evidence                                             | the Molecule `verify.yml` and the harness                                                                  | `molecule/default`                    |

### What each pinned program becomes

| Program                                         | Role                     | Notes                                                                |
| ----------------------------------------------- | ------------------------ | -------------------------------------------------------------------- |
| `branchleft_slot.py`                            | INSTALL                  | The wrapper. Installed, never run.                                   |
| `demo_sidecar.py`                               | INSTALL                  | Run by the colour drop-ins, never by the role.                       |
| `health_router.py`                              | INSTALL                  | Run by the router unit, never by the role.                           |
| `render_slot_sudoers.py`                        | RUN, stdout only         | Printed, not written: the comparison.                                |
| `render_colour_units.py`                        | RUN, stdout only         | The drop-ins' text.                                                  |
| `render_router_unit.py`                         | RUN, stdout only         | The router unit's text.                                              |
| `render_demo_edge.py`                           | RUN, stdout only         | The candidate fragment.                                              |
| `demo_uid_claims.py`                            | RUN, writes the register | Only when a claim is missing; never in check mode.                   |
| `render_demo_site.py`                           | STAGED                   | Part of the release the owner opens the demo from.                   |
| `demo_go_live.py`                               | STAGED, NOT ROLE         | The owner's go-live. The role never runs it.                         |
| `provision_socket_dirs.py`, `drain_flag_dir.py` | NOT FETCHED              | Their jobs are declared with `file` tasks, so a plan shows each one. |
| `branchleft_demo_egress.sh`                     | NOT ROLE                 | The egress ruleset; see the gaps.                                    |

"RUN, stdout only" means the renderer is run with no output flag: it prints to
standard output and writes nothing, so running it is a read and is the one
task allowed to run in check mode (ANS-10). Each such task runs with
`/usr/bin/python3 -E -s -B`, so no environment variable, user site or bytecode
file reaches the release.

### What the role does not do

- It does not write `/etc/sudoers.d/branchleft-slot` or create the `broker`
  account. `broker_deploy` owns both. A second writer of the grant is what the
  comparison and the Molecule control exist to catch.
- It does not apply `broker_deploy`, and it has no `dependencies` entry in
  `meta/main.yml` (ANS-12). `broker_deploy` is applied first, from the owner's
  inputs, and `demo1_build` refuses a host where it has not been.
- It does not write the live Caddyfile, run `demo_go_live.py`, or run
  `branchleft-slot reset`. Opening the demo is the owner's decision.
- It does not enable or start a health router or a colour unit.
- It does not fetch secrets. Anything secret on the host is a root-only file the
  owner puts there.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every variable and
[`defaults/main.yml`](defaults/main.yml) holds them. There is no required input and
no secret.

- `demo1_build_source_sha`: the ghost-platform commit the programs are fetched at.
- `demo1_build_source_base_url`: the raw URL at that commit (a test can point it at
  a copy).
- `demo1_build_release_files`: each program's path under the commit and its sha256.
- `demo1_build_slot_names`: the slot table, taken from `broker_deploy_slot_names`
  when that is set; the count of grant lines is derived from it.
- `demo1_build_wrapper_path`: taken from `broker_deploy_wrapper_path` when that is
  set; the role refuses to run unless every rule of the installed grant names exactly
  this path.

`vars/main.yml` holds the constants (paths, accounts, uids, patterns). A caller
cannot override them.

### The pin

The commit is `5e52f78427cab104438057164e4baa16b329875c`, which is at or after
`0a23634b652a37260d77e656ded3c37ff24d62ec`, the ghost-platform commit that moved the
drain flags out of the slot directory to
`/var/lib/branchleft-broker/drain-flags`. A pin older than that commit puts flags
where the broker does not look; the role refuses a sidecar that does so.

Two values must agree: the commit and the checksums. The role fetches each file
by its commit, so a changed commit with the old checksums fails at the download of
the first file that differs, and so does a changed checksum. The check runs at the
real download; CI runs it on every pull request, because the Molecule scenario
fetches the real files from `raw.githubusercontent.com` (below). To change the pin,
change the commit, compute each checksum with
`git show <commit>:<path> | shasum -a 256` in ghost-platform, and change
`defaults/main.yml` and `meta/argument_specs.yml` together.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 with Python 3 (`/usr/bin/python3`), systemd, and `sudo` (for
  `visudo`). The role runs as root.
- `broker_deploy` applied on the host first.
- Network from the host to `raw.githubusercontent.com` on a real apply.

## What it changes on a host

- `/opt/branchleft`, `/opt/branchleft/demo-host`, `releases/`, the release directory
  and its two subdirectories: `root:root` `0755`. The ten programs in
  `.../demo-host/provision/`: `root:root` `0644`. The link `current` to the release.
- `/usr/local/lib/branchleft/` (`root:root` `0755`) holding the sidecar and the
  health router (`root:root` `0755`), and the wrapper at `demo1_build_wrapper_path`
  (`root:root` `0755`).
- The uid register `/etc/branchleft/tenant-uids/`: one claim file per slot,
  `demo-<n>` with `slug=demo-<n>` and `uid=3000<n+1>`, and `demo-router` with uid 30008. Each `root` `0600`. The directory is `root` `0700`; the role refuses any
  other mode and never changes it.
- The `demo-router` group and account at 30008 (`/usr/sbin/nologin`, no home),
  only when the account does not exist. An existing account is checked against
  the same uid, gid, shell and group and is never modified.
- `/var/lib/branchleft/demo-router/` (`root:root` `0755`) and, under it, one
  directory per slot and one per colour (uid and gid 30008, `0700`).
- `/var/lib/branchleft-broker` (`broker:broker` `0750`) and its `drain-flags`
  directory (`broker:broker` `0755`). On a host whose flag directory holds no
  `*.drain` file, fourteen empty flags (`root` `0644`), one per slot and colour.
- `/etc/systemd/system/branchleft-compose@demo-<n>-<colour>.service.d/colour.conf`
  (`root:root` `0644`) for each slot and colour, and
  `branchleft-health-router@.service`; one systemd reload when any changed.
- `/var/lib/branchleft/demo-candidates/` (`root` `0700`) holding
  `edge-upstreams.caddy` (`root` `0600`).

### Drain flags

A flag's presence means the colour is drained, and the broker clears a flag by
deleting it when a colour goes live. So the role writes flags only into a directory
that holds none, and never recreates a flag after the broker removed it: putting one
back would drain a colour that is serving traffic. A directory with at least one
`*.drain` file is left alone, even if some of the fourteen are absent.

### The uid register

The register is written only by the pinned `demo_uid_claims.py`, which locks the
directory and writes each claim crash-safely. The program has no dry-run flag, so it
is not run in check mode. The role decides first, by reading, whether any of the
eight claims is missing; it runs the program only then. Before running it, the role
reads `/etc/passwd` and refuses to claim a uid that an account already has, and it
refuses a claim file that holds another uid. The program is consumed as it is: it
takes no lock against a concurrent tenant allocation, which is a known gap in
ghost-platform and is not fixed here.

## Check mode

A plan makes no change on the host. Every program the role runs in check mode only
prints, and every program that writes is skipped there with its reason stated at
the task. In order:

| Task                                                     | In check mode                                                                                                                                                |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Reads (`stat`, `slurp`, `getent`, `find`, `visudo -csf`) | Run.                                                                                                                                                         |
| Pinned renderers (stdout only)                           | Run with `check_mode: false`, only on a host that has the release; otherwise skipped, because there is no release to run.                                    |
| Directories, links, accounts, files, units               | Modules report what would change.                                                                                                                            |
| `get_url` of the programs                                | Run where the release directory exists (nothing to do); skipped where the directory does not exist, because `get_url` cannot write into a missing directory. |
| Colour drop-ins and edge candidate                       | Skipped where their directories do not exist yet, for the same reason.                                                                                       |
| `demo_uid_claims.py`                                     | Never run.                                                                                                                                                   |
| Drain-flag pre-seed                                      | Never run.                                                                                                                                                   |
| Integrity read-back                                      | Not run: it reads the result of a real run.                                                                                                                  |

The Molecule `converge.yml` runs the role in check mode and compares a list of
watched paths before and after: a path that did not exist must still not exist and
one that did must have the same modification time. That control holds on a fresh
host and on a configured one.

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes (Docker running locally, Python 3.12 or later):

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/demo1_build
```

The scenario runs the role on one systemd container (the same Debian 13 image and
settings as `broker_deploy`; the reason for each key is in `molecule.yml`, including
the host cgroup namespace, which is the stated exception). It takes about six
minutes.

### What runs for real

- `prepare.yml` renders `broker_deploy`'s own sudoers template and `broker.env`
  template with its own defaults and installs them. The role is therefore tested
  against the real component's output, and not against a fixture written to match.
- The real pinned programs are fetched from `raw.githubusercontent.com` and run:
  the renderers, the claim program and the checks of the sidecar's text. A pin that
  does not match fails the scenario. The scenario therefore needs the network, as
  the real apply does.
- The real `visudo` checks the grant, and systemd reads the units.

### What does not run for real

- The wrapper is installed and never run (it needs Docker and a slot). The sidecar
  and the health router are installed and never started.
- No colour unit and no router is enabled or started.
- Docker, Caddy and the tenant images are absent.

### What `converge.yml` proves

- A check run changes nothing on the host (above).
- The role leaves the sudoers grant and the broker's slots directory exactly as it
  found them: same checksum, same modification time, same entries.
- A drain flag the broker cleared is not put back by a later run.
- A pinned checksum with one digit changed stops the role at the download, naming
  the checksum.

### What `verify.yml` checks

The expected owners, modes, numbers and paths are written out in the file, not
read from the role's variables, so a role that produced a wrong value fails
instead of agreeing with itself. The one value read from the role is each program's
pinned checksum, which is the pin. It checks the release (files, owners, modes, no
bytecode, `current`), the three installed programs, the register and its eight
claims, the router's account, the socket tree, the state and flag directories and
the thirteen flags that remain, the fourteen drop-ins and the router unit, systemd
loading the router unit without enabling it, the candidate directory and file, and
the absences: no `Caddyfile` anywhere, no slot directory a `reset` would make, no
wrapper lock directory.

### What breaks which step

One row per edit, with the Molecule steps run over the role and a restore afterwards.
The retrieval is the run itself.

| Edit                                                       | Step that fails    | Assertion that names it                                                                                                                         |
| ---------------------------------------------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| A task that writes a different valid sudoers file          | `converge`         | "The role wrote the sudoers grant."                                                                                                             |
| A line of the host's grant replaced by another valid line  | `converge`         | "The installed sudoers grant is not what render_slot_sudoers.py renders."                                                                       |
| A line of the host's grant removed                         | `converge`         | "The installed sudoers grant holds N rules; the slot table of 7 slots expects 50."                                                              |
| The wrapper-path assertion of `_sudoers_check.yml` removed | `converge`         | the case for a path the grant does not name: "The role accepted a wrapper path that the sudoers grant does not name."                           |
| `_programs.yml` run before `_sudoers_check.yml`            | `converge`         | "The role installed the wrapper at /usr/local/sbin/branchleft-slot and then refused the sudoers grant."                                         |
| The wildcard assertion of `_sudoers_check.yml` removed     | `converge`         | the case for a wildcard rule: "The role failed on the line ... for a reason other than holds a line that is not a single literal NOPASSWD rule" |
| The dot-segment condition of `_inputs.yml` removed         | `converge`         | the case for a dotted wrapper path: "for a reason other than The wrapper path must be an absolute path"                                         |
| The socket directory mode changed                          | `verify`           | "The router's socket tree is not root's 0755 at the top and the router's 0700 below."                                                           |
| The drain-flag directory's owner changed to root           | `verify`           | "The broker's state directory is not broker:broker 0750, or the drain-flag directory is not broker:broker 0755."                                |
| The candidate written as a `Caddyfile`                     | `verify`           | "A Caddyfile exists, a slot directory exists, or the wrapper's lock directory exists."                                                          |
| The real wrapper's `reset` run by a task                   | `verify`           | the same assertion (the real wrapper leaves its lock directory)                                                                                 |
| An eighth slot added to the role's slot table              | `converge`         | "The installed sudoers grant holds 50 rules; the slot table of 8 slots expects 57."                                                             |
| The register directory made `0755` on the host             | `converge`         | "is not a directory owned by root with mode 0700."                                                                                              |
| The wrapper installed group-writable                       | `converge`         | the integrity assertion on the installed programs                                                                                               |
| One digit of a pin flipped                                 | `converge`         | "did not match" at the download                                                                                                                 |
| The claim program run in check mode                        | `converge` (check) | "The check run changed"                                                                                                                         |
| A file added to the broker's slots directory               | `converge`         | "The role changed the broker's slots directory"                                                                                                 |
| The pre-seed guard removed                                 | `converge`         | "The role put a cleared drain flag back."                                                                                                       |

### Named limits

- **The sidecar is not run.** It needs an image environment file that this role
  does not deliver; see the gaps. The test proves the text and the paths, not that
  a colour starts.
- **A silent skip passes.** Tasks skipped in check mode on a host with no release
  are not caught by the harness; this table and the comments at each skip are the
  review of it (ANS-10).
- **The mode at the instant of writing** of a file is a property of Ansible's
  temporary file and atomic move, not of anything the test observes.
- **A release directory is never removed.** Old releases stay.
- **A run killed after a unit file is written and before the systemd reload** leaves
  the new file unread by systemd. The next run finds nothing changed and does not
  reload, so the file is read at the next reload from any source (another role, a
  boot). Every file is written atomically, so none is ever half-written.
- Python unit tests, if any are added under `roles/*/tests`, are not run by CI.
  The Molecule scenario carries the controls.
- CI runs this scenario: the Ansible workflow runs the harness over every
  directory under `ansible/roles/`.

## Gaps the role names and does not close

- **The sidecar's image environment file has no delivery path.**
  `/etc/branchleft/demo-sidecar.image.env` is not written by this role or by
  `broker_deploy`. The colour units and drop-ins are installed, but no colour starts
  until the owner places the file.
- **No router is enabled or started.** The template unit is installed and systemd is
  reloaded; starting is the owner's step.
- **The compose template unit is not installed.** The drop-ins extend
  `branchleft-compose@`; the template they extend is delivered elsewhere.
- **The slot directories `/opt/branchleft/demo-<n>`** are made by the wrapper's
  `reset`, which this role never runs. They do not exist after the role.
- **The egress interaction is unverified.** The demo host's egress ruleset
  (`branchleft_demo_egress.sh`, ghost-platform) is not applied here, and the merged
  `egress_nat` role inserts NAT rules on the forward chain. Their interaction has
  not been checked, so the first converge of demo1 waits for that check.
- **The uid register has no lock** against a concurrent tenant allocation.
  The role consumes it as it is.
- **The first apply's expected difference** from the host as the runbook left it at
  its pinned commit (`fb2f064`): the sidecar and the health router are replaced by the
  pinned versions (the drain-flag path fix); everything else the role declares
  already matches. A running health router keeps the old code until the owner
  restarts it.
- **Ticket order.** The ticket for the demo-host work after this one lists this build
  as a dependency while `broker_deploy` (its real prerequisite) is merged: the
  recorded graph is inverted. The build order in this README is the correct one.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after the
approval of its protected environment. The plan job shows the host's diff in check
mode first. Nothing is applied from a laptop. This role is not applied to any host
yet: the host's enrolment (inventory entry, trigger and nightly drift check) is a
separate piece of work and is not in this role or in `ansible/playbooks/demo1.yml`.
The first live run is check mode; the apply waits on the owner.

The playbook `ansible/playbooks/demo1.yml` refuses any host but demo1. It does not
apply `broker_deploy`, whose inputs are the owner's built bundle and public key.
The trap of a `dependencies` entry (a role applied before its own inputs exist) is
therefore not reachable from this role.

## How to change it safely

1. To change the release, change `demo1_build_source_sha` and every checksum in
   `demo1_build_release_files` together, in `defaults/main.yml` and in
   `meta/argument_specs.yml`. A checksum that does not match fails the download.
2. Keep every task able to run under `--check --diff`. A task that writes a file a
   program owns is skipped in check mode with a stated reason; a task that only reads
   may use `check_mode: false`.
3. A task that writes anything `broker_deploy` owns is wrong: the sudoers grant, the
   `broker` account, the state root and the broker's slots directory are read only.
4. Never run `reset`, the go-live program or a renderer with an output flag from a
   task. A renderer prints to standard output; keep it that way.
5. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
6. Run the test command above before opening a pull request, then break the control
   you touched and see the step fail.
