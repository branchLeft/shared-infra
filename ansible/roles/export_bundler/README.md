# export_bundler

This role delivers the tenant export bundler to app1 as pinned files in a root-only directory, and makes the
export's state directories, without running anything.

This README is self-contained and is written for a maintainer new to the repository. It follows the order the
standard sets for a role README (ANS-14).

The bundler is `services/export-bundler` in `branchLeft/ghost-platform`. It is a small Node program that, inside a
support grant, calls a tenant's Ghost admin exports and writes one encrypted archive and a manifest. This role is
Part A of the export runbook (`tenant-export-runbook.md` in the private `ghost-platform-docs` repository, "Deliver
the bundler to app1") and the part of Part C that a role can declare (the state directories). Everything else in
the runbook stays with the owner; the last section lists it.

## What the role does, and what it does not

What the role does, in the order of `tasks/main.yml`:

1. **Checks its inputs** (`_inputs.yml`): the pinned commit is a full sha, every file has a 64-digit sha256, no file
   is listed twice, the only paths are `package.json` and files directly under `dist/`, and the two host paths are
   plain absolute paths that do not overlap.
2. **Holds the vendored bundler to its pins** (`_vendored.yml`), before anything is written to the host and before
   the host is read. Every file in the table is hashed on the machine that runs the role, and must exist, be a
   plain file with one link, and have its pinned sha256. The role also lists everything under its own `dist/` and
   refuses any file that no pin names. Either refusal stops the run and names the file.
3. **Delivers the bundler** (`_bundler.yml`). It looks at the bundler directory, its `dist/` and the state
   directories without following links, and refuses a link or a plain file where a directory belongs. Then it makes
   the bundler directory and `dist/` (`root:root`, `0700`), copies each pinned file (`root:root`, `0600`), removes
   anything under the host's `dist/` that the pins do not name, and writes `COMMIT`: the pinned ghost-platform
   commit and a newline, as the runbook wrote it.
4. **Makes the state directories** (`_state.yml`): the state directory and its `flags` and `out` directories,
   `root:root` `0700`. Nothing inside them is listed, changed or removed. The audit log, the token FIFO, the
   descriptors and the archives are made by the export and the owner, and are left exactly as they are.

What it does not do:

- It never runs `node`, the bundler, `docker` or `age`, and it does not install them. They are the host's baseline,
  and a failing prerequisite check would block a file copy. The runbook's read-only checks for them stay with the
  owner (below).
- It never reads, writes or names a descriptor, a break-glass token, a support grant, the audit log or an archive.
  It has no secret input.
- It does not open the support grant, mint a token or run the export.
- It does not install the storage gateway's keys. That is a different role that is not built yet (below).

Differences from the runbook's hand steps, all deliberate:

- The runbook's `mkdir -p -m 700 state/flags state/out` gives only `flags` and `out` mode `0700`; the state
  directory above them gets the shell's umask, normally `0755`. The role makes the state directory `0700` too.
- Files are `0600` and directories `0700`, because only root reads them. `scp -r` left them `0644` and `0755`.
- The runbook removed `dist` and copied a new one. The role copies each file and then removes what is no longer in
  the release, so there is no moment in which `dist` is missing, and a second run changes nothing.

## Interface

The variables the role reads, their types and defaults are in `meta/argument_specs.yml`. Ansible checks them when
the role starts and fails the role on a mismatch. `defaults/main.yml` holds the same defaults, and the table of
pinned files is the one home of the bundler's identity.

| Variable                       | Default                                        | What it is                                                      |
| ------------------------------ | ---------------------------------------------- | --------------------------------------------------------------- |
| `export_bundler_source_sha`    | the pinned ghost-platform commit               | Written to `COMMIT`. A bump changes it with the files and pins. |
| `export_bundler_release_files` | `package.json` and 22 files in `dist/`         | One path and one sha256 each. The role writes exactly these.    |
| `export_bundler_vendored_root` | `files/ghost-platform/services/export-bundler` | Where the copy is, where the role runs. Only tests change it.   |
| `export_bundler_dir`           | `/root/export-bundler`                         | The bundler on the host.                                        |
| `export_bundler_state_dir`     | `/root/export-bundler-state`                   | The export's state directory on the host.                       |

No variable of this role is a secret, and none is required. The host's play variables are pinned by the enrolment
check (R2), so a caller cannot override the table of pins on app1: the table can change only by a change to this
role, which the owner merges.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's `min_ansible_version` is that
  version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target systems: Linux with Python 3. The role is applied to app1, as root, under the gated pull.
- The machine that runs the role reads the vendored files there. Under the pull that is the host itself, from the
  signed commit it has checked out.

## What it changes on a host

| Path                                             | Owner and mode   | What                                                   |
| ------------------------------------------------ | ---------------- | ------------------------------------------------------ |
| `/root/export-bundler`                           | `root:root` 0700 | The bundler's directory.                               |
| `/root/export-bundler/package.json`              | `root:root` 0600 | Says the compiled files are ES modules.                |
| `/root/export-bundler/dist/*.js`                 | `root:root` 0600 | The 22 compiled files, each held to its pin.           |
| `/root/export-bundler/COMMIT`                    | `root:root` 0600 | The ghost-platform commit the files were built from.   |
| `/root/export-bundler-state`, `…/flags`, `…/out` | `root:root` 0700 | Where an export keeps its flags, output and audit log. |

It also removes any other file or directory under `/root/export-bundler/dist`. No service, port, user, package or
unit.

## Check mode

Check mode reports exactly (ANS-9, ANS-10). The pin checks and the link checks only read, so they run. On a host
that has not had the bundler, the `dist` directory does not exist yet, and `copy` refuses a destination whose
directory is missing, so the copies, the listing of `dist` and the `COMMIT` write are skipped there and the plan
shows the directories alone. On a host that has the directories, they run and report. The `plan` scenario proves
both: a check against a host with nothing on it, then a check after an apply, which must show nothing to change.

## Vendored files

The role's `files/ghost-platform/services/export-bundler/` is a built copy of `branchLeft/ghost-platform`
`services/export-bundler`: `package.json` and the 22 files tsc writes to `dist/`. The host takes them from the
signed commit; it never builds, fetches or installs anything. They are pinned by sha256 in
`defaults/main.yml`, and `export_bundler_source_sha` records the commit they came from.

**The pinned commit** is `5fb63577cb5850b351c964caa49c93a382516367`, the last ghost-platform commit that changed the
build inputs (`src/`, `pnpm-lock.yaml`, the tsconfig files, `package.json`). It is not the moving tip of `main`: a
later commit that does not touch those inputs produces the same bytes.

**To reproduce the files** (and for a reviewer to check them), from a clean detached worktree of that commit. The
repository converted from npm to pnpm in the pinned commit, so the runbook's old `npm ci` no longer applies. The
package manager is the one `package.json` names (`packageManager`: `pnpm@11.17.0`, from the corepack cache), the
Node is the one `.nvmrc` names (26.5.0), and no bare `pnpm`, `npm` or `npx` is used, because on the owner's
workstation those names are shell functions that read a registry token:

```text
git -C ghost-platform worktree add --detach ../export-bundler-build 5fb63577cb5850b351c964caa49c93a382516367
cd ../export-bundler-build/services/export-bundler
PATH=$HOME/.nvm/versions/node/v26.5.0/bin:$PATH NPM_CONFIG_USERCONFIG=/dev/null node $HOME/.cache/node/corepack/v1/pnpm/11.17.0/bin/pnpm.cjs install --prefer-offline --frozen-lockfile --ignore-scripts
PATH=$HOME/.nvm/versions/node/v26.5.0/bin:$PATH NPM_CONFIG_USERCONFIG=/dev/null node $HOME/.cache/node/corepack/v1/pnpm/11.17.0/bin/pnpm.cjs run build
PATH=$HOME/.nvm/versions/node/v26.5.0/bin:$PATH NPM_CONFIG_USERCONFIG=/dev/null node $HOME/.cache/node/corepack/v1/pnpm/11.17.0/bin/pnpm.cjs run typecheck
PATH=$HOME/.nvm/versions/node/v26.5.0/bin:$PATH NPM_CONFIG_USERCONFIG=/dev/null node $HOME/.cache/node/corepack/v1/pnpm/11.17.0/bin/pnpm.cjs run test:unit
```

Then compare: `shasum -a 256 package.json dist/*.js` against the table in `defaults/main.yml`, or
`diff -r dist <this role>/files/ghost-platform/services/export-bundler/dist`. At the pinned commit the build emits 22
files, the typecheck is clean, and all 406 unit tests pass in a full clean checkout.

Notes a reviewer needs:

- `@branchleft/tsconfig` is a development dependency from GitHub Packages, which refuses the agent App's token. The
  install above succeeds only when that package is already in the local pnpm store, which it is on a workstation
  that has installed this repository before. If the store lacks it, stop and report; do not look for a token. The
  other packages come from the public registry with no credential. `--ignore-scripts` means no package runs code on
  install.
- **Is tsc's output byte-stable?** Observed, on one toolchain only: macOS arm64, Node 26.5.0, TypeScript 5.9.3 from
  the lock. Two builds in one directory and one build in a second directory were identical under `diff -r`, `dist`
  holds no absolute path, and the files import only `node:` modules, so nothing is installed on the host. It is not
  proven on another operating system or toolchain, so the check that matters is the pin: the files in this role are
  what the pins say, whoever built them.
- Nothing rebuilds the files in CI. The control on a bump is the pins, the review class for
  `ansible/roles/*/files/ghost-platform/**` (the reviewer raises to the strongest model, and re-runs the commands
  above), and the owner's merge. A CI job that reproduces `dist` from the pinned commit would close this; it needs a
  GitHub Packages login for `@branchleft/tsconfig` and is filed as its own piece of work.

**To bump the bundler**, in one change: rebuild at the new commit with the commands above, replace everything under
`files/ghost-platform/services/export-bundler/`, and change `export_bundler_source_sha` and every checksum in
`export_bundler_release_files`, in `defaults/main.yml` and in the defaults of `meta/argument_specs.yml`, and the
expected values in `molecule/default/verify.yml`. A file added or removed under `dist/` is added or removed in the
table too. A copy that does not match its pin stops the role before it writes.

## Owner steps that stay with the owner

The role retires these steps of the runbook: Deliver step 4 (`mkdir`, `rm -rf dist`, `scp`, `COMMIT`), Deliver step
5 (the `rsync` check, replaced by the role's pin check before the copy and the second run's zero changes) and the
`mkdir` block of Run step 2. Deliver steps 1 and 2 (take the commit, build and test) become "To bump" above.

What remains, in order. Each crosses a boundary in the workspace principles (a mutating action on a host, a
break-glass key, a sensitive-data boundary) or is the tenant's own decision, so none is a task of this role:

1. **Check what app1 can run** (Deliver step 3), read-only: `node` at v26 or newer, `age`, `docker` and `docker
compose`, the tenant's rendered stack and its two env files, its image on the host, and a TLS route to its
   database server. The role installs none of these.
2. **Put the tenant's descriptor on the host** (the `scp` of Run step 2) at
   `/root/export-bundler-state/<slug>.descriptor.json`. The role makes the directory it goes in.
3. **Open the support grant** (Part B).
4. **Run the export** (Part C: Run steps 1 and 3 to 9): set the run's values, choose a free port, start the
   bundler waiting for a token, mint the break-glass token, feed it, and wait for the archive.
5. **Shut the support grant** (Part D).
6. **Bring the archive home and check it** (Part E).

After a gated apply, a person or an agent with the standing read-only SSH grant can read the result back:
`stat -c '%a %U:%G %n' /root/export-bundler /root/export-bundler/dist /root/export-bundler-state /root/export-bundler-state/flags /root/export-bundler-state/out`
must print `700 root:root` for each, `cat /root/export-bundler/COMMIT` must print the pinned commit, and
`sha256sum /root/export-bundler/package.json /root/export-bundler/dist/*.js` must equal the table.

## Not built here: the gateway's keys

The runbook for the storage gateway's credentials has host steps this role does not cover: the gateway's
configuration directory, its master secret and the controller key. They are separate roles, not built yet, because
the gateway host does not exist yet (its host, private network, TLS, delivery path and monitoring are open work).
The master secret stays made once by the owner, as that runbook says. This role neither depends on them nor is
depended on.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes, one command runs lint, yamllint,
the interface checks and the container test of a scenario:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/export_bundler --scenario default
.venv/bin/python ansible/harness/run_harness.py ansible/roles/export_bundler --scenario plan
.venv/bin/python ansible/harness/run_harness.py ansible/roles/export_bundler --scenario refusals
```

Each creates one container on the local Docker daemon and never touches a host. The steps are shared between the
scenarios (`molecule/*/skip-steps.txt`):

- `default` starts from the host as the hand steps leave it, and a little worse: the directories world-readable, a
  stale copy of one pinned file, a file and a directory the release does not have, an old `COMMIT`, and a state
  directory holding an audit line, a descriptor, a flag and an archive. It applies the role, applies it again (which
  must report no change) and verifies: every directory is `root:root` `0700`, every pinned file has its pin and mode
  `0600`, `dist` holds the 22 pinned files and nothing else, `COMMIT` is the pinned commit, and the state directory
  holds exactly what it held, with the same modes and the same audit line. The expected checksums are written out in
  `verify.yml`, not read from the role.
- `plan` runs the check steps: a check against a host with nothing on it, an apply, a check that must find nothing to
  change, and Molecule's own check.
- `refusals` is the safety-class test of the pin check. It runs the whole role against a copy of the bundler made on
  the machine that runs the role, in four cases, and then looks at the host:
  - **a. the pristine copy** is accepted and written (the control: a role that refused everything would fail it);
  - **b. one byte of `dist/cli.js` changed** is refused with "does not match its pin";
  - **c. a file under `dist` that no pin names** is refused, and the message names it;
  - **d. a link where the bundler directory belongs** is refused, and nothing is written through it.

  After b, c and d the host holds nothing at the case's directories: no write came before the refusal. Red with the
  control broken: delete the `Hold the vendored bundler to its pinned sha256` include from `tasks/main.yml`, and
  cases b and c go red because the role writes; restore it and they go green.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by running `ansible-playbook` by hand. App1's
playbook (`ansible/playbooks/app1.yml`) applies this role last, after `deploy_slot_keys`, and
`ansible/checks/host_roles.yml` lists it for app1. A merge to `main` queues the apply, and the apply waits for the
owner's approval. The enrolment check pins app1's play variables, so this role takes none from the playbook.

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together: the spec and the defaults must agree.
2. Keep every task able to run under `--check --diff`, and every refusal before the first write.
3. Never relax the pin check to accept a file "because it is the same". A different byte is a different program that
   root will run.
4. Extend `molecule/default/verify.yml` so it asserts the new outcome, and add a case to `molecule/refusals` for any
   new way the role can refuse.
5. Run the three scenarios above before opening a pull request.
