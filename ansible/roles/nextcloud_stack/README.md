# nextcloud_stack

This role brings the nextcloud1 Compose stack up on a host: the three secrets it
needs, the stack's Compose file, the systemd drop-in of its instance, then the
unit enabled and started. It is the Ansible form of the steps 1 to 6 of
`hetzner/RUNBOOK-nextcloud.md`, in the same order, with the same files, modes and
owners.

This README is written for a maintainer who is new to the repository. It follows the
order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

1. **Secrets, once.** When `/etc/branchleft/nextcloud1.env` is absent, the role
   generates `NEXTCLOUD_DB_PASSWORD`, `NEXTCLOUD_REDIS_PASSWORD` and
   `NEXTCLOUD_ADMIN_PASSWORD` on the host with `openssl rand -base64 24` and writes them
   into that file, mode `0600`, owner and group `root`. When the file exists, the role
   writes nothing and generates nothing: the runbook's rule is "edit the file in place
   rather than overwriting it", and a person does that by hand. No value is printed
   (`no_log`).
2. **The stack's files.** `compose.yml` is copied into `/opt/branchleft/nextcloud1`,
   mode `0644`, owner and group `root`.
3. **The drop-in.** `nextcloud1.override.conf` is installed as
   `/etc/systemd/system/branchleft-compose@nextcloud1.service.d/override.conf`, mode
   `0644`, in a directory of mode `0755`. The role reloads systemd when it changed.
4. **Enable and start.** `branchleft-compose@nextcloud1.service` is enabled and started.
   The unit's own `ExecStart` runs `docker compose up -d --wait`, so a unit that is
   active has seen every service with a healthcheck report healthy. The stack is
   restarted by the role when any file above changed in the run.
5. **The checks of step 6.** The unit must be `active` with the drop-in loaded. Docker,
   asked by Compose's labels and never by a fresh `docker compose`, must show one
   healthy container per service (`app`, `db`, `redis`), and the app container must
   answer `status.php` with `"installed":true`.

It does not remove a file, a volume, a container or a secret. It does not edit an env
file that exists. It does not install Docker, the Compose plugin or the shared Compose
unit template (the host baseline does that). It does not rotate a secret.

### What the role does not carry from the runbook

- The runbook's `rsync --delete` is not carried. A file removed from the repository
  stays on the host, as with `monitoring_stack`.
- Sections 7 to 9 of the runbook (the first-run app configuration, the four `occ`
  warnings of section 8, and the major-version upgrade of section 9 with its backup
  steps) and the "Rolling back" section are not in this role. They are the platform
  owner's to run by hand, and the runbook keeps them. See the PR body for the decision
  this leaves open.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables, and
[`defaults/main.yml`](defaults/main.yml) holds their defaults.

- `nextcloud_stack_project_dir` (default `/opt/branchleft/nextcloud1`). It must equal the
  `WorkingDirectory` the shared unit template derives from the instance name.
- `nextcloud_stack_check_containers` (default `true`). Whether the container checks run.
  Only the test sets it `false`, because the test has no Docker daemon. A check-mode run
  skips the container checks and the unit assertion for a stated reason (ANS-10): a
  check run writes no drop-in and starts nothing, so systemd has nothing to report yet.

`vars/main.yml` holds the constants: the instance name, the file list, the service
names, the env file path and the drop-in directory. They are not inputs.

No value in the role is a secret. The secrets are generated inside the play and are
only ever written to the env file.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; `min_ansible_version`
  is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- `openssl` on the host, as the runbook already requires.
- Target: Debian 13 with systemd and Docker, with the shared Compose unit template
  `branchleft-compose@.service` already on the host (the host baseline).
- The Compose file and the drop-in come from this repository through the links in
  `files/`, so the role must run from a checkout that keeps links, which the gated pull
  does.

## What it changes on a host

- `/etc/branchleft/` (mode `0755`, `root:root`) and `/etc/branchleft/nextcloud1.env`
  (mode `0600`, `root:root`), only when the env file is absent.
- `/opt/branchleft/nextcloud1/` (mode `0755`) and `compose.yml` in it (mode `0644`).
- `/etc/systemd/system/branchleft-compose@nextcloud1.service.d/` (mode `0755`) and
  `override.conf` in it (mode `0644`).
- One `daemon-reload` of the systemd manager when the drop-in changed.
- The unit `branchleft-compose@nextcloud1.service` enabled and started; restarted when a
  file above changed. Compose then starts, or recreates, the three containers.

## How it is tested

The harness runs the scenario in `molecule/default/` on one systemd container, with the
same platform as `monitoring_stack`. Its `prepare.yml` installs a placeholder for the
shared unit template, a oneshot that runs `/bin/true`, so no Docker runs in the test.

- `converge.yml` applies the role with the container checks off.
- `idempotence`: a second converge reports zero changes, so the env file is not written
  twice.
- `verify.yml`: the project directory, the Compose file (byte for byte its source, mode
  `0644`), each image pinned by digest, the env file (mode `0600`, root-owned, a value
  for each of the three secrets, names only in the output), the drop-in (byte for byte its
  source), and systemd holding the drop-in with the unit active, `MemoryMax` `536870912`
  and `CPUWeight` `100`.

Run it with the harness, as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/nextcloud_stack
```

### Controls, and their sabotage

Each control below is a line of the role that a test should see fail. The sabotage row
for each one is to be recorded in the PR's review round, not claimed here.

| Control                           | Edit that should turn it red                                                                 | Step that should fail                                                              |
| --------------------------------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Env file written only when absent | remove the `when` on the template task                                                       | `idempotence` (a second converge changes)                                          |
| Env file mode `0600`              | change the mode on the template task to `0644`                                               | `verify` (env file mode assertion)                                                 |
| Drop-in loaded                    | remove the `Reload systemd manager` notify on the drop-in                                    | `verify` (`MemoryMax` assertion, via the converge's own `flush_handlers` ordering) |
| Compose file byte for byte        | change `mode` of `compose.yml` copy to `0640`                                                | `verify` (Compose file assertion)                                                  |
| Images pinned by digest           | change one image in `files/stack/compose.yml` to a tag without a digest in a sabotage branch | `verify` (image pin assertion)                                                     |

The container checks have no test in this scenario: it has no Docker. They run on every
host, and the first live apply is their proof (ANS-17).

## Named limits

- **Docker, Compose and the real unit template are not exercised.** The test never runs
  the stack. The first live apply on `ops1`, through the gated workflow, is the proof of
  the healthy containers, and it waits on the enrolment of the host.
- **The unit template is a placeholder in the test.** `ExecStart`, `EnvironmentFile` and
  `AssertPathExists` of the drop-in are not exercised; `MemoryMax` and `CPUWeight` are.
- **Secrets are generated on the host by `openssl`.** The values are not checked for
  content, only for presence and the three names.
- **Silent skips.** The container checks and the unit assertion are skipped in check
  mode, and the container checks in the test. The harness does not catch a silent skip;
  the reason is stated in each place, and review is what checks it (ANS-10).
- **A file removed from the repository stays on the host** (no `--delete`).

## How to change it safely

1. To change what the stack is, change `hetzner/nextcloud1/stack/compose.yml` or the
   drop-in under `hetzner/nextcloud1/systemd/`; the role delivers them as they are.
2. Keep every task able to run under `--check --diff`, and keep the modes explicit.
3. Never print a secret: keep `no_log` on every task that reads or writes one.
4. Run the harness before opening a pull request, then break a control from the table
   above and see the named step fail.
