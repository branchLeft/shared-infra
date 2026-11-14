# edge_stack

Delivers the files of the edge Compose stack to `/opt/branchleft/edge` and applies each class of file by the one action it needs: reload Caddy, restart CrowdSec, or restart the Compose unit.

This README is for a maintainer who is new to the repository. It follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

The source of truth is the directory `hetzner/edge/stack` (the link `files/stack` points at it). Every file in it is in exactly one class, and a file in no class stops the run before anything changes:

| Class      | Files                                                                                                                                                                                                                           | Action when the class is due                                                                |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `caddy`    | `Caddyfile`                                                                                                                                                                                                                     | validate the candidate in the pinned image, write it in place, `caddy reload`, read it back |
| `compose`  | `compose.yml`, and the hash of `/etc/branchleft/edge.env`                                                                                                                                                                       | `systemctl restart branchleft-compose@edge.service`                                         |
| `crowdsec` | `crowdsec/config.yaml.local`, `crowdsec/appsec-configs/ghost-admin-previews.yaml`, `crowdsec/postoverflows/ghost-admin-api-postoverflow.yaml`, `crowdsec/parsers/edge-trusted-session.yaml`, every file in `crowdsec/acquis.d/` | `docker compose restart crowdsec`, then read back                                           |

**Restart shape.** This is the shape of the monitoring_stack role, as that role's restart-by-fingerprint amendment states it. A run works out what is due, validates every candidate, places every file, acts, reads the result back and writes the stamp last. There are no handlers. A class is due when its stamp is not the fingerprint of what the repository holds now, or when a file of the class on the host differs from the repository's (a hand edit, or a file torn by a power cut). Only the second of these is visible to a stamp that merely equals the fingerprint, which is why both are read. The steps that read the stamps, decide from them, mark, adopt and record are this role's own copy of the monitoring_stack steps ("The stamp steps" below); the hashes, the fingerprints, the drift, the gate and the actions with their read-backs are in the same role.

**Stamps.** One per class, in `/var/lib/branchleft`, root, mode 0600: `edge.caddy.applied`, `edge.compose.applied`, `edge.crowdsec.applied`. A stamp holds a sha256 and a newline, or `pending` from before the first file of a run is placed until the class has been read back. `pending` is never a fingerprint, so a run that dies after that point, in a placement or in an action, acts again, and a class whose file was placed is never taken for a hand-delivered host. A stamp that is there and cannot be read (a directory, a link to nothing, an I/O error) stops the run before anything is placed; only a stamp that is not there counts as none. A stamp is written only for a class whose marker the locked module returned after the read-back; a class that finished before a later one failed is stamped, one that did not is not.

**Order, in one run.**

1. Read and refuse, changing nothing: the pin, the secrets file, the Caddyfile on the host, and every file of the stack in the repository.
2. Work out what is due, from the host (a `stat` with a checksum runs in check mode too).
3. Put the candidate Caddyfile and Compose file in a directory closed to root, and read the CrowdSec files and the unit's drop-in from the repository, as bytes.
4. Call the locked module once. Under one hold of the deploy lock it validates both candidates (a refused candidate stops it with the host as it was), marks every class that is due `pending`, places every file (the Compose file from the candidate that was validated, not read from the repository a second time, so a checkout that changes in between cannot put an unvalidated file on the host; CrowdSec's files; the drop-in), prunes the acquisition directory and sets the Caddyfile's owner and mode, and then acts, only if the pin is still the one it validated in (exit code 74 if it is not), in this order: write the Caddyfile in place, restart the unit, restart CrowdSec, reload Caddy. The mark comes before any placement, so a run that dies while placing leaves the class due, not a class that looks hand-delivered. The Compose class is marked whenever its file differs, including while its unit is not enabled (then it is placed and left `pending`, and acted on once the unit is enabled). The unit comes before Caddy's reload so a `compose.yml` change that the Caddyfile relies on (a port, a mount) exists first, and every file is on the host before any container action, which also means a bind source that is a file is never missing when Docker looks for it.
5. Write the stamps for what the module read back, then fail the run if the locked step failed.

**Adoption.** A class with no stamp whose files equal the repository's is adopted: the stamp is written and nothing is acted on. This is the first run on the hand-delivered edge. If one class differs, only that class is acted on. The Compose class is adopted only while its unit is enabled; a unit that is not enabled is the owner's first start, so the role places the files and says so, and writes no Compose fingerprint: a Compose file that differs is placed and the class is left `pending`, so it is never adopted and is acted on (the unit is restarted) on the first run after the unit is enabled, whether or not the owner started it. Named limit: adoption trusts the files, not the containers. A host whose files equal the repository's but whose containers are running older configuration is adopted, not repaired. The owner's step that applies a config the containers do not have is a restart of the unit.

**What it does not do.**

- It never runs `docker compose up`. The unit `branchleft-compose@edge.service` is the only path that does (`up -d --remove-orphans --wait`, no force-recreate), and the role only restarts it. `branchleft-deploy` restarts the same unit when the image digest changes, so `edge.image.env` is in no fingerprint.
- It never writes `/etc/branchleft/edge.image.env` (`branchleft-deploy` does) and never writes `/etc/branchleft/edge.env` (the owner places it). No value of `edge.env` comes into the Ansible run or its log; "Environment semantics" below says which processes read the file on the host. Only its sha256 comes back, for the Compose fingerprint, so a rotated key reaches the containers by restarting the unit, which recreates them. Every task that handles that hash has `no_log: true`.
- It never restarts Caddy for a config change, and it does not apply a posture flip. A posture flip (`docker restart` of Caddy, RUNBOOK-edge 10a) stays an owner step, verified by step 8a.
- It starts no unit that is not enabled, installs no package, and removes nothing outside `crowdsec/acquis.d`. It restarts the unit for no change to the unit's drop-in.
- It has no saved-file or rollback path (see "Rollback").

## Interface

The inputs, their types and defaults are in `meta/argument_specs.yml`; Ansible checks them when the role starts. None is a secret.

| Variable                            | Default                       | What it is for                                                                                      |
| ----------------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------------- |
| `edge_stack_source_dir`             | `{{ role_path }}/files/stack` | The stack directory. Only the container test changes it.                                            |
| `edge_stack_lock_timeout`           | `600`                         | Seconds to wait for the deploy lock before failing with exit code 75 and changing nothing under it. |
| `edge_stack_crowdsec_wait_tries`    | `24`                          | Times CrowdSec's Local API is asked whether it answers after the restart.                           |
| `edge_stack_crowdsec_wait_interval` | `5`                           | Seconds between those asks.                                                                         |

The paths, the stamp names, the classes and the pin pattern are constants in `vars/main.yml`, not inputs: a caller cannot override them. The role has no `dependencies` and loads no other role (ANS-12): the stamp steps are its own task files ("The stamp steps" below). `playbooks/edge1.yml` applies this role after `host_baseline`, `ci_login` and `deploy_tooling` (see "How it is delivered").

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- A host with Docker, Docker Compose v2, `flock` (util-linux), systemd, and the unit `branchleft-compose@.service` from `hetzner/provision`. Nothing installs these here.
- On the host, before a live apply: `/etc/branchleft/edge.env` placed by the owner (root, mode 0600, a regular file), and `/etc/branchleft/edge.image.env` written by `branchleft-deploy` (exactly one `IMAGE=<reference>@sha256:<64 hex digits>` line). The role refuses to run without either and says which.

## What it changes on a host

- `/opt/branchleft/edge`, `crowdsec` and `crowdsec/acquis.d`: root:root, mode 0755. Every file in them: root:root, mode 0644. A container reads its bind-mounted configuration as its own user, so a tighter mode would break it. The shell copy this role replaces made the same modes (rsync `--no-owner --no-group --chmod=u=rwX,go=rX`).
- `/etc/systemd/system/branchleft-compose@edge.service.d` (0755) and `override.conf` in it (0644, root:root), and one `systemctl daemon-reload` when that file changed or systemd holds an older one ("The unit's drop-in").
- `/var/lib/branchleft` (0755; monitoring_stack creates it in the same mode, so whichever runs first creates it) and the three stamps in it (0600).
- Candidates, while the role runs, in `/var/lib/branchleft/edge.candidate` (root, 0700), removed at the end of every run, a failed one included. A leftover would make the next check-mode run report a change.
- The Caddyfile on a host that has none is created by the locked module, root:root 0644, before it is written, so Docker never creates a directory where the file is expected (the directory `caddy/` is created first, from `edge_stack_dirs`).
- Calls: `docker run --rm` (validate, nothing contacted, no certificate issued), `docker compose ... config -q`, `systemctl restart/is-active`, `docker compose ... restart crowdsec`, `docker compose ... exec` (read-backs, `caddy reload`, `cscli lapi status`). Compose is always given the project directory and both env files, exactly as the unit has them, so `${IMAGE}` and the required keys interpolate.

### Classes

A file added to `hetzner/edge/stack` is refused until it is in a class: add it to `vars/main.yml` (Caddyfile, Compose file and the CrowdSec files Compose mounts one by one are named there, and a new one of those also needs its container path in the module's `CROWDSEC_FILES_INSIDE` and in the stand-in `docker`; a file directly in `crowdsec/acquis.d` is CrowdSec's with no edit). A link is refused. A file removed from the repository stays on the host, as in the sibling roles, except under `crowdsec/acquis.d`, the one directory the role prunes: a file there that the repository does not hold is a CrowdSec configuration nobody reads in the repository. A stale file anywhere else under `/opt/branchleft/edge` is the owner's to remove.

### The unit's drop-in

The role installs the drop-in of the edge unit, `files/edge.override.conf` (a link to `hetzner/monitoring/systemd/edge.override.conf`), as `/etc/systemd/system/branchleft-compose@edge.service.d/override.conf` (directory 0755, file 0644, root:root). It bounds the edge unit's process tree with `MemoryMax` and `CPUWeight` on the host that also runs the monitoring stack; the reasoning is in `hetzner/RUNBOOK-monitoring.md`, "Colocation cgroup bounds". `monitoring_stack` used to install it, before this role existed; this role owns the edge unit, so it is the one home (`ansible/checks/test_edge_single_home.py`).

The drop-in is in no fingerprint and a change to it never restarts the unit: a restart is made for the Compose class only. It takes effect through one `daemon-reload`, made by the locked module after the files are placed and before it acts, when the module changed the file or when systemd says the unit's files on disk are newer than what it holds (`NeedDaemonReload`, read before anything was placed). The second term is what brings back a reload that a run which died after the copy did not make: the rerun finds the file unchanged. The drop-in is placed and read after the candidates were accepted, so a refused candidate leaves the host as it was, and a unit that is not enabled still gets it. In check mode the module is not called: `copy` shows the change and the reload is shown as a plan would show it ("Check mode and drift"). The scenario proves the install and the load (converge, `p28`), a changed drop-in put back and read with no action (`p29`) and the reload after a run that died (`p30`).

### The stamp steps

The steps that read the stamps, decide from them, adopt and record are four task files of this role (the mark is made by the locked module), copied from the `monitoring_stack` role's inline steps and generalised to a list of classes, because this role has three stamps and `monitoring_stack` has one. A role does not load another role (ANS-12, checked by `ansible/checks/check_role_imports.py`), and the owner ruled on 25 October 2026 that this role carries its own copy, as `monitoring_stack` does, on condition that one shared module is extracted later.

| File                | Called from                                     | Takes (`edge_stack_stamp_classes`)                                    | Sets                                            |
| ------------------- | ----------------------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------- |
| `_stamp_read.yml`   | `_decide.yml`, before anything is decided       | the three stamp files                                                 | `edge_stack_stamp_found`                        |
| `_stamp_decide.yml` | `_decide.yml`, after the fingerprints and drift | each class's stamp, fingerprint, drift, and for Compose the unit gate | `edge_stack_stamp_decisions` (adopt, due, mark) |
| `_stamp_adopt.yml`  | `_deliver.yml`, after the locked module         | each class's stamp file, fingerprint and adopt                        | nothing                                         |
| `_stamp_record.yml` | `_deliver.yml`, after the locked module         | each class's stamp file, fingerprint and whether its marker was read  | nothing                                         |

They compute and record only: none restarts a unit, a service or a container, and none edits a file that is not a stamp. The files are included by name with `include_tasks`, so the lint, the pull trigger and Molecule resolve them the same way. Two things the shared role had are gone because it had other callers and this role does not: the check of the caller's list (a stamp path outside `/var/lib/branchleft`, a name used twice, a fingerprint that is not a sha256), and the entry-point argument specs. The stamp paths and the two stamp words are constants in `vars/main.yml`, and a fingerprint is always a sha256 this role computed, so `pending` cannot be recorded as one. The stamp logic (the pending mark, adoption, the record only after a read-back, an unreadable stamp, a closed gate) is proved in this role's scenario, by the cases named under "How to test it".

### Why the Caddyfile is written in place

`compose.yml` bind-mounts the directory `caddy/`, so a rename is seen too; the write stays in place because a host that still has the earlier single-file mount, until its unit is recreated, holds the old inode and a rename would leave Caddy reloading bytes it already has. The locked module opens the file for writing and writes the candidate over it, so the inode the container's mount holds is the one that changes; no reload or restart can read a half-written file, because the write is under the same lock as the reload. Named limit: a power cut during the write can leave a torn file. The next run sees it (the host file differs from the repository's), and rewrites it, but a reboot before that run would start Caddy on the torn file. Accepted.

### The locked module

All locked work is in `library/edge_stack_apply.py`, a typed Ansible module (an `argument_spec`, check mode, documented returns; `ansible-doc -t module -M ansible/roles/edge_stack/library edge_stack_apply` renders it). The role calls it once per run. It opens `/etc/branchleft/edge.deploy.lock` (`O_CREAT`, mode 0600), takes `flock(2)` `LOCK_EX | LOCK_NB` and retries every 0.2 seconds until `edge_stack_lock_timeout`, exactly as `stack_deploy_lock` in `hetzner/provision/branchleft_deploy.py` does. That is the same kernel lock `branchleft-deploy` takes, so a deploy and this role cannot run their actions together, and the unit tests prove it with `stack_deploy_lock` itself.

**One hold, never released between the sections.** Inside the one hold the module does these, in this order, and lets go only when it returns:

1. Read `edge.image.env` and refuse anything but exactly one line that matches the pattern (64).
2. Validate the candidate Caddyfile in the pinned image (65) and the candidate Compose file with `docker compose config -q` (67). A refusal stops the module before anything is placed, so the host is as it was.
3. Place: mark each stamp that is due `pending`, make the drop-in directory, place the Compose file from the candidate that was validated, place the CrowdSec files and the unit's drop-in from the bytes the role read in the repository (checked against the sha256 the role hashed), prune the acquisition directory, set the owner and mode of a Caddyfile that is there, and run `systemctl daemon-reload` when the drop-in changed or systemd says it is behind.
4. Act: read the pin again and refuse if it is not the reference the candidates were validated in (74), then write the Caddyfile in place (66), restart the unit (68, 69), restart CrowdSec and read its files back (70, 71), reload Caddy and read the Caddyfile back (72, 73).

Before this change the script ran as two separate `flock` calls with the placement between them, unlocked. Step 3 is now inside the lock, so a deploy cannot restart the unit, or move the pin, between the validation and the actions. The module takes the lock only when there is something to validate or act on; a run with neither (nothing due, no Compose drift) places files without it, as before.

Why a module and not tasks: an Ansible task cannot hold a lock across tasks, and the decision is that one lock covers the pin read through the last action. The module is typed, has an `argument_spec` and a documented result, runs its commands by argument list with no shell (ANS-3), and replaces `files/edge_apply.sh`, which was run as `sh -ec <script>` under `flock(1)`. It handles no secret: it never opens `edge.env`, and returns paths, outcome names and markers, never a file's content.

Exit codes. The set is closed: `Code` in the module holds exactly these, each has one name, and any other code is a failure (`unmapped`), as is a step that stops with code 0.

| Code | Outcome             | Meaning                                                                      |
| ---- | ------------------- | ---------------------------------------------------------------------------- |
| 0    | `ok`                | Everything asked for was done and read back.                                 |
| 64   | `pin-refused`       | The pin file is not exactly one `IMAGE=<reference>@sha256:<64 hex>` line.    |
| 65   | `caddy-refused`     | The candidate Caddyfile is refused.                                          |
| 66   | `caddyfile-write`   | The Caddyfile could not be written in place, or is not the candidate after.  |
| 67   | `compose-refused`   | The candidate Compose file is refused.                                       |
| 68   | `unit-restart`      | The unit restart failed.                                                     |
| 69   | `unit-not-up`       | The unit is not active, or a service is not running, after the restart.      |
| 70   | `crowdsec-restart`  | The CrowdSec restart failed.                                                 |
| 71   | `crowdsec-readback` | CrowdSec's API did not answer, or a file inside it is not the host's.        |
| 72   | `caddy-reload`      | `caddy reload` failed.                                                       |
| 73   | `caddy-readback`    | The Caddyfile inside the container is not the one on the host.               |
| 74   | `pin-moved`         | The pin file no longer holds the reference the candidates were validated in. |
| 75   | `lock-busy`         | The deploy lock was not free in time. Nothing was validated, placed or done. |
| 76   | `lock-unusable`     | The lock file cannot be opened or locked.                                    |
| 77   | `host-error`        | A placement, removal, reload or command failed outside the steps above.      |

75 is the only code that says the lock was not free, so a timeout cannot be taken for a failed action. 76 and 77 are new: the script could exit with `flock(1)`'s status 1 for a lock file it could not open, or with an unnamed `sh -e` status for a failed `cat`, `install` or `sha256sum`, and the role reported those as an unnamed number. 64 to 75 mean what they meant. One code is gone: "the apply was given no validated pin" cannot happen now, because the validated reference does not travel between two programs but stays in the one call; 74 keeps its other meaning.

The module returns `code`, `outcome`, `phase` (`lock`, `validate`, `place` or `apply`, the last one reached), `message`, `detail` (the tail of the failed command's output as it wrote it, which for Compose is Compose's own error text), `pin`, `validated`, `markers`, `placed`, `marked` and `reloaded`. `markers` are the steps that finished and were read back, in order, and they are present on a failure too. The role keeps the result with `failed_when: false`, stops at once for a failure in the `lock`, `validate` or `place` phase, and for one in the `apply` phase first writes the stamps for the markers that were returned, then fails the run, so a class that finished before a later one failed is stamped.

**The pin.** The module reads the pin inside the lock, validates the candidates in that reference, and re-reads it before it acts. A pin that still matches the pattern but names another digest is refused with 74, which no other failure uses, so it cannot be taken for the pattern check (64). Within one lock only a writer that does not take the lock can move it. The reference is an image name and a digest, not a secret (the pin file is mode 0644).

**Lock windows.** The role gives up after `edge_stack_lock_timeout` (600 s); `branchleft-deploy` waits up to 1260 s for the same lock. The window between the validation and the apply, where the files were placed unlocked, is closed. What stays outside the lock is what the role reads before it calls the module (the early pin read, the hashes, the stamps, the unit state): they decide, they do not act, and the module reads the pin again inside the lock. A refused or failed run leaves the stamps `pending` for the classes it marked, and the Compose and CrowdSec files it had already placed stay on the host (they are the repository's); the next run validates and acts.

### Check mode and drift

Everything that decides runs in check mode: the classification, the hashes, the stamps, the unit state. The locked module is not called in check mode (its own check mode reads the host and reports what would change, and takes no lock), so the plan's view is the tasks that stay: `copy` and `file` tasks that run only in check mode and show the Compose file, the CrowdSec files, the drop-in, the prune and the Caddyfile's mode, and, for each class that would be acted on, a task that does nothing and reports `changed`: "the Caddyfile would be validated, written and reloaded", "the edge unit would be restarted", "the crowdsec container would be restarted". The plan job and the nightly drift check show those lines, so a plan is not silent for the file that terminates TLS. A file on the host that differs from the repository is shown by `copy` (diff) or reported by those tasks. Adoption is a stamp written, which also shows in a plan.

The harness runs the role in check mode before anything is applied (`check-fresh`) and again against the configured host (`check-configured`, zero changes expected).

### Rollback

There is no saved-file path (the shell runbooks had one, edge-ghost-setup-refusal section 6 and edge-portal-routes section 7). Rollback is: revert the commit and run the gated workflow. The role then writes the older files and acts on the classes that differ. Two things to know. A `compose.yml` that parses (`docker compose config -q` checks syntax and interpolation only) but breaks the stack stays on the disk after the unit restart fails, so the fix is forward, and a reboot starts the unit from that file. A failed run leaves the pending stamps, so the next run acts again.

### Environment semantics

**Who reads `edge.env`, and what comes back.** On the host, as root, four things read the file, and none returns its content to Ansible:

- the Ansible `stat` task in `_assert.yml` (with a checksum) reads the whole file to hash it; the sha256 is the only thing that comes back, and it goes into the Compose fingerprint and the Compose stamp;
- Docker Compose reads and parses it, because the locked module passes `--env-file /etc/branchleft/edge.env` to every Compose call: `config -q` on the candidate Compose file in the validation, and `ps`, `exec` and `restart` in the apply. The values stay inside the Compose process. `config -q` prints nothing when it succeeds, and the module returns no value. If Compose fails, its error text is shown in the failure message as Compose wrote it; the role does not filter it;
- systemd reads it as the unit's `EnvironmentFile=` when the unit is restarted (the unit's own behaviour, not this role's);
- the containers receive the values Compose interpolates, which is what the file is for.

The module itself never opens the file, and the Caddy validation does not use it.

The consumers read quotes differently: `docker run --env-file` keeps them literally, the unit's `EnvironmentFile=` and Compose strip them. The Caddy validation therefore passes placeholder values (`validation-only`, `validation@example.invalid`) for the two keys instead of `--env-file`, which parses and adapts the Caddyfile without contacting anyone. A quoted `ACME_EMAIL` is therefore not caught by the Caddy validation; it is the owner's to place unquoted. The role does not read `edge.env` to check for quotes: bringing a secrets file's content into the run is a decision for the owner, not the role.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes, one command runs lint, yamllint, the interface checks and the container test:

```text
python3 ansible/harness/run_harness.py ansible/roles/edge_stack
```

The container is a systemd platform. The test installs stand-ins and proves wiring only, never the live behaviour:

- a stand-in `docker` that logs every call, checks the arguments Compose needs, answers `run ... caddy validate` and `compose config`, models the container's single-file mount as a hard link in `/var/lib/standin-mount` (so a rename leaves the view on the old bytes and an in-place write does not), and fails or lies where a flag file in `/run` asks (`standin.fail.crowdsec`, `standin.fail.reload`, `standin.lapi.down`, `standin.stale.caddy`). It appends every call to `/var/log/docker-standin.calls`, refuses a Compose call that lacks the project directory or either env file, answers `run ... caddy validate` and `compose config` by looking for a marker in the file it is given, reports the services listed in `/run/standin.running` as running, and, when `/run/standin.pin.change` is there, moves the pin to another valid digest once while it validates a Caddyfile (a deploy that does not take the lock), and, when `/run/standin.compose.edit` is there, adds a comment line to the candidate Compose file once before it validates it. It logs the sha256 of the file it validated as `VALIDATED-COMPOSE sha=<sha256>`, so case `p27` can tell the file that was validated from the repository's;
- a placeholder `branchleft-compose@.service` whose start logs the hash of the Caddyfile and the Compose file on the host at that moment, so the test can see both were placed first.

`verify.yml` has one block per behaviour, tagged `p0` to `p30` (and `p9b`, `p11c`, `p11d` and `p20c`), each starting from the converged host and asserting on the stand-in's calls, the stamps and the files. Case `p26` is the pin that moves between the validation and the apply. Case `p27` is the Compose file that arrives: the stand-in adds a line to the candidate as it validates it, and the file on the host must be the one the validation read, which the repository's file is not. A block can be run alone with `ANSIBLE_RUN_TAGS=p7 molecule verify`, from the scenario that is its home (below). The Ansible log of every run of the scenario is scanned at the end for the sentinel values of the test's `edge.env` and for the three fingerprints, which pass through the includes of the `_stamp_*.yml` files as variables.

The module has its own unit tests, `tests/unit/test_edge_stack_apply.py`, run by `ansible/checks/run_role_unit_tests.sh` and, with the type check and the lint, by the CI step "Check each role's own library modules". `docker` and `systemctl` are stand-ins on `PATH` that log each call and whether another process could take the lock at that moment. They prove: the lock is held for every command of both sections and the placement between them; a second process asking for the lock while the module is inside the validation, inside the placement and inside the apply gets it only after the module's last command; `stack_deploy_lock` from `branchleft_deploy.py` cannot take the lock while the module holds it, and the module reports 75 while that program holds it; a busy lock is refused with 75 and nothing is placed or run; every code in the table above is produced by the condition it names; a code outside the set, and a stop with code 0, are failures; and check mode takes no lock, runs no command and changes no file. The container test does not run them. Molecule needs Docker, so the scenario above is run in CI.

The cases are shared out between four scenarios, each its own CI shard, because the one verify took about thirty minutes and the shard sets the length of every pull request that touches the role. Each scenario applies the role once by the converge it imports from `default`, then runs the blocks whose home it is, named in `edge_stack_verify_homes` in `verify.yml` (a mapping holds a key once, so a case has one home), and the log scan (`p25`), which has no home and runs in every scenario over that scenario's own log:

| Scenario   | Cases                                                                                                                                              | Steps it runs                                                                                                                                 |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `default`  | `p0` to `p8`: the converged host, one change per class, the stamps, the plan                                                                       | all of them: the plan against a fresh host, the second apply that must change nothing, the check of the configured host, Molecule's own check |
| `adoption` | `p9`, `p9b`, `p10`, `p11`, `p11c`, `p11d`, `p12`, `p20c`, `p24`: a host with no stamp, a run that dies, the read-back, a first delivery            | create, prepare, converge, verify                                                                                                             |
| `refusals` | `p13` to `p19`, `p26`: a candidate, a file in no class, a pin, a secrets file and the pin that moves, which the role refuses, and the deploy lock  | create, prepare, converge, verify                                                                                                             |
| `services` | `p20`, `p21`, `p22`, `p23`, `p27`, `p28`, `p29`, `p30`: the unit, CrowdSec, the containers, the Compose file that is validated, the unit's drop-in | create, prepare, converge, verify                                                                                                             |

The scenarios other than `default` leave out `check-fresh`, `idempotence`, `check-configured` and `molecule-check` (`skip-steps.txt`), which `default` runs once for the role. `molecule/<scenario>/` holds, for each, only the imports of the default scenario's converge, prepare and verify, a link to its `molecule.yml` and that list. `tests/unit/test_verify_parts.py` fails when a case block has no home, a home has no block, a block is gated on another case's name, a scenario is no home or a home no scenario, or a scenario leaves out a step `default` must run. A new case needs a line in `edge_stack_verify_homes`; put it where the shards are shortest.

The stamp steps are tested here and nowhere else: `p7` (a drifted file with an unchanged stamp is due), `p9`, `p10` and `p11` (adoption, and only of the class whose files equal the repository's), `p9b` (a stamp that is there and cannot be read stops the run before anything is placed), `p11c` and `p11d` (the `pending` mark is written before a file is placed, so a run that dies after placing is acted on again), `p12` (a stamp is written only for a class that was read back), `p20` and `p20c` (the closed gate for a unit that is not enabled), and `p21` to `p23` (a class whose action failed stays `pending`).

`ansible/checks/test_edge_single_home.py` fails when another role names `/opt/branchleft/edge`, delivers from the stack directory, or names `branchleft-compose@edge`, which includes the unit's drop-in directory `branchleft-compose@edge.service.d`: there is no exception. It reads the tasks, handlers, vars and defaults of the roles. Two homes for a file, or two roles that restart one unit, make the restart depend on which role ran last: that is the defect the stamps of this role exist to remove. The files of the stack are read from the stack directory itself, and the test that each of them is in a class is in the same file, so there is no second list to keep in step. `ansible/checks/check_role_imports.py` fails when this role loads another role, and `ansible/checks/check_role_paths.py` when another role writes a path this one does.

### Named limits

- The stand-ins prove the role's wiring, not Docker, Caddy, CrowdSec or systemd. That `docker compose config -q` agrees with the real one, that `caddy validate` finds what the stand-in's marker finds, and that CrowdSec's API answers are live facts.
- The in-container sha proves the mount sees the new bytes, not that Caddy loaded them. That is the exit status of `caddy reload`. A live apply puts both on the issue: the in-container sha equal to the repository's, and the reload's exit status.
- Posture flips are not applied.
- A torn Caddyfile after a power cut (above).
- The read of `edge.image.env` is early (a pin the role refuses stops it before anything changes), again inside the validation and again before the module acts. The module acts only on the pin the validation read, so a writer that does not take the lock is refused (exit code 74), never acted on. What stays on the host after that refusal is in "Lock windows".
- The fingerprints are computed from the first read of the repository. A checkout that changes before the candidate Compose file is copied leaves a stamp that is not the fingerprint of the file that was placed (the placed file is the one that was validated). The next run sees the difference and acts again.
- The stamp steps exist in two roles, this one and `monitoring_stack`, as the owner allowed on 25 October 2026 on condition that a shared module is extracted later. Until then a fix to the steps is made twice, and nothing fails when one copy changes and the other does not.
- `playbooks/edge1.yml` applies the role, but only the gated run on `main`, once the owner approves it, changes the host.

### Differences from the monitoring_stack family

The shape is the same. It differs, on purpose: three stamps named `edge.<class>.applied` against one `monitoring.applied`; the Compose fingerprint includes the hash of `edge.env` (monitoring's does too, by its own list); the unit is restarted if it is enabled, whatever its active state, so a `failed` unit with a corrected file is restarted; the Caddyfile has its own validation and an in-place write under the lock; the stamp steps are a list-driven copy of `monitoring_stack`'s inline steps, in the `_stamp_*.yml` files ("The stamp steps" above), because this role has three stamps to its one. The two roles share one shape and not one implementation. The unreadable-stamp rule is stricter here than in `monitoring_stack`: a stamp that is there and cannot be read stops the run before anything is placed.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by running `ansible-playbook` by hand. `playbooks/edge1.yml` applies this role after `host_baseline` (which installs Docker), `ci_login` and `deploy_tooling` (which installs the `branchleft-deploy` wrapper that writes `edge.image.env` and the `branchleft-compose@.service` template unit). A merge changes no host; the gated run does, after the owner approves it. The owner order for the first live apply is:

1. edge1's bootstrap (the owner's step).
2. The owner places `/etc/branchleft/edge.env` (root, 0600). The role asserts it and fails the run loudly until it is there.
3. `branchleft-deploy` writes `edge.image.env` with the live digest.
4. The check-mode output for edge1 is put on the PR before the approval; every class that would be acted on is named in it.
5. The gated run on `main`. It installs the edge unit's drop-in itself ("The unit's drop-in"), so nothing else needs to have placed it. The first apply adopts the host's existing files where they equal `hetzner/edge/stack` and acts only on a class that differs (see "Adoption"): if the plan job shows a Caddy restart rather than an adoption, reject the apply and read the difference first.

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together.
2. Keep every task that decides able to run under `--check --diff`; keep the locked module as the only place an action runs.
3. A new file in `hetzner/edge/stack` needs a class (above). A change to the Caddyfile, the Compose file or the CrowdSec files changes only that class's fingerprint, so only its action runs; keep it so.
4. Extend `verify.yml` with a block for the new behaviour, and prove it by sabotage: break the code, see the block go red, restore, see it green.
5. Run the command under "How to test it" before opening a pull request.
