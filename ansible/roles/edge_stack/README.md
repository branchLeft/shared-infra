# edge_stack

Delivers the files of the edge Compose stack to `/opt/branchleft/edge` and applies each class of file by the one action it needs: reload Caddy, restart CrowdSec, or restart the Compose unit.

This README is for a maintainer who is new to the repository. It follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

The source of truth is the directory `hetzner/edge/stack` (the link `files/stack` points at it). Every file in it is in exactly one class, and a file in no class stops the run before anything changes:

| Class      | Files                                                            | Action when the class is due                                                                |
| ---------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `caddy`    | `Caddyfile`                                                      | validate the candidate in the pinned image, write it in place, `caddy reload`, read it back |
| `compose`  | `compose.yml`, and the hash of `/etc/branchleft/edge.env`        | `systemctl restart branchleft-compose@edge.service`                                         |
| `crowdsec` | `crowdsec/config.yaml.local`, every file in `crowdsec/acquis.d/` | `docker compose restart crowdsec`, then read back                                           |

**Restart shape.** This is the shape of the monitoring_stack role, as that role's restart-by-fingerprint amendment states it. A run works out what is due, validates every candidate, places every file, acts, reads the result back and writes the stamp last. There are no handlers. A class is due when its stamp is not the fingerprint of what the repository holds now, or when a file of the class on the host differs from the repository's (a hand edit, or a file torn by a power cut). Only the second of these is visible to a stamp that merely equals the fingerprint, which is why both are read.

**Stamps.** One per class, in `/var/lib/branchleft`, root, mode 0600: `edge.caddy.applied`, `edge.compose.applied`, `edge.crowdsec.applied`. A stamp holds a sha256 and a newline, or `pending` from before the first file of a run is placed until the class has been read back. `pending` is never a fingerprint, so a run that dies after that point, in a placement or in an action, acts again, and a class whose file was placed is never taken for a hand-delivered host. A stamp that is there and cannot be read (a directory, a link to nothing, an I/O error) stops the run before anything is placed; only a stamp that is not there counts as none. A stamp is written only for a class whose marker the locked script printed after the read-back; a class that finished before a later one failed is stamped, one that did not is not.

**Order, in one run.**

1. Read and refuse, changing nothing: the pin, the secrets file, the Caddyfile on the host, and every file of the stack in the repository.
2. Work out what is due, from the host (a `stat` with a checksum runs in check mode too).
3. Put the candidate Caddyfile and Compose file in a directory closed to root, and validate both under the deploy lock. A refused candidate stops the run with the host as it was.
4. Mark every class that is due `pending`, then place every file: the Compose file and CrowdSec's files by `copy`, the acquisition directory pruned, the Caddyfile's owner and mode set. The mark comes first, so a run that dies while placing leaves the class due, not a class that looks hand-delivered. The Compose class is marked whenever its file differs, including while its unit is not enabled (then it is placed and left `pending`, and acted on once the unit is enabled).
5. Act, under the deploy lock, in this order: write the Caddyfile in place, restart the unit, restart CrowdSec, reload Caddy. The unit comes before Caddy's reload so a `compose.yml` change that the Caddyfile relies on (a port, a mount) exists first, and every file is on the host before any container action, which also means a bind source that is a file is never missing when Docker looks for it.
6. Write the stamps for what was read back, then fail the run if the locked step failed.

**Adoption.** A class with no stamp whose files equal the repository's is adopted: the stamp is written and nothing is acted on. This is the first run on the hand-delivered edge. If one class differs, only that class is acted on. The Compose class is adopted only while its unit is enabled; a unit that is not enabled is the owner's first start, so the role places the files and says so, and writes no Compose fingerprint: a Compose file that differs is placed and the class is left `pending`, so it is never adopted and is acted on (the unit is restarted) on the first run after the unit is enabled, whether or not the owner started it. Named limit: adoption trusts the files, not the containers. A host whose files equal the repository's but whose containers are running older configuration is adopted, not repaired. The owner's step that applies a config the containers do not have is a restart of the unit.

**What it does not do.**

- It never runs `docker compose up`. The unit `branchleft-compose@edge.service` is the only path that does (`up -d --remove-orphans --wait`, no force-recreate), and the role only restarts it. `branchleft-deploy` restarts the same unit when the image digest changes, so `edge.image.env` is in no fingerprint.
- It never writes `/etc/branchleft/edge.image.env` (`branchleft-deploy` does) and never writes `/etc/branchleft/edge.env` (the owner places it). No value of `edge.env` comes into the Ansible run or its log; "Environment semantics" below says which processes read the file on the host. Only its sha256 comes back, for the Compose fingerprint, so a rotated key reaches the containers by restarting the unit, which recreates them. Every task that handles that hash has `no_log: true`.
- It never restarts Caddy for a config change, and it does not apply a posture flip. A posture flip (`docker restart` of Caddy, RUNBOOK-edge 10a) stays an owner step, verified by step 8a.
- It starts no unit that is not enabled, installs no package, and removes nothing outside `crowdsec/acquis.d`.
- It has no saved-file or rollback path (see "Rollback").

## Interface

The inputs, their types and defaults are in `meta/argument_specs.yml`; Ansible checks them when the role starts. None is a secret.

| Variable                            | Default                       | What it is for                                                                                      |
| ----------------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------------- |
| `edge_stack_source_dir`             | `{{ role_path }}/files/stack` | The stack directory. Only the container test changes it.                                            |
| `edge_stack_lock_timeout`           | `600`                         | Seconds to wait for the deploy lock before failing with exit code 75 and changing nothing under it. |
| `edge_stack_crowdsec_wait_tries`    | `24`                          | Times CrowdSec's Local API is asked whether it answers after the restart.                           |
| `edge_stack_crowdsec_wait_interval` | `5`                           | Seconds between those asks.                                                                         |

The paths, the stamp names, the classes and the pin pattern are constants in `vars/main.yml`, not inputs: a caller cannot override them. The role has no `dependencies` (ANS-12); the playbook `playbooks/edge1.yml` lists it after `pull_trigger`.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- A host with Docker, Docker Compose v2, `flock` (util-linux), systemd, and the unit `branchleft-compose@.service` from `hetzner/provision`. Nothing installs these here.
- On the host, before a live apply: `/etc/branchleft/edge.env` placed by the owner (root, mode 0600, a regular file), and `/etc/branchleft/edge.image.env` written by `branchleft-deploy` (exactly one `IMAGE=<reference>@sha256:<64 hex digits>` line). The role refuses to run without either and says which.

## What it changes on a host

- `/opt/branchleft/edge`, `crowdsec` and `crowdsec/acquis.d`: root:root, mode 0755. Every file in them: root:root, mode 0644. A container reads its bind-mounted configuration as its own user, so a tighter mode would break it. The shell copy this role replaces made the same modes (rsync `--no-owner --no-group --chmod=u=rwX,go=rX`).
- `/var/lib/branchleft` (0755; monitoring_stack creates it in the same mode, so whichever runs first creates it) and the three stamps in it (0600).
- Candidates, while the role runs, in `/var/lib/branchleft/edge.candidate` (root, 0700), removed at the end of every run, a failed one included. A leftover would make the next check-mode run report a change.
- The Caddyfile on a host that has none is created by the locked script, root:root 0644, before it is written, so Docker never creates a directory where the single-file mount expects a file.
- Calls: `docker run --rm` (validate, nothing contacted, no certificate issued), `docker compose ... config -q`, `systemctl restart/is-active`, `docker compose ... restart crowdsec`, `docker compose ... exec` (read-backs, `caddy reload`, `cscli lapi status`). Compose is always given the project directory and both env files, exactly as the unit has them, so `${IMAGE}` and the required keys interpolate.

### Classes

A file added to `hetzner/edge/stack` is refused until it is in a class: add it to `vars/main.yml` (Caddyfile, Compose file and the single CrowdSec config are named there; a file directly in `crowdsec/acquis.d` is CrowdSec's with no edit). A link is refused. A file removed from the repository stays on the host, as in the sibling roles, except under `crowdsec/acquis.d`, the one directory the role prunes: a file there that the repository does not hold is a CrowdSec configuration nobody reads in the repository. A stale file anywhere else under `/opt/branchleft/edge` is the owner's to remove.

### Why the Caddyfile is written in place

`compose.yml` bind-mounts the Caddyfile as a single file. A rename (what `copy` does) leaves the container holding the old inode, so Caddy would reload bytes it already has. The locked script writes `cat candidate > file`, so the inode the container's mount holds is the one that changes; no reload or restart can read a half-written file, because the write is under the same lock as the reload. Named limit: a power cut during the write can leave a torn file. The next run sees it (the host file differs from the repository's), and rewrites it, but a reboot before that run would start Caddy on the torn file. Accepted.

### The locked script

All locked work is in `files/edge_apply.sh`, run as `flock -E 75 -w <timeout> /etc/branchleft/edge.deploy.lock /bin/sh -ec <script>`, once to validate and once to apply. The lock is the same kernel lock `branchleft-deploy` takes (`flock(1)` and `flock(2)` are one lock), so a deploy and this role cannot run their actions together. The script reads `edge.image.env` again inside the lock and refuses a pin that is not exactly the pattern, so a digest that changes while the role waits is never used. `-E 75` makes a timeout distinguishable from a failed action: the script never exits with 75.

Why a script and not shell tasks: an Ansible task cannot hold a lock across tasks, and the decision is that one lock covers the pin read through the last action of a section. The standard discourages shell beyond basic commands (SH-3); this is the single justified exception, the smallest thing that can hold one lock around an ordered sequence of `docker` calls and read them back, and it holds no value of a secret.

Exit codes: 64 the pin or the mode is wrong; 65 the candidate Caddyfile is refused; 66 the Caddyfile could not be written in place; 67 the candidate Compose file is refused; 68 the unit restart failed; 69 the unit is not active, or a service is not running, after the restart; 70 the CrowdSec restart failed; 71 CrowdSec's read-back failed; 72 `caddy reload` failed; 73 the Caddyfile inside the container is not the one on the host; 75 the lock was not free in time.

**Lock windows.** The role gives up after `edge_stack_lock_timeout` (600 s); `branchleft-deploy` waits up to 1260 s for the same lock. Two windows remain between the two locked sections and inside the apply: between the validation and the apply (files are placed between them, unlocked), and between the Caddyfile write and the reload, in which a deploy may roll back and restart Caddy. For Caddy this is harmless (the restart reads the new, already validated file). For the unit, a deploy that restarts it in a window restarts it with the files the role placed, which is the state the role intends. The apply re-checks the pin inside its own lock.

### Check mode and drift

Everything that decides runs in check mode: the classification, the hashes, the stamps, the unit state. The locked script is skipped in check mode, so each class that would be acted on is reported by a task that does nothing and reports `changed`: "the Caddyfile would be validated, written and reloaded", "the edge unit would be restarted", "the crowdsec container would be restarted". The plan job and the nightly drift check show those lines, so a plan is not silent for the file that terminates TLS. A file on the host that differs from the repository is shown by `copy` (diff) or reported by those tasks. Adoption is a stamp written, which also shows in a plan.

The harness runs the role in check mode before anything is applied (`check-fresh`) and again against the configured host (`check-configured`, zero changes expected).

### Rollback

There is no saved-file path (the shell runbooks had one, edge-ghost-setup-refusal section 6 and edge-portal-routes section 7). Rollback is: revert the commit and run the gated workflow. The role then writes the older files and acts on the classes that differ. Two things to know. A `compose.yml` that parses (`docker compose config -q` checks syntax and interpolation only) but breaks the stack stays on the disk after the unit restart fails, so the fix is forward, and a reboot starts the unit from that file. A failed run leaves the pending stamps, so the next run acts again.

### Environment semantics

**Who reads `edge.env`, and what comes back.** On the host, as root, four things read the file, and none returns its content to Ansible:

- the Ansible `stat` task in `_assert.yml` (with a checksum) reads the whole file to hash it; the sha256 is the only thing that comes back, and it goes into the Compose fingerprint and the Compose stamp;
- Docker Compose reads and parses it, because the locked script passes `--env-file /etc/branchleft/edge.env` to every Compose call: `config -q` on the candidate Compose file in the validation, and `ps`, `exec` and `restart` in the apply. The values stay inside the Compose process. `config -q` prints nothing when it succeeds, and the script prints no value. If Compose fails, its error text is shown in the failure message as Compose wrote it; the role does not filter it;
- systemd reads it as the unit's `EnvironmentFile=` when the unit is restarted (the unit's own behaviour, not this role's);
- the containers receive the values Compose interpolates, which is what the file is for.

The script itself never opens the file (no redirect, `cat` or `source`), and the Caddy validation does not use it.

The consumers read quotes differently: `docker run --env-file` keeps them literally, the unit's `EnvironmentFile=` and Compose strip them. The Caddy validation therefore passes placeholder values (`validation-only`, `validation@example.invalid`) for the two keys instead of `--env-file`, which parses and adapts the Caddyfile without contacting anyone. A quoted `ACME_EMAIL` is therefore not caught by the Caddy validation; it is the owner's to place unquoted. The role does not read `edge.env` to check for quotes: bringing a secrets file's content into the run is a decision for the owner, not the role.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes, one command runs lint, yamllint, the interface checks and the container test:

```text
python3 ansible/harness/run_harness.py ansible/roles/edge_stack
```

The container is a systemd platform. The test installs stand-ins and proves wiring only, never the live behaviour:

- a stand-in `docker` that logs every call, checks the arguments Compose needs, answers `run ... caddy validate` and `compose config`, models the container's single-file mount as a hard link (so a rename leaves the view on the old bytes and an in-place write does not), and fails or lies where a flag file in `/run` asks;
- a placeholder `branchleft-compose@.service` whose start logs the hash of the Caddyfile and the Compose file on the host at that moment, so the test can see both were placed first.

`verify.yml` has one block per behaviour, tagged `p0` to `p25` (and `p9b`, `p11c`, `p11d` and `p20c`), each starting from the converged host and asserting on the stand-in's calls, the stamps and the files. A block can be run alone with `ANSIBLE_RUN_TAGS=p7 molecule verify`. The Ansible log of every run of the scenario is scanned at the end for the sentinel values of the test's `edge.env`.

`ansible/checks/test_edge_single_home.py` fails when another role names `/opt/branchleft/edge`, delivers from the stack directory, or names `branchleft-compose@edge` (the drop-in directory `branchleft-compose@edge.service.d` is allowed, for the edge override).

### Named limits

- The stand-ins prove the role's wiring, not Docker, Caddy, CrowdSec or systemd. That `docker compose config -q` agrees with the real one, that `caddy validate` finds what the stand-in's marker finds, and that CrowdSec's API answers are live facts.
- The in-container sha proves the mount sees the new bytes, not that Caddy loaded them. That is the exit status of `caddy reload`. A live apply puts both on the issue: the in-container sha equal to the repository's, and the reload's exit status.
- Posture flips are not applied.
- A torn Caddyfile after a power cut (above).
- The read of `edge.image.env` is early (a pin the role refuses stops it before anything changes) and again inside each lock; between them a deploy may change it, which the second read refuses.

### Differences from the monitoring_stack family

The shape is the same. It differs, on purpose: three stamps named `edge.<class>.applied` against one `monitoring.applied`; the Compose fingerprint includes the hash of `edge.env` (monitoring's does too, by its own list); the unit is restarted if it is enabled, whatever its active state, so a `failed` unit with a corrected file is restarted; the Caddyfile has its own validation and an in-place write under the lock; the stamp tasks are in this role's `_stamp.yml`. A shared home for the stamp tasks is filed as its own ticket (`ansible/patterns` has no library use yet and ANS-12 keeps composition in playbooks); until it lands this is the second copy of the shape, written the same way as the first so the two can be diffed.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by running `ansible-playbook` by hand. edge1 pulls `playbooks/edge1.yml`, so a merge before the owner's bootstrap would run the role on a hand-delivered host; when to merge is the owner's call. The owner order for the first live apply:

1. edge1's bootstrap (the owner's step).
2. The owner places `/etc/branchleft/edge.env` (root, 0600). The role asserts it and fails the run loudly until it is there.
3. `branchleft-deploy` writes `edge.image.env` with the live digest.
4. The check-mode output for edge1 is put on the PR before the approval; every class that would be acted on is named in it.
5. The gated run on `main`, after the monitoring stack's `edge.override.conf` has landed.

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together.
2. Keep every task that decides able to run under `--check --diff`; keep the locked script as the only place an action runs.
3. A new file in `hetzner/edge/stack` needs a class (above). A change to the Caddyfile, the Compose file or the CrowdSec files changes only that class's fingerprint, so only its action runs; keep it so.
4. Extend `verify.yml` with a block for the new behaviour, and prove it by sabotage: break the code, see the block go red, restore, see it green.
5. Run the command under "How to test it" before opening a pull request.
