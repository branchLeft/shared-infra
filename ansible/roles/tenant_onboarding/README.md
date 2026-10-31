# tenant_onboarding

Makes one tenant's three Docker volumes and claims its UID on the application host.
It is the Ansible form of the host step of the tenant onboarding runbook that a person
ran by hand. The step is guarded: a plain apply does not run it, and it runs only when a
maintainer names its tag and its confirmation on the command line.

This README is written for a maintainer new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

1. A plain apply fetches the tenant volume program and its register from the
   ghost-platform repository at one pinned commit, and installs both root-owned with
   mode 0644 in `/opt/branchleft/app/provision`. Each fetch is checked against its pinned
   sha256, so a file whose bytes differ fails the apply. A plain apply runs no tenant step.
2. `PROVISION_TENANT_VOLUMES` runs the program with `--uid N`, once for one tenant. The
   program creates the tenant's three volumes (content, adapters and metrics), claims the
   UID in a root-owned register, and sets each volume's owner and mode. The program is the
   authority for the slug rules, the reserved names and the UID range; the role only types
   the two inputs.

It does not enable the tenant's compose unit. That step is an owner step for now (see the
open decision under "Named limits"). It does not create a database account, a database, a
media bucket or a credential, and it writes no secret. It does not write the tenant's
environment file, `compose.yml`, the deploy slot keys, the edge site block or the
`pull_trigger` step list; those are owner steps or other roles, named in the owner steps.
It does not wire itself into any host playbook: host wiring follows separately.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables.

- `tenant_onboarding_confirm`: the step id this run confirms, `PROVISION_TENANT_VOLUMES`.
  Empty on a plain apply.
- `tenant_onboarding_slug`: the tenant's slug for one request.
- `tenant_onboarding_uid`: the UID for one tenant, for `PROVISION_TENANT_VOLUMES`.

The slug and the UID are given on the command line for one run and are never committed.
The role reads no secret; no variable here holds a credential. The paths, the pinned commit,
the digests and the step id pattern are in `vars/main.yml`, not in the interface, because a
changed path would install a program the rest of the host does not run.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, and `min_ansible_version` in
  `meta/main.yml` equal to it.
- No collection beyond `ansible.builtin`.
- Target: a Linux host with `/usr/bin/python3` (the program is stdlib Python), a root
  account, and the Docker command the program calls for volumes.
- Before `PROVISION_TENANT_VOLUMES`: the plain apply has run, so the program is present.
  The step refuses by name when it is not.
- The compose file the tenant's unit runs (`compose.yml`) is delivered by the compose render
  role, which this role depends on by name only (ANS-12 forbids importing it). The compose
  file must be in place before the tenant's first deploy; this role does not check for it.

## What it changes on a host

- `/opt/branchleft/app/provision`: created root-owned, mode 0755.
- `/opt/branchleft/app/provision/provision_tenant_volume.py`: the program, root-owned, mode
  0644, its bytes the pinned ghost-platform file.
- `/opt/branchleft/app/provision/tenant-names.json`: the register the program reads beside
  itself, root-owned, mode 0644, its bytes the pinned file.
- With `PROVISION_TENANT_VOLUMES`, through the program: three Docker volumes named for the
  tenant, the claim directory `/etc/branchleft/tenant-uids` (root, 0700) and the tenant's
  claim file in it (root, 0600), and the owners and modes the program sets on each volume.
- No package, no user, no service, no secret file, no port and no firewall rule.

## The guard

The guarded step is imported with two tags, `never` and its own tag. A plain apply skips it,
and a request runs it only when its tag is named with `--tags`.

The step's first task refuses unless `tenant_onboarding_confirm` names its step id. A step
named by its tag but not confirmed stops the play with a message that begins `REFUSED:`, so
nothing runs silently. The step id is checked first, against the pattern in `vars/main.yml`,
and a confirmation with a line break is refused by name.

The step reads the UID claims through an import rather than an include, because an include
does not carry the step's tag into the tasks it runs. The guard is proven by the role's unit
test (`tests/unit/test_tenant_onboarding.py`): delete the step's confirmation assert or its
`never` tag and the test fails.

A request is made as a maintainer makes one, with the step's tag and its confirmation given
on the command line:

```text
ansible-playbook -i INVENTORY_FILE REQUEST_PLAYBOOK --tags tenant_onboarding_provision_volumes -e tenant_onboarding_confirm=PROVISION_TENANT_VOLUMES -e tenant_onboarding_slug=EXAMPLE_TENANT -e tenant_onboarding_uid=EXAMPLE_UID
```

Named with the tag and no confirmation, the same command stops with a `REFUSED:` message. A
plain apply is the command without `--tags` and without the confirmation.

## The log

A tenant value does not reach a log by the role's own output. The tasks that carry a slug or a
UID, and the program's output on success, are `no_log`. A refusal is the exception: it shows
the program's own message, which can name the tenant it is about (a UID held by another
tenant, for example). The scenario's verify play asserts that the canary tenant's name and
UID appear in no log the scenario writes, and it names refusals only with placeholder tenants.

## How it is delivered

Nothing applies this role to a host from a laptop. ANS-17 describes the only approved path: a
gated workflow run against `main`, which applies the role with a plan job before the approval
and a second run that must report zero changes. This role is not wired into any host playbook
by this change. Host wiring follows separately, after the rewiring of the host playbooks
(shared-infra#538), and needs two things the role does not supply: an entry in the host's
playbook, and a `host_inputs` row for the tenant list. Until then no step runs on any host.

## How it runs its test

`molecule/default` runs the role in a container (ANS-15). The scenario:

- fetches the program and register over the network from raw.githubusercontent.com at the
  pinned commit, so the container needs that network;
- stands in a fake `docker` command (`molecule/default/files/fake_docker.py`), since the
  program calls only volume commands;
- runs the plain apply, the refusals, the program's own refusals, a provisioning request, a
  second request that must change nothing, and the state each one leaves on the host, then
  scans the scenario's log for the canary tenant.

Run it through the harness:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/tenant_onboarding
```

`tests/unit/test_tenant_onboarding.py` runs with the role unit tests in CI.

## Owner steps

These steps need a value, a credential or a judgement only a person holds. The role does not
run them and writes no marker for them. Each is written with placeholders in capitals.

1. **Choose a free UID.** Run, on the application host as root:

   ```text
   /usr/bin/python3 /opt/branchleft/app/provision/provision_tenant_volume.py --list-claims
   ```

   Each line is `slug=uid`. A UID in the tenant range that no line names is free. The role
   does not check the host port the tenant uses; the owner records it.
   _Done when:_ the UID is written in the onboarding record and no line names it.

2. **Dispatch the tenant provisioning workflow and file its escrow ciphertext.** The workflow
   is named in the ghost-platform onboarding runbook (`RUNBOOK-tenant-onboarding.md`).
   _Done when:_ the workflow run is green and the ciphertext is filed in the escrow.

3. **Create the tenant database and its user on the database host.** A person runs this, and
   the password is printed once. The role's database step (`db1_grants`) does not mint an
   account. _Done when:_ the tenant can log in with its own account, and the password is held
   only in the escrow.

4. **Create the media bucket, its credential and its policy.** A person creates them in the
   object store. _Done when:_ the bucket exists and its credential is scoped to it alone.

5. **Hand over the secrets for the tenant's stack.** On a branch: set the stack's secrets with
   `pulumi config set --secret` (the database password, the media keys and the owner email),
   and record the host's public key in `known_hosts` from the host itself. _Done when:_ the
   handover branch carries no secret value, and the stack reads the values from its own
   configuration.

6. **Write the tenant's environment file.** As root, on the application host, write
   `/etc/branchleft/EXAMPLE_TENANT.env` with mode 0600, from `pulumi stack output` on standard
   input. Back up any file already there first; the ops runbook's blog credential rotation (its
   step 5) is the same write. _Done when:_ the file is root-owned, mode 0600, and the tenant's
   unit reads it.

7. **Mint the deploy slot keypair and grant it.** Run the deploy slot keys role's own procedure
   for the tenant's slot, then set `APP_HOST_DEPLOY_KEY` from the new public key. _Done when:_ a
   deploy as the slot key is accepted and any other command is refused.

8. **Enable the tenant's compose unit without starting it.** As root, on the application host:

   ```text
   systemctl enable branchleft-compose@EXAMPLE_TENANT.service
   ```

   Do not pass `--now`: the unit has no image pin until the tenant's first deploy. _Done when:_
   `systemctl is-enabled branchleft-compose@EXAMPLE_TENANT.service` prints `enabled` and
   `systemctl is-active branchleft-compose@EXAMPLE_TENANT.service` prints `inactive`.

9. **Register the edge site block.** Add the tenant's entry to the edge registry, as the edge
   runbook describes. _Done when:_ the tenant's hostname resolves through the edge.

10. **Merge the handover pull request.** The owner merges it. _Done when:_ the tenant's stack is
    in `main` and the gated apply has run.

11. **Teardown order.** To remove a tenant, reverse the steps: stop and disable the unit, remove
    the edge block, revoke the slot key, then remove the volumes and the claim only after the
    owner has the data. The program never frees a UID by itself. _Done when:_ no line of
    `--list-claims` names the tenant and its volumes are gone.

## Named limits

- **The enable step is not in this role (open decision).** The plan put enabling the compose
  unit here. The repository's single-owner check reads any reference to a unit that the
  deployment tooling role installs as a second owner. The owner rules who enables the unit:
  either an exemption for this role on the check's owner-held allow-list, or moving the step to
  the role that installs the unit. Until then the enable is owner step 8.
- **Ownership drift is repaired by a re-run and is not reported as a change.** The program sets
  each volume's owner and mode on every run. A re-run that repairs drift reports no change, so a
  drifted tenant shows as unchanged.
- **Command tasks are skipped in check mode**, except the read of the claims, which runs in check
  mode and reports no change. A check-mode request therefore shows no change for the program run.
- **The register pin can go stale.** The reserved-name register is pinned by digest. When
  ghost-platform changes it, a bump PR here must follow: a stale register is a reserved name the
  host does not know about.
- **A refusal can name another tenant.** A UID held by another tenant is refused with the
  program's message, which names the holder. That message reaches the log by design.
- **The step cannot be requested through the gated route yet.** `pull_trigger` takes a closed
  list of step ids for the control plane database, and a guarded step of this role is not on it.
  Until the owner-held `pull_trigger` change and the `host_inputs` row for the tenant list land,
  no step of this role runs on any host.
- **The program's own refusal messages are checked by their text.** A changed program message
  fails the scenario and is updated with the register bump.
- **The code owner of `ansible/` merges.** The change is reviewed and merged by the code owner
  named in `.github/CODEOWNERS`.

## Not covered

- The live run: the gated run's URL, a second run that reports zero changes, and the nightly drift
  run. These follow host wiring and a live run.
- The retirement of the hand sections in the ghost-platform onboarding runbook, the template and
  blog bootstrap runbooks, and the ops runbook's blog credential rotation. These follow the first
  live converge.
