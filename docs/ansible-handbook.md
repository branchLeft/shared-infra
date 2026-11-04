# Ansible estate handbook

This handbook is for someone new to the repository who has to write, test, change or deliver an Ansible role. Host state here is declared in roles that a person can read and change without an agent. CI proves each role in a container before it can reach a host, and a host applies a commit only after it has verified that commit itself. The sections follow that path: where things live, how to make, test, debug and change a role, the gate a change passes, the pull that applies it, the nightly drift run, how secrets and one-off steps are handled, and where each service role is explained.

## Layout

Everything Ansible lives under `ansible/`, plus two lint files at the repository root. The table says what each path holds. Roles and patterns are the code you will change most. The harness and the checks hold them to the standard, and most of those are owner-only (see "Change a role").

| Path                       | Contents                                                             |
| -------------------------- | -------------------------------------------------------------------- |
| `ansible/role_skeleton/`   | Skeleton copied by `ansible-galaxy role init --role-skeleton`.       |
| `ansible/roles/`           | One directory per role. `example_config` is the worked example.      |
| `ansible/patterns/`        | One directory per pattern, run by the harness like a role.           |
| `ansible/harness/`         | Test harness and its unit tests.                                     |
| `ansible/checks/`          | Pin, enrolment, delivery, role and path checks, with tests.          |
| `ansible/tools/`           | Record a new host's first boot is built from, and its tests.         |
| `ansible/inventories/`     | Inventory and group variables. `production` holds `edge1` and `db1`. |
| `ansible/playbooks/`       | One playbook per host. Shared pull values in `playbooks/includes/`.  |
| `ansible/trust/`           | One signer file per host, loaded only by its playbook.               |
| `ansible/requirements.in`  | The seven chosen tools, with exact pins.                             |
| `ansible/requirements.txt` | Hash-locked toolchain compiled from `requirements.in`.               |
| `ansible/requirements.yml` | Empty by design: no collection is fetched outside the lock.          |
| `.ansible-lint`            | Lint floor at the production profile.                                |
| `.yamllint`                | YAML floor.                                                          |

### Make a new role

Start from the skeleton, never from an empty directory. The command below copies `ansible/role_skeleton/` into `ansible/roles/`, which gives the new role an argument specification, defaults, a Molecule scenario and a README to fill in. Replace `YOUR_ROLE_NAME` with a name for the one service the role configures: one role per service. Then replace every placeholder the skeleton leaves, starting with the README. `ansible/roles/example_config` is the worked example to read beside it.

```text
.venv/bin/ansible-galaxy role init --role-skeleton ansible/role_skeleton --init-path ansible/roles YOUR_ROLE_NAME
```

### Test a role

A role is proven by the harness, which runs it in a container the way CI does. Set up once: create a virtual environment, then install the two hash-locked requirement sets, the checks' and the toolchain's. The flags refuse anything that is not pinned by hash or is not a prebuilt wheel. Then run the harness on the role directory.

```text
python3 -m venv .venv
.venv/bin/pip install --require-virtualenv --require-hashes --only-binary=:all: -r ansible/checks/pip-requirements.txt
.venv/bin/pip install --require-virtualenv --require-hashes --only-binary=:all: -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/roles/example_config
```

Pass `--scenario NAME` to run another scenario from `molecule/NAME/`. The harness runs these steps in order: `min-version`, `argument-specs`, `scenario-limits`, `ansible-lint`, `yamllint`, `create`, `prepare`, `check-fresh`, `converge`, `idempotence`, `verify`, `check-configured`, `molecule-check`, `destroy`.

### Debug a role

A failed harness run names the step that failed and says why. Start there instead of running it again. The steps run in the fixed order listed above, so the first red step is the one to fix.

The harness prints one line per step, with the reason beneath each failed step. `destroy` always runs. A run that is killed outright leaves its container, found by the `branchleft.role-test-run` label.

### Change a role

Most changes touch a role's own files and need only the ordinary review. The paths listed next are different: they decide what the estate trusts or how it is tested, so they are owner-only, and a pull request that touches one needs the owner to approve and merge it.

These paths are owner-only in `.github/CODEOWNERS`: `ansible/checks/`, `ansible/harness/`, `ansible/trust/`, `ansible/roles/pull_trigger/`, `ansible/roles/ansible_runtime/`, `.ansible-lint`, `ansible/pyproject.toml`, `ansible/requirements.in`, `ansible/requirements.txt` and `ansible/requirements.yml`. The Ansible loader directories are owner-only as well, at each level Ansible loads from: `library/`, `module_utils/`, `filter_plugins/` and the other loader names, at the top of `ansible/`, beside a playbook in `ansible/playbooks/`, in an imported playbook's directory, and in each role under `ansible/roles/`.

## The gate

Nothing reaches a host without passing the gate. The table lists the four events that run it: a pull request, the merge queue, a push to `main`, and a daily probe of the approval environment itself. Lint and tests come first, on the changed roles for a pull request and on every role for the merge queue. The delivery run that follows a merge is what carries the commit to the hosts.

| Event            | Workflow                                          | What runs                                                                                                                                                                                                                    |
| ---------------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pull request     | `.github/workflows/ansible.yml`                   | Lint, then the shards of changed roles. Required check: `Lint and test the Ansible roles`.                                                                                                                                   |
| Merge queue      | `.github/workflows/ansible.yml`                   | Lint and every shard.                                                                                                                                                                                                        |
| Push to `main`   | `.github/workflows/ansible-delivery.yml`          | Calls `branchLeft/github-workflows` `ansible-gated-apply.yml` at `v1.0.19`, then waits on environment `ansible-hosts`. The optional `ANSIBLE_PUSH_HOSTS` secret lists the hosts pushed to; empty means every host is pulled. |
| Daily, 05:41 UTC | `.github/workflows/ansible-environment-probe.yml` | Reads the protection of `ansible-hosts` and judges it with `ansible/checks/check_delivery.py environment`.                                                                                                                   |

The delivery workflow re-runs lint and Molecule over every role and pattern, unless the merge queue already tested the same commit (`ansible/checks/merge_group_proof.py`). Each host is asked, in check mode, what the commit would change, before the environment approval.

To read a delivery run, open the workflow named in the table and look at the row for each host: it says what the commit would change in check mode. The environment approval is the point where a person reads those rows. The environment's `prevent_self_review` rule means whoever merged cannot approve their own run, which is why changes go in through the merge queue and not by **Merge pull request**.

## The pull

A host does not wait for a workflow to do things to it with credentials of its own. The workflow only asks. The host runs a small program, `pull-trigger`, that decides whether the commit is acceptable and fetches it itself from a read-only remote. That keeps the trust decision on the host, against a signer list the host holds.

| Path                          | Contents                                                                            |
| ----------------------------- | ----------------------------------------------------------------------------------- |
| `ansible/roles/pull_trigger/` | Installs `/usr/local/sbin/pull-trigger`, config in `/etc/pull-trigger/config.json`. |
| `ansible/playbooks/HOST.yml`  | One playbook per host on the signed route: `edge1`, `app1`, `db1`, `ops1`, `demo1`. |
| `ansible/trust/HOST.yml`      | Signer list for that host. Empty list means the host refuses every run.             |
| `ansible/playbooks/includes/` | Shared pull values and refusals, defined once.                                      |

`ansible/playbooks/demo1.yml` is enrolled like the others: the two pull roles, its trust file `ansible/trust/demo1.yml`, then `ansible/roles/demo1_build` and `ansible/roles/demo1_egress_spool`. demo1 never fetches: its commit arrives by push, as a git bundle CI sends through edge1, and the trigger checks it against the same trust file. That sending arrives with shared-infra#511, which is not yet merged, so no bundle reaches demo1 until it lands. `host_baseline`, `egress_nat` and `broker_deploy` are not applied to it.

The program's steps for one request, from `ansible/roles/pull_trigger/README.md`:

1. Validates the request: one 40-digit lowercase commit id with mode `apply` or `check`.
2. Checks the host's playbook is on the allowlist, then takes a single-flight lock.
3. Fetches `main` only, from the configured read-only remote.
4. Refuses the commit unless it is an ancestor of the fetched tip of `main`.
5. Refuses a commit older than the last one applied (`last-applied`).
6. Verifies the commit signature against the allowlisted keys.
7. Checks out that commit into a fresh directory and checks the playbook path.
8. Runs `ansible-playbook` for this host only, with `--check --diff` in check mode.

The program prints one summary line, `pull-trigger verdict=... exit=... reason=... mode=... commit=... playbook=... changed=...`. The workflow reads exit status 0 as nothing more to change, which is the second pass that proves an apply converged.

## The drift run

The pipeline above runs when someone merges. The drift run covers the rest of the time. Every night it asks each host, in check mode, whether anything on the host differs from what `main` would apply, so a hand edit or a failed apply is found by a machine and not by the next person to deploy.

| Workflow                                    | Trigger              | Behaviour                                                                                                                                                                                                      |
| ------------------------------------------- | -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/ansible-drift-check.yml` | `17 3 * * *`, manual | Calls `branchLeft/github-workflows` `ansible-drift-check.yml` at `v1.0.19` with host label `ansible-estate`. The optional `ANSIBLE_PUSH_HOSTS` secret lists the hosts pushed to. No environment, no apply key. |

The reusable workflow asks each host in check mode what an apply would change. It goes red on drift or on a refusal, and opens or comments on one issue. `ansible/checks/test_drift_caller.py` checks the caller's shape.

A red drift run means a host would change, or refused the question. Read the issue the workflow opens or comments on: it names the host and the reason. A host that would change is fixed either by reverting the hand edit or by merging the change that makes the repository say what the host has. A refusal is read through the pull's own reasons, for example `rollback` or `unsigned`.

## Secrets and one-off patterns

A role never carries a secret in its variables, its logs or its diff. Secrets are run-time inputs: a value typed in, or a root-only file on the host, written out with mode `0600`, with `no_log: true` and `diff: false` on every task that touches them (clause ANS-16). The patterns below are the tested building blocks for that and for the other jobs roles repeat. Use one rather than writing the task again.

| Pattern                                    | Use                                                                                                                                           |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `ansible/patterns/secrets_and_no_log/`     | Writes a secret file, mode `0600`, from a run-time `value` or a root-only `source_file`. Tasks set `no_log: true` and `diff: false` (ANS-16). |
| `ansible/patterns/oneoff_guarded_tasks/`   | One-off step. Runs only when its tag is named and `oneoff_guarded_tasks_confirm` equals the step id. Writes a marker file after success.      |
| `ansible/patterns/program_and_timer/`      | Installs a program with a systemd service and timer.                                                                                          |
| `ansible/patterns/files_and_units/`        | Files, templates and systemd units.                                                                                                           |
| `ansible/patterns/compose_stack/`          | Compose stack delivery.                                                                                                                       |
| `ansible/patterns/packages_and_downloads/` | Packages and checksummed downloads.                                                                                                           |
| `ansible/patterns/firewall_nat_sysctl/`    | Firewall, NAT and sysctl rules.                                                                                                               |
| `ansible/patterns/sudoers_and_keys/`       | Sudoers fragments and `authorized_keys`.                                                                                                      |
| `ansible/patterns/typed_module/`           | Typed Python module for a role's own records.                                                                                                 |

Some steps must run once, and only when a person means it, such as a first-time import. `oneoff_guarded_tasks` is the pattern for them: the step runs only when its tag is named and a confirm variable equals the step's id, and it writes a marker file after success so it is not run twice by accident. A pulled host cannot be given extra variables on the command line, so the steps a host may run are listed in its owner variables, for example `pull_trigger_steps` for ops1.

## Whiteboard defence per service role

For each role that configures a service, its maintainer should be able to defend it at a whiteboard: say, without looking anything up, what it configures, what it deliberately leaves alone, which inputs it trusts, and how it fails. The README of each role is the written starting point for that defence, and the table links to every one.

| Role                       | README                                                        |
| -------------------------- | ------------------------------------------------------------- |
| `ansible_runtime`          | [README](../ansible/roles/ansible_runtime/README.md)          |
| `backup_restore`           | [README](../ansible/roles/backup_restore/README.md)           |
| `backup_worker`            | [README](../ansible/roles/backup_worker/README.md)            |
| `breakglass_grant_host`    | [README](../ansible/roles/breakglass_grant_host/README.md)    |
| `breakglass_mint_host`     | [README](../ansible/roles/breakglass_mint_host/README.md)     |
| `broker_deploy`            | [README](../ansible/roles/broker_deploy/README.md)            |
| `control_plane`            | [README](../ansible/roles/control_plane/README.md)            |
| `db1_backup_timers`        | [README](../ansible/roles/db1_backup_timers/README.md)        |
| `db1_grants`               | [README](../ansible/roles/db1_grants/README.md)               |
| `db1_stack`                | [README](../ansible/roles/db1_stack/README.md)                |
| `demo1_build`              | [README](../ansible/roles/demo1_build/README.md)              |
| `deploy_tooling`           | [README](../ansible/roles/deploy_tooling/README.md)           |
| `edge_stack`               | [README](../ansible/roles/edge_stack/README.md)               |
| `egress_nat`               | [README](../ansible/roles/egress_nat/README.md)               |
| `export_bundler`           | [README](../ansible/roles/export_bundler/README.md)           |
| `exporters_and_collectors` | [README](../ansible/roles/exporters_and_collectors/README.md) |
| `host_baseline`            | [README](../ansible/roles/host_baseline/README.md)            |
| `monitoring_stack`         | [README](../ansible/roles/monitoring_stack/README.md)         |
| `nextcloud_stack`          | [README](../ansible/roles/nextcloud_stack/README.md)          |
| `ntfy_pager`               | [README](../ansible/roles/ntfy_pager/README.md)               |
| `pull_trigger`             | [README](../ansible/roles/pull_trigger/README.md)             |
| `tunnel_account`           | [README](../ansible/roles/tunnel_account/README.md)           |
| `website_app1`             | [README](../ansible/roles/website_app1/README.md)             |

The defence of each role is the owner's to give, so this page links each README and does not write a defence on the owner's behalf.
