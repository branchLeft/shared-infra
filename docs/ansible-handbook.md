# Ansible estate handbook

HANDBOOK_INTRO_TEXT

## Layout

LAYOUT_INTRO_TEXT

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

MAKE_ROLE_INTRO_TEXT

```text
.venv/bin/ansible-galaxy role init --role-skeleton ansible/role_skeleton --init-path ansible/roles YOUR_ROLE_NAME
```

### Test a role

TEST_ROLE_INTRO_TEXT

```text
python3 -m venv .venv
.venv/bin/pip install --require-virtualenv --require-hashes --only-binary=:all: -r ansible/checks/pip-requirements.txt
.venv/bin/pip install --require-virtualenv --require-hashes --only-binary=:all: -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/roles/example_config
```

Pass `--scenario NAME` to run another scenario from `molecule/NAME/`. The harness runs these steps in order: `min-version`, `argument-specs`, `scenario-limits`, `ansible-lint`, `yamllint`, `create`, `prepare`, `check-fresh`, `converge`, `idempotence`, `verify`, `check-configured`, `molecule-check`, `destroy`.

### Debug a role

DEBUG_ROLE_INTRO_TEXT

The harness prints one line per step, with the reason beneath each failed step. `destroy` always runs. A run that is killed outright leaves its container, found by the `branchleft.role-test-run` label.

### Change a role

CHANGE_ROLE_INTRO_TEXT

These paths are owner-only in `.github/CODEOWNERS`: `ansible/checks/`, `ansible/harness/`, `ansible/trust/`, `ansible/roles/pull_trigger/`, `ansible/roles/ansible_runtime/`, `.ansible-lint`, `ansible/pyproject.toml`, `ansible/requirements.in`, `ansible/requirements.txt` and `ansible/requirements.yml`.

## The gate

GATE_INTRO_TEXT

| Event            | Workflow                                          | What runs                                                                                                              |
| ---------------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Pull request     | `.github/workflows/ansible.yml`                   | Lint, then the shards of changed roles. Required check: `Lint and test the Ansible roles`.                             |
| Merge queue      | `.github/workflows/ansible.yml`                   | Lint and every shard.                                                                                                  |
| Push to `main`   | `.github/workflows/ansible-delivery.yml`          | Calls `branchLeft/github-workflows` `ansible-gated-apply.yml` at `v1.0.16`, then waits on environment `ansible-hosts`. |
| Daily, 05:41 UTC | `.github/workflows/ansible-environment-probe.yml` | Reads the protection of `ansible-hosts` and judges it with `ansible/checks/check_delivery.py environment`.             |

The delivery workflow re-runs lint and Molecule over every role and pattern, unless the merge queue already tested the same commit (`ansible/checks/merge_group_proof.py`). Each host is asked, in check mode, what the commit would change, before the environment approval.

GATE_READ_RUN_TEXT

## The pull

PULL_INTRO_TEXT

| Path                          | Contents                                                                            |
| ----------------------------- | ----------------------------------------------------------------------------------- |
| `ansible/roles/pull_trigger/` | Installs `/usr/local/sbin/pull-trigger`, config in `/etc/pull-trigger/config.json`. |
| `ansible/playbooks/HOST.yml`  | One playbook per host on the signed route: `edge1`, `app1`, `db1`, `ops1`, `demo1`. |
| `ansible/trust/HOST.yml`      | Signer list for that host. Empty list means the host refuses every run.             |
| `ansible/playbooks/includes/` | Shared pull values and refusals, defined once.                                      |

`ansible/playbooks/demo1.yml` is enrolled like the others: the two pull roles, its trust file `ansible/trust/demo1.yml`, then `ansible/roles/demo1_build` and `ansible/roles/demo1_egress_spool`. demo1 never fetches: its commit arrives by push, as a git bundle CI sends through edge1, and the trigger checks it against the same trust file. `host_baseline`, `egress_nat` and `broker_deploy` are not applied to it.

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

DRIFT_INTRO_TEXT

| Workflow                                    | Trigger              | Behaviour                                                                                                                                  |
| ------------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `.github/workflows/ansible-drift-check.yml` | `17 3 * * *`, manual | Calls `branchLeft/github-workflows` `ansible-drift-check.yml` at `v1.0.16` with host label `ansible-estate`. No environment, no apply key. |

The reusable workflow asks each host in check mode what an apply would change. It goes red on drift or on a refusal, and opens or comments on one issue. `ansible/checks/test_drift_caller.py` checks the caller's shape.

DRIFT_READ_RUN_TEXT

## Secrets and one-off patterns

SECRETS_INTRO_TEXT

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

ONEOFF_INTRO_TEXT

## Whiteboard defence per service role

WHITEBOARD_INTRO_TEXT

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
| `exporters_and_collectors` | [README](../ansible/roles/exporters_and_collectors/README.md) |
| `host_baseline`            | [README](../ansible/roles/host_baseline/README.md)            |
| `monitoring_stack`         | [README](../ansible/roles/monitoring_stack/README.md)         |
| `nextcloud_stack`          | [README](../ansible/roles/nextcloud_stack/README.md)          |
| `ntfy_pager`               | [README](../ansible/roles/ntfy_pager/README.md)               |
| `pull_trigger`             | [README](../ansible/roles/pull_trigger/README.md)             |
| `tunnel_account`           | [README](../ansible/roles/tunnel_account/README.md)           |
| `website_app1`             | [README](../ansible/roles/website_app1/README.md)             |

Each row's defence is a placeholder until the owner supplies it: ROLE_DEFENCE_PLACEHOLDER.
