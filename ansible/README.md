# Ansible

Host state is declared here, in roles a person can read and change without an
agent. The shape of everything in this directory is set by the Ansible stack
page of the standards repository (clauses ANS-1 to ANS-17).

This directory holds the pattern every role is built from: a role skeleton, a
test harness that proves a role in containers, and one worked role made from
the skeleton. It holds no inventory, no playbook and no role for a real
service yet.

## Layout

| Path               | What it is                                                             |
| ------------------ | ---------------------------------------------------------------------- |
| `role_skeleton/`   | The skeleton `ansible-galaxy role init --role-skeleton` copies.        |
| `roles/`           | One directory per role. `example_config` is the worked example.        |
| `harness/`         | The test harness, its unit tests and nothing else.                     |
| `requirements.txt` | The pinned Python tools (ANS-4).                                       |
| `requirements.yml` | The pinned collections (ANS-4).                                        |
| `pyproject.toml`   | The Python floor for the harness: version, mypy strict, ruff (ANS-2).  |
| `../.ansible-lint` | The lint floor, production profile (ANS-5). Not editable by a role PR. |
| `../.yamllint`     | The YAML floor (ANS-6). Not editable by a role PR.                     |

## Make a new role

From the repository root, with the tools installed as the next section
describes:

```text
.venv/bin/ansible-galaxy role init --role-skeleton ansible/role_skeleton --init-path ansible/roles YOUR_ROLE_NAME
```

The role name is lowercase letters, digits and underscores, starting with a
letter, and it is the prefix of every variable the role reads (ANS-7, ANS-12).
The generated role passes lint and the container test with no edit: it writes
one file from a template and one fixed file. Replace that content with the
service's, and replace every ALL_CAPS placeholder in `meta/main.yml`,
`meta/argument_specs.yml` and `README.md`.

The skeleton is two templates at once. A file ending in `.j2` outside
`templates/` is rendered once, by `ansible-galaxy role init`, with the role name
available as `role_name`; the runtime braces in it are written with `lb` and
`rb`, which the file defines at its top. Files under `templates/` are copied
verbatim and are the role's own Jinja templates.

## Run the harness

Install the pinned tools into a virtual environment that is not committed.
Python 3.12 or later is needed, which is ansible-core's own floor for the
machine that runs it:

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
```

Then one command runs everything for one or more roles:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/example_config
```

For each role it runs, in this order, and prints one line per step at the end:

1. `min-version`: `min_ansible_version` is the pinned ansible-core.
2. `argument-specs`: `meta/argument_specs.yml` documents an entry point for
   every file under `tasks/`.
3. `ansible-lint`: at the production profile, `--strict`, with the committed
   `.ansible-lint`.
4. `yamllint`: `--strict`, with the committed `.yamllint`.
5. `create`, `prepare`, `converge`: Molecule starts one container and applies
   the role to it.
6. `idempotence`: a second converge that must report zero changed tasks.
7. `verify`: the scenario's `verify.yml` asserts the outcome.
8. `check-configured`: the converge playbook under `--check --diff` against
   the already configured container. It fails if any task would change, because
   an already configured host must show no drift.
9. `check-fresh`: Molecule's own `check` action, which recreates the container
   and runs the converge playbook under `--check` against an unconfigured one.
10. `destroy`: always runs, after a failure too.

The static steps do not depend on each other or on the container steps. A
failed container step skips the later ones except `destroy`. The exit status is
non-zero if any step failed.

The harness's own tests, type check and lint run from `ansible/`:

```text
python3 -m unittest discover -b -s harness -p "test_*.py"
.venv/bin/mypy harness
.venv/bin/ruff check harness
```

CI runs the same commands, and the harness over every role, when a file under
`ansible/` changes (`.github/workflows/ansible.yml`).

## The one privileged fact

Molecule's docker driver talks to the local Docker daemon, so the test
controls containers on that daemon: it creates one, runs the role in it and
removes it. On a developer machine that daemon is the developer's own. Nothing
else is mounted into the container, no socket is passed to it, and the role is
never applied to a host that is not that container.

The harness refuses a `DOCKER_HOST` that is not a local unix socket, because
ANS-15 forbids a test that can reach another engine.

Each run's container name is `role-test-` followed by a run id the harness
generates, and the container carries a `branchleft.role-test-run` label with
the same id. `destroy` removes only the containers named in that run's
scenario, so one run cannot remove another run's container, whether it is a
second role or a second session. If a run is killed, its container can be
found and removed by that label.

## What is not built yet

These are named so that a maintainer does not mistake their absence for an
oversight. Each is a decision the standard assigns to later work.

- **Vendored collections and transitive pins.** `requirements.txt` pins the
  tools by exact version and `requirements.yml` pins the collections by exact
  version, but the collections are downloaded from the public index on every
  run, not vendored, and the tools' own dependencies are not locked. ANS-4
  names where vendoring and the pin of ansible-core for production are decided.
- **The pre-commit hooks.** ANS-5 and ANS-6 say lint runs in pre-commit as well
  as in CI. This directory does not edit `.pre-commit-config.yaml`; only the CI
  run is wired.
- **The standard's own checks.** The checks that the standard's check plans
  describe (no `shell` tasks, exact pins, no loosened lint file, scenario
  limits) are not scripted here, so they are review today.
- **Delivery.** Nothing applies a role to a host. ANS-17 describes the only
  approved path; the trigger and the reusable workflow it needs are separate
  work.
- **Reuse by other repositories.** The harness is code another repository may
  one day run. It is not to be copied between repositories (ANS-13). The
  reusable CI work in the github-workflows repository is where it will be
  lifted, and this copy moves there rather than being duplicated.

## Image pin

`role_skeleton/molecule/default/molecule.yml` pins the platform image by the
digest of its multi-architecture index, so the same reference runs on an
amd64 runner and on an arm64 workstation. A digest does not move on its own:
bumping it is a deliberate change that updates the digest and nothing else.
