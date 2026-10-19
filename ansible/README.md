# Ansible

Host state is declared here, in roles a person can read and change without an
agent. The shape of everything in this directory is set by the Ansible stack
page of the standards repository (clauses ANS-1 to ANS-17).

This directory holds the pattern every role is built from: a role skeleton, a
test harness that proves a role in containers, and one worked role made from
the skeleton. It holds no host, no playbook and no role for a real
service yet; the inventory trees are empty by design.

## Layout

| Path               | What it is                                                             |
| ------------------ | ---------------------------------------------------------------------- |
| `role_skeleton/`   | The skeleton `ansible-galaxy role init --role-skeleton` copies.        |
| `roles/`           | One directory per role. `example_config` is the worked example.        |
| `patterns/`        | One directory per pattern, each a role the harness runs like `roles/`. |
| `harness/`         | The test harness, its unit tests and nothing else.                     |
| `requirements.txt` | The pinned Python tools (ANS-4). Code owners review a change.          |
| `requirements.yml` | The pinned collections (ANS-4). Code owners review a change.           |
| `vendor/`          | The vendored collection archives and their hashes (ANS-4).             |
| `checks/`          | The pin check and its unit tests (ANS-4).                              |
| `inventories/`     | The inventory and group-variable trees. Empty by design.               |
| `pyproject.toml`   | The Python floor for the harness: version, mypy strict, ruff (ANS-2).  |
| `../ansible.cfg`   | Where Ansible finds the installed collections (ANS-4).                 |
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
`meta/argument_specs.yml` and `README.md`. Nothing checks that the placeholders
are gone (see the limits below): the reviewer does.

The skeleton is two templates at once. A file ending in `.j2` outside
`templates/` is rendered once, by `ansible-galaxy role init`, with the role name
available as `role_name`; the runtime braces in it are written with `lb` and
`rb`, which the file defines at its top. Files under `templates/` are copied
verbatim and are the role's own Jinja templates, so they cannot name the role.
The skeleton's template reads `config_greeting`, a variable scoped to the one
task that renders it, which the task sets from the role's own prefixed variable;
every variable that crosses the role's boundary carries the role's name.

A tasks file whose name starts with an underscore is internal to the role: it is
included by another file and needs no entry point in `meta/argument_specs.yml`.
Every other file under `tasks/` does.

## Run the harness

Install the pinned tools into a virtual environment that is not committed
(`.venv` at the repository root is ignored by git). Python 3.12 or later is
needed, which is ansible-core's own floor for the machine that runs it:

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
```

The harness installs the collections for itself. To run `ansible-lint` or
`ansible-playbook` by hand, install them once from the vendored archives, with
no network, into the directory `ansible.cfg` names (the section on pins
below explains the form and the directory):

```text
(cd ansible && ../.venv/bin/ansible-galaxy collection install -r requirements.yml -p ../.ansible/collections)
```

Then one command runs everything for one or more roles:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/example_config
```

For each role it runs, in this order, and prints one line per step at the end,
with the reason beneath each failed interface or scenario check:

1. `min-version`: `min_ansible_version` is the pinned ansible-core.
2. `argument-specs`: `meta/argument_specs.yml` documents an entry point for
   every file under `tasks/` that does not start with an underscore.
3. `scenario-limits`: every `molecule/*/molecule.yml` stays inside the limits
   of ANS-15, read from the file before any container exists (below). A
   violation skips every container step, `destroy` included, so nothing is
   created or contacted.
4. `ansible-lint`: at the production profile, `--strict`, with the committed
   `.ansible-lint`.
5. `yamllint`: `--strict`, with the committed `.yamllint`.
6. `create`, `prepare`: Molecule starts one container and prepares it.
7. `check-fresh`: the converge playbook under `--check --diff` against that
   container before any real converge, so against a host no task has touched.
   It must complete; changes are expected and not counted. This is the state
   an approver's plan meets on a first apply.
8. `converge`: Molecule applies the role to the container.
9. `idempotence`: a second converge that must report zero changed tasks.
10. `verify`: the scenario's `verify.yml` asserts the outcome.
11. `check-configured`: the converge playbook under `--check --diff` against
    the configured container. It fails if any task would change, because an
    already configured host must show no drift.
12. `molecule-check`: Molecule's own `check` action, which ANS-15 requires. It
    recreates the container, converges for real and then runs the check-mode
    play, so it covers the configured state again and not the fresh one. The
    fresh state is covered by step 7 alone.
13. `destroy`: always runs, after a failure and after an interrupt too.

The static steps do not depend on each other or on the container steps. A
failed container step skips the later ones except `destroy`. The exit status is
non-zero if any step failed.

The harness's own tests, type check and lint run from `ansible/`, with the
virtual environment's Python because the harness reads YAML with the library the
tools bring. The pin check (below) is held to the same standard and run the
same way:

```text
.venv/bin/python -m unittest discover -b -s harness -p "test_*.py"
.venv/bin/python -m unittest discover -b -s checks -p "test_*.py"
.venv/bin/mypy harness checks
.venv/bin/ruff check harness checks
.venv/bin/ruff format --check harness checks
```

CI runs the same commands, the pin check, and the harness over every role. The workflow
(`.github/workflows/ansible.yml`) runs on every pull request and every push to
`main`, with no path filter, so its job always reports. The job's first step
decides whether a file under `ansible/`, the two lint files or the workflow
itself changed; when none did, the remaining steps are skipped and the job
passes.

## The scenario limits the harness reads

ANS-15 says a test never touches a host that already exists. The
`scenario-limits` step reads each scenario file and refuses:

- a driver other than `docker` or `podman` (so no `default` driver and no
  unmanaged scenario);
- the key `docker_host` anywhere (any case, so `DOCKER_HOST` in an environment
  block too), and the connection keys `ansible_host`, `ansible_ssh_host` and
  `ansible_connection`;
- an inventory that defines hosts or links of its own (group variables are
  fine: the platforms are the hosts);
- a platform without `pre_build_image: true`, or whose image is not pinned by
  digest;
- a platform that mounts a Docker or Podman socket;
- a platform that sets `privileged` or `capabilities` without a comment on the
  line above the key saying why (ANS-15 allows privilege with a stated reason);
- a role with no `molecule/default/molecule.yml`.

The harness also refuses a `DOCKER_HOST` that is not a local unix socket.

## The one privileged fact

Molecule's docker driver talks to the local Docker daemon, so the test
controls containers on that daemon: it creates one, runs the role in it and
removes it. On a developer machine that daemon is the developer's own. Nothing
else is mounted into the container, no socket is passed to it, and the role is
never applied to a host that is not that container.

Each run's container name is `role-test-` followed by a run id the harness
generates, and the container carries a `branchleft.role-test-run` label with
the same id. `destroy` removes only the containers named in that run's
scenario, so one run cannot remove another run's container, whether it is a
second role or a second session. An interrupt (Ctrl-C) runs `destroy` before
the harness exits. A run that is killed outright cannot, and its container can
be found and removed by that label.

## Pins, the vendored collections and the bump route

ANS-4 pins the toolchain and leaves four decisions to this work: where the
vendored copy lives, how Ansible and ansible-lint find it, how a check proves
it matches its pin, and how a Molecule scenario's dependency step is
configured. They are recorded here; each was established by running the tool,
and the commands are given so that a maintainer can run them again.

### What is pinned, and where

| What                                         | Where                           | Exact form                                |
| -------------------------------------------- | ------------------------------- | ----------------------------------------- |
| The Python tools, `ansible-core` among them  | `requirements.txt`              | `name==version`, one per line             |
| The collections                              | `requirements.yml`              | a vendored archive path and its `version` |
| The hash of each collection archive          | `vendor/collections/SHA256SUMS` | `sha256sum` format                        |
| The `ansible-lint` pre-commit hook, if any   | `../.pre-commit-config.yaml`    | `rev: v` and the `requirements.txt` pin   |
| Where Ansible looks for installed collection | `../ansible.cfg`                | `collections_path = .ansible/collections` |

### Where the vendored copy lives

`vendor/collections/` holds each collection as the archive Galaxy publishes,
byte for byte, beside `SHA256SUMS`. `requirements.yml` names each archive by
path and sets the exact `version` the archive must carry:

```yaml
collections:
  - name: vendor/collections/NAMESPACE-NAME-VERSION.tar.gz
    version: VERSION
```

`ansible-galaxy collection install -r requirements.yml` installs from those
paths and contacts no server. It also checks the version against the archive's
own manifest: an entry that says `9.9.9` beside a `2.2.2` archive is refused.
The paths resolve from the current directory, so the install runs from this
directory (run from the repository root, it reports that it cannot find the
archive). The harness already runs it from here, and CI's step sets the same
working directory.

Why archives and not an unpacked tree. An unpacked tree puts hundreds of
third-party YAML and Python files under `ansible/`. ANS-5 and ANS-6 require
ansible-lint and yamllint to run over every file there and forbid every route
that hides a file, so the tree would fail yamllint at the committed settings
(run `yamllint --strict -c .yamllint` over an installed copy to see it). An
archive is one binary file that neither tool reads, a bump replaces it, and its
hash is the one Galaxy publishes, so a reviewer can compare it with the source.
The cost is that a reviewer cannot read the collection's code in the diff: the
hash comparison and the check below stand in for that, and an installed copy is
there to read when the code matters. A git submodule was not chosen because a
checkout would then need the network, and a private Galaxy mirror because it is
a service to run.

This is a separate decision from the inventories, which ANS-13 leaves open (see
`inventories/README.md`).

### How Ansible and ansible-lint find it

They read an installed copy, not the archives. `../ansible.cfg` sets
`collections_path = .ansible/collections`, a git-ignored directory at the
repository root, and both tools read it from the current directory when run
from the repository root, as ANS-5 requires. `.ansible-lint` is unchanged. This
was established by running `ansible-lint --strict` over a playbook that uses
`ansible.posix.sysctl`: it fails with `syntax-check[unknown-module]` while
nothing is installed, passes once the collections are installed into
`.ansible/collections`, and fails again with `ansible.cfg` removed.

The harness and CI set `ANSIBLE_COLLECTIONS_PATH` to a directory of their own,
which takes precedence over the file, so they do not depend on it. A scenario
run with `molecule` directly from a role directory does not see the repository
root's `ansible.cfg`; run roles through the harness.

### How a check proves the copy matches its pin

`checks/check_pins.py` runs in CI and by hand:

```text
.venv/bin/python ansible/checks/check_pins.py
```

It fails when:

- a line in `requirements.txt` is not `name==version` (a range, `~=`, a
  wildcard, a bare name, an include or a marker), or a named tool is missing;
- an entry in `requirements.yml` is not a vendored archive path with an exact
  `x.y.z` version and nothing else (no `source`, no `type`), or the file pins
  anything but collections;
- an archive is missing, differs from its line in `SHA256SUMS` by one byte, or
  holds another collection or version than the entry names;
- a collection declares a dependency that is not pinned as well, or is pinned
  outside the range it asks for, because installing would then need the network;
- an archive or a hash line has no entry (a stale file left behind);
- `ansible.cfg` holds anything but the one `collections_path` setting;
- a Molecule scenario under `roles/`, `patterns/` or `role_skeleton/` does not
  set `dependency: enabled: false`;
- the `ansible-lint` hook in `.pre-commit-config.yaml`, when there is one, is
  not at `v` and the `requirements.txt` pin, or is taken from another
  repository.

The hashes were checked against the `artifact.sha256` Galaxy publishes for each
version when the archives were first vendored (the bump route below repeats
this). The check proves that an archive is the recorded one, not that the
recorded hash was right.

### How a scenario's dependency step is configured

Molecule's `dependency` step is first in its default sequences, and its default
manager is Galaxy. Run with the step on, the vendored copy not installed, no
requirements file and the network closed, it fails: it runs `ansible-galaxy collection install community.docker`
at a range, to get the docker driver's collection, and tries to reach Galaxy.
With the vendored copy installed and on `ANSIBLE_COLLECTIONS_PATH` it reaches
nothing and reports that its requirements files are missing. A scenario that
brings its own `collections.yml` naming a collection that is not vendored
reaches Galaxy again. So every scenario sets `dependency: enabled: false`, as
the skeleton does, with the harness installing the vendored set before Molecule
starts, and the check above fails a scenario that does not.

### Install with no network

```text
(cd ansible && ../.venv/bin/ansible-galaxy collection install -r requirements.yml -p ../.ansible/collections)
```

CI runs the same command with its proxy pointed at a closed port, so an entry
that needs a server fails the job. The pip install of the tools still reaches
the package index; only the collections are vendored.

### The bump route

A version changes in a deliberate pull request, and CODEOWNERS makes the
repository owner its reviewer. Nothing raises a collection bump (ANS-4's named
limit), and Dependabot raises no Ansible pins in this repository.

For a tool in `requirements.txt`:

1. Change the pin.
2. If it is `ansible-lint`, change the `rev` of its pre-commit hook to `v` and
   the same version in the same pull request. No such hook exists yet; the
   check compares it as soon as one does.
3. If it is `ansible-core`, change `min_ansible_version` in every role's
   `meta/main.yml` (the harness's `min-version` step fails otherwise), and read
   every collection pin against the new core in the same pull request.
4. Run the check, then the harness.

For a collection:

1. Download the new archive: `ansible-galaxy collection download
NAMESPACE.NAME:VERSION --no-deps -p DIRECTORY`.
2. Compare its hash with Galaxy's: read `artifact.sha256` from
   `https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/NAMESPACE/NAME/versions/VERSION/`
   and run `shasum -a 256` on the archive.
3. In `vendor/collections/`, delete the old archive and add the new one. If the
   new version declares a dependency that is not vendored yet, add that archive
   the same way.
4. Update the entry in `requirements.yml` (the path and the `version`) and
   rewrite `SHA256SUMS` from that directory with `shasum -a 256 *.tar.gz >
SHA256SUMS`.
5. Run the check, the install above, and the harness.

The pin, the archive and the hash change together, or the check fails.

### What this does not prove

- The Python tools' own dependencies are not locked: pip resolves them from the
  index on every install.
- The check reads each archive's `MANIFEST.json` and trusts the archive hash for
  the rest. It does not read a collection's code.
- The check runs in CI and by hand, not in pre-commit.
- ANS-5 says lint runs in pre-commit as well as CI. This repository has no
  ansible-lint hook yet, so no rev is compared; the check says so on every run.
- Nothing re-checks Galaxy after a collection is vendored, so a later change
  upstream is not noticed, which is the intent of vendoring.

## What the harness proves, and what it does not

These are named so that a maintainer does not read a green run as more than it
is.

- **It proves "reports zero changes", not "changes nothing".** The idempotence
  step reads the changed count Ansible reports. A `shell` task with
  `changed_when: false` that appends to a file on every run reports zero and
  passes, and ansible-lint at the production profile does not refuse it when the
  command uses shell features. ANS-3 forbids `shell`, `raw` and `script` in a
  role, but its check is not scripted here, so review is what closes it.
- **A silent skip under check mode passes.** A task wrapped in
  `when: not ansible_check_mode` runs in neither check step, and nothing fails.
  ANS-10 asks for a stated reason on every such skip; review is what checks it.
- **The scenario check reads one file.** It does not read Molecule's own base
  configuration, an `ansible.cfg`, the converge or verify playbooks, or the
  environment of the machine, so a path to another host outside
  `molecule.yml` is not seen.
- **The skeleton's platform cannot test a service.** It is a `python:3.12-slim`
  container with no init system, so a role that manages a unit or starts a
  service needs a different platform, which the author chooses and justifies in
  the scenario file.
- **Placeholders are not checked.** `AUTHOR_NAME`, `LICENSE_ID` and
  `REPLACE_WITH_ONE_SENTENCE` pass lint and the harness unedited, because a
  freshly made role must pass both with no edit. The reviewer is what stops a
  role reaching `main` with them.
- **Nothing raises a bump of the image digest.** Dependabot's docker ecosystem
  does not read `molecule.yml`, so the digest ages until someone bumps it.

## What is not built yet

These are named so that a maintainer does not mistake their absence for an
oversight. Each is a decision the standard assigns to later work.

- **Transitive pins.** `requirements.txt` pins the tools by exact version, but
  the tools' own dependencies are not locked.
- **The pre-commit hooks.** ANS-5 and ANS-6 say lint runs in pre-commit as well
  as in CI. The only change to `.pre-commit-config.yaml` here exempts the
  vendored archives from the large-file hook; only the CI run is wired.
- **The standard's own checks.** Of the checks the standard's check plans
  describe, the scenario limits and the pins are scripted. No `shell` tasks and
  no loosened lint file are still review.
- **Inventories.** The trees under `inventories/` are empty by design, and their
  layout is a proposal.
- **A required check.** The Ansible job runs on every pull request, so it can be
  required (CI-14), but making it required is a repository ruleset change and
  belongs to the owner. Until it is done a red Ansible job does not block a
  merge on its own.
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
amd64 runner and on an arm64 workstation. A digest does not move on its own,
and the tag beside it is only a label that may since have moved to a newer
digest. Bumping the digest is a deliberate change that updates the digest and
nothing else.
