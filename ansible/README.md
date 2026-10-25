# Ansible

Host state is declared here, in roles a person can read and change without an
agent. The shape of everything in this directory is set by the Ansible stack
page of the standards repository (clauses ANS-1 to ANS-17).

This directory holds the pattern every role is built from: a role skeleton, a
test harness that proves a role in containers, and one worked role made from
the skeleton. Its real hosts are `edge1` (`playbooks/edge1.yml`, which applies
`roles/ansible_runtime` and `roles/pull_trigger`) and `db1` (`playbooks/db1.yml`, which applies
`roles/db1_stack` and `roles/db1_grants`); the other trees hold only what those hosts need.

## Layout

| Path                  | What it is                                                             |
| --------------------- | ---------------------------------------------------------------------- |
| `role_skeleton/`      | The skeleton `ansible-galaxy role init --role-skeleton` copies.        |
| `roles/`              | One directory per role. `example_config` is the worked example.        |
| `patterns/`           | One directory per pattern, each a role the harness runs like `roles/`. |
| `harness/`            | The test harness, its unit tests and nothing else.                     |
| `requirements.in`     | The seven tools chosen on purpose, exact pins (ANS-4).                 |
| `requirements.txt`    | The hash-locked toolchain compiled from it, collections included.      |
| `requirements.yml`    | Empty by design: no collection is fetched outside the lock (ANS-4).    |
| `checks/`             | The pin, enrolment, delivery, role and path checks, with tests.        |
| `tools/`              | The record a new host's first boot is built from, and its tests.       |
| `inventories/`        | The inventory and group-variable trees. `production` holds edge1, db1. |
| `playbooks/`          | One playbook per host: selects hosts and lists roles (ANS-13).         |
| `playbooks/includes/` | The shared pull values and refusals, each defined once.                |
| `trust/`              | One signer file per host under the pull, loaded only by its playbook.  |
| `pyproject.toml`      | The Python floor for the harness: version, mypy strict, ruff (ANS-2).  |
| `../.ansible-lint`    | The lint floor, production profile (ANS-5). Not editable by a role PR. |
| `../.yamllint`        | The YAML floor (ANS-6). Not editable by a role PR.                     |

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
.venv/bin/pip install --require-virtualenv --require-hashes --only-binary=:all: -r ansible/checks/pip-requirements.txt
.venv/bin/pip install --require-virtualenv --require-hashes --only-binary=:all: -r ansible/requirements.txt
```

The first install is the one pip that `checks/test_lock_reader_parity.py` asks,
pinned in `checks/pip-requirements.txt`; without it that test fails on whatever
pip the virtual environment came with. The second installs the tools and the
collections the roles use, which come with the `ansible` package (the section
on pins below says why). Nothing else is installed, and `ansible-lint` and
`ansible-playbook` find the collections with no setting. Then one command runs
everything for one or more roles:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/example_config
```

`--scenario <name>` runs one other scenario of the role, from `molecule/<name>/`
(the default is `default`). The name is checked before anything runs: a name that
is not a plain directory name is refused, and a role without that scenario's
`molecule.yml` fails at `scenario-limits`, like a role without a `default` one.
The static steps read the whole role either way; the container steps run the
scenario named, every Molecule command with `-s <name>`, the final `destroy`
included, so a second scenario's container is always removed.

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

### Sharing steps between scenarios

Each scenario is its own shard with its own 25-minute limit. A role whose steps do not
fit one shard shares them out between its scenarios: a scenario's `skip-steps.txt`,
beside its `molecule.yml`, lists the steps its shard leaves out, one name per line,
and a line that starts with `#` is a comment. A scenario with no such file runs every
step. The leaving-out is shown, as `SKIP` in the summary, and not hidden.

Only `check-fresh`, `idempotence`, `verify`, `check-configured` and `molecule-check`
may be left out. `create`, `prepare`, `converge` and `destroy` are what any run needs.
A line that is not one of those five names fails `scenario-limits` and leaves nothing
out. So does a step that every scenario of the role leaves out: a role may share its
steps but not drop one, and the check reads every scenario's list whichever one the
run executes. The list is plain text and not YAML because `ansible-lint` takes any
YAML file in a scenario directory for a playbook.

A scenario that leaves out `verify` needs no `verify.yml`.

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
`main`, with no path filter, so its jobs always report. The first job decides
whether a file under `ansible/`, the two lint files or the workflow itself
changed (`ansible/` and `hetzner/` are watched whole); when none did, the other
jobs are skipped and the gate passes.

What runs, by event:

| Event          | Lint | Shards                                                                                                                                                                                    |
| -------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| pull request   | yes  | the roles and patterns it changed, those that name them, and those that read a changed file outside `ansible/`; every shard if the harness, checks, lock, lint config or workflow changed |
| merge queue    | yes  | every shard, whatever changed                                                                                                                                                             |
| push to `main` | yes  | none: the delivery workflow runs the harness before it applies anything                                                                                                                   |

The workflow has three kinds of job:

- `discover` runs `ansible/harness/list_shards.py`, which lists one shard for
  each scenario of every directory directly under `ansible/roles/` and
  `ansible/patterns/` (the `default` scenario first, then every other directory
  under `molecule/`), plus the fresh-role skeleton, from the repository tree. It
  prints the matrix as JSON, so no name is split by a line break. It fails if the
  list is empty, so the shard job cannot skip silently. A directory with no
  `molecule/` scenario still gets its `default` shard, and that shard fails at the
  `scenario-limits` step. A shard's name is the directory, and the directory and
  the scenario in brackets for any scenario but `default`, so names are unique.
  `ansible/checks/ci_select.py` then narrows that list by the table above (its
  docstring has the rules); any doubt keeps the shard.
- `lint` runs the static checks once: yamllint, ansible-lint, mypy, ruff and the
  harness's unit tests.
- `shard` runs the harness once for each entry `discover` kept, in parallel,
  with `--scenario` set to the entry's scenario, and only after `lint` has
  passed, so a lint error is red in minutes and starts no container. Each shard
  has its own time limit (25 minutes), so the run time does not grow with the
  number of roles in one job. A role whose one scenario would not fit in the
  limit puts its refusal cases in a second scenario, which is a second shard,
  not in a longer limit.

The gate job is named `Lint and test the Ansible roles`. The ruleset requires
a check with exactly that name, and a matrix job would report its checks under
other names, so the gate stays one job. It fails unless `discover` succeeded
and, when the Ansible inputs changed, `lint` succeeded and, when `discover`
chose shards, every chosen shard did. When nothing changed, `lint` and the
shards are skipped and the gate passes; when the lint passed and no shard was
needed, the shard job is skipped on purpose and the gate passes.

How to add a pattern: nothing to edit here. A directory directly under
`ansible/patterns/` or `ansible/roles/` is picked up by `discover` on the next
run. It needs a `molecule/default/molecule.yml` to pass its shard. A second
scenario is a directory `molecule/<name>/` with its own `molecule.yml`; it gets
its own shard, held to the same scenario limits. A second scenario that must share
the first's platform links its `molecule.yml` to `../default/molecule.yml`, so the
platform pin has one home.

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
- a role with no `molecule/default/molecule.yml`, or no `molecule.yml` for the
  scenario it is run with (a link to nothing counts as missing).

Every scenario directory under `molecule/` is read, not only the one being run, so
a second scenario cannot hold a privilege the default one is not allowed.

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

## Pins, the lock and the update route

ANS-4 pins the toolchain. The pins are in one hash-locked file, the collections
arrive inside it, and the route that keeps it current is automatic. Each choice
was established by running the tool, and the commands are given so that a
maintainer can run them again.

### What is pinned, and where

| What                                           | Where                         | Exact form                                                       |
| ---------------------------------------------- | ----------------------------- | ---------------------------------------------------------------- |
| The seven tools chosen on purpose              | `requirements.in`             | `name==version`, one per line, no hashes                         |
| Every Python package, `ansible-core` among     | `requirements.txt`            | `name==version` and one or more sha256 hashes                    |
| The collections the roles use                  | `requirements.txt`            | inside the pinned `ansible` package                              |
| That no collection is fetched outside the lock | `requirements.yml`            | the single line `collections: []`                                |
| The pip the parity test asks                   | `checks/pip-requirements.txt` | `pip==version` and one sha256 hash                               |
| What raises a bump                             | `../.github/dependabot.yml`   | a `uv` entry for `/ansible`, a `pip` entry for `/ansible/checks` |
| The `ansible-lint` pre-commit hook, if any     | `../.pre-commit-config.yaml`  | `rev: v` and the `requirements.txt` pin                          |

### Why `requirements.txt` is long, and that a tool writes it

`requirements.txt` is tool output, never edited by hand. `uv pip compile`
reads `requirements.in` and writes every package the seven tools need (51 of
them) with the sha256 of every published file of that version: one per platform
wheel, plus the source archive. That is why it runs to more than a thousand
lines (nine packages that ship a wheel per platform, such as `charset-normalizer`,
`markupsafe` and `cryptography`, carry about 930 of the hash lines), and it is
the integrity property: `pip install
--require-hashes` refuses a file whose hash is not listed, and a package that is
not listed at all. The header at the top records the command, and this
regenerates the file from the input:

```text
cd ansible && uv pip compile requirements.in --universal --python-version 3.12 --generate-hashes --output-file requirements.txt
```

`--universal` makes one lock for every platform and `--python-version` fixes the
floor, so a laptop and the CI runner resolve the same set. The header is kept
because it is the only record of those options. The `# via` comment under each
package says why it is there: `-r requirements.in` for the chosen seven, another
package's name for the rest. `ansible-core` is not chosen: the `ansible` package
fixes which release it needs, so it follows `ansible` and is pinned in the lock
only.

### Why the collections come with the `ansible` package

The roles use `ansible.posix`, `community.docker` and the filtering collection
`community.docker` depends on. The `ansible` package on PyPI bundles them, and
its release pins each one: `ansible` 14.5.0 carries `ansible.posix` 2.2.2,
`community.docker` 5.4.0 and `community.library_inventory_filtering_v1` 1.1.5
(read from the installed `ansible_collections/*/MANIFEST.json`, and listed in
the upstream build data at `14/ansible-14.5.0.deps` in
`ansible-community/ansible-build-data`), and requires `ansible-core~=2.21.5`,
which is the pinned core. So one hashed line fixes the Ansible engine and the
three collections together, and nothing is copied into git or fetched from
Galaxy.

Two routes were weighed and not taken:

- Galaxy pins in `requirements.yml` with a hash check of the download. Dependabot
  has no package ecosystem for Ansible collections (its supported list names
  `pip` and `pre-commit` among others, and nothing for Ansible or Galaxy), so
  nothing would raise a bump or a security update, and an entry in
  `requirements.yml` has no field for a hash. A scheduled workflow would have to
  be added and maintained for the update signal, and a separate step for the
  hash.
- Committing the collection archives. The copy is invisible to Dependabot and to
  an SBOM generator, and a fix upstream is never noticed.

### How Ansible and ansible-lint find the collections

They find them with no setting. The package installs them under the virtual
environment's `site-packages/ansible_collections`, which Ansible reads whatever
`ANSIBLE_COLLECTIONS_PATH` is set to (the harness points it at an empty
directory of its own). There is no `ansible.cfg` and `.ansible-lint` is
unchanged. To see what a given install carries:

```text
.venv/bin/ansible-galaxy collection list
```

### Install, and install with no network

```text
.venv/bin/pip install --require-virtualenv --require-hashes --only-binary=:all: -r ansible/checks/pip-requirements.txt
.venv/bin/pip install --require-virtualenv --require-hashes --only-binary=:all: -r ansible/requirements.txt
.venv/bin/pip check
```

`--require-hashes` makes pip refuse a package the lock does not name, and a
wheel whose hash is not listed. It does not by itself cover every file pip
runs: a package with no wheel for this machine's Python would be built from its
source archive, and the build backend that archive asks for is fetched from the
index with no hash, so code the lock never named would run on this machine.
`--only-binary=:all:` removes that build, so such a package fails the install
instead. A machine with no route to the package index installs from a copy of
the files, the same way:

```text
.venv/bin/pip download --require-hashes --only-binary=:all: -r ansible/checks/pip-requirements.txt -d WHEELHOUSE
.venv/bin/pip download --require-hashes --only-binary=:all: -r ansible/requirements.txt -d WHEELHOUSE
.venv/bin/pip install --require-virtualenv --require-hashes --only-binary=:all: --no-index --find-links WHEELHOUSE -r ansible/checks/pip-requirements.txt
.venv/bin/pip install --require-virtualenv --require-hashes --only-binary=:all: --no-index --find-links WHEELHOUSE -r ansible/requirements.txt
```

The two downloads run once where there is a network; the two installs need none.
The lock lists the packages for every platform, so a machine takes the files
for its own.

### How updates and advisories surface, with no one watching

`../.github/dependabot.yml` has a monthly `uv` entry for `/ansible`. The `uv`
ecosystem is the one that recompiles a lock made by `uv pip compile`: it finds
`requirements.in` beside `requirements.txt`, bumps the chosen pin in the input,
and reruns `uv pip compile` with `--generate-hashes`, `--universal` and the
Python version it reads from the lock's header, then writes the whole file back
under the original header. A new `ansible` release (which carries every
collection update), or a new release of any other locked package, therefore
opens a pull request that re-resolves the entire lock, and the Ansible workflow
tests it. The `pip` ecosystem would not do this: it runs `pip-compile`, which
has no universal mode, and it reads its options from a `pip-compile` header
that `uv` does not write. This was run, not only read, with the Dependabot CLI
against a copy of the lock one `ansible` release behind: the pull request it
produced changed the input pin and rewrote the lock to the file committed here,
byte for byte. The same run on a copy with the header removed compiled for the
runner's platform only: it dropped `pywin32` and the platform markers on three
packages and wrote no header, which is why the check refuses a lock without one. The entry groups minor and patch updates into one pull request;
a major version is a separate pull request (DEP-3). A
security advisory on a locked package is a Dependabot alert, a repository
setting that is not a file in git. The advisory database lists `ansible`
advisories that name a bundled collection, so a collection fix is covered by the
alert for the package that carries it.

`../.github/dependabot.yml` also has a monthly `pip` entry for `/ansible/checks`,
which reads the one-line pin in `checks/pip-requirements.txt` and opens a pull
request of its own for a new pip. That pull request fails the parity test until
the table in `checks/test_lock_reader_parity.py` is re-checked against the new
pip (`checks/README.md` says how), which is the prompt to do it.

`checks/check_pins.py` fails if the `uv` entry for `/ansible` or the `pip` entry
for `/ansible/checks` goes missing, so the route cannot be switched off by an
edit that looks unrelated.

### Where an SBOM reads the versions

The lock is the record: a generator or GitHub's dependency graph reads
`requirements.txt` and sees every package at its exact version. The collections
are part of the `ansible` package, so their versions follow from its version,
and the CI job prints `ansible-galaxy collection list` so the collection
versions of each run are in its log. A generator that wants the collections as
entries of their own reads that output or the `.deps` file named above.

### How a check proves the lock

`checks/check_pins.py` runs in CI and by hand:

```text
.venv/bin/python ansible/checks/check_pins.py
```

It fails when:

- a line in `requirements.txt` is not `name==version` with at least one
  `--hash=sha256:` of 64 hex digits (a range, `~=`, a wildcard, a bare name, an
  include, an editable install, a URL, an index option, or a pin with no hash),
  or a named tool is missing, or a package is pinned twice;
- `requirements.txt` starts with a byte-order mark or carries a `coding:` /
  `coding=` declaration in a comment on its first two lines (pip would read it
  in another encoding), or is not UTF-8 text. The check reads the lock with the
  reader of `roles/ansible_runtime/files/install_runtime.py`, loaded by path
  and not copied, so the install program and this gate read a lock one way
  (`checks/test_lock_reader_parity.py` holds that to pip's own code);
- `requirements.in` is missing, has a line that is not an exact
  `name==version`, does not name one of the seven chosen tools, or disagrees
  with the lock on a version;
- the lock's header does not record `uv pip compile requirements.in`,
  `--universal`, `--generate-hashes` and a `--python-version` (so a lock made
  with `--no-header` is refused), or a package in the lock has no `# via`
  comment, or the lock marks a package `-r requirements.in` that the input does
  not name, or the input names one the lock does not mark: every line of the
  lock is explained by the input or by another package;
- `requirements.yml` is anything but `collections: []`, so no collection or role
  is fetched outside the lock;
- an archive (`.tar.gz`, `.tgz`, `.tar`) or an `ansible_collections` tree sits
  anywhere under `ansible/`, a copy that the lock and an SBOM cannot see;
- `checks/pip-requirements.txt` is anything but one `pip==version` line with one
  `--hash=sha256:` of 64 hex digits (and comments): a range, a second package, a
  second hash, a marker or an option is refused;
- `../.github/dependabot.yml` has no scheduled `uv` entry for `/ansible`, or no
  scheduled `pip` entry for `/ansible/checks`;
- a Molecule scenario under `roles/`, `patterns/` or `role_skeleton/` does not
  set `dependency: enabled: false`;
- the `ansible-lint` hook in `.pre-commit-config.yaml`, when there is one, is
  not at `v` and the `requirements.txt` pin, or is taken from another
  repository.

CI also runs `pip check`, which fails when the pinned `ansible` package and the
pinned `ansible-core` disagree.

### How a scenario's dependency step is configured

Molecule's `dependency` step is first in its default sequences, and its default
manager is Galaxy. Run with the step on and the network closed, in a role with no
requirements file, it reaches nothing and reports both requirements files
missing, because the docker driver's collection is already installed. A scenario
that brings its own `collections.yml` naming a collection the package does not
carry reaches Galaxy (the run fails at `galaxy.ansible.com` with the proxy
closed). So every scenario sets `dependency: enabled: false`, as the skeleton
does, and the check above fails a scenario that does not.

### The bump route

Normally a person does nothing to learn of a bump: Dependabot opens it.

1. Read the pull request and the Ansible workflow's result. The workflow
   installs the new lock from scratch and runs the harness over every role and
   pattern.
2. If it changes `ansible-core`, change `min_ansible_version` in every role's
   `meta/main.yml` in the same pull request (the harness's `min-version` step
   fails otherwise), and read the release notes of the collections the new
   `ansible` release moved.
3. If it changes `ansible-lint`, change the `rev` of its pre-commit hook to `v`
   and the same version in the same pull request. No such hook exists yet; the
   check compares it as soon as one does.
4. Merge when the checks are green.

A pull request that changes `checks/pip-requirements.txt` is the other bump. Take
the new version's wheel hash from PyPI's JSON API (`https://pypi.org/pypi/pip/<version>/json`,
the `bdist_wheel` entry, not the source archive: the install is wheels-only),
and re-check the parity table against the new pip before merging.

To bump by hand, edit the pin in `requirements.in` and regenerate the lock with
the command under "Why `requirements.txt` is long", run from `ansible/`, then
run the install above, the check and the harness. Never edit `requirements.txt`
directly, and never regenerate it without the header or without `--universal`
and `--generate-hashes`: the check refuses it, and Dependabot reads those
options from the header.

### What this does not prove

- The check reads the shape of the lock, not that a hash is the right one. pip
  compares each file with the lock's hashes; a hash written wrongly at a bump
  fails the install, but a hash recorded from a malicious file would be
  accepted. A bump is reviewed, not trusted.
- A collection's own code is part of a 50 MB package and is not read in a diff.
  The package is trusted at the level PyPI and its hashes give.
- The Dependabot route was run with its CLI against a copy of the lock, not
  against this repository: the first real pull request can only follow the
  merge, and a person should read it once to confirm it changes `requirements.in`
  and `requirements.txt` and nothing else. The advisory alert is a repository
  setting the check cannot see.
- The `pip` entry for `/ansible/checks` was not run with the Dependabot CLI. The
  check proves the entry is there and the pin file has the shape that ecosystem
  reads; whether its first pull request rewrites the hash as well as the version
  is read once, when it opens.
- The check runs in CI and by hand, not in pre-commit.
- ANS-5 says lint runs in pre-commit as well as CI. This repository has no
  ansible-lint hook yet, so no rev is compared; the check says so on every run.
- The install is larger than before: the package adds the whole community
  collection set (about 235 MB installed) although the roles use three of them.

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

- **The pre-commit hooks.** ANS-5 and ANS-6 say lint runs in pre-commit as well
  as in CI. Nothing here changes `.pre-commit-config.yaml`; only the CI run is
  wired.
- **The standard's own checks.** Of the checks the standard's check plans
  describe, the scenario limits and the pins are scripted. No `shell` tasks and
  no loosened lint file are still review.
- **Inventories.** The trees under `inventories/` hold one host, and their
  layout is a proposal.
- **A required check.** The Ansible job runs on every pull request, so it can be
  required (CI-14), but making it required is a repository ruleset change and
  belongs to the owner. Until it is done a red Ansible job does not block a
  merge on its own.
- **Delivery.** Each of edge1, db1, app1 and ops1 has a playbook under `playbooks/`.
  edge1's first apply is the one-time root bootstrap and then the gated pull; db1's
  waits on the gated pull. ANS-17 describes the only approved path. The trigger is
  `roles/pull_trigger`, and its reusable workflow is in `branchLeft/github-workflows`;
  nothing in this repo calls that workflow yet.
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
