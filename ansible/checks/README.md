# ansible/checks

This folder holds the checks that prove the lock and the workflow. Their narrative lives here
because the CMT-3 gate requires comment blocks in the code to stay below 11 lines.

## test_lock_reader_parity.py: parity with pip

The install program (`ansible/roles/ansible_runtime/files/install_runtime.py`) refuses a lock that
pip would run with an option such as `--index-url`. Its first refusal, `check_lock_options`, does
not read the lock as pip joins it: it judges each physical line alone (the lines `str.splitlines`
gives, as pip splits them) and refuses any token that starts with a dash and is not an exact
`--hash=sha256:<64 hex>`. So the oracle is narrow: for a short table of lock shapes it asks pip's
own code how it reads each one (`_decode_req_file`, `preprocess` and `break_args_options` in
`pip/_internal/req/req_file.py`) and holds the program to it, with one test that no shape in which
pip sees a foreign option is accepted. Each shape says what the program must do and what pip must
see, and pip is asked as well, so a wrong entry in the table fails too. The table keeps one witness
for each rule (a line break pip and the program both split on, an encoding mark, a continuation, an
expanded variable); the shapes that only varied how a continuation ends are gone, because the
physical-line rule does not depend on the join.

The pip it asks is pinned. The pin is `ansible/checks/pip-requirements.txt`, a hashed requirement
for one version (26.1.2), which both CI tool environments in `.github/workflows/ansible.yml` install
with `--require-hashes --only-binary=:all:` before the lock. The lock does not pin pip, so without
this file the oracle would run whatever ensurepip bundles with the runner's Python. Before it calls
any pip internal, this file reads the interpreter's `pip.__version__` and fails, naming both
versions, when it is not the pin. It never skips and never falls back to `auto_decode`.

The version the test compares is read from `pip-requirements.txt` on every run, by `check_pins.py`
(`read_pip_pin`), so the file the workflow installs is the only home of the version. The comparison
runs before the test imports or probes any pip internal. Tests in the same file patch the version
they see and hold that down, so no second pip is needed to prove it.

pip's `req_file` module is not a public interface. A pip upgrade is therefore two steps, done
together: change the pin in `pip-requirements.txt` to the new version with the hash of its wheel
(the `bdist_wheel` entry of PyPI's JSON API; the install is wheels-only, so the source archive's
hash is never used), and re-check the table above against the new pip's `req_file` (the parity).
Until both are done the test fails, which is the intended result.

Dependabot watches the pin: its `pip` entry for `/ansible/checks` opens the bump, and
`check_pins.py` fails if that entry goes or if the pin file is anything but one `pip==X.Y.Z` line
with one sha256. `test_ci_python_steps.py` requires both CI tool environments, and the install
recipe in `ansible/README.md`, to install the pin before the lock, with hashes required and wheels
only.

# check_enrolment

`check_enrolment.py` checks the host playbooks that run under the gated pull.
A top-level playbook is under the pull when one of its plays applies the `pull_trigger`
role. Its trust anchor is `ansible/trust/HOST.yml`. A failure names the rule and the
file. `test_check_enrolment.py` runs the check over the real tree and over one sabotaged
copy per rule, and asserts that each sabotage hit its text.

## What the check sees, and what it does not

It sees the literal keys of every file under `ansible/` that R6 reads: a file whose name
ends in `.yml`, `.yaml` or `.json`, or has no extension, in a loaded directory. The
exception is a role's or pattern's `molecule/` directory and a role's or pattern's
`meta/argument_specs.yml`, which are fixtures and schema. A file that does not parse is
refused. A symlink that leads out of `ansible/` under a loaded directory is refused.

Under `playbooks/` and `trust/` the name rule is stricter, and R6 reads all of it. Every
entry there that is not a directory must be an exact `.yml` (case-sensitive, no other
suffix), or one of the two README paths named exactly: `playbooks/README.md` and
`trust/README.md`. A README anywhere else is refused. Each of the two exception READMEs is
refused if it parses as a YAML list, because `ansible-playbook` would run a list as plays.
That parse accepts every tag (`!unsafe`, `!vault`), as Ansible's loader does, so a tagged
list is refused too. A link is refused whatever its name,
so the check never follows one. The rule is one function, shared by R2, R4 and R5.

It catches a protected key (`pull_trigger_signers`, `pull_trigger_remote_url`,
`pull_trigger_playbook`, `pull_trigger_playbooks`, `enrolled_host`) set outside the one
file that owns it, and a loader it cannot read.

It does not judge what a role does. The roles run as root, so a change to `roles/` can
change what a host does with its signers, and this check does not see that. The reusable
gated apply exists in `branchLeft/github-workflows`, but nothing in this repo calls it, so
a role edit is not gated by anything here. The control on a role edit is the owner's
deploy approval of the gated apply, which is not yet wired. Which files the reviewer App
may merge alone is not yet decided by the owner.

Limits of R2. It pins `vars` to exactly `enrolled_host: HOST` (no other variable: a
templated `lookup`, an `ansible_*` setting or an override of a role's defaults is refused),
and pins `vars_files`, `roles` and `pre_tasks`, and refuses any play key outside `name`, `hosts`, `gather_facts`, `vars`,
`vars_files`, `pre_tasks` and `roles`. So a `tasks`, `post_tasks`, `handlers`,
`environment`, `module_defaults`, `collections`, `strategy`, `become`, `import_playbook`
or `include_vars` key, or any key it does not know, is refused by name, and no role can be
applied to a host by a path other than its `roles` list. A listed role is trusted by
name: the list does not say what the role does as root, and a role's own edit is still not
gated here. A playbook is a place a literal can hide as well as a role.

Limits of the loader rule. It reads literal mapping keys. It names the loaders listed in
`ROLE_LOADERS`, `TASK_FILE_LOADERS` and `INCLUDE_VARS`, in their bare, `ansible.builtin.`
and `ansible.legacy.` spellings, and the `action:` and `local_action:` forms of those. It
does not parse the free-form arguments of other modules, other than a protected key
written as `key=value` in a string. A loader or module outside those sets is not seen.

Limits of the README exception. A README that the checker's YAML parser cannot read is
accepted as prose, because the play-list check reads nothing from it. Ansible's loader and
this parser are not the same code, so a README that Ansible could load as a play list and
this parser cannot read passes. Parser parity is not checked, and no new refusal is added
for it, because a fail-closed rule would refuse real Markdown READMEs.

What stops such a README from running is not this check. The controls are: the pull runs
only the derived `HOST.yml` path (R3), so a README under `playbooks/` or `trust/` is never
the file it runs; the gated workflows; and the owner's deploy approval of the gated apply.
The last two are not yet wired in this repo, as the roles paragraph above says. Ownership
differs by file. `trust/README.md` is under the owner's merge (`/ansible/trust/` in
CODEOWNERS). `playbooks/README.md` has no CODEOWNERS line, so the reviewer App may merge an
edit to it alone until the owner decides which files the reviewer App may merge alone.

Out of scope: a case-insensitive filesystem. On macOS Ansible can find
`group_vars/all.YML` under the name `all.yml`, and R6 reads only the exact suffix. This is
not closed by the name rule, which covers `playbooks/` and `trust/` only. It does not reach
CI or the hosts, which are Linux, where both loaders compare case-sensitively, so the file
is not loaded there.

## Rules

- **R0** The three shared includes exist under `playbooks/includes/`. Each refusal
  include holds exactly one task: its name and its assert, with exactly its expressions
  and no other key (`when`, `ignore_errors` and `tags` are refused).
- **R1** At least one top-level playbook is enrolled, so the check cannot pass over nothing.
- **R2** The name rule (above) refuses every entry under `playbooks/` that is not an exact
  `.yml` at the top of `playbooks/` or in `playbooks/includes/`, at any depth. The pull
  runs only the derived `.yml` path, and `ansible-playbook` would run any other name, so
  R6 must read every file in the tree. Each enrolled `HOST.yml` has one play, with no key
  but `name`, `hosts`, `gather_facts`, `vars`, `vars_files`, `pre_tasks` and `roles`, on
  `hosts: all`, `vars` exactly `enrolled_host: HOST` and nothing else, `vars_files` exactly the shared
  include and `../trust/HOST.yml`, `roles` the runtime entry then the bare trigger as the
  first two entries and nothing attached to either, then only plain entries from that
  host's list in `host_roles.yml` (R9), and `pre_tasks` exactly the refusal include then
  the signer include, each a task of only its name and include. A plain entry is a mapping
  of one key, `role: ../roles/NAME`: no `vars`, `tags`, `when` or other key. A role is
  applied once, may be on its own host's list only, and is refused on any other host. A
  host with no list may apply the two pull roles and nothing else. An enrolled playbook is
  read only at the top of `playbooks/`; the pull runs only that path.
- **R3** The shared include holds exactly the remote literal and the playbook derivation
  from `enrolled_host`, and no other key.
- **R4** The trust files are exactly the enrolled playbooks, one file each. `trust/` is
  flat: a `.yml` in a subdirectory of `trust/` is refused by the name rule, so R4 and R5
  never see two files with one stem.
- **R5** Each trust file holds one key, `pull_trigger_signers`, as a list (it may be empty).
- **R6** A protected key is set only in its owner's file. `enrolled_host` may be set only
  in the play `vars` of an enrolled top-level playbook. `vars_files` is read only in an
  enrolled play, where R2 pins it. An include or import of a task file, a `vars_files`
  target, a role, or a role's `tasks_from`, `vars_from`, `defaults_from` or
  `handlers_from` that R6 cannot read is refused. A templated key is refused. An
  unparseable file is refused.
- **R7** A top-level playbook that is not enrolled names neither `pull_trigger` nor `trust/`.
- **R8** Exactly one task in `roles/pull_trigger/tasks/` writes the config: a task that
  names `pull_trigger_config` or the config path. That task copies the pinned content to
  the pinned config path, and its `signers` and `remote_url` are the pinned variables,
  not literals. Zero writers, or two, is a failure. A config path spelled as a literal
  is not seen.

- **R9** `host_roles.yml` exists and maps each host name to a list of distinct role names
  (`[a-z][a-z0-9_]*`), never `ansible_runtime` or `pull_trigger`. A host whose entry is
  malformed gets no listed roles, so its playbook may apply the two pull roles only. The
  file is in `ansible/checks/`, which CODEOWNERS gives to the owner, so adding a role to a
  host is the owner's merge. The check reads names, not directories: a role may be listed
  before its directory merges, and until then it runs nothing. Order after the pull roles
  is free, except for the loader (R10), and a listed role need not be applied.
- **R10** When a host applies `host_inputs`, the loader of the host's private role inputs
  (owner ruling, option A, branchLeft/workspace#2739), it is the first role after the two
  pull roles, so no role runs before the inputs are loaded or refused. A host that does not
  apply it is unaffected. `test_host_inputs_registry.py` holds the loader's row table, the
  literal keys of its input task, `host_roles.yml`, the playbook and the role argument specs
  in agreement, and the structure of the loader's tasks.

The refusal's host test is not a host control. Under the trigger `inventory_hostname` is
`localhost`, and the root-owned pull config is the control on the host.

# check_role_imports and check_role_paths

Two checks over the roles, each run by its own test file in the "Test the checks" step.

`check_role_imports.py` is ANS-12 as one sentence: no role imports another role. In
`tasks/`, `handlers/` and `meta/` of every directory under `roles/` and `patterns/` it refuses
`include_role`, `import_role` (in any spelling), a `roles:` key, a `dependencies` entry in
`meta/main.yml`, and a task or vars file loaded from a path with `..` in it. A `molecule/`
directory is a playbook and may name roles. It reads literal keys: a role loaded through a
templated name is not seen.

`check_role_paths.py` holds that no two roles write the same path. It reads the tasks of every
role under `roles/`, takes the `dest` or `path` of `copy`, `template`, `get_url`, `lineinfile`,
`blockinfile`, `replace`, `assemble` and of `file` with `state: link`, `hard` or `touch`, and
resolves each `{{ name }}` from the defaults and vars of the roles (names carry the role prefix,
ANS-7). It prints how many paths it compared and how many stayed templated, because a path with a
loop item or a filter is not compared. A directory two roles both make is not a write. It
replaces the per-role tests that each asserted one home for one role's files; it does not check
that a role holds no copy of a program (the DB-1 gate of the standards flags that).

## ci_select.py: which shards a run executes

`ci_select.py` narrows the shard list from `ansible/harness/list_shards.py` to the shards a
run needs, from the event and the files it changed. The rules, in the order they apply:

- the weekly scheduled run and a manual run execute every shard, whatever changed: they are
  what finds drift in an external image or collection, which no diff shows;
- a push to `main` executes none, and runs no lint: the pushed tree is the tree the merge
  queue tested, and the delivery workflow runs its own checks before it applies anything;
- a pull request or a merge-queue entry whose base commit is unknown, or whose changed
  files are not listed, executes every shard. The queue entry's changed files are the diff
  from its `base_sha` to its `head_sha`, so a shared file in that diff executes every shard,
  as it does in a pull request. An entry stacked on another is tested on that one's tree
  and diffed from it; if the earlier entry leaves the queue, the later one is tested again;
- a changed file that is part of the harness, the checks, the lock or the lint config
  executes every shard, because it decides what every role is held to;
- a changed file under `ansible/` that nothing here recognises executes every shard,
  because a new kind of file must be named in the program before it may skip a shard;
- a changed file in a role or pattern executes that role's or pattern's shards, and the
  shards of every role or pattern that names it;
- a changed file outside `ansible/` executes the shards of every role or pattern that
  reads it.

A shard that is wrongly left out is a gate that passes without running, so every rule
above errs towards running more.

## test_ci_gate_order.py: the workflow order and gate

These tests hold the CI workflows to what `ci_select.py` assumes:

- the shard job waits for the lint job, so a lint error starts no container;
- the shard job runs only when discover chose shards, and refuses the entry that stands
  for none;
- the gate job (the check the ruleset requires) fails unless the lint passed, and fails
  when shards were chosen and did not all pass;
- the merge queue still triggers the workflow, and the weekly sweep is scheduled;
- the lint and every shard restore the tool environment from a SHA-pinned `actions/cache`
  keyed on the lock files, and install only on a miss;
- the CrowdSec pin check opens a pull request on a stale pin and still fails when it cannot
  run;
- the ansible-hosts environment probe is scheduled and judges the environment;
- Dependabot runs monthly and grouped.

## check_delivery.py: C4, the environments of the other workflows

C4 fails when another workflow runs a job in the environment the Ansible apply is approved
in (`ansible-hosts`, compared without regard to case), because one approval would then release
both. It reads the `environment` of every other workflow's jobs, as a job key or as the
`with.environment` of a call, as a string or as a mapping's `name`.

An environment named by an expression cannot be read, so it is a finding that names the
expression. There is one exception, and it is one shape only:

```
${{ needs.<job>.outputs.<name> == '<A>' && '<A>' || '<B>' }}
```

`<A>` and `<B>` are plain literals (an ASCII letter or digit first, then letters, digits,
dots, underscores or hyphens). `<A>` is the same literal in the test and in the result, so the
job runs in `<A>` or in `<B>` and nowhere else. C4 reads both and judges each as if it were
named outright. This is how a Hetzner apply is routed to `production-free` or `production` by
the spend gate. Spaces and tabs may differ where the shape has them.

Every other expression stays a finding: another operator, a branch that is not a literal, a third
branch, a different literal in the test and the result, the `github`, `inputs` or `vars` context,
string concatenation, a function such as `format()`, a nested `${{ }}`, or any text before or
after the expression.

## test_no_new_hand_installers.py: the hand installers stay frozen

A hand installer is a bash script under any `provision/` directory, or under `hetzner/scripts`.
Each one is listed in `hand_installers.yml` with a reason: `stays-as-code`, or `pending-role`
naming the role that will replace it. The test walks the tree and fails on a script that is not
listed, and on an entry whose script is gone. The list is the baseline as it stood when the guard
was added, so a new installer needs a reviewed entry, which is an owner merge under CODEOWNERS.
The test reads the role name and does not check that the role exists, as `host_roles.yml` does.
It does not stop a runbook that edits a host by hand; that half is not covered here.

## merge_group_proof.py: when a delivery may skip its re-test

`ansible-delivery.yml` has a job, `queue-proof`, that decides whether the delivery of a pushed
commit may skip the lint and Molecule re-run. It reads the runs of `ansible.yml` for the pushed
commit and `merge_group_proof.py` answers `tested=true` only for a run that has all of:

- the workflow `.github/workflows/ansible.yml`, the event `merge_group`, the pushed commit as head;
- a head branch that starts with `gh-readonly-queue/`;
- the status `completed` and the conclusion `success`.

The event is judged here and is never narrowed by the API's own `event` filter, because after a
squash queue main carries a green push run of the same commit under the same check name, from a
job with no diff. A check name, or any success on the commit, is not proof. A merge that skipped
the queue has no queue run, so it gets `tested=false` and the delivery re-tests in full. An
unreadable, truncated or malformed answer is `false` too.

`check_delivery.py` fixes the shape of the proof job and of the two inputs the delivery passes
(`skip-rerun-after-merge-group` from the proof's output, and `merge-group-check-name`, the gate
job's name in `ansible.yml`). The reusable workflow then checks the queue's check run and suite
itself and refuses the delivery if they disagree, so a skip needs both to agree.

After a lock-file merge (for example Dependabot), dispatch the Ansible workflow, because the
venv cache stays cold until the Monday sweep.

Named limit: that only an org-admin pull-request bypass can skip the queue comes from the org
ruleset standard. The ruleset's bypass list could not be read with the App tokens, so the owner
should confirm it from the owner's view.
