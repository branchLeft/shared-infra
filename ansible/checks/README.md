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

Under `playbooks/`, `trust/` and `owner_vars/` the name rule is stricter, and R6 reads all of
it. Every entry there that is not a directory must be an exact `.yml` (case-sensitive, no
other suffix), or one of the two README paths named exactly: `playbooks/README.md` and
`trust/README.md`. A README anywhere else is refused, `owner_vars/` has none, and it is flat. Each of the two exception READMEs is
refused if it parses as a YAML list, because `ansible-playbook` would run a list as plays.
That parse accepts every tag (`!unsafe`, `!vault`), as Ansible's loader does, so a tagged
list is refused too. A link is refused whatever its name,
so the check never follows one. The rule is one function, shared by R2, R4 and R5.

It catches a protected key (`pull_trigger_signers`, `pull_trigger_remote_url`,
`pull_trigger_playbook`, `pull_trigger_playbooks`, `enrolled_host`) set outside the one
file that owns it, and a loader it cannot read.

It does not judge what a role does. The roles run as root, so a change to `roles/` can
change what a host does with its signers, and this check does not see that.
`.github/workflows/ansible-delivery.yml` calls the reusable gated apply in
`branchLeft/github-workflows`, and the control on a role edit is the owner's deploy
approval of that gated apply.

Limits of R2. It pins `vars` to exactly `enrolled_host: HOST` plus the entry pinned for that
host in `HOST_PLAY_VARS` in `check_enrolment.py` (five rows: edge1's `deploy_tooling_host_class`
with `egress_nat_gateway_enabled: true`, the one switch that makes a host a NAT gateway; edget's
`egress_nat_gateway_enabled: true` alone (edget is the server edge-t, the tenants network's gateway:
a network does not span hcloud projects, so there is one gateway per network, edge1 for the estate's
and edget for the tenants', and `test_egress_nat_single_gateway.py` refuses a second on either; the
logical name has no hyphen because `HOST_NAME` allows `[a-z][a-z0-9]*`); app1's
`deploy_tooling_host_class` with `deploy_tooling_policy_variant`,
which the role takes with no default for the class and which a host of class app must name; dbt1's
`deploy_tooling_host_class: internal`; and mx1's `host_baseline_fail2ban_ignoreip_none: true`; no other variable: a
templated `lookup`, an `ansible_*` setting or an override of a role's defaults is refused),
and pins `vars_files`, `roles` and `pre_tasks`, and refuses any play key outside `name`, `hosts`, `gather_facts`, `vars`,
`vars_files`, `pre_tasks` and `roles`. So a `tasks`, `post_tasks`, `handlers`,
`environment`, `module_defaults`, `collections`, `strategy`, `become`, `import_playbook`
or `include_vars` key, or any key it does not know, is refused by name, and no role can be
applied to a host by a path other than its `roles` list. A listed role is trusted by
name: the list does not say what the role does as root, and a role's own edit is still not
gated here. A playbook is a place a literal can hide as well as a role.

dbt1 (db-t1) has a `HOST_PLAY_VARS` row, `deploy_tooling_host_class: internal`, and no gateway
switch. It lists `egress_nat` bare, as a non-gateway, and its play sets no switch:
`test_egress_nat_single_gateway.py` pins the switch to edge1 and edget alone, and requires any
non-gateway that applies the role to apply it bare.

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
Ownership differs by file. `trust/README.md` is under the owner's merge (`/ansible/trust/` in
CODEOWNERS). `playbooks/README.md` has no CODEOWNERS line, so the reviewer App may merge an
edit to it alone.

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
  `hosts: all`, `vars` exactly `enrolled_host: HOST` plus that host's row in `HOST_PLAY_VARS`
  and nothing else, `vars_files` exactly the shared
  include and `../trust/HOST.yml`, then `../owner_vars/HOST.yml` if and only if that file
  exists (the playbook and the file must agree both ways), `roles` the runtime entry then the bare trigger as the
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
  is free, except for the loader (R11), and a listed role need not be applied.
- **R10** `owner_vars/` holds the owner's values for a host's roles. It is flat, and a name
  must be exactly `HOST.yml` for an enrolled host; the name rule above refuses anything
  else, and R6 refuses a protected key in it (its allowed set is empty). Each file holds
  exactly the keys its host is allowed and no other, with values of the right shape. For
  edge1 those are `ci_login_manage_keys`, a bool, and `ci_login_keys`, a list of
  `{key, mode}` entries with `mode` one of `apply` and `check`; an entry with any other
  key (a source address list, say) is refused. The four values of the `ci_jump` role that live in the repository are
  allowed on every host in `JUMP_HOSTS` (each jump host has its own file, address,
  destinations and keys): `ci_jump_manage_keys`, a bool, `ci_jump_own_address`, text,
  `ci_jump_destinations`, a list of text, and `ci_jump_keys`, a
  list of `{key}` entries with nothing else (a destination list per key is refused: the role
  takes one list for every key). `JUMP_HOSTS` (edge1 and edget) must equal the hosts whose row in
  `checks/host_roles.yml` lists `ci_jump`: a host cannot gain the role without its keys, nor
  the keys without the role. The role's fifth variable, `ci_jump_user` (the jump account's name, which
  the owner keeps out of the repository), is not allowed in an `owner_vars` file: it reaches the
  role through the host's `host_inputs` row. What a destination or a key may look like is the role's rule alone,
  in its module. For ops1 the two keys are `pull_trigger_steps`,
  the gated pull's step allow-list: a list of `{id, tag, word}` mappings, all text, and
  `control_plane_db_apps_image`, the applications image the steps run, which must be text.
  The `ring_controller_host` role adds three more, all text and all allowed on ops1 only:
  `ring_controller_host_bundle_sha256`, `ring_controller_host_bundle_url` and
  `ring_controller_host_ledger_url`. Each may be the empty string, which is how the role
  starts inert; what a value may look like is the role's rule alone. The push remote and the
  known-hosts line it used to take are no longer allowed, so an owner file that still sets one is
  refused here (Ansible's own spec check does not read an owner file's values).
  R10 reads only those shapes; `test_step_allowlist.py` holds the image to the role's own
  digest pattern, read by name from the role's constants. Which ids exist, that a tag is `control_plane_db_` plus the id and what a
  word may look like are the program's rules alone, and `test_step_allowlist.py` feeds the
  real file through the program's own `parse_config`. `control_plane_db_step` is never an owner
  key: it is the role's second key and only the pull sets it. A host with no allowed keys may
  have no file. The check does not judge a key's text; the `ci_login` and `ci_jump` roles do. The directory is the
  owner's (`/ansible/owner_vars/` in CODEOWNERS), so filling in the keys is the owner's merge.
- **R11** When a host applies `host_inputs`, the loader of the host's private role inputs
  (owner ruling, option A), it is the first role after the two
  pull roles, so no role runs before the inputs are loaded or refused. A host that does not
  apply it is unaffected. `test_host_inputs_registry.py` holds the loader's row table, the
  literal keys of its input task, `host_roles.yml`, the playbook and the role argument specs
  in agreement, and the structure of the loader's tasks.

The refusal's host test is not a host control. Under the trigger `inventory_hostname` is
`localhost`, and the root-owned pull config is the control on the host.

## test_ci_login_pins.py: the ci_login copies and the missing source limit

The `ci_login` role carries its own copy of the key shapes of the `sudoers_and_keys` pattern
and of the trigger program's path, because a role may not call a pattern or another role
(ANS-12). The test fails when either copy differs from its home
(`sudoers_and_keys_key_shapes`, `pull_trigger_program_path`), when the sudoers lines are
anything but the `env_keep` line and the two-command grant, and when a source address option
(`from=`, `from_addresses`, or an interface option with `from` in its name) appears in the
key template, the tasks, the variables or the argument spec. The owner accepted keys with no
source limit; this keeps that visible, so a limit is added by an owner ruling that changes
the test too. Each pin runs red on a sabotaged copy of its files and green once the file is
put back.

## test_ci_jump_pins.py: the ci_jump copies, its output and its task order

The `ci_jump` role carries its own copy of the constants its module also pins (the port, the fixed
options, the forced command and the paths of the key file and the sshd drop-in; the module is the
read-back oracle, so the two must be held equal), and a literal list of the accounts other roles
own, because a role may not call another or load its variables (ANS-12, R6). The test fails when a
constant differs, when the account names differ from `ci_login_user` in
`roles/ci_login/vars/main.yml` and `tunnel_account_user` in `roles/tunnel_account/vars/main.yml`
(read by variable name), when either template writes other text than the module expects, when the
key template and the drop-in template do not read their destinations from the one variable
`ci_jump_destinations`, when the module stops requiring `AllowTcpForwarding local` for the jump
account (a key line with `port-forwarding` also lets its holder open a port on the jump host with
`ssh -R` under any other value), when the argument spec and the defaults name different variables,
when the role's own defaults are not inert (the flag false, and no address, destination or key), when
an `owner_vars` file of a host the owner has not turned the role on for (the flag anything but the
bool true) does not ship those defaults, when a file that turns the role on (the flag true, as edge1
does after the owner's data change) lacks an address, a list of destinations or a list of keys,
when an `owner_vars` file carries the account's name, when a host lists the role without its variables or
without `ci_jump_user` in its `host_inputs` row, when a path the role writes or the module pins is made
from the account's name (each is rendered with a realistic name and must not hold it; only the paths
of the earlier hand-made layout, which the role removes, are), when a task that handles the name or
one of those paths does not hide its result and its diff, and when the order or hiding of the role's tasks changes
(the report runs whatever the flag is; the guards and the write are behind it, in that order; the
two files are written as `root:root` at `0644` by hidden template tasks, never by `authorized_key`;
the whole configuration is checked with `sshd -t`; a rescue puts the previous files back; the
read-back is inside the rolled-back block and skipped in check mode).

It also keeps the role's output out of the gated apply's plan scan, which withholds a host's whole
plan on one line that reads like a credential assignment, and keeps the jump account's name out of
the report and the plan. The module holds a copy of the scan's credential-assignment pattern
(`SCAN_PATTERN`, from `branchLeft/github-workflows/.github/actions/ssh-check-hosts/action.yml`
line 434 at tag v1.0.19). The test runs the module's report and plan over hostile values (option
values that read like credentials, an account whose name must appear nowhere) and fails when a line
matches, when the module's last-resort guard had to withhold one, or when the name is printed, and
it scans every variable name, task name and message of the role. **Drift of the copy from the
original is not checked here**: no test holds the two equal yet. Each pin runs red on a sabotaged
copy of its files and green once the file is put back.

## test_ci_jump_hosts.py: one role on edge1 and edge-t, and the two address rules

Two hosts apply `ci_jump`: edge1 and edge-t (`edget`, both in `JUMP_HOSTS`). The real-sshd proof in
the role's `molecule/default` (a destination not on the list is refused) covers both only if the role
is the same on both. The test fails when a jump host does not apply the role exactly once as a plain
role entry (no `when`, `vars` or `tags` on it), and when any part of the role that runs on a host
(tasks, templates, vars, defaults, meta, library, handlers, files) names the host or a group of
hosts (`enrolled_host`, `inventory_hostname`, `groups`, `hostvars` and the like). It also holds the
2 Nov ruling on the data: a tenants private address (read from `TENANTS_HOST_IPS` in
`hetzner-host/addressPlan.ts`, its one home, never copied) in `owner_vars/edge1.yml` is refused, so
the runner can only reach a tenants host through edge-t; edget's `ci_jump_own_address`, once set, must
equal `TENANTS_HOST_IPS.edgeT`; and a host that lists destinations must list its own address among
them. It fails when the address plan cannot be read, so an empty parse cannot let a list through. It
does not see edge-t's public address, which is in no file of the repository, nor whether a listed
address is the right one. Each pin runs red on a sabotaged copy of its files and green on the copy
left alone.

## ci_select.py: which shards a run executes

`ci_select.py` narrows the shard list from `ansible/harness/list_shards.py` to the shards a
run needs, from the event and the files it changed. The rules, in the order they apply:

- the daily scheduled run and a manual run execute every shard, whatever changed: they are
  what finds drift in an external image or collection, which no diff shows;
- a push to `main` executes none, and runs no lint: the pushed tree is the tree the merge
  queue tested, and the delivery workflow runs its own checks before it applies anything;
- a pull request or a merge-queue entry whose base commit is unknown, or whose changed
  files are not listed, executes every shard. The queue entry's changed files are the diff
  from its `base_sha` to its `head_sha`, so a shared file in that diff executes every shard,
  as it does in a pull request. An entry stacked on another is tested on that one's tree
  and diffed from it; if the earlier entry leaves the queue, the later one is tested again.
  The selection is still made for a queue entry, but the shard job's condition skips the
  shards in the queue (the pull request already ran them), so only the lint runs there;
- a changed file that is part of the harness, the lock, the lint config, or one of the three
  checks files the shards read (`ci_select.py`, `check_pins.py`, `pip-requirements.txt`)
  executes every shard, because it decides what every role is held to;
- any other file in `ansible/checks/` runs the lint job only, because lint runs its tests and
  no shard reads it;
- a changed file under `ansible/` that nothing here recognises executes every shard,
  because a new kind of file must be named in the program before it may skip a shard;
- a changed file in a role or pattern executes that role's or pattern's shards, and the
  shards of every role or pattern that reaches it, followed to the end (a cycle ends). A
  role reaches another when a file of it names it textually (`branchleft.name`, `../name`,
  `roles/name`, `patterns/name`, a README included), or when the structured scan reads one
  of these:
  - `include_role` or `import_role` (block, inline `{name: x}` or `name=x`), and a play's
    `roles:` or a role's `dependencies:` (`- x`, `- role: x`, `- { role: x }`, an inline
    list), naming `branchleft.x`, a bare `x`, or a path ending in `x`. A `{{ variable }}` is
    followed through the same role's own definitions of it (each must resolve, three deep);
    a `{{ playbook_dir }}` path is tried from the file's directory and each one above it up
    to the role's root; a name built with a trailing `~ "/x"` names `x`;
  - `import_playbook`, when the file it names lies in another role or pattern;
  - `notify:` of a handler that the role does not define itself (by `name:` or `listen:`)
    but another role or pattern does;
  - a symlink in the role whose target lies in another role or pattern;
- a changed file outside `ansible/` executes the shards of every role or pattern that
  reads it;
- a reference the scan cannot map to a role or pattern executes every shard whenever a role
  or pattern changed: a collection role, a name that is not a role here, a variable with no
  literal definition, a playbook outside any role, a handler defined nowhere, a symlink that
  is dangling, leaves the repository or points at a file under `ansible/` that no rule names,
  a line that names `include_role`, `import_role` or `roles:` in a form the scan does not read
  (a flow-style task, `action: include_role name=x`, a quoted key), and any file the scan
  cannot read. Such a reference may be a way the changed role is
  reached that the selection cannot see. A change that selects no role (a README, a
  lint-only file) still executes no shard, and the log names the first few such references.
  `test_ci_select.py` holds the real tree to none, so a new templated role name that the scan
  cannot place fails there before it sends every pull request to every shard; make the name
  literal, or give it through a variable of the same role with a literal value.

A shard that is wrongly left out is a gate that passes without running, so every rule
above errs towards running more.

## blocking_shards.json: which container tests fail the required check

Every container test (harness shard) runs on every pull request and stays visible. Only the
shards named in `blocking_shards.json` fail the required check, `Lint and test the Ansible
roles`; every other shard is advisory. An advisory shard that fails shows red on its own
check line, the required check does not wait for it, and the `report` job lists it in the
step summary. A scheduled or manual run treats every shard as blocking, so the daily run
catches what an advisory shard hides. The merge queue runs no shard, as before.

The file is one JSON object with the single key `blocking`: a list of shard ids, sorted,
each once, each one a shard that exists in the tree. A shard id is the name `list_shards.py`
gives it: `ansible/roles/ci_jump`, or `ansible/roles/ci_jump (refusals)` for a second
scenario. `blocking_shards.py validate` and `test_blocking_shards.py` hold those rules; the
discover job runs the same checks before it splits the shards, and fails when the list is
bad, which fails the required check.

The rules for the list:

- It starts with the shards of the lock-out roles, the ones whose break can cut the operator
  or the pipeline off a host: `pull_trigger`, `ci_jump`, `breakglass_mint_host`,
  `host_baseline`, `tunnel_account`, `edge_firewall`, `egress_nat` and `deploy_tooling`.
  They stay. A test fails when one of their shards is not listed, and takes any new scenario
  of one of those roles in too. Taking one off needs an owner-approved edit to
  `LOCKOUT_PATHS` in `test_blocking_shards.py` as well as to the list. `edge_firewall` is
  named in the test before its role is merged; its shards must be listed in the pull request
  that adds the role.
- A shard goes on the list by a reviewed pull request that cites the failing run that
  tripped it.
- A shard comes off the list by a pull request that cites five passes in a row of the daily
  run: `advisory_passes.py <shard id> --n 5` prints `PASS-STREAK=<k>` and the run URLs, and
  exits 0 only when k is at least n. It reads the newest completed scheduled runs of the
  workflow on `main`; a run in which the shard did not pass, or had no job, ends the streak.
  It reads only, with the token in `GH_TOKEN` or `GITHUB_TOKEN`; `--fixture FILE` runs it
  offline on recorded answers (`advisory_passes_fixture.json`).
- The approver records every red advisory shard of the pull request, from the `report` job's
  table, on the pull request.
- A red daily run opens one issue (`daily_red_issue.py`), titled with the date, with the run
  link and the failed shard ids and the one label `ci-red-daily`, or comments on the one still
  open. Nothing there mentions, assigns or prompts anyone or anything.

Two things to know. A new role or scenario starts advisory: it is on no list until a pull
request puts it there. And the delivery workflow (`ansible-delivery.yml`) runs the harness
over every role before it applies anything; this list does not change that run.

## test_ci_gate_order.py: the workflow order and gate

These tests hold the CI workflows to what `ci_select.py` assumes:

- the shard job waits for the quick lint gate (yamllint and `test_ci_select.py`) and not for
  the full lint, so a malformed file starts no container and the shards start sooner;
- the blocking shard job and the advisory shard job each run only when discover chose shards
  of their kind, and refuse the entry that stands for none; the advisory job runs the same
  steps as the blocking job (compared step for step), and both are named
  `Harness: <id>` and `Advisory harness: <id>`, which `shard_results.py` reads;
- the gate job (the check the ruleset requires) fails unless the quick gate and the full lint
  both passed, and fails when blocking shards were chosen and did not all pass. It needs the
  blocking shard job and not the advisory one. The one exception is
  the merge queue, where the shard job is skipped by a condition on `github.event_name`
  and the gate accepts the skip for that event alone; a skipped, failed or cancelled shard job
  fails it on every other event. The gate's own script is run under bash against a table of
  outcomes, with a control that cuts the full-lint refusal out and one that widens the queue
  skip to every event, and shows the table sees each go;
- only the issue job has a write permission, it runs for a red scheduled run alone, and no step
  in the workflow starts, wakes or prompts an agent or dispatches another workflow;
- the quick gate builds its tool environment with the same steps as the full lint, and the
  full lint keeps every step it had;
- the merge queue still triggers the workflow, and the daily sweep is scheduled;
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

## test_no_new_script_dependents.py: no new caller of a pending-role script

A tracked file depends on a `pending-role` script when its text names the script's path or its
basename, and a shared basename counts for each script that carries it.
`hand_installers_dependents.yml` maps each dependent file to the sorted scripts it names. The test
fails on a new dependency, on a file that names one with no row, on a row naming a script the file
no longer names, and on a row for a file that is gone. The baseline only shrinks; it is edited by
hand, never regenerated.

## test_no_new_hand_runbook_steps.py: the hand runbook steps stay frozen

A hand step is a fenced shell block in any `RUNBOOK*.md` that reaches a host (`ssh`, `scp`,
`rsync`) and changes it (writes a file, installs a package, manages a unit, moves files, changes
a firewall). `hand_runbook_steps.yml` lists how many such blocks each runbook holds, with a reason
as in `hand_installers.yml`. The test fails on more blocks than listed, on a runbook that is not
listed, and on fewer blocks than listed, so the count only falls: lower it in the PR that moves a
step into a role. Read-only checks over `ssh` and blocks fenced as `text` do not count.
It counts blocks, so rewriting one hand step into another keeps the count; a reviewer reads that.
The `Ansible` workflow watches `ansible/`, `hetzner/` and `mail/provision/` only (the last because
the `mx1_stack` role links and checks the mail host's scripts there), so a change to a runbook
under `mail/` or at the repository root does not start it; `mail/` is owner-gated by CODEOWNERS.

## merge_group_proof.py: whether the merge queue ran the Ansible workflow on a commit

The delivery no longer skips its lint and Molecule re-run for any commit: the merge queue runs
the lint and the unit tests only, so a queue run proves nothing about the containers, and the
delivery is the run that tests the merged tree in them. `check_delivery.py` holds the input
`skip-rerun-after-merge-group` at `false`. The job `queue-proof` of `ansible-delivery.yml` still
reads the runs of `ansible.yml` for the pushed commit and `merge_group_proof.py` answers
`tested=true` only for a run that has all of:

- the workflow `.github/workflows/ansible.yml`, the event `merge_group`, the pushed commit as head;
- a head branch that starts with `gh-readonly-queue/`;
- the status `completed` and the conclusion `success`.

The event is judged here and is never narrowed by the API's own `event` filter, because after a
squash queue main carries a green push run of the same commit under the same check name, from a
job with no diff. A check name, or any success on the commit, is not proof. A merge that skipped
the queue has no queue run, so it gets `tested=false`. An unreadable, truncated or malformed
answer is `false` too. The answer is not passed on: the delivery re-tests in full either way.

`check_delivery.py` fixes the shape of the proof job and the two inputs the delivery passes
(`skip-rerun-after-merge-group`, held at `false`, and `merge-group-check-name`, the gate job's
name in `ansible.yml`, which the reusable workflow ignores while the skip is off).

`check_delivery.py` also fixes the push route of both callers. The push list is the
`ANSIBLE_PUSH_HOSTS` repository secret, passed as `ssh_push_hosts` (the owner creates it; an unset
secret is empty, and empty means every host is pulled). The `push-playbook` input is the one path
`PUSH_PLAYBOOK`, defined once in `check_delivery.py` and imported by `test_drift_caller.py`. The
release floor `MIN_RELEASE` is `v1.0.23`, the first release of `branchLeft/github-workflows` that
declares the per-host key maps (`ssh_host_check_keys` and, for the delivery, `ssh_host_apply_keys`)
as well as the push list: a call that passes a key the called workflow does not declare fails on
GitHub. The delivery names `ssh_host_check_keys` (the repository secret `ANSIBLE_HOST_CHECK_KEYS`,
passed by the drift caller too) and `ssh_host_apply_keys` (the `SSH_HOST_APPLY_KEYS` secret of the
`ansible-hosts` environment). Both are optional in the workflow: an unset secret is empty, and a
host with no entry keeps the shared key. The `environment` command reports `ssh_host_apply_keys`
missing from the environment's secrets, because a repository secret of that name would be readable
by every workflow on main without the approval. A
`push-dry-run-stub` is not an allowed input.

After a lock-file merge (for example Dependabot), dispatch the Ansible workflow, because the
venv cache stays cold until the Monday sweep.

Named limit: that only an org-admin pull-request bypass can skip the queue comes from the org
ruleset standard. The ruleset's bypass list could not be read with the App tokens, so the owner
should confirm it from the owner's view.

## run_role_unit_tests.sh: the role unit suites

The lint job runs `run_role_unit_tests.sh` once, and it runs the unit tests of every
`roles/*/tests/unit` directory found by glob, with no list to edit. A suite fails the step when it
fails, runs no test, or skips or expected-fails a test: a role suite is a control, and a skipped
test is a control that does not run, so `OK (skipped=N)` and `OK (expected failures=N)` both fail
the step and name the role.

## test_plan_diff_scan.py: no copied file trips the plan's secret scan

The gated apply asks each host what a run would change, in check mode, with a diff. Before the plan
is shown to the approver, a scan reads that diff and withholds all of it when any line looks like a
secret. A role that copies a whole file (a program, a compose file) puts the file into the diff as it
changes, so one line that merely reads like a secret, such as a docstring sentence or an environment
variable reference, withholds the plan of the host: nothing can be approved.

The control is a task keyword, `diff: false`, set on the copy or template task whose file is not
secret but reads as secret-like text. The scan is a backstop, never loosened to fit a file (ANS-16).
There is no list of exceptions in the roles (owner ruling of 2 Nov 2026). A line that is prose is
reworded so it no longer matches. `diff: false` is set only on the task of a file whose matching line
is a variable reference or a name that cannot change, and each such task carries a comment citing
ANS-16.

The one exception is a named allowance in the scan itself (owner ruling of 10 Nov 2026): a file path
and one whole line, in the `allowances` array of the `ssh-check-hosts` action in `github-workflows`,
which the code owners approve, so a new entry is a reviewed change there. The scan passes that line
only in that file and only as the whole line; the diff of the file is still shown to the approver in
full. `SCAN_ALLOWANCES` in the test is a copy of the array, so the test passes the same line. Today it
holds one entry, the `GH_TOKEN` placeholder line of `hetzner/provision/branchleft-verify-image`, so
that file needs no `diff: false`. An entry is added in both places in one change. The test fails an
entry whose line is not on one line of its file, so a name held apart from its value cannot stand in
for it, and fails a shown file that assigns through an expanded name (`export "$NAME=$VALUE"`), the
shape that was used to hold a name apart. That second test reads one shape and is not a proof that no
other split exists: the scan reads a line at a time, and the review of a copied file is the rest.

What the test enforces, over every `copy` and `template` task of the roles the playbooks list:

- A task whose source has a matching line sets `diff: false`, on the task or on a block around it.
  `no_log` alone does not count: it hides the result, not the diff.
- A task that sets `diff: false` hides only files that match. A file with no matching line under
  it is a finding, so a loop that mixes the two is split into a hidden task and a visible one, with
  a constant list of the hidden files in the role's `vars/` (`control_plane`, `monitoring_stack`,
  `demo1_build`). The test resolves those loops through `intersect`, `difference`, `selectattr` and
  `rejectattr` against a list, and no other filter. A task that sets `no_log` is not held to this:
  it renders a secret into the file, which its source does not show.
- A source the test cannot find or resolve is a finding unless the task sets `diff: false`. Inline
  `content` and `remote_src` are skipped, as there is no local file. One list is made while the
  role runs: `edge_stack_deliver` is the static CrowdSec files of the role's vars plus the files
  directly in `crowdsec/acquis.d`, found by a `find` on the controller, and the test makes the same
  list from the checkout, so the CrowdSec and acquisition files stay visible in the plan and a
  matching line in one fails.

- A file whose text on a host still matches, though the checkout's no longer does, is listed in
  `RETIRED_MATCHES` with the line the host holds. A diff is the old text against the new one, so the
  removed line reaches the plan. The test then requires the task that copies it to set
  `diff: false`, and accepts that hide although the checkout has no matching line. It fails when the listed line no longer matches the scan or
  the checkout matches again. The entry and the file's place in the role's hidden list are removed
  once the apply that rewrites the text is live. It is never used for a line that can be reworded
  in the checkout.

A finding names the task file, the task, the source and the line number, never the text of the line.
The test reads the source of a task, not the text Ansible renders from it; a template whose rendered
text differs from its source is judged by its source.

The pattern is the `credential-assignment` entry of the backstop in the step "Judge the answers,
scan the diff and write the result" of the `ssh-check-hosts` action in branchLeft/github-workflows,
at the tag `ansible-gated-apply.yml` pins (v1.0.19 when this was written). The workflow runs it as
`grep -Eiq` on the diff, line by line, in the C locale. The test translates it: `re.I` for `-i`,
`re.A` so that `\s` is the ASCII set the C locale gives the POSIX space class, `\s` for
`[[:space:]]`, and a split on the newline alone (not `str.splitlines`, which also splits on form
feeds). A test runs the workflow's own expression through `grep -Ei` on sample lines and compares
verdicts. The other entries of the backstop name key material and tokens that no role file holds, so
they are not copied.

## check_secret_no_log.py: the secret taint check

The check reads every role under `ansible/roles/` and every pattern under `ansible/patterns/`,
and the host rows of `host_inputs`. Its test is `test_check_secret_no_log.py`, which runs in the
`unittest discover` step of `ansible.yml` with no workflow change. Run it as
`python3 ansible/checks/check_secret_no_log.py`; a finding prints as `FAIL R<n> <path>: <what>`
and names a task or a variable, never a value.

It imports `ansible-core` (the pinned version in `ansible/requirements.txt`), which the `checks`
job installs into the same virtual environment as `mypy` and `ruff`, so it needs no step of its
own. Run it under that environment: a Python without `ansible-core` cannot import the module, and
the failure is loud (an import error), never a pass.

Rules:

- **R1, taint.** The seeds are the options of the role's `main` argument spec with
  `no_log: true`, and, for a list or mapping option, the sub-options with `no_log: true`
  (see "Sub-option secrets" below). The `host_inputs` loader declares no option, so its own
  `host_inputs_raw` and `host_inputs_doc` are seeds by name, and a rename that leaves a seed
  named by no task is a finding. Taint follows a value through the role's `vars/` and
  `defaults/` by exact variable name, to a fixed point, and a variable that is reached through
  two secrets names both. A task under `tasks/` or `handlers/` that names a tainted variable must set
  `no_log: true` as a literal. `block`, `rescue` and `always` are recursed, and a block's
  literal `no_log` and `diff` are inherited. A task that writes a file (`copy`, `template`,
  `lineinfile`, `blockinfile`, `replace`, `assemble`) from a tainted variable must set
  `diff: false` as a literal (ANS-16). A task names a variable in any argument, loop,
  `with_*`, `vars`, `environment`, `loop_control` or in a template that its `src` names
  (read from `templates/`). It does not name one in `when`, `failed_when`, `changed_when`,
  `until` or the `that` of an assert: those print their expression, and the refusal asserts
  need their coded messages to reach the log. A secret named in an assert's `fail_msg` counts.
- **R2, the loader's names.** Each row of `host_inputs_required_by_host` must be a non-empty
  list of names for a host that `checks/host_roles.yml` lists. Each name must resolve to
  exactly one declared option of a role on that host's list. An unreadable file, row or host
  list is a finding, so an unreadable file never means that no loader secret exists.
- **R3, agreement.** The table "The secret options of the roles" in the pattern README must
  equal, as a set, the `(role, option)` pairs of the `no_log` options, and each Source must
  equal the value R2 derives: `host_inputs: HOST[, HOST]`, or `none`. The older table of
  script-side names must have each name read by a file under `hetzner/`, `mail/` or a root
  `RUNBOOK*.md`. The reverse direction, that every script name is listed, is reviewed by hand.
- **R4, tasks the check cannot follow.** In every role or pattern that holds a secret, each task
  must be one that Ansible's own task parser accepts and the check can follow (see "The task
  layer"). A finding reads `R4 <file>: task '<name>' cannot be followed: <why>`, and the reasons
  are: the parser refuses the task (the message names the class and Ansible's own text, never the
  task's data); the action does not resolve to a plugin Ansible can load (a templated action, an
  unknown name, a collection that is not installed, the removed bare `include:`); the task
  includes a file named by a template; it includes a file that is not a task file the check
  reads (a missing file, or one outside `tasks/` and `handlers/`); it includes a role; or a text
  reads variables by a name the check cannot see (`vars` or `hostvars` taken whole, called on, or
  subscripted by a name that is not a literal, a `vars` lookup with a term that is not a literal,
  a lookup whose plugin is not a literal), in a task, a template or a vars file. A file under
  `tasks/`, `handlers/`, `vars/`, `defaults/` or `meta/` that the check does not read is an
  `R4 <file>: ... does not read` finding naming the file (see "The role's files"). A role with no
  secret is not read, so R4 never fires there.

Sub-option secrets. An option such as `tenant_compose_stacks` holds a secret only in an
attribute of its items (`secrets_env_text`). The option is then a seed for that attribute only:
any read of the option needs `no_log`, whatever its spelling (`x.secrets_env_text`,
`x['secrets_env_text']`, `x.get('secrets_env_text')`, `x.items()`, `x.values()`, `x | to_json`,
a chain of calls). Only an allow-list is cleared: a read through a declared sub-option that is
not a secret (`x.slug`, `x['slug']`, `map(attribute='slug')`) and the `length` and `count`
filters. An attribute the spec does not declare is not cleared. A task that loops
over the option, and names a `loop_control.loop_var`, makes that loop variable a seed for the
same attributes in every task file of the role, because an `include_tasks` file reads it. A loop
over a secret that includes tasks and keeps the default `item` is a finding: the included tasks
cannot be followed through `item`. Names set under a task's `vars:` are not reads, but they
carry what they are set to: a name bound under `vars:` (an include's, a block's, an include's
`apply: vars:`) to a value that reads a secret is a secret in every task file of the role, because
the included file reads it and `no_log` on an include does not reach the tasks it includes. An
include's `apply: vars:` is read wherever Ansible's parser finds `apply` (see "The task layer").
A bare partial name keeps its attributes. An include that passes such a name into a file
the check cannot follow (a templated name, a file that is not a task file of the role, a role)
is an R1 finding as well as an R4 one, because R1 says which secret went there.

The task layer. What a task calls, which file an include names, and what an include binds under
`apply:` are never decided by a spelling matcher in the check. Each task of a role that holds a
secret is resolved the way the executor resolves it (`ansible.playbook.helpers.load_list_of_tasks`):

- `ModuleArgsParser(task).parse(skip_action_validation=True)` classifies it, so `include_tasks`,
  `ansible.builtin.include_tasks`, `ansible.legacy.include_tasks`, `action: include_tasks f.yml`
  and the same for the other three include actions all give the same answer.
- An include of tasks is then loaded by `TaskInclude.load` (`HandlerTaskInclude.load` under
  `handlers/`), whose `check_options` is the only place that chooses the file: `_raw_params`
  (the free-form text, or `args: {_raw_params: ...}`) when it is set, otherwise `file`. Both set
  is not a finding: the file followed is the one the executor includes. It also refuses what
  Ansible refuses (no file, an unknown key, `apply` on an `import_tasks`, `args` that is not a
  mapping, `diff:` or `delegate_to` on an include), and each refusal is an R4 finding.
- An include of a role is loaded by `IncludeRole.load` and is always an R4 finding: the role it
  runs is outside this role's taint, and no role includes another (ANS-12).
- Any other task is loaded by `Task.load` (`Handler.load` under `handlers/`) and resolved to its
  fully qualified name by Ansible's own plugin loaders. `copy`, `ansible.legacy.copy` and
  `action: copy content=...` are all `ansible.builtin.copy`, so the `diff: false` rule, the
  `template` source read and the assert allowance apply to every spelling. A module or action
  plugin a role ships under its own `library/` or `action_plugins/` resolves, because the check
  registers those directories as Ansible does when it loads a role (`add_all_plugin_dirs`).
- The file an include names is found by `DataLoader.path_dwim_relative`, beside the including
  file and then in the role's `tasks/` (or `handlers/`), and must be one of the task files the
  check reads. A name that is a template (`Templar.is_possibly_template`) has no static target.

- A module argument that is a bare variable name is a read of that variable with no braces.
  In `ansible-core` 2.21 that is `debug`'s `var` (any spelling that resolves to
  `ansible.builtin.debug`: `debug: var=x`, `var:`, `args:`, `action:`, `ansible.legacy.debug`) and
  `assert`'s `that` (already expression-only). `with_vars` terms are names too. The `with_*`
  forms of the other lookups take literals, not names.

The role's files. The files of a role are found the way `Role` finds them, not from a list kept
here. The spec comes from the first of `meta/argument_specs.yml`, `.yaml`, `.json`, else from the
`argument_specs:` key of the role's `meta/main` file (`Role._get_role_argspecs`); data is not
combined between the two. `tasks/` and `handlers/` are read from `main` in each layout
`DataLoader.find_vars_files` resolves (`main.yml`, `main.yaml`, `main.json`, `main` with no
extension, or a directory named `main`), and `vars/` and `defaults/` from the same names with the
directory form allowed, where every file under it is read. Any other file under `tasks/`,
`handlers/`, `vars/`, `defaults/` or `meta/` that the check does not read (a hidden or backup
file, one with another extension, a second `meta/main` that the first shadows, a spec that
another spec file shadows) is an R4 finding naming it, because a file the check does not read is
a file it cannot clear.

Indirect reads. `lookup('ansible.builtin.vars', 'name')` (any spelling of the plugin, and `query`
and `q`), `vars['name']`, `vars.name`, `hostvars[inventory_hostname].name` and
`hostvars[...]['name']` read the variable `name`, and count as a read of it, with a Name node of
its own or not, when the name is a literal. When it is not (`vars[x]`, `vars | to_json`, `vars.get(...)`,
`lookup('vars', x)`), the check cannot say which variable is read, and the text is an R4 finding.

The collection finder is installed with `init_plugin_loader`, as `ansible-playbook` installs it.
The only list of names the check keeps is the fully qualified names of the write actions, assert
and template, and those are matched after Ansible has resolved the spelling.

How references are read: by Jinja's parser alone (`Environment.parse`, then the names the
parse tree loads). The check does not compile the template, because Ansible's filters
(`dirname`, `password_hash`) are not Jinja's and a compile refuses them. A name bound by a
loop counts, which asks for more `no_log`, never less. A text that does not parse is a finding,
since a text the check cannot read cannot be cleared.

What it does not see:

- Only options and sub-options that declare `no_log: true` seed the taint (and the loader's two
  variables). An option that holds a credential without the flag is invisible to R1. Which
  options are secrets is the owner's classification, so that list is a ticket of its own.
- Taint is by variable name, within one role (ANS-12). It does not follow `set_fact`,
  `register`, or a value passed through a playbook, a `trust/` file or another role. The
  loader's facts are seeded by the role that consumes them, as options of that role.
- Playbooks and `trust/` files are not scanned, and neither is a `molecule/` directory.
- `control_plane_masterkey_secret` is not tainted. Its value is a file-attributes record (path,
  owner, group, mode) and holds no secret. The master key is guarded by the write task that
  names `control_plane_masterkey` directly, and the test pins that boundary, so it is a visible
  choice and not an accident. Tainting the record by a name prefix would force `no_log` onto
  the empty-create and mode tasks and hide their failures.
- The task layer is Ansible's, so its limits are named. A task with a template in its action
  is refused, not read. A `block` is read for its tasks only: Ansible's own validation of a
  block's keys is not applied, since a block carrying a stray key does not run. `apply:` can
  carry attributes of its own (`no_log`, `tags`), which the check does not read as inherited by
  the included tasks. Each task is resolved on its own: a `collections:` list set at play or role
  level (`meta/main.yml`) is not in scope, so a short module name that only that list resolves
  is an R4 finding (no role of this estate sets one). `include_vars` and `vars_files` are not
  followed. A module of one role resolves for a role checked after it in the same process, as it
  does in a play that loads both. The action lists the executor itself uses
  (`ansible.constants._ACTION_*`) are private names of `ansible-core`. The check reads them
  when it is imported, so a rename on a version bump is an `AttributeError` at import, never a
  quiet change in what is followed (a test removes each in turn). The check does not run Ansible: it knows what parsing and plugin
  resolution can say, and nothing that depends on a variable's value at run time.
- A loop variable is followed only when the loop names it (`loop_control.loop_var`), or the
  loop has no include. A `set_fact` or `register` that copies an attribute into another
  variable is not followed. A value that comes in through `lookup('template', ...)` is not
  read, and neither is a subscript the parser cannot see as constant (`x[name]`, which counts
  as a read of the whole option and so asks for more `no_log`).
- R3 checks the table's rows, not what the consuming role does with a value.

Sabotage, each one a copy of the real files with one control broken, and the baseline copy
clean (`test_check_secret_no_log.py`, 73 tests, green under the pinned ansible-core venv):

| Sabotage in the copy                                                  | Finding that goes red                                                                     |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `no_log: true` removed from the write of the four `NTFY_` lines       | R1: the task names `ntfy_pager_env_lines (secret through ...)` and the four pager secrets |
| The same write with `no_log: '{{ true }}'`                            | R1: must set `no_log: true` (a templated value is refused)                                |
| `no_log: true` removed from the loop over `monitoring_stack_env_keys` | R1: `monitoring_stack_env_keys (secret through ...)` and the monitoring secrets           |
| `no_log: true` removed from the write of the master key               | R1: names `control_plane_masterkey` and must set `no_log: true`                           |
| `diff: false` removed from the master key copy                        | R1: must set `diff: false (ANS-16)`                                                       |
| A task with a template that does not parse                            | R1: does not parse                                                                        |
| `no_log: true` removed from the loader's set_fact of every input      | R1: `host_inputs_doc`, must set `no_log: true`                                            |
| `no_log: true` removed from the loader's parse task                   | R1: `host_inputs_raw`, must set `no_log: true`                                            |
| `no_log: true` removed from the write of a tenant's secrets file      | R1: `tenant_compose_stack (secret through tenant_compose_stacks.secrets_env_text)`        |
| `no_log: true` removed from the loop that includes each tenant's file | R1: `tenant_compose_stacks (secret through ...)`                                          |
| `no_log: true` removed from the other four sub-option roles' writes   | R1: must set `no_log: true`, each named by its task                                       |
| A loop over a secret with an include and the default `item`           | R1: must name a loop_var                                                                  |
| The tenant secrets write read as `.get(...)`, `.items()`, `.values()` | R1: must set `no_log: true` (a call on the item is a read of the item)                    |
| A secret bound under an include's `vars:`, written with no `no_log`   | R1: the included file's task names the bound name (secret through ...)                    |
| A secret bound on an include of a file the check cannot read          | R1: passes the name into an include that cannot be followed                               |
| A secret bound under the task's `args:` `apply: vars:`, written bare  | R1: the included file's task names the bound name (secret through ...)                    |
| An include with an `args:` that is not a mapping                      | R4: Ansible's own task parser refuses it                                                  |
| An include spelled `ansible.legacy.`, `action:`, `args:` or free-form | R4 or R1 as for the bare spelling, one case per spelling in `TaskParserTest`              |
| `_raw_params` and `file` both set, the one Ansible includes unread    | R4: not a task file of the role that the check reads                                      |
| An include whose file is named by a template, a missing file          | R4: named by a template, or not a task file                                               |
| An include of a role, in any spelling                                 | R4: it includes a role                                                                    |
| An action Ansible cannot resolve, a templated action, bare `include:` | R4: cannot be followed                                                                    |
| A secret written by `ansible.legacy.copy` or `action: copy ...`       | R1: must set `diff: false (ANS-16)`, and `no_log: true`                                   |
| `debug` with `var:` or `var=` naming a secret, in every spelling      | R1: must set `no_log: true`                                                               |
| The spec in each file Ansible reads it from                           | R1: as for the spec in `meta/argument_specs.yml`                                          |
| Tasks, handlers, vars, defaults in each layout Ansible loads          | R1: the task or the derived variable is named                                             |
| A file of the role that the check does not read                       | R4: `does not read`, naming the file                                                      |
| A secret read by `vars[...]`, `hostvars[...]` or the `vars` lookup    | R1: names the secret, must set `no_log: true`                                             |
| `vars`, `hostvars` or a lookup read by a name that is not literal     | R4: reads variables indirectly                                                            |
| A renamed `ansible.constants._ACTION_*` name                          | `AttributeError` when the check is imported                                               |
| A row name that is no option (`monitoring_stack_smtp_passwd`)         | R2: resolves to 0 options, not one                                                        |
| The loader's rows file made unreadable                                | R2                                                                                        |
| A secret option with its row removed from the README                  | R3: no row for the no_log option                                                          |
| A row with a wrong source                                             | R3: has source `host_inputs: edge1`, the derived source is `host_inputs: edge1, edget`    |
| The table's heading changed                                           | R3: the table is missing, empty, or not three columns                                     |
| A script name that nothing reads                                      | R3: the name is read by no file under `hetzner/`, `mail/` or root                         |

The expression-only allowance is pinned too: an assert whose `that` names a secret, with no
`no_log`, is clean.

On the real tree the check reports how many `no_log` options it found and how many variables are
reached from them (run it to read the figures: `ntfy_pager_env_lines`, `monitoring_stack_env_keys`
and the `ci_jump_legacy_*` paths built from `ci_jump_user` are among them). Every task that names one of them already
sets `no_log: true`, and every file writer among them sets `diff: false`, so the check finds no
R1 failure on `main`.

## test_deploy_verifier_coverage.py: the verifier before every wrapper role

The deploy wrapper refuses a registered image unless `deploy_verifier` has put the verifier and its
pinned gh on the host. The test holds three things: the table `WRAPPER_ROLES` names every role that
names the wrapper's path in its tasks, vars or defaults; every playbook that applies one of those
roles applies `deploy_verifier` earlier in the same play, and only the hosts in
`WRAPPER_PLAYBOOKS` apply one at all; and the paths the wrapper reads, and the pins the role
installs, agree and sit in `vars/`. A new wrapper role is added to the table in the same change, or
the test names it.
