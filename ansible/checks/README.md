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

Limits of R2. It pins the values of `vars.enrolled_host`, `vars_files`, `roles` and
`pre_tasks`. It does not pin the other keys of that play, so a `post_tasks`,
`tasks`, `handlers`, `environment` or `module_defaults` copy that writes a literal
signer config is not seen. A playbook is a place a literal can hide as well as a role.

Limits of the loader rule. It reads literal mapping keys. It names the loaders listed in
`ROLE_LOADERS`, `TASK_FILE_LOADERS` and `INCLUDE_VARS`, in their bare, `ansible.builtin.`
and `ansible.legacy.` spellings, and the `action:` and `local_action:` forms of those. It
does not parse the free-form arguments of other modules, other than a protected key
written as `key=value` in a string. A loader or module outside those sets is not seen.

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
  R6 must read every file in the tree. Each enrolled `HOST.yml` has one play on
  `hosts: all`, `vars.enrolled_host` equal to `HOST`, `vars_files` exactly the shared
  include and `../trust/HOST.yml`, `roles` exactly the runtime entry then the bare trigger,
  and `pre_tasks` exactly the refusal include then the signer include, each a task of only
  its name and include. An enrolled playbook is read only at the top of `playbooks/`; the
  pull runs only that path.
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

The refusal's host test is not a host control. Under the trigger `inventory_hostname` is
`localhost`, and the root-owned pull config is the control on the host.
