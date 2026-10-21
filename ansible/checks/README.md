# check_enrolment

`check_enrolment.py` checks the host playbooks that run under the gated pull (ws#2340).
A top-level playbook is under the pull when one of its plays applies the `pull_trigger`
role. Its trust anchor is `ansible/trust/HOST.yml`. A failure names the rule and the
file. `test_check_enrolment.py` runs the check over the real tree and over one sabotaged
copy per rule, and asserts that each sabotage hit its text.

## What the check sees, and what it does not

It sees the literal keys of every YAML or JSON file under `ansible/` that Ansible can
load as variables (any name, any of `.yml`, `.yaml`, `.json` or no extension), except a
role's or pattern's `molecule/` directory and a role's `meta/argument_specs.yml`, which are
fixtures and schema. A file that does not parse is refused. A symlink that leads out of
`ansible/` under a loaded directory is refused.

It catches a protected key (`pull_trigger_signers`, `pull_trigger_remote_url`,
`pull_trigger_playbook`, `pull_trigger_playbooks`, `enrolled_host`) set outside the one
file that owns it, and a loader it cannot read.

It does not judge what a role does. The roles run as root, so a change to `roles/` can
change what a host does with its signers, and this check does not see that. The control
on a role edit is the deploy approval of a gated pull, which is not built on `main` yet
(ws#2338 and ws#2324 are open, and ws#2483 is an open design issue, not a ruling). Until
it is, a role edit is not gated by anything in this repo. Which files the reviewer App
may merge alone is an owner decision (Desk `pull-roles-owner-only-2340`).

Limits of the loader rule. It reads literal mapping keys. It names the loaders listed in
`ROLE_LOADERS`, `TASK_FILE_LOADERS` and `INCLUDE_VARS`, in their bare, `ansible.builtin.`
and `ansible.legacy.` spellings, and the `action:` and `local_action:` forms of those. It
does not parse the free-form arguments of other modules, other than a protected key
written as `key=value` in a string. A loader or module outside those sets is not seen.

## Rules

- **R0** The three shared includes exist under `playbooks/includes/`. Each refusal
  include holds exactly one task: its name and its assert, with exactly its expressions
  and no other key (`when`, `ignore_errors` and `tags` are refused).
- **R1** At least one top-level playbook is enrolled, so the check cannot pass over nothing.
- **R2** Each enrolled `HOST.yml` has one play on `hosts: all`, `vars.enrolled_host`
  equal to `HOST`, `vars_files` exactly the shared include and `../trust/HOST.yml`,
  `roles` exactly the runtime entry then the bare trigger, and `pre_tasks` exactly the
  refusal include then the signer include, each a task of only its name and include.
- **R3** The shared include holds exactly the remote literal and the playbook derivation
  from `enrolled_host`, and no other key.
- **R4** The trust files are exactly the enrolled playbooks, one file each.
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
