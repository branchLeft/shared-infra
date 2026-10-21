# check_enrolment

`check_enrolment.py` checks the host playbooks that run under the gated pull (ws#2340).
A playbook is under the pull when one of its plays applies the `pull_trigger` role. Its
trust anchor is `ansible/trust/HOST.yml`. A failure names the rule and the file, and
`test_check_enrolment.py` runs the check over the real tree and over one sabotaged
copy per rule.

## What the check catches, and what it does not

It catches a protected key (`pull_trigger_signers`, `pull_trigger_remote_url`,
`pull_trigger_playbook`, `pull_trigger_playbooks`, `enrolled_host`) set outside the one
file that owns it, and a loader R6 cannot read. It does not make a role edit safe. The
roles run as root, so a change to `roles/` can change what the host does with its
signers. The control on that is the deploy approval (T14, the gated workflow), not this
check. Which files the reviewer App can merge alone is an owner decision (Desk
`pull-roles-owner-only-2340`).

## Rules

- **R0** The three shared includes exist under `playbooks/includes/`. Each refusal
  include holds exactly one task: its assert, with exactly its expressions.
- **R1** At least one top-level playbook is enrolled, so the check cannot pass over nothing.
- **R2** Each enrolled `HOST.yml` has one play on `hosts: all`, `vars.enrolled_host`
  equal to `HOST`, `vars_files` exactly the shared include and `../trust/HOST.yml`,
  `roles` exactly the runtime entry then the bare trigger, and `pre_tasks` exactly the
  refusal include then the signer include, each a task of only its name and include.
- **R3** The shared include holds exactly the remote literal and the playbook derivation
  from `enrolled_host`, and no other key.
- **R4** The trust files are exactly the enrolled playbooks, one file each.
- **R5** Each trust file holds one key, `pull_trigger_signers`, as a list (it may be empty).
- **R6** A protected key is set only in its owner's file. An include or import of a
  task file, a role or a `vars_files` target that R6 cannot read is refused. Role
  argument specs and molecule scenarios are fixtures and are not read. An unparseable
  file is refused.
- **R7** A top-level playbook that is not enrolled names neither `pull_trigger` nor `trust/`.
- **R8** The config writer in `roles/pull_trigger/tasks/main.yml` takes its `signers`
  and `remote_url` from the pinned variables, not from a literal.

The refusal's host test is not a host control. Under the trigger `inventory_hostname` is
`localhost`, and the root-owned pull config is the control on the host.
