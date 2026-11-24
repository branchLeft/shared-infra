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
host in `HOST_PLAY_VARS` in `check_enrolment.py` (seven rows: ops1's, db1's and dbt1's are each `deploy_tooling_host_class: internal` alone; edge1's `deploy_tooling_host_class`
with `egress_nat_gateway_enabled: true`, the one switch that makes a host a NAT gateway, and the
`edge_firewall` role's `edge_firewall_nat_source` (the estate subnet it masquerades) and
`edge_firewall_enforce` (`false`, monitor mode, until the owner merges the one-line flip to
default-drop), so only edge1 can carry those two; edget's
`egress_nat_gateway_enabled: true` alone (edget is the server edge-t, the tenants network's gateway:
a network does not span hcloud projects, so there is one gateway per network, edge1 for the estate's
and edget for the tenants', and `test_egress_nat_single_gateway.py` refuses a second on either; the
logical name has no hyphen because `HOST_NAME` allows `[a-z][a-z0-9]*`); app1's
`deploy_tooling_host_class` with `deploy_tooling_policy_variant`,
which the role takes with no default for the class and which a host of class app must name; and mx1's `host_baseline_fail2ban_ignoreip_none: true`; no other variable: a
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
non-gateway that applies the role to apply it bare. appt1 (app-t1) is the same: the same
`HOST_PLAY_VARS` row and the same bare `egress_nat`.

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
Ownership is the same for both. CODEOWNERS releases every Markdown file except `CLAUDE.md` and
the files under `.github/`, which stay the owner's, so the reviewer App
may merge an edit to `trust/README.md` or to `playbooks/README.md` alone. The trust files beside
`trust/README.md` stay the owner's merge (`/ansible/trust/` in CODEOWNERS).

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
  host's list in `host_roles/HOST.yml` (R9), and `pre_tasks` exactly the refusal include then
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

- **R9** `host_roles/` exists and holds one `HOST.yml` per host, each a list of distinct role names
  (`[a-z][a-z0-9_]*`), never `ansible_runtime` or `pull_trigger`. A file that is not `HOST.yml`
  for a valid host name, or whose list is malformed, is a finding and gives that host no listed
  roles, so its playbook may apply the two pull roles only; a host with no file has none either.
  One file per host, not one list, so a pull request that gives one host a role does not meet
  another host's on a line. The directory is in `ansible/checks/`, which CODEOWNERS gives to the
  owner whole, so a new host's file is owned without a new CODEOWNERS line, and adding a role to a
  host is the owner's merge. The check reads names, not directories: a role may be listed
  before its directory merges, and until then it runs nothing. Order after the pull roles
  is free, except for the loader (R11), and a listed role need not be applied.
- **R10** `owner_vars/` holds the owner's values for a host's roles. It is flat, and a name
  must be exactly `HOST.yml` for an enrolled host; the name rule above refuses anything
  else, and R6 refuses a protected key in it (its allowed set is empty). Each file holds
  exactly the keys its host is allowed and no other, with values of the right shape. For
  edge1 those are `ci_login_manage_keys`, a bool, and `ci_login_keys`, a list of
  `{key, mode}` entries with `mode` one of `apply` and `check`; an entry with any other
  key (a source address list, say) is refused. edge1 also holds `sweego_receiver_port` and
  `sweego_receiver_drain_port`, each a whole number (a bool or text is refused; the role holds
  the range and that the two differ); `test_sweego_receiver_wiring.py` holds the webhook port to
  the edge's list of upstream ports and the drain port out of it and out of the public firewall. The four values of the `ci_jump` role that live in the repository are
  allowed on every host in `JUMP_HOSTS` (each jump host has its own file, address,
  destinations and keys): `ci_jump_manage_keys`, a bool, `ci_jump_own_address`, text,
  `ci_jump_destinations`, a list of text, and `ci_jump_keys`, a
  list of `{key}` entries with nothing else (a destination list per key is refused: the role
  takes one list for every key). `JUMP_HOSTS` (edge1 and edget) must equal the hosts whose
  `checks/host_roles/HOST.yml` lists `ci_jump`: a host cannot gain the role without its keys, nor
  the keys without the role. The role's fifth variable, `ci_jump_user` (the jump account's name, which
  the owner keeps out of the repository), is not allowed in an `owner_vars` file: it reaches the
  role through the host's `host_inputs` row. What a destination or a key may look like is the role's rule alone,
  in its module. For ops1 the required keys are `pull_trigger_steps`,
  the gated pull's step allow-list: a list of `{id, tag, word}` mappings, all text, and
  `control_plane_db_apps_image`, the applications image the steps run, which must be text.
  `control_plane_app_image`, the image the control plane runs, is allowed on ops1 only and is
  a key a file may leave out (`OPTIONAL_OWNER_KEYS`): it must be text when present, and
  `test_step_allowlist.py` holds it to the `control_plane` role's digest pattern. Absent, the role
  keeps the running image; present, the next gated apply moves the pin.
  The `ring_controller_host` role adds two more, both text and both allowed on ops1 only:
  `ring_controller_host_bundle_sha256` and `ring_controller_host_bundle_url`. Each may be the
  empty string, which is how the role starts inert; what a value may look like is the role's
  rule alone. The role's old `ring_controller_host_ledger_url` is no longer allowed: an owner
  file that still sets it is refused here, and the role refuses the name too. The push remote and the
  known-hosts line it used to take are no longer allowed, so an owner file that still sets one is
  refused here (Ansible's own spec check does not read an owner file's values).
  The `mail_collector` role adds its eight inputs (`MAIL_COLLECTOR_KEYS`), allowed on ops1 only and
  each optional, since an absent key leaves the role's inert default: `mail_collector_image`,
  `mail_collector_smtp_host`, `mail_collector_demo_mail_domain` and `mail_collector_shim_scheme`
  (text), `mail_collector_hosts` (a list), `mail_collector_smtp_port` and `mail_collector_shim_port`
  (whole numbers) and `mail_collector_smtp_secure` (a bool). What a value may look like is the
  role's rule alone. The sending credential is never a key here: it is the file the owner places.
  The `host_tls_identity` role adds one, `host_tls_identity_peer_cert`, text, allowed on the hosts that
  apply the role (`HOST_TLS_HOSTS`: demo1) and required there; it is empty until the owner has read the peer's
  public certificate off its host. The role holds every shape rule for it (one certificate, self-signed, the use,
  the name, the lifetime), so only the type is read here. `HOST_TLS_HOSTS` must equal the hosts whose
  `checks/host_roles/HOST.yml` lists the role, as for `ci_jump`.
  The `ci_step_login` role adds two, allowed on ops1 only: `ci_step_login_key`, text, and
  `ci_step_login_from`, a list of text. `test_ci_step_login_pins.py` holds the real key and
  addresses to the owner's values.
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
  literal keys of its input task, `host_roles/`, the playbook and the role argument specs
  in agreement, and the structure of the loader's tasks.

- **R12** `playbooks/bootstrap/HOST.yml` is the owner's one hand step for a host that has none of
  its inputs yet: it installs the pull and nothing else, so the first apply of every other role
  goes through the gated `ansible-hosts` approval. It exists only for an enrolled host (`HOST.yml`
  beside it), has one play with no key but `name`, `hosts`, `gather_facts`, `vars`, `vars_files`,
  `pre_tasks` and `roles`, on `hosts: all`, `vars` exactly `enrolled_host: HOST` (the
  host's other play variables belong to roles it does not apply), `vars_files` exactly the shared
  include, `../../trust/HOST.yml` and `../../owner_vars/HOST.yml` if and only if that file exists,
  `pre_tasks` the two refusals, and `roles` exactly the runtime entry and the bare trigger, at
  one level deeper than a host playbook. Any other role is a finding, `host_inputs` by name: a
  fresh host has no inputs file and its seed tool arrives with the first gated apply, which then
  stops at the loader. No tag, `when` or `vars` can sit on a role entry, so no tag widens the
  run. The file is never pulled (R3 derives `playbooks/HOST.yml`), and R6 reads it as an
  enrolled playbook. Run it with `-i "HOST," -e ansible_host=ADDRESS`, as for a host playbook.

The refusal's host test is not a host control. Under the trigger `inventory_hostname` is
`localhost`, and the root-owned pull config is the control on the host.
