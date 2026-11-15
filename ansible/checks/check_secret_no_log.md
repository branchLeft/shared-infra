# check_secret_no_log.py: the secret taint check

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
  list of names for a host that `checks/host_roles/` lists. Each name must resolve to
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
- **R5, the baseline.** `secret_no_log_baseline.yml` lists, by file and task name, the R1
  findings the tree has today (a task that names a tainted variable and lacks `no_log`, or
  `diff: false`). A finding it does not list fails the check, and an entry that no longer fires
  fails it too, so the list only shrinks: remove an entry in the change that fixes its task.
  Adding an entry is not a fix, and the baseline is a control, so a new entry needs the owner's
  review.

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
- Taint is by variable name, within one role (ANS-12). A `set_fact` argument is followed as a
  variable of its name, and a `register`ed result is followed when its task names a tainted
  variable, so a secret printed through either needs `no_log` on the task that prints it. It does
  not follow a value passed through a playbook, a `trust/` file or another role. The loader's
  facts are seeded by the role that consumes them, as options of that role.
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
  loop has no include. A `set_fact` or `register` copy of a secret attribute is followed as that
  attribute; a copy of a declared non-secret attribute is not, as for any read. Still open, and
  not followed: a value that comes in through `lookup('template', ...)` is not read, and a
  `collections:` list set at play or role level is not in scope, so a short name only that
  list resolves is an R4 finding. A
  subscript the parser cannot see as constant (`x[name]`) is not read either; it counts as a read
  of the whole option and so asks for more `no_log`.
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
