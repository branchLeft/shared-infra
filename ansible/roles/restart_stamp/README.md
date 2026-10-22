# restart_stamp

Reads, decides and records the stamps of a restart-by-fingerprint role: the one place that says whether a class of files is adopted, due or half-done, and writes the file that remembers it.

This README is for a maintainer who is new to the repository. It follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

A role that restarts something when its files change (the shape of `edge_stack` and `monitoring_stack`) works out a fingerprint of the files it delivers, acts, reads the result back and writes a stamp last, with no handlers. A handler loses its restart when a run fails between the write and the flush, because the rerun finds nothing changed; a stamp written only after the read-back does not. This role holds the steps of that shape that are the same for every caller, so there is one copy of them:

| Entry point    | What it does                                                                                                                     | Writes                             |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `read`         | Reads the stamp of each class. A stamp that is not there is `absent`; one that is there and cannot be read fails the run.        | nothing                            |
| `decide`       | For each class, works out whether it is adopted, due, and to be marked pending, from the stamp, the fingerprint and three flags. | nothing                            |
| `mark_pending` | Writes `pending` into the stamp of each marked class, before any file of the class is placed.                                    | `pending`, not in check mode       |
| `adopt`        | Writes the fingerprint into the stamp of each adopted class and acts on nothing.                                                 | the fingerprint, in check mode too |
| `record`       | Writes the fingerprint into the stamp of each class whose action the caller says was read back, and into no other.               | the fingerprint, not in check mode |

The caller keeps everything that depends on its host: the fingerprint of each class (which files, hashed how), whether a file differs on the host (drift), whether the class may be touched now (the gate), the action itself and its read-back. The role never sees a file of the caller's, never restarts a unit, a service or a container, and never edits a file that is not a stamp. A mechanical check holds it to that: `ansible/checks/test_restart_stamp_single_home.py` fails when this role uses a module that acts on anything but the stamps and the facts, and when any other role reads a stamp, writes one (or the `pending` mark), runs a command on one, or names a stamp file in a task or a script. A caller's `vars/` may name the files it hands to this role; that is data.

**A stamp** is `/var/lib/branchleft/<name>.applied`, root, mode 0600, holding a sha256 in hex and a newline, or `pending`. The role refuses any other path, so a mistake in a caller cannot make it write anywhere else. It refuses a fingerprint that is not 64 lowercase hex digits, so `pending` can never be written as the record of a finished action.

**The decision, for each class** (`decide`):

- `adopt` is true when the class is `adoptable`, the gate is open, there is no stamp and no file differs on the host. The host already has these files, as a hand-delivered host does, so the stamp is the whole change.
- `due` is true when the gate is open, the class is not adopted, and a file differs on the host or the stamp is not the fingerprint. `pending` is never the fingerprint, so a class a run left half-done is due again.
- `mark` is true when the class is due or a file differs on the host. A closed gate does not stop it: the file is still placed, and a placed file with no mark would make a host with no stamp look hand-delivered.

## Interface

The inputs, their types and defaults are in `meta/argument_specs.yml`; Ansible checks them when an entry point starts. Every entry point takes one list, `restart_stamp_classes`, with a different set of fields per entry point. None of the inputs is a secret, but a fingerprint is the hash of files that may hold one, so every task that handles it is `no_log` with `diff: false`.

| Entry point    | Fields of each class                                                                        |
| -------------- | ------------------------------------------------------------------------------------------- |
| `read`         | `name`, `file`                                                                              |
| `decide`       | `name`, `stamp`, `fingerprint`, `drift` (default false), `adoptable` (false), `gate` (true) |
| `mark_pending` | `name`, `file`, `mark`                                                                      |
| `adopt`        | `name`, `file`, `fingerprint`, `adopt`                                                      |
| `record`       | `name`, `file`, `fingerprint`, `read_back`                                                  |

**Facts it sets**, all prefixed `restart_stamp_` because `set_fact` is host-wide and a caller sets facts of its own:

- `restart_stamp_found` (from `read`): the class name to the stamp's content, trimmed, or `absent`.
- `restart_stamp_decisions` (from `decide`): the class name to `{adopt, due, mark}`, all booleans.

The caller passes a class's stamp to `decide` from `restart_stamp_found`, and the `mark`, `adopt` and `due` of a class to the later entry points from `restart_stamp_decisions`. Nothing is read from a fact by name inside the role, so what each call sees is on its own line in the caller.

**Flags that default off.** `drift` and `adoptable` default to false and `gate` to true (declared in `meta/argument_specs.yml`; the value that runs is the inline default of `tasks/decide.yml`, held equal to it by a check, see "Composition (ANS-12)"), so a caller that has no host-side comparison and does not adopt (the `monitoring_stack` shape) passes none of them and gets a missing stamp as plain `due`. A caller that does not need the pending mark never calls `mark_pending`; one that does not adopt never calls `adopt`.

### What each caller gets

| Behaviour                  | `edge_stack` (three classes)                                          | `monitoring_stack` (one class)                                    | Entry point and arguments                                               |
| -------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Stamps                     | `edge.caddy.applied`, `edge.compose.applied`, `edge.crowdsec.applied` | `monitoring.applied`                                              | `read` with one entry per class                                         |
| A missing stamp            | `absent`                                                              | `absent` (its own fact said `none`)                               | `read`                                                                  |
| A stamp that is unreadable | fails the run before anything is placed                               | fails the run (today it is read as missing and the unit restarts) | `read`: the one change for `monitoring_stack`, and it is stricter       |
| Drift                      | the host file against the repository file                             | none                                                              | `decide` with `drift`; left false by `monitoring_stack`                 |
| Adoption                   | yes, when the unit is enabled for the Compose class                   | no                                                                | `decide` with `adoptable: true`; `adopt` after it                       |
| The gate                   | the unit is enabled, for the Compose class; open for the other two    | the unit is enabled                                               | `decide` with `gate`                                                    |
| Pending mark               | yes, before the first file of a run is placed                         | no                                                                | `mark_pending` with the `mark` of `decide`; `monitoring_stack` omits it |
| What says "read back"      | the locked script printed the class's marker                          | the unit is `active` after the restart                            | the caller computes it and passes `record` `read_back`                  |
| Check mode                 | the adoption is reported, nothing else is written                     | nothing is written                                                | `adopt` runs in check mode; `mark_pending` and `record` do not write    |

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- A host with Python 3 and the directory `/var/lib/branchleft`, root, mode 0755. The role does not create it: more than one role shares it, and each creates it in the same mode before it calls this one.

## What it changes on a host

- The stamp files it is given, under `/var/lib/branchleft`: root:root, mode 0600, written by `copy` (a rename, so a reader never sees half a stamp). Nothing else, and nowhere else.
- `read` and `decide` change nothing. `mark_pending` and `record` write nothing in check mode.
- It calls no service, no unit and no container. Its modules are `stat`, `slurp`, `copy`, `set_fact`, `assert` and `include_tasks`.

## Composition (ANS-12)

A role that calls this one composes two roles, and ANS-12 carries a named limit on that: nothing in it forbids a role's tasks from including another role, and it says the question is decided with the first role pattern and recorded by amendment. `edge_stack` is the first use. The amendment is a change to the standards repository and is the owner's merge. This role is a capability role: a role that another role may include when it meets these conditions, and no other role may be included by one.

**Held by the gate** (`ansible/checks/role_composition.py` states this list once, and a test fails when this one and that one differ):

<!-- gate-conditions -->

1. It is included with `include_role`, never `import_role`.
2. It is named by a path built from the caller's own `role_path`, not by a bare name.
3. It declares its inputs in `meta/argument_specs.yml`, and the call gives every top-level required input of the entry point it names and no input that entry point does not declare.
4. Every option of the entry point it names, an option of a list element or of a dictionary included, is `required: true` or has a `default` key in `meta/argument_specs.yml`: the key counts whatever its value, null included, and a default found only in `defaults/main.yml`, in group vars or in the caller's vars does not.
5. It includes no role itself, and no role's `meta/main.yml` carries `dependencies`.
6. Its README names the roles that call it.
7. A role's `include_tasks` and `import_tasks` name a YAML file that exists under their own role's `tasks/` or `handlers/` (with links followed), as a literal path.

<!-- /gate-conditions -->

**Held by review only** (nothing in a task file shows any of them):

<!-- review-conditions -->

1. It is a cross-cutting capability with one reason to change, not a service: it configures no service and owns no host state.
2. It computes and records only.
3. Every variable its tasks read is an input it declares: the gate reads what a call gives, not what a task reads.
4. The value an omitted optional input takes when the role runs (in `defaults/main.yml`, or in the role's tasks for an option of a list element) equals the `default` its `argument_specs` entry declares: Ansible does not apply the declared default, and the gate reads the spec and the call.
5. Each list element a call passes gives the required options of its element: the gate reads the names of the vars a call sets, not what is inside the list.

<!-- /review-conditions -->

For this role the second review-only condition is also held by code: the single-home check below fails when this role uses a module that can act on anything but a stamp and the facts. The fourth is held by code for this role alone, by the defaults check below; for any other capability role it is review only.

The path of condition 2 (`{{ role_path | realpath | dirname }}/restart_stamp`, kept in `edge_stack_stamp_role`) is there because the host trigger starts in `ansible/`, the lint at the repository root and Molecule in a role directory, and a bare name is found by a search path they do not share. `realpath` is there because Molecule links the caller under its namespace, and the path must be that of the real directory. The gate resolves that name through the including role's own `vars/` and `defaults/` with one function that the single-home check also calls, so the two checks agree on what is included; a name it cannot resolve is reported by both.

**What a call must give, and what an option must declare.** "Every required input" is the wording, not "every input". A call passes every required input of the entry point it names, at the top level, and no input the entry point does not declare. An optional input (the clause's word for one that is not `required: true`) may be left out, and a caller with no host-side comparison, such as `monitoring_stack`, passes none of the optional fields of `decide` (`drift`, `adoptable` and `gate`) and keeps its behaviour. The gate checks the required ones are given; it cannot check that an optional one is passed on purpose, and does not try. What a call "gives" is every var that reaches it: the call's own `vars`, the `vars` of each block round it, and the `vars` of each `include_tasks` or `import_tasks` that names its file, however many levels up. An input given through any of them counts as given, and one the entry point does not declare is reported wherever it came from.

What an omitted optional input becomes is stated once, in `meta/argument_specs.yml`, and the gate fails when it is not. Every option of the entry point that is not `required: true` must have a `default` key there, at any depth: the options of a list element and of a dictionary are inputs too, so `restart_stamp_classes[].gate` is the option `gate` of each class. The key is what counts, not its value: `default: false` (as `drift` and `adoptable` have), `default: 0` and `default: null` all pass, and `default: null` is how an input with no sensible default says so. A default found only in `defaults/main.yml`, in group vars or in the caller's own vars does not count, because it is not declared in the one file a reader of the interface reads. The report names each option by its path.

**The declared default is not the one that runs.** Ansible does not apply the default of an `argument_specs` entry to a role. The value an omitted `drift`, `adoptable` or `gate` takes is the inline `| default(...)` of `tasks/decide.yml`, and the spec states the same value so that a reader learns what an omission becomes. These are two copies, and the composition gate reads the spec and the call, so it cannot see which one runs. For this role `ansible/checks/test_restart_stamp_defaults.py` holds them equal: it fails when the literal of any `<option> | default(...)` in `tasks/decide.yml` is not the declared default (compared with its type, so `0` is not `false`), when an option has no such copy, and when a literal it cannot read is there, so a change to one copy that leaves the other is stopped before it merges. It reads only the options of a list element and only the tasks file of their entry point; a default declared anywhere else makes it fail until it is extended. The container test also decides on the defaults (the last row of `r2` omits all three flags), but that row cannot tell a flipped `drift` default: an absent stamp is due whatever `drift` defaults to. With the `drift` default set to true the container test failed, but at its idempotence step, which is a side effect of the converge's classes and not a row about the rule. The equality is therefore held by code and not left to the container test. For any other capability role the equality is review only.

**What the gate reports.** The default report is one more among those the gate kept: an undeclared input, a bare name, `import_role`, a callee that includes a role, a caller the README of the callee does not name, `dependencies`, and an `include_tasks` or `import_tasks` that leaves the role. Its limits: it reads the entry point a call names, so another entry point of the same capability role, never called, is not checked, and a call whose target cannot be resolved is reported by that resolution and not read for defaults; and it does not look inside the list a call passes, so the required options of each element are review only.

**Gate.** The pull request that adds this role does not merge until the amendment is merged in the standards repository and cited. Two checks in `ansible/checks/test_role_composition_gate.py` hold it, kept apart so each can fail alone:

- The structure of every composition (the seven conditions above that the gate holds) is checked on the real tree. It is green now and stays green.
- The citation. While any role has a task that includes or imports another role, `ansible/checks/ans12_composition_citation.txt` must hold one line, `https://github.com/branchLeft/standards/pull/<number> merged <40-hex merge commit>`. The check reads that pull request from the standards repository and fails unless it is merged, into `main`, with exactly that merge commit, and unless `docs/stacks/ansible.md` at that commit has an ANS-12 section that no longer carries the named limit and states the capability-role rule. A merged pull request that is not the amendment is refused. Until the amendment is merged the file does not exist, and this one test is red on purpose with the message "citation.txt is missing", and so is the required check `Lint and test the Ansible roles`, which needs the job that runs it; every other test in `ansible/checks` is green. The lint job stops at its first failed step, so the steps after "Test the checks" do not run in CI while it is red and are run locally instead. A second test shows the missing citation is the only problem the tree has.

The lookup is the workflow's own `GITHUB_TOKEN` against the public API, so it is not rate-limited as an anonymous caller on a shared runner would be. In CI a lookup that fails (a transport error or a 5xx is tried again once; a refusal is not) is red and is never skipped. Outside CI it is skipped with the reason printed, so a maintainer with no network is told the citation was not checked and is not told it passed.

**If the amendment is refused.** Nothing is delivered on the assumption that it is accepted: the pull request cannot pass its required check without the citation. If the owner declines, the playbook lists `restart_stamp` and passes its facts between the pieces of `edge_stack`, or the stamp steps become a filter plugin. What is discarded then is the include of `restart_stamp` in `edge_stack`, the composition gate and its citation file; the single-home check and the one home of the stamp steps stand. Ruling out the composition would leave two owner rulings in tension (a duplicate blocks a merge, and composition is in a playbook), and the resolution is the owner's.

**Unblocking, step by step.** The orchestrator owns it, and the trigger is the merge of the amendment's pull request in the standards repository.

1. Read the merged clause against the two lists above. They were written against ANS-12 as it stands in standards pull request 162 at a755162; if the clause has changed since, or its wording differs from them, change the list in `role_composition.py` and in this README to match before anything else. The clause is the source, not the decision that preceded it. The citation check compares only that the named limit is gone and the rule is named.
2. Commit the one line of `ans12_composition_citation.txt` to the pull request's branch. That commit is the only change.
3. The commit changes the head, so the last review no longer covers it. One narrow re-check of that one-file diff follows, and the approving review is of the new head.

**Merge order with the second caller.** The repository's `main` ruleset requires the check `Lint and test the Ansible roles` to be up to date (strict). Whichever of this pull request and the pull request that adds `monitoring_stack` lands second must be rebased onto the first, and the single-home check then runs on the result. If this one lands first, the other fails the check while it keeps its own inline copy of the stamp steps, and must call `restart_stamp` instead. If the other lands first, this one fails the check on its rebase and must also move `monitoring_stack` onto `restart_stamp` in the same pull request. Nothing stops the first of the two; the check stops the second.

### The single-home check

`ansible/checks/test_restart_stamp_single_home.py` is the only code that holds the stamps to one home. The role is the only code that reads a stamp (`/var/lib/branchleft/*.applied`), decides from one, or writes one; a second copy of those steps in another role is the defect the role exists to remove, because the copies drift and a fix to one leaves the other restarting on the wrong day. The check reads the tasks and handlers of every role. Its screen is an allow-list of the tasks that do not act, so a module nobody thought of is screened too. It fails when:

- a role other than this one has a task that is none of the allowed three (below) and any key of that task, not only the module's arguments, names a stamp file or a stamp variable (a name ending in `_stamp_file`, `_stamp_files` or `_stamps`); the destination can be the loop item, with the stamps named only in the loop or in the task's `vars`. The module is read by its module word in the `action:` and `local_action:` forms too;
- such a task names the `pending` mark in its arguments, whatever the module and the destination;
- any task that names a stamp also calls `lookup(`, `query(` or `q(`, since a lookup reads a file on the controller whatever module the task is;
- a `loop`, a `with_*` loop, `until`, `when`, `changed_when`, `failed_when` or `register` of any task names a stamp file or a stamp variable;
- a script or other non-YAML file of a role names a stamp file;
- this role uses any module that is not one of `assert`, `copy`, `include_tasks`, `set_fact`, `slurp` and `stat`. Every module key of every task is read, not only those on a list.

The three tasks of another role that may carry a stamp in their arguments are `include_role` of this role (found by the same resolution as the composition gate), a fact, an assertion or a message (`set_fact`, `assert`, `debug`), and `include_tasks` of the role's own files, meaning a literal YAML file that exists under `tasks/` or `handlers/`, the only places the check reads, with links followed: an include of a file anywhere else in the role (`vars/`, `files/`), of a file reached through a linked directory that leads out of those two, or of a file the role does not have at all (Ansible would then look in the playbook's directory and the working directory, which the check does not read) is not an own file, is reported by the composition gate, and may carry no stamp. A role may name its stamp files in `vars/` or `defaults/`, which are data, and hand them to this role by `include_role`. The directory of the stamps is not a stamp: a role may create it. Named limit: a stamp variable with a name outside those three endings is not seen; the check reads names, not what a variable holds.

The tests that follow the scan prove it can fail: each way a role could keep a copy is built in a throwaway role and must be reported, and so must the real `edge_stack` with a stamp write put back.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes, one command runs lint, yamllint, the interface checks and the container test:

```text
python3 ansible/harness/run_harness.py ansible/roles/restart_stamp
```

The container is a plain Python image: the role reads and writes files and does nothing else. `verify.yml` has one block per behaviour, tagged `r0` to `r8`, each starting from the converged host and calling the entry points through `tasks/call.yml`:

| Tag  | What it proves                                                                                                                                                                            |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `r0` | The converge wrote the three stamps (an adopted class, a class that was acted on, a class of the other shape) as a caller's first run does.                                               |
| `r1` | A missing stamp is `absent`, the others are read and trimmed, and a stamp that is a dangling link or a directory fails the run.                                                           |
| `r2` | A table of classes, each with a stamp and the three flags, decided as the rule above says, and the defaults of the three flags.                                                           |
| `r3` | Only a marked class gets `pending`; nothing is written in check mode.                                                                                                                     |
| `r4` | Only an adopted class gets its fingerprint.                                                                                                                                               |
| `r5` | Only a class that was read back is recorded; nothing is written in check mode.                                                                                                            |
| `r6` | Lists the role refuses (a path outside the stamp directory, a repeated name, `pending` as a fingerprint and so on), with nothing written, not even for the good class beside the bad one. |
| `r7` | A plan (`ansible-playbook --check`) reports the adoption as a change and the other two as nothing.                                                                                        |
| `r8` | No fingerprint, made for the run, is in the Ansible log of the scenario, which runs at the highest verbosity with a diff on every task.                                                   |

A block can be run alone with `ANSIBLE_RUN_TAGS=r2 molecule verify`. The rows of the stamp logic are proved here and only here: the `edge_stack` scenario keeps the rows that need its host and re-runs its own, with the real role.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by running `ansible-playbook` by hand. This role reaches a host through the role that calls it; it has no playbook of its own.

## How to change it safely

1. Change the tasks, `meta/argument_specs.yml` and this README together. A new field of a class is added to the entry points that need it, with a `default` in `meta/argument_specs.yml` (the gate fails an optional option without one) and the same literal inline in `tasks/decide.yml` (`ansible/checks/test_restart_stamp_defaults.py` fails when the two differ), so that every caller's behaviour is as it was.
2. Keep every entry point read-only or limited to a stamp file. A task that acts on anything else belongs to the caller, and the single-home check fails the pull request that adds one here.
3. Every change to a rule in `decide` needs a row in `r2` that goes red without it. Prove it by sabotage: break the rule, see the row go red, restore, see it green.
4. Run the command under "How to test it", and the checks in `ansible/checks`, before opening a pull request.
