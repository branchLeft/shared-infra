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

The caller keeps everything that depends on its host: the fingerprint of each class (which files, hashed how), whether a file differs on the host (drift), whether the class may be touched now (the gate), the action itself and its read-back. The role never sees a file of the caller's, never restarts a unit, a service or a container, and never edits a file that is not a stamp. A mechanical check holds it to that: `ansible/checks/test_restart_stamp_single_home.py` fails when this role uses a module that acts on anything but the stamps and the facts, and when any other role writes, reads or names a stamp itself.

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

**Flags that default off.** `drift` and `adoptable` default to false and `gate` to true, so a caller that has no host-side comparison and does not adopt (the `monitoring_stack` shape) passes none of them and gets a missing stamp as plain `due`. A caller that does not need the pending mark never calls `mark_pending`; one that does not adopt never calls `adopt`.

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

A role that calls this one composes two roles, and ANS-12 carries a named limit on that: nothing in it forbids a role's tasks from including another role, and it says the question is decided with the first role pattern and recorded by amendment. `edge_stack` is the first use. The role is built to meet the conditions the amendment records, and the single-home check holds it to them:

1. It is a cross-cutting capability with one reason to change (the stamp steps), not a service.
2. It computes and records only. It never restarts a unit, a service or a container, and never edits a file another role owns.
3. Its inputs are typed in `meta/argument_specs.yml`, and it reads no variable of its caller except through them.
4. It is named by a path built from `role_path` (`{{ role_path }}/../restart_stamp`), not by a bare name. The host trigger starts in `ansible/`, the lint at the repository root and Molecule in a role directory, and a bare name is found by a search path they do not share.
5. Only this role is included by another role. A second one needs its own review against the clause.

**Gate.** The pull request that adds this role does not merge until that amendment is merged in the standards repository and cited in the pull request. The text proposed there is in the pull request description.

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
| `r8` | No fingerprint is in the Ansible log of the scenario, which runs at the highest verbosity with a diff on every task.                                                                      |

A block can be run alone with `ANSIBLE_RUN_TAGS=r2 molecule verify`. The rows of the stamp logic are proved here and only here: the `edge_stack` scenario keeps the rows that need its host and re-runs its own, with the real role.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by running `ansible-playbook` by hand. This role reaches a host through the role that calls it; it has no playbook of its own.

## How to change it safely

1. Change the tasks, `meta/argument_specs.yml` and this README together. A new field of a class is added to the entry points that need it, with a default that leaves every caller's behaviour as it was.
2. Keep every entry point read-only or limited to a stamp file. A task that acts on anything else belongs to the caller, and the single-home check fails the pull request that adds one here.
3. Every change to a rule in `decide` needs a row in `r2` that goes red without it. Prove it by sabotage: break the rule, see the row go red, restore, see it green.
4. Run the command under "How to test it", and the checks in `ansible/checks`, before opening a pull request.
