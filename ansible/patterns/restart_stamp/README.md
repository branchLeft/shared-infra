# Pattern: the stamp steps of a restart-by-fingerprint role

This directory is the one home of the module `restart_stamp`, which every role that restarts
a unit only when what the unit runs from has changed uses to read, decide on, adopt and record
its stamps. The directory is also a small role that the harness runs like `roles/`, to prove the
module on a container. It is a pattern: it is never applied to a host and no playbook names it.

## What it does and does not do

A stamp is a file holding the sha256 fingerprint of the inputs a unit was last restarted for,
written only after the restart was read back, or the word `pending` between the first placed file
of a run and that read-back. The module has four steps, selected by `state`:

| `state`  | Does                                                                                                                    | Check mode                         |
| -------- | ----------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `read`   | Returns what each stamp holds, or the `absent` word for a stamp that is not there.                                      | runs                               |
| `decide` | Says, for each class, whether it is adopted, due and to be marked pending. Reads and writes nothing.                    | runs                               |
| `adopt`  | Writes the stamp of each class whose `adopt` is true: the host already has the files, so the stamp is the whole change. | reports its change, writes nothing |
| `record` | Writes the stamp of each class whose `read_back` is true. The last thing a run does for a class.                        | does nothing: no action ran        |

It does not restart a unit, hash a file, place a file, decide what a gate is, or write the
`pending` mark: a role works out its fingerprints, its drift and its gate, and its own program
places the files and marks. It writes no file that is not a stamp.

The rules it holds for every role, so a fix is made here once:

- A fingerprint it writes is a sha256 (64 lower-case hex digits). `pending`, `absent` and any other
  word are refused, so a stamp can never be recorded as a fingerprint it is not.
- Only a stamp that is not there is `absent`. A stamp that is there and cannot be read (a directory,
  a link to nothing, an I/O error) stops the run, unless the role says `unreadable: absent`.
- `pending` is never a fingerprint, so a class a run left half-done is due again.
- A class with no stamp and no drift is adopted only when it is adoptable and its gate is open. A
  closed gate is neither adopted nor due, but a file that drifts is still marked, because it is
  still placed.
- A stamp is written atomically with its owner and mode already set, and a stamp that is already
  as it would be written is left alone and reports no change.
- It never returns a fingerprint from a write. `read` returns stamps, so a task that calls it is
  `no_log: true` (ANS-16).

## Interface

The module's own interface is its `DOCUMENTATION` block, which `ansible-doc` renders:

```text
.venv/bin/ansible-doc -t module -M ansible/patterns/restart_stamp/library restart_stamp
```

`meta/argument_specs.yml` declares the two variables of the pattern's own role,
`restart_stamp_dir` and `restart_stamp_input`. They exist only for the test.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`.
- Python 3.13 on the target, the floor of every host (PY-3).
- Root on the target, for the default owner and group of a written stamp.

## What it changes on a host

The pattern's role makes `/var/lib/restart_stamp_example` (0755, root) and writes
`example.applied` in it (0600, root). Nothing else.

## How to run the test

From the repository root, with the virtual environment the harness README describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/restart_stamp
```

The unit tests run from this directory with `library/` on the path, and run again in each role that
links the module:

```text
cd ansible/patterns/restart_stamp
PYTHONPATH=library ../../../.venv/bin/python -m unittest discover -b -s tests/unit
../../../.venv/bin/mypy --strict library tests/unit
```

## How it is delivered

It is not delivered to a host as a pattern. A role carries the module by a symbolic link in its own
`library/`, and a host receives it with the role, from the signed checkout.

## How to change it safely

A change here changes every role that links the module, and `ansible/checks/ci_select.py` reads the
links, so the shards of each of them run. Run the harness of each role that links it before the
change is proposed:

| Role               | Link                                                                |
| ------------------ | ------------------------------------------------------------------- |
| `monitoring_stack` | `roles/monitoring_stack/library/restart_stamp.py` and its unit test |
| `edge_stack`       | `roles/edge_stack/library/restart_stamp.py` and its unit test       |

Each role's Molecule cases prove its stamp behaviour: the pending mark before a placement, a stamp
written only after a read-back, adoption, an unreadable stamp and a closed gate. A control here is
proved by sabotage: break it in the module, see the named test or case go red, restore it with
`git restore`, see it green. The unit test names the four breaks the pattern's own tests carry.

## How a role uses it

1. Link the module and its test into the role. From the role's directory:

   ```text
   ln -s ../../../patterns/restart_stamp/library/restart_stamp.py library/restart_stamp.py
   ln -s ../../../../patterns/restart_stamp/tests/unit/test_restart_stamp.py tests/unit/test_restart_stamp.py
   ```

   The role needs a `library/`, a `tests/unit/` and a `pyproject.toml` that names `library` as its
   mypy path, as `edge_stack` has.

2. Call the module with the role's own classes, and keep the stamp paths and the two words as
   constants in the role's `vars/main.yml`. The role does not load this pattern (ANS-12): the
   module is a file the role holds.
3. Keep `no_log: true` and `diff: false` on every task that calls it.

## Named limits

- The module runs as the Ansible user of the host, which is root in every delivery, because the
  default owner of a stamp is root. A non-root run needs `owner` and `group` it can chown to.
- A link at a stamp's path is followed on a write, as `ansible.builtin.copy` follows it. A link to a
  file in another directory is written through.
- A stamp that is there is read as UTF-8 and trimmed; a byte that is not UTF-8 reads as a
  replacement character, so it is never a fingerprint.
- `decide` trusts the `absent` word: a role must pass the word it passed to `read`.
