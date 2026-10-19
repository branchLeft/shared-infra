# Pattern: a typed Python module and its tests

This role is a recipe, not a service. A maintainer copies its module, its
tests and its Molecule steps into a service role when that role needs a custom
module. It manages one small placeholder file and should never be applied to a
host.

The module in this pattern is deliberately trivial so that its shape is easy to
copy. See "When to write a module at all" before copying it.

## What it does and does not do

The role has one task that calls the module `typed_module_record`. The module
writes a record file (a name, a count and, when a token is given, a keyed
signature of the name) or removes it. It replaces the file atomically, reports
a change only when the content or the mode differs, and in check mode reports
what it would do and changes nothing.

It does not manage the owner or group of the file, create its directory,
follow symbolic links or take a lock. It is not a service: it starts nothing
and opens no port.

## Interface

`meta/argument_specs.yml` declares every variable the role reads, and
`defaults/main.yml` holds the same defaults (ANS-7). One variable is a secret:
`typed_module_token`. It has no default, it is supplied at run time, the
module marks it `no_log`, and the written file never contains it (it only keys
the signature). The module has its own interface in its `DOCUMENTATION`
block, which `ansible-doc` renders:

```text
.venv/bin/ansible-doc -t module -M ansible/patterns/typed_module/library typed_module_record
```

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version (ANS-4).
- No collection beyond `ansible.builtin` for the role. The harness installs the
  collections pinned in `ansible/requirements.yml` for every run.
- A Debian 13 target with `python3` (3.13 on the pinned test image). The
  pattern's `requires-python` is `>=3.13`, the oldest interpreter any target
  host provides (PY-3); `verify.yml` asserts the instance runs 3.13 or newer.
- To run the test: Docker on the machine, and network access the first time
  for the pinned collections and the image.

## What it changes on a host

- The record file at `typed_module_path` (default `/etc/typed_module.record`),
  with the mode `typed_module_mode`, owned by the user the play runs as.
- A temporary file beside it while it is replaced, removed whether the write
  succeeds or not.

It starts no service, opens no port and creates no user or directory.

## How to run the test

From the repository root. Build the pinned tools into a virtual environment as
`ansible/README.md` describes, then:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/typed_module
```

The harness runs the lint steps and Molecule: the scenario is a container from
the Debian 13 image, converged once, converged again to prove idempotence, then
verified (`molecule/default/verify.yml` is where the module is exercised), and
run under check mode against a fresh and a configured container. CI runs the
harness over every role and every pattern (the workflow step "Run the harness
over every role and pattern"), so this scenario runs in CI.

The module's own checks are not part of the harness. CI does not run them for
a pattern (see the named limits), so run them yourself before every push, from
the repository root:

```text
.venv/bin/mypy --config-file ansible/patterns/typed_module/pyproject.toml ansible/patterns/typed_module/library ansible/patterns/typed_module/tests
.venv/bin/ruff check ansible/patterns/typed_module
.venv/bin/ruff format --check ansible/patterns/typed_module
PYTHONPATH=ansible/patterns/typed_module/library .venv/bin/python -m unittest discover -b -s ansible/patterns/typed_module/tests/unit -p "test_*.py"
```

`PYTHONPATH` names the directory the module is imported from: Ansible loads it
by path, so it has no package to install.

## How it is delivered

This role is never delivered. A service role copied from it is applied to a
production host only through the gated workflow of ANS-17: a plan job in check
mode, the approval of the protected environment, `ansible-pull` of that exact
commit of `main`, and a second run that must report zero changes. Nothing in
this directory runs `ansible-playbook` against a host, and an author's local
run is the Molecule test on a container.

## How to change it safely

- Change the parameters in one place: the `Params` dataclass. The
  `argument_spec` is generated from it. Then change the `DOCUMENTATION` block to
  match; a unit test fails until the two agree.
- Keep the split between the pure decision (`plan`, `render`, `validate`) and
  the one function that changes the host (`apply`). Check mode is safe because
  `run` calls `apply` only when `check_mode` is false; do not add a second
  place that writes.
- Run the module's four commands above and the whole harness, not only the
  step you touched. Keep every sabotage in "What the test proves" red: edit
  the control, see the named assertion fail, undo the edit.
- Never loosen `verify.yml` or a unit test to make a change pass.

## When to write a module at all

Almost never. The order of ANS-9 is: a built-in module first, then
`ansible.builtin.command` with an argument list and a stated change, and a
Python module only for a command that is needed twice or whose output must be
parsed or branched on. A module is code that runs on the host with the
privileges of the play, in a language the standard makes you type, test and
document (ANS-2). Write one only after you have looked for a module that does
the job, in `ansible.builtin` and in the pinned collections, and found none.

This pattern's module writes a three-line file, and `ansible.builtin.copy` with
`content:` does the same job. A real role would use `copy` and never ship this
module. Copy the shape, not the purpose.

## The recipe: the shell shape it replaces

A script that keeps a small file in step with a name and a count:

```text
printf 'name=EXAMPLE_NAME\ncount=3\n' > /etc/EXAMPLE_SERVICE.record
chmod 0600 /etc/EXAMPLE_SERVICE.record
echo "signature=$(printf EXAMPLE_NAME | openssl dgst -sha256 -hmac "$EXAMPLE_TOKEN" -r | cut -d' ' -f1)" >> /etc/EXAMPLE_SERVICE.record
```

Every run rewrites the file and reports nothing. It cannot say whether it
would change the host, so there is no dry run. The file is open and world
readable until the `chmod`, a failure between the lines leaves a half-written
file, and the token sits in the process list and in the shell history.

## The recipe: the Ansible shape

The role's task calls the module, with the secret kept out of the log:

```yaml
- name: Manage the record file
  typed_module_record:
    path: '{{ typed_module_path }}'
    name: '{{ typed_module_name }}'
    count: '{{ typed_module_count }}'
    state: '{{ typed_module_state }}'
    mode: '{{ typed_module_mode }}'
    token: '{{ typed_module_token | default(omit) }}'
  no_log: true
  diff: false
```

The module (`library/typed_module_record.py`) has these parts, in this order:

1. `DOCUMENTATION`, `EXAMPLES` and `RETURN` blocks (ANS-2).
2. `Params`, a frozen dataclass with one annotated field per parameter. A field
   with no default is required, `X | None = None` is optional, a
   `Literal["a", "b"]` is a `choices` list, and `metadata={"no_log": True}`
   marks a secret. `repr=False` keeps the secret out of any traceback.
3. `build_argument_spec(Params)`, which generates the `argument_spec` from the
   types and refuses a type it cannot state.
4. Pure functions: `validate` (a named refusal for a value that has the right
   type and is not acceptable), `render` (the content) and `plan` (what an
   apply would do, from what `observe` read).
5. `apply`, the only function that changes the host, and `run`, which calls it
   only when `check_mode` is false.
6. `main`, the only function that touches `AnsibleModule`:

```python
module = AnsibleModule(argument_spec=ARGUMENT_SPEC, supports_check_mode=True)
```

## Why each choice is made

- `supports_check_mode=True` and `apply` behind `check_mode`: the dry run an
  approver sees (ANS-10) is the module's own answer to "what would change".
- The `argument_spec` is generated from the dataclass, not written twice: the
  types are the single source, and the documentation is the one thing a human
  keeps in step, which a unit test compares (type, required, default, choices)
  for every option.
- `no_log: True` on the token in the spec, as well as `no_log: true` on the
  task (ANS-16): the first masks the value wherever Ansible prints the module's
  arguments or result, the second hides the whole task result. The record holds
  a keyed signature, never the token.
- `validate` raises one named exception class per refusal, so the message is
  stated once and a test names the case. `main` turns them, and the `OSError`s
  of the host, into `fail_json(msg=...)`: the play fails with a sentence, not a
  traceback. The token is never in a message.
- The file is written to a temporary file in the same directory with its final
  mode already set, flushed to disk, and renamed into place: a reader never
  sees a half-written file or a wider mode, and a failed write removes its
  temporary file.
- `observe` uses `lstat` and refuses anything that is not a regular file: the
  module never follows a symbolic link to write somewhere else.
- A missing directory fails in both modes. Check mode must report what the
  apply would do, including that it would fail.
- `requires-python = ">=3.13"` and `python_version = "3.13"` in `pyproject.toml`:
  the oldest interpreter on any target is Debian 13's (PY-3, ANS-2). The mypy
  override names `ansible.*` only; any other untyped import is still an error.

## What the test proves

Three layers. Each control below fails by default, with a named assertion,
when it is removed.

**Types and lint (the module's four commands).**

- `mypy --strict` over the module and its tests. Removing an annotation from a
  function is a `no-untyped-def` error.
- `ruff check` and `ruff format --check` with the repository's policy.

**Unit tests (`tests/unit`).**

- The generated `argument_spec` equals the one expected for the dataclass, and
  every option of it agrees with the `DOCUMENTATION` block on type, required,
  default and choices (`test_documentation_options_match_the_generated_argument_spec`
  names the option). Every secret-named option is `no_log`.
- The generator refuses a type, a choice list, a union or a default it cannot
  state.
- `validate` refuses each bad value with its named message; no message carries
  the token; the token is not in `repr(Params)`.
- `plan` decides write, chmod, remove or nothing from what was observed.
- Against a real directory: a check-mode run changes nothing, an apply changes
  once, a second apply changes nothing, a drifted content or mode is reported
  by check mode and repaired by an apply, a removal behaves the same way, a
  missing directory, a directory or a symbolic link in the way is refused, and
  a failed write leaves no temporary file.
- `main` builds `AnsibleModule` with `supports_check_mode=True` and the
  generated spec, passes `check_mode` on, and fails with the named message.

**Molecule (`molecule/default`).**

- The role's apply writes the record with the scenario's name, count and mode
  (which differ from the defaults), a 64-hex signature and no token.
- The harness's idempotence step: the role's second converge reports zero
  changes. The harness's check steps: the role completes under `--check --diff`
  on a fresh and on a configured container, and the configured one shows no
  change.
- `verify.yml` calls the module directly on a probe file: a check-mode run
  reports a write and creates nothing; an apply changes once; a second apply
  and a check-mode run after it change nothing; drifted content and a drifted
  mode are reported by check mode and left alone, then repaired by an apply
  that changes once; a removal is reported by check mode, kept, then done once.
- A run with the throwaway token and no task-level `no_log` leaves the token
  out of the registered result (the text the default callback prints), the
  diff and the file, and shows Ansible's mask in its place. That fails if the
  module's own `no_log` is removed.
- Each bad argument in the list fails with its named message, no `exception`
  and no `Traceback`: a count below and above the range, a name that is not one word,
  a mode that is not octal, an empty token, a state outside its choices, a
  missing required argument, and a missing directory in both modes.
- The role itself refuses a state outside its choices and names the variable.
- The instance runs Python 3.13 or newer, the pattern's `requires-python`.

Each is proven by sabotage; the commands and results are in the pull request.

## Named limits

- **CI does not run the module's mypy, ruff or unit tests for a pattern.** The
  workflow's type-check, lint and unit-test steps cover `ansible/harness`
  only, and `ansible/pyproject.toml` has no `ansible.*` override. This pattern
  carries its own `pyproject.toml` and the four commands above are run by hand.
  The Molecule scenario does run in CI. ANS-2 asks for mypy and ruff over
  `ansible/` in CI; widening the workflow is separate work, not decided here.
- **Types stop at the Ansible boundary.** `ansible` is untyped, so mypy sees
  `AnsibleModule` as `Any`: calls to `module.params`, `exit_json` and
  `fail_json` are not type-checked. The unit tests use a stand-in for
  `AnsibleModule`; only the Molecule scenario runs the real one.
- **The documentation is compared on four keys.** The unit test compares type,
  required, default and choices for each option. It does not compare
  descriptions, `elements` or aliases, does not check the `RETURN` block
  against what the module returns, and does not run the Ansible project's
  `ansible-test sanity --test validate-modules`, which needs a collection
  layout. Reviewed, not tested.
- **`no_log` is proven on the registered result, not on every log.** The scan
  reads what the default callback prints for a task. It does not read the
  controller's log file, a higher verbosity, or the target's journal, where
  `AnsibleModule` logs its arguments with `no_log` values masked. A failure
  inside the role's own task is hidden by the task's `no_log: true`, so the
  named messages are proven by calling the module directly.
- **Ownership is not managed.** The file belongs to the user the play runs as.
  The instance runs as root, so the test cannot tell an `owner:` parameter from
  the default; a module that manages ownership needs a non-root user in its
  scenario.
- **The directory must exist.** A role that creates the directory with
  `ansible.builtin.file` and then calls this module meets the check-mode trap of
  ANS-10: on a fresh host the `file` task did not run, so the module's check
  run fails. Guard the module task with an explicit, commented
  `when: not ansible_check_mode` skip, or give the module a parent-directory
  parameter and test it.
- **Concurrent writers and power loss.** There is no lock, so two plays writing
  the same file race; the temporary file is flushed before the rename, but
  the directory is not flushed, so a crash can lose the rename.
- **The unit tests run on the venv's Python.** The venv needs Python 3.12 or
  later (ansible-core's floor), the module targets 3.13, and nothing runs the
  unit tests on 3.13. The module itself runs on 3.13 in Molecule.
- **A single-file module.** Shared code goes in the role's `module_utils/`
  (ANS-2); this pattern has none, so how mypy and Ansible's packaging find it
  is not shown here. The first role that needs one records it.
- **A symbolic link makes the module visible to the verify play.**
  `molecule/default/library` points at `../../library`: Ansible, and the
  ansible-lint syntax check, look for a `library/` next to a playbook, and
  `verify.yml` calls the module by its bare name. The converge play finds the
  module through the role. Without the link ansible-lint reports an unknown
  module.
- **ANS-8 and the bare name.** At the production profile, ansible-lint raised
  no finding for the bare name `typed_module_record`, called from the role and
  from the verify play. The module carries the role's name as its prefix, as
  ANS-8 asks.
- **The image digest and the collections age.** Nothing raises a bump of the
  digest in `molecule.yml` (Dependabot does not read it) or of a collection pin.
- **Placeholders are not checked.** `AUTHOR_NAME`, `LICENSE_ID` and the
  `EXAMPLE_` and `SCENARIO_` names pass lint and the harness unedited; the
  reviewer stops a role reaching `main` with them.

## How a service role copies it

1. Look for a module first (see the top of this page). Copy only after you have
   found none.
2. Copy `library/typed_module_record.py` to the service role's `library/`,
   renamed with the role's name as prefix (ANS-8), for example
   `SERVICE_NAME_THING.py`, and rename the module in the three documentation
   blocks.
3. Replace the fields of `Params`, `validate`, `render`, `observe`, `plan` and
   `apply` with the service's. Keep the split: `plan` is pure, `apply` is the
   only writer, `run` calls `apply` only outside check mode. Keep
   `build_argument_spec(Params)`; do not write the spec by hand.
4. Mark every secret field with `metadata={"no_log": True}` and `repr=False`,
   and give it no default in the role's `defaults/main.yml` (ANS-16).
5. Update the `DOCUMENTATION`, `EXAMPLES` and `RETURN` blocks until the
   documentation unit test passes.
6. Copy `pyproject.toml` (or, once CI covers patterns, add its two settings to
   `ansible/pyproject.toml`: the `ansible.*` override and `requires-python`), and
   copy `tests/unit/test_typed_module_record.py`, renamed. Adapt the sample values
   and the cases; keep every class of test listed above.
7. Call the module from the role's task with the role-prefixed variables.
   A task that passes a secret sets `no_log: true` and `diff: false`.
8. Copy `verify.yml`'s sequence for the module (check mode on a fresh file, an
   apply, a second apply, drift, removal, the secret scan, the bad arguments)
   and the `molecule/default/library` link.
9. Run the four commands and the harness. Then break each control once and see
   it fail by name: remove an annotation (mypy), change a field's type (the
   documentation test), let `run` apply in check mode (unit and Molecule),
   make the apply always change (idempotence) and drop `no_log` (the secret
   scan).

The recipe text for the standards page is not written here; the recipes are
collected into one standards pull request later.

## Clauses this recipe exercises

ANS-1 (host state in Ansible), ANS-2 (typed Python, `DOCUMENTATION`, `EXAMPLES`
and `RETURN`, `supports_check_mode=True`, unit tests, the `ansible.*`-only
override, the module in the role's `library/`), ANS-3 (no `shell`, `raw` or
`script` task), ANS-7 (interface spec), ANS-8 (the role-prefixed bare name),
ANS-9 (a module before a command; when to write one), ANS-10 (check mode that
changes nothing), ANS-11 (a second run changes nothing), ANS-14 (this README),
ANS-15 (container-only Molecule test; the image is pinned by digest with
`pre_build_image: true`), ANS-16 (`no_log` and `diff: false`, a throwaway value,
no default for a secret). Also TYP-2 and TYP-5, PY-2 and PY-3 and TEST-1, as
ANS-2 cites them.

The image reference is `geerlingguy/docker-debian13-ansible:latest@sha256:...`.
The digest is the pin and the tag is informational: upstream rebuilds weekly,
so `latest` moves and the digest does not.
