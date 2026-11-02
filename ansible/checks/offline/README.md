# Offline render and validate

`ansible/checks/offline_render.py` renders every `template` task of every host's roles on
the machine that runs it, then validates the result. It exists because the gated plan runs in
check mode, and check mode skips `validate:`. A sudoers file visudo refuses, or a compose file
Docker refuses, shows as a harmless change in the plan and fails only at the live apply. This
tool runs the same templates and the same validators in seconds, before a merge, with no host
and no secret.

It is advisory. `.github/workflows/ansible-offline.yml` runs it, and it is not a required
check. It is promoted into the gate in `ansible.yml` after ten consecutive green runs on `main`
with nothing not-covered.

## Run it

```sh
python3 ansible/checks/offline_render.py [--root DIR] [--host H ...] [--summary-file PATH]
```

Use the Python of the hash-locked tool environment (`ansible/README.md`): `ansible-playbook` is
found beside it. Exit 0 means no red, 1 a red, 2 a tool or usage error (a missing fixture, no
`ansible-playbook`). One line is printed per output (host, role, template), with its class
and, for a red, the reason class and a name. It never prints a rendered line or a variable
value. `--show-validator-output` prints a table validator's own text to stderr, for local
debugging only; CI never passes it.

## What it does

For each playbook in `ansible/playbooks/`, and for one more host called `unwired` that holds
every role no playbook applies (those roles run by hand, or on no host yet), one
`ansible-playbook` run on localhost replays the roles in the playbook's order:

1. The variables of the run are layered, lowest first: typed dummies, the overrides in
   `dummies.yml`, each role's defaults and vars, the playbook's vars, its vars files (the shared
   include, the trust file, the owner's values), and the parameters on a role entry.
2. A dummy is made for every argument_specs option that is required and has no default, and
   for every `host_inputs` key of the host, with the type the spec declares. No host-inputs
   file is read.
3. Facts come from `facts/<host>.yml`, set as `ansible_facts` before the first role.
4. The role's `ansible.builtin.validate_argument_spec` runs against these variables.
5. Each template task is replayed with its own `src`, `vars`, loop and `validate:`. Its `dest`
   is rewritten into a throwaway directory (mode 0700, deleted after the run), its owner and
   mode are dropped, and its `when:` is dropped so that both branches render. The task is
   `no_log` and never fatal.
6. The driver runs a table validator from `validators.yml` on each output of a template with
   one, and reads a classified summary Ansible wrote.

Ansible's own output is discarded, because a failed task echoes the lines it rendered. Two
layers keep rendered lines out of the logs, and each is enough alone: the output goes
nowhere, and every task is `no_log`. The child's environment is an allowlist (`PATH`, `LANG`,
`LC_ALL`) with a fresh `HOME` and an empty `ANSIBLE_CONFIG`, so a template that reads
`lookup('env', ...)` renders empty.

## Outcome classes

| Class       | Meaning                                                                     |
| ----------- | --------------------------------------------------------------------------- |
| ok          | Rendered, and every validator that applies passed.                          |
| red         | A real defect, or a fixture gap. Fails the run.                             |
| unresolved  | Not renderable offline. Allowed only for a pair listed in `unresolved.yml`. |
| not-covered | A validator's program is not installed, so the output was not validated.    |

A red has one reason class: a syntax error; a variable defined nowhere (in no layer, and not
assigned by any task, `set_fact`, `register`, loop or `vars:` of the role); a fact the roles
read that the fixture lacks; a `validate:` or table validator that exited non-zero; inputs
that break the role's argument spec; an unresolved pair that is not in the ratchet; or a
ratchet entry that now renders.

A variable a task assigns while the role runs cannot be rendered offline, so a template that
uses one is unresolved, unless `dummies.yml` gives that variable a value of its shape. The
ratchet in `unresolved.yml` lists the pairs still unresolved. It only shrinks: a new pair is
red, and a listed pair that renders is red until it is removed from the list.

## Files

| File               | Holds                                                                                                                                                                                                                                                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `facts/<host>.yml` | The facts the host's roles read. A test finds them in the roles and fails when one is missing, so a new `ansible_facts` read forces an edit here. The release is the codename of the OS image `hetzner/estate/Pulumi.production.yaml` builds, tied by a test. They are derived from that image, not captured from a host. |
| `dummies.yml`      | Overrides for a variable whose consumer needs a shaped value (a registered result, a key, an address). Each declares its type; a test checks it against the role's argument_specs and that a role uses the name.                                                                                                          |
| `validators.yml`   | A validator by template name, for templates whose task has no `validate:`. Each names the binary it needs.                                                                                                                                                                                                                |
| `unresolved.yml`   | The ratchet.                                                                                                                                                                                                                                                                                                              |

To add a template with a validator of its own, add the task and nothing else: its `validate:`
is reused as written. To add one that Docker or ssh-keygen should check, add its name to
`validators.yml`.

## Proof

`sabotage_offline_render.py` copies the tree, plants defects, and requires the run to exit 1
and name each by host, role and output; the clean copy must exit 0. It plants a sudoers line
that visudo refuses, an unknown compose key, a malformed authorized key, an unclosed `{% if %}`,
a variable removed from a role, a fact removed from a fixture, and an input that breaks an
argument spec. It also plants a sentinel in a rendered line, and requires it in no output
even with either of the two layers above removed, and visible with both removed; and it puts
secret-looking values in the environment and requires a template that reads them to render
empty. It fails, and does not skip, when `docker`, `visudo` or `ssh-keygen` is missing. The
workflow runs it after the render. It is not named `test_*` so that the lint job's discovery
does not run its minutes of Ansible.

## Limits

- Only `ansible.builtin.template` tasks are replayed. A `copy` with `content:` is not
  rendered, and the static files under `files/` are not read. The stack files under `hetzner/`
  have their own validators in `ci.yml`.
- `when:` is dropped, so a branch the role would never take is rendered with the same
  variables as one it would take. A template that needs a variable only the other branch
  defines is unresolved or red; give the variable an override.
- A variable set by a `vars:` on a block or an include is not carried to the template. It is
  counted as assigned at run time.
- `dest`, owner, mode, handlers and every other task are not run, so a wrong mode or a task
  that fails on a host is not found here.
- A value is always a dummy, so a template that fails only for a particular real value, or that
  a real value makes valid, is not found.
- The fixture is a stand-in: a host that differs from the image config differs from it.
