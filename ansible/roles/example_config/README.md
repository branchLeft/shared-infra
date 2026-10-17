# example_config

REPLACE_WITH_ONE_SENTENCE: the one service this role configures.

This README is written for a maintainer who is new to the repository. It
follows the order the standard sets for a role README (ANS-14). Replace every
ALL_CAPS placeholder and delete this paragraph when the role is real.

## What the role does, and what it does not

The role writes two files: a configuration file rendered from a template and a
fixed notice file. With `example_config_state` set to `absent` it removes both.

It does not install packages, manage users or start services. Anything else is
another role (one role per service, ANS-12), and the role declares no
`dependencies`.

## Interface

The variables the role reads, their types, choices and defaults are in
`meta/argument_specs.yml`. Ansible checks them when the role starts and fails
the role on a mismatch. `defaults/main.yml` holds the same defaults.

No variable of this role is a secret. A role that takes one lists it here,
supplies it at run time, never gives it a default, and sets `no_log: true` and
`diff: false` on every task that handles it (ANS-16).

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target systems: any Linux system with Python 3 and a writable `/etc`.

## What it changes on a host

- The file at `example_config_config_path`: the rendered `config.conf.j2`.
- The file at `example_config_notice_path`: a copy of `files/notice.txt`.

No services, ports or users.

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes, one command runs lint, yamllint, the interface checks and the
container test:

```text
python3 ansible/harness/run_harness.py ansible/roles/example_config
```

Run it with the Python of the virtual environment that holds the pinned tools.
The test creates one container on the local Docker daemon, runs the role in
check mode against it before anything is applied, applies the role, applies it
a second time (which must report no change), verifies the outcome, runs check
mode again against the configured container and removes the container. It never
touches a host.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by
running `ansible-playbook` by hand. Nothing applies this role to a host yet.

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together: the
   spec and the defaults must agree.
2. Keep every task able to run under `--check --diff`.
3. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
4. Extend `molecule/default/verify.yml` so it asserts the new outcome, not only
   that converge finished.
5. Run the test command above before opening a pull request.
