# mail_collector_inputs

This role reads the file the owner places for the mail collector on `ops1`, and the directory of
descriptors the collector drains from, and stops the plan if either is wrong. It writes nothing,
creates nothing and returns no value. It exists so that the collector is never started with a real
dead-man's-switch URL and no host to drain, which would withhold every ping and page, and so that a
credential file with the wrong owner, mode or shape is found in the plan the owner approves and not
at the first start.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role runs one read-only module, `mail_collector_inputs_check`, and acts on what it returns:

1. If the input file does not exist, it says so and changes nothing. That is the state before the
   owner places the file, and the collector is not meant to run yet.
2. If the file exists, it requires: the directory above it is root's and not writable by group or
   others; the file is a plain file with one name, owned by root, mode exactly `0600`, and not a link;
   every line is blank, a comment, or `KEY=VALUE` with a key of the collector's own namespace
   (`COLLECTOR_` and capitals, digits and underscores); no key twice; the drain token, the
   dead-man's-switch URL, the submission user and the submission password each present and of a
   safe shape; the URL a Healthchecks ping address; the drain token at least 32 characters.
3. Once the file exists and holds the URL, it requires at least one plain `*.json` file in the
   descriptor directory. A collector given a real URL and an empty drain list pings nothing, so the
   check turns Down and pages, by the standing ruling "zero hosts pages"; the role refuses that pair in
   the plan instead.

It does **not**: install, start or stop the collector (the collector's own role does), write the
input file, write a descriptor, read a value into a variable, a fact, a log or a return value,
check that a credential is right (only mx1 and Healthchecks can say that), or touch Healthchecks.
It does not alert: the page for a silent collector is the owner's Healthchecks check and its
notification route, which only the owner can create and test (see "What pages, and where").

## Interface

The role takes no argument ([`meta/argument_specs.yml`](meta/argument_specs.yml)). Its two paths are
constants in [`vars/main.yml`](vars/main.yml): role variables outrank every play and inventory value,
and the pull route has no `-e`, so a caller cannot point the check at another file.

| Constant                               | Value                                        |
| -------------------------------------- | -------------------------------------------- |
| `mail_collector_inputs_secrets_path`   | `/etc/branchleft/mail-collector/secrets.env` |
| `mail_collector_inputs_descriptor_dir` | `/etc/branchleft/mail-collector/descriptors` |

The descriptor path is the collector's `COLLECTOR_DESCRIPTOR_DIR`. Both paths must equal what the
collector's own role uses; one place has to change when that role fixes its layout (see "Named
limits").

## What the file looks like

One line per key, no quotes, no spaces, none of `$`, a backslash or a backtick in a value (the
container runtime and Compose read those differently, so the check refuses them):

```text
COLLECTOR_DRAIN_TOKEN=ALL_CAPS_PLACEHOLDER_AT_LEAST_32_CHARACTERS
COLLECTOR_HEARTBEAT_URL=https://hc-ping.com/CHECK_UUID
COLLECTOR_SMTP_USER=ALL_CAPS_PLACEHOLDER
COLLECTOR_SMTP_PASS=ALL_CAPS_PLACEHOLDER
```

The token is letters, digits and `. _ ~ + / = -`. The URL is `https://hc-ping.com/<uuid>` or
`https://hc-ping.com/<ping-key>/<slug>`; a `/start`, `/fail` or `/log` ending, or a numeric exit
status, is refused because it is not the plain ping. The owner makes the file as root, reading each
value into the shell and never typing it on a command line; no value is in this repository.

## The codes

A refusal names a code, and at most a key the collector defines or a line number. It never shows a
line or a value.

| Code                  | Meaning                                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------------------- |
| `directory-mode`      | The directory above the file is missing, a link, not root's, or group/other-writable                    |
| `file-mode`           | Not a plain file, not root's, not mode `0600`, a link, or has a second name                             |
| `file-unreadable`     | The file exists and could not be opened                                                                 |
| `line-shape:N`        | Line N is neither blank, a comment, nor `KEY=VALUE`                                                     |
| `unknown-key:N`       | Line N names a key outside the collector's namespace                                                    |
| `duplicate-key:KEY`   | A key is set twice                                                                                      |
| `missing-key:KEY`     | A required key is absent or empty                                                                       |
| `value-shape:KEY`     | A value holds a space, quote, backslash, `$` or backtick, or the token's characters are outside its set |
| `heartbeat-url-shape` | The URL is not a plain Healthchecks ping address                                                        |
| `drain-token-short`   | The drain token is under 32 characters                                                                  |
| `descriptor-dir`      | The descriptor directory is missing or cannot be listed                                                 |
| `no-host-named`       | The URL is set and no plain `*.json` file is in the descriptor directory                                |

## What pages, and where

The collector pings the owner's Healthchecks check only once every host its descriptors name has
completed a poll cycle (the dead-man's-switch module in `branchLeft/ghost-platform`). Silence
turns the check Late, then Down, and Healthchecks pages through the notification route the owner set
on the check. That route is in the owner's Healthchecks account, not in this repository, and no
Prometheus metric stands behind it: the collector serves `/healthz` only, and a liveness probe of
that answers while the loop is wedged, which is the failure the switch exists to catch. So this
role adds no Alertmanager rule. The page register and the Alertmanager route are not changed.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13, Python 3.13 (the module's floor).
- `/etc/branchleft`, made by `host_inputs`, which goes first on `ops1`.

## What it changes on a host

Nothing. It reads two paths and writes none. A plan and an apply report zero changes, and the
Molecule scenario's idempotence step holds that.

## How the values are kept out of every log

The input file's lines are read inside the module and never leave it. The task that calls it has
`no_log: true` and `diff: false`; the codes are shown by a second task that reads only the returned
codes. The Molecule scenario runs at Ansible verbosity 3, places three made-up values, drives eight
refusals and one control, and then requires that none of the three is in the log and that a control
text is (so an empty scan would not pass).

## How to test it

From the repository root, with the pinned tools installed as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/mail_collector_inputs
```

The module has unit tests. From `ansible/roles/mail_collector_inputs`:

```text
PYTHONPATH=files:library python -m unittest discover -b -s tests/unit -p 'test_*.py'
```

Four controls are proven by sabotage; break the named line, see the named test go red, restore:

| Break                                                         | Test that goes red                             |
| ------------------------------------------------------------- | ---------------------------------------------- |
| In `check_inputs`, drop `and count == 0` so no host is needed | `test_heartbeat_with_no_descriptor_is_refused` |
| In `placed_by_owner`, drop the mode comparison                | `test_group_readable_file_is_refused`          |
| In `parse`, drop the `COLLECTOR_KEY` match                    | `test_unknown_key_is_refused`                  |
| In `parse`, put the line's text into the `line-shape` code    | `test_no_result_carries_a_value`               |

## How it is delivered

`ansible/playbooks/ops1.yml` applies it just before the ring controller's role (which stays last), and `ansible/checks/host_roles.yml` lists it for
`ops1`. A merge of this role changes nothing on a host: delivery is a gated plan, the `ansible-hosts`
approval, an apply, then a second run that reports zero changes. Until the owner places the file, the
role's only output is the line saying the collector's inputs are not placed yet.

## How to change it safely

- A new required key: add it to `REQUIRED_KEYS` and to the table above, and add a case to the unit
  test and the Molecule scenario. Do not add a way to return a value.
- A new code: add a constant, a row in the table and a test that it is the only code returned for the
  fault.
- The two paths: change `vars/main.yml`, the scenario's `group_vars` and the module's callers
  together; the scenario spells the paths out so that a changed constant fails it.

## Named limits

- The paths are this role's choice. The collector's own role is built separately and may place its
  input file and descriptor directory elsewhere; one constant each changes here when it does.
- The role cannot tell a real credential from a made-up one of the right shape. Only mx1 (for the
  submission pair), the spool (for the drain token) and Healthchecks (for the URL) can.
- Descriptors are counted, not validated: a `.json` file that the collector's own schema check
  refuses still counts as naming a host. The collector reports that on its own `/healthz`.
- In a plan the `ansible-hosts` approver reads, a refusal stops the plan for the whole host, so a
  wrong file placed early holds the host's later roles back until it is corrected. The role goes
  near the end for that reason.

## Clauses this role exercises

ANS-3 (modules, no shell), ANS-9 (a custom module only where no built-in reads a file this way),
ANS-10 (check mode: the module reads in both), ANS-12 (no import of another role), ANS-15 (container
test), ANS-16 (no value in any output).
