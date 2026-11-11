# mail_reconcilers

This role places the mail host's reconciler programs on it and runs four of them on request:
reconcile Stalwart's settings, create the mailboxes, create one submission credential, and
create the mail collector's credential with its sender scope. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

On a **plain apply** it makes `/root/mail-provision` (root, 0755) and places nineteen programs
from `mail/provision/` in it, each root-owned with mode 0755. It runs none of them, and a
second plain apply reports no change. On a **step request** it runs one program by its wrapper:
`configure` runs `40`, `mailboxes` runs `50`, `mint` runs one of `60`, `61`, `62`, `64`, `66`
and `68`, and `collector` runs `67 --dry-run` and then `67`.

The programs hold the logic and its idempotence, so the role writes no marker and carries no
API call and no secret. It decides whether a program may run, from what, and what is shown if
it fails. It does not rotate or retire a credential, bootstrap or deploy anything, run the
sender-scope checks (they probe SMTP), place a file the stack role owns, or wire itself in.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares two inputs and
[`defaults/main.yml`](defaults/main.yml) holds the same empty defaults. Neither is a secret,
and both are set on a request's command line, never in an inventory.

- `mail_reconcilers_step`: `configure`, `mailboxes`, `mint` or `collector`.
- `mail_reconcilers_credential`: for `mint` only, `website`, `blog`, `shim`, `alerting`,
  `nextcloud` or `zitadel`.

The closed lists, paths, modes and patterns are in `vars/main.yml`, so an inventory cannot
loosen them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, and `ansible.builtin` only.
- The mail host as root, with `python3`, Docker and Stalwart answering on loopback, and
  `/root/.stalwart-admin-credentials` made by the owner's one-time bootstrap.

## What it changes on a host

- `/root/mail-provision` and the nineteen programs, on every plain apply.
- A step changes what its program changes through Stalwart's API; the programs write
  `/root/.stalwart-service-credentials` and `/root/.stalwart-mailbox-credentials`, which the role
  checks and never reads. `configure` and `collector` restart Stalwart when they change
  something, so sign-in links fail while it is down.

## The guard

A step runs only if three things hold. **The tag**: each step is imported with `never` and
`mail_reconcilers_<id>`, so a plain apply and `--tags all` skip it. **The confirmation**: each
import has `when: mail_reconcilers_step == '<id>'`. **The tripwire**: one task carries `never`
and all four step tags, so it runs whenever any step tag is requested, before any step, and
stops the play with `REFUSED:` unless `mail_reconcilers_step` is a known id whose own tag is
among the tags requested. So a tag with no or a wrong confirmation, or a confirmation whose tag
was not requested, runs nothing; two tags with one confirmed step run only that step.

Every step then checks the **preconditions** before any program runs: the install directory
is root's with mode 0755, `/root/.stalwart-admin-credentials` exists, and that file and the
other two credential files, if present, are regular files (not links) of root with mode 0600.
The programs are told to read exactly these paths. `mint` takes one row of a closed table per
request, with an id pattern ending `\Z` so a trailing line break is refused; there is no row for
a rotation, the administrator or the collector. `collector` runs the program's dry run first
under `check_mode: false`, and starts the real run only if the dry run exited 0 and printed
`DRY RUN, nothing written`; the real run is skipped in check mode and must print
`sender scope stored`. Every task that runs a program has `no_log: true`; on failure a separate
task shows only output lines matching a closed refusal pattern, cut to 200 characters. The
programs echo an API error body on failure; that line matches nothing and is withheld.

The calling playbook must include the role so its tasks run under `--tags`: `include_role` with
`tags: always` on the include (as `molecule/default/request.yml` does), or `import_role`.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes:

```text
.venv/bin/python -m unittest discover -s ansible/roles/mail_reconcilers/tests/unit -p 'test_*.py'
.venv/bin/python ansible/harness/run_harness.py ansible/roles/mail_reconcilers
```

The first needs no Docker. The second runs a container with a stand-in for Stalwart's API
that logs every request, so a case can say a refusal made zero calls, and a stand-in `docker`.
Throwaway secrets are searched for in every request's output and in the whole run's log.

## How it is delivered

`playbooks/mx1.yml` applies this role, after `host_baseline` and `mx1_stack`, as a plain apply
only: it places the programs and runs none of them. The gated pull's step allow-list holds only
the control plane's three steps, and `owner_vars/mx1.yml` may not carry one (R10), so no step of
this role can be requested through the pull. The hand procedure in the mail runbooks is
unchanged, and so is the owner's merge of any change to this role. A run that touches mx1 is the
owner's to approve.

## How to change it safely

1. A new step: a new id in `mail_reconcilers_step_ids`, a `_<id>.yml` that imports
   `_preconditions.yml` before it runs a program, and a tagged import and tripwire tag.
2. A file added under `mail/provision/` fails the unit test until it is installed or classified
   in `vars/main.yml`. Never place a file the host's stack role owns: `check_role_paths.py`
   cannot see a loop destination.
3. Keep `no_log: true` on every task that runs a program, and extend `verify.yml` and the unit
   tests, showing the new control red.

## Named limits

- **Programs read and write credential files.** The role never reads, writes or passes a
  secret; it hides the programs' output with `no_log`.
- **Minting `zitadel` through Ansible removes the show-once display.** The program prints that
  secret only at a terminal; run here it is recorded in the service credential file and shown
  nowhere, so delivery is a hand read of that file.
- **The fresh-host bootstrap of Stalwart is the owner's.** `configure` refuses while the
  administrator credential file is absent, so the role never takes the program's bootstrap path.
- **The stand-in proves the calls and the guards, not the reconcile.** The happy-path cases for
  `configure` and `mailboxes` are not in the container test; the first live run proves them.
- **No step can be requested through the pull**, and a change under `mail/provision` alone does not reselect
  this role's test: the change detection knows only the Hetzner program directories.
- **`mail_reconcilers_step` set in an inventory defeats the second key.**
