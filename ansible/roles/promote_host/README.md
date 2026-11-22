# promote_host

This role installs the host side of the signed-image deploy route on app1: the applier program
(`branchleft-promote`), the one public key it trusts to sign a promotion ledger, the slot map that
turns a ledger's opaque slot number into a stack, an environment file of public values, a service
unit and a timer. The applier reads a ledger over public HTTPS, checks its signature, and hands
each move to the deploy wrapper (`branchleft-deploy`), which verifies the image's attestation
before it takes the stack lock, pins the image or restarts anything. The role is how a stack, the
website first, can leave the host-level SSH deploy key.

**The timer is inert until both inputs are set.** With either empty the role installs the
program, the slot map and both units, writes no signer file, and holds the timer disabled and
stopped. A host with no signer file trusts nothing, and the applier refuses to run.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role:

1. Refuses a bad input before anything changes: a ledger URL that is not a plain https address,
   a signer key that is not one ed25519 public key line, and either input set without the other.
2. Checks, and never makes or changes, `/etc/branchleft` and `/var/lib/branchleft`: each must be
   a real directory that is root's and that group and others cannot write.
3. Checks that `ssh-keygen` is an executable file when the inputs are set. The applier checks a
   ledger's signature with it and refuses every ledger without it.
4. Makes `/etc/branchleft/promote` (public text) and `/var/lib/branchleft/promote` (root's, mode
   `0700`, the applier's replay protection and lock).
5. Installs `hetzner/provision/branchleft_promote.py` as `/usr/local/sbin/branchleft-promote`. The
   role holds no copy of the program; there is one home for it.
6. Writes the slot map, the signer file (only when a signer is set, and removes it when the
   signer is cleared), the environment file and the two units.
7. Holds the timer on or off by the inputs.

It does not produce, sign or publish a ledger (that is the ring controller, a separate piece of
the route), does not hold or print any key, does not install the deploy wrapper (that is
`deploy_tooling`, which runs before this role on app1), does not install the attestation verifier
(`deploy_verifier`), and does not touch a tenant's stack. It makes no account: the applier runs
as root, as the wrapper does, because every file the applier trusts must be root's.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the two inputs. Both are public
values and neither is a secret, so neither needs a `host_inputs` entry. Both default to empty,
and empty is valid: the role then does what it can without them.

| Variable                  | Default | Meaning                                                                             |
| ------------------------- | ------- | ----------------------------------------------------------------------------------- |
| `promote_host_ledger_url` | empty   | The https URL of the signed ledger. The signature is the same URL with `.sig` added |
| `promote_host_signer_key` | empty   | The one ed25519 public key line the applier trusts, with no comment                 |

Each is checked by its own task before anything changes, and a refusal names the input and never
its value. The shapes are patterns in `vars/main.yml`; none admits a space, a quote, a backslash,
a dollar sign or a hash, so each value is one plain word. The role does not read either input
from `host_inputs`: neither is private. The owner's values would live in
`ansible/owner_vars/app1.yml`, which does not exist yet; setting them is the owner's step
(see "How it is delivered").

The paths, names, modes and the slot map are constants in `vars/main.yml`, not inputs: an
inventory value cannot move them. A unit test holds each path equal to the default of the same
path in the program.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Python 3.13 and systemd. The program starts with `/usr/bin/python3 -I`.
- `/etc/branchleft` made by `host_inputs`, and `/var/lib/branchleft` made by the break-glass grant
  and the deploy verifier, which run before this role on app1.
- `/usr/local/sbin/branchleft-deploy`, installed by `deploy_tooling` (the unit does not start
  without it) and, once an image is attested, `deploy_verifier` for the check the wrapper runs.
- `ssh-keygen` (the OpenSSH client), once the inputs are set.
- Only app1 may apply it. That is the owner's list (`ansible/checks/host_roles/app1.yml`, rule R9);
  a test inside the role would be no control, because under the pull inventory the host's name is
  `localhost`.

## What it changes on a host

| Path                                                       | Owner | Mode   | What                                         |
| ---------------------------------------------------------- | ----- | ------ | -------------------------------------------- |
| `/etc/branchleft/promote`                                  | root  | `0755` | Config directory                             |
| `/etc/branchleft/promote/slots.json`                       | root  | `0644` | The slot map: the website's row              |
| `/etc/branchleft/promote/allowed_signers`                  | root  | `0644` | The one trusted signer; only when one is set |
| `/etc/branchleft/promote/promote.env`                      | root  | `0644` | The ledger URL, one name                     |
| `/var/lib/branchleft/promote`                              | root  | `0700` | The applier's state and lock                 |
| `/usr/local/sbin/branchleft-promote`                       | root  | `0755` | The applier                                  |
| `/etc/systemd/system/branchleft-promote.service`, `.timer` | root  | `0644` | The two units                                |

Nothing else. The applier itself refuses to run when its signer file, slot map, wrapper or state
directory is a link, is not root's, or can be written by group or others, so these modes are the
ones it requires and not a preference.

## The website's slot

The ledger names no stack, tag, tenant or address. A slot is an opaque number from 30000 to 30999,
and this host's slot map turns it into a stack. The role writes one row, `30999` for `website`.
The website's stack name is public, so the row is a constant. A tenant's stack name is private and
is not in this role; a tenant's row is a later piece of the route.

30999 is the top of the applier's range, so a tenant slot allocated upward from 30000 never meets
it. The number is a contract with the ledger's writer: it must use 30999 for the website.

The row alone does not move the website. The applier refuses an image whose repository is not on
the wrapper's register of attested images, and until the website's image is on that register
(`ATTESTED_IMAGES` in `hetzner/provision/branchleft_deploy.py`) a ledger entry for slot 30999 is refused with "image is not on the attested register", before the
wrapper is called.

## How the signer file is made safe

The file holds one line, `ring-controller namespaces="branchleft-promotion-ledger" <key>`. The
principal and the namespace are the program's own constants, and a unit test holds them equal.
The `namespaces` option means the same key cannot sign for another purpose (a git commit, a file)
and have it pass as a ledger. Four tests sign with a key made for the test, render the role's
template and run the program's own `verify_signature`: the placed key in the ledger namespace is
accepted, and another key, another namespace and a changed body are each refused. The Molecule
`configured` scenario makes the same four checks with `ssh-keygen` on the real platform, against
the file the role wrote.

A pattern holds the key to one ed25519 line with no comment, no option and no second line, so
nothing can be added to the file's one grant by way of the input.

## How it is delivered

Delivery is the gated workflow only (ANS-17): a plan in check mode, the `ansible-hosts` approval,
a pull of that exact commit on the host, and a second run that must report zero changes. Nothing
here applies the role by hand.

Wiring the role to app1 is an owner merge: `ansible/checks/host_roles/app1.yml`,
`ansible/playbooks/app1.yml` and `.github/CODEOWNERS` are owner-merged paths, and the role's
whole directory is the owner's.

Merging and applying this role makes the applier present and inert. Turning it on is two owner
steps, in this order, once the ledger's writer exists and has a signing key: set
`promote_host_signer_key` and `promote_host_ledger_url` in `ansible/owner_vars/app1.yml` (the
playbook's `vars_files`, the owner-vars check's allowed keys and that file are one owner change,
not yet made), and let the gated apply run. The first run with both set enables the timer.

## How to test it

From the repository root, with the pinned tools installed as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/promote_host
.venv/bin/python ansible/harness/run_harness.py ansible/roles/promote_host --scenario configured
.venv/bin/python ansible/harness/run_harness.py ansible/roles/promote_host --scenario refusals
```

The unit tests need `ssh-keygen` and run from `ansible/roles/promote_host`:

```text
PYTHONPATH=files:library python -m unittest discover -b -s tests/unit -p 'test_*.py'
```

The `default` scenario applies the role with no input and converges twice. It checks each file's
owner and mode, the slot map's one row, no signer file, the program's first line, the timer
installed, disabled and stopped, and that the applier run by hand on this inert host refuses
before it fetches anything and leaves no state beyond its lock. The `configured` scenario gives
both inputs and signs with a key made in the container, checks that the placed file accepts the
good signature and refuses the other three, that the timer is on, and that clearing both inputs
removes the signer file and holds the timer off. The `refusals` scenario puts each bad input or
bad parent in turn, requires the role's exact message with no value in it and no change to any
path it writes, after a control that the host as delivered is accepted.

The sabotage controls, each red when its guard is removed: the key and URL patterns
(`test_a_signer_key_pattern_takes_one_ed25519_line_and_nothing_else`,
`test_a_ledger_url_pattern_takes_one_plain_https_address_and_nothing_else`), the namespace
restriction (`test_the_placed_key_cannot_sign_for_another_namespace`), the removal of a cleared
signer (`test_the_signer_file_is_removed_when_no_signer_is_set_and_written_when_one_is` and the
`configured` verify), the timer following the URL, the program's paths held equal to the role's,
the unit passing the URL only, `test_codeowners.py` (the owner line) and
`test_check_host_roles.py` (the role on any host but app1).

## How to change it safely

- A change to the signer file, the pattern for a key, the units or the tasks is a change to what a
  root timer on a production host will act on, so it gets the deep review a trust anchor gets,
  and the owner's merge: the role's directory is owned in `.github/CODEOWNERS`.
- The paths and the signer's name and namespace are the program's; change the program and the
  role in one pull request, and a unit test fails if only one moves.
- Do not add an input for a path, a second signer or a program option to the unit: a second
  signer widens who can move a stack, and a unit test holds the unit to the URL alone.
- Do not add a model key, a push route or an agent program to the unit.

## Named limits

- **The role proves the files, not the ledger.** Nothing here makes, signs or serves a ledger. The
  first real tick is the first proof that the signer, the URL and the slot number agree with the
  ledger's writer.
- **A ledger entry for the website is refused until the website's image is registered.** See
  "The website's slot".
- **Check mode on a fresh host shows less.** With no unit files yet, the tasks that read them are
  skipped and the first plan shows the files as "would create" and nothing about the timer.
- **The test platform has no `ssh-keygen`.** The `configured` scenario installs the OpenSSH client
  in `prepare`, as an app host has it; the `refusals` scenario leaves it out to test the case.
- **A key cleared from the inputs is removed from the host, and the timer is held off, on the
  next apply, not at once.** Until then the host trusts the key it was last given.
- **The systemd test platform is a container.** It proves the files, owners, modes and systemd's
  view of the units; it does not prove a tick moves a stack.

## Clauses this role exercises

ANS-2 (typed tests), ANS-7 (defaults mirror the spec), ANS-10 (check mode), ANS-11 (idempotence),
ANS-12 (no role imports another), ANS-14 (this README), ANS-15 (a container test), ANS-16 (no
value in a refusal) and ANS-17 (the gated pull).
