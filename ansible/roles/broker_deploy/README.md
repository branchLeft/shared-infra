# broker_deploy

This role installs the demo host's broker on a host and runs it, in place of the
broker runbook's hand install: the pinned Node runtime, the broker account, the state
directories, one pinned release of the broker's bundle with the current link pointing at
it, the public half of the request-signing key, the environment file and the systemd
unit. It enables and starts the unit, restarts it when what it runs changed, and waits for
the broker's status answer.

The release is the one the broker's release workflow builds in CI and signs with a
build attestation. The role carries that release's files, each held to a sha256 pinned in
reviewed code, and fetches nothing: see "How the release arrives".

It is built from the `monitoring_stack` role and the patterns under `ansible/patterns/`.

## What it changes on a host

| Path                                              | Owner       | Mode                  | Source                                                                       |
| ------------------------------------------------- | ----------- | --------------------- | ---------------------------------------------------------------------------- |
| `/opt/branchleft/broker/node/` (the Node runtime) | root        | 0755                  | Node tarball, checked against its published sha256                           |
| `broker` account                                  | system      | no login shell        | none                                                                         |
| `/etc/branchleft/`                                | root        | 0755                  | none                                                                         |
| `/var/lib/branchleft/`                            | root        | 0755                  | none                                                                         |
| `/var/lib/branchleft/broker-slots/`               | broker      | 0755                  | none                                                                         |
| `/var/lib/branchleft/broker-slots/admin-keys/`    | broker      | 0700                  | none                                                                         |
| `/opt/branchleft/broker/releases/<version>/`      | root        | dirs 0755, files 0644 | the pinned release files, `broker_deploy_release_dir`                        |
| `/opt/branchleft/broker/current` (link)           | root        | link                  | the release directory                                                        |
| `/etc/branchleft/broker-verify-key.bin`           | root:broker | 0640                  | the 32 raw bytes of `files/broker-verify-key.hex`, held to a sha256          |
| `/etc/branchleft/broker.env`                      | root        | 0600                  | `templates/broker.env.j2`, the shipped template with the slots-file line set |
| `/etc/sudoers.d/branchleft-slot`                  | root        | 0440                  | `templates/branchleft-slot.sudoers.j2`, one literal line per invocation      |
| `/etc/systemd/system/branchleft-broker.service`   | root        | 0644                  | `files/branchleft-broker.service`                                            |

After the role the unit is loaded, enabled and active, and the broker answers
`GET /status/0` on the loopback address.

## How the release arrives

The broker's release workflow packs the bundle into a deterministic tarball, attests it, and
publishes it as a release. The demo host reaches no network place but its package mirrors,
its commit arrives signed, and no archive may be committed under `ansible/`, so the role
takes the release's files from its own `files/releases/VERSION/` directory, in the commit,
and not from the release page.

Two controls stand between the files and the host. Before the role writes anything,
`tasks/_release_pin.yml` refuses the release unless the directory holds exactly the files
pinned for the version in `broker_deploy_release_pins` (none missing, none extra, hidden files
included), no link among them, and each one a plain file with its pinned sha256. The pins
are reviewed code, so a release is chosen by a reviewed change and not by a tag. And the
files are added to `files/releases/VERSION/`, with their pins, only after the release's
attestation has been verified against the broker's release workflow, as the broker's
runbook describes, and the tarball unpacked. The role does not verify an attestation, and a
pin proves the bytes did not change since it was chosen, not that CI built them.

Release 0.2.1 is carried: `broker_deploy_release_version` is `0.2.1` and
`broker_deploy_release_pins` holds its five files, and those of 0.2.0, which stays for a rollback. While no release is carried (both inputs
empty), the role waits. It says so (a debug task, ANS-10) and ends with `meta: end_role`, first of
`tasks/_release_pin.yml`, with nothing read from the host or written to it, in a plan and in an
apply; the verify key check and every task after it are skipped with it, and the rest of the
host's play goes on. A run does the whole role from the first pull after a version and its pins
are carried. A release that is only half carried, a
version with no pins or pins with no version, is not a wait: it is refused below, as are all
the other refusals. The step that carries the first release sets the version, the pins and the
files in one change. That
step is made by `ansible/tools/carry_broker_release.py` (see `ansible/tools/README.md`) from the
tarball the owner has verified, so the files and pins are not typed by hand.

A version is delivered into its own directory under `releases/` and the `current` link is
swapped to it, so the old directory stays for a rollback by pinning the old version. A byte
that changed in a delivered release is put back by the next run, and shows in a plan. A file
on the host that is not part of the release is left alone.

## Starting and restarting

The role enables the unit and starts it. It restarts the broker, once, when the delivered
release, the current link, the verify key, the environment file or the unit changed in the
same run (`broker_deploy_inputs_changed`, set in `tasks/main.yml` and read in
`tasks/_run.yml`). A run that changes none of them leaves the process alone. A broker that
is stopped or failed is started by the enable-and-start task on the next run. Last, the
role asks `GET http://127.0.0.1:8090/status/0` until it answers 200 with slot `0`, and fails
the run when it does not, so a unit that starts and dies is not reported as converged.

Check mode names the start or restart in a plan with a task that runs `true` and reports
changed. It skips two things, each for a stated reason: the start of a unit that is not on
the host yet (the module would fail to find it), and the status request (a plan starts
nothing).

## Inputs

Every input has a default, because a playbook entry for this role carries no variables. The
release stays empty until the owner carries one, and the role waits and changes nothing while
it is (see above).

- The release is `broker_deploy_release_version` (empty until one is carried), its digests are
  in `broker_deploy_release_pins`, and the files are in `broker_deploy_release_dir`.
- The request-signing public key is the text file `files/broker-verify-key.hex` of this role
  (`broker_deploy_verify_key_src`): its 64 lower-case hex digits spell the key's 32 bytes, and
  those bytes are held to the sha256 in `broker_deploy_verify_key_sha256` (the owner's key,
  carried). The key is text so that no binary file is tracked in the repository. The role
  builds the 32 raw bytes from the hex where it runs (`vars/main.yml`) and writes those bytes to
  `/etc/branchleft/broker-verify-key.bin`; it never writes the hex. It refuses, before anything
  is written and in a plan too, a digest that is empty or malformed, a file that is missing or a
  link, text that is not exactly 64 lower-case hex digits (one line feed after them is allowed),
  and bytes that do not have the pinned digest. After the write it reads the host's file back
  and refuses one that is not 32 bytes with that digest. Changing the key is one change that
  replaces the file and the digest, and a test holds the file to the key's hex and to the
  digest, so a key is chosen by a reviewed change. The private half stays with the owner and
  never reaches the role. The file's place and the digest are role defaults, so a run-time `-e`
  could point `broker_deploy_verify_key_src` at another key file and give its digest; the pull
  route passes no `-e` of its own, and a run by hand with one is outside the signed route.

- The owner's due-diligence address is `broker_deploy_owner_due_diligence_email`. It has no
  value in the repository (the default is empty), and it is the broker's `OWNER_DUE_DILIGENCE_EMAIL`:
  the broker adds it to every demo as a reader and refuses to start without it. The role checks it
  before anything is written and before the environment file is templated: while a release is carried,
  an empty value, or one that is not a plain address, stops the run and prints no value. The environment
  file task and the restart decision that reads its result hide their output (`no_log`, `diff: false`).
  It is the owner's to place. It is not yet fed from the host's inputs file: demo1 has no `host_inputs`
  row, so the value has to reach the role by a route the owner decides (see "Steps the role does not take").

[`meta/argument_specs.yml`](meta/argument_specs.yml) documents all of them. None
of them is a secret. The private half of the key never reaches the role.

## Requirements on the host

- `xz` (the Node tarball is unpacked with it).
- systemd, to load the unit.
- `sudo`, which provides `visudo`, to check the grant.

## Steps the role does not take

These stay with an owner, as the runbook already says:

- Cutting a release: that is the broker's release workflow, on a signed tag.
- Adding a release's files to `files/releases/VERSION/` and their pins, after the attestation
  was verified. A version whose files are not carried stops the role; no version at
  all makes it wait.
- Making the request-signing key pair, and saving the private half in the
  owner's password manager.
- Installing the slot wrapper program itself, which the sudoers grant names.
  The grant is installed here; the wrapper comes from the host build.

## Tests

The Molecule scenario in `molecule/default` runs the role in a systemd container
against a stand-in release (`files/release/0.0.1`) and a zero-filled 32-byte key, carried as 64 hex digits. Neither is
a broker artefact: the stand-in entry point only answers the status request. A test-only
drop-in (`prepare.yml`) lifts the unit's sandbox, which an unprivileged container cannot
provide, so the sandboxed start is not proven here. `verify.yml` reads the result back, and
compares the unit with its source and reads the verify key back as 32 bytes with the pinned
sha256, which is the digest of the 32 zero bytes the stand-in file spells. It checks the delivered release's
owner and modes, that the unit is enabled and active, that the broker answers its status
request, and that the start step leaves the process alone when nothing changed and replaces
it when the release changed. It checks the environment file's owner, mode, slots-file line
and that `LISTEN_HOST` is unset, but not every line of it.

The unit tests in `tests/unit` run the pin check and the release tasks with
`ansible-playbook` on the machine that runs them, in a scratch directory with every path
moved into it: a release with a changed, missing, extra, hidden or linked file, a missing
directory, or a version or a pin of the wrong shape is refused before anything is written, a
plan writes nothing, an apply delivers and links once, the next run and the next plan change
nothing, and a byte changed on the host shows in a plan and is put back. A contract test holds
the pins' shape, the stand-in release to its pins, the carried key file to the owner's key (as
hex, with no binary file left in the role), the stand-in key to its pin, the readiness port to
the environment file's, and both pin checks ahead of any write. The wait test holds the wait's
condition and its place, first in `_release_pin.yml`, and runs the real pin check in a scratch
role for the three outcomes: nothing carried ends the role, a version with no pins or pins with
no version is refused, and a carried release goes on. The pin check runs inside a role in
every test because a play cannot run `end_role` outside one. The Molecule verify runs the role
from its defaults against the instance, as an apply and as a plan, and compares what the role
writes before and after.

The same tests run the two verify key task files: the host gets the pinned bytes of the carried
key, which are not text, and every byte value from 0 to 255 comes out as it went in; the key
file with one hex digit changed, a pin of another key, a malformed pin, a file that is not
exactly 64 lower-case hex digits, and a missing or linked file are each refused before the
host's key is written, in a plan too; a plan writes nothing, the next run and plan change
nothing, and a key changed on the host shows in a plan and is put back.

The Node unpack is skipped in check mode: `unarchive` needs its destination to
exist even then, and on a host the role has not touched the directory and the
download are only reported, not made.

## Known limits

- The Node runtime is downloaded from nodejs.org, over https on the default port, so a host's
  egress must allow that one host besides the package mirrors, for this download alone. The
  owner decided it: the pinned Node version, its sha256 as the get_url `checksum`, no other
  host. The allowlist is the host's, not this repository's. The check that holds demo1's roles
  to no fetch (`ansible/checks/test_demo1_no_github_fetch.py`) lets through this one `get_url`
  and refuses any other: a download with no checksum, from another host (a suffix of
  nodejs.org included, or GitHub), from another role or another file of this role, a second
  `get_url` in `tasks/main.yml`, a second place that sets `broker_deploy_node_base_url`, or a
  pin that is not a sha256. Changing the base url or the url shape is a change to that test.
  The check reads this role's text; the host's own firewall is not read by it. A variable
  passed at run time could still move the base url (the pull route passes none, and the
  checksum must still match). A host that already has the pinned version skips the download.
- The attestation is not verified by the role, only the pinned digests (see "How the
  release arrives").
- The sandboxed start of the unit is proven by the broker's own boot test, not by this
  role's container test.
