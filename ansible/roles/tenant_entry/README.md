# tenant_entry

Installs the tenant app host's entry point: one program, one account that may run only that
program, and one forced-command key line, so the controller can set up a new tenant's slot, deploy
key and host files without a person on the host.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role makes the program `branchleft-tenant-entry` and the three things that bound who can run
it:

- the program, root-owned, which reads one request, checks it, and calls the programs that already
  own each step;
- the account `tenant-entry` (locked password, real shell), its sudoers file (one command with one
  argument) and its authorised keys, which are exactly one line: the controller's key, restricted,
  limited to the declared source addresses, and forced to the program;
- the register directory of the tenants the program has claimed;
- the tenant secrets program, fetched from ghost-platform at one pinned commit;
- the owner script, fetched from ghost-platform at one pinned commit and held to its sha256, and
  the node it runs under, the tarball nodejs.org publishes held to its published sha256, in a
  root-owned directory of its own (the `owner` verb runs the one with the other as root);
- the judge of a tenant's compose text, a byte-identical copy of `tenant_compose`'s module, which
  the program loads from a root-owned file;
- the host's own private address, kept in a root-owned file beside the register, where the stack
  verb publishes each tenant's ports.

It does not run the program. A request is made over SSH by the controller, never by Ansible.

It does not install the programs the entry point calls. The volume program and its name register
come from `tenant_onboarding`, the slot program from `deploy_slot_keys`, and the deploy wrapper from
`deploy_tooling`. This role reads that they are there and fails closed, naming the program, when one
is not. It writes a compose file only through the `stack` and `restack` verbs, which build the file themselves from
its own template, the tenant's claim and a few checked parameters, and gives the result to the same
judge `tenant_compose` runs. A caller never sends compose text: every line of that file is an
isolation control, and the judge is a short list of forbidden keys, not a description of what a
tenant stack may do. It never writes an image pin: the first pin is `branchleft-deploy`'s, written
after it has verified the image's attestation.

It does not mint, store or print a key or a secret. The controller's public key is the role's one
input. The role adds itself to no playbook (see "Owner steps").

## What the program accepts

The request is `VERB SLUG` in `SSH_ORIGINAL_COMMAND`, two words and nothing else. A verb that needs
more reads one JSON object on stdin, at most 64 KiB, whose keys are exactly the ones named here. The
slug must match the volume program's own rule (a lower-case letter first, then letters, digits and
hyphens, 26 characters at most); the volume program stays the authority on reserved names.

| Verb      | Stdin                                      | What it does                                                                                                                                                                                                                                                                     | Needs first             |
| --------- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `status`  | none                                       | Reports how far one slug has got. A slug this entry point never claimed reports only that.                                                                                                                                                                                       | nothing                 |
| `claim`   | none                                       | Takes the lowest free uid in 30000 to 30999 and the first free block of four ports from 40000, writes the slug's marker, and asks the volume program to make the volumes and claim the uid. Prints the uid and the three ports (colour a, colour b, health router).              | the slug exists nowhere |
| `secrets` | `template`, `values`                       | Writes the template to a closed temporary file and passes the values on the secrets program's stdin. The program writes the tenant's secrets file.                                                                                                                               | `claim`                 |
| `stack`   | `size`, `mail`, `environment`              | Builds `compose.yml` from the host's template, the claim's uid and ports and these parameters, judges it with the judge `tenant_compose` runs and, only if it passes, writes it. No pin. The same parameters again succeed; never over a different file, never outside the slot. | `secrets` file in place |
| `restack` | `size`, `mail`, `environment`              | For a tenant already live: rebuilds `compose.yml` the same way `stack` does, judges it, and only if the judge passes replaces the file in one rename. Then queues a restart of the unit if it is running (never starts one). A retry finds the file in place and restarts again. | `enable` and `stack`    |
| `enable`  | none                                       | Enables the tenant's compose unit, never starts it: the unit has no image pin until its first deploy, and without one it stays inactive.                                                                                                                                         | `secrets` file in place |
| `key`     | `public_key`                               | Grants the slug's deploy slot to one ed25519 public key through the slot program, once. A slot that exists is never replaced.                                                                                                                                                    | `enable`                |
| `owner`   | `colour`, `name`, `site_url`, `site_title` | Finds the running colour's container and runs the platform's own owner script, so the Ghost owner exists before the hostname is served.                                                                                                                                          | `enable`                |

The order is enforced by the program, not by the caller: a later verb on a slug that has not passed
the earlier step is refused by name (`secrets-first`, `enable-first`). The secrets file is in place
before the service is named, because the reverse aborts the whole stack.

The `stack` verb takes parameters only. The compose file is the host's own template (two Ghost
colours, both on `${IMAGE}`, the platform renderer's runtime posture for a paying tenant) filled from
four things the caller does not choose: the slug, the claim's uid (the service `user`), the claim's
ports (colour a on `port_a`, colour b on `port_b`) and this host's private address (the bind
address). The caller chooses three:

- `size`: `small`, `standard` or `large`, which the host maps to its own cpu, process and file caps.
- `mail`: true or false, whether both colours join the spool's network for this uid.
- `environment`: 1 to 64 names and values. A name is a letter then letters, digits and
  underscores. A value is a number, a boolean, text of printable ASCII with no `$` (so no compose
  reference), or `{"secret": "GHOST_NAME"}`, which the host writes as a reference to that key of
  the tenant's secrets file.

The file is JSON, which is YAML, so the encoder quotes every value and no value can add a key. The
judge then reads the built text against the tenant's uid, the volume program's claims and the
secrets file. A request repeated with the same parameters finds its file in place and succeeds
(`compose.yml already in place`), so a retry after a lost reply needs no hand step. Other
parameters over an existing file are `stack-exists`.

It refuses by name: `not-claimed-here` and `secrets-first` before it reads its payload;
`pin-not-accepted` for a request that carries an image pin, and `compose-not-accepted` for one that
carries a compose text; `payload-keys` for any other key or a missing one (a `volumes`, `user`,
`entrypoint` or `ports` key included), `payload-not-json`, `payload-not-object` and
`payload-too-large`; `field-size`, `field-mail` and `field-environment`; `path-outside-slot` for a
stack root that is missing or open to another user's write, or a stack directory that is a link,
not a directory or not root's; `stack-exists` for a file that is already there and is not this
request's own; `judge-refused` when the judge refuses the built stack; `claim-mismatch`; and
`judge-unsafe` for a judge file that is not root's or is writable by another user. A judge that is
missing, or has no PyYAML, is `failed: judge-missing` or `failed: judge-yaml-missing`; a missing or
unreadable address file is `failed: bind-address`; a write that fails is `failed: write`. A
`judge-refused` is the one refusal that carries more than its word: the rules the judge says were
broken follow it, one line, cut to 1000 characters. The judge names rules, services and key names
and never a value, and the program withholds the whole line if it repeats a secret value anyway.

`status` also prints the claim: `uid=`, `port_a=`, `port_b=` and `port_health=` for a slug this entry
point claimed, so a caller that was not there for the claim reads the host's own numbers. `stack=yes`
means the compose file is in place; it says nothing about a pin.

`restack` is the one way to change an existing tenant's environment after onboarding. It takes the
same three parameters as `stack`, builds the file from the same template and the claim, and runs the
same judge before anything is written, so a judge refusal (`judge-refused`) leaves the file on disk
byte for byte as it was. It refuses `stack-first` when no compose file is in place, and
`enable-first` when the unit is not enabled. It queues a restart of the running unit with
`systemctl try-restart --no-block`, so the colour reads the new environment. `try-restart` acts only
on a running unit, so a unit that is down is never started, and the reply says
`not restarted: not running`. The `--no-block` queue returns at once: a unit still starting or
restarting gets `deferred: restart queued, the new file is read when the unit starts`, not a
`failed: timeout`, so the step timeout never waits on a unit's start. A unit in a failed state fails
the step (`failed: restart`); the file already holds the new text, so a repeat of the request
restarts again. The `deferred` reply is given for every running unit (active, activating,
deactivating or reloading), so it does not by itself mean the unit is still starting. A unit that
fails after a deferred reply is not in that reply: a later `status` prints `unit=` with the unit's
own state (`unit=failed`), which is the read that shows it. Restart in place is the MVP's; the colour-swap apply replaces it when it lands. The
verb takes no uid, port, compose text or pin.

### The first pin, and a unit with no pin

The verb writes no `SLUG.image.env`. The first pin comes from `branchleft-deploy`, which verifies the
image's attestation against its register before it writes the pin and starts the unit, exactly as
`tenant_compose` runs it for a tenant with no pin. `enable` enables the unit and starts nothing.
The compose unit asserts that the pin file exists (`AssertPathExists`, no leading dash), so an
enabled unit with a compose file and no pin stays inactive at boot and at `systemctl start`; a test
holds that line of the unit. Order for a new tenant, none of it by hand: claim, secrets, stack,
enable, key, then the tenant's first deploy through its slot.

Exit codes: 0 done, 1 refused (stderr `refused: WORD`), 2 usage, 3 another request is running,
4 a step failed (stderr `failed: STEP`, then the step's own message, cut to 1000 characters).
A refusal is a fixed word and never repeats the request (`judge-refused` adds the judge's rules,
above). Every request leaves one syslog line with
the verb, the slug and the result, and never a payload.

### Why a tenant set up by hand is never touched

`claim` writes a marker at `/etc/branchleft/tenant-entry/SLUG.json` (root, mode 0600) and refuses a
slug for which a marker, a claim, a secrets file, a stack directory or a deploy slot already exists.
Every later verb requires that marker. A tenant made by hand has none, so no verb can reach its
files, however well-formed the request.

### Where each secret goes

The `stack` verb reads the tenant's secrets file only to give it to the judge, which checks that the
stack asks for no secret the file lacks; the text is never written, printed or logged. A secret
reaches the stack only as a reference to its name (`${GHOST_NAME:?...}`), never as a value.

Values reach the secrets program on its stdin and the template reaches it as a file in the register
directory, which is deleted after the call. Neither is an argument or an environment variable. A
step's message is withheld whole if it repeats any value the request carried. The public key reaches
the slot program on stdin. The owner's address is read by the owner script from the secrets file,
never passed.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the two inputs, and Ansible checks them
when the role starts. Neither has a default (ANS-7): a host that is not told its controller key and
source addresses is not given any.

| Variable                    | Meaning                                                                                                                   |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `tenant_entry_key`          | The controller's public key: one ed25519 public key on one line. Hidden from logs.                                        |
| `tenant_entry_from`         | The source addresses the key may connect from: dotted IPv4 addresses or ranges from /24 to /32. An empty list is refused. |
| `tenant_entry_bind_address` | This host's own private IPv4 address (10/8, 172.16/12 or 192.168/16), where each tenant's ports are published.            |

Every path, the account name, the sudoers lines, the pinned ghost-platform commit and the digest are
in [`vars/main.yml`](vars/main.yml), where an inventory value cannot change them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, with `min_ansible_version` in `meta/main.yml`
  equal to it.
- The collections that come with the `ansible` package: `ansible.posix` for the key module.
- Target: Debian 13 with Python 3.13, `sudo` and `visudo`, and the program directory made by
  `tenant_onboarding` with its volume program in it.
- On the host when a request runs: the slot program at the path `deploy_slot_keys` installs it at,
  `systemctl`, and for `owner` the docker command (this role does not install it).
- To unpack node, `/usr/bin/xz` on the host when node has to be installed (`xz-utils`, a standard
  Debian package); the role stops by name when it is missing. The host must be `x86_64` or
  `aarch64`, the two builds with a pinned digest.

## What it changes on a host

- `/usr/local/sbin/branchleft-tenant-entry`: the program (`root:root`, `0755`).
- `/etc/branchleft/tenant-entry`: the register directory (`root:root`, `0700`).
- `/etc/branchleft/tenant-entry/bind-address`: the host's private address, one line (`root:root`,
  `0600`).
- `/root/platform-provision/render_tenant_secrets.py`: the secrets program, the pinned bytes
  (`root:root`, `0755`).
- `/root/platform-provision/provision-owner.mjs`: the owner script, the pinned bytes
  (`root:root`, `0644`), in the directory `tenant_onboarding` makes.
- `/usr/local/lib/branchleft-tenant-entry/node`: the node runtime, unpacked whole from the pinned
  tarball (`root:root`, `0755`); the program runs `bin/node` in it, never a node found on `PATH`.
  A different version, or no node, is put back whole: the directory is removed and unpacked
  again. The download goes through `/var/tmp/branchleft-tenant-entry-node.tar.xz`, removed after.
- `/usr/local/lib/branchleft-tenant-entry/tenant_compose_check.py`: the judge, a copy of
  `tenant_compose`'s module (`root:root`, `0644`, in a `root:root` `0755` directory).
- The account `tenant-entry`: a system account with a home, a real shell and a locked password. An
  password or shell that a person changed on it is put back by the next apply.
- `/etc/sudoers.d/tenant-entry` (`root:root`, `0440`), checked by `visudo -csf` before it replaces
  anything. Two lines: one keeps the request text through sudo, one grants this account the program
  with the one argument `--from-ssh`, as root, with no password. sudo matches a command with
  arguments exactly, so no other argument passes.
- The account's `authorized_keys`, exactly one line:

```text
restrict,from="ADDRESSES",command="sudo /usr/local/sbin/branchleft-tenant-entry --from-ssh" KEY
```

A request on a running host changes more, through the programs it calls: volumes, the uid claim, the
secrets file, the unit's enable link and the deploy slot. Those are the programs' changes and are
described in their own documents. The `stack` and `restack` verbs write one file itself, as root: the stack
directory `/opt/branchleft/SLUG` (`0755`) with `compose.yml` in it (`0644`), the names and modes
`tenant_compose` uses. It never writes `/etc/branchleft/SLUG.image.env`.

## How to test it

The program has unit tests with a fake host. From the repository root, with the tools installed as
`ansible/README.md` describes:

```text
cd ansible/roles/tenant_entry && PYTHONPATH=files ../../../.venv/bin/python -m unittest discover -b -s tests/unit
```

The harness runs lint, the container scenario and the rest:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/tenant_entry
```

The scenario fetches the secrets program from the network at its pinned commit. It stands in a
small volume program that keeps the claims it is given and a placeholder template unit, applies the
role, applies it again (no change), and then runs the real program, the real judge and the real
secrets program as root through sudo as the entry account, taking a fresh tenant through claim,
secrets, stack and enable with `status` after each. The Molecule scenario needs Docker; the unit
tests do not.

## How it is delivered

Delivery to a host is the gated workflow only (ANS-17): a plan in check mode, the approval of the
protected environment, a pull of that exact commit, and a second run that must report zero changes.
Nothing applies the role from a laptop. The controller's requests are not delivery: they are made
over SSH by the controller, with the key this role installs.

## Owner steps

The role is not yet in any host's playbook, and the key is not yet supplied. These are the owner's
because they live in files a role change may not edit (`ansible/checks/`, `ansible/trust/`,
`roles/host_inputs/`) or hold a value only a person holds.

1. **Add the role to the tenant app host.** Add `tenant_entry` to the host's list in
   `ansible/checks/host_roles/` and its playbook, after `tenant_onboarding` and `deploy_slot_keys`
   (the role reads their programs).
   _Done when:_ the plan lists the role's tasks for that host.
2. **Supply the controller's public key and its source addresses** to the host through the
   `host_inputs` row for this role.
   _Done when:_ the apply reports the key task changed and a second run reports no change.
3. **Prove it from the controller.** From the controller's account, ask for `status` of a slug that
   does not exist.
   _Done when:_ the answer is `claimed-here=no`, and a request with any other first word is
   refused with `refused: unknown-verb`.
4. **Run the penetration test the storage decision requires** before the first live tenant.

## How to change it safely

- A change to the program, the sudoers lines, the key options or the paths is a change to what a
  key may do as root. It is the owner's to merge (`.github/CODEOWNERS`).
- The program's paths are held equal to the roles that install the programs by
  `tests/unit/test_branchleft_tenant_entry.py`. Change a path in both places in one change.
- A bump of the ghost-platform pin moves the commit and the digest together, and the volume program
  at the new commit must still be the one `tenant_onboarding` pins, because the secrets program
  imports it.
- The port range (40000 to 40999) is reserved for tenants claimed through this program. A port
  assigned by hand must stay outside it.

## What the test proves

The unit tests run the real program against a temporary directory and fake programs, and each guard
has a case that goes red when the guard is removed:

- Hostile request text (a shell metacharacter, a second word, a path, an upper-case or non-ASCII
  slug, a newline, an unknown verb) is refused before any program or file is touched.
- A tenant claimed by hand, or any slug that exists on the host, is refused by every verb and its
  files are unchanged.
- A secrets file for another tenant, or a path outside the slot, cannot be asked for: the secrets
  program is always called with the request's own slug and the fixed directory.
- The service is not enabled, and the slot and owner steps do not run, before the secrets file is in
  place; the enable argument list never carries a start.
- A key that is not one plain ed25519 key (options in front, a second line, another type, a
  separator, a non-ASCII comment) is refused before the slot program runs.
- A value never reaches a program's argument list, the output or the log, and a program message that
  repeats one is withheld.
- A register directory or marker that is loose, a link or unreadable stops every verb.
- `stack` takes parameters only. A request that carries a compose text, an image pin or any key
  beyond `size`, `mail` and `environment` (a mount, a user, an entrypoint, a port) is refused by
  name; a value outside its schema is refused by its field; every value that passes is encoded, so
  the built file has the same keys whatever the parameters say. It writes nothing for a stack the
  judge refuses (a secret nobody supplies, a uid another tenant holds), for a slug that was never
  claimed here or whose secrets step is not done, and over no file that is not its own request's
  built text, a dangling link included. The same parameters again succeed and change nothing. A
  file that appears between the check and the write is not replaced. A stack root that is open to
  writes, or a stack directory that is a link or not a directory, is refused, and the directory a
  link pointed at stays empty. A failed write leaves no temporary file. It writes no pin, and a
  test pins the compose unit's assertion that a missing pin keeps the unit from starting. A judge
  that is not root's, is a link or is writable by another user is not loaded, and a judge message
  that repeats a secret is withheld.
- The judge file is a byte-identical copy of `tenant_compose`'s, and the stack paths and modes are
  those `tenant_compose` uses.
- The owner script and node are where the program looks for them (`owner_program`, `node`), the
  script is pinned to a full commit and a sha256, node's version and both digests are the ones
  `broker_deploy` pins (ANS-12: a copy, held equal), and neither node nor the script appears in a
  sudoers line or in the key options, so installing them gives the account nothing it did not have.

The container scenario then runs the real program through sudo as the entry account (a stand-in
Docker answers the owner verb: see "Named limits"): another mode,
an extra or doubled argument and another program are refused by sudo, hostile requests are refused
by word with nothing written, the account cannot read the register, a claim takes the first uid and
ports and writes a closed marker, and the later verbs refuse in order. It then runs a fresh tenant
through secrets, stack and enable, reads the file `stack` wrote (owner, mode, the uid, ports and
address in it, nothing else beside it, and no pin anywhere) and `status` after each step, and shows
the verb refusing by name: a stack the judge refuses, a request that carries a pin or a compose
text, a parameter that tries to add a mount or a user, a value that is a compose reference, a
name that tries to carry a key, a tenant never claimed, other parameters over the existing file (the
file unchanged), and a slot whose directory leads outside it (the directory outside left empty). The
same parameters again succeed.

## Named limits

- **The container is not the app host.** The scenario stands in the volume program and has no
  running systemd, no Docker and no slot program. The unit tests cover those calls with fakes. The
  first live request is the evidence for the rest.
- **The first pin is not written here.** It is `branchleft-deploy`'s, after the attestation check.
  Until the tenant's first deploy runs, an enabled unit stays inactive (no pin file). That deploy is
  the platform's own step (`first-deploy`), not this verb's.
- **The template is a copy of the renderer's posture, not the renderer.** It writes two Ghost
  colours with the platform's runtime controls and carries no verdict sidecar and no per-tenant
  limits beyond three sizes. A change to the renderer's posture is a change to
  `build_stack` here too; the two are held together by review, and the judge is the second lock.
- **`tenant_compose` and `stack` are two routes to the same file.** A tenant that is both stacked
  here and named in `tenant_compose_stacks` has its compose file replaced by that role's text on its
  next run; keep a tenant on one route.
- **The judge needs PyYAML on `/usr/bin/python3`.** The role refuses a host that lacks it (task
  `Refuse a host whose python3 has no PyYAML`), and the verb fails `judge-yaml-missing` if it is
  removed later.
- **The `owner` verb is untested against a live Ghost.** It calls the platform's owner script with
  checked arguments. The script's own tests are in ghost-platform. The scenario runs the real
  node and the real script, installed by the role, against the real secrets file, and gives them a
  stand-in Docker that lists one container and answers the script's inner program with the result a
  fresh Ghost gives. It shows the script is there, runs under the pinned node, reads the address
  from the secrets file and sends it only on stdin; it does not show a Ghost owner is made.
- **The owner script is pinned to a main commit, and node to a build.** A new script on
  ghost-platform's main is not picked up until the commit and digest are bumped together
  (`tenant_entry_owner_ghost_commit` and `tenant_entry_owner_program_sha256`). Node is the one
  version `broker_deploy` pins; a bump of one is a bump of both, and a test holds them equal.
- **No node means `program-missing`; no script means `failed: owner`.** The program names a node it
  cannot start `program-missing`. A node that runs and finds no script exits non-zero, and the
  program reports that step as `failed: owner` with node's own message. The scenario shows both,
  and that the role puts each back.
- **The role is in no host's list yet.** `tenant_entry` is not in `ansible/checks/host_roles/appt1.yml`
  or any playbook; adding it is the owner's merge (Owner steps, 1).
- **A port assigned by hand inside the reserved range is not seen.** The program knows only the
  ports it gave out.
- **A step that failed after its program changed the host is not undone.** `status` shows how far a
  slug got. A claim whose volume step failed, timed out, was terminated by SIGTERM or SIGHUP, or had
  an unreadable listing afterwards keeps its marker. The next `claim` for that slug settles it: a
  marker with a listed claim refuses `slug-in-use` (the claim stands; `status` reports
  `volumes=yes`), and a marker with no claim is removed and the claim is made again.
- **A marker is written whole or not at all.** The bytes go to a dot-named temporary file in the
  register, are synced, and are linked into place; a failed write leaves no marker and the slug is
  free for a retry.
- **Rotation is not here.** A secrets file that exists with different content, and a slot that
  exists, are refused; each is a separate step.

## Clauses this role exercises

ANS-2 (a typed program), ANS-7 (no default for either input), ANS-10 (check mode: the checks, the
fetches and the unpack are skipped there, with the reason in the task; the version probe is a read
and runs), ANS-11 (idempotence), ANS-12 (no role
imports another), ANS-14 (this README), ANS-15 (a container test), ANS-16 (`no_log` and `diff: false`
where a key passes) and ANS-17 (the gated pull).
