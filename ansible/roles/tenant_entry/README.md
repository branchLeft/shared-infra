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
- the tenant secrets program, fetched from ghost-platform at one pinned commit.

It does not run the program. A request is made over SSH by the controller, never by Ansible.

It does not install the programs the entry point calls. The volume program and its name register
come from `tenant_onboarding`, the slot program from `deploy_slot_keys`, and the compose file and
the deploy wrapper from `tenant_compose` and `deploy_tooling`. This role reads that they are there
and fails closed, naming the program, when one is not. It never writes a compose file, because every
line of that file is an isolation control that the renderer owns and `tenant_compose` judges.

It does not mint, store or print a key or a secret. The controller's public key is the role's one
input. The role adds itself to no playbook (see "Owner steps").

## What the program accepts

The request is `VERB SLUG` in `SSH_ORIGINAL_COMMAND`, two words and nothing else. A verb that needs
more reads one JSON object on stdin, at most 64 KiB, whose keys are exactly the ones named here. The
slug must match the volume program's own rule (a lower-case letter first, then letters, digits and
hyphens, 26 characters at most); the volume program stays the authority on reserved names.

| Verb      | Stdin                                      | What it does                                                                                                                                                                                                                                                        | Needs first             |
| --------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `status`  | none                                       | Reports how far one slug has got. A slug this entry point never claimed reports only that.                                                                                                                                                                          | nothing                 |
| `claim`   | none                                       | Takes the lowest free uid in 30000 to 30999 and the first free block of four ports from 40000, writes the slug's marker, and asks the volume program to make the volumes and claim the uid. Prints the uid and the three ports (colour a, colour b, health router). | the slug exists nowhere |
| `secrets` | `template`, `values`                       | Writes the template to a closed temporary file and passes the values on the secrets program's stdin. The program writes the tenant's secrets file.                                                                                                                  | `claim`                 |
| `enable`  | none                                       | Enables the tenant's compose unit, never starts it: the unit has no image pin until its first deploy.                                                                                                                                                               | `secrets` file in place |
| `key`     | `public_key`                               | Grants the slug's deploy slot to one ed25519 public key through the slot program, once. A slot that exists is never replaced.                                                                                                                                       | `enable`                |
| `owner`   | `colour`, `name`, `site_url`, `site_title` | Finds the running colour's container and runs the platform's own owner script, so the Ghost owner exists before the hostname is served.                                                                                                                             | `enable`                |

The order is enforced by the program, not by the caller: a later verb on a slug that has not passed
the earlier step is refused by name (`secrets-first`, `enable-first`). The secrets file is in place
before the service is named, because the reverse aborts the whole stack.

Exit codes: 0 done, 1 refused (stderr `refused: WORD`), 2 usage, 3 another request is running,
4 a step failed (stderr `failed: STEP`, then the step's own message, cut to 1000 characters).
A refusal is a fixed word and never repeats the request. Every request leaves one syslog line with
the verb, the slug and the result, and never a payload.

### Why a tenant set up by hand is never touched

`claim` writes a marker at `/etc/branchleft/tenant-entry/SLUG.json` (root, mode 0600) and refuses a
slug for which a marker, a claim, a secrets file, a stack directory or a deploy slot already exists.
Every later verb requires that marker. A tenant made by hand has none, so no verb can reach its
files, however well-formed the request.

### Where each secret goes

Values reach the secrets program on its stdin and the template reaches it as a file in the register
directory, which is deleted after the call. Neither is an argument or an environment variable. A
step's message is withheld whole if it repeats any value the request carried. The public key reaches
the slot program on stdin. The owner's address is read by the owner script from the secrets file,
never passed.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the two inputs, and Ansible checks them
when the role starts. Neither has a default (ANS-7): a host that is not told its controller key and
source addresses is not given any.

| Variable            | Meaning                                                                                                                   |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `tenant_entry_key`  | The controller's public key: one ed25519 public key on one line. Hidden from logs.                                        |
| `tenant_entry_from` | The source addresses the key may connect from: dotted IPv4 addresses or ranges from /24 to /32. An empty list is refused. |

Every path, the account name, the sudoers lines, the pinned ghost-platform commit and the digest are
in [`vars/main.yml`](vars/main.yml), where an inventory value cannot change them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, with `min_ansible_version` in `meta/main.yml`
  equal to it.
- The collections that come with the `ansible` package: `ansible.posix` for the key module.
- Target: Debian 13 with Python 3.13, `sudo` and `visudo`, and the program directory made by
  `tenant_onboarding` with its volume program in it.
- On the host when a request runs: the slot program at the path `deploy_slot_keys` installs it at,
  `systemctl`, and for `owner` the docker command, node and the platform's owner script.

## What it changes on a host

- `/usr/local/sbin/branchleft-tenant-entry`: the program (`root:root`, `0755`).
- `/etc/branchleft/tenant-entry`: the register directory (`root:root`, `0700`).
- `/root/platform-provision/render_tenant_secrets.py`: the secrets program, the pinned bytes
  (`root:root`, `0755`).
- The account `tenant-entry`: a system account with a home, a real shell and a locked password. An
  existing account is judged, never changed.
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
described in their own documents.

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
small volume program that keeps the claims it is given, applies the role, applies it again (no
change), and then runs the real program as root through sudo as the entry account.

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
4. **Place what the `owner` verb needs.** The owner script from ghost-platform and node are not
   installed by any role yet; until they are, `owner` fails closed with `failed: program-missing`.
5. **Run the penetration test the storage decision requires** before the first live tenant.

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

The container scenario then runs the real program through sudo as the entry account: another mode,
an extra or doubled argument and another program are refused by sudo, hostile requests are refused
by word with nothing written, the account cannot read the register, a claim takes the first uid and
ports and writes a closed marker, and the later verbs refuse in order.

## Named limits

- **The container is not the app host.** The scenario stands in the volume program and has no
  systemd, no Docker and no slot program. The unit tests cover those calls with fakes. The first
  live request is the evidence for the rest.
- **The program does not write the compose file.** Delivery of that file stays with `tenant_compose`.
  A controller that needs the file delivered per tenant needs that route first.
- **The `owner` verb is untested against a live Ghost.** It calls the platform's owner script with
  checked arguments. The script's own tests are in ghost-platform.
- **A port assigned by hand inside the reserved range is not seen.** The program knows only the
  ports it gave out.
- **A step that failed after its program changed the host is not undone.** `status` shows how far a
  slug got, and a claim whose volume step failed after taking a uid keeps its marker.
- **Rotation is not here.** A secrets file that exists with different content, and a slot that
  exists, are refused; each is a separate step.

## Clauses this role exercises

ANS-2 (a typed program), ANS-7 (no default for either input), ANS-10 (check mode: the checks and
the fetch are skipped there, with the reason in the task), ANS-11 (idempotence), ANS-12 (no role
imports another), ANS-14 (this README), ANS-15 (a container test), ANS-16 (`no_log` and `diff: false`
where a key passes) and ANS-17 (the gated pull).
