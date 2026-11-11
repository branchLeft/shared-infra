# safety_service

This role installs the content-safety service on `ops1`: the account it runs as, two directories,
its configuration, and a systemd unit that runs the service's digest-pinned container image. The
service dials each host it is configured for, takes the perceptual hashes the host has queued,
asks the hash source about them, and returns a verdict for each. A host holds no credential for
the hash source and never dials the service.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role:

1. Checks that `docker`, `/etc/branchleft` and `/var/lib/branchleft` exist and are root's and that
   no one else can change them. It makes none of them (`host_inputs` and the roles before it do).
2. Makes the system account `content-safety` (no login, no home) and its group.
3. Makes `/etc/branchleft/safety-service` (root's, `0755`) and `/var/lib/branchleft/safety-service`
   (the account's, `0700`, which holds the audit trail).
4. Writes the environment file (the image and the account's numeric ids) and, when the service is
   meant to run, the configuration (`config.json`). Both hold public values only.
5. Installs the unit `content-safety.service` as a static file, then holds it enabled and started
   when the service is meant to run and disabled and stopped when it is not.

The service is **meant to run** only when both `safety_service_arachnid_base_url` and
`safety_service_hosts` are set. Either empty keeps it off, so landing the role changes nothing
about what the host does until the owner sets them.

The role does not write the channel signing key (`safety_channel_key` makes it), does not place the
hash-source credential (the owner does, into `/etc/branchleft/content-safety/arachnid-credential`,
and no role handles its value), does not
pull the image ahead of the first start (Docker pulls it by digest when the unit first runs), and
does not decide which hosts are dialled (that is the owner's input below).

## Fail closed

A service that cannot answer is not a pass, and the host end holds an upload that has no verdict.
This role keeps its half of that: the unit does not start unless the configuration, the signing key
and the hash-source credential are all on the host (three `ConditionPathExists` lines, so a missing
one leaves the unit inactive and not failed), the service refuses to start without its credential,
and a role run that holds the service off never writes the configuration. Nothing in the role
makes a host see "allow" for want of an answer.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the three inputs and Ansible checks
them when the role starts. The role refuses a malformed value before it changes anything, and its
message never names the value (ANS-16). None is a secret.

| Variable                           | Default                                        | Meaning                                                          |
| ---------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------- |
| `safety_service_image`             | the attested build, `...content-safety@sha256` | The image the unit runs; a tag is refused                        |
| `safety_service_arachnid_base_url` | empty                                          | The https origin of the hash source; empty keeps the service off |
| `safety_service_hosts`             | empty list                                     | Hosts to dial, each `{id, kind, endpoint}`; empty keeps it off   |

The image default is the digest the content-safety repository's image workflow printed for the
build that carries the verdict channel. A bump is a change to that one line and is the owner's
merge, as the whole role is. The origin and the hosts are set in a later change by the owner; the
role holds their shapes (`vars/main.yml`) and takes no other.

The paths, the account and the unit's flags are constants in `vars/main.yml` and the unit file, not
inputs: an inventory value cannot move them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Docker installed (the role asserts `/usr/bin/docker` and never installs it).
- `/etc/branchleft` made by `host_inputs`, which goes first on `ops1`, and `/var/lib/branchleft`.
- The hosts' endpoints reachable from `ops1` over https, and the image reachable from the host:
  the unit's first start pulls `ghcr.io/branchleft/content-safety` by digest.

## What it changes on a host

| Path                                         | Owner   | Mode   | What                                                |
| -------------------------------------------- | ------- | ------ | --------------------------------------------------- |
| `/etc/branchleft/safety-service`             | root    | `0755` | The directory of the two public files below         |
| `/etc/branchleft/safety-service/config.json` | root    | `0644` | The service's configuration; absent while it is off |
| `/etc/branchleft/safety-service/service.env` | root    | `0644` | The image and the account's ids, public values      |
| `/var/lib/branchleft/safety-service`         | service | `0700` | The audit trail, written by the service             |
| `/etc/systemd/system/content-safety.service` | root    | `0644` | The unit                                            |

It also makes the `content-safety` account and group. It names, and never writes, the key and the
credential in `/etc/branchleft/content-safety`.

## What the unit runs

`docker run --rm` of the pinned image, as the account's numeric id, with a read-only root
filesystem, every capability dropped, no new privileges, no published port and no network option
(the service only dials). Three bind mounts: the configuration directory and the key and
credential directory, both read-only, and the state directory, read-write. The only variable passed
into the container names the configuration file. The Docker socket, the host's other directories
and the environment file are not mounted.

## How the credential and the key reach the service

The signing key is made on the host by `safety_channel_key`, as root's file. The service runs as
the `content-safety` account and cannot read a root-owned key, so before the service is turned on
the owner sets `safety_channel_key_owner` and `safety_channel_key_group` to `content-safety` in a
later change, and the key role adopts the existing key to that owner without touching its bytes.
That change waits for the first apply of this role, because the key role refuses an account the
host does not yet have, and that includes the plan. This role goes before the key role in the
playbook so the account exists when the later change reaches it. The hash-source credential is placed by the owner in
`/etc/branchleft/content-safety/arachnid-credential`, owned by the account and not readable by
group or others, which the service enforces. Until both exist the unit does not start. After the
owner places the credential, the next gated apply starts the unit, because the role converges it to
started on every run.

## How to test it

From the repository root, with the pinned tools installed as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/safety_service
```

The role has unit tests. From `ansible/roles/safety_service`:

```text
PYTHONPATH=files:library python -m unittest discover -b -s tests/unit -p 'test_*.py'
```

They hold the unit to its flags and mounts (and show the check able to find each way the unit could
be loosened), render the configuration and the environment and hold them to the keys the service
reads, hold the key and credential paths equal to the key role's, hold the run rule (both inputs
or off), the order of refusal before change, and the shapes of the image, origin and host id. The
Molecule `default` scenario converges twice with the inputs set, against stand-ins for `docker` and
the key and credential, and checks the files, owners and modes, that the unit runs, and that a
file of another role is left alone.

## How it is delivered

Delivery is the gated workflow only (ANS-17): a plan in check mode, the `ansible-hosts` approval, a
pull of that exact commit on the host, and a second run that must report zero changes. Nothing here
applies the role by hand, and nobody reads or carries the key or the credential.

Wiring the role to `ops1` is the owner's merge, because the lists it edits are owner-merged paths
(`ansible/checks/host_roles.yml`, `.github/CODEOWNERS`). The first apply after that merge makes the
account, installs the unit and leaves the service off; the key stays root's until the later change
named above.

## How to change it safely

- A change to the unit, the mounts or the account is a change to who can read the hash-source
  credential and the signing key, so it gets the deep review and the owner's merge.
- Keep the pins equal: the key and credential paths and the directory with the key role's
  constants (a test holds them), and the keys of the configuration with the service's own reader.
- Bump the image only to a digest the content-safety image workflow printed and attested.
- Never add an environment value, a published port, a network option, or a mount of the Docker
  socket or any other directory to the unit. The unit test names each.

## Named limits

- **The first start needs the image to be pullable.** The role does not pull ahead of the start.
  If the package is private the unit fails to start and the cause is the pull, not the role.
- **A condition is not an alarm.** A unit whose key or credential is missing stays inactive without
  failing, so nothing pages on it. The service's own health is another change's alerting.
- **The test platform is a container with stand-ins.** It proves files, owners, modes and that the
  unit runs a command with the right arguments; it does not prove the service answers a host. That
  is the content-safety repository's channel tests, and the first real run.
- **The audit trail is not backed up by this role.** It lives in the state directory.
- **The check-mode plan on a fresh host** cannot show the environment file, which needs the
  account's ids, so it prints only the account and directories it would make.

## Clauses this role exercises

ANS-7 (defaults mirror the spec), ANS-9 (no shell), ANS-10 (check mode), ANS-11 (idempotence),
ANS-12 (no role imports another), ANS-14 (this README), ANS-15 (a container test), ANS-16 (no
value in a message) and ANS-17 (the gated pull).
