# mail_collector

This role installs the mail collector on `ops1`: the account it runs as, its directories, two
environment files of public values, and a systemd unit that runs the collector's digest-pinned
container image. The collector holds a drain connection to every host a descriptor names, submits
each drained message over authenticated SMTP, and acknowledges it back to the host's spool. It is
the one place that drains every host: a host no descriptor names is a host whose mail is never
collected.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role:

1. Checks that `docker`, `/etc/branchleft` and `/var/lib/branchleft` exist and are root's and that
   no one else can change them. It makes none of them (`host_inputs` and the roles before it do).
2. If the owner's credentials file is already on the host, checks that it is a regular file, root's
   and mode `0600`, and stops the run if it is not. It reads its owner and mode only, never its
   content and never a checksum of it.
3. Makes the system account `mail-collector` (no login, no home) and its group.
4. Makes `/etc/branchleft/mail-collector` (root's, `0755`), the descriptor directory inside it
   (root's, `0755`) and `/var/lib/branchleft/mail-collector` (the account's, `0700`, which holds
   the collector's persistent state) with its `pins` directory (the account's, `0700`).
5. Writes one descriptor into the descriptor directory for each host in `mail_collector_hosts`, and
   removes every other `.json` file there (see The drain list).
6. Writes `unit.env` (the image and the account's numeric ids) and, when the collector is meant to
   run, `collector.env` (the sending target and the drain surface's scheme and port). Both hold
   public values only.
7. Installs the unit `mail-collector.service` as a static file, then holds it enabled and started
   when the collector is meant to run and disabled and stopped when it is not.

The collector is **meant to run** only when `mail_collector_image` is a real digest (the default is
a placeholder of all zeros, which the role refuses to run) and `mail_collector_smtp_host` is set.
Either missing keeps it off, so landing the role changes nothing about what the host does until the
owner sets them.

The role does not place the credentials file (the owner does), does not pull the image ahead of the first start (Docker pulls it by digest when the
unit first runs), does not choose the sending target, and does not build the path from `ops1` to
any host's drain surface. See Named limits.

## Fail closed

A collector that cannot start is not a pass. The unit starts only when all three of these hold, each
a start condition, so an unmet one leaves the unit inactive and not failed:

- `collector.env` exists and is not empty: the image is real and a sending target is set;
- `credentials.env` exists and is not empty: the owner has placed the sending user and password,
  the drain token and the heartbeat URL;
- the descriptor directory holds a file: at least one host is named.

The last one matters. The collector pings its heartbeat only when every named host has completed a
cycle, and with no host named it withholds every ping by design ("zero hosts pages me"). Starting it
against a real heartbeat URL before a host is named is not what is meant, so the unit does not start
until a descriptor is there. Once running, removing the last descriptor does not stop it: it carries
on with an empty list and withholds its pings.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the inputs and Ansible checks them when
the role starts. The role refuses a malformed value before it changes anything, and its message
never names the value (ANS-16). None is a secret.

| Variable                     | Default                                                  | Meaning                                                            |
| ---------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------ |
| `mail_collector_image`       | `ghcr.io/branchleft/mail-collector@sha256:` and 64 zeros | The image the unit runs; a tag is refused; the zeros refuse to run |
| `mail_collector_smtp_host`   | empty                                                    | The sending target's host name; empty keeps the collector off      |
| `mail_collector_smtp_port`   | `587`                                                    | The submission port                                                |
| `mail_collector_smtp_secure` | `false`                                                  | `true` for implicit TLS, `false` for STARTTLS                      |
| `mail_collector_shim_scheme` | `http`                                                   | The scheme every host's drain surface is reached on                |
| `mail_collector_shim_port`   | `8080`                                                   | The port every host's drain surface is reached on                  |
| `mail_collector_hosts`       | `[]`                                                     | The hosts the collector drains, one entry each (The drain list)    |

`mail_collector_demo_mail_domain` is optional and empty by default. It is the platform's shared demo
mail domain, the one domain a demo host's header From may carry, and the role writes it as
`COLLECTOR_DEMO_MAIL_DOMAIN` only when set. Empty is the safe state while no demo host is named: the
collector then holds every demo host's mail, unsent and unacked, and logs `demo_mail_domain_not_set`
at start-up. When set it must be a bare domain, with no scheme, no at sign and no space, or the run
stops before anything changes. Once a demo host is in `mail_collector_hosts` it must be set, or the
run stops (The drain list): a demo host named with its mail silently held would look live and send
nothing.

The sending target is an input, not something the role decides. The owner sets these in a later
change, to the digest the collector's image workflow printed and attested.

The paths, the account and the unit's flags are constants in `vars/main.yml` and the unit file, not
inputs: an inventory value cannot move them.

An empty or malformed `mail_collector_image` stops the run at its first task, before anything
changes. The all-zero default is the one value that passes that check and is held off by the run
rule instead: the host's play carries the default, so stopping on it would fail every apply of the
host until the owner sets a digest.

## The drain list

The collector drains the hosts its descriptor directory names and no others, and nothing else names
a host. `mail_collector_hosts` is that list. Each entry holds exactly three keys, all public:

| Key           | Meaning                                                                    |
| ------------- | -------------------------------------------------------------------------- |
| `slug`        | The host's name: lowercase letters, digits and hyphens, unique in the list |
| `kind`        | `demo` or `tenant`                                                         |
| `app_host_ip` | The private IPv4 address the collector dials (10/8, 172.16/12, 192.168/16) |

For each entry the role writes `<slug>.json` (root's, `0644`) holding `slug`, `kind`, `appHostIp` and
`expiresAt`, which is always `null`: a host leaves the drain list by leaving this list, not by a
date. Then it removes every other `.json` file in the directory. A file that is not named `*.json`
is left alone, because the collector never reads one.

- **Why a role task.** The only route to ops1 is the gated apply (ANS-17), the values are public
  and a descriptor is a few lines of text, so a task that renders them from the repository adds no
  second delivery path, no credential and no new host-side program. A pull from another host would
  need a route and a key from ops1, and a file copied by hand would never track the list.
- **A removed host drops out.** Removing an entry removes its file at the next gated apply. The
  collector re-reads the directory every `COLLECTOR_DESCRIPTOR_REFRESH_MS` (5 seconds unless set)
  and drains only what it finds, so the host is dropped within one refresh period of that apply.
  The collector is not restarted for a descriptor change. Emptying the list empties the directory,
  and a running collector then withholds every heartbeat ping, which is the alarm.
- **No secret.** The argument spec refuses any key but the three, and the template names the four
  fields it writes and never iterates the entry, so there is nowhere for a token or a password to
  go. The address is the private one the estate already publishes in `addressPlan.ts`, or an alias
  on ops1 when the path to the host is a tunnel.
- **Refused before anything is written.** A key besides the three, a missing key, a slug that is not
  a plain lowercase name (so a file name cannot climb out of the directory), a kind that is not
  `demo` or `tenant`, an address that is not private IPv4, two entries with one slug, and a demo
  host while `mail_collector_demo_mail_domain` is empty each stop the run with the directory as it
  was. The message names the entry's place in the list, never a value.
- **Hand placement is replaced.** A descriptor put on ops1 by hand and not in the list is removed by
  the next apply. Put the host in the list instead.

## State that survives a restart

The collector keeps three things on disk, and with any one unset it keeps that thing in memory only
and a restart forgets it: the record of submitted messages, the per-message target pins and the
Sweego usage counters. `collector.env` sets all three, each under `/state`, the container's view of
the state directory the unit mounts read-write:

- `COLLECTOR_DEDUPE_STATE_PATH=/state/dedupe.json`, the record of submitted messages;
- `COLLECTOR_PIN_STATE_DIR=/state/pins`, the per-message target pins;
- `COLLECTOR_SWEEGO_USAGE_STATE_PATH=/state/sweego-usage.json`, the Sweego usage counters.

On the host these are under `/var/lib/branchleft/mail-collector`. The state directory and the pin directory are the account's, mode `0700`. A task refuses the run,
before anything changes, if any of the three is empty or is not under `/state`.

The collector writes marker files beside these (for the usage counters,
`sweego-usage.json.initialised`). They record that a file once existed, so that a lost volume is not
read as a fresh allowance. Clearing one is the owner's act, on the host, and this role never does it.

## The owner's credentials file

`/etc/branchleft/mail-collector/credentials.env`, root's, mode `0600`, one `NAME=value` per line, and
no other name:

| Name                      | What it is                                  |
| ------------------------- | ------------------------------------------- |
| `COLLECTOR_SMTP_USER`     | The sending account's user                  |
| `COLLECTOR_SMTP_PASS`     | The sending account's password              |
| `COLLECTOR_DRAIN_TOKEN`   | The bearer token every spool's drain checks |
| `COLLECTOR_HEARTBEAT_URL` | The dead-man's switch URL                   |

No role handles a value of these. The unit passes the file to the container with `--env-file`, read
by the Docker client as root; it is never mounted, and its path is the only thing in the unit that
names it.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Docker installed (the role asserts `/usr/bin/docker` and never installs it).
- `/etc/branchleft` made by `host_inputs`, which goes first on `ops1`, and `/var/lib/branchleft`.
- The image reachable from the host: the unit's first start pulls `ghcr.io/branchleft/mail-collector`
  by digest.

## What it changes on a host

| Path                                           | Owner     | Mode   | What                                                       |
| ---------------------------------------------- | --------- | ------ | ---------------------------------------------------------- |
| `/etc/branchleft/mail-collector`               | root      | `0755` | The directory of the files below                           |
| `/etc/branchleft/mail-collector/descriptors`   | root      | `0755` | One JSON file per host in `mail_collector_hosts`, no other |
| `.../descriptors/<slug>.json`                  | root      | `0644` | A host's descriptor: four public fields                    |
| `/etc/branchleft/mail-collector/unit.env`      | root      | `0644` | The image and the account's ids, public values             |
| `/etc/branchleft/mail-collector/collector.env` | root      | `0644` | The settings; absent while the collector is off            |
| `/var/lib/branchleft/mail-collector`           | collector | `0700` | The collector's persistent state, written by the collector |
| `/var/lib/branchleft/mail-collector/pins`      | collector | `0700` | The per-message target pins                                |
| `/etc/systemd/system/mail-collector.service`   | root      | `0644` | The unit                                                   |

It also makes the `mail-collector` account and group. It names, and never writes, the credentials
file.

## What the unit runs

`docker run --rm` of the pinned image, as the account's numeric id, with a read-only root
filesystem, every capability dropped, no new privileges, no published port and no network option.
Two bind mounts: the descriptor directory, read-only, and the state directory, read-write. Settings
come from the two `--env-file` flags and nothing else; the Docker socket and the host's other
directories are not mounted.

It restarts whatever the exit (`Restart=always`, ten seconds between tries) and has no start limit: a
collector that stays stopped is a host whose mail is never collected, so a limit that left it failed
after a burst would be the silent failure the unit is built against.

## How to test it

From the repository root, with the pinned tools installed as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/mail_collector
```

The role has unit tests. From `ansible/roles/mail_collector`:

```text
python -m unittest discover -b -s tests/unit -p 'test_*.py'
```

They hold the unit to its flags, mounts, start conditions and restart policy (and show the check
able to find each way the unit could be loosened), render both environment files and hold them to the
names the collector reads, hold the run rule (a real image and a sending host, or off), the order of
refusal before change, that the credentials file is never written, and the shapes of the image and
host. A second suite, `tests/unit/test_descriptors.py`, runs the role's own drain-list tasks with
Ansible on the machine that runs the tests, against a scratch directory (no host), and reads the
directory the way the collector reads it. It holds that a host missing from the list is missing from
the drain list until it is listed, that a host removed from the list leaves the drain list, that a
second run changes nothing, that a refused list leaves the directory as it was, and that a demo host
with no demo mail domain stops the run. The Molecule `default` scenario converges twice with the
inputs set, against stand-ins for `docker` and a made-up credentials file, with two hosts listed and
a stale descriptor and a note already in the directory, and checks the files, owners and modes, the
two descriptors, that the stale one is gone and the note is not, that the unit runs with the two env
files, and that the owner's file is left alone. The `inert` scenario converges at the defaults and
checks that nothing runs even with the credentials file in place, and that the hand-placed
descriptors are removed.

## How it is delivered

Delivery is the gated workflow only (ANS-17): a plan in check mode, the `ansible-hosts` approval, a
pull of that exact commit on the host, and a second run that must report zero changes. Nothing here
applies the role by hand, and nobody reads or carries a credential. Wiring the role to `ops1` is the
owner's merge, because the lists it edits are owner-merged paths (`ansible/checks/host_roles.yml`,
`.github/CODEOWNERS`). The first apply after that merge makes the account and directories, installs the
unit and leaves the collector off.

## How to change it safely

- A change to the unit, the mounts or the account is a change to who can read the sending credentials,
  so it gets the deep review and the owner's merge.
- Keep the collector's names equal: the names in `collector.env.j2` and in the credentials table are
  the ones the collector's own reader takes (a test holds the first).
- Bump the image only to a digest the collector's image workflow printed and attested.
- Never add an `--env` value, a published port, a network option, or a mount of the Docker socket,
  the credentials file or any other directory to the unit. The unit test names each.

## Named limits

- **No path to any host yet.** The role installs the collector; it does not build the tunnel or
  address that lets a container on `ops1` reach a host's drain surface. Until that exists every drain
  call is refused, a failed cycle, and the heartbeat is withheld. How the container reaches the
  address (bridge, or the host's network) is decided with that path, not here.
- **The list is the owner's input.** The role writes whatever `mail_collector_hosts` holds and
  nothing else; with the default empty list the directory is empty and the unit does not start.
  The addresses are the owner's to set, and the one for a host behind a tunnel is the tunnel's
  alias, which does not exist yet. A removal reaches the directory at the next gated apply, not
  at once.
- **The first start needs the image to be pullable.** The role does not pull ahead of the start. If
  the package is private the unit fails to start and the cause is the pull, not the role.
- **A condition is not an alarm.** A unit whose settings, descriptor or credentials are missing stays
  inactive without failing, so nothing pages on it from here. The heartbeat's silence does.
- **The test platform is a container with stand-ins.** It proves files, owners, modes and that the
  unit runs a command with the right arguments; it does not prove the collector drains or sends.
- **The state is not backed up by this role.** It lives in the state directory.
- **The dropped-recipient report needs the spool's opt-in.** The collector reports dropped recipients
  to each spool's `POST /drain/outcomes`, which a spool serves only with `SHIM_DRAIN_OUTCOMES=true` in
  its own environment; otherwise it answers 404 and the report does nothing. That setting belongs to
  the spool's environment, which this role does not render.

## Clauses this role exercises

ANS-7 (defaults mirror the spec), ANS-9 (no shell), ANS-10 (check mode), ANS-11 (idempotence),
ANS-12 (no role imports another), ANS-14 (this README), ANS-15 (a container test), ANS-16 (no value
in a message) and ANS-17 (the gated pull).
