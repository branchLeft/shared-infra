# mx1_abuse_page

This role installs the program and timer that page the owner's phone when a report reaches abuse@
on the mail host, and keeps them off until the host has been given its publish-only pager token.
It follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

Every minute a systemd timer starts a one-shot service, which runs a small program as root. The
program asks Stalwart on loopback which messages abuse@ holds (ids only, never a header, sender or
body), compares them with the ids it saw last time, and, when one is new, posts one fixed notice to
the pager's abuse topic with the mail host's publish-only token. The notice names only that an
abuse report arrived: no sender, no message text, no tenant. Several new messages in one minute
page once. The first run after install records the mailbox as it stands and pages nothing, so
installing it does not page for old mail.

The role installs the program (after the program's own `--check`), the service and the timer,
makes the directories they use, writes the token file when a token is given, and holds the timer
enabled and started when the host has a token and disabled and stopped when it has none.

It does not make a token, choose where one comes from, read mail, change the mailbox or its
forwarding script, touch Stalwart's settings, or start a run. It never reads the token file.
The page's title and message are ALL_CAPS placeholders in the program (`PAGE_TITLE`,
`PAGE_MESSAGE`): the words are the owner's.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares one optional input, which has no
default (the loader leaves an absent input unset, and a row input may not have one): the role
reads it through `mx1_abuse_page_token_value` in `vars/main.yml`.

| Variable               | Default | Meaning                                                               |
| ---------------------- | ------- | --------------------------------------------------------------------- |
| `mx1_abuse_page_token` | none    | The publish-only ntfy token, the value of `NTFY_MX1_TOKEN` (`no_log`) |

The token is a secret. It reaches the role from the host's private inputs file through the
`host_inputs` loader (the optional input `mx1_abuse_page_token` of mx1's row), is never given a
default, and every task that handles it has `no_log: true` and `diff: false` (ANS-16). A value of
only spaces, or one with a line break, is refused before anything is written. The paths, unit
names and the key name are constants in `vars/main.yml`, so an inventory cannot move them.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; `min_ansible_version` is that
  version and the harness checks it. No collections beyond `ansible.builtin`.
- Debian 13 with Python 3 and systemd, as root. The program uses the standard library only.
- Stalwart answering on loopback and `/root/.stalwart-admin-credentials` (`user:secret`, root,
  mode 0600), made by the owner's one-time mail bootstrap. Without it the program fails and says so.
- The pager must list the host's token: the `ntfy_pager` role writes it on the monitoring host
  from the same value (its optional input `ntfy_pager_mx1_token`), and the pager grants it
  publish-only access to the abuse topic and nothing else.

## What it changes on a host

- `/etc/branchleft` and `/var/lib/branchleft` (root, `0755`) when absent, `/opt/branchleft/abuse-page`
  (root, `0755`) holding `branchleft_abuse_page.py` (root, `0755`), and `/var/lib/branchleft/abuse-page`
  (root, `0700`), where the program keeps the ids it last saw.
- `/etc/systemd/system/branchleft-abuse-page.service` and `.timer` (root, `0644`), and a reload of
  systemd when either changes.
- `/etc/branchleft/mx1-abuse-page.env` (root, `0600`) with the one line `NTFY_MX1_TOKEN=...` when a
  token is given, and removes it when none is.
- The timer: enabled and started with a token, disabled and stopped without one.

The service is conditioned on the token file (`ConditionPathExists`), so a host without it
starts nothing and the unit stays inactive instead of failing every minute. It runs with
`ProtectSystem=strict` and one writable path, its state directory, `NoNewPrivileges`, a private
`/tmp`, the kernel and cgroup protections, and only IPv4 and IPv6 sockets. `ProtectHome=read-only`
because the administrator credential it reads is under `/root`.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes:

```text
.venv/bin/python -m unittest discover -b -s ansible/roles/mx1_abuse_page/tests/unit -p 'test_*.py'
cd ansible/roles/mx1_abuse_page && ../../../.venv/bin/mypy --strict files tests/unit
.venv/bin/python ansible/harness/run_harness.py ansible/roles/mx1_abuse_page
```

The unit tests run with no network and no Stalwart: a fake answers JMAP and the pager and records
every request, so a test says what was asked of whom, what was written, and that nothing of a
message left the host. The harness lints the role and runs its Molecule scenario on one systemd
container: files and modes, the token file's exact content, the timer on with a token and off
without one, the service's condition and confinement, three refused tokens that must leave the
file untouched, and a scan of the run's log, which must hold the control canary and no token.

## How it is delivered

Only the gated workflow applies this role (ANS-17). mx1 is on the owner's never-list, so every
plan and apply for it is the owner's to read and approve. The host's inputs file must exist
before the first plan can pass the loader: the owner places it with
`seed_host_inputs.py --host mx1` (see `ansible/tools/README.md`).

## How to change it safely

1. The page's words are the owner's: replace `PAGE_TITLE` and `PAGE_MESSAGE` only with text the
   owner wrote, and never add a sender, a subject, a body or an address to them or to the request.
2. The program asks for ids only. A change that asks Stalwart for any other property of a message
   fails `test_nothing_of_a_message_is_asked_for_only_its_id`.
3. The program's paths and the role's constants must stay equal; the unit tests pin them.
4. Keep every task able to run under `--check --diff`, and `no_log: true` and `diff: false` on every
   task that handles the token.

## Named limits

- **Failures are not paged.** A poll that fails (Stalwart down, the pager unreachable, a
  refused token) exits non-zero and the unit shows as failed; nothing raises an alert for a stale
  poll yet. A page is lost only while polls keep failing, and the next success pages for what
  arrived meanwhile, because the state is kept.
- **A page sent and a state write that then fails pages again** on the next run (exit code 3).
- **Up to about a minute of delay,** the timer's period, plus the pager's own latency.
- **The Stalwart calls are proved against a stand-in,** not a live Stalwart. The first live run
  is the proof: the owner sends a test message to abuse@ and reads the page on the phone.
- **Only the newest 200 messages are looked at.** A burst larger than that still pages once.
- **The first run records, it does not page.** A report that arrives between the apply and the
  first run is missed; the owner's test message is sent after the first run.
