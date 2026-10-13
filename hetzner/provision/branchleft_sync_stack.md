# branchleft_sync_stack.py

## What it is

`/usr/local/sbin/branchleft-sync-stack` installs one Compose stack's committed
files from a tar archive on stdin, then restarts that stack's unit if, and only
if, something changed. It exists so that `hetzner/monitoring/stack/` reaches
`edge1` from a gated workflow run (`.github/workflows/deliver-monitoring.yml`)
and not from a hand `rsync`.

`branchleft-deploy` cannot do this. It pins an image and restarts a stack, it
writes nothing under `/opt/branchleft/<stack>/`, and it refuses the monitoring
stack outright because that stack pins its images inline. The deploy account's
only sudo grant is that one binary, so no existing CI credential can write the
stack's files.

## The key is the boundary

The caller is one SSH key whose `authorized_keys` line forces the command
`/usr/local/sbin/branchleft-sync-stack monitoring` (`install-stack-sync.sh`
writes it). The stack name is in the forced command, so a client cannot choose
another stack, and `SSH_ORIGINAL_COMMAND` is never read. The key is on `root`,
which sshd already allows by key only (`00-harden-ssh.sh`), so no sudoers file
is edited. `restrict` removes forwarding and a terminal.

## What it does, in order

1. Reads the whole archive and validates it before touching the host. Only
   regular files and directories are accepted: a link, device or fifo, an
   absolute path, a `..` component or an unusual file name refuses the whole
   archive. Size, entry count and depth are bounded.
2. Requires the files a complete stack has (`compose.yml`, the Prometheus and
   Alertmanager inputs, the render script) and a final `END-OF-STACK` member.
   A stream cut off cleanly between two files is otherwise indistinguishable
   from a smaller stack, and the delete step would remove the rest.
3. Refuses an archive that carries a host-rendered file
   (`alertmanager/alertmanager.yml`, `ntfy/server.yml`,
   `prometheus/mx1-metrics-password`). Those hold secrets, are rendered on the
   host by `render_alertmanager_config.py` from `/etc/branchleft/monitoring.env`,
   and are never in the repository.
4. Notes whether the unit is enabled. A unit that is not enabled still gets its
   files, so the first delivery can precede first-time bring-up, but it is
   never started or restarted here and the output says `NOT RESTARTED`.
   Bring-up (RUNBOOK-monitoring.md step 7a) stays a runbook step.
5. Makes the directory match: files written through a temporary file and
   renamed, stale files and directories removed, host-rendered files left
   alone. Modes are set here (`0644`, `0755` for directories and for files the
   archive marks executable) and ownership is `root:root`; the archive's own
   modes and uids are ignored, which is what the runbook's
   `--no-owner --no-group --chmod=u=rwX,go=rX` was working around.
6. Restarts `branchleft-compose@monitoring.service` when step 5 changed
   anything, and exits non-zero if the restart fails, so the workflow run
   goes red. A second run with the same archive changes and restarts nothing.

Because the host-rendered files survive, the hand copy's problem (the render
being deleted, so a copy with no restart left the host without
`alertmanager.yml`) does not arise. The restart still regenerates them from the
current template and secrets, as before.

## Rehearsal

`branchleft-sync-stack --rehearse DIR monitoring` runs steps 1, 2, 3 and 5
against `DIR`, with no ownership change, no unit check and no restart. The
workflow and the pull-request job use it to prove an archive is accepted and
that a second sync of it changes nothing, with no host involved.

## What it does not protect

Anyone who can have this key used can install any `compose.yml` on `edge1`, and
the stack's Compose file mounts the host filesystem for its exporters. The key
is therefore root-equivalent on that host in effect, whatever the forced
command says. The control is where the key can be used: only the
`production-monitoring` environment holds it, that environment requires a
reviewer, and the workflow refuses any ref but `main`. The key is not on the
deploy account, which has no way to write files.

Drop-ins under `hetzner/monitoring/systemd/` and the SNDS collector units are
not delivered by this. They are not in `stack/`, they change rarely, and they
need `systemctl daemon-reload`, which is a different action from a stack
restart.
