# test_runbook_rsync_commands.py

## Module overview

The runbooks' `rsync` commands must not carry workstation permissions onto a host.

`rsync -a` implies `-p`, `-o` and `-g`, and the last two take effect because the
receiving side is `root`. So a plain `rsync -av` reproduces the *workstation's*
file modes and uid/gid on the host — while every container in both stacks reads
its config through a bind mount **as the container-side user**, not as root.

That combination broke a real deploy. `prometheus.yml` is written by
`npm run render` (a Vitest file snapshot), which left it `0600` in one
workstation checkout. Git records `100644` and cannot see the difference — it
tracks only the executable bit — so the mode is invisible to review, to
`git status`, and to CI, which checks out its own copy at `0644`. `rsync -av`
copied `0600 uid=501 gid=20` onto the host and Prometheus, running as `nobody`,
crash-looped on `permission denied`.

Additionally, `rsync --no-owner --no-group` does not modify the ownership of
files that already exist on the receiving host. Files copied with incorrect
ownership must be corrected with an explicit `chown -R root:root` after the
rsync.

Nothing available to CI can observe a workstation's file modes, so the deploy
command itself has to be immune to them. That makes the command *shape* the
control, and this asserts the shape — the same reasoning, and the same
technique, as `RunbookScpCommandTests` in `test_branchleft_nat.py`.

## The placeholder and fixed-host checks

Moved here from the comment above `COMMAND_FENCE_LANGS` in the test module.

A command that looks copy-pasteable but silently is not breaks every
command that reaches it, in either of two ways: an unresolved placeholder
standing in for an address, or the real address pasted in its place. Both
are checked below, over the same fenced blocks: a committed file must not
carry a concrete operational value, and a pasteable command must not carry
an unsubstituted placeholder either. The fix in both directions is
threading the value through an environment variable, populated by a lookup
the operator runs.

The placeholder check does not scope by hostname or by where in the line
the placeholder sits. Both restrictions were tried and each left a gap: a
host-name scope misses a placeholder for a host it does not name, and an
assignment-shaped scope misses the identical placeholder used inline, or
assigned via `export`/`local`, or quoted. The property that actually makes
a placeholder wrong is simpler than either restriction: it reads as an
address (see `ADDRESS_WORD`) and nothing has substituted it. That is what
`address_placeholders` checks, independent of host, variable name, quoting
or position in the line.

Deliberately narrower than "no `<...>` anywhere in a fenced block" or "no
IPv4-shaped token anywhere in a fenced block":
- Only a `bash` fence counts as a command block in these runbooks —
  `json`, `text` and `yaml` fences hold illustrative sample output, and a
  `console` fence is a captured transcript (a `$ ` prompt plus what it
  printed, sometimes with a placeholder inside the printed command itself)
  rather than something pasted and run.
- The address word must be *trailing*, not merely present, so a resource
  id such as `<edge1-ipv4-id>` is left alone: a destructive deletion is
  deliberately worked by id, looked up fresh, rather than by a hardcoded
  literal that could be stale or simply mistyped.
- A token that legitimately varies per invocation (`<stack>`, `<host>`,
  `<repo>`, `<image>`, `<digest>`) is not address-shaped and never matches,
  whether it is an assignment's whole value or an argument inside a larger
  command (`hcloud server describe <host> -o json | ...` is the corrected
  form of the anti-pattern this file used to carry).
- The literal check below (`fixed_host_literals`) is a genuinely different
  property from the placeholder check, and stays separate: it matches only
  the *bare* form of a specific, known address, never a `/32` (a
  verification block reading real remote state renders one back that way)
  and never a CIDR. A threaded `$VARIABLE` reference holds no such literal
  and is never flagged, by construction.
