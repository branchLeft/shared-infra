# `dockerHarness.ts` notes

The bounds, the slot rules and the limits left in place. Update this doc, not a
long comment block in that file, when any of them changes.

## What it is for

Tests that start a container (the live-Caddy check in `ghostSetup.test.ts`) run
inside a commit hook. The harness makes that hook fail in seconds with a message
when the Docker engine is silent, instead of holding the commit. It is a
hang-breaker, not a correctness control: it decides nothing about the thing the
test proves.

It does three things: a **probe** (`probeEngine`, `probeEngineSync`), a
**slot** (`takeSlot`: at most two Docker proofs at once on one machine) and
**cleanup** (a container is removed by its exact name on every exit path,
including an interrupt and process exit).

## The bound on one step

`docker image inspect`, `create` and `start` each run under one bound: **30
seconds by default**. Set `BRANCHLEFT_DOCKER_STEP_MS` (a whole number of
milliseconds, from 1000 to 2147483647, the largest delay a timer honours: a
larger one fires after 1 ms) to change it; anything else is ignored and the
default applies. The pull (120 s), the port read (15 s), the removal (10 s)
and the probe (10 s) have their own fixed bounds.

A silent step is not proof that the engine is wedged: an engine that is busy
can answer `docker info` and still take longer than the bound on a create or a
start. The failure says so, and names this variable. If the machine was busy,
re-run when it is idle or raise the bound; if it was not, report the engine as
wedged and do not retry in a loop.

`ghostSetup.test.ts` derives its setup timeout from the exported limits, so
raising the bound raises the hook's own timeout with it.

## Slots

A slot is a directory `slot-N` under `BRANCHLEFT_DOCKER_SLOTS` (default: a
directory under the temp dir), taken with an atomic `mkdir`; its `owner` file
reads `pid=<pid> <label>` and is created with `wx`, so a holder that was
reclaimed while suspended loses the slot instead of overwriting the owner file
of the session that took it.

- A slot whose owner names a **dead** process is reclaimed.
- A slot with **no owner file** (missing, or empty) is reclaimed once its
  directory is older than `ORPHAN_SLOT_AGE_MS` (10 seconds). The owner file is
  written within microseconds of the `mkdir`, so a younger directory is a
  holder still starting and is left alone. "No owner file" means the file is
  absent or empty; a file that exists and cannot be read is not that.
- A slot whose owner is in any other format, whose owner file cannot be read,
  or whose directory time cannot be told (it cannot be read, or lies in the
  future) is **never** reclaimed: the harness cannot tell whether that proof
  has finished. The failure names the slot and the `rm -r` that clears it
  (the path single-quoted for the shell), and says to run it only when no Docker
  proof is running.
- A slot that is stale but cannot be removed for want of permission fails at
  once with the same `rm -r` rather than waiting out the slot wait. A removal
  that fails because another session is clearing the same slot is looked at
  again on the next poll.
- When no slot frees within the wait, the failure lists every holder and gives
  only the advice that is true of it: wait (a running holder), re-run shortly
  (a young slot with no owner file), or clear it by hand (a holder naming no
  running process, or one that cannot be classified). The command, if any, is
  the last thing in the message.

## Limits left in place

None of these is a correctness failure of what a test proves: the worst
outcomes are leftover work and a duplicate slot holder. They are recorded so a
surprise is recognised.

- **Two sessions reclaiming the same stale slot at the same moment can both
  hold it. This reproduces; it is not rare under a deliberate collision.** The
  reclaim is a check and then a removal, not one atomic step: one session
  removes the slot and takes it, a second that read the old state removes that
  new directory and takes it too. It applies to both reclaim rules (a dead
  owner, and a slot with no owner file). Measured with a throwaway driver (not
  in the repository), eight worker processes released at one shared start
  time on a single stale slot (`max: 1`), each holding it 400 ms after taking
  it, 20 rounds, a round counted when two holders' hold intervals overlap;
  three runs of 20 rounds each for the code in this change, and three for the
  code it replaced:
  - an aged slot with no owner file: 5 or 6 of 20 rounds had two holders (the
    earlier code never reclaims this slot);
  - a slot whose owner is a dead pid: 9 to 17 of 20 rounds;
  - a dead-pid slot with the earlier code: 8 to 15 of 20 rounds, and in
    7 to 13 of the 160 workers a run `takeSlot` threw a raw filesystem error
    (`ENOENT` or `EINVAL` on the owner write, `ENOTEMPTY` on the removal),
    which the slot code now treats as "look again" (none were thrown in the
    runs of this change).

  The rates are for a worst-case burst released on one start time, not for
  ordinary use (two proofs a commit hook starts at different moments). A
  fix would be an atomic claim: rename the stale directory to a name only the
  claimer holds, then remove it. It is left until it shows up in practice.

- **A holder suspended for more than 10 seconds between its `mkdir` and its
  owner write is reclaimed while alive.** It then loses the slot (the owner
  write is exclusive) and takes another or waits; it no longer overwrites the
  new holder. The window is microseconds in ordinary running and needs a stall
  (a stopped process, a frozen VM) at exactly that point.
- **A SIGKILL of the worker process itself is unhandled, and nothing ends the
  docker client afterwards.** No handler can run and the deadline timer dies
  with the worker. Measured with a client that never answers under a 30 s
  bound, the worker killed 1.5 s in: the client was still alive 2, 20, 35 and
  45 seconds after the kill. It lives until the engine answers it or restarts.
  A container the run had created but not started is not removed by the
  harness either: remove it by hand with `docker rm -f -v <name>` (the live
  check's containers carry the label
  `branchleft.agent=edge-ghost-setup-test`, so
  `docker ps -a --filter label=branchleft.agent=edge-ghost-setup-test` lists
  them).
- **A SIGINT or SIGTERM sent to the test runner's main process alone orphans
  the worker and its docker client.** The review recorded that they are
  cleaned up when the step deadline expires (30 seconds by default); that was
  not re-measured here, and the SIGKILL case above shows that a deadline is
  only as good as the process that still holds its timer.
- **A slot path that cannot be classified is left for a human.** A directory
  time in the future (clock skew), a dangling symlink named `slot-N`, an owner
  file that cannot be read, or an owner in another format is never reclaimed
  and is reported with its `rm -r`. The slot wait runs out before anything
  changes, which is the intended refusal, not a hang.

## Why not a library

A container library (dockerode, testcontainers) would still need a configured
request timeout and this harness's own slot, probe and cleanup logic, so it
would not remove the need for it.
