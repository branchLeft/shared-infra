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
milliseconds, at least 1000) to change it; anything else is ignored and the
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
reads `pid=<pid> <label>`.

- A slot whose owner names a **dead** process is reclaimed.
- A slot with **no owner file** (or an empty one) is reclaimed once its
  directory is older than `ORPHAN_SLOT_AGE_MS` (10 seconds). The owner file is
  written within microseconds of the `mkdir`, so a younger directory is a
  holder still starting and is left alone.
- A slot whose owner is in any other format is **never** reclaimed: the
  harness cannot tell whether that proof has finished. The failure names the
  slot and the `rm -r` that clears it, and says to run it only when no Docker
  proof is running.
- When no slot frees within the wait, the failure lists every holder and gives
  only the advice that is true of it: wait (a running holder), re-run shortly
  (a young slot with no owner file), or clear it by hand (a holder naming no
  running process).

## Limits left in place

None of these is a correctness failure: the worst outcomes are a few seconds of
leftover work and a duplicate slot holder. They are recorded so a surprise is
recognised. Each is fixed when it shows up in practice, not before.

- **Two sessions reclaiming the same dead slot at the same moment can both
  hold it.** The reclaim is a check and then a removal, not one atomic step.
  Reading the age immediately before the removal narrows the window for a slot
  with no owner file; it does not close it. Read from the code; repeated runs
  of eight concurrent workers did not reproduce it.
- **A SIGKILL of the worker process itself is unhandled.** No handler can run,
  so the container and the docker client it started are left until the step
  deadline (30 seconds by default).
- **A SIGINT or SIGTERM sent to the test runner's main process alone orphans
  the worker and its docker client.** They are cleaned up at the step
  deadline (30 seconds by default).

## Why not a library

A container library (dockerode, testcontainers) would still need a configured
request timeout and this harness's own slot, probe and cleanup logic, so it
would not remove the need for it.
