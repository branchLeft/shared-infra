---
title: 'How it works'
---

## From a hostname to a web server

The edge VM serves every public hostname through Caddy, with CrowdSec watching its access logs.
Neither is configured by hand. `sites.ts` lists each site: its hostnames, the private address and
port it is served from, and a request body ceiling. A renderer in `hetzner/edge/` reads that list
and writes the Caddy configuration and the CrowdSec acquisition files; a second renderer in
`hetzner/monitoring/` writes the probe targets the monitoring stack checks. Because both read one
list, a site cannot be served without being monitored, and a hostname cannot be defined in two
places that then drift apart.

The generated files are committed next to the code that generates them. A test re-renders them
from the registry and fails if the committed copy differs, so a hand edit is caught before it
ships.

## How an infrastructure change is applied

The Pulumi stacks (the mail host, the network and the estate) are applied by CI, not from a laptop.
When a merge to `main` touches a stack's own inputs, a `changes` job traces that stack's real
import graph, so an unrelated merge plans and applies nothing. For each affected stack:

1. A **plan** job runs `pulumi preview` and writes the result to the job summary.
2. A **guard** reads the plan. A script refuses any plan that deletes a Hetzner resource, and a
   spend gate classifies whether every change is free.
3. An **apply** job waits on an environment with an approval rule. A person reads the plan and
   approves it. Plans the spend gate reads as entirely free go to an environment that only the
   reviewer App can answer; any plan the gate cannot read goes to a human.
4. Only then does the apply run.

The guard catches the destructive class mechanically. The reviewer is there for the plan that is
green and still wrong.

## How a change reaches a host

Host configuration is Ansible, and it reaches a host by a pull that the host verifies itself.

{{< diagram >}}

- A pull request runs lint and the tests of the roles it changed. The merge queue runs lint and
  every role's tests, so what lands has been tested whole.
- A push to `main` starts the delivery workflow. It asks every host, in check mode, what the commit
  would change, then pauses on an environment for approval.
- On approval the workflow calls each host's `pull-trigger`. The trigger does the checking, not the
  workflow. It runs eight steps: validate the request; check the playbook is allowlisted and take a
  single-flight lock; fetch `main` only, from a read-only remote; refuse a commit that is not an
  ancestor of the fetched tip; refuse a commit older than the last one applied; verify the commit
  signature against the allowlisted signers; check the commit out into a fresh directory; and run
  `ansible-playbook` for this host only.
- It prints one summary line. A run that reports nothing left to change is the second pass that
  proves the apply converged.

Each host has one playbook and one signer file. An empty signer list means the host refuses every
run, which is the safe default for a host not yet enrolled.

## Who may change what

Some paths are owner-only, because they decide what is trusted: the checks and the harness, the
signer files, the pull trigger role, the Ansible runtime role, the lint floor and the dependency
pins. A change there needs the owner to merge it. The role skeleton, the roles themselves and the
patterns are ordinary reviewed code, tested by a harness that runs a role in a container, applies
it, runs it again to prove it changes nothing the second time, and verifies the result.
