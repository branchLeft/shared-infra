# probe-project-isolation.py

The module docstring of `probe-project-isolation.py` kept its summary paragraph; the rest of the narrative, usage notes and rationale is below, unchanged.

Usage (tokens are read from the environment and never printed):

    read -rs HCLOUD_PROBE_TOKEN_MAIL; export HCLOUD_PROBE_TOKEN_MAIL
    ... one per project: MAIL, ORG, TENANTS, DEMOS, DNS, BACKUP, DEMO_DNS
    probe-project-isolation.py                           # the 7x7 proof
    probe-project-isolation.py --control-swap tenants=demos

**Why a denial alone proves nothing.** The Cloud API is implicitly scoped to
the token's project, so "token A cannot see project B" and "token A is broken,
expired, or pointed at an empty project" produce the same empty answer. Every
negative cell here is therefore paired with a positive one taken by the same
instrument:

- **Listing.** Each token must list its own project's marker firewall (the
  positive), and must not list any other project's marker or known server.
- **Real hosts.** The mail token must also list and fetch by id `mx1`, and
  the org token `edge1`, so the positive is tied to the production project
  and not only to a firewall someone created by hand.
- **By id.** Each marker is fetched by id with its own token, which must
  return 200 and the marker's name. Every other token fetching that same id
  must return 404 `not_found`. The 200 is what makes the 404 mean "a different
  project", rather than "this path never works".

**The control case.** `--control-swap tenants=demos` evaluates the tenants
row with the demos token. A working probe must report FAIL for it, and
specifically must mark the tenants row REACHES ACROSS in the demos column: the
demos marker is listed and fetched by that token. A FAIL for any other reason
-- the tenants marker missing, say -- does not count, because a probe whose
cross-reach check is broken would still produce that one. The control exits
0 only when it saw the reach.

Exit codes: 0 PASS (or a control that failed as required), 1 FAIL (or a control
that passed), 2 the probe could not run -- a transport error, a refused token,
or a malformed response. 2 is never read as isolation.

Only GET requests are issued, so a "Read" token is enough. The project table
below is a copy of `hetzner/projects.ts`; `test_probe_project_isolation.py`
fails if the two differ.
