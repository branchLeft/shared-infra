# check-crowdsec-hub-pin.py

The module docstring of `check-crowdsec-hub-pin.py` kept its summary paragraph; the rest of the narrative, usage notes and rationale is below, unchanged.

Usage:

```text
check-crowdsec-hub-pin.py
check-crowdsec-hub-pin.py --pinned-version v1.7.7
```

`hetzner/edge/stack/crowdsec/config.yaml.local` pins `cscli.hub_branch:
master` so a container start never depends on `version.crowdsec.net` being
reachable. Upstream's own `chooseBranch` only returns `master` for an
unpinned agent while the running version is upstream's newest release; once
a newer release ships, the unpinned choice becomes the version branch and
our pin keeps saying `master`, which then serves hub content authored for a
newer agent to this one. Nothing in this repository changes when that
happens -- the trigger is an upstream release -- so this is a scheduled,
independent check rather than a gate on any pull request: it must be able to
fail on its own without blocking anyone's merge, and a pull request here
must never depend on this endpoint being reachable.

This mirrors `chooseBranch`'s own three-way compare, not an approximation of
it: the pin is stale exactly when an unpinned cscli at the pinned version
would no longer choose `master`.

Exit status:

- `0` the pin is still correct (pinned version is upstream's newest, or
  ahead of it -- a pre-release image compared against a stable "latest")
- `1` the pin is stale: upstream has shipped something newer than the
  pinned image, so the master branch is now built for a newer agent
- `2` the check itself could not run: the image pin could not be found or
  parsed, or upstream's version endpoint could not be read -- kept
  distinct from 1 so a failed run's log says which one happened
