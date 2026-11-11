# Publish edge Caddy workflow pin tests

`scripts/test_publish_edge_caddy.py` pins `.github/workflows/publish-edge-caddy.yml`,
the workflow that builds and pushes the production edge image. It holds a
registry-write credential, so what it refuses matters more than what it does.
Every pin is a check on the parsed workflow, never a search of its text.

The workflow is read with the strict loader from `test_workflow_concurrency.py`
(duplicate keys, merge keys and explicit tags are refused), not a second parser.
A missing job, step or key is a reported problem, never a pass.

`problems(text)` is the whole set of pins. It returns a list, so the mutation
tests can feed it a damaged copy of the file. Full-line comments inside a `run:`
body are ignored when a step is checked, so a pin written in a comment does not
satisfy it.

## PublishEdgeCaddyPinTests

The real workflow holds every pin:

- the trigger set is exactly `workflow_dispatch`, with one required string
  input, `revision`;
- the top-level permission is `contents: read` and only the one job holds
  `packages: write` (with the `contents: read` its checkout needs);
- every `uses:` is a 40-hex commit with a `# vX.Y.Z` comment, and the only
  actions are checkout and `docker/login-action`, so no QEMU or buildx setup;
- the job runs only from `main`: the job-level `if:` and a first step that fails
  on any other ref;
- the login uses `secrets.GITHUB_TOKEN` and no other secret is named anywhere;
- the revision reaches the shell only through `env:`, and no `${{` appears in
  any `run:` body;
- no `latest` tag, no `--platform`, no `qemu`, no `buildx`, and no copy of the
  module assertion (`list-modules`): the Dockerfile stays the one place that
  proves the modules are built in;
- a timeout, `persist-credentials: false`, a literal job concurrency group that
  never cancels, and the repository's own concurrency rules;
- the step order is fixed, so a refusal cannot slip behind the push it guards.

## PublishEdgeCaddyMutationTests

A pin that cannot fail protects nothing. Each mutation damages one mechanism of
the real file (a trigger added, a permission moved, a commit replaced by a tag,
the main-only condition or a refusal removed, a platform flag or a `latest` tag
added, a secret added, and so on) and asserts that the pins report it with a
message that names it. Each mutation's target must occur exactly once in the
file, so a mutation cannot go stale and pass by matching nothing.

Unparseable, empty and job-less files must also be reported.

## Step behaviour tests

The text pins say a refusal is written down; these say it works. Each step body
that decides a refusal is run under `bash -e`, as the runner runs it, with a fake
`docker` and `uname` first on the path. The fake answers every call with a
configured output and exit status.

- `MainOnlyGuardTests`: only `refs/heads/main` passes.
- `RevisionValidationTests`: only a positive integer with no leading zero is
  passed on; anything else, including a value with a newline or shell syntax, is
  refused and leaves the environment file untouched.
- `TagStepTests`: the tag is the Dockerfile's version plus the revision; a
  missing, doubled or malformed version line is refused; only the `ARG` line is
  read.
- `NativeArchitectureTests` and `BuiltArchitectureTests`: only an amd64 runner,
  an amd64 Docker server and an amd64 image pass; a Docker that cannot answer
  fails the step.
- `OverwriteRefusalTests`: an existing tag is refused; only a plain "not found"
  answer is read as absent; denied, unauthorised, network, rate-limit and empty
  answers are refused, because they say nothing about whether the tag exists.
- `DigestVerificationTests`: the output is the digest-qualified reference of our
  own repository, taken from the image store; a missing, doubled, short, long,
  upper-case, wrongly prefixed or non-hex digest fails and writes no output; a
  second line cannot smuggle an output key.
- `SummaryTests`: a run with a digest prints commit, tag, reference and the
  public-package reminder; a run without one says "NO DIGEST" and names no
  reference.

The fake stands in for the Docker daemon, which a unit test cannot start. What
the real registry answers for a missing tag, and what `docker version` prints on
a hosted runner, are checked by the first real run, not here.
