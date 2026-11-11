# Publish hetzner-host workflow pin tests

`scripts/test_publish_hetzner_host.py` pins `.github/workflows/publish-hetzner-host.yml`,
the workflow that publishes `@branchleft/hetzner-host`. It signs the tarball it
publishes with a build attestation, so what it holds and the order of its steps matter.
Every pin is a check on the parsed workflow (the strict loader of
`test_workflow_concurrency.py`), except the version comment on the attest `uses:`
line, which a parser drops and a one-line match reads.

`problems(text, other_workflows=...)` is the whole set of pins; it returns a list so
the sabotage tests can feed it a damaged copy.

## PublishHetznerHostPinTests

The real workflow holds every pin:

- the top-level permission is `contents: read` and the one job holds exactly
  `contents: read`, `packages: write`, `id-token: write` and `attestations: write`;
- exactly one step calls `attest-npm-tarball`, pinned to the v1.2.0 commit with a
  `# v1.2.0` comment, with the repository, signer workflow and tarball as literals and
  the ref taken from the `attest-ref` step (built from the packed version, never from
  `github.ref`), and no `if` or `continue-on-error`;
- the steps run in the order pack, attest-ref, attest, publish; the publish step
  publishes the packed tarball with `--no-git-checks` and the run's `GITHUB_TOKEN`;
- no other workflow in the directory runs `pnpm publish` or `npm publish` without
  calling the attest action.

## PublishHetznerHostSabotageTests

Each pin is broken in a copy of the file and must go red: the attest step removed,
a tag instead of a commit, a commit with no version comment, `id-token` dropped, a
permission widened, a signing permission at the top level, the package directory
published instead of the tarball, publish before attest, the ref read from
`github.ref`, `continue-on-error` on the attest step, and a new unattested publish
workflow.
