# deploy_verifier

Installs the two things the deploy wrapper needs before it pins a registered image: the attestation
verifier, and the pinned `gh` release the verifier runs. The wrapper is `branchleft-deploy`, and its
check is in `hetzner/provision/branchleft_deploy.py`, `verify_attestation`.

## What it installs

- `/usr/local/sbin/branchleft-verify-image`, root, 0755: copied from `hetzner/provision/`, the single home. The role holds no copy.
- `/usr/local/libexec/branchleft-verifier/gh`, root, 0755: gh 2.103.3, the release named in `vars/main.yml`, installed from its tarball.
- `/var/lib/branchleft/verifier-home`, root, 0700: empty. The wrapper points `HOME`, `GH_CONFIG_DIR` and `XDG_CONFIG_HOME` here.

The pins (version, tarball digest, download URL) are in `vars/main.yml`, not `defaults/`, so no
inventory or play variable can override them. `test_deploy_verifier_coverage.py` holds the three to
one another.

## The fail-closed design

The verifier runs with a fixed environment and **no GitHub credential**. The host holds none. A
registered image is deployed only when `gh attestation verify --bundle-from-oci` succeeds for its
digest, signer and `refs/heads/main`. gh will not start without a non-empty token, so the verifier
gives it the fixed constant `placeholder-not-a-credential` on that path when no token is set. That
satisfies gh's local gate only: no API call is made and verification is against Sigstore and the
signer identity, not an account. When gh still asks for a login, the deploy is refused with the
message "the host verifier needs GitHub credentials this host does not hold". The design is
fail-closed: nothing in it falls back to an unverified deploy. The why and the observed runs are in
`hetzner/provision/branchleft_deploy.md`, "The verifier runs with no credential".

The role refuses a host where a gh config or credential file already sits in the verifier's home.
gh writes none there with the placeholder (only a cache and a device id), so a second apply passes.

## Where it runs

The role is applied by the playbooks of every host that runs the deploy wrapper: `edge1` and `app1`
(before `deploy_tooling`, and before `website_app1` on app1), `ops1` (before `control_plane`), and
`db1` (before `db1_stack`). `test_deploy_verifier_coverage.py` fails when a playbook applies a
wrapper-calling role without applying this one first.

A host that gets the wrapper from the hand-run `30-install-deploy-tooling.sh` and not from a role
has no verifier until this role runs there. Such a host refuses every registered image, and
every other image too (default deny).

## Check mode

The reads (the pins, the gh version, the credential check) run under `--check`. The writes are
reported, not made. The download and the install are skipped in check mode with that reason beside
them, because check mode fetches and extracts nothing (ANS-10).

## Tests

- `molecule/default`: converges the role on a container. It downloads the pinned gh tarball, so
  the digest check runs for real in CI, and `verify.yml` checks the installed files against the
  repository's copy and the version against `vars/main.yml`.
- `ansible/checks/test_deploy_verifier_coverage.py`: the wrapper's paths agree with these vars, the
  pins agree and sit in vars, every wrapper-calling role is in the table, and every playbook applies
  this role before them.
