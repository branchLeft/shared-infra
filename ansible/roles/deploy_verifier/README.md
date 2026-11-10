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

The verifier runs with a fixed environment and **no GitHub API credential**. The host holds none; it
holds at most a registry read key, reached only through `DOCKER_CONFIG` (next section). A
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

## The registry read key (checked, never written)

A private image's attestation is read from the registry, which needs a read key. The owner places
`/etc/branchleft/registry/docker` and the role only looks (`tasks/_registry_key.yml`):

- no such directory: reported, not refused. The host stays anonymous and public images still pull.
- the directory: a plain directory, `root:root`, 0700.
- `config.json` inside it: a plain file, `root:root`, 0600, a JSON object with an auth entry for
  `ghcr.io`, no other registry, and no `credsStore` or `credHelpers`.

The file is read to judge its shape. Both tasks that touch it are `no_log` and `diff: false`, only
truth values leave the task that reads it, and the register is emptied in an `always` section. A
refusal names the rule (`registry key directory`, `registry key file`, `registry key content`) and
never a value. The role never writes, fetches or prints the key. `branchleft-compose@.service` sets
the same `DOCKER_CONFIG` for its pull, and the wrapper hands it to the verifier; the three are held
to one path by a test in `hetzner/provision/test_branchleft_deploy.py`.

The role is applied on every host that runs the wrapper, so all five (`app1`, `db1`, `dbt1`, `edge1`,
`ops1`) are checked. `app1` pulls no private image yet, so for it the check is harmless and an
absent key stays anonymous.

The directory is one constant here, `deploy_verifier_registry_docker_dir`. Every other task or
program that pulls or runs an image directly takes it too, from its own pinned copy, and
`ansible/checks/test_registry_key_callers.py` finds each caller by scanning and fails when one lacks
it or its copy differs.

## Where it runs

The role is applied by the playbooks of every host that runs the deploy wrapper: `edge1` and `app1`
(before `deploy_tooling`, and before `website_app1` on app1), `ops1` (before `control_plane`), and
`db1` (before `db1_stack`). `test_deploy_verifier_coverage.py` fails when a playbook applies a
wrapper-calling role without applying this one first.

A host that gets the wrapper from the hand-run `30-install-deploy-tooling.sh` and not from a role
has no verifier until this role runs there. Such a host refuses every registered image and still
deploys unregistered ones.

## Check mode

The reads (the pins, the gh version, the credential check) run under `--check`. The writes are
reported, not made. The download and the install are skipped in check mode with that reason beside
them, because check mode fetches and extracts nothing (ANS-10).

## Tests

- `molecule/default`: converges the role on a container. It downloads the pinned gh tarball, so
  the digest check runs for real in CI, and `verify.yml` checks the installed files against the
  repository's copy and the version against `vars/main.yml`.
- `molecule/default/tasks/case_registry_key.yml`, run once per case from `verify.yml`: no key,
  a good key, a directory or file open to others, a directory with no file, two registries, the
  wrong registry, an entry with no auth, a credential helper, a file that is not JSON, and JSON
  that is not an object. Each case names the rule the refusal must contain.
- `ansible/checks/test_deploy_verifier_coverage.py`: the wrapper's paths agree with these vars, the
  pins agree and sit in vars, every wrapper-calling role is in the table, and every playbook applies
  this role before them.
