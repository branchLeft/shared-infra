# Pattern: apt packages, repository keys and pinned downloads

This role is a recipe, not a service. A maintainer copies its tasks into a
service role when that role must install apt packages, add a signed apt
repository, or fetch a pinned binary. It configures no real service and
should never be applied to a host.

## What the recipe replaces

A shell script that does three things in order:

```text
apt-get update
apt-get install -y EXAMPLE_PACKAGE
curl -fsSL https://DOWNLOAD_HOST/EXAMPLE_TOOL-VERSION -o /usr/local/bin/EXAMPLE_TOOL
chmod 0755 /usr/local/bin/EXAMPLE_TOOL
apt-key add EXAMPLE_KEY.asc
```

Each line changes the host without saying what the host should look like.
A second run repeats the download, reports nothing, and cannot be told apart
from a first run in the log. `apt-key` also trusts its key for every
repository on the host.

## The Ansible shape

Each shell line becomes a module that states its end state (ANS-1, ANS-9).

Named apt packages, from a cached index that is refreshed only when stale:

```yaml
- name: Install the named apt packages from the cached index
  ansible.builtin.apt:
    name: '{{ packages_and_downloads_apt_packages }}'
    state: present
    update_cache: true
    cache_valid_time: 3600
```

A repository key delivered as a file, and a source that names that file:

```yaml
- name: Deliver the repository source, signed by that key file
  ansible.builtin.template:
    src: packages-and-downloads.sources.j2
    dest: /etc/apt/sources.list.d/packages-and-downloads.sources
    owner: root
    group: root
    mode: '0644'
```

The template carries `Signed-By: /etc/apt/keyrings/packages-and-downloads.asc`.
The `deb822_repository` module would do the same, but it needs `python3-debian`
on the target, which the test image does not carry and which installing needs
the network for. A file the role renders needs no extra package.

A pinned download, with the checksum passed on every call:

```yaml
- name: Download each pinned artefact and check its sha256
  ansible.builtin.get_url:
    url: '{{ item.url }}'
    dest: '{{ item.dest }}'
    checksum: 'sha256:{{ item.checksum }}'
    owner: '{{ item.owner }}'
    group: '{{ item.group }}'
    mode: '{{ item.mode }}'
  loop: '{{ packages_and_downloads_downloads }}'
```

## Why each parameter is set

- `state: present` on apt: the packages must exist; removal is a different
  decision and has its own module call.
- `update_cache: true` with `cache_valid_time: 3600`: the index is refreshed
  when it is more than an hour old and not on every run. Without
  `cache_valid_time` every run refreshes it, and the apt task reports change
  on a cold cache.
- `signed_by` names a key file, not an `apt-key` keyring. The key is trusted
  only for the source that names it. `apt-key` is deprecated and trusts a key
  for every source.
- The key file is written `0644`, owned by root; it is public material.
- `checksum: "sha256:..."` on `get_url`: the download refuses a file whose
  digest differs, and the module reports no change when the file already
  matches. A download without a checksum fails the test (see below).
- `mode` and `owner` on the download: a binary on a host must be root-owned
  and not writable by others. The sha256 pin is the only version control; the
  version lives in the variable that names the URL and checksum together.
- `loop` over `packages_and_downloads_downloads`: one entry per artefact, so a
  service role declares the pin in one place.

The pinned version is the URL and the checksum together. Changing one without
the other makes the download fail, which is the intended behaviour.

## The interface

`meta/argument_specs.yml` declares every variable. Every download entry must
set `url`, `dest` and `checksum`. `owner`, `group` and `mode` have defaults.
Pass every key explicitly from a caller's `vars`: in the run that built this
pattern, sub-option defaults did not fill the items passed to `include_role`,
and a missing `group` failed the task at finalisation. Whether the defaults
fill items set in `group_vars` is not established here.

## What the test proves

`molecule/default/` runs the role on one container from the Debian 12 base
pinned in `molecule.yml`, with no network use by the test.

- **The checksum rule is enforced by verify.** `verify.yml` reads
  `tasks/main.yml` on the controller through `MOLECULE_PROJECT_DIRECTORY`,
  asserts that at least one `get_url` task exists, and asserts that every
  `get_url` task carries a `checksum` key. A get_url task without one fails
  the verify play, even though that download would still succeed on its own.
- **A wrong checksum is refused.** Changing a pinned digest makes the
  converge fail at the download, because `get_url` refuses the file. This is
  a module failure, not an assertion, and it is the designed result.
- **The pinned download is correct.** The tool is written with its digest,
  mode `0755` and owner `root`.
- **The apt install is idempotent offline.** `bash` is already in the image,
  so `state: present` changes nothing on either run. A local `.deb` built into
  the test (see below) is installed with `apt` `deb:` from a
  checksum-verified copy, and `package_facts` confirms both packages.
- **The repository key and source are files.** The key is a `0644` file and
  the source file contains `Signed-By:` naming it.
- **Idempotence (ANS-11).** The second converge must report zero changes.

The offline apt path works because `prepare.yml` touches
`/var/lib/apt/periodic/update-success-stamp`. The apt module skips its index
refresh while that stamp is younger than `cache_valid_time`, so no `apt-get
update` runs and nothing is fetched.

## Named limits

- **No real index install is proven.** The apt index is not refreshed, so
  installing a package from a real repository is not exercised. The
  repository source points at `file:/srv/packages-and-downloads/repo`, which
  does not exist, so `apt-get update` would fail until a real repository is
  named. A later service role must prove its own index install with network
  or a real local repository.
- **The key is a placeholder.** `files/example-archive-key.asc` is not a GPG
  key. The test checks that the file is delivered and named by the source; it
  does not check any signature.
- **The downloaded artefacts are local.** The test serves them from
  `file:///srv/...`, placed by `prepare.yml`. The checksum and the module are
  real; the network is not.
- **The check covers `tasks/main.yml` only.** A `get_url` task in another
  tasks file, a handler or an included file is not read by the verify step.
- **The enforcement is in verify, not in lint.** ansible-lint at the
  production profile has no rule for a missing checksum, so the rule runs
  only in the Molecule test. CI's Ansible job runs the harness over
  `ansible/roles/*` and does not run this pattern until a workflow change
  adds `ansible/patterns/*`.
- **The apt step does not handle an apt failure with a retry.** The apt module
  retries a failed refresh itself; the test does not exercise that path.

## How a service role copies it

1. Copy the three apt and download tasks into the service role's
   `tasks/main.yml`, with the `packages_and_downloads_` prefix renamed to the
   service's prefix (ANS-7).
2. Copy the entries of `meta/argument_specs.yml` for those variables, keeping
   `checksum` required.
3. Copy the verify step that reads the tasks file, pointed at the service
   role's tasks. Without it, a `get_url` without a checksum passes the test.
4. Put the real key file under the service role's `files/` and the real URL
   and checksum in the caller's `vars`.
5. Keep the converge's pins and the verify's expected digest in step: a
   version bump changes both in one change.

The recipe text for the standards page is not written here; the recipes are
collected into one standards pull request later.

## Clauses this recipe exercises

ANS-1 (host state in Ansible), ANS-7 (interface spec), ANS-8 (fully qualified
names), ANS-9 (module before command), ANS-11 (second run changes nothing),
ANS-14 (this README), ANS-15 (container-only Molecule test), ANS-16 (no secret
in this role; the test values are placeholders). ANS-3 holds: the role has no
`shell`, `raw` or `script` task.
