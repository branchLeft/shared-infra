# Pattern: apt packages, repository keys and pinned downloads

This role is a recipe, not a service. A maintainer copies its tasks into a
service role when that role must install apt packages, add a signed apt
repository, or fetch a pinned binary. It configures no real service and should
never be applied to a host.

## What it does and does not do

It does three things on a Debian host: it installs named apt packages, it
delivers an apt repository as a key file and a source file that names that key,
and it downloads artefacts that are pinned by a checksum, installing the ones
that are package files.

It does not manage a service, a unit, a user or a port. It does not decide
which packages, repositories or artefacts a service needs. It does not prove
that a pinned artefact is the right one: a checksum says the bytes did not
change since the pin was chosen, not that the vendor published them.

The pin is enforced twice (see "The two layers of the checksum control"). A
download without a sha256 or sha512 digest fails the role's own run, and fails
the test.

## Interface

`meta/argument_specs.yml` declares every variable the role reads, and
`defaults/main.yml` holds the same defaults (ANS-7). None of the variables is a
secret: a checksum, a key digest and a repository address are public. Do not
put a token in a download URL; pass credentials another way, decided by the
secrets pattern.

Each entry of `packages_and_downloads_downloads` has `url`, `dest` and
`checksum`, and may set `owner`, `group` and `mode`. ansible-core validates
the arguments against the spec but discards the `default` it finds under a
nested option such as `owner`: the validator returns only error messages, so a
value omitted from an entry stays absent. That is why the spec marks the three
nested options as not required and says in their description what happens when
they are omitted: the task reads `item.owner | default(...)` and falls back to
the flat variables `packages_and_downloads_download_owner`, `_group` and
`_mode`, which do carry real defaults. The test proves it with an entry that
sets none of the three.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version (ANS-4).
- No collection beyond `ansible.builtin` for the role itself. The test also
  uses `community.docker` and `ansible.posix`, pinned in
  `ansible/requirements.yml`.
- A Debian 13 target with `python3` and `python3-apt`, which the `apt` module
  needs. Debian 13 is the release every production host runs. The test image
  has both and has `dpkg-deb`, which the test uses to build its placeholder
  package.
- To run the test: Docker on the machine, and network access the first time for
  the pinned collections and the image.

## What it changes on a host

- The destination of every download entry, with its owner, group and mode.
- `/etc/apt/keyrings/` (a directory), `/etc/apt/keyrings/packages-and-downloads.asc`
  and `/etc/apt/sources.list.d/packages-and-downloads.sources`, only when
  `packages_and_downloads_repository_present` is true.
- The packages named in `packages_and_downloads_apt_packages`, and the
  packages inside the files listed in `packages_and_downloads_debs`.
- The apt package index, when it is more than an hour old and a package is
  named.

It starts no service, opens no port and creates no user.

## How to run the test

From the repository root, with the pinned tools installed as `ansible/README.md`
describes:

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/packages_and_downloads
```

The harness runs lint, yamllint, a fresh-state check-mode run, converge, a
second converge that must change nothing, verify, a configured-state check-mode
run, Molecule's own check action, and destroy. Each step prints one line.

To run only the second layer of the checksum control against an already
converged test container, run `molecule verify` from this directory, with the
same environment the harness sets.

## How it is delivered

This role is never delivered. A service role copied from it is applied to a
production host only through the gated workflow of ANS-17: a plan job in check
mode, the approval of the protected environment, `ansible-pull` of that exact
commit of `main`, and a second run that must report zero changes. Nothing in
this directory runs `ansible-playbook` against a host, and an author's local run
is the Molecule test on a container.

## How to change it safely

- A new pin is one change: the `url` and the `checksum` of the entry, and the
  digest that `verify.yml` and `converge.yml` expect, together. Changing one
  without the other makes the download fail, which is intended.
- Run the whole harness, not only the step you touched, and keep every
  sabotage in "What the test proves" red: edit the control, see the assertion
  fail, undo the edit.
- Never loosen `scan-downloads.j2` or the assertions at the top of
  `tasks/main.yml` to make a task pass. A download that cannot satisfy them is
  missing its pin.

## The recipe: the shell shape it replaces

A shell script that does three things in order:

```text
apt-get update
apt-get install -y EXAMPLE_PACKAGE
curl -fsSL https://DOWNLOAD_HOST/EXAMPLE_TOOL-VERSION -o /usr/local/bin/EXAMPLE_TOOL
chmod 0755 /usr/local/bin/EXAMPLE_TOOL
apt-key add EXAMPLE_KEY.asc
```

Each line changes the host without saying what the host should look like. A
second run repeats the download, reports nothing, and cannot be told apart from
a first run in the log. The download has no checksum, so a changed file is
installed without a warning. `apt-key` also trusts its key for every repository
on the host.

## The recipe: the Ansible shape

Each shell line becomes a module that states its end state (ANS-1, ANS-9). The
snippets below are the role's tasks.

Named apt packages, from a cached index that is refreshed only when stale:

```yaml
- name: Install the named apt packages from the cached index
  ansible.builtin.apt:
    name: '{{ packages_and_downloads_apt_packages }}'
    state: present
    update_cache: true
    cache_valid_time: 3600
  when: packages_and_downloads_apt_packages | length > 0
```

A repository key delivered as a file, and a source that names that file:

```yaml
- name: Deliver the repository key as a file
  ansible.builtin.copy:
    src: example-archive-key.asc
    dest: /etc/apt/keyrings/packages-and-downloads.asc
    owner: root
    group: root
    mode: '0644'
  when: packages_and_downloads_repository_present

- name: Deliver the repository source, signed by that key file
  ansible.builtin.template:
    src: packages-and-downloads.sources.j2
    dest: /etc/apt/sources.list.d/packages-and-downloads.sources
    owner: root
    group: root
    mode: '0644'
  when: packages_and_downloads_repository_present
```

The template carries `Signed-By: /etc/apt/keyrings/packages-and-downloads.asc`.
A real service role should prefer the maintained `deb822_repository` module to
a hand-written file. This role renders a file instead only because
`deb822_repository` needs `python3-debian` on the target, which the test image
does not carry and which installing needs the network for.

A pinned download, with the checksum passed on every call:

```yaml
- name: Download each pinned artefact and check its digest
  ansible.builtin.get_url:
    url: '{{ item.url }}'
    dest: '{{ item.dest }}'
    checksum: '{{ item.checksum }}'
    owner: '{{ item.owner | default(packages_and_downloads_download_owner) }}'
    group: '{{ item.group | default(packages_and_downloads_download_group) }}'
    mode: '{{ item.mode | default(packages_and_downloads_download_mode) }}'
  loop: '{{ packages_and_downloads_downloads }}'
```

A downloaded package file, installed from the local path only:

```yaml
- name: Install each local package file the pinned downloads delivered
  ansible.builtin.apt:
    deb: '{{ item }}'
    state: present
  loop: '{{ packages_and_downloads_debs }}'
  when: not ansible_check_mode
```

## Why each parameter is set

- `state: present` on apt: the packages must exist; removal is a different
  decision and has its own module call.
- `update_cache: true` with `cache_valid_time: 3600`: the index is refreshed
  when it is more than an hour old and not on every run. Without
  `cache_valid_time` every run refreshes it, and the apt task reports change on
  a cold cache.
- `Signed-By` in the source names a key file, not an `apt-key` keyring. The key
  is trusted only for the source that names it. `apt-key` is deprecated and
  trusts a key for every source.
- The key file is written `0644`, owned by root; it is public material.
- `checksum: 'sha256:HEX64'` or `'sha512:HEX128'` on `get_url`: the download
  refuses a file whose digest differs, and the module reports no change when
  the file already matches. The algorithm is part of the value, so md5 and sha1
  cannot be passed by mistake.
- `mode`, `owner` and `group` on the download: a binary on a host must be
  root-owned and not writable by others. The digest is the only version
  control; the version lives in the variable that names the URL and checksum
  together.
- `loop` over `packages_and_downloads_downloads`: one entry per artefact, so a
  service role declares each pin in one place.
- `deb` takes a local path that a pinned download wrote, never a URL: the apt
  module would fetch a URL itself with no digest check.

## The two layers of the checksum control

The rule is: a download without a pin fails.

1. **At run time, in the role.** The first tasks of `tasks/main.yml` assert, for
   every entry of `packages_and_downloads_downloads`, that the checksum is a
   string of exactly `sha256:` and 64 lowercase hex digits, or `sha512:` and 128.
   An empty value, another algorithm, a URL (which `get_url` would treat as a
   pointer to a digest file it downloads) or a trailing newline is refused
   before any task changes the host. Every entry of `packages_and_downloads_debs`
   must be an absolute path that is the `dest` of one of the downloads and must
   not contain `://`. This layer runs on every real run, so a service role that
   copies it keeps it.
2. **In the test, over the source.** `verify.yml` lists every file in the role
   directory and hands the ones under `tasks/` and `handlers/`, at any depth,
   to `scan-downloads.j2`. The template parses each file and walks every
   mapping and list in it, so a task inside `block`, `rescue` or `always` is
   read like any other. It refuses:
   - a `get_url` with no checksum, or an empty one, or one that is not a
     `sha256:` or `sha512:` literal, or exactly `{{ item.checksum }}` in a task
     looping over the validated downloads variable;
   - a `uri` task with `dest` (it writes a file and has no checksum option);
   - an `unarchive` whose `src` is a literal URL;
   - an `apt` task whose `deb` is not a literal local path or exactly
     `{{ item }}` looping over the validated debs variable;
   - a `command`, `shell`, `raw` or `script` task that mentions `curl` or `wget`;
   - the `action` and `local_action` keywords, free-form module arguments and
     the `args` keyword on those modules, which hide the arguments from the
     walk;
   - an `include_tasks` or `import_tasks` whose target is not a literal file name
     of a file under `tasks/` or `handlers/` that this same scan read (a file
     at the role root, a missing file, a template, `..` or a leading `/` is
     refused, unless a file of the same name also exists under `tasks/` or
     `handlers/`; see the named limit on the include check);
   - a scan that read no `tasks/main.yml`, or saw no `get_url` task at all, so
     the check cannot pass by finding nothing.

ansible-lint is a third, partial net. At the production profile it refuses
`curl` and `wget` run through `command` written as a free-form string or as
`cmd:`, and a short module name. It does not read an `argv` list: a task
`ansible.builtin.command` with `argv: [curl, ...]` passes lint, and only the
scan above refuses it.

The scan is Jinja in a template file, not a module, plugin or filter, so ANS-2
(typed Python for custom code) does not apply: there is no custom code to type.

## What the test proves

`molecule/default/` runs the role on one container from the Debian 13 base
pinned in `molecule.yml`, with no network use by the test. The platform matches
the release production runs. Its command is `sleep infinity`, not systemd: the
pattern needs no init system, so the scenario keeps the container alive without
one and needs no cgroup mount, no `cgroupns_mode` and no tmpfs.

- **The pin is enforced at run time.** An md5 digest, an empty digest or a URL
  given as the checksum, and a URL in the package list, each fail converge at
  an assertion before any change.
- **The pin is enforced over the source.** The scan fails verify for each case
  listed above, and for a `get_url` in a second tasks file or a handlers file.
- **A wrong digest is refused.** Changing a pinned digest to another well-formed
  value makes converge fail at the download, because `get_url` refuses the
  file. This is a module failure, not an assertion, and it is the designed
  result.
- **The pinned downloads are correct.** The tool is written with its digest,
  mode `0755` and owner `root`. The entry that sets no owner, group or mode
  gets `root`, `root` and `0644` from the role's variables.
- **The apt install is idempotent offline.** `bash` is already in the image,
  so `state: present` changes nothing on either run. A placeholder package file
  that `prepare.yml` builds inside the instance with `dpkg-deb` (no binary is
  committed) is installed with `apt` `deb:` from a checksum-verified copy, and
  `package_facts` confirms both packages. The build is uncompressed, with a
  fixed timestamp and root ownership, so the same inputs give the same bytes
  and `converge.yml` can pin the digest.
- **The repository key and source are files.** The key is a `0644` file with
  the digest the role pinned, and the source file contains `Signed-By:` naming
  it.
- **Idempotence (ANS-11).** The second converge must report zero changes.
  Making the local package install always report change fails this step.
- **Check mode (ANS-10).** The harness runs the converge play under
  `--check --diff` against a fresh container and against the configured one,
  and Molecule's own check action.

## Named limits

- **No real index install is proven.** The offline design touches
  `/var/lib/apt/periodic/update-success-stamp` in `prepare.yml` so that the apt
  module skips its refresh while the stamp is younger than `cache_valid_time`.
  That stamp hides two things a real role has. First, a source added within an
  hour of the last refresh is not seen: the refresh is skipped, so a package
  from the new repository is missing from the index and the first install can
  fail. A real role forces a refresh after the source changes, for example an
  `apt` task with `update_cache: true` run `when` the source task reported
  change. Second, in check mode a stale cache always reports the apt task as
  changed (the module source sets the change flag whenever it would refresh in
  check mode), so a nightly drift run would show drift on every host with an
  old index. The repository source points at `file:/srv/packages-and-downloads/repo`,
  which does not exist, so `apt-get update` would fail until a real repository
  is named.
- **The source is a template only because of the test image.** The maintained
  `deb822_repository` module needs `python3-debian`, which the test image lacks;
  a real role prefers the module. This was checked on the Debian 13 image: the
  module import still fails there, so the reason holds on trixie.
- **Debian 13 differences the test meets.** The image's Python is 3.13 and its
  apt sources are the deb822 file `/etc/apt/sources.list.d/debian.sources`, the
  format the rendered `.sources` file uses. `dpkg-deb` builds the placeholder
  package with the same flags as on Debian 12, and the digest in `converge.yml`
  is unchanged: `converge` passes on this image, so the bytes it builds still
  match the pin.
- **Key provenance is a pin, not a trust decision.** A real role ships the
  armored key as a file under `files/` and pins its sha256 in the caller's
  variables, as this role does for its placeholder key: the role compares the
  file with the pinned digest on the controller before it delivers it, so a
  changed key file stops the run. The first pin is a human decision: compare the
  key's fingerprint with the one the vendor publishes, for example with
  `gpg --show-keys --with-fingerprint FILE`, when the key is added, and record
  where the fingerprint was read. The placeholder key is not a GPG key, and the
  test checks no signature.
- **The downloaded artefacts are local.** The test serves them from
  `file:///srv/...`, placed by `prepare.yml`. The checksum and the module are
  real; the network is not.
- **The check-mode skip is wider than its reason.** The local package install is
  skipped in check mode (ANS-10) because on a host not yet applied the download
  has not run, so there is no file to read. The skip also applies to an already
  configured host, so a check-mode run, the plan job or the nightly drift run,
  never reports a package file whose package was removed. Closing it needs a
  task that reads the installed packages and compares them with the expected
  list; this pattern does not do that.
- **The include check matches by name, not by the path Ansible resolves.** The
  scan accepts an `include_tasks` or `import_tasks` target by the file name it
  read under `tasks/` or `handlers/`. A role-root file of the same name is
  refused only when no such file exists. So a role with a clean
  `handlers/extra.yml`, an unpinned `extra.yml` at the role root, and
  `include_tasks: extra.yml` in `tasks/main.yml` passes the scan, and Ansible
  may run the role-root file. This needs two same-named files placed on
  purpose. The safe rule for a service role that copies this pattern is to put
  every included file under `tasks/` only, and to review any YAML file at the
  role root by hand.
- **A `uri` task without `dest` is not refused.** Followed by a `copy` with
  `content:` it fetches with no pin, and the scan passes it.
- **A rewrite of the downloads variable after the first assertions is not
  tested.** A `set_fact` that changes it later would feed an unvalidated entry to
  the loop. It was not reproduced: a caller's `include_role` `vars:` outranks
  `set_fact`. It could matter when the list comes from a lower-precedence source
  such as `group_vars`.
- **The repository URI and suite are not checked.** They go into the source file
  unchecked, so a caller value with a newline could add a field to the stanza.
  The caller is trusted here.
- **The key file name is hard-coded.** See step 4 of "How a service role copies
  it".
- **What the control does not cover.** A custom module that fetches. A `shell`
  task (ANS-3 forbids it, and the scan only looks for `curl` and `wget` in it).
  A fetch by another tool or a script run through `command` (`python3`, `git`,
  `pip`). An `unarchive` or `apt` whose URL is assembled from a variable, or a
  `deb822_repository`, `apt_key` or `apt_repository` that fetches a key by URL;
  none of these is read. An `include_role` or `import_role` of another role,
  which has its own test. A URL assembled outside the role and passed in as an
  already valid `url` with a valid digest: the digest is then the caller's
  claim. A file under `tasks/` that is not valid YAML stops the scan with an
  error rather than an assertion. The pin proves the bytes did not change, not
  that the vendor published them.
- **CI runs the harness over this pattern too.** CI's lint and yamllint steps
  cover `ansible/` as a whole. The workflow step named "Run the harness over
  every role and pattern" runs `ansible/harness/run_harness.py` over
  `ansible/roles/*/` and `ansible/patterns/*/`, so the container test and the
  download scan run in CI for this pattern. The run-time assertions run wherever
  the role runs.
- **The harness lints this pattern from the repository root, which lints a
  tracked directory fully.** For a role directory that git does not track, such
  as a fresh skeleton role made in a temporary directory, ansible-lint reports
  one file processed and missed a short-name `get_url`. That step proves little
  for a fresh role.
- **The apt step does not handle an apt failure with a retry.** The apt module
  retries a failed refresh itself; the test does not exercise that path.
- **The pinned package digest depends on `dpkg-deb`.** The placeholder package
  is built by the `dpkg-deb` in the pinned image. A different image can build
  different bytes and needs the digest in `converge.yml` re-pinned.

## How a service role copies it

1. Copy the download, apt and key tasks into the service role's
   `tasks/main.yml`, including the assertions at the top, with the
   `packages_and_downloads_` prefix renamed to the service's prefix (ANS-7).
   Change the `prefix` that `verify.yml` passes to the scan as well, because
   the scan checks the loop variable by name.
2. Copy the entries of `meta/argument_specs.yml` for those variables, keeping
   `checksum` required, and the same defaults in `defaults/main.yml`.
3. Copy `scan-downloads.j2` and the verify tasks that run it, pointed at the
   service role's directory. Without them a download without a pin passes the
   test.
4. Put the real key file under the service role's `files/`, the real URL and
   digest in the caller's `vars`, and the key's digest in the key variable.
   The key file name `example-archive-key.asc` is hard-coded: it is also written
   in the key-digest assertion and the key copy task in `tasks/main.yml`, so a
   copier who renames the file must rename it in both places too (a rename in
   `files/` alone fails the run at the assertion). Prefer `deb822_repository` to
   the rendered source file.
5. Keep the converge's pins and the verify's expected digests in step: a
   version bump changes both in one change.

The recipe text for the standards page is not written here; the recipes are
collected into one standards pull request later.

## Clauses this recipe exercises

ANS-1 (host state in Ansible), ANS-7 (interface spec), ANS-8 (fully qualified
names), ANS-9 (module before command), ANS-10 (check mode, with the skip named),
ANS-11 (second run changes nothing), ANS-14 (this README), ANS-15
(container-only Molecule test; the image is pinned by digest with
`pre_build_image: true`), ANS-16 (no secret in this role; the test values are
placeholders). ANS-3 holds: the role has no `shell`, `raw` or `script` task.

The image reference is `geerlingguy/docker-debian13-ansible:latest@sha256:...`.
The digest is the pin and the tag is informational: upstream rebuilds weekly,
so `latest` moves and the digest does not.
