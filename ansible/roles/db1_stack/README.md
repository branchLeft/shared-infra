# db1_stack

This role prepares the database host. This first part installs the host's
prerequisites (`age` and a MySQL 8.0 client toolchain held to that line) and
renders the credentials file of the database's metrics exporter from a password
given at run time. It replaces two hand-run scripts, one that installed the
prerequisites and one that rendered the credentials file.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

It does two things on a Debian 13 host.

1. It installs the host prerequisites. It delivers the MySQL repository as a key
   file, a source file and an apt pin that holds the toolchain to the 8.0 line;
   it downloads one pinned package file and installs it; it installs `age` and
   the two MySQL packages; and it checks that the two MySQL packages are on the
   8.0 line.
2. It writes the exporter's credentials file, `/etc/branchleft/db-exporter.my.cnf`,
   from a password the caller supplies, owned by the account the exporter runs
   as, readable by that account only.

This is part one of two. It does not deliver the compose stack, the systemd
drop-in, the MySQL configuration or the units that run the database, and it does
not start or restart anything. A second part adds those and retires the
runbook steps that do these jobs by hand. The role has not been applied to the
host: the live run waits on the pull trigger and the gated workflow (see "How it
is delivered"). After it is applied, the hand-run prerequisites script must not
be run again: it would put back the repository entry the role removes (see
"What it changes on a host").

**The role must not be applied to the live host before part two.** A second
writer of the exporter file exists today: the database stack's systemd drop-in
(`db/systemd/db.override.conf` in the `ghost-platform` repository) runs
`render_exporter_my_cnf.py` before every start of the database stack, and that
script rewrites the same `/etc/branchleft/db-exporter.my.cnf` from the password
in `db.env`. The drop-in is the legacy writer and this role is the target one.
Until part two removes the drop-in, the two share the file, and if the password
this role is given differs from the one in `db.env` the file flips to the other
value on every restart of the stack. This change touches nothing in
`ghost-platform`.

It does not decide where the password comes from, create the database account the
password belongs to, or rotate the password in the database. The role makes the
file match a password it is given; putting the same password in the database is a
separate step.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every input, and
[`defaults/main.yml`](defaults/main.yml) holds the same defaults. Ansible checks
the inputs when the role starts.

| Variable                      | Default                    | Meaning                                                                                   |
| ----------------------------- | -------------------------- | ----------------------------------------------------------------------------------------- |
| `db1_stack_exporter_password` | none, required, **secret** | The exporter account's password: at least 20 characters of `A-Za-z0-9._~-`, nothing else. |
| `db1_stack_apt_packages`      | `age`, the two MySQL ones  | Packages installed from the apt index.                                                    |
| `db1_stack_downloads`         | the `libaio1` package file | Pinned downloads: `url`, `dest` and a `sha256:` or `sha512:` `checksum`.                  |
| `db1_stack_debs`              | the same package file      | Local package files installed by path; each must be the `dest` of a download.             |

**The password is the only secret.** It reaches the role as a variable supplied
at run time, never as a default and never in a file of this repository. Every task
that reads, templates or passes it sets `no_log: true`, and `diff: false` where a
diff would show it (ANS-16). Where the value comes from, and how it reaches a host
that pulls its commit, is the owner's decision (PRIN-6) and not this role's; until
it is made, nothing can supply the password on a real host.

The pins that are not inputs (the repository, its suite and component, the key
digest, the version line, the packages the pin file covers, the exporter's uid and
the file mode, the password rules) are in [`vars/main.yml`](vars/main.yml), each
with the reason for it. An inventory value does not change them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` in
  `meta/main.yml` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Python 3 and `python3-apt`. Debian 13 is the release
  every production host runs.
- A host that can reach `deb.debian.org` (the download runs on the host, not on
  the controller) and `repo.mysql.com` (the index). The test needs neither.

## What it changes on a host

- `/var/cache/db1-stack/` (root, `0755`) and the pinned package files in it
  (root, `0644`).
- `/etc/apt/keyrings/mysql-community.asc` (root, `0644`): the vendored repository
  keys. `/etc/apt/sources.list.d/mysql-community.sources` (root, `0644`): the
  repository, signed by that file. `/etc/apt/preferences.d/mysql-community-8.0`
  (root, `0644`): the pin that holds the toolchain to the 8.0 line, with priority
  1001 so a newer candidate is never chosen.
- Removes `/etc/apt/sources.list.d/mysql-community.list` and
  `/usr/share/keyrings/mysql.gpg`, which the hand-run script made. They name the
  same repository with another key file, and apt refuses two entries for one
  repository that disagree about the key. If either was there, the role refreshes
  the apt index.
- Installs the packages in `db1_stack_debs` and `db1_stack_apt_packages`.
- `/etc/branchleft/` (root, `0755`), the directory the host's provisioning
  creates; the role states its owner and mode so a run puts them back.
- `/etc/branchleft/db-exporter.my.cnf`: owner and group uid 65534 (`nobody`, the
  user the exporter image runs as), mode `0400`. Content: `[client]`, then the
  `user`, `password` and `socket` lines.

It starts no service, opens no port and creates no user.

## How to run its test

From the repository root, with the pinned tools installed as `ansible/README.md`
describes:

```text
python3 -m venv .venv
# Install the lock with the one recipe: ansible/README.md, "Install, and install with no network".
.venv/bin/python ansible/harness/run_harness.py ansible/roles/db1_stack
```

The harness runs lint, yamllint, a fresh-state check-mode run, converge, a second
converge that must change nothing, verify, a configured-state check-mode run,
Molecule's own check action and destroy. It needs Docker on the machine and
creates one container with no network. It never touches a host.

CI runs the harness over every role and every pattern (the Ansible workflow), so
this scenario runs on each pull request.

## How it is delivered

Delivery to a host is the gated workflow only (ANS-17): a plan job in check mode,
the approval of the protected environment, a pull of that exact commit of `main`
on the host, and a second run that must report zero changes. Nothing in this
repository applies the role by hand, and an author's local run is the container
test. The live run is waiting on the pull trigger and the gated workflow being
available for this host; until then this role is tested and not delivered.

## How to change it safely

- A pin changes in one place and in one change: the value in `vars/main.yml` or
  `defaults/main.yml`, the digest or text the test expects in
  `molecule/default/verify.yml`, and (for the key) the key file.
- Run the whole harness, not only the step you touched. Every control below has a
  test that fails when the control is removed; keep it that way.
- Never turn `no_log` off to see why a task failed on a real host. Reproduce on a
  lab host with a throwaway value.
- Never loosen `scan-downloads.j2` (in the `packages_and_downloads` pattern), the
  assertions at the top of `tasks/main.yml`, or the password rules to make a run
  pass. A download that cannot satisfy the first, or a password the second
  refuses, is the thing to fix.

## What it replaces, and why each parameter is set

The two hand-run scripts did these jobs with shell and Python on the host: they
fetched the repository key live, wrote a repository entry, installed packages
and wrote the credentials file. The role does the same jobs with modules, and
differs in these ways, each on purpose.

- **The key is a file of the role, not a fetch.** A key fetched at run time is
  trusted because of where it came from on that day; a vendored file with a pinned
  digest is trusted because a human compared it with the vendor's published
  fingerprint once, and a change to it stops the run. The pattern this role
  follows (`packages_and_downloads`) forbids the live fetch for that reason.
- **The repository is a deb822 `.sources` file signed by one named key file**
  (`Signed-By`), not a key added to the system keyring. The key can then sign this
  repository only.
- **The pin file has priority 1001 and covers `mysql-common` too.** A priority above
  1000 makes apt choose the pinned line even over a newer candidate, and
  `mysql-common` is shared by all the others: leaving it out would let it move to a
  newer line and pull the rest with it.
- **The suite is `bookworm` on a Debian 13 host.** The vendor publishes the 8.0
  component under that release only.
- **`libaio1` is a downloaded package file with a pinned sha256**, installed by
  path, so the apt module is never handed a URL or an unchecked file.
- **The exporter file is closed before it is written.** A missing file is created
  empty with its final owner and mode; a file that exists, left wide by an
  earlier release, is closed by a separate task that sets its owner and mode,
  because the create task changes nothing for a file that exists. See "What the
  test proves" below.
- **What is not carried over from the scripts.** The warning about the retired
  data-source variable is not carried. `mysqldump --version` and
  `mysqlbinlog --version` are not run; the role checks the installed package
  versions instead. The run-time refusal of a key file that carries an extra
  primary key is not carried: the role compares the digest of the whole key file
  with the pinned one, and a human fixes the pin. The script's explicit handling
  of a leftover `.tmp` file is not needed, because Ansible writes through a
  temporary name of its own.
- **The password rules are the exporter's, not Ansible's.** The exporter expands a
  dollar sign, unquotes a double quote and treats a number sign, a semicolon and a
  backslash as syntax, so any of them makes it send a different password from the
  one the database holds. The role refuses them, and a password shorter than 20
  characters, before it writes anything. The refusal messages name the rule and
  never the value. Every pattern ends in `\Z` and not `$`, because `$` also matches
  before a final line break.

## What the test proves

The test runs in one Debian 13 container with no network. Every control in the
table is removed in turn, by a single edit, and the whole harness is run: each
removal makes a named step fail with the message shown, and the file is restored
afterwards. A control that does not make the test fail when it is removed is not
claimed.

| Control                                                            | Removed by                                  | The harness then fails at                                                                                                      |
| ------------------------------------------------------------------ | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| The write task hides its result (`no_log`)                         | deleting `no_log` on the write              | verify, "Assert no sentinel reached the log": the log holds the whole-file text of the exporter file                           |
| The file mode is `0400`                                            | setting `0644`                              | verify, "Assert the exporter file is private to the exporter's account"                                                        |
| The file is owned by the exporter's uid                            | setting uid `0`                             | the same task: `mode 0400, uid 0`                                                                                              |
| The password is refused for a character outside the set            | the anchor `\Z` changed to `$`              | verify, the trailing-line-break case: the role accepted the input                                                              |
| The same, for every character class                                | the set opened to any text                  | verify, the first bad character: the role accepted the input (the test tries a list of different characters and others)        |
| The allowed set is exact                                           | adding one character to the set in `vars`   | verify, "Assert the password pattern accepts exactly the allowed ASCII characters": the code point is on the wrong side        |
| An existing wide file is closed before the write                   | deleting the close task                     | verify, "Assert the wide file was closed by the task that runs before the write"                                               |
| A link at the file path is removed before the write                | dropping the link test from the removal     | verify, "Assert the link was removed and a closed file created in its place"                                                   |
| A directory holding only a hidden file is not removed              | `hidden: false` on the listing              | verify, the hidden-file case: the role accepted the input                                                                      |
| A directory holding only a subdirectory is not removed             | `file_type: file` on the listing            | verify, the subdirectory case: the role accepted the input                                                                     |
| A key change alone refreshes the index                             | dropping the key from the refresh condition | verify, the key case: "Expected the role to stop at 'Refresh the apt index after the repository files changed'"                |
| The password is refused when shorter than 20                       | the minimum lowered to 1                    | verify, the short case: the role accepted the input                                                                            |
| The exporter file is created empty and closed before it is written | disabling the task                          | verify, "The task that creates the exporter file empty and closed did not run, so the write created the file"                  |
| A directory left by Docker at the file path is removed             | disabling the removal                       | verify, the same assertion, because the directory stays in the way                                                             |
| The key file is compared with its pinned digest                    | deleting the comparison                     | verify, "Expected the role to stop at 'Refuse a repository key whose digest is not the pinned one'"                            |
| A download carries a sha256 or sha512 digest                       | deleting the form check                     | verify, "Expected the role to stop at 'Refuse a download entry that is not pinned by a sha256 or sha512 digest'"               |
| The download module checks the digest                              | deleting `checksum:` from `get_url`         | verify, the source scan: "Unpinned download in the role: ... get_url has no checksum"                                          |
| A package file is installed only from a pinned download            | deleting the destination check              | verify, "Expected the role to stop at 'Refuse a package file that is not the destination of a pinned download'"                |
| The toolchain is on the 8.0 line                                   | deleting the version match                  | verify, "Expected the role to stop at 'Refuse a MySQL toolchain that is not on the pinned line'"                               |
| The pin file holds the line                                        | priority `1001` changed to `500`            | verify, "The file /etc/apt/preferences.d/mysql-community-8.0 is not as declared"                                               |
| The hand-run installer's repository entry is removed               | disabling the removal                       | verify, "Expected the role to stop at 'Refresh the apt index after the repository files changed'": apt refuses the old entry   |
| The index is refreshed after a repository file changes             | disabling the refresh                       | verify, "Expected the role to stop at 'Refresh the apt index after the repository files changed'": the role accepted the input |
| No secret is a default                                             | adding one to `defaults/main.yml`           | verify, "The role's defaults/main.yml holds a variable the role does not declare, a password, or a sentinel"                   |
| The password option is secret in the argument spec                 | deleting `no_log` in `argument_specs.yml`   | verify, "The password option is not required and no_log, or has a default, or the spec holds a sentinel"                       |
| A second run changes nothing                                       | making the empty-file task rewrite each run | idempotence                                                                                                                    |

Two things the sabotage runs found and the role was changed for:

- Disabling the empty-file task first left every step green: the log check saw
  only the task's name, which a skipped task still prints. The task now registers
  its result and the empty-directory case asserts that it changed.
- Removing `no_log` from the empty-file task also left every step green, so the
  claim that its output carried a digest of the file was false. The task has no
  `no_log`, and the scan reads its output on a file that holds the password.

One control is a second layer and is not independently proven: `diff: false` on
the write. Removing it alone leaves every step green, because `no_log` already
hides the diff. ANS-16 asks for both, so both stay.

The log scan reads the whole log of every run (verbosity 3): the sentinel text,
its SHA-1, MD5 and SHA-256, and its base64 form (whole, and as the middle of the
encoding at the three alignments it can have inside a longer encoded blob), and
the same forms of the whole file, for the password and for the rotated password.
Its controls are a canary the converge prints, task names of the role, and a
digest the scan must find in its SHA-1, SHA-256 and base64 forms.

## Where the key comes from, and how a human renews it

`files/mysql-repo-keys.asc` is the vendor's two published signing key files
joined, the 2025 file first and the 2023 file after it. Both carry the same
primary key, fingerprint `BCA43417C3B485DD128EC6D4B7B3B788A8D3785C` (written
without spaces, as it is in the code), and differ in the dates of their
self-signatures. The 2025 file's signature expires on 2027-10-23; the 2023
file's expired on 2025-10-22. The older one is kept because it is the one that
still signs some published Release files.

Where the fingerprint was read: it is the constant in the hand-run prerequisites
script, whose notes say it was cross-checked against the value Oracle publishes
on its own page about checking the signature of a package. This change did not
read that page again, and did not fetch the key: it ran `gpg --show-keys` on the
vendored file and compared the result with the script's constant. A human who
renews the key reads the vendor's page afresh (step 1 below).

A human renews it. Nothing in this repository fetches the key, and no dependency
bot sees it.

1. Download the vendor's current signing key files from its repository host and
   read the fingerprint the vendor publishes in its documentation.
2. Run `gpg --show-keys --with-colons FILE` on each and compare the `fpr` lines
   with the published fingerprint.
3. Join the files into `files/mysql-repo-keys.asc`, compute `sha256sum` of it, and
   put that digest in `db1_stack_mysql_key_sha256` in `vars/main.yml` and in
   `verify_key_sha256` in `molecule/default/verify.yml` in the same change.
4. Run the whole harness.

## Named limits

- The test has no network. It proves the role refreshes the apt index when a
  repository file changes by letting that refresh fail offline, and the placeholder
  packages carry the real package names with versions made for the test. It does
  not prove that the repository serves the 8.0 line, that the key verifies its
  Release file, or that the pinned `libaio1` file installs on a Debian 13 host.
- The download runs against a `file://` URL in the test. The real URL, and the
  digest in `defaults/main.yml`, are checked by the download module on a real run
  and by nothing before it.
- Check mode skips three groups of tasks, each with its reason in the task file:
  the install of the local package files, the version check of the installed
  toolchain, and the index refresh. A plan does not show them.
- A write that fails half way cannot be provoked in the container, so the claim
  that a failed write leaves the old file whole rests on Ansible's atomic move, not
  on a test. The `no_log` on the step that computes the password's problems is
  reviewed, not tested.
- The window in which the file is open to others is closed by the order of the
  tasks. A missing file is created closed and an existing file is closed by its
  own task; the test checks that the task that applies to the case ran and
  changed something, and that the names come before the write in the log. It
  cannot watch the filesystem between them. The write moves the new file over
  the old one and the move copies the old file's owner and mode, which is why the
  existing file has to be closed first.
- The role must not be applied to the live host before part two removes the
  drop-in that also writes the exporter file (see the top of this README). The
  password the role is given and the one in `db.env` must be the same until then.
- The plan limit on a host that was never applied: on a host whose apt index has
  never held the MySQL repository, the task that installs the named packages
  from the index fails even under `--check`, because the package is not known to
  apt. The `check-fresh` step passes only because the prepare step installs
  placeholder packages first, so it does not exercise a never-applied host. The
  database host already has the packages, so its plan works.
- The containers ran on one machine type (arm64 Docker Desktop). The role is not
  tested on an amd64 host.
- The role has not been applied to the host. After it is, the hand-run
  prerequisites script must not be run again.
- MySQL 8.0 reaches the end of its vendor support at a date this README does not
  state, because it was not checked here; the database's own ticket owns that.

## Clauses this role exercises

ANS-3 (no shell), ANS-9 (a module before a command), ANS-10 (check mode and what is
skipped in it), ANS-11 (a second run changes nothing), ANS-14 (this order), ANS-15
(the test runs in a container only), ANS-16 (secrets, `no_log`, no diff of a
secret) and ANS-17 (delivery through the gated workflow only).
