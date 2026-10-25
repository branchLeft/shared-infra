# ansible/tools

This folder holds `pull_bootstrap.py`. Its narrative lived in the module docstring until the
CMT-3 gate required it cut below 11 lines; the constraints it stated are kept here in full.

## pull_bootstrap.py: the bootstrap record

Build and check the bootstrap record that a new host's first-boot document is made from.

A new host fetches three files of this repository over HTTPS and checks each against a SHA-256
before it runs anything: the pull program, the program that installs the pinned Ansible, and the
hash-locked requirements. It also writes the pull program's configuration. This tool produces the
record that names those files at a commit of `main`, their hashes and the configuration text, and
checks a record against the repository.

The pin of each file is the last commit that changed it, read from the history, so the record
never names a commit that a squash merge could remove. That is enforced here, not assumed: both
commands refuse a shallow clone, whose history cannot say which commit last changed a file, then
fetch `main` from `origin` afresh and refuse without it. Both then refuse unless HEAD is the tip
of that fetched `main`: the history a pin is read from and the files the configuration is rendered
from are HEAD's, so a checkout behind `main` would call a record current that `main` has since
replaced. `verify` also refuses a record whose pin is not an ancestor of the tip, so a record
built on a branch, or one that names a commit that only a pull request's ref or a fork holds, is
never accepted. `origin` is taken to be `branchLeft/shared-infra`: the tool runs in a checkout of
it.

The configuration is not written a second time here. Its keys are read from the role's own task,
its values from the role's own variable files, the shared include
`playbooks/includes/pull_trigger_common.yml` and edge1's trust file `trust/edge1.yml` (the
signer allowlist), and it is serialised the way Ansible's `to_nice_json` does;
`test_pull_bootstrap` runs the role's own task and compares the bytes. The shared include
derives the playbook from `enrolled_host`: the tool fills only plain `{{ name }}` references,
from the variable files and from `enrolled_host` set to the stem of the one playbook, and
refuses any other template. It refuses a playbook that does not load exactly those two files and
set `enrolled_host` to that stem, so the files it reads are the files the host will run.

Usage:

    pull_bootstrap.py generate --repo DIR --out FILE
    pull_bootstrap.py verify --repo DIR --record FILE
