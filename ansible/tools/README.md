# ansible/tools

This folder holds `pull_bootstrap.py` and `seed_host_inputs.py`. Their narrative lived in the
module docstrings until the CMT-3 gate required it cut below 11 lines; the constraints they
stated are kept here in full.

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

## seed_host_inputs.py: the writer of a host's inputs file

Place or rotate `/etc/branchleft/host-inputs.json`, the one root-only file the `host_inputs`
loader reads on a pulled host. The loader never writes it; this is the owner-run writer. It runs
ON the host, as root, with the interpreter the host already has (standard library only), and
seeds edge1, ops1 and app1. db1 already has its file and no live file to read; a test names it, so
a new host row in the loader fails until it is classified.

What it does, in this order:

1. Refuses unless the effective user is root and `/`, `/etc` and `/etc/branchleft` are real
   directories owned by root that neither their group nor others can write (the loader's own
   rule, held to the loader's list by a test). The destination is a constant: there is no path
   flag, and no value is ever an argument. An argument it does not know is refused without being
   shown, because it might be a value typed by mistake.
2. For each key of the host's row, in order, takes the value from the first live file that holds
   it. The one table, in the tool, says which: `monitoring.env` for the monitoring keys;
   `ntfy-pager.env` and then `monitoring.env` for the four pager keys (the unit loads the pager's
   file later, so it wins, and the hand runbook put them in `monitoring.env` first);
   `backup-worker.env` for the worker keys; `db1-ca.pem` whole for the CA; the lines of
   `backup-worker-recipients` for the tenants, in order; `state-copy.env` for the state-copy keys;
   `website.env` for the app1 contact keys.
   A value is the raw text after the first equals sign, which is what the roles write, so the
   first apply finds nothing to change. Live always wins and is never prompted over. A live file
   that is a link, not a regular file, not owned by root, writable by others or not valid text,
   and a key found twice in one file, are reported by file and key name and treated as not found;
   the tool never guesses between two values.
3. Asks a hidden prompt (`getpass`) for each key it could not find live: the tenants as
   `slug recipient` lines until an empty one, the CA as the path of a PEM file (a certificate,
   never one holding a private key), and app1's deploy slots as `stack public_key [adopt]` lines
   until an empty one (`adopt`, the literal word at the end, sets `adopt_existing`; a slot the
   host already runs needs it). A slot line that is malformed, or repeats a stack or a key, is
   refused and the whole list is left missing, so nothing is written and the line is never shown.
   The role checks each slot's shape on the host, so the tool judges none of it. An empty answer,
   or no terminal, leaves the key missing.
4. If any key is missing, writes nothing, names the missing keys, and exits 1. A rerun then needs
   no `--replace`, and the loader never meets a half file.
5. Writes a temporary file in `/etc/branchleft` created exclusively with mode `0600`, owner
   root:root, syncs it, then puts it in place with a hard link (which fails if the destination
   exists, even as a link) or, with `--replace`, a rename; syncs the directory; and reads the
   destination back: a regular `root:root 0600` file whose JSON equals what was written. The
   temporary file is removed on any failure. An existing file is refused before anything is read
   unless `--replace` is given.

`--host H --set KEY` changes one key of an existing file: the file must be regular, `root:root
0600`, one JSON object with keys inside the row, and KEY must be in the row. The new value is
asked with `getpass`; nothing else changes; the file is replaced atomically as above. It prints
the key name and the byte length of the new value, to catch a truncated paste, and never the
value. Do not run the fill step with `--replace` between a `--set` and the apply that delivers it:
the fill reads the live files, which still hold the old value.

Output is key names in three lists (filled from live, typed, still missing), the unusable live
sources by file and key, and the path written. A failure prints the exception class, never its
text. No value passes through `print`, logging or an argument list; `test_seed_host_inputs`
plants sentinel values in the live files and in the typed answers and scans every output.

The key-to-file table lives only in the tool. `test_seed_host_inputs` holds it to its
authorities: the host rows equal the loader's `host_inputs_required_by_host` both ways, each
`NAME` equals the role's own (`monitoring_stack_env_keys`, the pager's `ntfy_pager_env_lines`
and `ntfy_pager_env_names`, and the `NAME={{ input }}` lines of `backup-worker.env.j2` and
`state-copy.env.j2`, and of `website.env.j2` for app1), and each path equals the role's constant.

Usage, on the host as root:

    python3 -I seed_host_inputs.py --host edge1|ops1|app1 [--replace]
    python3 -I seed_host_inputs.py --host edge1|ops1|app1 --set KEY

It is at `/var/lib/pull-trigger/current/ansible/tools/seed_host_inputs.py` once a commit that
holds it has been applied on the host; before that the file is copied there by hand from the
branch.
