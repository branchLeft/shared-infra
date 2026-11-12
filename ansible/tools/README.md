# ansible/tools

This folder holds `pull_bootstrap.py`, `seed_host_inputs.py` and the three demo1 bootstrap guards,
described in the last section. The narrative of the first two lived in the module docstrings until
the CMT-3 gate required it cut below 11 lines; the constraints they stated are kept here in full.

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
seeds edge1, edget (edge-t), ops1 and app1. edget has one input, `ci_jump_user`, typed because it
exists nowhere on the host. db1 already has its file and no live file to read; a test names it, so
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
   `website.env` for the app1 contact keys. app1's `tenant_compose_stacks` is not a file: the
   tool runs the volume program (`/root/platform-provision/provision_tenant_volume.py
--list-claims`, the one process it starts, by that fixed path with no shell, no input and a
   clean environment, and only when the program is a regular file owned by root and writable by
   no one else) and reads each claimed tenant's `/opt/branchleft/<slug>/compose.yml`,
   `/etc/branchleft/<slug>.env` and `/etc/branchleft/<slug>.image.env` with the checks below. A
   claim the role's module would refuse (a slug or uid of the wrong shape, a repeat, the mail
   spool) makes the whole list unusable before any path is built from it. A claimed tenant with
   none of the three files is left out and named; one with only some, or an empty one, is
   unusable and nothing is written. The report names the tenants and never a text.
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
   The tool checks each slot's shape at the prompt: a stack, then the type `ssh-ed25519`, then a
   base64 key. It drops any comment, and it discards pending terminal input on a refusal. The role
   checks the key and the stack again on the host. An empty answer,
   or no terminal, leaves the key missing. edge1's `ci_jump_user`, the CI jump account's name, is
   typed in the same way: it exists on no live file, and it is held out of the repository and of
   every log, so the prompt is hidden and the name is never printed (a fill asks for it last; on
   a host whose file already exists, add it once with `--set ci_jump_user`, see below). A
   tenant stack is never asked for: `tenant_compose_stacks` that cannot be read live stays
   missing.
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
value. On edge1 whose file was placed before the jump account existed, this is the one-time owner
step that adds the twelfth key, as root on the host:
`python3 -I seed_host_inputs.py --host edge1 --set ci_jump_user`. Do not run the fill step with `--replace` between a `--set` and the apply that delivers it:
the fill reads the live files, which still hold the old value.

`--set tenant_compose_stacks` is the one `--set` that asks nothing: it reads the stacks from the
live files exactly as the fill does, and changes that key only. Every other key of the existing
file is carried over as it stands. This is the command for an app1 whose file already holds other
keys, and above all one that holds a key with no live source (one that was only ever typed, such
as `deploy_slot_keys_slots`). `--replace` is not that command: the fill never reads the old file,
so it asks for such a key again and writes nothing if it is not answered, and a tool that does not
know the key writes a file without it. If no stack can be read, nothing is changed. Nor is
anything changed when a tenant would drop out: a slug the file already holds that the new read
does not return, or a claimed tenant with no stack on the host (the fill leaves such a tenant out
and says so; a write over an existing key refuses). The refusal names the slugs, never a text.
There is no path yet to remove a tenant on purpose; a tenant stays listed.

Output is key names in three lists (filled from live, typed, still missing), the unusable live
sources by file and key, and the path written. A failure prints the exception class, never its
text. No value passes through `print`, logging or an argument list; `test_seed_host_inputs`
plants sentinel values in the live files and in the typed answers and scans every output.

The key-to-file table lives only in the tool. `test_seed_host_inputs` holds it to its
authorities: the host rows equal the loader's `host_inputs_required_by_host` both ways, each
`NAME` equals the role's own (`monitoring_stack_env_keys`, the pager's `ntfy_pager_env_lines`
and `ntfy_pager_env_names`, and the `NAME={{ input }}` lines of `backup-worker.env.j2` and
`state-copy.env.j2`, and of `website.env.j2` for app1), and each path equals the role's constant.
For the stacks, the stack and configuration directories and the volume program's path equal
`tenant_compose`'s own variables (one home: the tool holds copies of the constants and a test
fails when they differ), the three file names equal the ones its tasks write, and the slug, uid
and claim rules equal its module's.

Usage, on the host as root:

    python3 -I seed_host_inputs.py --host edge1|ops1|app1 [--replace]
    python3 -I seed_host_inputs.py --host edge1|ops1|app1 --set KEY

It is at `/var/lib/pull-trigger/current/ansible/tools/seed_host_inputs.py` once a commit that
holds it has been applied on the host; before that the file is copied there by hand from the
branch.

## The three guards of the demo1 root bootstrap

`pubkey_only.py`, `ci_key_line.py` and `spool_image_gate.py` are small, standard-library-only
programs that the demo1 bootstrap runbook calls before it changes anything on the host, so that a
mistake stops there and not on a production machine. Each prints a verdict and a reason code, never
a key, a line read back, an address or any other text it was given; an argument it does not know is
refused as `usage error` without being shown. Each is run as the runbook prints it, with the
interpreter of the pinned worktree's virtual environment in isolated mode:
`python -I ansible/tools/<tool>.py ...`. Each has its own test file, and each test file holds a
corpus of bad inputs that must be refused with their own reason code, runs the same corpus against
a stand-in that accepts everything to show each case would go red without the guard, runs the exact
command line, and plants sentinels to prove nothing leaks. CI runs them in the `Test the tools`
step. The tools, their tests and the captured output in `fixtures/` are the owner's in CODEOWNERS.

### pubkey_only.py: a file that is one public key and nothing else

    pubkey_only.py check FILE [--type ssh-ed25519]

Exit 0 and `pubkey=ok type=T fingerprint=SHA256:...`, or exit 1 and `pubkey=REFUSED reason=CODE`.
The reasons are `unreadable`, `too_large` (over 2 KiB), `private_key` (armour, or the binary
magic, of a private key anywhere in the file), `not_text`, `empty`, `several_lines`,
`options_in_front` (anything before the key type), `several_keys` (a second key type or key body
after the first key; the rest of the line is a comment and nothing else), `bad_shape` (not a key type the `ci_login`
role accepts, a body of the wrong length, or a body that does not name its own type) and
`wrong_type` (with `--type`). The key shapes are the `ci_login` role's `ci_login_key_shapes`, held
equal by a test.

### ci_key_line.py: the two forced-command lines of a CI account

    ci_key_line.py build --mode check|apply --pub FILE --from IPV4
    ci_key_line.py verify --file READBACK --check-pub FILE --apply-pub FILE --from IPV4 [--not-keys FILE]

`build` runs the public-key check (an `ssh-ed25519` key is required) and prints exactly
`restrict,from="IPV4",command="sudo /usr/local/sbin/pull-trigger --mode MODE" ssh-ed25519 BODY`
on stdout, with the key's comment dropped. A refusal writes `keyline=REFUSED reason=CODE` to stderr
and nothing to stdout, so a redirect into a key file never receives it. The address is a dotted
quad in plain form (`bad_from` otherwise); a mode other than the two is `bad_mode`. `--from` is
required by both subcommands: leaving it out is a `usage error`, so a line with no source address
cannot be built or accepted.

`verify` rebuilds both lines and requires the read-back to equal them byte for byte: check then
apply, two lines, a final line break, nothing else. It prints `keylines=ok` or exit 1 and
`keylines=REFUSED reason=CODE`. The reasons are `check_pub_*` and `apply_pub_*` (the public-key
reasons above), `same_key_both_modes`, `key_in_not_keys` (a key body present in the `--not-keys`
file, which is how a stop-gap key shared with another host is refused as this host's own),
`not_keys_unreadable`, `readback_unreadable` (including over 4 KiB), `bad_from`, `line_count`,
`order_swapped`, `restrict_missing`, `command_mismatch`, `from_missing` (a read-back line with no
`from=`), `several_from` (more than one), `from_mismatch`, `options_differ`,
`key_mismatch` and `not_identical`. The program path, the option and the two modes are the
`ci_login` role's, held equal to it, to the `pull_trigger` role and to the role's sudoers grant by
tests.

### spool_image_gate.py: the mail spool's image is on the host

    spool_image_gate.py ref --compose FILE (--pin-file FILE | --no-pin)
    spool_image_gate.py check --ref REF   (the output of `docker image inspect REF` on stdin)

`ref` prints the digest-pinned image the host would run. Where the host has its pin file
`/etc/branchleft/mail-spool.image.env`, the runbook reads it over ssh into a file and passes
`--pin-file`: the file must be exactly one `IMAGE=<name>@sha256:<64 hex digits>` line (the role's
own pattern), and the printed image is that one, not the Compose file's. Anything else is refused
on stderr as `ref=REFUSED reason=CODE`: `pin_old_form` (the older `MAIL_SPOOL_IMAGE=` form),
`pin_malformed` (any other text, a second line, carriage returns, quotes, over 4 KiB) or
`pin_unreadable`. Only where the pin file was checked to be absent on the host does the runbook
pass `--no-pin`, and then the image is the `mail-spool` service's in the vendored Compose file
(`compose_unreadable`, `compose_too_large`, `no_image`, `several_images`, `ref_not_digest_pinned`).
Naming neither flag, or both, is a `usage error`, so the pin file cannot be skipped by leaving it
out.

`check` prints `gate=pass`, or exit 1 and `gate=STOP reason=CODE`: `ref_not_digest_pinned`,
`no_output`, `unreadable`, `image_absent` (the empty list `docker` prints with exit 1),
`several_images`, `no_repo_digest` (the image lists no `RepoDigests`, empty, null or missing: the
daemon finding it by name does not show it is the pinned one), `digest_mismatch`. It passes only
when exactly one image came back and its `RepoDigests` hold the pinned digest (under any name).
The pattern and the service are the `demo1_egress_spool` role's, held equal by a test. The two
fixtures are real `docker image inspect` output (Docker 29, containerd image store) for a loaded
image queried by its digest-form reference, and for an absent one.
