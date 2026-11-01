# host_inputs

The one loader of a pulled host's private role inputs. A host that pulls its own
playbook has no operator and no `-e`, so a role that needs a secret or a private
address as a required argument has no way to receive it. This role reads one
root-only file that the owner places on the host, checks that the file is what the
owner left, and sets each value in it as a host fact under the name of the role
argument it feeds. The roles that follow take their inputs from those facts and
need no change.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14). The decision it carries out
is the owner's, option A: one root-only file per host,
written by the owner at bootstrap and edited by hand to rotate, read at run time by
one shared loader.

## What the role does, and what it does not

In this order, and each step before the first input is set:

1. Looks the host up in its row table (`host_inputs_required_by_host` in
   `vars/main.yml`) by `enrolled_host`. A host with no row is refused.
2. Checks every directory above the file (`/`, `/etc`, `/etc/branchleft`): a real
   directory, owned by uid 0, writable by neither its group nor others.
3. Checks the file `/etc/branchleft/host-inputs.json`: it exists, it is a regular file
   (a link, even to a good file, and a directory are refused), owned by uid 0 and gid
   0, with mode exactly `0600`.
4. Reads it and parses it as one JSON document. A read or parse failure is a fixed
   message; the text is never shown.
5. Requires one JSON object whose keys are exactly this host's row: a key outside the
   row (the protected keys `pull_trigger_signers` and `enrolled_host` included) is
   refused, and so is a key that is missing or has no value (null, `false`, `0`, an
   empty or blank string, an empty list or object).
6. Sets one fact per key, under the name of the role argument, then drops its own
   copies of the file's text.

It never writes a file, never prints, diffs or defaults a value, and never sets a
name that is not in the row of the host it runs on. It does not create the file or
rotate a value: the owner does, as root, on the host, with `ansible/tools/seed_host_inputs.py`
(see "Bootstrap and rotation"). It does not check that a
value is right for the role that takes it; that role's own input check does.

A refusal names a path, or the name of an input from the row, and never a value. Each
starts with a code, so that a test can tell one from another:

| Code                        | Meaning                                                                |
| --------------------------- | ---------------------------------------------------------------------- |
| `host_inputs[no-host-row]`  | `enrolled_host` is undefined, or the host has no row                   |
| `host_inputs[dir]`          | a directory above the file is missing, a link, not root's, or writable |
| `host_inputs[file-missing]` | the file does not exist                                                |
| `host_inputs[file-mode]`    | not a regular file, not owned by root:root, or the mode is not `0600`  |
| `host_inputs[parse]`        | the file could not be read, or is not exactly one JSON document        |
| `host_inputs[shape]`        | the document is not a JSON object                                      |
| `host_inputs[unknown-key]`  | the file holds a key outside the host's row (the key is not shown)     |
| `host_inputs[missing-key]`  | an input of the row is missing or has no value (its name is given)     |

## Interface

The role has no argument of its own ([`meta/argument_specs.yml`](meta/argument_specs.yml)
documents one entry point and no option). The host is the playbook's `enrolled_host`.
Everything else is a constant in [`vars/main.yml`](vars/main.yml): role variables
outrank every play and inventory value, and the pull route has no `-e`
(`check_enrolment` R2), so a caller cannot move the file or loosen what is asked of
it.

The file is one JSON object, for db1:

```text
{
  "db1_stack_exporter_password": "<string>",
  "db1_grants_tenants": ["<slug>", "<slug>"],
  "db1_grants_ops1_host": "<IPv4 address>"
}
```

JSON, not YAML, so that no value is coerced to another type and the file is written with
`json.dumps`, never from a value typed into a command line. For app1
the file is one JSON object of four strings, the port included (`"587"`, not `587`,
because the website role's argument is a string), and the list of tenant stacks
that `tenant_compose` delivers:

```text
{
  "website_app1_smtp_host": "<string>",
  "website_app1_smtp_port": "<string>",
  "website_app1_smtp_user": "<string>",
  "website_app1_smtp_password": "<string>",
  "tenant_compose_stacks": [
    {
      "slug": "<tenant name>",
      "uid": 30900,
      "compose_text": "<the stack's compose file, byte for byte>",
      "secrets_env_text": "<the stack's GHOST_ environment file, byte for byte>",
      "image_env_text": "<the stack's IMAGE=name@sha256:digest line>"
    }
  ]
}
```

`tenant_compose_stacks` is a non-empty list with one entry for each tenant of the host, exactly
as `tenant_compose`'s argument specification gives it. It holds each tenant's secrets file, so it
is as private as `/etc/branchleft/<slug>.env` itself (root:root, `0600`, same host), and the
loader sets it with `no_log` and never templates it again. An empty list counts as no value and
stops the run with `host_inputs[missing-key]`: the file is not valid until it names the tenants.

For edge1 the file is one JSON object of eleven keys, each the name of a required argument
of `monitoring_stack` (seven) or `ntfy_pager` (four). The values must equal what is live on
the host now, or the first apply rewrites `monitoring.env` and `ntfy-pager.env` with others:

```text
{
  "monitoring_stack_smtp_username": "<string>",
  "monitoring_stack_smtp_password": "<string>",
  "monitoring_stack_healthchecks_ping_url": "<string>",
  "monitoring_stack_alert_recipient_email": "<string>",
  "monitoring_stack_mailhost_ping_url": "<string>",
  "monitoring_stack_grafana_admin_password": "<string>",
  "monitoring_stack_snds_data_url": "<string>",
  "ntfy_pager_pager_token": "<string>",
  "ntfy_pager_watcher_token": "<string>",
  "ntfy_pager_owner_password_hash": "<string>",
  "ntfy_pager_machine_password_hash": "<string>"
}
```

For ops1 the file is one JSON object of twenty keys, each the name of a required argument of
`backup_worker` (ten) or `backup_restore` (ten). `backup_worker_tenants` is a list; the rest
are strings:

```text
{
  "backup_worker_db_host": "<string>",
  "backup_worker_db_user": "<string>",
  "backup_worker_db_password": "<string>",
  "backup_worker_db_ca_pem": "<string>",
  "backup_worker_bucket": "<string>",
  "backup_worker_s3_endpoint": "<string>",
  "backup_worker_s3_region": "<string>",
  "backup_worker_s3_access_key_id": "<string>",
  "backup_worker_s3_secret_access_key": "<string>",
  "backup_worker_tenants": [{"slug": "<slug>", "recipient": "<public key>"}],
  "backup_restore_state_copy_recipient": "<string>",
  "backup_restore_state_copy_dest_access_key_id": "<string>",
  "backup_restore_state_copy_estate_bucket": "<string>",
  "backup_restore_state_copy_estate_endpoint": "<string>",
  "backup_restore_state_copy_estate_region": "<string>",
  "backup_restore_state_copy_estate_access_key_id": "<string>",
  "backup_restore_state_copy_tenant_bucket": "<string>",
  "backup_restore_state_copy_tenant_endpoint": "<string>",
  "backup_restore_state_copy_tenant_region": "<string>",
  "backup_restore_state_copy_tenant_access_key_id": "<string>"
}
```

A value
is set exactly as the file gave it: a string stays a string, a list stays a list, and
braces or `{%` in a string are not evaluated a second time.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collection beyond `ansible.builtin`.
- Target: any Linux host with Python 3, run as root.
- A row for the host in `vars/main.yml`, the host's entry in `checks/host_roles.yml`
  listing `host_inputs`, and the loader as the first role after the two pull roles in
  the host's playbook (`check_enrolment` R11).

## What it changes on a host

Nothing. It reads one file and sets facts in memory for the run. No file, package,
service, user or port is touched.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes:

```text
python3 ansible/harness/run_harness.py ansible/roles/host_inputs
```

The container test places the file as the owner does, runs the role, then runs it once
for each state it must refuse (about fifty: a missing file, a file of another owner or
group, modes 0640, 0644, 0400, 0700 and 0666, a link to a good file, a directory in the
file's place, a group-writable or missing directory above, empty and malformed text, a
JSON array, an unknown or protected key, each key missing or empty, a host with no row)
and requires each to stop with its own code, to have set no input, and to hold no
value from the file in its message. It then reads the log of the whole scenario, at
verbosity 3, and fails if any value from the file is in it.
`checks/test_host_inputs_registry.py` holds the role's three tables to each other and
checks the structure of its tasks (nothing can be skipped, every task that touches the
content hides its result, every check precedes the first input).

## How it is delivered

It is applied by the host's pulled playbook (ANS-17), after the two pull roles, and by
nothing else. Today the playbooks of edge1, ops1, db1 and app1 apply it. On edge1 the loader is
followed by the roles up to `edge_stack` and then the monitoring roles, and on ops1 by the roles
up to `control_plane` and then the backup roles; on both, the first run after this change stops
here with `host_inputs[file-missing]`, before anything else is applied, until the owner has placed
`/etc/branchleft/host-inputs.json` (root:root, `0600`, the keys above). The first db1 apply that includes
it stops here until the owner has placed the file, which proves the file on the host before
the database roles depend on it. db1 also needs its signer in `ansible/trust/db1.yml`
before any pull runs. On app1 the loader is followed by `website_app1`, and the same holds:
the first app1 run after this change stops here with `host_inputs[file-missing]`, before
the website role starts, until the owner has placed `/etc/branchleft/host-inputs.json` on
app1 (root:root, `0600`, the five keys above). The tool places it: `seed_host_inputs.py --host
app1` reads the four SMTP keys from the `website.env` that the website role's env file holds (the
same four `CONTACT_SMTP_*` lines), and `tenant_compose_stacks` from the tenants themselves, so the
values equal what is live.

`tenant_compose` is applied last on app1, after the website role, and its stacks arrive only
through this file. An app1 whose file already holds the four SMTP keys and not
`tenant_compose_stacks` stops at `host_inputs[missing-key]` on every apply, the website role
included, and so does the nightly drift check: the owner runs `seed_host_inputs.py --host app1
--set tenant_compose_stacks` as root on app1 before approving the apply that carries
`tenant_compose`. It changes that one key and keeps every other key of the file (a plain
`--replace` would rebuild the file and lose any key that has no live source). How a NEW
tenant's rendered stack reaches the file is the render path's job and not this loader's; until it
exists, a new site needs the file edited by the owner.

## Bootstrap and rotation

The owner places the file once, on the host, as root: one JSON object whose keys are exactly
the names in the host's row in `vars/main.yml`, owned by root:root with mode `0600`, in
directories only root can write. The role never writes it. For edge1, ops1 and app1 the writer is
`ansible/tools/seed_host_inputs.py --host edge1` (or `ops1`, or `app1`), which:

- takes each key's value from the live file the hand install wrote (its one table of
  key-to-file is held by a test to this row and to the roles that write those files), so the
  values equal what is live and the first apply changes nothing. app1's `tenant_compose_stacks`
  is not one file: the tool asks the volume program (`provision_tenant_volume.py --list-claims`,
  run by its fixed path, as root, with no shell) which tenants are claimed, then reads each one's
  `/opt/branchleft/<slug>/compose.yml`, `/etc/branchleft/<slug>.env` and
  `/etc/branchleft/<slug>.image.env`, with the same checks as every source (opened without
  following a link, owned by root, not writable by others). A claimed tenant with none of the
  three files is left out and named in the report; one with only some, or an empty one, stops
  the fill. The report lists the tenant names, never a value;
- asks a hidden prompt only for a key it cannot find live, and writes nothing at all if any key
  is still missing;
- writes the file in one atomic step, refuses to overwrite an existing file unless `--replace`,
  and prints key names only, never a value.

db1 is not seeded by the tool: its file exists already and there is no live file to read, so it is
written with `json.dumps` from values read into the shell, never typed into a command line.

To rotate one value, `seed_host_inputs.py --host H --set KEY` asks for the new value at a hidden
prompt and changes that key only. `--set tenant_compose_stacks` asks nothing: a stack is never
typed at a prompt, so it reads the stacks from the live files again and changes that key only. It
writes a new file beside the old one, renames it over the old
one, then reads the result back. If the read-back fails, the tool prints "inspect it" and exits
non-zero; the new file stays in place and the old one is not restored. The loader refuses a file
that is not regular `root:root` 0600, is not one JSON object, or whose keys are not exactly the
row's; it does not check values, so the owner inspects the file after a failed read-back. The
next pull reads it, and the role that takes the input delivers it at the next gated apply. Do
not run the fill step again (`--replace`) between a `--set` and the apply that delivers it: it
fills from the live files, which still hold the old value. After the first apply of a commit that
holds the tool, it is at `/var/lib/pull-trigger/current/ansible/tools/seed_host_inputs.py` on the
host; before that, the pull request that adds the tool carries the step that copies it there.

A run before the file exists stops at `host_inputs[file-missing]`, which is how the first pull
proves the file is in place before the roles that need it run.

## How to change it safely

1. A new host, or a new input for a host, is one edit to its row in `vars/main.yml`, one
   line in the literal keys of the "Set each input" task, and the host's entries in
   `checks/host_roles.yml` and its playbook. The registry test fails when they disagree.
   The name must be a required argument of a role on the host's list with no default.
2. Never template a key, never loop the task that sets the inputs, and never add a `when`,
   `ignore_errors` or `failed_when` to any task: a templated key is refused by
   `check_enrolment` R6, set_fact of a whole templated mapping sets nothing and does not
   fail, and the registry test fails on the others.
3. Every task that reads or sets a value keeps `no_log: true` and `diff: false`. A message
   names a path or a name from the row and never a value.
4. This directory is the owner's alone in `.github/CODEOWNERS`: every host's private values
   pass through it as root, and a check that fails open here exposes them all.

## Known limits

- Whoever lands a malicious signed commit gets root on the host and can read any file on
  it, this one included. This option does not change that; the pull's signer list does.
- POSIX ACLs are not inspected. The check is mode `0600` exactly, owner and group root,
  in directories only root can write.
- Between the check of the file and its read, root could swap it; no one else can, because
  every directory above it is root's and closed.
- The facts the loader sets stay in memory for the rest of the play. A later task that
  handles one must keep its own `no_log`.
- An input that is `false` or `0` is refused as empty. The inputs this role carries are
  strings and lists of strings, so none is.
