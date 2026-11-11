# check_ghost_pin_lag

Reports every host role whose pinned ghost-platform files differ from ghost-platform main.

## Why

A role here does not hold a copy of a ghost-platform program. It fetches the program at one
pinned 40-character commit and holds the bytes to a sha256 digest. That makes what a host runs
exact and checkable, and the daily Ansible run proves the host matches the pin. It says nothing
about the pin itself. A fix merged to ghost-platform reaches the host only when someone bumps the
pin and its digests, and until then the host runs the older bytes with every check green.

This check closes that gap. For each file a role pins, it reads the file at the pin and at
`main` and compares the sha256 of the two. A difference is lag.

## What counts

- `changed`: the file's bytes at `main` differ from its bytes at the pin.
- `removed`: the file exists at the pin and not at `main` (a rename or a delete). The role would
  fetch a file that no longer has a home.
- A file that does not exist at its own pin is not lag but a wrong registry or a wrong source
  list, so the check stops with status 2 and names it.
- A file that changed and was changed back is not lag: the comparison is of bytes, not history.

## The registry

`ghost_pin_consumers.json` lists each role that pins ghost-platform: the role's name, the host
that applies it, where its pinned commit is held, and where its list of pinned files is held.
The check reads both from the role's own files, so the list of files is never copied here. A
source has one of three shapes:

- `strings`: a list of file names, each joined to `prefix`;
- `keys`: a mapping whose keys are file names, each joined to `prefix`;
- `path_field`: a list of mappings, each with a `path`, joined to `prefix`.

A source can also be one literal `path`.

`test_check_ghost_pin_lag.py` fails when a role under `ansible/roles` pins ghost-platform and is
not listed, so a new consumer cannot go unwatched. Add the role to the registry in the same pull
request that adds it.

## Exit status

| Status | Meaning                                                                                                      |
| ------ | ------------------------------------------------------------------------------------------------------------ |
| 0      | Every pinned file is the same at `main`.                                                                     |
| 1      | At least one pinned file differs from `main` or is gone from it.                                             |
| 2      | The check could not run: a pin is not a full commit, a source is unreadable, or GitHub could not be reached. |

## The alert

`.github/workflows/ghost-pin-lag.yml` runs the check daily and by hand. Statuses 1 and 2 turn the
run red, the report goes into the run's step summary, and GitHub emails the account that owns the
schedule. It is not a required check and it cannot block a merge. It reads public files and
writes nothing.

## What it does not do

- It does not bump a pin. A bump changes what runs on a host, so it stays a reviewed change to
  the role, with its digests moved in the same pull request.
- It does not look at a host. What a host holds against its pin is the job of the Ansible drift
  check; this check is the other half, the pin against `main`.
- It does not cover a role that vendors a copy of a ghost-platform file into its own `files/`
  directory, or a role that pins a container image. Those pin by other means.
- It has no way to mark a difference as meant to wait. The run stays red until the pin moves.
