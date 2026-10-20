# Group variables for production

A file or directory here is named for an inventory group, or `all` for every
host. Ansible loads `all/` first and a group's directory after it, so a group
overrides `all`.

- A directory is preferred to a single file, so that one concern is one file
  (`all/ROLE_NAME.yml` holds the values for one role).
- Every variable here is read by a role, carries that role's prefix and is
  declared in the role's `meta/argument_specs.yml` (`ANS-7`). A value no role
  reads is removed.
- Variables for one host are not given a directory here. A host that differs
  from its group is a group of one, named for the difference.
- Only values that are safe to publish are committed. A secret is supplied at
  run time (`ANS-16`).

The `edge/` directory holds the values for the edge hosts: `pull_trigger.yml`.
