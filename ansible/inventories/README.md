# Inventories

This directory holds the inventories and the group variables that go with
them. It holds three hosts: `edge1`, in the group `edge`, and `mx1`, in the group `mx`,
which have no group variables now. Their values, and their trusted signer lists, are
loaded by `playbooks/edge1.yml` and `playbooks/mx1.yml` through `vars_files`, and `db1`, in the group `db`,
which has no group variables because its inputs are private and reach the host
through its delivery channel (`roles/db1_grants`). `playbooks/db1.yml` is under the
pull and loads its trust file, `trust/db1.yml`, through `vars_files`. A role
applied to a new host adds its host and variables in the same pull request. `ops1`, `app1` and `demo1` have
playbooks under the pull route but no inventory entry: an inventory entry does not enrol a host
(a playbook and its trust file do), so against this inventory `--limit ops1`, `--limit app1` and
`--limit demo1` match nothing.
Their bootstrap route is the one the refusal include describes: on an inline
one-host inventory (`-i 'HOST,'`) the one-host test is true by construction.
`ANS-13` leaves the placement of inventories undecided; this layout is a
proposal that the repository owner confirms or changes.

## Layout

```text
inventories/
  README.md                 this file
  ENVIRONMENT/
    hosts.yml               groups and logical host names (does not exist yet)
    group_vars/
      README.md             what group variables hold
      all/                  variables for every host (does not exist yet)
      GROUP_NAME/           variables for one group (does not exist yet)
```

One directory per environment, with that environment's variables inside it.
`production` is the only environment today, because every host the estate runs
is a production host (`ANS-17`); a lab or a second environment would be a
sibling directory. A playbook is pointed at one environment with
`-i inventories/ENVIRONMENT`, and Ansible loads that directory's `group_vars`
beside the inventory, so one environment's variables cannot reach another's.

## The alternatives, and why this one

- **One `inventory/` with `group_vars/` beside the playbooks.** Simpler while
  there is one environment. Variables beside the playbooks load for every
  inventory the playbook runs against, so a lab inventory would read
  production's values. Not chosen.
- **A separate repository for inventories.** Keeps host lists out of this
  repository. `ANS-13` keeps a role with the service it configures so that a
  change to both is one pull request, and a second repository for the data
  splits that change and leaves open which repository owns the playbook. Not
  chosen.
- **Per-environment directories (chosen).** Ansible's documented layout for
  separate environments, with the variables under the inventory they belong to.

## Rules

- A host is named by its logical name. No address, hop route or credential
  appears here, in a name or in a value: a repository that is public is read by
  everyone, and where a name resolves to an address is decided with the
  delivery trigger (`ANS-17`), not here.
- A variable carries the prefix of the role that reads it (`ANS-7`), so a value
  here sets `ROLE_NAME_SETTING` and nothing else.
- No secret is committed. A secret arrives at run time (`ANS-16`); where it
  comes from is decided by the secrets pattern, not here.
- No tenant name or other tenant data.
