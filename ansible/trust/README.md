# Trust files

Each host on the signed route has one file here, `HOST.yml`, that holds its
trusted signer list (`pull_trigger_signers`). The list is the trust anchor of that
route: a commit signed by a key on it is applied to the host as root. On a pulled
host that commit is a commit of `main`. demo1 is not pulled: its commit arrives by
push, so a commit of `main` is not what it applies. The limit for demo1 is in
`trust/demo1.yml`.

- The file is loaded by exactly one playbook, `playbooks/HOST.yml`, through
  `vars_files`. `group_vars/all` and every other group never hold a signer list.
- A list may be empty. An empty list makes the host refuse every run before any
  task (`playbooks/includes/require_signers.yml`), so the host fails closed until
  the owner writes a value.
- Public keys only. Never a secret.
- Only exact `.yml` files sit at the top of this directory, plus this README. A file of
  any other name, case or depth is refused by the check (`checks/README.md`, name rule).
- `checks/check_enrolment.py` requires that the files here are exactly the enrolled
  playbooks, one file each (R4), and that no other file under `ansible/` that Ansible
  loads as variables sets `pull_trigger_signers` (R6). The config writer must take its
  signers from the pinned variable (R8).
- Owner-only in `.github/CODEOWNERS`: a change to a trust file here is the owner's merge. This
  README is a document, and CODEOWNERS releases every Markdown file except `CLAUDE.md` and the
  files under `.github/`.
- The check does not stop a role edit. A role runs as root and can set the list
  in code. `.github/workflows/ansible-delivery.yml` calls the reusable gated apply in
  `branchLeft/github-workflows`, and the control on a role edit is the owner's deploy
  approval of that gated apply.

The rules, and what each one does not see, are in `checks/README.md` (R0 to R8).
Which keys a host trusts, and when, is an owner decision, not a code decision.
