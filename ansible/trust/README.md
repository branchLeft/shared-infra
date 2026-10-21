# Trust files

Each host under the gated pull has one file here, `HOST.yml`, that holds its
trusted signer list (`pull_trigger_signers`). The list is the trust anchor of the
pull: a commit of `main` signed by a key on it is applied to the host as root
(ws#2340).

- The file is loaded by exactly one playbook, `playbooks/HOST.yml`, through
  `vars_files`. `group_vars/all` and every other group never hold a signer list.
- A list may be empty. An empty list makes the host refuse every run before any
  task (`playbooks/includes/require_signers.yml`), so the host fails closed until
  the owner writes a value.
- Public keys only. Never a secret.
- `checks/check_enrolment.py` requires that the files here are exactly the enrolled
  playbooks, one file each (R4), and that no other file under `ansible/` that Ansible
  loads as variables sets `pull_trigger_signers` (R6). The config writer must take its
  signers from the pinned variable (R8).
- Owner-only in `.github/CODEOWNERS`: a change here is the owner's merge.
- The check does not stop a role edit. A role runs as root and can set the list
  in code. The reusable gated apply exists in `branchLeft/github-workflows`, but
  nothing in this repo calls it, so no gate on a role edit is wired (ws#2338,
  ws#2324, design ws#2483). Which files the reviewer App may merge alone is an owner
  decision (Desk `pull-roles-owner-only-2340`).

The rules, and what each one does not see, are in `checks/README.md` (R0 to R8).
Which keys a host trusts, and when, is an owner decision, not a code decision.
