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
  playbooks, one file each, and that no other file defines `pull_trigger_signers`.
- Owner-only in `.github/CODEOWNERS`: a change here is the owner's merge.

The rules are in `checks/check_enrolment.py` (R0 to R7). Which keys a host trusts,
and when, is an owner decision, not a code decision.
