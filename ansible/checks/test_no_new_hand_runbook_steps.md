# test_no_new_hand_runbook_steps.py: the hand runbook steps stay frozen

A hand step is a fenced shell block in any `RUNBOOK*.md` that reaches a host (`ssh`, `scp`,
`rsync`) and changes it (writes a file, installs a package, manages a unit, moves files, changes
a firewall). `hand_runbook_steps.yml` lists how many such blocks each runbook holds, with a reason
as in `hand_installers.yml`. The test fails on more blocks than listed, on a runbook that is not
listed, and on fewer blocks than listed, so the count only falls: lower it in the PR that moves a
step into a role. Read-only checks over `ssh` and blocks fenced as `text` do not count.
It counts blocks, so rewriting one hand step into another keeps the count; a reviewer reads that.
The `Ansible` workflow watches `ansible/`, `hetzner/` and `mail/provision/` only (the last because
the `mx1_stack` role links and checks the mail host's scripts there), so a change to a runbook
under `mail/` or at the repository root does not start it; `mail/` is owner-gated by CODEOWNERS.
