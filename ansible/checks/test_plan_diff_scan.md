# test_plan_diff_scan.py: no copied file trips the plan's secret scan

The gated apply asks each host what a run would change, in check mode, with a diff. Before the plan
is shown to the approver, a scan reads that diff and withholds all of it when any line looks like a
secret. A role that copies a whole file (a program, a compose file) puts the file into the diff as it
changes, so one line that merely reads like a secret, such as a docstring sentence or an environment
variable reference, withholds the plan of the host: nothing can be approved.

The control is a task keyword, `diff: false`, set on the copy or template task whose file is not
secret but reads as secret-like text. The scan is a backstop, never loosened to fit a file (ANS-16).
There is no list of exceptions in the roles (owner ruling of 2 Nov 2026). A line that is prose is
reworded so it no longer matches. `diff: false` is set only on the task of a file whose matching line
is a variable reference or a name that cannot change, and each such task carries a comment citing
ANS-16.

The one exception is a named allowance in the scan itself (owner ruling of 10 Nov 2026): a file path
and one whole line, in the `allowances` array of the `ssh-check-hosts` action in `github-workflows`,
which the code owners approve, so a new entry is a reviewed change there. The scan passes that line
only in that file and only as the whole line; the diff of the file is still shown to the approver in
full. `SCAN_ALLOWANCES` in the test is a copy of the array, so the test passes the same line. Today it
holds no entry. Its one entry was the `GH_TOKEN` placeholder line of the shell verifier,
`hetzner/provision/branchleft-verify-image`; the verifier is now a Python program in the
`deploy_verifier` role, none of whose lines the scan matches, so it is copied shown with neither an
entry nor `diff: false`, and the test fails if a line of it ever does match. The action's array still
names the retired shell path, which passes nothing now; dropping it is a change in `github-workflows`.
An entry is added in both places in one change. The test fails an
entry whose line is not on one line of its file, so a name held apart from its value cannot stand in
for it, and fails a shown file that assigns through an expanded name (`export "$NAME=$VALUE"`), the
shape that was used to hold a name apart. The mechanism is tested against a made-up entry that is
never in the real tuple. That second test reads one shape and is not a proof that no
other split exists: the scan reads a line at a time, and the review of a copied file is the rest.

What the test enforces, over every `copy` and `template` task of the roles the playbooks list:

- A task whose source has a matching line sets `diff: false`, on the task or on a block around it.
  `no_log` alone does not count: it hides the result, not the diff.
- A task that sets `diff: false` hides only files that match. A file with no matching line under
  it is a finding, so a loop that mixes the two is split into a hidden task and a visible one, with
  a constant list of the hidden files in the role's `vars/` (`control_plane`, `monitoring_stack`,
  `demo1_build`). The test resolves those loops through `intersect`, `difference`, `selectattr` and
  `rejectattr` against a list, and no other filter. A task that sets `no_log` is not held to this:
  it renders a secret into the file, which its source does not show.
- A source the test cannot find or resolve is a finding unless the task sets `diff: false`. Inline
  `content` and `remote_src` are skipped, as there is no local file. One list is made while the
  role runs: `edge_stack_deliver` is the static CrowdSec files of the role's vars plus the files
  directly in `crowdsec/acquis.d`, found by a `find` on the controller, and the test makes the same
  list from the checkout, so the CrowdSec and acquisition files stay visible in the plan and a
  matching line in one fails.

- A file whose text on a host still matches, though the checkout's no longer does, is listed in
  `RETIRED_MATCHES` with the line the host holds. A diff is the old text against the new one, so the
  removed line reaches the plan. The test then requires the task that copies it to set
  `diff: false`, and accepts that hide although the checkout has no matching line. It fails when the listed line no longer matches the scan or
  the checkout matches again. The entry and the file's place in the role's hidden list are removed
  once the apply that rewrites the text is live. It is never used for a line that can be reworded
  in the checkout.

A finding names the task file, the task, the source and the line number, never the text of the line.
The test reads the source of a task, not the text Ansible renders from it; a template whose rendered
text differs from its source is judged by its source.

The pattern is the `credential-assignment` entry of the backstop in the step "Judge the answers,
scan the diff and write the result" of the `ssh-check-hosts` action in branchLeft/github-workflows,
at the tag `ansible-gated-apply.yml` pins. The workflow runs it as
`grep -Eiq` on the diff, line by line, in the C locale. The test translates it: `re.I` for `-i`,
`re.A` so that `\s` is the ASCII set the C locale gives the POSIX space class, `\s` for
`[[:space:]]`, and a split on the newline alone (not `str.splitlines`, which also splits on form
feeds). A test runs the workflow's own expression through `grep -Ei` on sample lines and compares
verdicts. The other entries of the backstop name key material and tokens that no role file holds, so
they are not copied.
