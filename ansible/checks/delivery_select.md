# delivery_select.py: which shards a delivery runs

`delivery_prepare.py` runs this program on a push to `main`, inside the discover job of the
reusable workflow (its `prepare-command` input), and the workflow takes its two answers:
`shards` (`true` when any shard must run) and `directories` (the globs it tests in place of the
`role-directories` input, one directory per line). The files it
asks `ci_select.py` about are those changed since a base commit, with the pull request rules
(`ci_select.select`, event `pull_request`), so a delivery and the gate read one rulebook.
On top of them, a change to `ansible-delivery.yml` or to `delivery_select.py` runs every
shard. The fresh-role skeleton is not a delivery shard (the delivery's globs never matched
it), so a change to it alone selects none.

- **The base is the last delivery that finished green, not the commit before the push.** A
  delivery is cancelled when the next push arrives, so the commit before may never have had
  its shards run, and a diff from it would send that commit's roles to a host untested. The
  base is the nearest first-parent ancestor of the previous tip (at most 40 back) whose
  delivery run has a successful `Discover` job, and a successful `Lint` job with every
  `Molecule:` job successful, or a skipped `Lint` with no shard anything but skipped or
  successful and the `Discover` job's step "Confirm the merge queue passed this commit"
  successful (the queue-vouched, no-shard run: that step is its only proof, and it is skipped
  on a run that tested its own tree). A cancelled, failed, running or missing job, or a
  confirm step that is skipped, failed, missing or unreadable on a skipped-lint run, is no
  pass. No such commit within reach selects every shard.
- **A failure selects every shard, never none.** Any error in the program (git, GitHub, the
  shard list, the rules, a bad argument) prints every role and pattern and exits 0. If
  `delivery_prepare.py` cannot run at all, or prints an answer without both its `shards` and
  its `tested` line, the discover job of the reusable workflow writes `shards=true` and
  `tested=false` itself and tests the `role-directories` the caller passed, which is every role
  and pattern (`check_delivery.py` pins that input to `roles/*` and `patterns/*`).
- **No shard means the lint and the shards are skipped, on two conditions.** The call sets
  `skip-rerun-after-merge-group` to the boolean `true`, and the reusable workflow then skips
  only when the preparation said `shards=false` (this program found no file any shard reads)
  and `tested=true` (the merge queue passed this exact commit: its lint and unit tests). A merge
  that skipped the queue has no queue run, so with no shard it still runs the lint and every
  role. The `directories` answer is then the full globs, which the reusable workflow lists and
  ignores.
- The job names it reads (`Discover the Ansible checks`, `Lint the Ansible inputs`,
  `Molecule: ...`) are the reusable workflow's. A rename there reads as no pass, which selects
  every shard. The daily scheduled run of `ansible.yml` still runs every shard and covers drift.
