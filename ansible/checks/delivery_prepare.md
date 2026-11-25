# delivery_prepare.py: the one preparation of a delivery

The delivery used to find out two things in jobs of their own before the reusable workflow
began: whether the merge queue passed the pushed commit, and which Molecule shards the push
calls for. Each job waited for a runner, and the reusable workflow's first job waited for another
after them. This program does both in one answer, and the reusable workflow runs it inside its
first job (the `discover` job, through the `prepare-command` input of `ansible-delivery.yml`),
so the delivery waits for one runner before its checks.

It prints, in the form of `$GITHUB_OUTPUT`:

- `tested`: the proof of `merge_group_proof.py`, from the runs of `ansible.yml` for the commit.
- `shards` and `directories`: the choice of `delivery_select.py`.

Every failure leans toward testing, as each half did alone. A proof that cannot be read is
`tested=false`, and a selection that cannot be made is every role and pattern. The program
exits 0 whatever happens. If it cannot run, or its answer lacks the `shards` or the `tested`
line, the discover job writes `shards=true` and `tested=false`. The lint and shards are skipped
only on `shards=false` and `tested=true` together.

A change to this file runs every shard on its delivery (`delivery_select.EVERY_SHARD`),
as a change to `delivery_select.py` or to the caller does.
