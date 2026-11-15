# merge_group_proof.py: whether the merge queue ran the Ansible workflow on a commit

The merge queue runs the lint and the unit tests only, so a queue run proves nothing about the
containers, and the delivery is the run that tests the merged tree in them. The delivery skips
its lint and Molecule re-run only when this proof is true and `delivery_select.py` found no
shard called for; `check_delivery.py` holds the input `skip-rerun-after-merge-group` at that
exact expression. The job `queue-proof` of `ansible-delivery.yml`
reads the runs of `ansible.yml` for the pushed commit and `merge_group_proof.py` answers
`tested=true` only for a run that has all of:

- the workflow `.github/workflows/ansible.yml`, the event `merge_group`, the pushed commit as head;
- a head branch that starts with `gh-readonly-queue/`;
- the status `completed` and the conclusion `success`.

The event is judged here and is never narrowed by the API's own `event` filter, because after a
squash queue main carries a green push run of the same commit under the same check name, from a
job with no diff. A check name, or any success on the commit, is not proof. A merge that skipped
the queue has no queue run, so it gets `tested=false`. An unreadable, truncated or malformed
answer is `false` too. A false answer means the delivery re-tests, with the lint and the shards
the selection names, whatever the selection says.

`check_delivery.py` fixes the shape of the proof job and the two inputs the delivery passes
(`skip-rerun-after-merge-group`, held at the two-condition expression, and
`merge-group-check-name`, the gate job's name in `ansible.yml`, which the reusable workflow
reads only while the skip is on), and of the `select` job, its outputs, its step and its fallback.

`check_delivery.py` also fixes the push route of both callers. The push list is the
`ANSIBLE_PUSH_HOSTS` repository secret, passed as `ssh_push_hosts` (the owner creates it; an unset
secret is empty, and empty means every host is pulled). The `push-playbook` input is the one path
`PUSH_PLAYBOOK`, defined once in `check_delivery.py` and imported by `test_drift_caller.py`. The
release floor `MIN_RELEASE` is `v1.0.23`, the first release of `branchLeft/github-workflows` that
declares the per-host key maps (`ssh_host_check_keys` and, for the delivery, `ssh_host_apply_keys`)
as well as the push list: a call that passes a key the called workflow does not declare fails on
GitHub. The delivery names `ssh_host_check_keys` (the repository secret `ANSIBLE_HOST_CHECK_KEYS`,
passed by the drift caller too) and `ssh_host_apply_keys` (the `SSH_HOST_APPLY_KEYS` secret of the
`ansible-hosts` environment). Both are optional in the workflow: an unset secret is empty, and a
host with no entry keeps the shared key. The `environment` command reports `ssh_host_apply_keys`
missing from the environment's secrets, because a repository secret of that name would be readable
by every workflow on main without the approval. A
`push-dry-run-stub` is not an allowed input.

After a lock-file merge (for example Dependabot), dispatch the Ansible workflow, because the
venv cache stays cold until the Monday sweep.

Named limit: that only an org-admin pull-request bypass can skip the queue comes from the org
ruleset standard. The ruleset's bypass list could not be read with the App tokens, so the owner
should confirm it from the owner's view.
