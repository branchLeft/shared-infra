# test_deploy_verifier_coverage.py: the verifier before every wrapper role

The deploy wrapper refuses a registered image unless `deploy_verifier` has put the verifier and its
pinned gh on the host. The test holds three things: the table `WRAPPER_ROLES` names every role that
names the wrapper's path in its tasks, vars or defaults; every playbook that applies one of those
roles applies `deploy_verifier` earlier in the same play, and only the hosts in
`WRAPPER_PLAYBOOKS` apply one at all; and the paths the wrapper reads, and the pins the role
installs, agree and sit in `vars/`. A new wrapper role is added to the table in the same change, or
the test names it.
